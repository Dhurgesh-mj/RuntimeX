"""Controlled execution of local test binaries.

The runner is deliberately boring: spawn one process, feed it the exact input
bytes, enforce a wall-clock timeout, capture stdout/stderr, and write a
self-contained run directory. No shell is involved in execution
(``shell=False``); the human-readable reproduction string is generated only
after the fact.

Run directory layout::

    results/runs/<run_id>/
        input.bin           # byte-for-byte copy of the seed (never moved)
        stdout.txt
        stderr.txt
        run_manifest.json   # serialized RunResult
        run.log
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

from crashlab.config import RunConfig
from crashlab.logging_setup import add_run_log, remove_handler
from crashlab.models import (
    InputMode,
    InputRef,
    RunResult,
    RunStatus,
    sha256_bytes,
    sha256_file,
    utc_now,
    utc_now_iso,
)
from crashlab.signals import (
    build_environment,
    decode_returncode,
    describe_platform,
    format_reproduction_command,
    new_process_group_kwargs,
    terminate_process_tree,
)

LOGGER = logging.getLogger("crashlab.runner")

_ASAN_MARKERS = (
    b"ERROR: AddressSanitizer:",
    b"ERROR: LeakSanitizer:",
    b"ERROR: UndefinedBehaviorSanitizer:",
)


class RunnerError(RuntimeError):
    """Raised when a run cannot be prepared or the runner is misconfigured."""


@dataclass
class RunArtifact:
    """Internal bundle: result plus paths used during execution."""

    result: RunResult
    run_dir: Path


class TestRunner:
    """Execute target binaries under controlled conditions."""

    #: Pytest otherwise tries to collect this class because of its name.
    __test__ = False

    def __init__(self, config: RunConfig, *, base_dir: str | Path | None = None) -> None:
        self.config = config
        self.base_dir = Path(base_dir or Path.cwd()).resolve()
        self.results_dir = self._resolve_path(config.results_dir)
        self.binary_path = (
            self._resolve_binary(config.binary) if config.binary else None
        )
        if config.binary and self.binary_path is not None and not self.binary_path.exists():
            LOGGER.warning("binary does not exist yet: %s", self.binary_path)

    # -- path helpers -----------------------------------------------------

    def _resolve_path(self, value: str | os.PathLike[str]) -> Path:
        path = Path(value).expanduser()
        return path.resolve() if path.is_absolute() else (self.base_dir / path).resolve()

    def _resolve_binary(self, value: str | os.PathLike[str]) -> Path:
        """Resolve a target binary, honoring PATH for bare command names.

        ``--binary python`` is a common portable invocation, so a bare name
        that is not a file in the working directory is looked up on PATH.
        """

        text = str(value)
        path = Path(text).expanduser()
        if path.is_absolute() or path.parent != Path(""):
            return self._resolve_path(path)
        local = (self.base_dir / path).resolve()
        if local.is_file():
            return local
        found = shutil.which(text)
        return Path(found).resolve() if found else local

    def _unique_run_dir(self, run_id: str) -> Path:
        parent = self.results_dir / "runs"
        parent.mkdir(parents=True, exist_ok=True)
        candidate = parent / run_id
        suffix = 1
        while candidate.exists():
            suffix += 1
            candidate = parent / f"{run_id}_{suffix}"
        candidate.mkdir(parents=False, exist_ok=False)
        return candidate

    # -- input handling ---------------------------------------------------

    def _read_input(self, input_path: Path) -> bytes:
        try:
            return input_path.read_bytes()
        except OSError as exc:
            raise RunnerError(f"cannot read input {input_path}: {exc}") from exc

    def _decorate_argv(
        self, base_argv: Sequence[str], input_path: Path, payload: bytes
    ) -> tuple[list[str], Path | None, str | None]:
        """Return ``(argv, stdin_file, text_payload)`` for the configured mode."""

        argv = list(base_argv)
        mode = self.config.input_mode
        template = self.config.arg_template

        if mode is InputMode.STDIN:
            if template:
                raise RunnerError("arg_template is only valid for file/arg input modes")
            return argv, input_path, None

        if mode is InputMode.FILE:
            value = template.replace("{input}", str(input_path)) if template else str(input_path)
            argv.append(value)
            return argv, None, None

        # ARG mode: input bytes become an argv element, so they must be text.
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RunnerError(
                "input mode 'arg' requires UTF-8 text input; use stdin/file mode "
                "for binary payloads"
            ) from exc
        value = template.replace("{input}", text) if template else text
        argv.append(value)
        return argv, None, text

    # -- logging ----------------------------------------------------------

    def _run_logger(self, run_id: str, run_dir: Path) -> tuple[logging.Logger, logging.Handler]:
        logger = logging.getLogger(f"crashlab.run.{run_id}")
        logger.setLevel(logging.DEBUG)
        logger.propagate = True
        handler = add_run_log(logger, run_dir / "run.log")
        return logger, handler

    # -- execution --------------------------------------------------------

    def run_one(
        self,
        input_path: str | os.PathLike[str],
        *,
        batch_id: str | None = None,
        progress: Callable[[RunResult], None] | None = None,
    ) -> RunResult:
        """Execute the target once with ``input_path`` and persist the result."""

        if self.binary_path is None:
            raise RunnerError("no target binary configured (use --binary or [run] binary)")
        if not self.binary_path.is_file():
            raise RunnerError(f"target binary not found: {self.binary_path}")
        if self.config.timeout <= 0:
            raise RunnerError("timeout must be greater than zero")

        source = Path(input_path).expanduser().resolve()
        if not source.is_file():
            raise RunnerError(f"input file not found: {source}")

        payload = self._read_input(source)
        digest = sha256_bytes(payload)
        run_id = make_run_id(digest)
        run_dir = self._unique_run_dir(run_id)
        logger, log_handler = self._run_logger(run_id, run_dir)

        input_copy = run_dir / "input.bin"
        input_copy.write_bytes(payload)

        stdout_path = run_dir / "stdout.txt"
        stderr_path = run_dir / "stderr.txt"
        timestamp_start = utc_now_iso()
        started = time.perf_counter()

        argv, stdin_file, _ = self._decorate_argv(
            [str(self.binary_path), *self.config.extra_args], source, payload
        )
        env, overrides, effective_preload, preload_applied = build_environment(
            run_id=run_id,
            batch_id=batch_id,
            timestamp_start=timestamp_start,
            timeout_seconds=self.config.timeout,
            input_sha256=digest,
            preload=self.config.preload,
            asan_options=self._effective_asan_options(),
        )
        if self.config.preload and not preload_applied:
            logger.warning(
                "LD_PRELOAD requested (%s) but not applied on this platform",
                self.config.preload,
            )

        cwd = self._resolve_path(self.config.cwd) if self.config.cwd else self.base_dir
        cwd.mkdir(parents=True, exist_ok=True)
        command = format_reproduction_command(
            argv,
            env_overrides=overrides,
            stdin_path=input_copy if stdin_file is not None else None,
        )

        logger.info("run_id=%s", run_id)
        logger.debug("argv=%r", argv)
        logger.debug("cwd=%s", cwd)
        logger.debug("overrides=%r", overrides)

        stdout_handle = stdout_path.open("wb")
        stderr_handle = stderr_path.open("wb")
        stdin_handle = stdin_file.open("rb") if stdin_file is not None else None
        timed_out = False
        error: str | None = None
        exit_code: int | None = None
        signal_info = None
        status = RunStatus.ERROR

        try:
            try:
                process = subprocess.Popen(
                    argv,
                    stdin=stdin_handle,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    cwd=str(cwd),
                    env=env,
                    shell=False,
                    close_fds=not os.name == "nt",
                    **new_process_group_kwargs(),
                )
            except (OSError, ValueError) as exc:
                error = f"failed to launch target: {exc}"
                logger.error(error)
            else:
                logger.info(
                    "started pid=%s timeout=%ss", process.pid, self.config.timeout
                )
                try:
                    process.communicate(timeout=self.config.timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    logger.warning("timeout after %ss; terminating process tree", self.config.timeout)
                    terminate_process_tree(process)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:  # pragma: no cover - extreme
                        logger.error("process %s did not exit after kill", process.pid)
                    try:
                        process.communicate(timeout=1)
                    except (subprocess.TimeoutExpired, ValueError):
                        pass
                except OSError as exc:
                    error = f"process communication failed: {exc}"
                    logger.error(error)
                exit_code = process.returncode
        finally:
            if stdin_handle is not None:
                stdin_handle.close()
            stdout_handle.close()
            stderr_handle.close()

        timestamp_end = utc_now_iso()
        duration_ms = int((time.perf_counter() - started) * 1000)

        if not timed_out:
            status, signal_info, decode_error = decode_returncode(exit_code)
            if decode_error:
                error = decode_error if error is None else f"{error}; {decode_error}"
            if status is RunStatus.NORMAL and exit_code not in (0, None):
                # A fatal sanitizer report is a crash even when the sanitizer
                # chose to exit instead of aborting. This is detection, not
                # vulnerability confirmation.
                if self._has_fatal_sanitizer_report(stderr_path):
                    status = RunStatus.CRASH
                    error = (
                        "sanitizer reported a fatal error and exited with "
                        f"code {exit_code} (no signal)"
                    )
                    logger.warning(error)
        if timed_out:
            status = RunStatus.TIMEOUT

        result = RunResult(
            run_id=run_id,
            status=status,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
            binary=self.config.binary or str(self.binary_path),
            binary_resolved=str(self.binary_path),
            binary_sha256=_safe_sha256(self.binary_path),
            argv=argv,
            input=InputRef(
                sha256=digest,
                size=len(payload),
                mode=self.config.input_mode,
                original_path=str(source),
                stored_name="input.bin",
            ),
            timeout_seconds=self.config.timeout,
            duration_ms=duration_ms,
            exit_code=exit_code,
            signal=signal_info,
            preload=effective_preload,
            preload_applied=preload_applied,
            asan_options=self._effective_asan_options(),
            cwd=str(cwd),
            command=command,
            run_dir=str(run_dir),
            stdout_sha256=_safe_sha256(stdout_path),
            stderr_sha256=_safe_sha256(stderr_path),
            env_overrides=overrides,
            batch_id=batch_id,
            error=error,
            host_platform=describe_platform(),
        )

        self._write_manifest(result, run_dir / "run_manifest.json")
        logger.info(
            "finished status=%s exit=%s signal=%s duration=%sms",
            result.status.value,
            result.exit_code,
            result.signal.name if result.signal else None,
            result.duration_ms,
        )
        remove_handler(logger, log_handler)

        if progress is not None:
            progress(result)
        return result

    def run_batch(
        self,
        inputs: Iterable[str | os.PathLike[str]],
        *,
        workers: int | None = None,
        batch_id: str | None = None,
        progress: Callable[[RunResult], None] | None = None,
    ) -> list[RunResult]:
        """Execute every input, optionally with a worker pool.

        Results are returned in input order for deterministic reports/logs.
        A single unreadable input does not abort the batch; it is logged and
        skipped (infrastructure failures should be visible, not silent).
        """

        paths = [Path(item) for item in inputs]
        if not paths:
            raise RunnerError("no input files supplied")
        worker_count = max(1, workers if workers is not None else self.config.workers)
        batch = batch_id or make_batch_id()

        if worker_count == 1:
            results: list[RunResult] = []
            for path in paths:
                try:
                    results.append(self.run_one(path, batch_id=batch, progress=progress))
                except RunnerError as exc:
                    LOGGER.error("skipping %s: %s", path, exc)
            return results

        results_by_path: dict[Path, RunResult] = {}
        with ThreadPoolExecutor(
            max_workers=worker_count, thread_name_prefix="crashlab-run"
        ) as pool:
            futures = {
                pool.submit(self.run_one, path, batch_id=batch, progress=progress): path
                for path in paths
            }
            for future in as_completed(futures):
                path = futures[future]
                try:
                    results_by_path[path] = future.result()
                except RunnerError as exc:
                    LOGGER.error("skipping %s: %s", path, exc)
                except Exception as exc:  # pragma: no cover - defensive
                    LOGGER.exception("unexpected error running %s: %s", path, exc)
        return [results_by_path[path] for path in paths if path in results_by_path]

    # -- helpers ----------------------------------------------------------

    def _effective_asan_options(self) -> str | None:
        if self.config.asan_options:
            return self.config.asan_options
        if self.config.preload and "asan" in self.config.preload.lower():
            # Ensure ASan terminates with a signal so signal-based classification
            # works, and keep reports symbolized when possible.
            return "abort_on_error=1:detect_leaks=0:symbolize=1"
        return None

    @staticmethod
    def _has_fatal_sanitizer_report(stderr_path: Path, limit: int = 512 * 1024) -> bool:
        try:
            with stderr_path.open("rb") as handle:
                head = handle.read(limit)
        except OSError:
            return False
        if b"ERROR: LeakSanitizer:" in head:
            # Leak reports are not crashes; only treat ASan/UBSan fatal errors.
            head = head.replace(b"ERROR: LeakSanitizer:", b"ERROR: LeakSanitizer(ignored):")
        return any(marker in head for marker in _ASAN_MARKERS[:1] + _ASAN_MARKERS[2:])

    @staticmethod
    def _write_manifest(result: RunResult, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            prefix=".run_manifest.", suffix=".tmp", dir=str(path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(result.to_json())
                handle.write("\n")
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def make_run_id(input_sha256: str) -> str:
    """Timestamp + input hash + entropy, per the results-directory contract."""

    timestamp = utc_now().strftime("%Y%m%dT%H%M%S%f")
    return f"{timestamp}_{input_sha256[:12]}_{uuid.uuid4().hex[:4]}"


def make_batch_id() -> str:
    """Unique batch identifier shared by all runs in one invocation."""

    timestamp = utc_now().strftime("%Y%m%dT%H%M%S")
    return f"batch_{timestamp}_{uuid.uuid4().hex[:6]}"


def load_run_result(run_or_manifest: str | os.PathLike[str]) -> RunResult:
    """Load a run manifest from a manifest path or a run directory."""

    path = Path(run_or_manifest)
    manifest = path / "run_manifest.json" if path.is_dir() else path
    if not manifest.is_file():
        raise RunnerError(f"run manifest not found: {manifest}")
    data = __import__("json").loads(manifest.read_text(encoding="utf-8"))
    result = RunResult.from_dict(data)
    # Trust the actual location over a stored absolute path (results may move).
    result.run_dir = str(manifest.parent)
    return result


def discover_runs(results_dir: str | os.PathLike[str]) -> list[RunResult]:
    """Load every ``runs/*/run_manifest.json`` beneath ``results_dir``."""

    root = Path(results_dir) / "runs"
    if not root.is_dir():
        return []
    runs: list[RunResult] = []
    for manifest in sorted(root.glob("*/run_manifest.json")):
        try:
            runs.append(load_run_result(manifest))
        except Exception as exc:  # pragma: no cover - corrupted manifest
            LOGGER.warning("ignoring unreadable manifest %s: %s", manifest, exc)
    return sorted(runs, key=lambda item: item.timestamp_start)


def _safe_sha256(path: Path) -> str | None:
    try:
        return sha256_file(path)
    except OSError:
        return None
