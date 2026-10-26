from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from crashlab.config import RunConfig
from crashlab.models import InputMode, RunStatus
from crashlab.runner import RunnerError, TestRunner, load_run_result


def write_script(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def config_for(tmp_path: Path, script: Path, **overrides) -> RunConfig:
    values = dict(
        binary=sys.executable,
        extra_args=[str(script)],
        timeout=5.0,
        results_dir=str(tmp_path / "results"),
        input_mode=InputMode.STDIN,
        workers=1,
    )
    values.update(overrides)
    return RunConfig(**values)


def test_normal_run_captures_streams_and_manifest(tmp_path: Path) -> None:
    script = write_script(
        tmp_path,
        "normal.py",
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "print(f'got:{len(data)}')\n"
        "sys.stderr.write('to-stderr\\n')\n",
    )
    input_file = tmp_path / "case.bin"
    input_file.write_bytes(b"ABCDE")

    runner = TestRunner(config_for(tmp_path, script))
    result = runner.run_one(input_file)

    assert result.status is RunStatus.NORMAL
    assert result.exit_code == 0
    assert result.signal is None
    assert result.input.sha256
    assert result.input.size == 5
    assert result.duration_ms >= 0
    assert result.command
    assert "<" in result.command  # stdin redirect recorded
    assert result.run_id.startswith("2026") or "_" in result.run_id

    run_dir = Path(result.run_dir)
    assert (run_dir / "input.bin").read_bytes() == b"ABCDE"
    assert "got:5" in (run_dir / "stdout.txt").read_text(encoding="utf-8")
    assert "to-stderr" in (run_dir / "stderr.txt").read_text(encoding="utf-8")
    assert (run_dir / "run.log").is_file()

    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["run_id"] == result.run_id
    assert manifest["status"] == "normal"
    assert manifest["input"]["sha256"] == result.input.sha256
    assert manifest["env_overrides"]["CRASHLAB_RUN_ID"] == result.run_id

    loaded = load_run_result(run_dir)
    assert loaded.run_id == result.run_id
    assert loaded.status is RunStatus.NORMAL

    # The seed is copied, never moved.
    assert input_file.is_file()
    assert input_file.read_bytes() == b"ABCDE"


def test_crash_run_decodes_signal(tmp_path: Path) -> None:
    if os.name == "nt":
        body = "import os\nos._exit(-1073741819)\n"
    else:
        body = "import os, signal\nos.kill(os.getpid(), signal.SIGSEGV)\n"
    script = write_script(tmp_path, "crash.py", body)
    input_file = tmp_path / "case.bin"
    input_file.write_bytes(b"H")

    result = TestRunner(config_for(tmp_path, script)).run_one(input_file)

    assert result.status is RunStatus.CRASH
    assert result.signal is not None
    assert result.signal.name == "SIGSEGV"
    if os.name == "nt":
        assert result.signal.native_status == 0xC0000005
        assert result.exit_code == 0xC0000005
    else:
        assert result.exit_code == -11


def test_timeout_kills_process_and_marks_timeout(tmp_path: Path) -> None:
    script = write_script(tmp_path, "sleepy.py", "import time\ntime.sleep(30)\n")
    input_file = tmp_path / "case.bin"
    input_file.write_bytes(b"T")
    started = time.perf_counter()

    result = TestRunner(config_for(tmp_path, script, timeout=0.4)).run_one(input_file)

    elapsed = time.perf_counter() - started
    assert result.status is RunStatus.TIMEOUT
    assert elapsed < 15
    assert result.duration_ms < 15_000


def test_file_input_mode_passes_path_as_last_argument(tmp_path: Path) -> None:
    script = write_script(
        tmp_path,
        "echo_file.py",
        "import sys\nprint(open(sys.argv[1], 'rb').read().decode())\n",
    )
    input_file = tmp_path / "case.bin"
    input_file.write_bytes(b"FILE-MODE")
    result = TestRunner(config_for(tmp_path, script, input_mode=InputMode.FILE)).run_one(
        input_file
    )
    assert result.status is RunStatus.NORMAL
    assert result.argv[-1] == str(input_file.resolve())
    assert "FILE-MODE" in (Path(result.run_dir) / "stdout.txt").read_text(encoding="utf-8")


def test_asan_exit_without_signal_is_detected_as_crash(tmp_path: Path) -> None:
    script = write_script(
        tmp_path,
        "asan_exit.py",
        "import sys\n"
        "sys.stderr.write('==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x01\\n')\n"
        "sys.stderr.write('SUMMARY: AddressSanitizer: heap-buffer-overflow demo.c:1 in main\\n')\n"
        "sys.exit(1)\n",
    )
    input_file = tmp_path / "case.bin"
    input_file.write_bytes(b"H")
    result = TestRunner(config_for(tmp_path, script)).run_one(input_file)
    assert result.status is RunStatus.CRASH
    assert result.signal is None
    assert result.error is not None and "sanitizer" in result.error


def test_leak_only_exit_is_not_treated_as_crash(tmp_path: Path) -> None:
    script = write_script(
        tmp_path,
        "leak_exit.py",
        "import sys\n"
        "sys.stderr.write('==1==ERROR: LeakSanitizer: detected memory leaks\\n')\n"
        "sys.exit(1)\n",
    )
    input_file = tmp_path / "case.bin"
    input_file.write_bytes(b"L")
    result = TestRunner(config_for(tmp_path, script)).run_one(input_file)
    assert result.status is RunStatus.NORMAL


def test_run_ids_and_directories_are_unique(tmp_path: Path) -> None:
    script = write_script(tmp_path, "normal.py", "print('ok')\n")
    input_file = tmp_path / "case.bin"
    input_file.write_bytes(b"SAME")
    runner = TestRunner(config_for(tmp_path, script))
    first = runner.run_one(input_file)
    second = runner.run_one(input_file)
    assert first.run_id != second.run_id
    assert first.run_dir != second.run_dir
    assert Path(first.run_dir).is_dir() and Path(second.run_dir).is_dir()


def test_batch_mode_runs_every_input_in_order(tmp_path: Path) -> None:
    script = write_script(
        tmp_path,
        "batch.py",
        "import sys\nprint(sys.stdin.buffer.read().decode().strip())\n",
    )
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    names = ["a.bin", "b.bin", "c.bin"]
    for name in names:
        (corpus / name).write_text(name, encoding="utf-8")

    runner = TestRunner(config_for(tmp_path, script, workers=2))
    results = runner.run_batch(sorted(corpus.iterdir()), workers=2)

    assert len(results) == 3
    assert [Path(run.input.original_path).name for run in results] == names
    assert all(run.status is RunStatus.NORMAL for run in results)
    assert len({run.batch_id for run in results}) == 1
    assert results[0].batch_id is not None


def test_missing_binary_is_a_runner_error(tmp_path: Path) -> None:
    config = RunConfig(
        binary=str(tmp_path / "missing-target"),
        timeout=1,
        results_dir=str(tmp_path / "results"),
    )
    runner = TestRunner(config)
    with pytest.raises(RunnerError):
        runner.run_one(tmp_path / "case.bin")


def test_preload_is_recorded_but_not_applied_on_windows(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("POSIX LD_PRELOAD execution is covered by build_environment tests")
    script = write_script(tmp_path, "normal.py", "print('ok')\n")
    input_file = tmp_path / "case.bin"
    input_file.write_bytes(b"N")
    config = config_for(tmp_path, script, preload="C:\\libs\\instrument.dll")
    result = TestRunner(config).run_one(input_file)
    assert result.status is RunStatus.NORMAL
    assert result.preload == "C:\\libs\\instrument.dll"
    assert result.preload_applied is False
    assert "LD_PRELOAD" not in result.env_overrides


def test_relative_extra_args_resolve_from_invocation_directory(tmp_path: Path) -> None:
    script = write_script(tmp_path, "relative.py", "print('relative-ok')\n")
    input_file = tmp_path / "case.bin"
    input_file.write_bytes(b"R")
    config = RunConfig(
        binary=sys.executable,
        extra_args=["relative.py"],
        timeout=5.0,
        results_dir=str(tmp_path / "results"),
    )

    result = TestRunner(config, base_dir=tmp_path).run_one(input_file)

    assert result.status is RunStatus.NORMAL
    assert result.cwd == str(tmp_path)
    assert "relative-ok" in (Path(result.run_dir) / "stdout.txt").read_text(
        encoding="utf-8"
    )


def test_initial_asan_options_are_derived_for_asan_preload(tmp_path: Path) -> None:
    config = RunConfig(preload="/usr/lib/libasan.so.8")
    runner = TestRunner(config, base_dir=tmp_path)
    assert runner._effective_asan_options() == (
        "abort_on_error=1:detect_leaks=0:symbolize=1"
    )
