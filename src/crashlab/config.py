"""Configuration loading for the CLI.

Precedence is: explicit CLI flag > TOML config file > built-in default.
The parser is intentionally small and stdlib-only; unknown config keys are
ignored with a warning so a newer config can be read by an older checkout.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping

try:  # pragma: no cover - Python 3.11+ path
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef]

from crashlab.models import InputMode, ReportConfig

LOGGER = logging.getLogger(__name__)

DEFAULT_CONFIG_NAME = "crashlab.toml"


class ConfigError(ValueError):
    """Raised for invalid or unreadable configuration."""


@dataclass
class RunConfig:
    """Everything needed to execute and analyze a target."""

    binary: str | None = None
    preload: str | None = None
    timeout: float = 5.0
    results_dir: str = "results"
    input_mode: InputMode = InputMode.STDIN
    workers: int = 1
    cwd: str | None = None
    extra_args: list[str] = field(default_factory=list)
    arg_template: str | None = None
    asan_options: str | None = None
    gdb_path: str = "gdb"
    enable_gdb: bool = True
    gdb_timeout: float = 30.0
    signature_frames: int = 5

    def validate(self) -> None:
        if self.timeout <= 0:
            raise ConfigError("timeout must be greater than zero")
        if self.workers < 1:
            raise ConfigError("workers must be at least 1")
        if self.gdb_timeout <= 0:
            raise ConfigError("gdb_timeout must be greater than zero")
        if self.signature_frames < 1:
            raise ConfigError("signature_frames must be at least 1")
        if self.input_mode is InputMode.ARG and self.arg_template is None:
            LOGGER.warning(
                "input mode 'arg' passes raw input as an argv element; "
                "ensure the input is UTF-8 text"
            )


def load_toml(path: str | Path | None) -> dict[str, Any]:
    """Load a TOML file, returning an empty mapping when ``path`` is None."""

    if path is None:
        return {}
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"config file not found: {config_path}")
    try:
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:  # type: ignore[attr-defined]
        raise ConfigError(f"invalid TOML in {config_path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"config root must be a table: {config_path}")
    return data


def _coerce(value: Any, annotation: Any) -> Any:
    """Best-effort coercion of TOML values to dataclass field types."""

    if value is None:
        return None
    name = getattr(annotation, "__name__", str(annotation))
    if name == "InputMode":
        try:
            return value if isinstance(value, InputMode) else InputMode(str(value))
        except ValueError as exc:
            allowed = ", ".join(item.value for item in InputMode)
            raise ConfigError(f"input_mode must be one of: {allowed}") from exc
    if name in {"float"}:
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"expected a number, got {value!r}") from exc
    if name in {"int"}:
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"expected an integer, got {value!r}") from exc
    if name in {"bool"}:
        if isinstance(value, bool):
            return value
        raise ConfigError(f"expected a boolean, got {value!r}")
    if name in {"str", "Optional[str]"}:
        return str(value) if value is not None else None
    return value


def _merge(cls: type, section: Mapping[str, Any], overrides: Mapping[str, Any]) -> Any:
    known = {item.name: item for item in fields(cls)}
    values: dict[str, Any] = {}
    for key, value in section.items():
        if key not in known:
            LOGGER.warning("ignoring unknown config key %s.%s", cls.__name__, key)
            continue
        if value is None:
            continue
        values[key] = _coerce(value, known[key].type)
    for key, value in overrides.items():
        if value is None:
            continue
        if key not in known:
            raise ConfigError(f"unknown configuration override: {key}")
        values[key] = _coerce(value, known[key].type)
    return cls(**values)


def load_run_config(
    path: str | Path | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> RunConfig:
    """Build a :class:`RunConfig` from TOML ``[run]`` plus CLI overrides."""

    data = load_toml(path)
    section = data.get("run", {})
    if not isinstance(section, dict):
        raise ConfigError("[run] must be a TOML table")
    config = _merge(RunConfig, section, overrides or {})
    config.validate()
    return config


def load_report_config(
    path: str | Path | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> ReportConfig:
    """Build a :class:`ReportConfig` from TOML ``[report]`` plus overrides."""

    data = load_toml(path)
    section = data.get("report", {})
    if not isinstance(section, dict):
        raise ConfigError("[report] must be a TOML table")
    return _merge(ReportConfig, section, overrides or {})


def discover_config(explicit: str | Path | None, start: Path | None = None) -> Path | None:
    """Return the explicit config, or ``./crashlab.toml`` when present."""

    if explicit:
        return Path(explicit)
    candidate = (start or Path.cwd()) / DEFAULT_CONFIG_NAME
    return candidate if candidate.is_file() else None
