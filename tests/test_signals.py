from __future__ import annotations

import os

from crashlab.models import RunStatus
from crashlab.signals import (
    build_environment,
    decode_returncode,
    format_reproduction_command,
    is_crash_signal,
    posix_signal,
)


def test_sigsegv_is_a_crash() -> None:
    status, info, error = decode_returncode(-11, platform_name="linux")
    assert status is RunStatus.CRASH
    assert info is not None
    assert info.name == "SIGSEGV"
    assert info.number == 11
    assert error is None


def test_sigabrt_sigbus_sigfpe_sigill_are_crashes() -> None:
    expected = {
        -6: "SIGABRT",
        -7: "SIGBUS",
        -8: "SIGFPE",
        -4: "SIGILL",
    }
    for returncode, name in expected.items():
        status, info, _ = decode_returncode(returncode, platform_name="linux")
        assert status is RunStatus.CRASH
        assert info is not None and info.name == name


def test_normal_exit_is_normal_even_nonzero() -> None:
    assert decode_returncode(0, platform_name="linux")[0] is RunStatus.NORMAL
    assert decode_returncode(42, platform_name="linux")[0] is RunStatus.NORMAL


def test_non_crash_signal_is_not_promoted() -> None:
    status, info, error = decode_returncode(-15, platform_name="linux")
    assert status is RunStatus.ERROR
    assert info is not None and info.name == "SIGTERM"
    assert error


def test_timeout_wins() -> None:
    status, info, error = decode_returncode(-11, timed_out=True, platform_name="linux")
    assert status is RunStatus.TIMEOUT
    assert info is None and error is None


def test_windows_access_violation_maps_to_sigsegv() -> None:
    status, info, error = decode_returncode(0xC0000005, platform_name="windows")
    assert status is RunStatus.CRASH
    assert info is not None
    assert info.name == "SIGSEGV"
    assert info.number == 11
    assert info.native_status == 0xC0000005
    assert error is None


def test_windows_signed_status_is_masked() -> None:
    status, info, _ = decode_returncode(-1073741819, platform_name="windows")
    assert status is RunStatus.CRASH
    assert info is not None and info.native_status == 0xC0000005


def test_windows_heap_and_stack_fast_fail_map_to_sigabrt() -> None:
    for code in (0xC0000374, 0xC0000409):
        status, info, _ = decode_returncode(code, platform_name="windows")
        assert status is RunStatus.CRASH
        assert info is not None and info.name == "SIGABRT"


def test_windows_unknown_status_is_error_not_crash() -> None:
    status, info, error = decode_returncode(0xC0000001, platform_name="windows")
    assert status is RunStatus.ERROR
    assert info is None
    assert "unrecognized" in (error or "")


def test_windows_dll_not_found_is_error() -> None:
    status, _, error = decode_returncode(0xC0000135, platform_name="windows")
    assert status is RunStatus.ERROR
    assert "DLL" in (error or "")


def test_posix_signal_info() -> None:
    info = posix_signal(11, platform_name="linux")
    assert info.label == "SIGSEGV (11)"
    assert info.description


def test_is_crash_signal() -> None:
    assert is_crash_signal("SIGSEGV")
    assert not is_crash_signal("SIGKILL")
    assert not is_crash_signal(None)


def test_build_environment_sets_correlation_keys_and_preload() -> None:
    env, overrides, effective, applied = build_environment(
        run_id="run-123",
        batch_id="batch-1",
        timestamp_start="2026-01-01T00:00:00.000Z",
        timeout_seconds=5,
        input_sha256="abc",
        preload="/tmp/libinstr.so",
        asan_options="detect_leaks=0",
    )
    assert env["CRASHLAB_RUN_ID"] == "run-123"
    assert env["CRASHLAB_BATCH_ID"] == "batch-1"
    assert env["CRASHLAB_TIMEOUT_SECONDS"] == "5"
    assert env["ASAN_OPTIONS"] == "detect_leaks=0"
    assert overrides["CRASHLAB_RUN_ID"] == "run-123"
    assert effective == "/tmp/libinstr.so"
    if os.name == "nt":
        assert applied is False
        assert "LD_PRELOAD" not in env
    else:
        assert applied is True
        assert env["LD_PRELOAD"].startswith("/tmp/libinstr.so")


def test_reproduction_command_posix() -> None:
    command = format_reproduction_command(
        ["./target", "case.bin"],
        env_overrides={"CRASHLAB_RUN_ID": "r1"},
        stdin_path="input.bin",
        platform_name="linux",
    )
    assert "CRASHLAB_RUN_ID=r1" in command
    assert "./target case.bin" in command
    assert "< input.bin" in command


def test_reproduction_command_windows() -> None:
    command = format_reproduction_command(
        ["target.exe", "C:\\cases\\one.bin"],
        env_overrides={"CRASHLAB_RUN_ID": "r1"},
        stdin_path="input.bin",
        platform_name="win32",
    )
    assert 'set "CRASHLAB_RUN_ID=r1"' in command
    assert "target.exe" in command
