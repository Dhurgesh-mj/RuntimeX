from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from crashlab.debugger.gdb import (
    GdbOutputParser,
    GdbRequest,
    GdbTimeoutError,
    GdbUnavailableError,
    LiveGdbBridge,
)

from _helpers import load_fixture


def parsed():
    return GdbOutputParser().parse(load_fixture("gdb", "heap_overflow.txt"))


def test_parser_extracts_signal_and_fault_state() -> None:
    findings = parsed()
    assert findings.available is True
    assert findings.crashed is True
    assert findings.signal_name == "SIGSEGV"
    assert findings.signal_number == 11
    assert findings.pc == "0x5555555551c4"
    assert findings.fault_address == "0x7fffffffe1d0"
    assert findings.fault_instruction is not None
    assert findings.fault_instruction.startswith("0x5555555551c4")
    assert "mov" in findings.fault_instruction


def test_parser_extracts_backtrace() -> None:
    findings = parsed()
    assert len(findings.backtrace) == 5
    top = findings.backtrace[0]
    assert top.index == 0
    assert top.function == "heap_overflow"
    assert top.file == "target_demo.c"
    assert top.line == 39
    assert top.address == "0x00005555555551c4"
    assert top.location == "target_demo.c:39"

    main_frame = findings.backtrace[1]
    assert main_frame.function == "main"
    assert main_frame.line == 112


def test_parser_extracts_registers_and_disassembly() -> None:
    findings = parsed()
    assert findings.registers["rip"] == "0x5555555551c4"
    assert findings.registers["rdi"] == "0x5555555592a0"
    assert findings.registers["eflags"] == "0x10202"
    assert len(findings.disassembly) == 5
    assert findings.disassembly[0].startswith("=>")
    assert findings.raw_output


def test_parser_handles_missing_markers() -> None:
    text = (
        "Program received signal SIGABRT, Aborted.\n"
        "0x00007ffff7a9e9b9 in raise () from /lib/libc.so.6\n"
        "bt full\n"
        "#0  0x00007ffff7a9e9b9 in raise () from /lib/libc.so.6\n"
        "#1  0x00007ffff7a9f1a8 in abort () from /lib/libc.so.6\n"
    )
    findings = GdbOutputParser().parse(text)
    assert findings.crashed is True
    assert findings.signal_name == "SIGABRT"
    assert findings.pc is None or findings.pc == ""
    assert findings.fault_address is None
    assert findings.backtrace[0].function == "raise"
    assert findings.backtrace[0].module == "/lib/libc.so.6"


def test_command_construction_includes_script_and_inferior_args(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def runner(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, stdout=load_fixture("gdb", "heap_overflow.txt"), stderr="")

    bridge = LiveGdbBridge("/opt/fake/gdb", runner=runner, which=lambda name: name)
    stdin_path = tmp_path / "input.bin"
    stdin_path.write_bytes(b"HA")
    request = GdbRequest(
        binary="/tmp/target",
        argv=["/tmp/case.bin"],
        stdin_file=str(stdin_path),
        cwd=str(tmp_path),
        timeout=7,
        env={"CRASHLAB_RUN_ID": "r1"},
    )
    findings = bridge.collect(request)

    command = captured["command"]
    assert isinstance(command, list)
    assert command[0] == "/opt/fake/gdb"
    assert "--batch" in command and "--quiet" in command and "--nx" in command
    assert "--args" in command
    assert command[command.index("--args") + 1 :] == ["/tmp/target", "/tmp/case.bin"]
    joined = " ".join(command)
    assert f"run < {stdin_path}" in joined
    assert "bt full" in joined
    assert "info registers" in joined
    assert "x/5i $pc" in joined
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["timeout"] == 7
    assert kwargs["cwd"] == str(tmp_path)
    assert kwargs["env"] == {"CRASHLAB_RUN_ID": "r1"}
    assert findings.signal_name == "SIGSEGV"


def test_file_mode_has_no_stdin_redirect() -> None:
    bridge = LiveGdbBridge(
        "/opt/fake/gdb", runner=lambda *a, **k: None, which=lambda name: name
    )
    command = bridge.build_command(
        GdbRequest(binary="/tmp/target", argv=["/tmp/case.bin"])
    )
    joined = " ".join(command)
    assert "run" in command
    assert "run <" not in joined


def test_unavailable_gdb_raises() -> None:
    bridge = LiveGdbBridge("definitely-not-a-real-gdb-binary", which=lambda name: None)
    assert bridge.available is False
    with pytest.raises(GdbUnavailableError):
        bridge.collect(GdbRequest(binary="/tmp/target"))


def test_timeout_raises() -> None:
    def runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 1)

    bridge = LiveGdbBridge("/opt/fake/gdb", runner=runner, which=lambda name: name)
    with pytest.raises(GdbTimeoutError):
        bridge.collect(GdbRequest(binary="/tmp/target", timeout=1))


def test_nonzero_gdb_exit_sets_error() -> None:
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 1, stdout="", stderr="Error: no such file or directory"
        )

    bridge = LiveGdbBridge("/opt/fake/gdb", runner=runner, which=lambda name: name)
    findings = bridge.collect(GdbRequest(binary="/tmp/missing"))
    assert findings.crashed is False
    assert findings.error is not None


def test_parser_does_not_mistake_locals_for_frames() -> None:
    findings = parsed()
    assert all(frame.index < 10 for frame in findings.backtrace)
    assert not any(frame.function.startswith("buf =") for frame in findings.backtrace)


def test_parser_frame_with_module_only() -> None:
    text = (
        "Program received signal SIGSEGV, Segmentation fault.\n"
        "#0  0x00007ffff7a9e9b9 in ?? () from /lib/x86_64-linux-gnu/libc.so.6\n"
    )
    findings = GdbOutputParser().parse(text)
    assert findings.backtrace[0].function == "??"
    assert findings.backtrace[0].module == "/lib/x86_64-linux-gnu/libc.so.6"
