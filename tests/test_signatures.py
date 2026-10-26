from __future__ import annotations

from crashlab.models import (
    Classification,
    Confidence,
    StackFrame,
    VulnerabilityClass,
    group_by_signature,
)
from crashlab.signatures import (
    compute_signature,
    describe_group,
    normalize_frame,
    normalize_function,
)

from _helpers import make_record, make_signal


def frame(index: int, function: str, file: str, line: int, address: str = "0x1000") -> StackFrame:
    return StackFrame(index=index, function=function, file=file, line=line, address=address)


def test_normalize_function_strips_args_offsets_and_noise() -> None:
    assert normalize_function("main") == "main"
    assert normalize_function("main+0x29") == "main"
    assert normalize_function("main+41") == "main"
    assert normalize_function("??") == "[unknown]"
    assert normalize_function("0x401234 in foo") == "foo"
    assert normalize_function("widget (int, char*)") == "widget"
    assert normalize_function("") == "[unknown]"


def test_normalize_frame_removes_absolute_paths_and_addresses() -> None:
    left = frame(0, "heap_overflow", "/build/a/target_demo.c", 39, "0x1111")
    right = frame(0, "heap_overflow", "/other/build/target_demo.c", 39, "0xffff")
    assert normalize_frame(left) == normalize_frame(right) == "heap_overflow @ target_demo.c:39"


def test_signature_is_stable_across_aslr_addresses() -> None:
    first = compute_signature(
        make_signal(),
        [
            frame(0, "heap_overflow", "/a/demo.c", 39, "0x1111"),
            frame(1, "main", "/a/demo.c", 112, "0x2222"),
        ],
    )
    second = compute_signature(
        make_signal(),
        [
            frame(0, "heap_overflow", "/b/demo.c", 39, "0xaaaa"),
            frame(1, "main", "/b/demo.c", 112, "0xbbbb"),
        ],
    )
    assert first.digest == second.digest
    assert first.method == "gdb"
    assert first.text == second.text
    assert "SIGSEGV" in first.text


def test_signature_distinguishes_different_top_frames() -> None:
    one = compute_signature(make_signal(), [frame(0, "alpha", "/a/demo.c", 10)])
    two = compute_signature(make_signal(), [frame(0, "beta", "/a/demo.c", 10)])
    assert one.digest != two.digest


def test_signature_uses_only_top_n_frames() -> None:
    frames = [frame(index, f"fn{index}", "/a/demo.c", index + 1) for index in range(8)]
    signature = compute_signature(make_signal(), frames, top_n=3)
    assert len(signature.frames) == 3
    assert signature.frames[0].startswith("fn0")


def test_deeper_frames_do_not_change_signature() -> None:
    shallow = [frame(index, f"fn{index}", "/a/demo.c", index + 1) for index in range(5)]
    deeper = shallow + [
        frame(5, "libc_start", "/lib/libc.so.6", 0),
        frame(6, "_start", "/lib/libc.so.6", 0),
    ]
    assert compute_signature(make_signal(), shallow).digest == compute_signature(
        make_signal(), deeper
    ).digest


def test_duplicate_normalized_frames_are_collapsed() -> None:
    frames = [
        frame(0, "main", "/a/demo.c", 10),
        frame(1, "main", "/a/demo.c", 10),
        frame(2, "start", "/a/demo.c", 3),
    ]
    signature = compute_signature(make_signal(), frames)
    assert signature.frames == ("main @ demo.c:10", "start @ demo.c:3")


def test_ip_fallback_normalizes_hex_width() -> None:
    narrow = compute_signature(make_signal(), None, fault_ip="0xdead")
    wide = compute_signature(make_signal(), None, fault_ip="0x0000dead")
    assert narrow.digest == wide.digest
    assert narrow.method == "instruction-pointer"


def test_signal_only_fallback() -> None:
    signature = compute_signature(make_signal("SIGABRT"), None)
    assert signature.method == "signal-only"
    assert "SIGABRT" in signature.text
    assert signature.digest != compute_signature(make_signal("SIGSEGV"), None).digest


def test_group_by_signature_prefers_confirmed_and_counts_inputs() -> None:
    confirmed = make_record(
        run_id="confirmed",
        signature_hash="aaaa",
        classification=Classification.CONFIRMED_VULNERABILITY,
        vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
        confidence=Confidence.HIGH,
    )
    unconfirmed = make_record(
        run_id="unconfirmed",
        signature_hash="bbbb",
        classification=Classification.CRASH,
        confidence=Confidence.LOW,
    )
    same_group = make_record(
        run_id="confirmed-2",
        signature_hash="aaaa",
        classification=Classification.CONFIRMED_VULNERABILITY,
        vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
        confidence=Confidence.HIGH,
    )
    groups = group_by_signature([unconfirmed, confirmed, same_group])
    assert [group.signature_hash for group in groups] == ["aaaa", "bbbb"]
    assert len(groups[0].records) == 2
    assert groups[0].representative.run_id == "confirmed"
    assert describe_group(groups[1]).startswith("bbbb")
