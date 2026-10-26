from __future__ import annotations

from crashlab.debugger.asan import AsanParser, classify_asan_error
from crashlab.models import VulnerabilityClass

from _helpers import load_fixture


def parse(name: str):
    return AsanParser().parse(load_fixture("asan", name))


def test_heap_buffer_overflow() -> None:
    finding = parse("heap_buffer_overflow.txt")
    assert finding is not None
    assert finding.error_type == "heap-buffer-overflow"
    assert finding.vulnerability_class is VulnerabilityClass.HEAP_BUFFER_OVERFLOW
    assert finding.access_type == "write"
    assert finding.access_size == 1
    assert finding.fault_address == "0x602000000011"
    assert finding.thread_id == 0
    assert finding.region_size == 16
    assert len(finding.crash_stack) == 4
    assert finding.crash_stack[0].function == "heap_overflow"
    assert finding.crash_stack[0].file.endswith("target_demo.c")
    assert finding.crash_stack[0].line == 39
    assert len(finding.alloc_stack) == 3
    assert finding.alloc_stack[1].function == "heap_overflow"
    assert finding.summary is not None
    assert "heap-buffer-overflow" in finding.summary
    assert finding.is_specific


def test_use_after_free_has_free_and_alloc_stacks() -> None:
    finding = parse("use_after_free.txt")
    assert finding is not None
    assert finding.error_type == "heap-use-after-free"
    assert finding.vulnerability_class is VulnerabilityClass.USE_AFTER_FREE
    assert finding.access_type == "read"
    assert finding.access_size == 1
    assert len(finding.crash_stack) == 3
    assert len(finding.free_stack) == 3
    assert len(finding.alloc_stack) == 3
    assert finding.free_stack[0].function == "free"
    assert finding.alloc_stack[0].function == "malloc"
    assert finding.region_size == 32


def test_double_free() -> None:
    finding = parse("double_free.txt")
    assert finding is not None
    assert finding.error_type == "attempting double-free"
    assert finding.vulnerability_class is VulnerabilityClass.DOUBLE_FREE
    assert finding.thread_id == 0
    assert finding.fault_address == "0x602000000010"
    assert len(finding.crash_stack) == 3
    assert len(finding.free_stack) == 3
    assert len(finding.alloc_stack) == 3
    assert finding.region_size == 24


def test_stack_buffer_overflow_does_not_duplicate_frame_section() -> None:
    finding = parse("stack_buffer_overflow.txt")
    assert finding is not None
    assert finding.error_type == "stack-buffer-overflow"
    assert finding.vulnerability_class is VulnerabilityClass.STACK_BUFFER_OVERFLOW
    assert finding.access_type == "write"
    assert finding.access_size == 64
    assert len(finding.crash_stack) == 3
    assert finding.crash_stack[0].function == "stack_overflow"
    assert finding.region is not None and "stack" in finding.region


def test_segv_is_not_a_specific_class() -> None:
    finding = parse("segv_null.txt")
    assert finding is not None
    assert finding.error_type == "SEGV"
    assert finding.vulnerability_class is VulnerabilityClass.NULL_POINTER_DEREFERENCE
    assert finding.access_type == "write"
    assert finding.access_size is None
    assert finding.fault_address == "0x000000000000"
    assert finding.is_specific is False
    assert len(finding.crash_stack) == 3


def test_global_buffer_overflow() -> None:
    finding = parse("global_buffer_overflow.txt")
    assert finding is not None
    assert finding.vulnerability_class is VulnerabilityClass.GLOBAL_BUFFER_OVERFLOW
    assert finding.access_size == 4
    assert finding.region is not None and "global variable" in finding.region


def test_leak_report_is_parsed_but_not_a_crash_class() -> None:
    finding = parse("leak_only.txt")
    assert finding is not None
    assert finding.sanitizer == "LeakSanitizer"
    assert finding.vulnerability_class is VulnerabilityClass.UNKNOWN
    assert finding.is_specific is False


def test_missing_report_returns_none() -> None:
    parser = AsanParser()
    assert parser.parse("") is None
    assert parser.parse("ordinary program output\n") is None


def test_multiple_reports_are_returned_in_order() -> None:
    text = load_fixture("asan", "heap_buffer_overflow.txt") + load_fixture(
        "asan", "use_after_free.txt"
    )
    findings = AsanParser().parse_all(text)
    assert len(findings) == 2
    assert [item.error_type for item in findings] == [
        "heap-buffer-overflow",
        "heap-use-after-free",
    ]
    assert AsanParser().parse(text).error_type == "heap-buffer-overflow"


def test_raw_output_path_is_attached() -> None:
    finding = AsanParser().parse(
        load_fixture("asan", "heap_buffer_overflow.txt"), raw_output_path="/tmp/asan.txt"
    )
    assert finding is not None and finding.raw_output_path == "/tmp/asan.txt"


def test_error_class_mapping() -> None:
    assert classify_asan_error("heap-buffer-overflow") is VulnerabilityClass.HEAP_BUFFER_OVERFLOW
    assert classify_asan_error("heap-use-after-free") is VulnerabilityClass.USE_AFTER_FREE
    assert classify_asan_error("stack-use-after-scope") is VulnerabilityClass.USE_AFTER_SCOPE
    assert classify_asan_error("attempting double-free") is VulnerabilityClass.DOUBLE_FREE
    assert classify_asan_error("alloc-dealloc-mismatch (operator new [] vs free)") is (
        VulnerabilityClass.INVALID_FREE
    )
    assert classify_asan_error("something-new") is VulnerabilityClass.UNKNOWN
