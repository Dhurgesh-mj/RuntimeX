# Sample Vulnerability Targets

A collection of standalone, controlled C test targets demonstrating specific memory-safety vulnerability classes. These samples are designed for testing and observing RuntimeX, HeapSentry, and CrashLab in a local environment.

---

## 📦 Available Vulnerability Samples

| File | Target Binary | Vulnerability Class | Severity | Detection Mechanism |
|---|---|---|---|---|
| [`heap_overflow_demo.c`](heap_overflow_demo.c) | `heap_overflow_demo` | CWE-122 (Heap Buffer Overflow) | `CRITICAL` | 16-byte right red-zone canary (`0xFEEDFACEDEADBEEF`) |
| [`use_after_free_demo.c`](use_after_free_demo.c) | `use_after_free_demo` | CWE-416 (Use-After-Free Write) | `HIGH` | Post-free memory poisoning (`0xDD`) |
| [`double_free_demo.c`](double_free_demo.c) | `double_free_demo` | CWE-415 (Double Free) | `CRITICAL` | 512-slot quarantine ring buffer |
| [`memory_leak_demo.c`](memory_leak_demo.c) | `memory_leak_demo` | CWE-401 (Memory Leak) | `MEDIUM` | Exit-time hash table walk (`atexit`) |
| [`integer_overflow_demo.c`](integer_overflow_demo.c) | `integer_overflow_demo` | CWE-190 -> CWE-122 | `CRITICAL` | Arithmetic wrap -> undersized malloc |
| [`target_demo.c`](target_demo.c) | `target` | Multi-bug corpus test target | `VARIOUS` | First byte mode switch (`H/U/D/S/P/T`) |

---

## 🔨 How to Build

Build all targets with debug symbols:
```bash
cd examples
make all
```

Or build with AddressSanitizer:
```bash
make asan
```

Clean build products:
```bash
make clean
```

---

## 🚀 How to Test with RuntimeX

From the repository root:

```bash
# 1. Test Heap Buffer Overflow
./runtimex scan examples/heap_overflow_demo --out results_heap

# 2. Test Double Free
./runtimex scan examples/double_free_demo --out results_df

# 3. Test Use-After-Free
./runtimex scan examples/use_after_free_demo --out results_uaf

# 4. Test Memory Leak
./runtimex scan examples/memory_leak_demo --out results_leak

# 5. Test Integer Overflow leading to Heap Overflow
./runtimex scan examples/integer_overflow_demo --out results_int
```

Open the generated report for any run:
```bash
open results_heap/unified_report.html
```
