# RuntimeX — Unified Memory-Safety Scanner & Crash Triage Toolkit

**RuntimeX** unifies active runtime heap instrumentation with automated crash triage into a single, cohesive security toolkit:
1. **HeapSentry**: Active runtime memory-safety detection via custom C dynamic interposition (`LD_PRELOAD`), catching heap buffer overflows (`0xFEEDFACEDEADBEEF` red-zone canaries), double-frees (512-slot quarantine ring buffer), use-after-free writes (`0xDD` memory poisoning), and leak walks at exit without binary recompilation.
2. **CrashLab**: Automated crash triage, signal monitoring (`SIGSEGV`, `SIGABRT`, `SIGBUS`, etc.), GDB symbolication, faulting instruction disassembly, register dumps, ASan/UBSan report parsing, and normalized stack signature deduplication.
3. **Unified Dashboard**: A single interactive, dark-themed HTML report and JSON summary correlating active heap corruptions with debugger call stacks.

---

## ⚡ Quickstart — Run Everything in One Command

### 1. Unified Corpus Scan (HeapSentry + CrashLab)
Run both engines in parallel against your target binary and a test corpus (a directory containing multiple test input files):
```bash
./runtimex scan examples/target --input-dir corpus --workers 4 --out runtimex_out
```
*Or using the shell script:*
```bash
./runtimex.sh examples/target corpus runtimex_out
```

> **Note:** A **corpus** is a directory of test input files (valid cases, edge cases, and crash triggers). You can also test a **single file** using `--input <file>` or test a binary without inputs.

### 2. Testing Your Own Program
To test any compiled C/C++ program:
```bash
# 1. Compile with debug symbols (-g)
gcc -g -O0 your_program.c -o your_program

# 2. Run RuntimeX (single input, corpus, or standalone)
./runtimex scan ./your_program --input-dir corpus/ --out my_results
# Or single input:
./runtimex scan ./your_program --input input.bin --out my_results
```

Output:
```text
============================================================
 RuntimeX Unified Memory-Safety & Crash Triage Pipeline
 Target:  examples/target
 Mode:    Corpus (corpus)
 Workers: 4  |  Timeout: 5.0s  |  GDB: Enabled
============================================================

[Phase 1/3] Running HeapSentry Active Canary & Quarantine Detection...
  [1/8] 02_heap_overflow.bin — 1 critical, 2 medium
  [2/8] 04_double_free.bin   — 1 critical, 1 medium
  [3/8] 07_null_deref.bin     — 1 high
  ...

[Phase 2/3] Running CrashLab Signal Monitoring & GDB Triage...

[Phase 3/3] Generating Unified RuntimeX Report...

============================================================
 RuntimeX Execution Summary
============================================================
 HeapSentry Violations:  14 (2 critical, 3 high)
   • [CRITICAL] heap_buffer_overflow @ 0x5e0748b9d300
   • [CRITICAL] double_free @ 0x5a63376b9300
   • [MEDIUM]   memory_leak (12 blocks)
 CrashLab Crash Groups:  2 unique signatures (3 total crashes)
   • [CONFIRMED_VULNERABILITY] double-free (x2) -> signature a6ff66efe94b6524
   • [CRASH] null-pointer-dereference (x1) -> signature 7507755df97342e9
------------------------------------------------------------
 📊 HTML Report: file:///.../runtimex_out/unified_report.html
 📄 JSON Report: file:///.../runtimex_out/unified_report.json
============================================================
```

### 2. View the Unified Report
Open the generated report in any web browser:
```bash
open runtimex_out/unified_report.html
```

### 3. Check System Capabilities
Verify your GDB, ASan, C compiler, and detection runtime:
```bash
./runtimex doctor
```

---

## 📊 Unified Report Highlights

The unified HTML report (`unified_report.html`) is completely self-contained (inline CSS & JS, zero external dependencies) and includes:
- **Executive Threat Level**: Dynamic risk indicator (`CRITICAL RISK`, `HIGH RISK`, `MEDIUM RISK`, `CLEAN`) with executive metric cards.
- **Cross-Engine Correlation**: Table correlating active HeapSentry red-zone/quarantine detections with CrashLab GDB debugger signals.
- **Interactive Finding Cards**:
  - 💥 **Exploit Impact**: Real-world exploit scenarios, CVE analogies, and severity justifications.
  - 🛠️ **Remediation Guide**: Clear, actionable instructions for developers to fix the flaw.
  - 💻 **Code Patterns**: Side-by-side ❌ Vulnerable vs ✅ Safe C/C++ code comparisons.
  - 🔍 **Raw Evidence**: Allocation IDs, pointers, memory addresses, and canary byte stamps.
- **Deduplicated Crash Groups**:
  - GDB call stacks with frame numbers, function symbols, source files, and lines.
  - Faulting assembly instructions and register state dumps.
  - Exact copyable reproduction commands.
- **Allocation Lifecycle Timeline**: Tracking every buffer from allocation to its final fate (`freed`, `leaked`, `overflowed`, `double_freed`).
- **Low-Level Hook Event Stream**: Chronological event logs with nanosecond deltas and canary values (`0xFEEDFACEDEADBEEF`).
- **Memory-Safety Matrix**: Visual diagnostic cards for Heap Buffer Overflow, Double-Free, Use-After-Free, and Memory Leaks.

---

## 🛠️ Individual Sub-Tools

RuntimeX also allows you to invoke each engine independently:

### HeapSentry Alone
```bash
# Scan single input
PYTHONPATH=src python3 -m heapsentry scan ./your_binary --input input.bin --out hs_out

# Scan entire corpus
PYTHONPATH=src python3 -m heapsentry scan ./your_binary --input-dir corpus/ --workers 4 --out hs_out
```

### CrashLab Alone
```bash
# Run GDB crash triage across corpus
PYTHONPATH=src python3 -m crashlab run --binary ./your_binary --input-dir corpus/ --workers 4 --out cl_out

# Re-analyze saved runs
PYTHONPATH=src python3 -m crashlab analyze --results cl_out/ --report-html cl_out/report.html
```

### Regenerate Unified Report from Existing Runs
```bash
PYTHONPATH=src python3 src/unified_report.py \
  --heapsentry-dir runtimex_out/heapsentry \
  --crashlab-dir runtimex_out/crashlab \
  --binary examples/target \
  --out runtimex_out/unified_report.html \
  --out-json runtimex_out/unified_report.json
```

---

## 🧪 Testing & Validation

Run the full automated test suite (122+ tests):
```bash
PYTHONPATH=src pytest tests/
```

Build the detection dynamic library:
```bash
make -f Makefile.heapsentry library
```

---

## 📁 Repository Structure

```text
RuntimeX/
├── runtimex                         # Main executable CLI wrapper
├── runtimex.sh                      # One-command bash runner
├── src/
│   ├── runtimex/                    # Unified orchestrator & CLI
│   │   ├── cli.py                   # runtimex CLI entry point
│   │   └── orchestrator.py          # Coordinates HeapSentry + CrashLab
│   ├── unified_report.py            # Unified HTML & JSON report generator
│   ├── heapsentry/                  # Active memory-safety engine (LD_PRELOAD)
│   └── crashlab/                    # Crash triage & GDB analysis engine
├── runtime/                         # C allocator hooks, canaries & quarantine
├── corpus/                          # Test suite inputs for memory-safety flaws
├── examples/                        # Sample targets (synthetic & demo C binaries)
└── tests/                           # 122+ automated pytest test cases
```

---

## 🛡️ License

MIT License. Designed for authorized defensive research, fuzzing triage, and memory-safety analysis.
