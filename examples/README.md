# Sample targets

Two local targets are provided. Both are intentionally buggy and exist only
for defensive crash-triage research.

## Real ASan/GDB target (Linux/macOS)

Requires a C compiler with ASan support.

```sh
cd examples
make          # ./target
make asan     # ./target_asan
```

Start with the plain build, then repeat the same input with the ASan build:

```sh
# stdin delivery
crashlab run --binary ./target --input ../corpus/02_heap_overflow.bin --timeout 5

# repeat with ASan and capture stderr evidence
crashlab run --binary ./target_asan --input ../corpus/02_heap_overflow.bin \
  --timeout 5 --asan-options abort_on_error=1:symbolize=1

# or analyze a saved separately-captured ASan report
crashlab analyze --results results --asan-dir ./asan-logs
```

Input modes:

| First byte | Bug |
|---|---|
| `N` | normal path |
| `H` | one-byte heap overflow |
| `U` | use-after-free read |
| `D` | double free |
| `S` | stack buffer overflow |
| `P` | null-pointer write |
| `T` | sleeps forever (timeout path) |

## Portable smoke target (any host)

`examples/synthetic_target.py` requires no compiler. It reproduces the runner,
signal normalization, classification, and report pipeline, but it is **not** a
real memory-safety test target:

```sh
python examples/synthetic_target.py corpus/02_heap_overflow.bin
python -m crashlab run --binary python --binary-arg examples/synthetic_target.py \
  --input-mode file --input corpus/02_heap_overflow.bin --timeout 5
```

Modes `H/U/D/S/P` terminate with a real POSIX signal where available and with a
simulated canonical NTSTATUS on Windows. Mode `A` writes a realistic
AddressSanitizer report to stderr and exits 1, which exercises the ASan parser,
confirmation logic, and both report writers without needing an instrumented
build.

## ASan runtime

On Linux, ASan is normally linked into the build (`-fsanitize=address`). If you
use a dynamically loaded runtime instead, pass it explicitly:

```sh
crashlab run --binary ./target --input ./case.bin \
  --preload /usr/lib/x86_64-linux-gnu/libasan.so.8
```

`LD_PRELOAD` is a POSIX feature. On Windows the value is recorded in the run
manifest but not applied; use a Windows debugger/sanitizer stack separately.
