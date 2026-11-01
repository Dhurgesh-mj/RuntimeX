#!/usr/bin/env bash
# ==============================================================================
# RuntimeX — Unified Memory-Safety & Crash Triage Pipeline
# Combines HeapSentry (Active LD_PRELOAD Canary/Quarantine) + CrashLab (GDB Triage)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${SCRIPT_DIR}/src:${PYTHONPATH:-}"

if [ $# -eq 0 ]; then
    python3 -m runtimex --help
    exit 0
fi

# If first arg is a known subcommand (scan, run, report, doctor), delegate directly
case "$1" in
    scan|run|report|doctor)
        exec python3 -m runtimex "$@"
        ;;
esac

# Otherwise, treat as simple quick invocation: ./runtimex.sh <binary> [input_or_dir] [out_dir]
TARGET="$1"
INPUT_ARG="${2:-corpus}"
OUT_DIR="${3:-runtimex_out}"

if [ -d "$INPUT_ARG" ]; then
    exec python3 -m runtimex scan "$TARGET" --input-dir "$INPUT_ARG" --out "$OUT_DIR" --workers 4
elif [ -f "$INPUT_ARG" ]; then
    exec python3 -m runtimex scan "$TARGET" --input "$INPUT_ARG" --out "$OUT_DIR"
else
    # Default to scanning with whatever was given
    exec python3 -m runtimex scan "$TARGET" --out "$OUT_DIR"
fi
