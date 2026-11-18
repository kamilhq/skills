#!/bin/sh
# Ask an analysed Ghidra project about addresses, read-only (no external disassembler or MCP needed).
# Usage: inspect.sh <project_dir> <binary file name, e.g. Game.exe> <0xaddr> [<0xaddr> ...]
# Prints the code unit, containing data/function and all references for each address (Inspect.java).
set -eu
[ $# -ge 3 ] || { sed -n '2,4p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/ghidra_env.sh"
PROJ="$(cd "$1" && pwd)"; PROG="$2"; shift 2
"$H" "$PROJ" "$(echo "$PROG" | sed 's/\.[^.]*$//')" -process "$PROG" -noanalysis -readOnly \
  -scriptPath "$HERE" -postScript Inspect.java "$@" 2>&1 | grep 'INSPECT' | sed 's/.*> INSPECT/INSPECT/; s/ (GhidraScript).*//'
