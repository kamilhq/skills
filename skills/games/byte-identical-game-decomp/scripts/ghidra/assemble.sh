#!/bin/sh
# Assemble x86-32 instruction lines with Ghidra's assembler (AssembleLines.java) in a throw-away project
# that holds only a 16-byte dummy program of language x86:LE:32:default - no original binary involved.
# Usage: assemble.sh <in.tsv> <out.tsv> [choose]      (formats: see AssembleLines.java)
# Exit: 0 ran (per-line errors are reported in out.tsv), 1 Ghidra failure, 2 bad arguments / no Ghidra.
set -eu
[ $# -ge 2 ] || { sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/ghidra_env.sh"
IN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUTD="$(cd "$(dirname "$2")" && pwd)"; OUT="$OUTD/$(basename "$2")"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ghidra_asm.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT INT TERM
printf '\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220' > "$TMP/dummy.bin"
mkdir "$TMP/proj"
run_headless "$TMP/log.txt" "$TMP/proj" asm -import "$TMP/dummy.bin" -noanalysis \
  -processor x86:LE:32:default -cspec windows -loader BinaryLoader \
  -scriptPath "$HERE" -postScript AssembleLines.java "$IN" "$OUT" ${3:+"$3"} -deleteProject
grep -E '> ASSEMBLE ' "$TMP/log.txt" | sed 's/.*> //; s/ (GhidraScript).*//'
