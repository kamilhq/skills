#!/bin/sh
# Decompile a Win32 PE (exe or dll) with complete function recovery, using Ghidra headless.
#
# Usage: run_recovery.sh <binary> <out_dir> [project_dir]
#   <out_dir>/functions/0x<addr>.c   one pseudocode file per function
#   <out_dir>/index.json             every function: address, name, size, status, callees (call graph)
#   <out_dir>/coverage_gaps.txt      executable runs >= 16 non-padding bytes in no function (0x<addr> len= nonpad=)
#   <out_dir>/codegaps_failures.txt  code-gap starts DisassembleCodeGaps could not or would not (not code) turn into functions (0x<addr> reason)
#   <out_dir>/recover_failures.txt, name_failures.txt   (empty unless addresses/names were passed)
#   <out_dir>/instructions.tsv       every disassembled instruction: address, length, function, flow, targets, text
#   <out_dir>/functions.tsv          every function: entry, name, exact (multi-range) body
#   <out_dir>/recovery.log           the full Ghidra log; the summary lines are printed at the end
#   [project_dir] the analysed Ghidra project, kept for later passes (apply_names.sh);
#                 default <out_dir>/../ghidra_<binary stem>. It holds a copy of the binary: keep it out of git.
# Relative paths are fine (they are made absolute; Ghidra rejects relative project paths).
# Re-running wipes <out_dir> and <project_dir> and starts from a fresh import. It refuses to delete a
# non-empty dir it did not create, and a project that apply_names.sh has written names into, unless FORCE=1.
#
# Pipeline (why each step exists is in references/code-recovery.md):
#   import + auto-analysis with the Aggressive Instruction Finder
#   -> UnreferencedRegions    (large relocation-free, unreferenced regions of .text: clear, mark as data)
#   -> RecoverPointerTargets  (functions only reachable through vtables / callback tables)
#   -> CreateOrphanFunctions  (disassembled code that belongs to no function)
#   -> DisassembleCodeGaps    (never-disassembled code; undecoded jump tables are left as data)
#   -> CreateOrphanFunctions  (again, for code the previous step exposed)
#   -> RemoveNonExecFunctions (functions Ghidra made from data in non-executable sections)
#   -> RecoverAndExport       (coverage report + decompile everything)
#   -> ExportListing          (instruction listing for the coverage check; no external disassembler needed)
# Env: GHIDRA_HOME (dir containing support/analyzeHeadless), JAVA_HOME (a JDK >= Ghidra's
#      application.java.min: 25 for Ghidra 12.2, 21 for 12.1) - both auto-detected when unset (ghidra_env.sh);
#      MAX_CPU (default 4); FORCE=1 to allow deleting dirs as described above.
# Exit: 0 ok; 1 Ghidra/script failure (log excerpt printed); 2 bad arguments or missing Ghidra/JDK.
set -eu
[ $# -ge 2 ] && [ $# -le 3 ] || { sed -n '2,/^set -eu/p' "$0" | sed 's/^# \{0,1\}//; /^set -eu/d' >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/ghidra_env.sh"

BIN="$1"; OUT="$2"
[ -f "$BIN" ] || die "binary not found: $BIN"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
NAME="$(basename "$BIN" | sed 's/\.[^.]*$//')"
PROJ="${3:-$(dirname "$OUT")/ghidra_$NAME}"

for d in "$OUT" "$PROJ"; do
  r="$(cd "$d" 2>/dev/null && pwd -P || true)"
  [ "$r" = / ] || [ "$r" = "$(cd "$HOME" && pwd -P)" ] && die "refusing to use '$d' ($r) as an output dir"
done
guard_dir "$OUT" .run_recovery out_dir
guard_dir "$PROJ" .run_recovery project_dir
if [ -f "$PROJ/.names_applied" ] && [ "${FORCE:-0}" != 1 ]; then
  die "project_dir '$PROJ' has names applied by apply_names.sh (last: $(tail -1 "$PROJ/.names_applied")). Re-running would discard them; use apply_names.sh to re-export, another project_dir, or FORCE=1"
fi
rm -rf "$OUT" "$PROJ"
OUT="$(abs_dir "$OUT")"; PROJ="$(abs_dir "$PROJ")"
[ "$OUT" != "$PROJ" ] || die "out_dir and project_dir must differ"
echo "$BIN" > "$OUT/.run_recovery"; echo "$BIN" > "$PROJ/.run_recovery"
printf '*\n' > "$PROJ/.gitignore"     # the project embeds the game binary: never commit it
EMPTY="$OUT/.empty_addresses.txt"; : > "$EMPTY"
LOG="$OUT/recovery.log"

run_headless "$LOG" "$PROJ" "$NAME" -import "$BIN" -scriptPath "$HERE" \
  -preScript EnableAggressiveFinder.java \
  -postScript UnreferencedRegions.java \
  -postScript RecoverPointerTargets.java \
  -postScript CreateOrphanFunctions.java \
  -postScript DisassembleCodeGaps.java \
  -postScript CreateOrphanFunctions.java \
  -postScript RemoveNonExecFunctions.java \
  -postScript RecoverAndExport.java "$EMPTY" "$OUT" \
  -postScript ExportListing.java "$OUT" \
  -max-cpu "${MAX_CPU:-4}"

grep -E '> CODEGAPS_(FAIL|REJECT) ' "$LOG" | sed 's/.*> CODEGAPS_[A-Z]* //; s/ (GhidraScript).*//' | sort -u > "$OUT/codegaps_failures.txt" || true
summary "$LOG"
grep -qE '> EXPORT written=' "$LOG" || { note "ERROR: no EXPORT line in $LOG - the export did not run"; tail -15 "$LOG" >&2; exit 1; }
[ -s "$OUT/index.json" ] || { note "ERROR: $OUT/index.json missing"; exit 1; }
echo "out_dir:     $OUT"
echo "project_dir: $PROJ (program $(basename "$BIN"); pass it to apply_names.sh)"
