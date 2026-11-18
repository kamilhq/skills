#!/bin/sh
# Apply a names file to a Ghidra project made by run_recovery.sh and re-export every function.
#
# Usage: apply_names.sh <binary> <project_dir> <names.json> <out_dir>
#   <binary>       the binary run_recovery.sh imported (only its file name is used: it is the program
#                  name inside the project, e.g. Praetorians.exe)
#   <project_dir>  the project_dir run_recovery.sh printed (default there: <out_dir>/../ghidra_<stem>)
#   <names.json>   UTF-8 JSON, either a flat map or a list:
#                    {"0x401000": "WinMain", "0x401230": "CUnit::Update", "0x401300": "CUnit::~CUnit"}
#                    [{"address": "0x401000", "name": "WinMain"}, ...]
#                  "Class::Method" puts the function in class Class (created if new); "A::B::m" makes A a
#                  namespace and B a class. Addresses must be function entry points.
#   <out_dir>      a NEW export dir (same layout as run_recovery.sh: functions/, index.json, ...)
# The names are saved into the project, so later passes (and re-runs of this script) see them; re-running
# with a newer names file is fine. run_recovery.sh refuses to wipe a project named this way unless FORCE=1.
# Env: GHIDRA_HOME, JAVA_HOME (auto-detected, see ghidra_env.sh); FORCE=1 to overwrite a foreign out_dir.
# Exit: 0 all names applied; 3 exported, but some names failed (see <out_dir>/name_failures.txt);
#       1 Ghidra/script failure, including a names file that is unreadable, of the wrong shape, or of
#       which nothing could be applied (nothing is exported then); 2 bad arguments / Ghidra or JDK missing.
set -eu
[ $# -eq 4 ] || { sed -n '2,/^set -eu/p' "$0" | sed 's/^# \{0,1\}//; /^set -eu/d' >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/ghidra_env.sh"

PROG="$(basename "$1")"; PROJ="$2"; NAMES="$3"; OUT="$4"
[ -d "$PROJ" ] || die "project_dir not found: $PROJ"
PROJ="$(cd "$PROJ" && pwd -P)"
set -- "$PROJ"/*.gpr
[ $# -eq 1 ] && [ -f "$1" ] || die "expected exactly one .gpr Ghidra project file in $PROJ (found: $*)"
PNAME="$(basename "$1" .gpr)"
[ -f "$NAMES" ] || die "names file not found: $NAMES"
NAMES="$(cd "$(dirname "$NAMES")" && pwd -P)/$(basename "$NAMES")"

guard_dir "$OUT" .run_recovery out_dir
rm -rf "$OUT"
OUT="$(abs_dir "$OUT")"
[ "$OUT" != "$PROJ" ] || die "out_dir and project_dir must differ"
case "$OUT/" in "$PROJ"/*) die "out_dir must not be inside project_dir" ;; esac
echo "apply_names $NAMES" > "$OUT/.run_recovery"
EMPTY="$OUT/.empty_addresses.txt"; : > "$EMPTY"
LOG="$OUT/apply_names.log"

run_headless "$LOG" "$PROJ" "$PNAME" -process "$PROG" -noanalysis -scriptPath "$HERE" \
  -postScript RecoverAndExport.java "$EMPTY" "$OUT" "$NAMES"

summary "$LOG"
grep -qE '> EXPORT written=' "$LOG" || { note "ERROR: no EXPORT line in $LOG (is '$PROG' the program in $PROJ?)"; tail -15 "$LOG" >&2; exit 1; }
printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$NAMES" >> "$PROJ/.names_applied"
echo "out_dir: $OUT"
if [ -s "$OUT/name_failures.txt" ]; then
  note "WARNING: $(wc -l < "$OUT/name_failures.txt" | tr -d ' ') names were not applied; first ones ($OUT/name_failures.txt):"
  head -10 "$OUT/name_failures.txt" >&2
  exit 3
fi
