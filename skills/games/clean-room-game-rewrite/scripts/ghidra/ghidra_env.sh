# Sourced by run_recovery.sh and apply_names.sh (POSIX sh). Finds Ghidra and a JDK it accepts, and
# defines small helpers. After sourcing: GHIDRA_HOME, H (analyzeHeadless), JAVA_HOME (exported),
# GHIDRA_VERSION, JAVA_MIN.
#   GHIDRA_HOME  honoured if set; else Homebrew (`brew --prefix ghidra`), ghidraRun/analyzeHeadless on PATH,
#                /opt/ghidra*, /usr/share/ghidra, ~/ghidra_*.
#   JAVA_HOME    honoured if its java is >= application.java.min of that Ghidra (25 for 12.2, 21 for 12.1);
#                else /usr/libexec/java_home (macOS), Homebrew openjdk kegs, /usr/lib/jvm/*, java on PATH.

die() { echo "ERROR: $*" >&2; exit 2; }
note() { echo "$*" >&2; }

_real() { realpath "$1" 2>/dev/null || readlink -f "$1" 2>/dev/null || echo "$1"; }

# absolute, normalised path of a directory that may not exist yet (its parent is created)
abs_dir() {
  case "$1" in /*) _p="$1" ;; *) _p="$PWD/$1" ;; esac
  mkdir -p "$_p" && (cd "$_p" && pwd -P)
}

_ghidra_ok() { [ -n "$1" ] && [ -x "$1/support/analyzeHeadless" ]; }

find_ghidra() {
  if [ -n "${GHIDRA_HOME:-}" ]; then
    _ghidra_ok "$GHIDRA_HOME" || die "GHIDRA_HOME=$GHIDRA_HOME has no support/analyzeHeadless"
    return 0
  fi
  _bp=""; command -v brew >/dev/null 2>&1 && _bp="$(brew --prefix ghidra 2>/dev/null || true)"
  for _c in "${_bp:+$_bp/libexec}" /opt/homebrew/opt/ghidra/libexec /usr/local/opt/ghidra/libexec \
            /home/linuxbrew/.linuxbrew/opt/ghidra/libexec; do
    _ghidra_ok "$_c" && { GHIDRA_HOME="$_c"; return 0; }
  done
  for _t in ghidraRun analyzeHeadless; do
    _w="$(command -v "$_t" 2>/dev/null || true)"; [ -n "$_w" ] || continue
    _d="$(dirname "$(_real "$_w")")"
    for _c in "$_d" "$_d/.." "$_d/../libexec"; do
      _ghidra_ok "$_c" && { GHIDRA_HOME="$(cd "$_c" && pwd)"; return 0; }
    done
  done
  for _c in /opt/ghidra* /usr/share/ghidra /usr/local/ghidra* "$HOME"/ghidra_*; do
    _ghidra_ok "$_c" && GHIDRA_HOME="$_c"     # last match = highest version when names sort
  done
  [ -n "${GHIDRA_HOME:-}" ] || die "Ghidra not found. Install it (macOS: brew install ghidra; Linux: unzip a release from github.com/NationalSecurityAgency/ghidra/releases) and set GHIDRA_HOME to the dir containing support/analyzeHeadless"
}

_java_major() {  # major version of <java_home>/bin/java, empty if it does not run
  [ -x "$1/bin/java" ] || return 0
  # macOS /usr/bin/java is a stub that can hang (install prompt) when no JDK is registered; java_home covers it
  [ "$(uname -s)" = Darwin ] && [ "$(_real "$1/bin/java")" = /usr/bin/java ] && return 0
  "$1/bin/java" -version 2>&1 | sed -n 's/.*version "\([0-9][0-9]*\).*/\1/p' | head -1
}

_java_fits() { _m="$(_java_major "$1")"; [ -n "$_m" ] && [ "$_m" -ne 1 ] && [ "$_m" -ge "$JAVA_MIN" ]; }

find_java() {
  JAVA_MIN="$(sed -n 's/^application\.java\.min=//p' "$GHIDRA_HOME/Ghidra/application.properties" 2>/dev/null | tr -dc 0-9)"
  [ -n "$JAVA_MIN" ] || JAVA_MIN=21
  if [ -n "${JAVA_HOME:-}" ]; then
    _java_fits "$JAVA_HOME" && return 0
    note "warning: JAVA_HOME=$JAVA_HOME is not a JDK >= $JAVA_MIN (Ghidra $GHIDRA_VERSION needs it); searching for another"
  fi
  JAVA_HOME=""
  if [ -x /usr/libexec/java_home ]; then
    _c="$(/usr/libexec/java_home -v "$JAVA_MIN+" 2>/dev/null || true)"
    [ -n "$_c" ] && _java_fits "$_c" && { JAVA_HOME="$_c"; return 0; }
  fi
  _bp=""; command -v brew >/dev/null 2>&1 && _bp="$(brew --prefix 2>/dev/null || true)"
  for _p in ${_bp:+"$_bp"} /opt/homebrew /usr/local /home/linuxbrew/.linuxbrew; do
    for _k in "$_p"/opt/openjdk@* "$_p"/opt/openjdk; do
      for _c in "$_k/libexec/openjdk.jdk/Contents/Home" "$_k/libexec"; do
        _java_fits "$_c" && { JAVA_HOME="$_c"; return 0; }
      done
    done
  done
  for _c in /usr/lib/jvm/* /Library/Java/JavaVirtualMachines/*/Contents/Home; do
    _java_fits "$_c" && { JAVA_HOME="$_c"; return 0; }
  done
  if command -v java >/dev/null 2>&1 && ! { [ "$(uname -s)" = Darwin ] && [ "$(_real "$(command -v java)")" = /usr/bin/java ]; }; then
    _c="$(java -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java\.home = //p' | head -1)"
    [ -n "$_c" ] && _java_fits "$_c" && { JAVA_HOME="$_c"; return 0; }
  fi
  die "no JDK >= $JAVA_MIN found (required by Ghidra $GHIDRA_VERSION at $GHIDRA_HOME). Install one (macOS: brew install openjdk@$JAVA_MIN; Linux: openjdk-$JAVA_MIN-jdk) or set JAVA_HOME"
}

find_ghidra
GHIDRA_VERSION="$(sed -n 's/^application\.version=//p' "$GHIDRA_HOME/Ghidra/application.properties" 2>/dev/null)"
H="$GHIDRA_HOME/support/analyzeHeadless"
find_java
export GHIDRA_HOME JAVA_HOME

# Run analyzeHeadless with all output in <log>; die loudly if it fails or a script errors.
# Usage: run_headless <log> <analyzeHeadless args...>
run_headless() {
  _log="$1"; shift
  note "Ghidra $GHIDRA_VERSION, JDK $(_java_major "$JAVA_HOME") at $JAVA_HOME; log: $_log"
  _rc=0; "$H" "$@" > "$_log" 2>&1 || _rc=$?
  # analyzeHeadless exits 0 even when a -postScript throws, so also scan the log
  if [ "$_rc" -ne 0 ] || grep -qE 'SCRIPT ERROR|Exception in thread|REPORT: Import failed|ERROR Abort due to Headless analyzer error' "$_log"; then
    note "ERROR: Ghidra headless run failed (exit $_rc). From $_log:"
    if grep -qE 'ERROR|Exception' "$_log"; then grep -E 'ERROR|Exception|Caused by' "$_log" | head -10 >&2
    else tail -15 "$_log" >&2; fi
    exit 1
  fi
}

# Summary lines printed by the .java scripts (RECOVER NAMES PTRTARGETS ORPHANS CODEGAPS NONEXEC COVERAGE EXPORT LISTING)
summary() {
  grep -E '> (OPTIONS|RECOVER|NAMES|UNREFREGIONS?|PTRTARGETS|ORPHANS|CODEGAPS|NONEXEC|COVERAGE|EXPORT|LISTING) ' "$1" | sed 's/.*> //; s/ (GhidraScript).*//'
}

# Refuse to wipe a non-empty directory this tooling did not create (marker file), unless FORCE=1.
# Usage: guard_dir <dir> <marker> <what>
guard_dir() {
  [ -d "$1" ] || return 0
  [ -z "$(ls -A "$1" 2>/dev/null)" ] && return 0
  [ -f "$1/$2" ] && return 0
  [ "${FORCE:-0}" = 1 ] && return 0
  die "$3 '$1' exists, is not empty and was not created by these scripts (no $2). Refusing to delete it; pick another path or set FORCE=1"
}
