#!/bin/sh
# Report what the clean-room rewrite needs, per step, with install hints for this OS (macOS/Homebrew,
# Debian/Ubuntu apt, Fedora dnf, Arch pacman). The analysis is Python 3 stdlib plus Ghidra (and the JDK Ghidra
# runs on); the JavaScript ports (scripts/js) need Node.js >= 20 instead of Python. The oracle and the rewrite
# need Wine on macOS/Linux (to run the game and the Windows build tools) and a toolchain for the language the
# user picks at step 6 (references/toolchains.md). Nothing else is installed or downloaded.
# Usage: sh check_deps.sh
# Status: [ok] present; [MISSING] needed by that step; [opt] optional; [env] found, but the environment
# variable that raw Ghidra commands need is not set - the "export" lines printed at the end fix that.
# Exit code 0 always; read the table (the last lines summarise what is missing).
# Env honoured: GHIDRA_HOME, JAVA_HOME, MSVC_PREFIX, WINEPREFIX.

ok()   { printf '  [ok]      %-22s %s\n' "$1" "$2"; }
miss() { printf '  [MISSING] %-22s %s\n' "$1" "$2"; MISSING="${MISSING:+$MISSING, }$1"; }
opt()  { printf '  [opt]     %-22s %s\n' "$1" "$2"; }
envw() { printf '  [env]     %-22s %s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }
ver()  { "$@" 2>&1 | head -1; }
MISSING=""; EXPORTS=""

OS=$(uname -s)
if [ "$OS" = Darwin ]; then PM=brew
elif have apt-get; then PM=apt
elif have dnf; then PM=dnf
elif have pacman; then PM=pacman
else PM=other; fi
[ "$OS" = Darwin ] && ! have brew && PM=brew-missing
[ -n "${CHECK_DEPS_PM:-}" ] && PM=$CHECK_DEPS_PM     # testing aid: brew|apt|dnf|pacman|other
# hint <brew> <apt> <dnf> [pacman]: the install command for this host
hint() {
  case "$PM" in
    brew) echo "brew install $1" ;;
    brew-missing) echo "install Homebrew (https://brew.sh), then: brew install $1" ;;
    apt) echo "sudo apt install $2" ;;
    dnf) echo "sudo dnf install $3" ;;
    pacman) echo "sudo pacman -S ${4:-$2}" ;;
    *) echo "install '$2' with your package manager" ;;
  esac
}
brew_prefix() { have brew && brew --prefix "$@" 2>/dev/null; }

# py_ge <python> <major> <minor>: true if that interpreter runs and is at least that version
py_ge() { "$1" -c "import sys; sys.exit(0 if sys.version_info[:2] >= ($2, $3) else 1)" 2>/dev/null; }
py_ver() { "$1" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null; }

echo "Host: $OS (package hints for: $PM)"
echo "Core (every phase)"
if have python3 && py_ge python3 3 9; then ok python3 "$(py_ver python3) (stdlib only for the scripts and decoders)"
elif have python3; then miss python3 "found $(py_ver python3), need >= 3.9: $(hint python python3 python3 python)"
else miss python3 "$(hint python python3 python3 python)"; fi
# node_ge <major>: true if node runs and is at least that major version
node_ge() { node -e "process.exit(+process.versions.node.split('.')[0] >= $1 ? 0 : 1)" 2>/dev/null; }
if have node && node_ge 20; then
  ok node "$(node --version) (optional JavaScript ports in scripts/js, same results; zlib $(node -p process.versions.zlib))"
elif have node; then opt node "found $(node --version), the JavaScript ports need >= 20: $(hint node nodejs nodejs nodejs)"
else opt node "only for the JavaScript ports in scripts/js (the Python scripts do not need it): $(hint node nodejs nodejs nodejs)"; fi
echo "Steps 1-2 - intake, inventory, format readers"
ok "(nothing extra)" "scripts/inno.py extracts GOG Inno Setup installers; readers are stdlib Python"

echo "Step 3 - analysis: code recovery and naming (analysts only)"
# Ghidra: same search order as ghidra/ghidra_env.sh (used by run_recovery.sh / apply_names.sh)
gh_ok() { [ -n "$1" ] && [ -x "$1/support/analyzeHeadless" ]; }
GH=""; GH_FROM=""
if [ -n "${GHIDRA_HOME:-}" ]; then
  if gh_ok "$GHIDRA_HOME"; then GH="$GHIDRA_HOME"; GH_FROM=env; else GH_BAD="$GHIDRA_HOME"; fi
fi
if [ -z "$GH" ]; then
  BP=$(brew_prefix ghidra)
  for c in ${BP:+"$BP/libexec"} /opt/homebrew/opt/ghidra/libexec /usr/local/opt/ghidra/libexec /home/linuxbrew/.linuxbrew/opt/ghidra/libexec; do
    gh_ok "$c" && { GH="$c"; break; }
  done
fi
if [ -z "$GH" ]; then
  for t in ghidraRun analyzeHeadless; do
    w=$(command -v "$t" 2>/dev/null) || continue
    d=$(dirname "$(realpath "$w" 2>/dev/null || readlink -f "$w" 2>/dev/null || echo "$w")")
    for c in "$d" "$d/.." "$d/../libexec"; do gh_ok "$c" && { GH=$(cd "$c" && pwd); break 2; }; done
  done
fi
if [ -z "$GH" ]; then
  for c in /opt/ghidra* /usr/share/ghidra /usr/local/ghidra* "$HOME"/ghidra_*; do gh_ok "$c" && GH="$c"; done
fi
JAVA_MIN=21
if [ -n "$GH" ]; then
  GV=$(sed -n 's/^application\.version=//p' "$GH/Ghidra/application.properties" 2>/dev/null)
  JM=$(sed -n 's/^application\.java\.min=//p' "$GH/Ghidra/application.properties" 2>/dev/null | tr -dc 0-9)
  [ -n "$JM" ] && JAVA_MIN=$JM
  case "$GV" in 12.*) note="" ;; *) note=" (the skill was tested with 12.x)" ;; esac
  if [ "$GH_FROM" = env ]; then ok ghidra "$GV at $GH, needs JDK >= $JAVA_MIN$note"
  else envw ghidra "$GV at $GH, needs JDK >= $JAVA_MIN$note; $( [ -n "${GH_BAD:-}" ] && echo "GHIDRA_HOME=$GH_BAD has no support/analyzeHeadless" || echo "GHIDRA_HOME not set")"; EXPORTS="$EXPORTS
export GHIDRA_HOME='$GH'"; fi
else
  if [ "$PM" = brew ]; then GHH="brew install ghidra  (formula, not a cask; pulls in the JDK it needs)"
  else GHH="unzip a release from https://github.com/NationalSecurityAgency/ghidra/releases and set GHIDRA_HOME to the folder holding support/analyzeHeadless"; fi
  miss ghidra "$GHH${GH_BAD:+ (GHIDRA_HOME=$GH_BAD has no support/analyzeHeadless)}"
fi

# JDK >= Ghidra's application.java.min (25 for Ghidra 12.2, 21 for 12.1)
java_major() { [ -x "$1/bin/java" ] && "$1/bin/java" -version 2>&1 | sed -n 's/.*version "\([0-9][0-9]*\).*/\1/p' | head -1; }
java_fits() { m=$(java_major "$1"); [ -n "$m" ] && [ "$m" -ne 1 ] && [ "$m" -ge "$JAVA_MIN" ]; }
J=""; J_FROM=""
if [ -n "${JAVA_HOME:-}" ]; then
  if java_fits "$JAVA_HOME"; then J="$JAVA_HOME"; J_FROM=env; else J_BAD="$JAVA_HOME (java $(java_major "$JAVA_HOME"))"; fi
fi
if [ -z "$J" ] && [ -x /usr/libexec/java_home ]; then
  c=$(/usr/libexec/java_home -v "$JAVA_MIN+" 2>/dev/null) && java_fits "$c" && J="$c"
fi
if [ -z "$J" ]; then
  BP=$(brew_prefix)
  for p in ${BP:+"$BP"} /opt/homebrew /usr/local /home/linuxbrew/.linuxbrew; do
    for k in "$p"/opt/openjdk@* "$p"/opt/openjdk; do
      for c in "$k/libexec/openjdk.jdk/Contents/Home" "$k/libexec"; do java_fits "$c" && { J="$c"; break 3; }; done
    done
  done
fi
if [ -z "$J" ]; then
  for c in /usr/lib/jvm/* /Library/Java/JavaVirtualMachines/*/Contents/Home; do java_fits "$c" && { J="$c"; break; }; done
fi
if [ -z "$J" ] && have java; then
  c=$(java -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java\.home = //p' | head -1)
  [ -n "$c" ] && java_fits "$c" && J="$c"
fi
if [ -n "$J" ]; then
  if [ "$J_FROM" = env ]; then ok JDK "java $(java_major "$J") at $J (Ghidra needs >= $JAVA_MIN)"
  else envw JDK "java $(java_major "$J") at $J (Ghidra needs >= $JAVA_MIN); $( [ -n "${J_BAD:-}" ] && echo "JAVA_HOME=$J_BAD is too old" || echo "JAVA_HOME not set")"; EXPORTS="$EXPORTS
export JAVA_HOME='$J'"; fi
else
  miss JDK "need a JDK >= $JAVA_MIN for this Ghidra${J_BAD:+ (JAVA_HOME=$J_BAD is too old)}: $(hint "openjdk@$JAVA_MIN" "openjdk-$JAVA_MIN-jdk" "java-$JAVA_MIN-openjdk-devel" "jdk-openjdk")"
fi

echo "Steps 4-8 - oracle, toolchain, rewrite (the language is chosen at step 6)"
case "$OS" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) ok wine "not needed on Windows: the game and the tools run natively" ;;
  *)
    if have wine; then ok wine "$(ver wine --version) (runs the original game for the oracle, the rewrite, and MSVC)"
    else
      case "$PM" in
        brew) WH="brew install --cask wine-stable" ;;
        apt) WH="sudo apt install wine (on builds without WoW64 also: sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install wine32)" ;;
        *) WH="$(hint wine wine wine wine)" ;;
      esac
      miss wine "$WH  (runs the original game and the Windows build tools on this OS)"
    fi ;;
esac
MP="${MSVC_PREFIX:-$HOME/.wine-vs2010}"; CL=""
for c in "$MP"/drive_c/Program\ Files*/Microsoft\ Visual\ Studio/*/*/VC/Tools/MSVC/*/bin/Hostx86/x86/cl.exe \
         "$MP"/drive_c/Program\ Files*/Microsoft\ Visual\ Studio*/VC/bin/cl.exe; do
  [ -f "$c" ] && CL="$c"
done
if [ -n "$CL" ]; then ok "MSVC" "$CL (the probe; a C++ rewrite: sh scripts/msvc.sh --version)"
elif have cl.exe; then ok "MSVC" "$(command -v cl.exe)"
else opt "MSVC" "USER-SUPPLIED (licensed): builds the probe DLL (step 4) and a C++ rewrite; any MSVC that targets x86 works, under Wine in MSVC_PREFIX (default ~/.wine-vs2010, as msvc.sh) on macOS/Linux (references/toolchains.md)"; fi
if have clang; then ok clang "$(ver clang --version) (c99 libraries, the Rust gnu runtime shim)"
else opt clang "$(hint llvm clang clang clang) (only for c99 libraries and a Rust rewrite)"; fi
if have rustup; then
  if rustup target list --installed 2>/dev/null | grep -qx i686-pc-windows-gnu; then ok rust "$(ver rustc --version), target i686-pc-windows-gnu installed"
  else opt rust "$(ver rustc --version); for a Rust rewrite: rustup target add i686-pc-windows-gnu"; fi
else opt rust "only for a Rust rewrite: https://rustup.rs, then rustup target add i686-pc-windows-gnu"; fi
echo
if [ -n "$EXPORTS" ]; then
  echo "Found but not exported - paste before running raw analyzeHeadless commands (run_recovery.sh and"
  echo "apply_names.sh detect GHIDRA_HOME/JAVA_HOME themselves):$EXPORTS"
fi
if [ -n "$MISSING" ]; then echo "Missing: $MISSING  (each is needed only from the step it is listed under)"
else echo "Nothing missing."; fi
exit 0
