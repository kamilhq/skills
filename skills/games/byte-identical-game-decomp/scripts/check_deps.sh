#!/bin/sh
# Report what the byte-identical decompilation pipeline needs, per phase, with install hints for this OS
# (macOS/Homebrew, Debian/Ubuntu apt, Fedora dnf, Arch pacman). The pipeline itself is Python 3 stdlib plus
# Ghidra (and the JDK Ghidra runs on); its JavaScript ports (scripts/js) need Node.js >= 20 instead of Python. Phase 6 additionally needs the game's original compiler, which the
# user supplies, and on macOS/Linux Wine to run that compiler. Nothing else is installed or downloaded.
# Usage: sh check_deps.sh
# Status: [ok] present; [MISSING] needed by that phase; [opt] optional; [env] found, but the environment
# variable that raw Ghidra/VC6 commands need is not set - the "export" lines printed at the end fix that.
# Exit code 0 always; read the table (the last lines summarise what is missing).
# Env honoured: GHIDRA_HOME, JAVA_HOME, VC6_ROOT (the VC98 folder), WINEPREFIX, DXSDK_DIR.

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
echo "Phases 1-3 - intake, inventory, data decoding"
ok "(nothing extra)" "scripts/inno.py extracts GOG Inno Setup installers; decoders are stdlib Python"

echo "Phases 4, 5, 5b - code recovery, naming, reassembly"
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

echo "Phase 6 - matching decompilation (inputs the user supplies)"
MP="${MSVC_PREFIX:-$HOME/.wine-vs2010}"; MSVC_OK=0
for c in "$MP/drive_c/Program Files (x86)/Microsoft Visual Studio 10.0/VC/bin/cl.exe"; do
  [ -f "$c" ] && { MSVC_OK=1; ok "MSVC under Wine" "$c  (check the build: sh scripts/msvc.sh --version)"; }
done
case "$OS" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) ok wine "not needed on Windows: the compiler runs natively" ;;
  *)
    if have wine; then ok wine "$(ver wine --version) (runs the user's original cl.exe/link.exe)"
    else
      case "$PM" in
        brew) WH="brew install --cask wine-stable" ;;
        apt) WH="sudo apt install wine (on builds without WoW64 also: sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install wine32)" ;;
        *) WH="$(hint wine wine wine wine)" ;;
      esac
      miss wine "$WH  (only for phase 6: runs the original Windows compiler on this OS)"
    fi ;;
esac
# Visual C++ 6.0: every file a compile+link under Wine needs, matched case-insensitively
ipath() {  # ipath <dir> <rel/path>: print the real path, matching each component case-insensitively
  cur="$1"; rest="$2"
  while [ -n "$rest" ]; do
    comp=${rest%%/*}; [ "$comp" = "$rest" ] && rest="" || rest=${rest#*/}
    [ "$comp" = ".." ] && { cur="$cur/.."; continue; }
    hit=$(ls -a "$cur" 2>/dev/null | grep -iFx -- "$comp" | head -1)
    [ -n "$hit" ] || return 1
    cur="$cur/$hit"
  done
  printf '%s\n' "$cur"
}
WP="${WINEPREFIX:-$HOME/.wine}"
VC6=""
for c in "${VC6_ROOT:-}" "$WP/drive_c/Program Files (x86)/Microsoft Visual Studio/VC98" "$WP/drive_c/Program Files/Microsoft Visual Studio/VC98"; do
  [ -n "$c" ] && [ -n "$(ipath "$c" Bin/CL.EXE)" ] && { VC6="$c"; break; }
done
if [ -n "$VC6" ]; then
  LACK=""
  for f in Bin/CL.EXE Bin/C1.DLL Bin/C1XX.DLL Bin/C2.DLL Bin/LINK.EXE Bin/LIB.EXE Bin/CVTRES.EXE Lib/LIBCMT.LIB Lib/KERNEL32.LIB Include/WINDOWS.H; do
    [ -n "$(ipath "$VC6" "$f")" ] || LACK="$LACK $f"
  done
  PDB=$(ipath "$VC6" Bin/MSPDB60.DLL || ipath "$VC6" ../Common/MSDev98/Bin/MSPDB60.DLL)
  [ -n "$PDB" ] || LACK="$LACK MSPDB60.DLL(Bin or ../Common/MSDev98/Bin)"
  RCX=$(ipath "$VC6" Bin/RC.EXE || ipath "$VC6" ../Common/MSDev98/Bin/RC.EXE)
  if [ -n "$LACK" ]; then miss "Visual C++ 6.0" "$VC6 is incomplete, missing:$LACK"
  elif [ -z "${VC6_ROOT:-}" ]; then envw "Visual C++ 6.0" "$VC6 (compiler, linker, CRT libs, headers, MSPDB60.DLL present); VC6_ROOT not set"; EXPORTS="$EXPORTS
export VC6_ROOT='$VC6'"
  else ok "Visual C++ 6.0" "$VC6 (compiler, linker, CRT libs, headers, MSPDB60.DLL present)"; fi
  [ -n "$RCX" ] || opt "rc.exe" "not found in VC98/Bin or Common/MSDev98/Bin (needed only to rebuild resources)"
  echo "            the Rich build of this toolchain is confirmed by compiling a test program and running rich_header.py --compare (not by the cl banner)"
else
  if [ "$MSVC_OK" = 1 ]; then opt "Visual C++ 6.0" "not found (needed only for VC6-built games; an MSVC under Wine is present above)"
  else miss "original compiler" "USER-SUPPLIED (licensed): the exact compiler/linker the Rich header names (rich_header.py). For Visual C++ 6.0: install it under Wine (or copy VC98 AND Common/MSDev98) and set VC6_ROOT to the VC98 folder. Other MSVC versions (e.g. VS2010 SP1): point the build at their cl.exe/link.exe; this check only knows VC6's layout (references/matching-decomp.md)${VC6_ROOT:+; VC6_ROOT=$VC6_ROOT has no Bin/CL.EXE}"; fi
fi
if [ -n "${DXSDK_DIR:-}" ] && [ -d "$DXSDK_DIR" ]; then ok "DirectX SDK" "$DXSDK_DIR"
else opt "DirectX SDK" "set DXSDK_DIR to a period-correct DirectX SDK (Include/Lib) if the game's code uses DirectX headers/import libs"; fi
echo
if [ -n "$EXPORTS" ]; then
  echo "Found but not exported - paste before running raw analyzeHeadless / VC6 commands (run_recovery.sh and"
  echo "apply_names.sh detect GHIDRA_HOME/JAVA_HOME themselves):$EXPORTS"
fi
if [ -n "$MISSING" ]; then echo "Missing: $MISSING  (each is needed only from the phase it is listed under)"
else echo "Nothing missing."; fi
exit 0
