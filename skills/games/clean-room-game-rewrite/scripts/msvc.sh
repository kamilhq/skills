#!/bin/sh
# Run the user's MSVC toolchain (cl, link, lib, dumpbin, ...) under Wine with INCLUDE/LIB/PATH set (the probe DLL, a C++ rewrite, the libraries).
#
# Usage: msvc.sh <tool> [args...]        e.g.  msvc.sh cl /nologo /c /O2 /MT /EHsc /GS /Oy- /Gy Unit.cpp
#                                              msvc.sh link /nologo a.obj b.obj /OUT:test.exe
#        msvc.sh --version                prints the cl and link banners
# Run it from the folder that holds the sources and pass RELATIVE file names: cl reads a leading "/" as an
# option, so absolute macOS/Linux paths must not be passed (Wine maps the current folder for you).
# Env (defaults = the VS2010 SP1 layout made by references/toolchains.md "Installing MSVC under Wine"):
#   MSVC_PREFIX  Wine prefix holding the toolchain            (default ~/.wine-vs2010)
#   MSVC_VS      Visual Studio folder inside the prefix       (default C:\Program Files (x86)\Microsoft Visual Studio 10.0)
#   MSVC_SDK     Windows SDK folder inside the prefix         (default C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1)
# On Windows, run the tools directly instead. Exit code: the tool's.
set -eu
[ $# -ge 1 ] || { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
export WINEPREFIX="${MSVC_PREFIX:-$HOME/.wine-vs2010}"
VS="${MSVC_VS:-C:\\Program Files (x86)\\Microsoft Visual Studio 10.0}"
SDK="${MSVC_SDK:-C:\\Program Files (x86)\\Microsoft SDKs\\Windows\\v7.1}"
export WINEPATH="$VS\\Common7\\IDE;$VS\\VC\\bin;$SDK\\Bin"
export INCLUDE="$VS\\VC\\include;$SDK\\Include"
export LIB="$VS\\VC\\lib;$SDK\\Lib"
export WINEDEBUG="${WINEDEBUG:--all}" WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-mscoree,mshtml=}" MVK_CONFIG_LOG_LEVEL=0
[ -d "$WINEPREFIX" ] || { echo "Wine prefix $WINEPREFIX not found (set MSVC_PREFIX)" >&2; exit 2; }
if [ "$1" = --version ]; then
  wine "$VS\\VC\\bin\\cl.exe" 2>&1 | grep -a 'Version' || true
  wine "$VS\\VC\\bin\\link.exe" 2>&1 | grep -a 'Version' || true
  exit 0
fi
TOOL="$1"; shift
case "$TOOL" in
  cl|link|lib|dumpbin|editbin|nmake|ml) EXE="$VS\\VC\\bin\\$TOOL.exe" ;;
  rc|mt) EXE="$SDK\\Bin\\$TOOL.exe" ;;
  *) EXE="$TOOL" ;;
esac
# keep the tool's exit code while dropping Wine's fixme lines and Vulkan banner noise
TMP="$(mktemp "${TMPDIR:-/tmp}/msvc.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
set +e
wine "$EXE" "$@" > "$TMP" 2>&1
rc=$?
set -e
grep -avE '^[0-9a-f]{4}:fixme:|^\[mvk-|^\s+VK_|Vulkan extensions' "$TMP" || true
exit $rc
