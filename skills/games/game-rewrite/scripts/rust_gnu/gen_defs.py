#!/usr/bin/env python3
"""Generate/extend the import-library .def files the i686-pc-windows-gnu link needs (Python stdlib only).

The Rust gnu target's prebuilt std links against MinGW import libraries (-lkernel32 -lntdll -lws2_32 ...),
which we do not have (no MinGW install). This tool takes the "undefined symbol" lines of a failed rust-lld
link, finds which system DLL exports each function (by reading the export tables of the 32-bit DLLs in a
Wine prefix's syswow64 folder, or C:\\Windows\\SysWOW64), and adds the decorated names to <defs>/<lib>.def.
`build_libs.py runtime --defs <defs>` turns those .def files into lib<lib>.a import libraries with
`rust-lld -flavor link /lib /def:`.

Usage: gen_defs.py <link-output.txt> [--defs DIR] [--syswow64 DIR]
       --defs     default: rewrite/third_party/build/rust-gnu/defs (the runtime's copy of this skill's defs)
       --syswow64 default: $WINEPREFIX or ~/.wine, + drive_c/windows/syswow64
Symbols that crt_shim.c provides (startup, unwinder stubs) are skipped. Port: ../js/rust_gnu/gen_defs.mjs.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import rwlib  # noqa: E402
import wintools  # noqa: E402

# -l name used by rustc/std  ->  DLL that the import library points at (searched in this order)
LIBS = [
    ("kernel32", "kernel32.dll"),
    ("msvcrt", "msvcrt.dll"),      # before ntdll: ntdll also exports memcpy/strlen/..., msvcrt is the usual home
    ("ntdll", "ntdll.dll"),
    ("ws2_32", "ws2_32.dll"),
    ("userenv", "userenv.dll"),
    ("synchronization", "api-ms-win-core-synch-l1-2-0.dll"),   # WaitOnAddress & co (Windows 8+)
    ("advapi32", "advapi32.dll"),
    ("user32", "user32.dll"),
]
# where to look up exports of DLLs that Wine implements as an api set (no file of its own)
LOOKUP = {"api-ms-win-core-synch-l1-2-0.dll": "kernelbase.dll"}
SYNCH = {"WaitOnAddress", "WakeByAddressAll", "WakeByAddressSingle"}
SHIM = {"mainCRTStartup", "WinMainCRTStartup", "__main", "atexit", "__register_frame_info",
        "__deregister_frame_info"}


def undecorate(sym):
    """'_Foo@8' -> ('Foo', '_Foo@8 == Foo'), '_memcpy' -> ('memcpy', 'memcpy').

    The second value is the .def entry for `rust-lld -flavor link /lib /def:` (llvm-lib, MSVC rules).
    A plain cdecl name gets its '_' added and is imported by name without the prefix. A stdcall name must
    be written fully decorated with "== undecorated": that yields the linker symbol _Foo@8 with import name
    type UNDECORATE, so the DLL is asked for "Foo". (Writing just "Foo@8" gives the symbol "Foo@8" without
    the underscore, and "_Foo@8" alone makes the loader look for "_Foo@8" - both wrong.)"""
    s = sym[1:] if sym.startswith("_") else sym
    m = re.match(r"^(.*)@(\d+)$", s)
    return (m.group(1), "%s == %s" % (sym, m.group(1))) if m else (s, s)


def read_def(path):
    names = []
    if os.path.exists(path):
        with open(path) as f:
            lines = f.read().splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith(("LIBRARY", "EXPORTS", ";")):
                names.append(line)
    return names


def main(argv):
    a = rwlib.parse_args('gen_defs', __doc__, argv, [
        ('--syswow64', 'str', None), ('--defs', 'str', os.path.join('rewrite', 'third_party', 'build', 'rust-gnu', 'defs'))],
        [('link_output', '1')])
    sysdir = a['syswow64'] or os.path.join(os.environ.get('WINEPREFIX', os.path.expanduser('~/.wine')),
                                           'drive_c', 'windows', 'syswow64')
    exports = {}
    for lib, dll in LIBS:
        p = os.path.join(sysdir, LOOKUP.get(dll, dll))
        exports[lib] = set(wintools.pe_exports(p)) if os.path.exists(p) else set()
    with open(a['link_output']) as f:
        text = f.read()
    # accepts rust-lld output ("undefined symbol: _Foo@8") or a plain list of symbols, one per line
    syms = sorted(set(re.findall(r"undefined symbol: (\S+)", text) or text.split()))
    defsdir = a['defs']
    os.makedirs(defsdir, exist_ok=True)
    added, unknown = {}, []
    for sym in syms:
        plain, entry = undecorate(sym)
        if plain in SHIM or plain.startswith("_Unwind_"):
            continue
        lib = "synchronization" if plain in SYNCH else next((l for l, _ in LIBS if plain in exports[l]), None)
        if lib is None:
            unknown.append(sym)
            continue
        added.setdefault(lib, set()).add(entry)
    for lib, dll in LIBS:
        path = os.path.join(defsdir, lib + ".def")
        old = read_def(path)
        new = sorted(set(old) | added.get(lib, set()), key=lambda s: (s.lower(), s))
        if new != old or not os.path.exists(path):
            wintools.write_def(path, dll, new)
            print("%-16s %4d entries (+%d)" % (lib + ".def", len(new), len(set(new) - set(old))))
    if unknown:
        print("not found in any DLL (provide them yourself):", " ".join(unknown))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
