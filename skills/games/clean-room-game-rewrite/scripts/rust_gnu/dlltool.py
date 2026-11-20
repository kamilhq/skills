#!/usr/bin/env python3
"""Stand-in for MinGW's i686-w64-mingw32-dlltool, which rustc runs to make the import library of every
#[link(kind = "raw-dylib")] block on the i686-pc-windows-gnu target (Python stdlib only).

rustc calls:  dlltool -d X.def -D X.dll -l out.lib -m i386 -f --32 --no-leading-underscore --temp-prefix P
with a .def listing the C names (e.g. "SDL_Init"); with import_name_type = "undecorated" the Rust object
then references __imp_SDL_Init (no leading underscore, as --no-leading-underscore says) and expects the
DLL to be asked for "SDL_Init".

rust-lld's llvm-lib mode (/lib /def:) follows MSVC rules and would name the symbols _SDL_Init /
__imp__SDL_Init, so this script lets it build the library (it supplies the import descriptor objects) and
then rewrites every short import member to the exact symbol with import name type IMPORT_NAME, and writes
the archive again (GNU format, with a fresh symbol table). Entries with '@' (stdcall, "Foo@8") are given to
llvm-lib as "_Foo@8 == Foo": symbol _Foo@8, import name "Foo" (untested: the validated case binds only cdecl).
Needs RUST_GNU_LLD (set by rust_build.sh) or rust-lld on PATH. Port: ../js/rust_gnu/dlltool.mjs.
"""
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import wintools  # noqa: E402

IMPORT_NAME = 1


def parse_args(argv):
    args = {}
    i = 0
    while i < len(argv):
        if argv[i] in ("-d", "-D", "-l", "-m", "--temp-prefix") and i + 1 < len(argv):
            args[argv[i]] = argv[i + 1]
            i += 2
        else:
            i += 1
    return args


def short_import(body):
    """(symbol, dll, type_field) of a short import object, or None."""
    if len(body) < 20 or body[:4] != b"\0\0\xff\xff":
        return None
    sym, dll = body[20:].split(b"\0")[:2]
    return sym.decode("latin-1"), dll.decode("latin-1"), struct.unpack_from("<H", body, 18)[0]


def make_short_import(body, new_sym, name_type):
    hdr = bytearray(body[:20])
    _, dll, typ = short_import(body)
    rest = new_sym.encode() + b"\0" + dll.encode() + b"\0"
    struct.pack_into("<I", hdr, 12, len(rest))                          # SizeOfData
    struct.pack_into("<H", hdr, 18, (typ & ~(7 << 2)) | (name_type << 2))
    return bytes(hdr) + rest


def write_gnu_archive(path, members):
    """members: [(name, body, [symbols])] -> GNU ar with a '/' symbol table and '//' long names."""
    longnames = b""
    names = []
    for name, _, _ in members:
        n = name.encode() + b"/"
        if len(n) > 16:
            names.append(b"/%d" % len(longnames))
            longnames += n + b"\n"
        else:
            names.append(n)

    def header(name, size):
        return b"%-16s%-12s%-6s%-6s%-8s%-10d`\n" % (name, b"0", b"0", b"0", b"644", size)

    syms = [(s, i) for i, (_, _, ss) in enumerate(members) for s in ss]
    strtab = b"".join(s.encode() + b"\0" for s, _ in syms)
    symsize = 4 + 4 * len(syms) + len(strtab)
    pos = 8 + 60 + symsize + (symsize & 1)
    if longnames:
        pos += 60 + len(longnames) + (len(longnames) & 1)
    offsets = []
    for (_, body, _), n in zip(members, names):
        offsets.append(pos)
        pos += 60 + len(body) + (len(body) & 1)
    out = bytearray(b"!<arch>\n")
    out += header(b"/", symsize) + struct.pack(">I", len(syms))
    out += b"".join(struct.pack(">I", offsets[i]) for _, i in syms) + strtab
    if symsize & 1:
        out += b"\n"
    if longnames:
        out += header(b"//", len(longnames)) + longnames + (b"\n" if len(longnames) & 1 else b"")
    for (_, body, _), n in zip(members, names):
        out += header(n, len(body)) + body + (b"\n" if len(body) & 1 else b"")
    with open(path, "wb") as f:
        f.write(out)


def main(argv):
    args = parse_args(argv)
    if "-d" not in args or "-l" not in args:
        sys.stderr.write("dlltool.py: need -d <def> and -l <output>\n")
        return 2
    if args.get("-m", "i386") != "i386":
        sys.stderr.write("dlltool.py: only -m i386 is supported\n")
        return 2
    dll = args.get("-D")
    plain = set()                                  # cdecl names: fix to symbol == import name
    out = ["LIBRARY %s" % dll] if dll else []
    with open(args["-d"]) as f:
        def_lines = f.read().splitlines()
    for line in def_lines:
        s = line.strip()
        if not s or s.upper().startswith("LIBRARY"):
            continue
        m = re.match(r"^([A-Za-z_]\w*)@(\d+)(\s.*)?$", s)
        if m:
            s = "_%s@%s == %s%s" % (m.group(1), m.group(2), m.group(1), m.group(3) or "")
        elif re.match(r"^[A-Za-z_]\w*$", s):
            plain.add(s)
        out.append(s)
    lib = args["-l"]
    tmp_def = lib + ".tmp.def"
    with open(tmp_def, "w") as f:
        f.write("\n".join(out) + "\n")
    lld = os.environ.get("RUST_GNU_LLD", "rust-lld")
    r = subprocess.run([lld, "-flavor", "link", "/lib", "/machine:x86", "/def:" + tmp_def, "/out:" + lib])
    os.remove(tmp_def)
    if r.returncode:
        return r.returncode
    members = []
    for name, body in wintools.archive_members(lib):
        si = short_import(body)
        if si is None:
            members.append((name, body, wintools.coff_defined_externals(body)))
            continue
        sym = si[0]
        if sym.startswith("_") and sym[1:] in plain:
            sym = sym[1:]
            body = make_short_import(body, sym, IMPORT_NAME)
        members.append((name, body, [sym, "__imp_" + sym]))
    write_gnu_archive(lib, members)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
