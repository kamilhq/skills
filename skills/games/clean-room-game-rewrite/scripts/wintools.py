#!/usr/bin/env python3
"""Small Windows-binary helpers for the rewrite toolchain (Python stdlib only; port: js/wintools.mjs).

  pe_exports(path)            -> list of export names of a PE (DLL/EXE)
  pe_imports(path)            -> {dll_name: [function names]} of a PE
  coff_defined_externals(obj) -> external symbols defined by a COFF .obj (names as stored, e.g. "_foo")
  archive_members(lib)        -> [(member name, bytes)] of an ar/.lib archive
  write_def(path, dll, names) -> writes a module-definition (.def) file

Command line:
  wintools.py exports <pe>             print the export names
  wintools.py imports <pe>             print "dll: function" lines
  wintools.py externals <obj|lib>...   print external symbols defined by objects / archive members
  wintools.py def <pe> [<out.def>]     module-definition file of a DLL's exports (stdout or <out.def>), the
                                       input of `lib /DEF:` or `rust-lld -flavor link /lib /def:` to make an
                                       import library for a DLL that came without one
  wintools.py proxy <dll> <target> [--hook A,B] [<out.def>]
                                       module-definition file of a proxy DLL (the probe, references/harness.md):
                                       every named export of <dll> forwarded to <target> (the original DLL,
                                       renamed, without .dll), except the --hook names, which the probe
                                       defines itself; exit 1 when a --hook name is not exported
"""
import struct
import sys


# ----------------------------------------------------------------------------------------------- PE
def _pe_sections(data):
    if data[:2] != b"MZ":
        raise ValueError("not an MZ/PE file")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("no PE signature")
    machine, nsect, _, _, _, optsize, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    ddir = opt + (96 if magic == 0x10B else 112)
    dirs = [struct.unpack_from("<II", data, ddir + 8 * i) for i in range(16)]
    sects = []
    sh = opt + optsize
    for i in range(nsect):
        name, vsize, va, rawsize, rawptr = struct.unpack_from("<8sIIII", data, sh + 40 * i)
        sects.append((va, max(vsize, rawsize), rawptr))
    return magic, dirs, sects


def _rva2off(sects, rva):
    for va, size, raw in sects:
        if va <= rva < va + size:
            return rva - va + raw
    raise ValueError("rva %#x outside sections" % rva)


def _cstr(data, off):
    end = data.index(b"\0", off)
    return data[off:end].decode("latin-1")


def pe_exports(path):
    with open(path, "rb") as f:
        data = f.read()
    _, dirs, sects = _pe_sections(data)
    rva, size = dirs[0]
    if not rva:
        return []
    off = _rva2off(sects, rva)
    (_, _, _, _, _, _, _, nnames, _, names_rva, _) = struct.unpack_from("<IIHHIIIIIII", data, off)
    names = []
    noff = _rva2off(sects, names_rva) if nnames else 0
    for i in range(nnames):
        names.append(_cstr(data, _rva2off(sects, struct.unpack_from("<I", data, noff + 4 * i)[0])))
    return names


def pe_imports(path):
    with open(path, "rb") as f:
        data = f.read()
    magic, dirs, sects = _pe_sections(data)
    rva, _ = dirs[1]
    out = {}
    if not rva:
        return out
    off = _rva2off(sects, rva)
    thunk = 4 if magic == 0x10B else 8
    flag = 1 << (8 * thunk - 1)
    while True:
        oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if not name_rva:
            break
        dll = _cstr(data, _rva2off(sects, name_rva))
        funcs = []
        t = _rva2off(sects, oft or ft)
        while True:
            v = struct.unpack_from("<I" if thunk == 4 else "<Q", data, t)[0]
            if not v:
                break
            funcs.append("#%d" % (v & 0xFFFF) if v & flag else _cstr(data, _rva2off(sects, v & 0x7FFFFFFF) + 2))
            t += thunk
        out[dll] = funcs
        off += 20
    return out


# ---------------------------------------------------------------------------------------------- COFF
def coff_defined_externals(data, with_kind=False):
    """External symbols defined (section number > 0) in a COFF object given as bytes.
    with_kind=True returns (name, is_function) pairs (COFF type 0x20 = function)."""
    machine, nsect, _, symptr, nsyms, optsize, _ = struct.unpack_from("<HHIIIHH", data, 0)
    if machine not in (0x14C, 0x8664) or not symptr:
        return []
    strtab = symptr + 18 * nsyms
    out = []
    i = 0
    while i < nsyms:
        o = symptr + 18 * i
        raw, value, secnum, typ, sclass, naux = struct.unpack_from("<8sIhHBB", data, o)
        if raw[:4] == b"\0\0\0\0":
            name = _cstr(data, strtab + struct.unpack_from("<I", raw, 4)[0])
        else:
            name = raw.rstrip(b"\0").decode("latin-1")
        if sclass == 2 and secnum > 0:          # IMAGE_SYM_CLASS_EXTERNAL, defined
            out.append((name, (typ >> 4) == 2) if with_kind else name)
        i += 1 + naux
    return out


def archive_members(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:8] != b"!<arch>\n":
        return [(path, data)]
    out = []
    off = 8
    longnames = b""
    while off + 60 <= len(data):
        hdr = data[off:off + 60]
        name = hdr[:16].decode("latin-1").strip()
        size = int(hdr[48:58].decode().strip())
        body = data[off + 60:off + 60 + size]
        if name == "//":
            longnames = body
        elif name not in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            if name.startswith("/") and name[1:].isdigit():
                s = int(name[1:])
                name = longnames[s:longnames.index(b"\n", s) if b"\n" in longnames[s:] else None]
                name = name.decode("latin-1").rstrip("/")
            out.append((name.rstrip("/"), body))
        off += 60 + size + (size & 1)
    return out


def write_def(path, dll, names):
    with open(path, "w") as f:
        f.write(def_text(dll, names))


def def_text(dll, names):
    return 'LIBRARY %s\nEXPORTS\n' % dll + ''.join('    %s\n' % n for n in names)


def proxy_def_text(dll, target, names, hooks):
    return 'LIBRARY %s\nEXPORTS\n' % dll + ''.join(
        '    %s\n' % n if n in hooks else '    %s=%s.%s\n' % (n, target, n) for n in names)


def main(argv):
    if len(argv) < 3:
        print(__doc__.strip())
        return 2
    cmd = argv[1]
    if cmd == "exports":
        for n in pe_exports(argv[2]):
            print(n)
    elif cmd == "imports":
        for dll, funcs in pe_imports(argv[2]).items():
            for fn in funcs:
                print("%s: %s" % (dll, fn))
    elif cmd == "externals":
        for p in argv[2:]:
            for _, body in archive_members(p):
                for n in coff_defined_externals(body):
                    print(n)
    elif cmd == "def":
        import os
        text = def_text(os.path.basename(argv[2]), pe_exports(argv[2]))
        if len(argv) > 3:
            with open(argv[3], "w") as f:
                f.write(text)
        else:
            sys.stdout.write(text)
    elif cmd == "proxy":
        import os
        args = argv[2:]
        hooks = []
        if "--hook" in args:
            i = args.index("--hook")
            if i + 1 >= len(args):
                print(__doc__.strip())
                return 2
            hooks = [h for h in args[i + 1].split(",") if h]
            del args[i:i + 2]
        if len(args) not in (2, 3):
            print(__doc__.strip())
            return 2
        names = pe_exports(args[0])
        missing = [h for h in hooks if h not in names]
        if missing:
            sys.stderr.write("wintools: not exported by %s: %s\n" % (os.path.basename(args[0]), ", ".join(missing)))
            return 1
        text = proxy_def_text(os.path.basename(args[0]), args[1], names, set(hooks))
        if len(args) == 3:
            with open(args[2], "w") as f:
                f.write(text)
        else:
            sys.stdout.write(text)
    else:
        print(__doc__.strip())
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
