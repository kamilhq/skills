#!/usr/bin/env python3
"""objcmp.py - compare functions in MSVC COFF objects (cl.exe /c) with the original 32-bit PE, byte for byte.

Pure Python 3.9 stdlib; run with -I. Replaces reccmp for phase 6 (matching decompilation).

  objcmp.py compare <obj> <symbol> <pe> <va> [size] [--map F]... [--functions index.json] [--json OUT] [--all-diffs]
  objcmp.py report --pe <pe> --src <dir|file>... --obj <dir|file>... [--module M] [--map F]...
                   [--functions index.json] [--json OUT] [--verbose]
  objcmp.py dump <obj> [--json OUT]

compare: <symbol> is the decorated obj symbol (?Update@CUnit@@QAEXXZ, _main, _foo@8) or an undecorated
  C/C++ name (Class::Method, foo) that matches exactly one function symbol. <va> is hex. [size] is the
  original function size (strict: the original must end there, trailing CC/90 padding allowed); without it
  the original must end where the obj function ends: the next original byte is CC/90 padding or a known
  function start (--functions index.json, or annotations in report mode).
report: scans sources for reccmp-style annotations (// FUNCTION: [MODULE] 0x<addr> [symbol]), maps each to an
  obj symbol and compares every one; prints per-function status and totals.
dump: sections, COMDAT selections, symbols (functions with sizes) and relocations of one object.

Masking: bytes under an obj relocation and bytes under an original .reloc fixup are not compared directly.
Relocations whose target address is known (address map: --map files, annotations, PE imports for __imp_
symbols, Ghidra default names FUN_/DAT_/LAB_/PTR_<8 hex>, symbols in the function's own section) are
resolved and compared with the original field; unknown targets are inferred from the original and must be
consistent inside the function. Original fixups without an obj DIR32 relocation (and the reverse) count as
differences.

Address map files (--map): JSON {"name": "0x401000" | 4198400}, JSON [{"name":..,"address":..}],
{"functions": [...]} (Ghidra index.json), or text lines "name 0x401000" / "0x401000 name" (# comments).

Exit codes: 0 every compared function identical (and every annotation mapped); 1 differences, unmapped or
ambiguous annotations; 2 bad arguments or unreadable inputs.

Library use: read_coff(path), PEImage(path), compare_function(...), write_obj(path, functions=[...]).
"""
import argparse
import bisect
import contextlib
import difflib
import json
import os
import re
import struct
import sys
import zlib

# ----------------------------------------------------------------------------------------------- constants

MACHINE_I386 = 0x14C
BIGOBJ_CLSID = bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')   # {D1BAA1C7-BAEE-4ba9-AF20-FAF66AA4DCB8}

REL_NAMES = {0x0: 'ABSOLUTE', 0x1: 'DIR16', 0x2: 'REL16', 0x6: 'DIR32', 0x7: 'DIR32NB', 0x9: 'SEG12',
             0xA: 'SECTION', 0xB: 'SECREL', 0xC: 'TOKEN', 0xD: 'SECREL7', 0x14: 'REL32'}
REL_BY_NAME = {v: k for k, v in REL_NAMES.items()}
REL_SIZE = {0x0: 0, 0x1: 2, 0x2: 2, 0x6: 4, 0x7: 4, 0x9: 2, 0xA: 2, 0xB: 4, 0xC: 4, 0xD: 1, 0x14: 4}
DIR32, DIR32NB, SECTION_REL, SECREL, REL32 = 0x6, 0x7, 0xA, 0xB, 0x14
SUPPORTED_RELS = {0x0, DIR32, DIR32NB, SECTION_REL, SECREL, REL32}

SCN_CNT_CODE, SCN_CNT_IDATA, SCN_CNT_UDATA = 0x20, 0x40, 0x80
SCN_LNK_INFO, SCN_LNK_REMOVE, SCN_LNK_COMDAT = 0x200, 0x800, 0x1000
SCN_NRELOC_OVFL, SCN_DISCARDABLE = 0x01000000, 0x02000000
SCN_EXEC, SCN_READ, SCN_WRITE = 0x20000000, 0x40000000, 0x80000000
SCN_FLAG_NAMES = [(SCN_CNT_CODE, 'CODE'), (SCN_CNT_IDATA, 'IDATA'), (SCN_CNT_UDATA, 'UDATA'),
                  (SCN_LNK_INFO, 'INFO'), (SCN_LNK_REMOVE, 'REMOVE'), (SCN_LNK_COMDAT, 'COMDAT'),
                  (SCN_NRELOC_OVFL, 'NRELOC_OVFL'), (SCN_DISCARDABLE, 'DISCARD'), (SCN_EXEC, 'X'),
                  (SCN_READ, 'R'), (SCN_WRITE, 'W')]
CLASS_EXTERNAL, CLASS_STATIC, CLASS_LABEL, CLASS_WEAK = 2, 3, 6, 105
CLASS_NAMES = {2: 'EXTERNAL', 3: 'STATIC', 6: 'LABEL', 101: 'FUNCTION', 103: 'FILE', 104: 'SECTION',
               105: 'WEAK_EXTERNAL', 107: 'CLR_TOKEN'}
COMDAT_NAMES = {1: 'NODUPLICATES', 2: 'ANY', 3: 'SAME_SIZE', 4: 'EXACT_MATCH', 5: 'ASSOCIATIVE', 6: 'LARGEST'}
PAD_BYTES = (0xCC, 0x90)


class CoffError(Exception):
    pass


class PEError(Exception):
    pass


def rel_type(t):
    """'DIR32' / 'IMAGE_REL_I386_REL32' / 6 -> int."""
    if isinstance(t, int):
        return t
    t = t.upper().replace('IMAGE_REL_I386_', '')
    if t not in REL_BY_NAME:
        raise ValueError(f'unknown relocation type {t}')
    return REL_BY_NAME[t]


def scn_flags(ch):
    names = [n for bit, n in SCN_FLAG_NAMES if ch & bit]
    a = (ch >> 20) & 0xF
    if a:
        names.append(f'ALIGN{1 << (a - 1)}')
    return '|'.join(names)


# ----------------------------------------------------------------------------------------------- COFF reader

class Section:
    def __init__(self):
        self.number = 0            # 1-based
        self.name = ''
        self.characteristics = 0
        self.data = b''            # raw data (empty for uninitialised data)
        self.size = 0              # SizeOfRawData
        self.relocs = []
        self.comdat = 0            # COMDAT selection (0 = not a COMDAT)
        self.assoc = 0             # associated section number (selection 5)
        self.checksum = 0
        self.nlinenums = 0

    @property
    def is_code(self):
        return bool(self.characteristics & (SCN_CNT_CODE | SCN_EXEC))


class Symbol:
    def __init__(self):
        self.index = 0
        self.name = ''
        self.value = 0
        self.secnum = 0            # >0 section, 0 undefined/common, -1 absolute, -2 debug
        self.type = 0
        self.storage = 0
        self.naux = 0
        self.aux = []
        self.section = None
        self.is_section_sym = False
        self.is_function = False
        self.size = None           # function extent (bytes) when is_function
        self.weak_default = None   # weak external: default symbol index

    @property
    def defined(self):
        return self.secnum > 0

    @property
    def key(self):
        """Identity for address inference: externals by name, statics per section."""
        if self.storage == CLASS_STATIC and self.secnum > 0:
            return f'{self.name}#sec{self.secnum}'
        return self.name


class Reloc:
    def __init__(self, offset, symidx, rtype, symbol=None):
        self.offset = offset
        self.symidx = symidx
        self.type = rtype
        self.symbol = symbol

    @property
    def size(self):
        return REL_SIZE.get(self.type, 4)

    @property
    def type_name(self):
        return REL_NAMES.get(self.type, f'0x{self.type:x}')


class CoffObj:
    """An i386 COFF object (regular or /bigobj)."""

    def __init__(self, data, path='<obj>'):
        self.path = path
        self.data = data
        self.sections = []
        self.symbols = {}          # index -> Symbol (aux slots absent)
        self.by_name = {}
        self.strtab = b''
        self._parse()

    # -- parsing
    def _parse(self):
        d = self.data
        if len(d) < 20:
            raise CoffError('file too small for a COFF header')
        sig1, sig2 = struct.unpack_from('<HH', d, 0)
        if sig1 == 0 and sig2 == 0xFFFF:
            version, machine = struct.unpack_from('<HH', d, 4)
            if version >= 2 and d[12:28] == BIGOBJ_CLSID:
                if len(d) < 56:
                    raise CoffError('truncated bigobj header')
                self.bigobj = True
                self.timestamp = struct.unpack_from('<I', d, 8)[0]
                nsec, symptr, nsyms = struct.unpack_from('<III', d, 44)
                hdr = 56
            elif version == 0:
                raise CoffError('short import object (import-library member), not compiled code')
            else:
                raise CoffError('anonymous object header (likely /GL link-time code generation: IL, not machine '
                                'code); recompile without /GL')
        else:
            self.bigobj = False
            machine, nsec, self.timestamp, symptr, nsyms, optsize, _ = struct.unpack_from('<HHIIIHH', d, 0)
            hdr = 20 + optsize
        if machine != MACHINE_I386:
            raise CoffError(f'machine 0x{machine:04x} is not i386 (0x14c); not a 32-bit x86 COFF object')
        self.machine = machine
        self.symsize = 20 if self.bigobj else 18
        strpos = symptr + nsyms * self.symsize
        if symptr and strpos + 4 <= len(d):
            n = struct.unpack_from('<I', d, strpos)[0]
            self.strtab = d[strpos:strpos + max(n, 4)]
        if hdr + 40 * nsec > len(d):
            raise CoffError('section table runs past end of file')
        for i in range(nsec):
            o = hdr + 40 * i
            raw = d[o:o + 8]
            vsize, vaddr, rawsize, rawptr, relptr, lnptr, nrel, nln, ch = struct.unpack_from('<IIIIIIHHI', d, o + 8)
            s = Section()
            s.number, s.characteristics, s.size, s.nlinenums = i + 1, ch, rawsize, nln
            s.name = self._section_name(raw)
            if not ch & SCN_CNT_UDATA and rawptr:
                if rawptr + rawsize > len(d):
                    raise CoffError(f'section {s.name} data runs past end of file')
                s.data = d[rawptr:rawptr + rawsize]
            count, rp = nrel, relptr
            if ch & SCN_NRELOC_OVFL and nrel == 0xFFFF:
                count = struct.unpack_from('<I', d, relptr)[0] - 1
                rp = relptr + 10
            if rp + 10 * count > len(d):
                raise CoffError(f'section {s.name} relocations run past end of file')
            for k in range(count):
                va, si, t = struct.unpack_from('<IIH', d, rp + 10 * k)
                s.relocs.append(Reloc(va, si, t))
            self.sections.append(s)
        i = 0
        symfmt = '<8sIiHBB' if self.bigobj else '<8sIhHBB'
        if symptr and symptr + nsyms * self.symsize > len(d):
            raise CoffError('symbol table runs past end of file')
        while i < nsyms:
            o = symptr + i * self.symsize
            raw, value, secnum, typ, storage, naux = struct.unpack_from(symfmt, d, o)
            sym = Symbol()
            sym.index, sym.value, sym.secnum, sym.type, sym.storage, sym.naux = i, value, secnum, typ, storage, naux
            sym.name = self._sym_name(raw)
            sym.aux = [d[o + self.symsize * (k + 1):o + self.symsize * (k + 2)] for k in range(naux)]
            if 0 < secnum <= len(self.sections):
                sym.section = self.sections[secnum - 1]
            self.symbols[i] = sym
            self.by_name.setdefault(sym.name, []).append(sym)
            i += 1 + naux
        for sym in self.symbols.values():
            sec = sym.section
            if (sec is not None and sym.storage == CLASS_STATIC and sym.naux and sym.value == 0
                    and sym.name == sec.name and sym.type == 0):
                sym.is_section_sym = True
                a = sym.aux[0]
                if self.bigobj:
                    ln, nr, nl, ck, num, sel, _, hi = struct.unpack_from('<IHHIHBBH', a, 0)
                    num |= hi << 16
                else:
                    ln, nr, nl, ck, num, sel = struct.unpack_from('<IHHIHB', a, 0)
                sec.checksum = ck
                if sec.characteristics & SCN_LNK_COMDAT:
                    sec.comdat, sec.assoc = sel, num
            if sym.storage == CLASS_WEAK and sym.aux:
                sym.weak_default = struct.unpack_from('<I', sym.aux[0], 0)[0]
        for s in self.sections:
            for r in s.relocs:
                r.symbol = self.symbols.get(r.symidx)
        # functions and their extents
        per_sec = {}
        for sym in self.symbols.values():
            sec = sym.section
            if sec is None or sym.is_section_sym or sym.storage not in (CLASS_EXTERNAL, CLASS_STATIC):
                continue
            if sym.name.startswith('$') or not sec.is_code:
                continue
            if ((sym.type >> 4) & 3) == 2 or sec.is_code:
                sym.is_function = True
                per_sec.setdefault(sec.number, []).append(sym)
        for secnum, syms in per_sec.items():
            sec = self.sections[secnum - 1]
            starts = sorted({s.value for s in syms})
            for s in syms:
                k = bisect.bisect_right(starts, s.value)
                end = starts[k] if k < len(starts) else sec.size
                s.size = max(0, end - s.value)

    def _str(self, off):
        if off >= len(self.strtab):
            raise CoffError(f'string table offset {off} out of range')
        end = self.strtab.find(b'\0', off)
        return self.strtab[off:end if end >= 0 else len(self.strtab)].decode('latin-1')

    def _sym_name(self, raw):
        if raw[:4] == b'\0\0\0\0':
            return self._str(struct.unpack_from('<I', raw, 4)[0])
        return raw.rstrip(b'\0').decode('latin-1')

    def _section_name(self, raw):
        if raw[:2] == b'//':      # base64 offset (very large string tables)
            alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
            off = 0
            for c in raw[2:].rstrip(b'\0').decode('ascii'):
                off = off * 64 + alpha.index(c)
            return self._str(off)
        if raw[:1] == b'/' and raw[1:].rstrip(b'\0').isdigit():
            return self._str(int(raw[1:].rstrip(b'\0')))
        return raw.rstrip(b'\0').decode('latin-1')

    # -- queries
    def functions(self):
        return [s for s in self.symbols.values() if s.is_function]

    def find(self, name):
        return [s for s in self.by_name.get(name, []) if s.is_function]

    def function_bytes(self, sym):
        """(bytes, [Reloc with offsets relative to the function start]) of a function symbol."""
        sec = sym.section
        start, end = sym.value, sym.value + (sym.size or 0)
        data = sec.data[start:end]
        rels = []
        for r in sec.relocs:
            if start <= r.offset < end:
                rels.append(Reloc(r.offset - start, r.symidx, r.type, r.symbol))
        return data, rels


def read_coff(path):
    with open(path, 'rb') as f:
        return CoffObj(f.read(), path)


# ----------------------------------------------------------------------------------------------- PE reader

class PEImage:
    """A 32-bit PE: sections, image base, .reloc fixups, imports, VA -> file offset."""

    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        d = self.data
        if d[:2] != b'MZ' or len(d) < 0x40:
            raise PEError('no MZ header')
        o = struct.unpack_from('<I', d, 0x3C)[0]
        if d[o:o + 4] != b'PE\0\0':
            raise PEError('no PE signature')
        self.machine, nsec = struct.unpack_from('<HH', d, o + 4)
        optsize = struct.unpack_from('<H', d, o + 20)[0]
        opt = o + 24
        magic = struct.unpack_from('<H', d, opt)[0]
        if magic != 0x10B:
            raise PEError(f'optional header magic 0x{magic:x}: only PE32 (32-bit) is supported')
        self.image_base = struct.unpack_from('<I', d, opt + 28)[0]
        nrva = struct.unpack_from('<I', d, opt + 92)[0]
        self.dirs = [struct.unpack_from('<II', d, opt + 96 + 8 * k) for k in range(min(nrva, 16))]
        self.sections = []
        so = opt + optsize
        for i in range(nsec):
            name, vsize, va, rawsize, rawptr = struct.unpack_from('<8sIIII', d, so + 40 * i)
            ch = struct.unpack_from('<I', d, so + 40 * i + 36)[0]
            self.sections.append((name.rstrip(b'\0').decode('latin-1'), va, vsize, rawsize, rawptr, ch))
        self.fixups = self._relocs()
        self.fixups_set = set(self.fixups)
        self.has_relocs = bool(self.fixups) or (len(self.dirs) > 5 and self.dirs[5][1] > 0)
        self.imports = self._imports()

    def section_index(self, va):
        rva = va - self.image_base
        for k, (_, sva, vsize, rawsize, _, _) in enumerate(self.sections):
            if sva <= rva < sva + max(vsize, rawsize):
                return k
        return None

    def section_base(self, va):
        k = self.section_index(va)
        return None if k is None else self.image_base + self.sections[k][1]

    def is_exec(self, va):
        k = self.section_index(va)
        return k is not None and bool(self.sections[k][5] & (SCN_CNT_CODE | SCN_EXEC))

    def read(self, va, n):
        """Bytes at VA; virtual tails read as zero; stops at the section end."""
        k = self.section_index(va)
        if k is None:
            raise PEError(f'0x{va:x} is not inside any section of {self.path}')
        _, sva, vsize, rawsize, rawptr, _ = self.sections[k]
        delta = va - self.image_base - sva
        n = min(n, max(vsize, rawsize) - delta)
        file_part = self.data[rawptr + delta:rawptr + min(rawsize, delta + n)] if delta < rawsize else b''
        return file_part + b'\0' * (n - len(file_part))

    def _rva_read(self, rva, n):
        return self.read(self.image_base + rva, n)

    def _relocs(self):
        if len(self.dirs) <= 5 or not self.dirs[5][0]:
            return []
        rva, size = self.dirs[5]
        blob = self._rva_read(rva, size)
        out, p = [], 0
        while p + 8 <= len(blob):
            page, bsize = struct.unpack_from('<II', blob, p)
            if bsize < 8:
                break
            for k in range((bsize - 8) // 2):
                e = struct.unpack_from('<H', blob, p + 8 + 2 * k)[0]
                t, off = e >> 12, e & 0xFFF
                if t == 3:          # HIGHLOW
                    out.append(self.image_base + page + off)
                elif t not in (0,):
                    out.append(self.image_base + page + off)   # other types: still mask 4 bytes
            p += bsize
        return sorted(set(out))

    def fixups_in(self, va, n):
        """Fixup VAs whose 4 bytes overlap [va, va+n)."""
        lo = bisect.bisect_left(self.fixups, va - 3)
        hi = bisect.bisect_left(self.fixups, va + n)
        return self.fixups[lo:hi]

    def _imports(self):
        out = {}
        if len(self.dirs) <= 1 or not self.dirs[1][0]:
            return out
        try:
            rva = self.dirs[1][0]
            while True:
                oft, _, _, name_rva, ft = struct.unpack('<IIIII', self._rva_read(rva, 20))
                if not (oft or name_rva or ft):
                    break
                dll = self._cstr(name_rva)
                lookup = oft or ft
                k = 0
                while True:
                    ent = struct.unpack('<I', self._rva_read(lookup + 4 * k, 4))[0]
                    if not ent:
                        break
                    slot = self.image_base + ft + 4 * k
                    if ent & 0x80000000:
                        out.setdefault(f'{dll}#{ent & 0xFFFF}', slot)
                    else:
                        out.setdefault(self._cstr(ent + 2), slot)
                    k += 1
                rva += 20
        except (PEError, struct.error):
            pass
        return out

    def _cstr(self, rva):
        b = self._rva_read(rva, 512)
        return b.split(b'\0', 1)[0].decode('latin-1')


# ----------------------------------------------------------------------------------------------- address map

GHIDRA_NAME = re.compile(r'^[_@]?(?:FUN|DAT|LAB|PTR|SUB|sub|thunk_FUN|switchD|caseD|BYTE|WORD|DWORD|byte|word|dword|'
                         r'off|unk|loc)_([0-9A-Fa-f]{8})(?:@\d+)?$')


def parse_int(v, hex_default=True):
    """int, '0x401000', '401000' (hex by default) or decimal with hex_default=False."""
    if isinstance(v, int):
        return v
    v = str(v).strip()
    if v.lower().startswith('0x'):
        return int(v, 16)
    return int(v, 16 if hex_default else 10)


class AddrMap:
    """symbol name -> original VA. Sources: map files, annotations, PE imports, Ghidra default names."""

    def __init__(self, pe=None, auto_names=True):
        self.names = {}
        self.source = {}
        self.conflicts = []
        self.pe = pe
        self.auto_names = auto_names

    def add(self, name, va, source):
        old = self.names.get(name)
        if old is not None and old != va:
            self.conflicts.append({'symbol': name, 'addresses': [hex(old), hex(va)],
                                   'sources': [self.source[name], source]})
            return False
        self.names[name] = va
        self.source.setdefault(name, source)
        return True

    def load(self, path):
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
        st = text.lstrip()
        if st.startswith('{') or st.startswith('['):
            obj = json.loads(text)
            if isinstance(obj, dict) and isinstance(obj.get('functions'), list):
                obj = obj['functions']
            if isinstance(obj, dict):
                for k, v in obj.items():
                    self.add(k, parse_int(v), path)
            else:
                for e in obj:
                    nm = e.get('name') or e.get('symbol')
                    if nm is not None and e.get('address') is not None:
                        self.add(nm, parse_int(e['address']), path)
            return
        for ln in text.splitlines():
            ln = ln.split('#', 1)[0].strip()
            if not ln:
                continue
            a, b = ln.split(None, 1) if len(ln.split(None, 1)) == 2 else (ln, '')
            if re.fullmatch(r'0x[0-9a-fA-F]+', a):
                self.add(b.strip(), int(a, 16), path)
            else:
                self.add(a, parse_int(b), path)

    def resolve(self, name):
        if name in self.names:
            return self.names[name], self.source[name]
        if self.pe is not None and name.startswith('__imp_'):
            raw = name[6:]
            imp = self.pe.imports
            for cand in (raw, raw[1:] if raw.startswith('_') else None,
                         re.sub(r'@\d+$', '', raw[1:]) if raw[:1] in '_@' else None):
                if cand and cand in imp:
                    return imp[cand], 'import'
        if self.auto_names:
            m = GHIDRA_NAME.match(name)
            if m:
                return int(m.group(1), 16), 'ghidra-name'
        return None, None


def load_function_list(path):
    """Ghidra index.json -> {va: size}."""
    with open(path, 'r', encoding='utf-8') as f:
        obj = json.load(f)
    funcs = obj['functions'] if isinstance(obj, dict) else obj
    out = {}
    for e in funcs:
        try:
            out[parse_int(e['address'])] = int(e.get('size') or 0)
        except (KeyError, ValueError, TypeError):
            continue
    return out


# ----------------------------------------------------------------------------------------------- compare

def _u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def _s32(v):
    return v - (1 << 32) if v & 0x80000000 else v


def compare_function(obj, sym, pe, va, size=None, amap=None, known_starts=None, max_diffs=64):
    """Compare obj function `sym` with the original at `va`. Returns a result dict (see 'identical')."""
    amap = amap or AddrMap(pe)
    ob, rels = obj.function_bytes(sym)
    n_obj = len(ob)
    n_orig = n_obj if size is None else size
    span = max(n_obj, n_orig)
    try:
        orig = pe.read(va, span + 16)
    except PEError as e:
        return {'symbol': sym.name, 'obj': obj.path, 'va': va, 'identical': False, 'status': 'error',
                'error': str(e)}
    mask_obj = bytearray(span)
    mask_orig = bytearray(span)
    issues = []
    res = {'symbol': sym.name, 'obj': obj.path, 'va': va, 'obj_size': n_obj, 'orig_size': n_orig,
           'size_given': size is not None}

    # obj relocations: mask, resolve, check
    rel_at = {}
    checked = inferred_only = 0
    inferred = {}
    sources = {}
    for r in rels:
        rs = r.size
        for k in range(r.offset, min(r.offset + rs, span)):
            mask_obj[k] = 1
        if r.type not in SUPPORTED_RELS:
            issues.append({'offset': r.offset, 'kind': 'unsupported_reloc',
                           'detail': f'relocation type {r.type_name} to {r.symbol.name if r.symbol else r.symidx} '
                                     f'is not supported'})
            continue
        if r.type == 0:
            continue
        rel_at[r.offset] = r
        if r.offset + rs > len(orig) or r.offset + rs > n_obj:
            continue
        tsym = r.symbol
        if tsym is None:
            issues.append({'offset': r.offset, 'kind': 'bad_reloc', 'detail': f'symbol index {r.symidx} missing'})
            continue
        addend = _s32(_u32(ob, r.offset)) if rs == 4 else struct.unpack_from('<h', ob, r.offset)[0]
        tva, src = None, None
        if tsym.secnum == -1:
            tva, src = tsym.value, 'absolute'
        elif tsym.section is sym.section and tsym.defined:
            tva, src = va - sym.value + tsym.value, 'same-section'
        if tva is None and not tsym.is_section_sym:
            tva, src = amap.resolve(tsym.name)
        p = va + r.offset
        val = _u32(orig, r.offset) if rs == 4 else struct.unpack_from('<H', orig, r.offset)[0]
        what = f'{r.type_name} -> {tsym.name}' + (f'{addend:+#x}' if addend else '')
        if r.type == DIR32:
            want = None if tva is None else (tva + addend) & 0xFFFFFFFF
            got_target = (val - addend) & 0xFFFFFFFF
        elif r.type == DIR32NB:
            want = None if tva is None else (tva - pe.image_base + addend) & 0xFFFFFFFF
            got_target = (val + pe.image_base - addend) & 0xFFFFFFFF
        elif r.type == REL32:
            want = None if tva is None else (tva + addend - (p + 4)) & 0xFFFFFFFF
            got_target = (val + p + 4 - addend) & 0xFFFFFFFF
        elif r.type == SECREL:
            base = None if tva is None else pe.section_base(tva)
            want = None if base is None else (tva - base + addend) & 0xFFFFFFFF
            got_target = None
        else:   # SECTION
            k = None if tva is None else pe.section_index(tva)
            want = None if k is None else k + 1
            got_target = None
        if want is not None:
            checked += 1
            sources[src if src in ('absolute', 'same-section', 'import', 'ghidra-name') else 'map'] = \
                sources.get(src if src in ('absolute', 'same-section', 'import', 'ghidra-name') else 'map', 0) + 1
            if val != want:
                issues.append({'offset': r.offset, 'kind': 'target_mismatch',
                               'detail': f'{what}: target 0x{tva:x} ({src}) expects field 0x{want:08x}, '
                                         f'original has 0x{val:08x}'
                                         + (f' (-> 0x{got_target:x})' if got_target is not None else '')})
        elif got_target is not None:
            inferred_only += 1
            prev = inferred.get(tsym.key)
            if prev is not None and prev[0] != got_target:
                issues.append({'offset': r.offset, 'kind': 'inconsistent_target',
                               'detail': f'{what}: original implies 0x{got_target:x} but +0x{prev[1]:x} '
                                         f'implies 0x{prev[0]:x} for the same symbol'})
            else:
                inferred.setdefault(tsym.key, (got_target, r.offset))
        # base-relocation agreement
        if pe.has_relocs and r.type == DIR32:
            has_fix = p in pe.fixups_set
            if tsym.secnum == -1 and has_fix:
                issues.append({'offset': r.offset, 'kind': 'fixup_mismatch',
                               'detail': f'{what}: absolute symbol, but the original has a base relocation here'})
            elif tsym.secnum != -1 and not has_fix:
                issues.append({'offset': r.offset, 'kind': 'reloc_without_fixup',
                               'detail': f'{what}: obj has an absolute address, original has no base relocation '
                                         f'here (a constant, or code shifted)'})
        elif pe.has_relocs and r.type in (REL32, DIR32NB, SECREL) and p in pe.fixups_set:
            issues.append({'offset': r.offset, 'kind': 'fixup_mismatch',
                           'detail': f'{what}: original has an absolute address (base relocation) here'})

    # original fixups: mask; each must coincide with an obj DIR32
    nfix = 0
    for f in pe.fixups_in(va, span):
        nfix += 1
        o = f - va
        for k in range(max(0, o), min(o + 4, span)):
            mask_orig[k] = 1
        if 0 <= o and o + 4 <= min(n_obj, n_orig):
            r = rel_at.get(o)
            if r is None or r.type != DIR32:
                issues.append({'offset': o, 'kind': 'fixup_without_reloc',
                               'detail': f'original has an absolute address 0x{_u32(orig, o):08x} (base relocation) '
                                         f'here; obj has ' + (f'{r.type_name}' if r else 'no relocation')})

    # bytes
    diffs = []
    common = min(n_obj, n_orig)
    for i in range(common):
        if not (mask_obj[i] or mask_orig[i]) and ob[i] != orig[i]:
            diffs.append(i)
    padding = 0
    size_issue = None
    if n_orig > n_obj:
        tail = orig[n_obj:n_orig]
        bad = [k for k, b in enumerate(tail) if b not in PAD_BYTES]
        if bad:
            size_issue = (n_obj + bad[0], f'original is {n_orig} bytes, obj function only {n_obj}; original continues '
                                          f'with non-padding bytes at +0x{n_obj + bad[0]:x}')
        else:
            padding = len(tail)
    elif n_obj > n_orig:
        extra = [n_orig + k for k in range(n_obj - n_orig)
                 if n_orig + k >= len(orig) or ob[n_orig + k] != orig[n_orig + k]]
        if extra or any(b not in PAD_BYTES for b in ob[n_orig:]):
            size_issue = (n_orig, f'obj function is {n_obj} bytes, original size is {n_orig}')
        else:
            padding = n_obj - n_orig
    if size is None and size_issue is None:
        nxt = va + n_obj
        if not (known_starts and nxt in known_starts):
            if n_obj >= len(orig) or orig[n_obj] not in PAD_BYTES:
                if not (n_obj >= len(orig) and pe.section_index(nxt) is None):
                    nb = orig[n_obj] if n_obj < len(orig) else None
                    size_issue = (n_obj, f'original continues after the obj function end (+0x{n_obj:x} is '
                                         f'{"%02x" % nb if nb is not None else "end"}, not CC/90 padding nor a known '
                                         f'function start); pass a size or --functions to confirm the boundary')
    if size_issue:
        issues.append({'offset': size_issue[0], 'kind': 'size', 'detail': size_issue[1]})

    offsets = diffs + [i['offset'] for i in issues]
    identical = not offsets
    res['identical'] = identical
    res['status'] = 'identical' if identical else 'different'
    res['first_diff'] = None if identical else min(offsets)
    res['diff_bytes'] = len(diffs)
    res['diff_ranges'] = _ranges(diffs)[:max_diffs]
    res['issues'] = issues
    res['relocs'] = len(rels)
    res['relocs_checked'] = checked
    res['relocs_inferred'] = inferred_only
    res['resolved_by'] = sources
    res['orig_fixups'] = nfix
    res['masked_bytes'] = sum(1 for i in range(span) if mask_obj[i] or mask_orig[i])
    res['padding'] = padding
    res['inferred'] = {k: hex(v[0]) for k, v in inferred.items()}
    if identical:
        res['ratio'] = 1.0
    else:
        res['ratio'] = round(_ratio(ob, orig[:n_orig], mask_obj, mask_orig), 4)
        res['context'] = hex_context(ob, orig[:max(n_orig, min(len(orig), n_obj))], mask_obj, mask_orig,
                                     res['first_diff'], va)
    return res


def _ranges(idx):
    out = []
    for i in idx:
        if out and out[-1][1] == i:
            out[-1][1] = i + 1
        else:
            out.append([i, i + 1])
    return out


def _ratio(a, b, ma, mb):
    ta = [256 if (i < len(ma) and (ma[i] or mb[i])) else a[i] for i in range(len(a))]
    tb = [256 if (i < len(ma) and (ma[i] or mb[i])) else b[i] for i in range(len(b))]
    if len(ta) * len(tb) > 64_000_000:      # very large: aligned compare only
        same = sum(1 for x, y in zip(ta, tb) if x == y)
        return 2.0 * same / (len(ta) + len(tb)) if ta or tb else 1.0
    return difflib.SequenceMatcher(None, ta, tb, autojunk=False).ratio()


def hex_context(a, b, ma, mb, at, va, before=16, after=32):
    start = max(0, (at // 16) * 16 - before)
    end = min(max(len(a), len(b)), (at // 16) * 16 + after)
    lines = []

    def cell(buf, mask, i):
        if i >= len(buf):
            return '  '
        return '..' if (i < len(ma) and (ma[i] or mb[i])) else f'{buf[i]:02x}'

    for row in range(start, end, 16):
        ra = ' '.join(cell(a, ma, i) for i in range(row, min(row + 16, end)))
        rb = ' '.join(cell(b, mb, i) for i in range(row, min(row + 16, end)))
        mk = ' '.join('^^' if (cell(a, ma, i) != cell(b, mb, i)) else '  ' for i in range(row, min(row + 16, end)))
        lines.append(f'  obj  +{row:04x}  {ra}')
        lines.append(f'  orig {va + row:08x} {rb}')
        if mk.strip():
            lines.append(f'               {mk}'.rstrip())
    return '\n'.join(lines)


def format_result(r, verbose=True, all_diffs=False):
    head = f'{r["symbol"]} [{os.path.basename(r["obj"])}] vs 0x{r["va"]:x}: '
    if r['status'] == 'error':
        return head + 'ERROR ' + r['error']
    if r['identical']:
        s = (head + f'IDENTICAL  {r["obj_size"]} bytes, {r["relocs"]} relocs ({r["relocs_checked"]} target-checked, '
             f'{r["relocs_inferred"]} inferred), {r["orig_fixups"]} original fixups')
        if r['padding']:
            s += f', {r["padding"]} padding bytes'
        return s
    out = [head + f'DIFFERENT  ratio {r["ratio"]:.4f}, first difference at +0x{r["first_diff"]:x} '
                  f'(0x{r["va"] + r["first_diff"]:x}); sizes obj {r["obj_size"]} / orig {r["orig_size"]}, '
                  f'{r["diff_bytes"]} differing unmasked bytes']
    if verbose:
        for i in r['issues'][:20]:
            out.append(f'  +0x{i["offset"]:04x} {i["kind"]}: {i["detail"]}')
        if len(r['issues']) > 20:
            out.append(f'  ... {len(r["issues"]) - 20} more issues')
        if all_diffs and r['diff_ranges']:
            out.append('  differing ranges: ' + ', '.join(f'+0x{a:x}..+0x{b:x}' for a, b in r['diff_ranges']))
        out.append(r.get('context', ''))
    return '\n'.join(out)


# ----------------------------------------------------------------------------------------------- names

OPS = {'0': '<ctor>', '1': '<dtor>', '2': '<op new>', '3': '<op delete>', '4': '<op=>', '5': '<op>>>',
       '6': '<op<<>', '7': '<op!>', '8': '<op==>', '9': '<op!=>', 'A': '<op[]>', 'B': '<opcast>', 'C': '<op->>',
       'D': '<op*>', 'E': '<op++>', 'F': '<op-->', 'G': '<op->', 'H': '<op+>', 'I': '<op&>', 'J': '<op->*>',
       'K': '<op/>', 'L': '<op%>', 'M': '<op<>', 'N': '<op<=>', 'O': '<op>>', 'P': '<op>=>', 'Q': '<op,>',
       'R': '<op()>', 'S': '<op~>', 'T': '<op^>', 'U': '<op|>', 'V': '<op&&>', 'W': '<op||>', 'X': '<op*=>',
       'Y': '<op+=>', 'Z': '<op-=>', '_0': '<op/=>', '_1': '<op%=>', '_2': '<op>>=>', '_3': '<op<<=>',
       '_4': '<op&=>', '_5': '<op|=>', '_6': '<op^=>', '_7': '<vftable>', '_8': '<vbtable>', '_E': '<vdtor>',
       '_G': '<sdtor>', '_U': '<op new[]>', '_V': '<op delete[]>'}


def name_parts(name):
    """Qualified-name parts (outer -> inner) of a decorated symbol, or None (templates, unparsable).
    ?Update@CUnit@@QAEXXZ -> ('CUnit','Update'); ??0CUnit@@QAE@XZ -> ('CUnit','<ctor>'); _foo@8 -> ('foo',)."""
    if name.startswith('__imp_'):
        return None
    if not name.startswith('?'):
        m = re.fullmatch(r'[_@]?([A-Za-z_$][\w$]*?)(?:@\d+)?', name)
        return (m.group(1),) if m else None
    s = name[1:]
    names = []
    if s.startswith('?'):
        code = s[1:3] if s[1:2] == '_' else s[1:2]
        first = OPS.get(code)
        if first is None:
            return None
        rest = s[1 + len(code):]
    elif s.startswith('$'):
        return None
    else:
        i = s.find('@')
        if i <= 0:
            return None
        first = s[:i]
        names.append(first)
        rest = s[i + 1:]
    scopes = []
    while True:
        if rest.startswith('@'):
            break
        if not rest:
            return None
        c = rest[0]
        if c.isdigit():
            k = int(c)
            if k >= len(names):
                return None
            scopes.append(names[k])
            rest = rest[1:]
            continue
        if c == '?':
            if rest.startswith('?$'):
                return None
            j = rest.find('@')
            if j < 0:
                return None
            scopes.append('<anon>' if rest.startswith('?A') else rest[1:j])
            rest = rest[j + 1:]
            continue
        j = rest.find('@')
        if j < 0:
            return None
        names.append(rest[:j])
        scopes.append(rest[:j])
        rest = rest[j + 1:]
    return tuple(reversed(scopes)) + (first,)


SKIP_CALLS = {'__declspec', '__attribute__', 'alignas', 'decltype', '__pragma', '_Pragma', 'if', 'while', 'for',
              'switch', 'return', 'sizeof', 'DECOMP_SIZE_ASSERT', 'static_assert'}
QUAL_CALL = re.compile(r'((?:~?[A-Za-z_]\w*\s*::\s*)*(?:operator\s*(?:\(\s*\)|\[\s*\]|new\s*\[\s*\]|delete\s*\[\s*\]|'
                       r'new\b|delete\b|->\*|->|[-+*/%^&|~!=<>,]+)|~?[A-Za-z_]\w*))\s*\(')


def source_parts(qual):
    """'CUnit::Update' -> ('CUnit','Update'); 'A::A' -> ('A','<ctor>'); 'A::~A' -> ('A','<dtor>')."""
    if '<' in qual:
        return None
    parts = [p.strip() for p in qual.split('::')]
    last = parts[-1]
    if last.startswith('operator'):
        op = re.sub(r'\s+', '', last[8:])
        if op in ('new', 'delete', 'new[]', 'delete[]'):
            op = ' ' + op
        parts[-1] = f'<op{op}>'
    elif last.startswith('~'):
        parts[-1] = '<dtor>'
    elif len(parts) >= 2 and last == parts[-2]:
        parts[-1] = '<ctor>'
    return tuple(parts)


def parse_definition(text):
    """Qualified function name from a definition's text (up to '{' or ';')."""
    for m in QUAL_CALL.finditer(text):
        q = re.sub(r'\s+', '', m.group(1)) if 'operator' not in m.group(1) else m.group(1).strip()
        if q.split('::')[-1] in SKIP_CALLS:
            continue
        return q
    return None


# ----------------------------------------------------------------------------------------------- annotations

ANNOT = re.compile(r'^\s*//\s*(FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY|GLOBAL|VTABLE|STRING)\s*:\s*'
                   r'(?:([A-Za-z_][A-Za-z0-9_]*)\s+)?0x([0-9A-Fa-f]+)\b\s*(.*?)\s*$')
SRC_EXT = ('.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx', '.inl', '.inc')


def iter_sources(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs.sort()
                for f in sorted(files):
                    if f.lower().endswith(SRC_EXT):
                        yield os.path.join(root, f)
        else:
            yield p


def scan_annotations(paths, module=None):
    out = []
    for path in iter_sources(paths):
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()
        i = 0
        while i < len(lines):
            m = ANNOT.match(lines[i])
            if not m:
                i += 1
                continue
            group = []
            while i < len(lines) and ANNOT.match(lines[i]):
                m = ANNOT.match(lines[i])
                group.append({'kind': m.group(1), 'module': m.group(2), 'va': int(m.group(3), 16),
                              'explicit': m.group(4) or None, 'file': path, 'line': i + 1})
                i += 1
            # following comment lines (reccmp puts names of SYNTHETIC/TEMPLATE/LIBRARY there), then the declaration
            comment_name = None
            j = i
            while j < len(lines) and (not lines[j].strip() or lines[j].strip().startswith('//')):
                if comment_name is None and lines[j].strip().startswith('//'):
                    comment_name = lines[j].strip()[2:].strip() or None
                j += 1
            decl = []
            k = j
            while k < len(lines) and k < j + 12:
                decl.append(lines[k])
                if re.search(r'[{;]', lines[k]) or ANNOT.match(lines[k]):
                    break
                k += 1
            text = ' '.join(decl)
            text = re.split(r'[{;]', text, 1)[0] if re.search(r'[{;]', text) else text
            for a in group:
                if module and a['module'] and a['module'] != module:
                    continue
                a['decl'] = text.strip()
                a['comment_name'] = comment_name
                out.append(a)
    return out


def decl_parts(a):
    """Expected name parts for an annotation, or (None, reason)."""
    kind = a['kind']
    if kind in ('FUNCTION', 'STUB'):
        q = parse_definition(a['decl'])
        if not q:
            return None, f'no function definition found after the annotation: {a["decl"][:80]!r}'
        p = source_parts(q)
        return (p, q) if p else (None, f'templates are not mapped automatically ({q}); add the decorated symbol')
    if kind in ('TEMPLATE', 'SYNTHETIC', 'LIBRARY'):
        nm = a.get('comment_name') or ''
        nm = nm.replace("`scalar deleting destructor'", '<sdtor>').replace("`vector deleting destructor'", '<vdtor>')
        if not nm:
            return None, f'{kind} needs the name on the next comment line or a decorated symbol'
        if '<' in nm.replace('<sdtor>', '').replace('<vdtor>', ''):
            return None, f'templates are not mapped automatically ({nm}); add the decorated symbol'
        parts = [p.strip() for p in nm.split('::')]
        return tuple(parts) if parts[-1].startswith('<') else source_parts(nm), nm
    if kind == 'VTABLE':
        m = re.search(r'\b(?:class|struct)\s+(?:__declspec\([^)]*\)\s*)?([A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*)',
                      a['decl'])
        if not m:
            return None, 'no class/struct after VTABLE annotation'
        q = re.sub(r'\s+', '', m.group(1))
        return tuple(q.split('::')) + ('<vftable>',), q
    if kind == 'GLOBAL':
        t = re.split(r'=', a['decl'], 1)[0]
        m = re.search(r'\(\s*\*\s*([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\)', t) or \
            re.search(r'((?:[A-Za-z_]\w*\s*::\s*)*[A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*$', t.strip())
        if not m:
            return None, 'no variable name found after GLOBAL annotation'
        q = re.sub(r'\s+', '', m.group(1))
        return tuple(q.split('::')), q
    return None, f'{kind} annotations are listed only'


def obj_stem(path):
    return os.path.splitext(os.path.basename(path))[0].lower()


def map_annotation(a, objs, all_names):
    """Fill a['symbol'], a['objpath'] or a['status'] = 'unmapped'/'ambiguous' with a['error']."""
    stem = obj_stem(a['file'])
    is_func = a['kind'] in ('FUNCTION', 'STUB', 'TEMPLATE', 'SYNTHETIC', 'LIBRARY')
    same_tu = [o for o in objs if obj_stem(o.path) == stem]
    if is_func:
        pool = [(o, s) for o in (same_tu or objs) for s in o.functions()]
        if same_tu and a['explicit']:
            pool += [(o, s) for o in objs if o not in same_tu for s in o.functions()]
    else:
        pool = [(o, s) for o, s in all_names]
    explicit = a['explicit'].split()[0] if a['explicit'] else None
    if explicit and (explicit[0] in '?_@' or any(s.name == explicit for _, s in pool)):
        hits = [(o, s) for o, s in pool if s.name == explicit]
        if not hits:
            a['status'], a['error'] = 'unmapped', f'explicit symbol {explicit} not found in the objects'
            return
        a['symbol'], a['objpath'] = explicit, hits[0][0].path
        a['candidates_objs'] = sorted({o.path for o, _ in hits})
        a['status'] = 'mapped'
        return
    parts, q = decl_parts(a)
    if parts is None:
        a['status'], a['error'] = 'unmapped', q
        return
    a['source_name'] = q
    want = tuple(parts)
    if a['kind'] == 'VTABLE' and explicit:
        hits = [(o, s) for o, s in pool if s.name.startswith('??_7' + '@'.join(reversed(want[:-1])) + '@@6B')
                and f'{explicit}@@' in s.name]
    else:
        hits = [(o, s) for o, s in pool if name_parts(s.name) == want]
    names = sorted({s.name for _, s in hits})
    if not names:
        last = want[-1]
        near = sorted({s.name for _, s in pool if (name_parts(s.name) or ('',))[-1] == last})[:6]
        a['status'] = 'unmapped'
        a['error'] = f'no symbol for {q} ' + (f'(same name in other scopes: {", ".join(near)})' if near
                                              else f'in {", ".join(os.path.basename(o.path) for o in (same_tu or objs)) or "no objects"}')
        return
    if len(names) > 1:
        a['status'] = 'ambiguous'
        a['error'] = f'{q} matches {len(names)} symbols: {", ".join(names[:8])}; put the decorated name on the ' \
                     f'annotation line'
        return
    a['symbol'] = names[0]
    a['objpath'] = hits[0][0].path
    a['candidates_objs'] = sorted({o.path for o, _ in hits})
    a['status'] = 'mapped'


def collect_objs(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, fs in os.walk(p):
                dirs.sort()
                files += [os.path.join(root, f) for f in sorted(fs) if f.lower().endswith('.obj')]
        else:
            files.append(p)
    return files


def run_report(args):
    try:
        pe = PEImage(args.pe)
    except (OSError, PEError) as e:
        print(f'objcmp: {args.pe}: {e}', file=sys.stderr)
        return 2
    objs, load_errors = [], []
    for f in collect_objs(args.obj):
        try:
            objs.append(read_coff(f))
        except (OSError, CoffError, struct.error) as e:
            load_errors.append(f'{f}: {e}')
    for e in load_errors:
        print(f'objcmp: {e}', file=sys.stderr)
    amap = AddrMap(pe, auto_names=not args.no_auto_names)
    try:
        for m in args.map or []:
            amap.load(m)
        flist = load_function_list(args.functions) if args.functions else {}
    except (OSError, ValueError, KeyError) as e:
        print(f'objcmp: address map: {e}', file=sys.stderr)
        return 2
    annots = scan_annotations(args.src, args.module)
    all_names = [(o, s) for o in objs for s in o.symbols.values() if not s.is_section_sym and s.storage in
                 (CLASS_EXTERNAL, CLASS_STATIC, CLASS_WEAK)]
    seen_va = {}
    for a in annots:
        if a['kind'] == 'STRING':
            a['status'] = 'listed'
            continue
        map_annotation(a, objs, all_names)
        if a.get('status') == 'mapped':
            amap.add(a['symbol'], a['va'], f'{a["file"]}:{a["line"]}')
        if a['kind'] in ('FUNCTION', 'STUB', 'TEMPLATE', 'SYNTHETIC', 'LIBRARY'):
            key = (a['module'], a['va'])
            if key in seen_va:
                a['status'] = 'error'
                a['error'] = f'address 0x{a["va"]:x} already annotated at {seen_va[key]}'
            else:
                seen_va[key] = f'{a["file"]}:{a["line"]}'
    known_starts = set(flist) | {a['va'] for a in annots if a['kind'] in ('FUNCTION', 'STUB', 'TEMPLATE',
                                                                          'SYNTHETIC', 'LIBRARY')}
    by_path = {o.path: o for o in objs}
    funcs, globs = [], []
    inferred_all = {}
    for a in annots:
        if a['kind'] not in ('FUNCTION', 'STUB', 'TEMPLATE', 'SYNTHETIC', 'LIBRARY'):
            globs.append({k: a.get(k) for k in ('kind', 'module', 'file', 'line', 'symbol', 'status', 'error')}
                         | {'va': hex(a['va'])})
            continue
        e = {'kind': a['kind'], 'module': a['module'], 'va': a['va'], 'file': a['file'], 'line': a['line'],
             'symbol': a.get('symbol'), 'status': a['status']}
        if a['kind'] == 'STUB' and a['status'] != 'error':
            e['status'] = 'stub'
            e['orig_size'] = flist.get(a['va'])
            funcs.append(e)
            continue
        if a['status'] != 'mapped':
            e['error'] = a.get('error')
            e['orig_size'] = flist.get(a['va'])
            funcs.append(e)
            continue
        o = by_path[a['objpath']]
        sym = [s for s in o.find(a['symbol'])][0]
        r = compare_function(o, sym, pe, a['va'], None, amap, known_starts)
        e.update({k: r.get(k) for k in ('status', 'identical', 'ratio', 'obj_size', 'orig_size', 'first_diff',
                                        'diff_bytes', 'issues', 'relocs', 'relocs_checked', 'relocs_inferred',
                                        'orig_fixups', 'padding', 'error', 'context')})
        e['obj'] = o.path
        if len(a.get('candidates_objs', [])) > 1:
            e['note'] = f'symbol defined in {len(a["candidates_objs"])} objects; compared {o.path}'
        for k, v in r.get('inferred', {}).items():
            inferred_all.setdefault(k, {}).setdefault(v, []).append(hex(a['va']))
        funcs.append(e)
    # summary
    compared = [f for f in funcs if f['status'] in ('identical', 'different')]
    ident = [f for f in compared if f['status'] == 'identical']
    failed = [f for f in funcs if f['status'] not in ('identical', 'stub')]
    bytes_total = sum((f.get('orig_size') or 0) for f in funcs)
    bytes_ident = sum(f['orig_size'] for f in ident)
    cross = {k: v for k, v in inferred_all.items() if len(v) > 1}
    summary = {'annotated_functions': len(funcs), 'compared': len(compared), 'identical': len(ident),
               'different': len(compared) - len(ident), 'stubs': sum(1 for f in funcs if f['status'] == 'stub'),
               'unmapped': sum(1 for f in funcs if f['status'] in ('unmapped', 'ambiguous', 'error')),
               'bytes_identical': bytes_ident, 'bytes_total': bytes_total, 'objects': len(objs),
               'object_errors': load_errors, 'pe_has_relocs': pe.has_relocs}
    for f in funcs:
        tag = {'identical': 'OK', 'different': 'DIFF', 'stub': 'STUB'}.get(f['status'], f['status'].upper())
        ratio = f'{100 * f["ratio"]:6.2f}%' if f.get('ratio') is not None else '      -'
        size = f'{f.get("obj_size") or f.get("orig_size") or 0:6d}'
        line = f'{tag:9} 0x{f["va"]:08x} {ratio} {size}  {f.get("symbol") or "-"}'
        if f['status'] == 'different':
            line += f'  first diff +0x{f["first_diff"]:x}'
            if f.get('issues'):
                line += f' ({f["issues"][0]["kind"]})'
        elif f.get('error'):
            line += f'  {f["error"]}'
        rp = os.path.relpath(f['file'])
        line += f'  [{f["file"] if rp.startswith("..") else rp}:{f["line"]}]'
        if not args.quiet or f['status'] != 'identical':
            print(line)
        if args.verbose and f['status'] == 'different':
            for i in f['issues'][:10]:
                print(f'      +0x{i["offset"]:04x} {i["kind"]}: {i["detail"]}')
            print(f.get('context', ''))
    for g in globs:
        print(f'{g["kind"]:9} {g["va"]:>10} {g.get("symbol") or "-"}  {g.get("error") or ""}'.rstrip())
    for c in amap.conflicts:
        print(f'CONFLICT  {c["symbol"]}: {", ".join(c["addresses"])} from {", ".join(map(str, c["sources"]))}')
    for k, v in cross.items():
        print(f'WARNING   {k} inferred at different addresses: ' +
              '; '.join(f'{t} in {",".join(fs)}' for t, fs in v.items()))
    pct = lambda a, b: f'{100.0 * a / b:.1f}%' if b else '-'
    print(f'functions identical: {len(ident)}/{len(funcs)} ({pct(len(ident), len(funcs))}), compared {len(compared)}, '
          f'unmapped/ambiguous {summary["unmapped"]}, stubs {summary["stubs"]}; bytes identical: {bytes_ident}/'
          f'{bytes_total} ({pct(bytes_ident, bytes_total)})')
    if not pe.has_relocs:
        print('note: the PE has no .reloc; original-side masking relies on obj relocations only')
    if args.json:
        out = {'pe': args.pe, 'module': args.module, 'summary': summary, 'functions': funcs, 'data': globs,
               'address_conflicts': amap.conflicts,
               'inferred_symbols': {k: list(v)[0] for k, v in inferred_all.items() if len(v) == 1},
               'inferred_conflicts': cross}
        for f in funcs:
            f['va'] = hex(f['va'])
        _write_json(args.json, out)
    ok = not failed and not amap.conflicts and not load_errors
    return 0 if ok else 1


def _write_json(path, obj):
    text = json.dumps(obj, indent=1, default=str)
    if path == '-':
        sys.__stdout__.write(text + '\n')
    else:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text + '\n')


# ----------------------------------------------------------------------------------------------- dump

def dump_obj(o):
    out = [f'{o.path}: {"bigobj" if o.bigobj else "COFF"} i386, {len(o.sections)} sections, '
           f'{len(o.symbols)} symbols (+aux), timestamp 0x{o.timestamp:08x}', '', 'Sections:']
    for s in o.sections:
        c = ''
        if s.comdat:
            c = f' COMDAT {COMDAT_NAMES.get(s.comdat, s.comdat)}' + (f' assoc={s.assoc}' if s.comdat == 5 else '')
        out.append(f'  #{s.number:<3} {s.name:<12} size {s.size:6d} relocs {len(s.relocs):4d} '
                   f'{scn_flags(s.characteristics)}{c}')
    out += ['', 'Symbols:']
    for sym in o.symbols.values():
        sec = {0: 'UNDEF', -1: 'ABS', -2: 'DEBUG'}.get(sym.secnum, f'#{sym.secnum}')
        extra = ''
        if sym.is_function:
            extra = f' FUNCTION size {sym.size}'
        elif sym.is_section_sym:
            extra = ' (section)'
        elif sym.weak_default is not None:
            extra = f' weak -> [{sym.weak_default}]'
        out.append(f'  [{sym.index:4d}] {sec:>6} {sym.value:08x} type {sym.type:04x} '
                   f'{CLASS_NAMES.get(sym.storage, sym.storage):<9} {sym.name}{extra}')
    out += ['', 'Relocations:']
    for s in o.sections:
        for r in s.relocs:
            nm = r.symbol.name if r.symbol else f'?{r.symidx}'
            sz = r.size
            inplace = s.data[r.offset:r.offset + sz] if s.data else b''
            add = f' addend {_s32(_u32(inplace, 0)):+#x}' if sz == 4 and len(inplace) == 4 else ''
            flag = '' if r.type in SUPPORTED_RELS else '  UNSUPPORTED'
            out.append(f'  #{s.number:<3} +{r.offset:06x} {r.type_name:<8} [{r.symidx}] {nm}{add}{flag}')
    return '\n'.join(out)


def dump_json(o):
    return {'path': o.path, 'bigobj': o.bigobj, 'machine': o.machine,
            'sections': [{'number': s.number, 'name': s.name, 'size': s.size, 'characteristics': s.characteristics,
                          'comdat': s.comdat, 'assoc': s.assoc, 'checksum': s.checksum,
                          'relocs': [{'offset': r.offset, 'type': r.type_name, 'symbol': r.symbol.name if r.symbol
                                      else r.symidx} for r in s.relocs]} for s in o.sections],
            'symbols': [{'index': s.index, 'name': s.name, 'value': s.value, 'section': s.secnum, 'type': s.type,
                         'class': s.storage, 'naux': s.naux, 'function': s.is_function, 'size': s.size}
                        for s in o.symbols.values()]}


# ----------------------------------------------------------------------------------------------- writer

def _align_flag(n):
    return (n.bit_length()) << 20 if n and n & (n - 1) == 0 else 0x00500000


def jamcrc(data):
    return (zlib.crc32(data) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def write_obj(path, functions=(), data=(), absolutes=None, bigobj=False, comdat=True, text_name=None,
              timestamp=0, align=16):
    """Write an i386 COFF object.

    functions: [{name, bytes, relocations: [{offset, type ('DIR32'|'REL32'|'DIR32NB'|'SECREL'|'SECTION'|int),
                 symbol, addend (optional: written in place)}], static (bool), selection (COMDAT, default 1
                 NODUPLICATES; 2 ANY), section (name override), align}]
    data:      [{name, bytes, section ('.data'|'.rdata'|'.bss'), relocations, static, align, size (bss)}]
    absolutes: {name: value} absolute symbols (section -1).
    comdat=True puts every function in its own COMDAT section (like /Gy; name text_name, default '.text$mn');
    comdat=False concatenates all functions into one '.text' section (no padding) like a compile without /Gy.
    Relocation targets not defined here become undefined external symbols. Returns the bytes written.
    """
    absolutes = dict(absolutes or {})
    secs = []      # dicts: name, ch, data(bytearray|None), size, relocs [(off, symname, type)], syms [(name, off, static, func)], sel
    if comdat:
        tname = text_name or '.text$mn'
        for f in functions:
            al = f.get('align', align)
            secs.append({'name': f.get('section', tname),
                         'ch': SCN_CNT_CODE | SCN_LNK_COMDAT | SCN_EXEC | SCN_READ | _align_flag(al),
                         'data': bytearray(f['bytes']), 'relocs': [], 'syms': [(f['name'], 0, f.get('static'), True)],
                         'sel': f.get('selection', 1)})
            for r in f.get('relocations', ()):
                secs[-1]['relocs'].append((r['offset'], r['symbol'], rel_type(r['type']), r.get('addend')))
    elif functions:
        sec = {'name': text_name or '.text', 'ch': SCN_CNT_CODE | SCN_EXEC | SCN_READ | _align_flag(align),
               'data': bytearray(), 'relocs': [], 'syms': [], 'sel': 0}
        for f in functions:
            base = len(sec['data'])
            sec['data'] += f['bytes']
            sec['syms'].append((f['name'], base, f.get('static'), True))
            for r in f.get('relocations', ()):
                sec['relocs'].append((base + r['offset'], r['symbol'], rel_type(r['type']), r.get('addend')))
        secs.append(sec)
    for dd in data:
        sname = dd.get('section', '.data')
        al = dd.get('align', 4)
        if sname.startswith('.bss'):
            ch = SCN_CNT_UDATA | SCN_READ | SCN_WRITE | _align_flag(al)
            secs.append({'name': sname, 'ch': ch, 'data': None, 'size': dd.get('size', len(dd.get('bytes', b''))),
                         'relocs': [], 'syms': [(dd['name'], 0, dd.get('static'), False)], 'sel': 0})
            continue
        ch = SCN_CNT_IDATA | SCN_READ | _align_flag(al) | (0 if sname.startswith('.rdata') else SCN_WRITE)
        secs.append({'name': sname, 'ch': ch, 'data': bytearray(dd['bytes']), 'relocs': [],
                     'syms': [(dd['name'], 0, dd.get('static'), False)], 'sel': 0})
        for r in dd.get('relocations', ()):
            secs[-1]['relocs'].append((r['offset'], r['symbol'], rel_type(r['type']), r.get('addend')))

    # in-place addends
    for s in secs:
        for off, _, t, add in s['relocs']:
            if add is not None and s['data'] is not None:
                if REL_SIZE.get(t) == 4:
                    struct.pack_into('<i' if add < 0 else '<I', s['data'], off, add)
                elif REL_SIZE.get(t) == 2:
                    struct.pack_into('<h' if add < 0 else '<H', s['data'], off, add)

    strtab = bytearray(b'\0\0\0\0')
    str_off = {}

    def strref(nm):
        if nm not in str_off:
            str_off[nm] = len(strtab)
            strtab.extend(nm.encode('latin-1') + b'\0')
        return str_off[nm]

    def sym_name(nm):
        b = nm.encode('latin-1')
        return b.ljust(8, b'\0') if len(b) <= 8 else struct.pack('<II', 0, strref(nm))

    def sec_name(nm):
        b = nm.encode('latin-1')
        return b.ljust(8, b'\0') if len(b) <= 8 else (f'/{strref(nm)}').encode('ascii').ljust(8, b'\0')

    symsize = 20 if bigobj else 18
    symfmt = '<8sIiHBB' if bigobj else '<8sIhHBB'
    records = []                 # raw symbol-table records
    index = {}                   # defined/abs/undef name -> symbol index

    def add_sym(nm, value, secnum, typ, storage, aux=()):
        idx = len(records)
        records.append(struct.pack(symfmt, sym_name(nm), value & 0xFFFFFFFF, secnum, typ, storage, len(aux)))
        for a in aux:
            records.append(a.ljust(symsize, b'\0'))
        return idx

    # section symbols + defined symbols (the COMDAT symbol right after its section symbol)
    for i, s in enumerate(secs, 1):
        raw = bytes(s['data']) if s['data'] is not None else b''
        size = len(raw) if s['data'] is not None else s['size']
        s['size'] = size
        nrel = len(s['relocs'])
        if bigobj:
            aux = struct.pack('<IHHIHBBH', size, min(nrel, 0xFFFF), 0, jamcrc(raw), 0, s['sel'], 0, 0)
        else:
            aux = struct.pack('<IHHIHB', size, min(nrel, 0xFFFF), 0, jamcrc(raw), 0, s['sel'])
        add_sym(s['name'], 0, i, 0, CLASS_STATIC, [aux])
        for nm, off, static, func in s['syms']:
            if nm in index:
                raise ValueError(f'symbol {nm} defined twice')
            index[nm] = add_sym(nm, off, i, 0x20 if func else 0, CLASS_STATIC if static else CLASS_EXTERNAL)
    for nm, v in absolutes.items():
        index[nm] = add_sym(nm, v, -1, 0, CLASS_STATIC if nm.startswith('@') else CLASS_EXTERNAL)
    for s in secs:
        for _, nm, t, _ in s['relocs']:
            if nm not in index:
                index[nm] = add_sym(nm, 0, 0, 0x20 if t == REL32 else 0, CLASS_EXTERNAL)

    hdr_size = 56 if bigobj else 20
    pos = hdr_size + 40 * len(secs)
    layout = []
    for s in secs:
        rawptr = 0
        if s['data'] is not None and s['size']:
            rawptr = pos
            pos += s['size']
        relptr = 0
        nrel = len(s['relocs'])
        if nrel:
            relptr = pos
            pos += 10 * (nrel + (1 if nrel >= 0xFFFF else 0))
        layout.append((rawptr, relptr))
    symptr = pos
    nsyms = len(records)

    out = bytearray()
    if bigobj:
        out += struct.pack('<HHHHI16sIIII', 0, 0xFFFF, 2, MACHINE_I386, timestamp, BIGOBJ_CLSID, 0, 0, 0, 0)
        out += struct.pack('<III', len(secs), symptr, nsyms)
    else:
        out += struct.pack('<HHIIIHH', MACHINE_I386, len(secs), timestamp, symptr, nsyms, 0, 0)
    sec_names = [sec_name(s['name']) for s in secs]      # may extend strtab; fine (strtab written last)
    for s, nm, (rawptr, relptr) in zip(secs, sec_names, layout):
        nrel = len(s['relocs'])
        ch = s['ch'] | (SCN_NRELOC_OVFL if nrel >= 0xFFFF else 0)
        out += struct.pack('<8sIIIIIIHHI', nm, 0, 0, s['size'], rawptr, relptr, 0,
                           0xFFFF if nrel >= 0xFFFF else nrel, 0, ch)
    for s, (rawptr, relptr) in zip(secs, layout):
        if rawptr:
            assert len(out) == rawptr
            out += bytes(s['data'])
        if relptr:
            assert len(out) == relptr
            if len(s['relocs']) >= 0xFFFF:
                out += struct.pack('<IIH', len(s['relocs']) + 1, 0, 0)
            for off, nm, t, _ in s['relocs']:
                out += struct.pack('<IIH', off, index[nm], t)
    assert len(out) == symptr
    for rec in records:
        out += rec
    struct.pack_into('<I', strtab, 0, len(strtab))
    out += strtab
    with open(path, 'wb') as f:
        f.write(out)
    return bytes(out)


# ----------------------------------------------------------------------------------------------- CLI

def resolve_symbol(obj, spec):
    hits = obj.find(spec)
    if hits:
        return hits[0], None
    q = spec if '::' in spec or re.fullmatch(r'[A-Za-z_]\w*', spec) else None
    want = source_parts(q) if q else None
    if want:
        cands = [s for s in obj.functions() if name_parts(s.name) == want]
        if len({s.name for s in cands}) == 1:
            return cands[0], None
        if cands:
            return None, f'{spec} is ambiguous: ' + ', '.join(sorted({s.name for s in cands}))
    return None, f'no function symbol {spec} in {obj.path} (functions: ' + \
        ', '.join(s.name for s in obj.functions()[:12]) + (' ...' if len(obj.functions()) > 12 else '') + ')'


def run_compare(args):
    try:
        obj = read_coff(args.obj)
        pe = PEImage(args.pe)
        va = parse_int(args.va)
        size = parse_int(args.size, hex_default=False) if args.size else None
        amap = AddrMap(pe, auto_names=not args.no_auto_names)
        for m in args.map or []:
            amap.load(m)
        flist = load_function_list(args.functions) if args.functions else {}
    except (OSError, CoffError, PEError, ValueError, KeyError, struct.error) as e:
        print(f'objcmp: {e}', file=sys.stderr)
        return 2
    sym, err = resolve_symbol(obj, args.symbol)
    if sym is None:
        print(f'objcmp: {err}', file=sys.stderr)
        return 2
    r = compare_function(obj, sym, pe, va, size, amap, set(flist))
    print(format_result(r, True, args.all_diffs))
    if args.json:
        _write_json(args.json, r)
    if r['status'] == 'error':
        return 2
    return 0 if r['identical'] else 1


def run_dump(args):
    try:
        o = read_coff(args.obj)
    except (OSError, CoffError, struct.error) as e:
        print(f'objcmp: {args.obj}: {e}', file=sys.stderr)
        return 2
    print(dump_obj(o))
    if args.json:
        _write_json(args.json, dump_json(o))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog='objcmp.py', description=__doc__.split('\n')[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd')
    c = sub.add_parser('compare', help='compare one obj function with the original at a VA')
    c.add_argument('obj')
    c.add_argument('symbol')
    c.add_argument('pe')
    c.add_argument('va')
    c.add_argument('size', nargs='?')
    r = sub.add_parser('report', help='compare every annotated function')
    r.add_argument('--pe', required=True)
    r.add_argument('--src', nargs='+', required=True)
    r.add_argument('--obj', nargs='+', required=True)
    r.add_argument('--module')
    r.add_argument('--verbose', '-v', action='store_true', help='issues and hex context for each difference')
    r.add_argument('--quiet', '-q', action='store_true', help='do not list identical functions')
    for p in (c, r):
        p.add_argument('--map', action='append', help='address map file (repeatable)')
        p.add_argument('--functions', help='Ghidra index.json: known function starts (end-of-function checks)')
        p.add_argument('--no-auto-names', action='store_true', help='do not resolve FUN_/DAT_<hex> names')
        p.add_argument('--json', help='write JSON results (- for stdout)')
    c.add_argument('--all-diffs', action='store_true', help='list every differing byte range')
    d = sub.add_parser('dump', help='sections, symbols and relocations of an object')
    d.add_argument('obj')
    d.add_argument('--json')
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    runner = {'compare': run_compare, 'report': run_report, 'dump': run_dump}.get(args.cmd)
    if runner:
        if getattr(args, 'json', None) == '-':          # JSON on stdout, text to stderr
            with contextlib.redirect_stdout(sys.stderr):
                return runner(args)
        return runner(args)
    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())
