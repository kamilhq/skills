#!/usr/bin/env python3
"""Phase 6: relink a PE with the original linker (link.exe) from compiled objects + objects made from assembly.

  relink.py prepare <reassembled_dir> <symbols.json> <decompiled_dir> <out_dir> [--cache <file>]
                    [--libdir <dir with import .lib files, e.g. the Windows SDK's Lib>]... [--free]
      --free: build from source. The map may hold edited functions (hybrid_link.py map --all): each replaces
      its original slot and the code after it moves; sections new to the original (literals, constants,
      helpers) come from the units' objects, new code after the original code, new data after the original
      data. Skips the .reloc calibration; `finish` does not apply.
      Writes into <out_dir>:
        code_NNN.obj     the code section as COMDAT pieces: every function hybrid_link.py mapped as identical
                         (the COMPILER's bytes, its relocations retargeted to synthetic symbols _A_<va>) and the
                         phase-5b assembly between them, split at every function start (absolute pointers ->
                         DIR32, direct rel32 branches leaving a piece -> REL32)
        round<k>.obj     pieces that use imports of link.exe's library-search pass k >= 2 (the CRT, SDL2main...),
                         turned into round<k>.lib at link time and placed after the last import library of that
                         pass, so link.exe pulls them - and their imports - in the same passes as the original
        imports_order.obj  undefined symbols only: the first pass's imports in the original's hint/name order
        imp_<dll>.def    import libraries to generate (DLLs that no --libdir library matches by name and hint)
        data.obj         .rdata/.data(+.bss)/... as raw sections with DIR32 relocations; the export table as
                         .edata, the load config as __load_config_used; IAT and import tables left out (link.exe
                         builds them from the import libraries)
        resources.res + manifest.xml  when the original's .rsrc was rewritten by mt.exe (PADDINGXX fill)
        order.txt, link.rsp  /ORDER file (every code COMDAT in address order) and link.exe options from the header
  relink.py link <out_dir> <original>
      lib.exe for the .def/.obj libraries, link.exe, mt.exe for the manifest; measures the .reloc reserve once
      and adds dropped.obj (a discarded COMDAT with the missing relocation count) and links again. Compares
      with the original: SHA-256, section by section, data directories, header bytes (compare.json).
  relink.py check <out_dir> <original> <symbols.json> <instructions.tsv> <functions index.json>
      For a --free build: every direct branch and code pointer of the original (outside edited functions)
      must reach its target's new address in the link map (relinked.map). Exit 0 when none misses.
  relink.py finish <out_dir> <original>
      Post-link facts the inputs cannot reproduce (Rich header, timestamp, IAT slot order inside each DLL,
      Wine-vs-Windows UpdateResource bytes, checksum), taken from the original, applied to relinked.exe ->
      final.exe with every patched byte counted per fact (facts.json). Exit 0 when final.exe is identical.

Synthetic symbols: every relocation target gets `_A_<hex va>` defined in the piece that contains it; targets in
the headers use `___ImageBase`; IAT slots become `__imp_<symbol>` of the import library. Python stdlib + the
user's toolchain (link.exe, lib.exe, mt.exe under Wine) only.
"""
import bisect, hashlib, json, os, re, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import objcmp       # noqa: E402
import reassemble   # noqa: E402

DIR32, DIR32NB, REL32 = 0x6, 0x7, 0x14
SCN_CNT_CODE, SCN_CNT_IDATA, SCN_CNT_UDATA = 0x20, 0x40, 0x80
SCN_LNK_COMDAT, SCN_EXEC, SCN_READ, SCN_WRITE = 0x1000, 0x20000000, 0x40000000, 0x80000000
ALIGN1 = 0x00100000


def sname(va):
    return f'_A_{va:x}'


class Coff:
    """Minimal i386 COFF writer: sections with several symbols, COMDATs, relocations."""

    def __init__(self):
        self.secs = []

    def section(self, name, ch, data, size=None, comdat=False):
        self.secs.append(dict(name=name, ch=ch, data=data, size=size if size is not None else len(data or b''),
                              relocs=[], syms=[], comdat=comdat))
        return len(self.secs)          # 1-based section number

    def symbol(self, secnum, name, value, external=True):
        self.secs[secnum - 1]['syms'].append((name, value, external))

    def reloc(self, secnum, off, name, typ):
        self.secs[secnum - 1]['relocs'].append((off, name, typ))

    def write(self, path):
        strtab = bytearray(b'\0\0\0\0')

        def nm8(n):
            b = n.encode('latin-1')
            if len(b) <= 8:
                return b.ljust(8, b'\0')
            off = len(strtab)
            strtab.extend(b + b'\0')
            return b'\0\0\0\0' + struct.pack('<I', off)
        syms, index = [], {}

        def add(rec):
            syms.append(rec)
        # explicitly listed undefined symbols first (their order is the order link.exe meets them), then
        # the other relocation targets
        undefined = [n for n in dict.fromkeys(getattr(self, 'undefined', []))
                     if not any(n == x[0] for sec_ in self.secs for x in sec_['syms'])]
        for i, s in enumerate(self.secs, 1):
            # section symbol (+ aux) first
            add(nm8(s['name']) + struct.pack('<IhHBB', 0, i, 0, 3, 1))
            sel = 2 if s['comdat'] else 0
            add(struct.pack('<IHHIhB', s['size'], len(s['relocs']), 0, 0, 0, sel) + b'\0' * 3)
            for (n, v, ext) in s['syms']:
                index[n] = len(syms)
                add(nm8(n) + struct.pack('<IhHBB', v, i, 0x20 if s['ch'] & SCN_EXEC else 0, 2 if ext else 3, 0))
        for s in self.secs:
            for (_, n, _) in s['relocs']:
                if n not in index and n not in undefined:
                    undefined.append(n)
        for n in undefined:
            index[n] = len(syms)
            add(nm8(n) + struct.pack('<IhHBB', 0, 0, 0, 2, 0))
        nsec = len(self.secs)
        hdr_size = 20 + 40 * nsec
        off = hdr_size
        layout = []
        for s in self.secs:
            dptr = off if s['data'] is not None else 0
            off += len(s['data']) if s['data'] is not None else 0
            rptr = off if s['relocs'] else 0
            off += 10 * len(s['relocs'])
            layout.append((dptr, rptr))
        symptr = off
        out = bytearray(struct.pack('<HHIIIHH', 0x14c, nsec, 0, symptr, len(syms), 0, 0))
        for s, (dptr, rptr) in zip(self.secs, layout):
            out += nm8(s['name']) if len(s['name']) <= 8 else nm8(s['name'])
            out += struct.pack('<IIIIIIHHI', 0, 0, s['size'], dptr, rptr, 0, len(s['relocs']), 0, s['ch'])
        for s in self.secs:
            if s['data'] is not None:
                out += s['data']
            for (o, n, t) in s['relocs']:
                out += struct.pack('<IIH', o, index[n], t)
        for r in syms:
            out += r
        out += struct.pack('<I', len(strtab)) + strtab[4:]
        open(path, 'wb').write(out)
        return len(syms)


def read_imports(img, dirs, secs):
    """Import descriptors in file order: [(dll, [(hint, name, iat_rva)])], plus the RVA span of the import
    data link.exe builds outside the IAT (descriptors, lookup tables, hint/name entries, DLL names)."""
    if len(dirs) < 2 or not dirs[1][1]:
        return [], None

    def off(rva):
        s = next(x for x in secs if x['va'] <= rva < x['va'] + max(x['vsize'], x['raw_size']))
        return s['raw_ptr'] + rva - s['va']

    def cstr(rva):
        o = off(rva)
        return img[o:img.index(b'\0', o)].decode('latin-1')
    out, lo, hi, i = [], dirs[1][0], dirs[1][0], 0
    while True:
        oft, _, _, name, ft = struct.unpack_from('<IIIII', img, off(dirs[1][0] + 20 * i))
        if not oft and not name:
            hi = max(hi, dirs[1][0] + 20 * (i + 1))
            break
        dll = cstr(name)
        hi = max(hi, name + len(dll) + 1)
        fns, k = [], 0
        while True:
            e = struct.unpack_from('<I', img, off(oft + 4 * k))[0]
            if e == 0:
                break
            if e & 0x80000000:
                raise SystemExit(f'{dll}: import by ordinal not supported')
            hint = struct.unpack_from('<H', img, off(e))[0]
            fn = cstr(e + 2)
            fns.append((hint, fn, ft + 4 * k))
            lo, hi = min(lo, oft, e), max(hi, oft + 4 * (k + 2), e + 2 + len(fn) + 1)
            k += 1
        out.append((dll, fns))
        i += 1
    return out, (lo, hi)


def import_rounds(img, dirs, secs, imports):
    """Split the imports into link.exe's library-search passes, from the order of the hint/name entries.
    Returns ([[(dll, name)...] per pass], [dll in library order])."""
    def off(rva):
        s = next(x for x in secs if x['va'] <= rva < x['va'] + max(x['vsize'], x['raw_size']))
        return s['raw_ptr'] + rva - s['va']
    entries = []
    for i, (dll, fns) in enumerate(imports):
        oft = struct.unpack_from('<I', img, off(dirs[1][0] + 20 * i))[0]
        for k, (_, fn, _) in enumerate(fns):
            entries.append((struct.unpack_from('<I', img, off(oft + 4 * k))[0], dll, fn))
    entries.sort()
    lib_order = list(dict.fromkeys(dll for _, dll, _ in entries))
    rank = {d: i for i, d in enumerate(lib_order)}
    rounds, prev = [[]], None
    for _, dll, fn in entries:
        if prev is not None and dll != prev and rank[dll] < rank[prev]:
            rounds.append([])
        rounds[-1].append((dll, fn))
        prev = dll
    return rounds, lib_order


def prepare(reasm, map_path, ddir, outdir, cache=None, libdirs=(), free=False):
    os.makedirs(outdir, exist_ok=True)
    m = json.load(open(map_path))
    if any(not f.get('identical', True) for f in m['functions']) and not free:
        raise SystemExit('the map has edited functions: use --free (build from source, layout may change)')
    if free:
        open(os.path.join(outdir, 'FREE'), 'w').write('build from source: layout may differ from the original\n')
    elif os.path.exists(os.path.join(outdir, 'FREE')):
        os.remove(os.path.join(outdir, 'FREE'))
    new_secs = m.get('new_sections', {})
    new_name = {nk: f'_N_{i}' for i, nk in enumerate(sorted(new_secs))}
    tmp = tempfile.mkdtemp()
    reassemble.build(reasm, os.path.join(tmp, 'img.bin'), cache)
    img = open(os.path.join(tmp, 'img.bin'), 'rb').read()
    base, dirs, secs = reassemble.pe_parse(img)
    rel, reloc_name = reassemble.relocs_of(img, base, dirs, secs)
    T = next(s for s in secs if s['exec'])
    t0 = base + T['va']
    t_end = t0 + min(T['vsize'], T['raw_size'])

    def raw(va, n):
        s = next(x for x in secs if x['va'] <= va - base < x['va'] + max(x['raw_size'], x['vsize']))
        o = va - base - s['va']
        b = img[s['raw_ptr'] + o:s['raw_ptr'] + min(o + n, s['raw_size'])]
        return b + b'\0' * (n - len(b))
    # compiled functions. A target is an original VA (from the map), ('self', offset from the function start)
    # for an edited function's references into its own section (jump tables, labels), or ('new', symbol,
    # offset) for a section taken from the unit's object (new_sections).
    def target_of(o, t, own_secnum, own_value, edited):
        if edited and own_secnum > 0 and t.secnum == own_secnum:
            return ('self', (0 if t.is_section_sym else t.value) - own_value)
        base_key = (f"{os.path.basename(o.path)}#{t.name}#sec{t.secnum}"
                    if (t.is_section_sym or (t.storage not in (objcmp.CLASS_EXTERNAL, objcmp.CLASS_WEAK) and t.secnum > 0))
                    else t.name)
        v = m['symbols'].get(f'{os.path.basename(o.path)}@{base_key}', m['symbols'].get(base_key))
        if isinstance(v, dict):
            return ('new', new_name[v['new']], v['offset'])
        if v is None:
            raise SystemExit(f'{os.path.basename(o.path)}: no address for {base_key}')
        return v
    funcs = []
    objs = {}
    edited_vas = set()
    for f in m['functions']:
        va = int(f['va'], 16)
        o = objs.get(f['obj']) or objs.setdefault(f['obj'], objcmp.read_coff(f['obj']))
        sym = next(s for s in o.symbols.values() if s.index == f['index'] and s.name == f['symbol'])
        code, rels = o.function_bytes(sym)
        ed = not f.get('identical', True)
        if ed:
            edited_vas.add(va)
        tr = [(r.offset, r.type, target_of(o, r.symbol, sym.secnum, sym.value, ed))
              for r in rels if r.type != 0 and r.symbol is not None]
        funcs.append((va, bytes(code), tr))
    # sections taken from the units' objects for edited functions (new literals, constants, helpers)
    new_pieces = []
    for nk in sorted(new_secs):
        ns = new_secs[nk]
        o = objs.get(ns['obj']) or objs.setdefault(ns['obj'], objcmp.read_coff(ns['obj']))
        sec = o.sections[ns['section'] - 1]
        tr = [(r.offset, r.type, target_of(o, r.symbol, ns['section'], 0, True))
              for r in sec.relocs if r.type != 0 and r.symbol is not None]
        new_pieces.append((new_name[nk], sec, tr))
    funcs.sort()
    # pieces of the code section: compiled functions and the stretches between them
    pieces = []          # (start, end, kind, payload); end = the original extent
    fstarts = sorted(int(f['address'], 16) for f in json.load(open(os.path.join(ddir, 'index.json')))['functions'])
    fvas = [f[0] for f in funcs]
    cur = t0
    for n_, (va, code, tr) in enumerate(funcs):
        if va > cur:
            pieces.append((cur, va, 'asm', None))
        end = va + len(code)
        if va in edited_vas:       # an edited function replaces its original extent (up to the next function)
            nxt = [x for x in (fstarts[bisect.bisect_right(fstarts, va)] if bisect.bisect_right(fstarts, va) < len(fstarts) else None,
                               fvas[n_ + 1] if n_ + 1 < len(fvas) else None, t_end) if x is not None]
            end = min(nxt)
        pieces.append((va, end, 'fn', (code, tr)))
        cur = end
    if cur < t_end:
        pieces.append((cur, t_end, 'asm', None))
    # assembly stretches are split at every function start (Ghidra's list), so each function can go into the
    # object or library member that the import passes call for
    split = []
    for (ps, pe_, kind, payload) in pieces:
        if kind != 'asm':
            split.append((ps, pe_, kind, payload))
            continue
        cuts_ = [ps] + [f for f in fstarts[bisect.bisect_right(fstarts, ps):bisect.bisect_left(fstarts, pe_)]] + [pe_]
        split += [(a_, b_, 'asm', None) for a_, b_ in zip(cuts_, cuts_[1:])]
    pieces = split
    starts = [p[0] for p in pieces]
    # direct branches in asm stretches that leave the stretch
    br = {}
    with open(os.path.join(ddir, 'instructions.tsv')) as fh:
        next(fh)
        for line in fh:
            a, ln, fn, flow, targets, text = line.rstrip('\n').split('\t', 5)
            if flow in ('call', 'jump', 'cjump') and targets:
                br[int(a, 16)] = (int(ln), int(targets.split(',')[0], 16))
    # every relocation target needs a symbol in the piece / section that holds it
    targets = set()
    for va, code, tr in funcs:
        targets.update(t for _, _, t in tr if not isinstance(t, tuple))
    for _, _, tr in new_pieces:
        targets.update(t for _, _, t in tr if not isinstance(t, tuple))
    # RVA fields the PE keeps without base relocations: the SafeSEH handler table (load config) and the export
    # table. They go to link.exe as DIR32NB relocations, so they follow the code when the layout changes.
    rva_sites = rva_fields(img, base, dirs, secs)
    targets.update(rva_sites.values())
    for site, v in rel.items():
        targets.add(v)
    _pe = struct.unpack_from('<I', img, 0x3c)[0]
    targets.add(struct.unpack_from('<I', img, _pe + 24 + 16)[0] + base)     # the entry point
    data_secs = [s for s in secs if not s['exec'] and s['name'] != reloc_name]

    def where(va):
        if t0 <= va < t_end:
            i = bisect.bisect_right(starts, va) - 1
            return ('code', i)
        for j, s in enumerate(data_secs):
            if s['va'] <= va - base < s['va'] + max(s['vsize'], s['raw_size']):
                return ('data', j)
        return ('header', None)
    # imports: link.exe builds the IAT and the import tables from import libraries (lib.exe /DEF with every
    # name DATA - no jump thunks - and its hint as @ordinal, then name_imports() makes them imports by name);
    # pointers into the IAT become __imp__<name> references
    imports, imp_span = read_imports(img, dirs, secs)
    # an import library already on hand (--libdir, e.g. the SDK's) is used when it has every name of a DLL
    # with the same hints; the others are generated
    sdk = {}
    for ld in libdirs:
        for fn_ in sorted(os.listdir(ld)):
            if fn_.lower().endswith('.lib'):
                try:
                    for k, v in lib_imports(os.path.join(ld, fn_)).items():
                        sdk.setdefault(k, (v[0], v[1], os.path.join(ld, fn_)))
                except (ValueError, struct.error):
                    pass
    use_lib, sym_of = {}, {}
    for dll, fns in imports:
        hit = [sdk.get((dll.upper(), fn)) for _, fn, _ in fns]
        libs_ = {h[2] for h in hit if h}
        if all(h and h[0] == hint for h, (hint, _, _) in zip(hit, fns)) and len(libs_) == 1:
            use_lib[dll] = libs_.pop()
            for h, (_, fn, _) in zip(hit, fns):
                sym_of[(dll, fn)] = h[1]
        else:
            for _, fn, _ in fns:
                sym_of[(dll, fn)] = '_' + fn
    iat_name = {base + rva: f'__imp_{sym_of[(dll, fn)]}' for dll, fns in imports for _, fn, rva in fns}
    code_syms = {}
    data_syms = {}
    ext_name = {}
    for t in targets:
        if t in iat_name:
            ext_name[t] = iat_name[t]
            continue
        kind, i = where(t)
        if kind == 'code':
            code_syms.setdefault(i, set()).add(t)
            ext_name[t] = sname(t)
        elif kind == 'data':
            data_syms.setdefault(i, set()).add(t)
            ext_name[t] = sname(t)
        else:
            ext_name[t] = None      # headers: ___ImageBase + addend
    # pre-pass: direct rel32 branches in asm stretches whose target lies in another piece
    branch_relocs = {}
    rel8_cross = 0
    rel8_pairs = []
    for i, (s, e, kind, payload) in enumerate(pieces):
        if kind != 'asm':
            continue
        for a2 in range(s, e):
            if a2 not in br:
                continue
            ln, tgt = br[a2]
            if s <= tgt < e:
                continue
            b = raw(a2, ln)
            if b[:1] in (b'\xe8', b'\xe9') and ln == 5:
                o = a2 - s + 1
            elif b[:1] == b'\x0f' and ln == 6 and 0x80 <= b[1] <= 0x8f:
                o = a2 - s + 2
            else:
                rel8_cross += 1          # short branch across pieces: relies on identical layout
                rel8_pairs.append((a2, tgt))
                continue
            k2, i2 = where(tgt)
            if k2 != 'code':
                continue
            code_syms.setdefault(i2, set()).add(tgt)
            ext_name[tgt] = sname(tgt)
            branch_relocs.setdefault(i, []).append((o, tgt))
    if edited_vas:
        # an edited function moves everything after it: nothing may point into its old interior, and no short
        # branch between two other pieces may span it
        bad = []
        ranges = sorted((p_[0], p_[1]) for p_ in pieces if p_[0] in edited_vas)
        rstarts = [r[0] for r in ranges]

        def in_edited(x):
            k = bisect.bisect_right(rstarts, x) - 1
            return k >= 0 and x < ranges[k][1]
        # targets referenced from outside the edited functions (their own jump tables are replaced with them)
        outside = {v for site, v in rel.items() if not in_edited(site)}
        outside |= {v for site, v in rva_sites.items() if not in_edited(site)}
        for va_, code_, tr_ in funcs:
            if va_ not in edited_vas:
                outside |= {t for _, _, t in tr_ if not isinstance(t, tuple)}
        for i2, brs in branch_relocs.items():
            outside |= {t for _, t in brs}
        outside |= {base + struct.unpack_from('<I', img, struct.unpack_from('<I', img, 0x3c)[0] + 40)[0]}
        for i, p_ in enumerate(pieces):
            if p_[0] in edited_vas:
                bad += [f'{t:#x} (inside {p_[0]:#x})' for t in code_syms.get(i, ()) if t != p_[0] and t in outside]
                bad += [f'short branch {x:#x}->{y:#x} spans {p_[0]:#x}' for x, y in rel8_pairs
                        if min(x, y) <= p_[0] < max(x, y) or min(x, y) < p_[1] <= max(x, y)]
        if bad:
            raise SystemExit('edited functions cannot move: ' + '; '.join(bad[:10]))
    stats = dict(rel8_branches_across_pieces=rel8_cross, edited_functions=len(edited_vas), new_sections=len(new_pieces), code_pieces=len(pieces), compiled=len(funcs), asm=sum(1 for p in pieces if p[2] == 'asm'),
                 asm_rel32_relocs=0, dir32_relocs=0, header_targets=sum(1 for v in ext_name.values() if v is None))
    # Import passes (see import_rounds): a piece that uses an import of pass k >= 2 goes into the member of
    # library round<k>.lib; every other piece into the plain objects code_NNN.obj
    rounds, lib_order = import_rounds(img, dirs, secs, imports)
    pass_of = {sym_of[k]: r for r, names in enumerate(rounds, 1) for k in names}
    piece_imports = []
    for i, (ps, pe_, kind, payload) in enumerate(pieces):
        tv = [t for _, _, t in payload[1]] if kind == 'fn' else [rel[x] for x in range(ps, pe_) if x in rel]
        piece_imports.append([ext_name[t][6:] for t in tv if t in iat_name])
    piece_pass = [max([pass_of[n] for n in ims] or [1]) for ims in piece_imports]
    stats['pieces_per_pass'] = {k: piece_pass.count(k) for k in sorted(set(piece_pass))}

    def write_piece(c, i):
        s, e, kind, payload = pieces[i]
        if kind == 'fn':
            data = bytearray(payload[0])
        else:
            data = bytearray(raw(s, e - s))
        sec = c.section('.text$mn', SCN_CNT_CODE | SCN_EXEC | SCN_READ | SCN_LNK_COMDAT | ALIGN1, data, comdat=True)
        c.symbol(sec, sname(s), 0)
        for t in sorted(code_syms.get(i, ())):
            if t != s:
                c.symbol(sec, sname(t), t - s)
        if kind == 'fn':
            emit_targets(c, sec, data, payload[1], sname(s))
        else:
            for site in range(s, e):
                if site in rel:
                    v = rel[site]
                    struct.pack_into('<I', data, site - s, 0)
                    _emit(c, sec, data, site - s, DIR32, v, 0, s, base, ext_name, stats)
            for o, tgt in branch_relocs.get(i, ()):
                struct.pack_into('<i', data, o, 0)          # MSVC REL32: in-place addend 0
                c.reloc(sec, o, ext_name[tgt], REL32)
                stats['asm_rel32_relocs'] += 1
    def emit_targets(c, sec, data, tr, self_name):
        for off, typ, tva in tr:
            add = struct.unpack_from('<i', data, off)[0]
            if isinstance(tva, tuple):
                name, extra = (self_name, tva[1]) if tva[0] == 'self' else (tva[1], tva[2])
                struct.pack_into('<i', data, off, add + extra)
                c.reloc(sec, off, name, typ)
            else:
                _emit(c, sec, data, off, typ, tva, add, None, base, ext_name, stats)
    order = [sname(p_[0]) for p_ in pieces]
    plain = [i for i in range(len(pieces)) if piece_pass[i] == 1]
    nobj = 0
    per_obj = 400
    for k in range(0, len(plain), per_obj):
        c = Coff()
        for i in plain[k:k + per_obj]:
            write_piece(c, i)
        c.write(os.path.join(outdir, f'code_{nobj:03d}.obj'))
        nobj += 1
    stats['plain_pieces'] = len(plain)
    has_new_data = False
    if new_pieces:                 # sections from the units' objects (edited functions' new data and helpers):
        c = Coff()                 # new code after the original code, new data after the original data
        nd = Coff()
        for nm_, sec_, tr in new_pieces:
            if sec_.is_code:
                ch = SCN_CNT_CODE | SCN_EXEC | SCN_READ | ALIGN1
                name = '.text$mn'
            else:
                ch = sec_.characteristics & ~(0x00F00000 | SCN_LNK_COMDAT | 0x800 | 0x200)
                ch |= 0x00300000               # 4-byte alignment
                name = sec_.name.split('$')[0] or '.rdata'
            udata = bool(sec_.characteristics & SCN_CNT_UDATA)
            data = None if udata else bytearray(sec_.data[:sec_.size])
            cc = c if sec_.is_code else nd
            n_ = cc.section(name, ch, data, size=sec_.size)
            cc.symbol(n_, nm_, 0)
            if data is not None:
                emit_targets(cc, n_, data, tr, nm_)
        if c.secs:
            c.write(os.path.join(outdir, f'code_{nobj:03d}.obj'))
            nobj += 1
        if nd.secs:
            nd.write(os.path.join(outdir, 'new_data.obj'))
            has_new_data = True
    # data sections. The export table goes back to the linker as an .edata section (placed last in .rdata,
    # export directory filled by link) and __load_config_used marks the load configuration (directory 10).
    dd_rva = {k: dirs[k] for k in (0, 1, 10, 12) if len(dirs) > k and dirs[k][1]}
    # Resources. When the original's .rsrc was rewritten by UpdateResource (its 'PADDINGXX' fill: Visual
    # Studio's mt.exe embedding the manifest after link), the resources go to link.exe as a .res file without
    # the manifest, and the link step runs mt.exe the same way; otherwise .rsrc stays a raw section.
    res = read_resources(img, dirs, secs)
    rsrc_sec = next((x for x in data_secs if len(dirs) > 2 and dirs[2][1] and x['va'] == dirs[2][0]), None)
    mt_manifest = None
    if res and rsrc_sec is not None:
        tail = img[rsrc_sec['raw_ptr'] + rsrc_sec['vsize']:rsrc_sec['raw_ptr'] + rsrc_sec['raw_size']]
        mans = [r for r in res if r[0] == 24]
        if b'PADDINGXX' in tail and len(mans) == 1 and mans[0][1] == 1:
            if any(rsrc_sec['va'] <= t - base < rsrc_sec['va'] + rsrc_sec['vsize'] for t in targets):
                raise SystemExit('pointers into .rsrc: cannot rebuild it from a .res file')
            mt_manifest = mans[0][3]
            open(os.path.join(outdir, 'manifest.xml'), 'wb').write(mt_manifest)
            write_res(os.path.join(outdir, 'resources.res'), [r for r in res if r[0] != 24])
            data_secs = [x for x in data_secs if x is not rsrc_sec]
            data_syms = {data_secs.index(x): data_syms.get(j_, set()) for j_, x in enumerate(
                [y for y in secs if not y['exec'] and y['name'] != reloc_name]) if x in data_secs}
    stats['resources'] = 'resources.res + mt.exe manifest' if mt_manifest else 'raw .rsrc'
    d = Coff()
    for j, s in enumerate(data_secs):
        n = s['name']
        rawb = bytearray(img[s['raw_ptr']:s['raw_ptr'] + s['raw_size']]) if s['raw_size'] else bytearray()
        vlen = s['vsize'] or s['raw_size']          # a zero tail (.bss) only where vsize exceeds the raw data
        writable = n not in ('.rdata', '.rsrc')
        ch = SCN_CNT_IDATA | SCN_READ | (SCN_WRITE if writable else 0) | ALIGN1
        init_len = min(s['raw_size'], s['vsize']) if s['vsize'] else s['raw_size']
        # split points inside this section
        cuts = {0: n, init_len: None}
        if n == '.rdata':
            sva = s['va']
            def inside(r):
                return sva <= r < sva + init_len
            if 0 in dd_rva and inside(dd_rva[0][0]):
                cuts[dd_rva[0][0] - sva] = '.edata'
            # the IAT and the import tables are left out: link.exe builds them from the import libraries
            spans = ([(dd_rva[12][0], dd_rva[12][0] + dd_rva[12][1])] if 12 in dd_rva else []) + \
                ([imp_span] if imp_span else [])
            for lo_r, hi_r in spans:
                if not inside(lo_r):
                    continue
                nxt = min([c for c in cuts if c > lo_r - sva] or [init_len])
                cuts[lo_r - sva] = None                      # skipped
                if hi_r - sva < nxt and any(rawb[hi_r - sva:nxt]):  # zero padding up to the next piece is link's
                    cuts.setdefault(hi_r - sva, '.rdata')
        pts = sorted(cuts)
        for k in range(len(pts) - 1):
            lo, hi = pts[k], pts[k + 1]
            if hi <= lo:
                continue
            nm = cuts[lo]
            if nm is None:
                bad = [hex(site) for site in rel if lo <= site - base - s['va'] < hi]
                bad += [hex(t) for t in data_syms.get(j, ()) if lo <= t - base - s['va'] < hi]
                if bad:
                    raise SystemExit(f'pointers into the import tables at {bad[:5]}')
                continue
            # .edata keeps the original's alignment (link pads after the import tables to reach it)
            al = ch
            if nm == '.edata':
                ev = s['va'] + lo
                al = (ch & ~0x00F00000) | (0x00500000 if ev % 16 == 0 else 0x00300000 if ev % 4 == 0 else ALIGN1)
            sec = d.section(nm, al, rawb[lo:hi])
            d.symbol(sec, f'_SEC_{nm.strip(".").replace("$", "_")}_{lo:x}', 0)
            for t in sorted(data_syms.get(j, ())):
                off = t - base - s['va']
                if lo <= off < hi:
                    d.symbol(sec, sname(t), off - lo)
            if 10 in dd_rva and s['va'] + lo <= dd_rva[10][0] < s['va'] + hi:
                d.symbol(sec, '__load_config_used', dd_rva[10][0] - s['va'] - lo)
            for site, v in rel.items():
                off = site - base - s['va']
                if lo <= off < hi:
                    struct.pack_into('<I', d.secs[sec - 1]['data'], off - lo, 0)
                    _emit(d, sec, d.secs[sec - 1]['data'], off - lo, DIR32, v, 0, site, base, ext_name, stats)
            for site, v in rva_sites.items():
                off = site - base - s['va']
                if lo <= off < hi:
                    struct.pack_into('<I', d.secs[sec - 1]['data'], off - lo, 0)
                    d.reloc(sec, off - lo, ext_name[v], DIR32NB)
                    stats['dir32nb_relocs'] = stats.get('dir32nb_relocs', 0) + 1
        if vlen > init_len:                 # zero-initialised tail -> .bss (merged into the section by link)
            bsec = d.section('.bss', SCN_CNT_UDATA | SCN_READ | SCN_WRITE | ALIGN1, None, size=vlen - init_len)
            for t in sorted(data_syms.get(j, ())):
                off = t - base - s['va']
                if off >= init_len:
                    d.symbol(bsec, sname(t), off - init_len)
    d.write(os.path.join(outdir, 'data.obj'))
    libs = []
    for dll, fns in imports:
        if dll in use_lib:
            continue
        stem = os.path.splitext(dll)[0].lower()
        if any(h == 0 for h, _, _ in fns):
            raise SystemExit(f'{dll}: hint 0 cannot be written as a /DEF ordinal')
        open(os.path.join(outdir, f'imp_{stem}.def'), 'w').write(
            f'LIBRARY "{dll}"\nEXPORTS\n' + ''.join(f'  {fn} @{h} DATA\n' for h, fn, _ in fns))
        libs.append(f'imp_{stem}')
    # Import order. link.exe lays out the hint/name entries in the order it pulls import members from the
    # libraries: the order it first met the symbols, searching the libraries in passes (command-line order,
    # repeated while something new was pulled). The original's hint/name table shows those passes as runs of
    # DLL groups (a DLL earlier in library order starting a new run = a new pass: there the CRT and then
    # SDL2main, both from libraries, pulled imports in later passes). imports_order.obj (the first object) names
    # the first pass's imports in order; the pieces using pass-k imports form the one member of round<k>.lib,
    # whose symbol table starts with that pass's imports in order, placed on the command line right after the
    # last import library its pass-k imports come from (so it is pulled one pass earlier, after those libs).
    lib_for = {dll: use_lib.get(dll) or f'imp_{os.path.splitext(dll)[0].lower()}.lib' for dll, _ in imports}
    rank = {dll: i for i, dll in enumerate(lib_order)}

    def ordered(names):
        return [f'__imp_{sym_of[k]}' for k in names]
    io = Coff()
    io.undefined = ordered(rounds[0])
    io.write(os.path.join(outdir, 'imports_order.obj'))
    slot_libs = {dll: [] for dll in lib_order}
    tail = []
    round_libs = []
    owner = {}
    for i, p_ in enumerate(pieces):
        for t in [p_[0]] + sorted(code_syms.get(i, ())):
            owner[sname(t)] = i
    for k in range(2, len(rounds) + 1):
        members = [i for i in range(len(pieces)) if piece_pass[i] == k]
        if not members:
            continue
        c = Coff()
        mine = {n for i in members for n in piece_imports[i]}
        c.undefined = [x for x in ordered(rounds[k - 1]) if x[6:] in mine] + \
            [x for kk in range(k - 1, 0, -1) for x in ordered(rounds[kk - 1]) if x[6:] in mine]
        for i in members:
            write_piece(c, i)
        c.write(os.path.join(outdir, f'round{k}.obj'))
        round_libs.append(f'round{k}')
        last = max((dll for dll, fn in rounds[k - 1] if sym_of[(dll, fn)] in mine), key=lambda d: rank[d])
        slot_libs[last].append(f'round{k}.lib')
        # a member of a pass >= 3 must not be referenced by anything linked before its pass
        if k >= 3:
            ms = set(members)
            early = {owner[r[1]] for i in range(len(pieces)) if piece_pass[i] < k - 1
                     for sec_ in [None] for r in _piece_refs(pieces[i], rel, branch_relocs.get(i, ()), ext_name)
                     if r[1] in owner and owner[r[1]] in ms}
            if early:
                stats.setdefault('warnings', []).append(f'round{k}: referenced from earlier pieces {sorted(early)[:5]}')
    stats['import_passes'] = [len(r) for r in rounds]
    open(os.path.join(outdir, 'order.txt'), 'w').write('\n'.join(o[1:] for o in order) + '\n')
    # options from the PE header
    pe = struct.unpack_from('<I', img, 0x3c)[0]
    opt = pe + 24
    entry = struct.unpack_from('<I', img, opt + 16)[0] + base
    subsystem = struct.unpack_from('<H', img, opt + 68)[0]
    dllch = struct.unpack_from('<H', img, opt + 70)[0]
    osmaj, osmin = struct.unpack_from('<HH', img, opt + 40)
    ssmaj, ssmin = struct.unpack_from('<HH', img, opt + 48)
    stack_res, stack_com, heap_res, heap_com = struct.unpack_from('<IIII', img, opt + 72)
    falign = struct.unpack_from('<I', img, opt + 36)[0]
    salign = struct.unpack_from('<I', img, opt + 32)[0]
    opts = ['/NOLOGO', '/MACHINE:X86', f'/BASE:0x{base:x}', f'/ENTRY:A_{entry:x}', '/NODEFAULTLIB',
            f'/SUBSYSTEM:{"WINDOWS" if subsystem == 2 else "CONSOLE"},{ssmaj}.{ssmin:02d}',
            f'/STACK:0x{stack_res:x},0x{stack_com:x}', f'/HEAP:0x{heap_res:x},0x{heap_com:x}',
            *([f'/ALIGN:{salign}'] if salign != 0x1000 else []), f'/FILEALIGN:{falign}', '/ORDER:@order.txt', '/OPT:REF', '/OPT:NOICF',
            '/INCREMENTAL:NO', '/MANIFEST:NO', '/SAFESEH:NO',
            '/DYNAMICBASE' if dllch & 0x40 else '/DYNAMICBASE:NO', '/NXCOMPAT' if dllch & 0x100 else '/NXCOMPAT:NO',
            '/OUT:relinked.exe', '/MAP:relinked.map', 'imports_order.obj'] + [f'code_{i:03d}.obj' for i in range(nobj)] + ['data.obj'] + \
        (['new_data.obj'] if has_new_data else []) + \
        (['resources.res'] if mt_manifest else []) + \
        [x for d_ in lib_order for x in [msvc_path(lib_for[d_]) if d_ in use_lib else lib_for[d_]] + slot_libs[d_]]
    open(os.path.join(outdir, 'libs.txt'), 'w').write(''.join(f'def {x}\n' for x in libs) +
                                                       ''.join(f'obj {x}\n' for x in round_libs))
    # /OPT:REF drops the jump thunks of the SDK's code imports (the original has none); every piece is kept
    # by an /INCLUDE of its symbol
    opts += [f'/INCLUDE:{sname(pieces[i][0])}' for i in plain]
    open(os.path.join(outdir, 'link.rsp'), 'w').write('\n'.join(opts) + '\n')
    stats['objects'] = nobj + 1
    stats['import_libs'] = dict(existing={d_: os.path.basename(v) for d_, v in use_lib.items()}, generated=libs)
    print(json.dumps(stats, indent=1))
    return 0



def rva_fields(img, base, dirs, secs):
    """{field VA: target VA} for RVAs stored without base relocations: SafeSEH handler table entries and the
    export table (directory name/table pointers, function RVAs that are not forwarders, name pointers)."""
    def off(rva):
        x = next(s_ for s_ in secs if s_['va'] <= rva < s_['va'] + max(s_['vsize'], s_['raw_size']))
        return x['raw_ptr'] + rva - x['va']
    out = {}
    if len(dirs) > 10 and dirs[10][1] and struct.unpack_from('<I', img, off(dirs[10][0]))[0] >= 72:
        lc = off(dirs[10][0])                # the struct's own Size (the directory entry may say less)
        tab, cnt = struct.unpack_from('<II', img, lc + 64)
        if tab and cnt:
            for i in range(cnt):
                out[tab + 4 * i] = struct.unpack_from('<I', img, off(tab - base) + 4 * i)[0] + base
    if dirs and dirs[0][1]:
        e0, esz = dirs[0]
        e = off(e0)
        name, _, nfun, nnames, afun, anames, aords = struct.unpack_from('<IIIIIII', img, e + 12)
        for k, v in ((12, name), (28, afun), (32, anames), (36, aords)):
            if v:
                out[base + e0 + k] = base + v
        for i in range(nfun):
            v = struct.unpack_from('<I', img, off(afun) + 4 * i)[0]
            if v and not (e0 <= v < e0 + esz):         # forwarders point into the export section
                out[base + afun + 4 * i] = base + v
        for i in range(nnames):
            out[base + anames + 4 * i] = base + struct.unpack_from('<I', img, off(anames) + 4 * i)[0]
    return out


def reloc_vsize(img):
    base, dirs, secs = reassemble.pe_parse(img)
    if len(dirs) < 6 or not dirs[5][1]:
        return 0
    return next((x['vsize'] for x in secs if x['va'] == dirs[5][0]), 0)


def read_resources(img, dirs, secs):
    """[(type, name, lang, data)] from the resource directory; type/name are ints or strings."""
    if len(dirs) < 3 or not dirs[2][1]:
        return []
    sec = next(x for x in secs if x['va'] <= dirs[2][0] < x['va'] + max(x['vsize'], x['raw_size']))
    R = img[sec['raw_ptr'] + dirs[2][0] - sec['va']:sec['raw_ptr'] + sec['raw_size']]
    out = []

    def ident(v):
        if v & 0x80000000:
            o = v & 0x7FFFFFFF
            n = struct.unpack_from('<H', R, o)[0]
            return R[o + 2:o + 2 + 2 * n].decode('utf-16le')
        return v

    def walk(o, path):
        n1, n2 = struct.unpack_from('<HH', R, o + 12)
        for i in range(n1 + n2):
            nm, off = struct.unpack_from('<II', R, o + 16 + 8 * i)
            if off & 0x80000000:
                walk(off & 0x7FFFFFFF, path + [ident(nm)])
            else:
                drva, sz, _, _ = struct.unpack_from('<IIII', R, off)
                o2 = sec['raw_ptr'] + drva - sec['va']
                out.append((path[0], path[1], ident(nm), img[o2:o2 + sz]))
    walk(0, [])
    return out


def write_res(path, res):
    """A Win32 .res file (what rc.exe writes) for link.exe / cvtres."""
    def idb(v):
        return struct.pack('<HH', 0xFFFF, v) if isinstance(v, int) else v.upper().encode('utf-16le') + b'\0\0'
    out = bytearray(struct.pack('<II', 0, 32) + struct.pack('<HHHH', 0xFFFF, 0, 0xFFFF, 0) + bytes(16))
    for typ, name, lang, data in res:
        h = idb(typ) + idb(name)
        h += b'\0' * (-len(h) % 4)
        h += struct.pack('<IHHII', 0, 0x1030 if typ in (3, 14) else 0x1030, lang, 0, 0)
        out += struct.pack('<II', len(data), 8 + len(h)) + h + data + b'\0' * (-len(data) % 4)
    open(path, 'wb').write(out)


def _piece_refs(piece, rel, branches, ext_name):
    s, e, kind, payload = piece
    if kind == 'fn':
        return [(o, ext_name.get(t)) for o, _, t in payload[1]]
    return [(x - s, ext_name.get(rel[x])) for x in range(s, e) if x in rel] + [(o, ext_name.get(t)) for o, t in branches]


def msvc_path(p):
    """A host path inside a Wine prefix's drive_c as a Windows path for link.exe; other paths unchanged."""
    i = p.find('/drive_c/')
    return '"C:\\' + p[i + 9:].replace('/', '\\') + '"' if i >= 0 else p


def _emit(c, sec, data, off, typ, tva, add, piece_start, base, ext_name, stats):
    nm = ext_name.get(tva)
    if nm is None:
        nm = '___ImageBase'
        add = tva - base + add
        struct.pack_into('<i', data, off, add)
    c.reloc(sec, off, nm, typ)
    if typ == DIR32:
        stats['dir32_relocs'] += 1


def lib_imports(lib_path):
    """{(DLL upper, import name): (hint, symbol)} for the short import members of an import library."""
    b = open(lib_path, 'rb').read()
    o, out = 8, {}
    while o + 60 <= len(b):
        size = int(b[o + 48:o + 58].decode().strip())
        m = o + 60
        if struct.unpack_from('<HH', b, m) == (0, 0xFFFF):
            hint, t = struct.unpack_from('<HH', b, m + 16)
            n = struct.unpack_from('<I', b, m + 12)[0]
            sym, dll = (x.decode('latin-1') for x in b[m + 20:m + 20 + n].split(b'\0')[:2])
            nt = t >> 2
            name = (sym.lstrip('_?@').split('@')[0] if nt == 3 else sym[1:] if nt == 2 else sym)
            if nt:
                out[(dll.upper(), name)] = (hint, sym)
        o = m + size + (size & 1)
    return out


def name_imports(lib_path):
    """lib.exe /DEF turns `name @n` into an import by ordinal n. The original imports by name with hint n, so
    every short import member (IMPORT_OBJECT_HEADER, Sig1 0 / Sig2 0xFFFF) gets name type NAME_NOPREFIX
    (the symbol minus its leading underscore); the hint stays in the Ordinal/Hint field."""
    b = bytearray(open(lib_path, 'rb').read())
    assert b[:8] == b'!<arch>\n'
    o, n = 8, 0
    while o + 60 <= len(b):
        size = int(b[o + 48:o + 58].decode().strip())
        m = o + 60
        if struct.unpack_from('<HH', b, m) == (0, 0xFFFF):
            t = struct.unpack_from('<H', b, m + 18)[0]
            struct.pack_into('<H', b, m + 18, (t & 3) | (2 << 2))
            n += 1
        o = m + size + (size & 1)
    open(lib_path, 'wb').write(b)
    return n


def link(outdir, original):
    sk = os.path.join(HERE, 'msvc.sh')
    libs_txt = os.path.join(outdir, 'libs.txt')
    for line in (open(libs_txt).read().splitlines() if os.path.exists(libs_txt) else []):
        kind, x = line.split()
        src = f'/DEF:{x}.def' if kind == 'def' else f'{x}.obj'
        p = subprocess.run(['sh', sk, 'lib', '/NOLOGO', '/MACHINE:X86', src, f'/OUT:{x}.lib'],
                           cwd=outdir, capture_output=True, text=True)
        if p.returncode:
            print(p.stdout + p.stderr)
            return 2
        if kind == 'def':
            name_imports(os.path.join(outdir, f'{x}.lib'))
    out = os.path.join(outdir, 'relinked.exe')

    def run_link():
        if os.path.exists(out):
            os.remove(out)
        p = subprocess.run(['sh', sk, 'link', '@link.rsp'], cwd=outdir, capture_output=True, text=True)
        print((p.stdout + p.stderr)[-3000:])
        return os.path.exists(out)
    if not run_link():
        return 2
    # .reloc: link.exe reserves 2 bytes per absolute (DIR32) relocation of its input sections, also those in
    # COMDATs that /OPT:REF then discards (the original's unreferenced CRT and /Gy functions), so the
    # original's .reloc is larger than its relocation table. One discarded COMDAT with that many relocations
    # (dropped.obj, measured against the original once) gives link.exe the same input count.
    rsp = os.path.join(outdir, 'link.rsp')
    if 'dropped.obj' not in open(rsp).read() and not os.path.exists(os.path.join(outdir, 'FREE')):
        ro = reloc_vsize(open(original, 'rb').read())
        rn = reloc_vsize(open(out, 'rb').read())
        if ro and rn and ro > rn and (ro - rn) % 2 == 0:
            c = Coff()
            k = (ro - rn) // 2
            sec = c.section('.text$mn', SCN_CNT_CODE | SCN_EXEC | SCN_READ | SCN_LNK_COMDAT | ALIGN1, bytes(4 * k), comdat=True)
            c.symbol(sec, '_relink_discarded_relocations', 0)
            for i in range(k):
                c.reloc(sec, 4 * i, '___ImageBase', DIR32)
            c.write(os.path.join(outdir, 'dropped.obj'))
            txt = open(rsp).read().replace('data.obj\n', 'data.obj\ndropped.obj\n', 1)
            open(rsp, 'w').write(txt)
            print(f'.reloc: {k} discarded relocations added (dropped.obj); linking again')
            if not run_link():
                return 2
    if os.path.exists(os.path.join(outdir, 'manifest.xml')):
        p = subprocess.run(['sh', sk, 'mt', '-nologo', '-manifest', 'manifest.xml', '-outputresource:relinked.exe;#1'],
                           cwd=outdir, capture_output=True, text=True)
        print((p.stdout + p.stderr)[-2000:])
        if p.returncode:
            return 2
    a, b = open(original, 'rb').read(), open(out, 'rb').read()
    print('SHA-256', 'IDENTICAL' if a == b else 'DIFFERENT', f'(original {len(a)} bytes, relinked {len(b)})')
    ba, da, sa = reassemble.pe_parse(a)
    bb, db, sb = reassemble.pe_parse(b)
    rows = []
    for s in sa:
        t = next((x for x in sb if x['name'] == s['name']), None)
        if t is None:
            rows.append(dict(section=s['name'], status='missing'))
            continue
        x = a[s['raw_ptr']:s['raw_ptr'] + s['raw_size']]
        y = b[t['raw_ptr']:t['raw_ptr'] + t['raw_size']]
        first = next((i for i in range(min(len(x), len(y))) if x[i] != y[i]), None)
        rows.append(dict(section=s['name'], va=hex(s['va']), va_relinked=hex(t['va']), vsize=hex(s['vsize']),
                         vsize_relinked=hex(t['vsize']), raw=len(x), raw_relinked=len(y),
                         identical=x == y, first_diff=None if first is None else hex(first),
                         differing_bytes=sum(1 for i in range(min(len(x), len(y))) if x[i] != y[i])))
    extra = [x['name'] for x in sb if x['name'] not in {s['name'] for s in sa}]
    dd = [dict(index=i, original=[hex(v) for v in da[i]], relinked=[hex(v) for v in db[i]])
          for i in range(min(len(da), len(db))) if da[i] != db[i]]
    hdr_a, hdr_b = a[:sa[0]['raw_ptr']], b[:sb[0]['raw_ptr']]
    res = dict(sections=rows, extra_sections=extra, data_directories_differing=dd,
               header_bytes_differing=sum(1 for i in range(min(len(hdr_a), len(hdr_b))) if hdr_a[i] != hdr_b[i]))
    json.dump(res, open(os.path.join(outdir, 'compare.json'), 'w'), indent=1)
    print(json.dumps(res, indent=1)[:6000])
    return 0 if a == b else 1


def pe_checksum(img, csum_off):
    s = 0
    n = len(img)
    data = img + (b'\0' if n % 2 else b'')
    for i in range(0, len(data), 2):
        if i == csum_off or i == csum_off + 2:
            continue
        s += data[i] | data[i + 1] << 8
        s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (s + n) & 0xFFFFFFFF


def finish(outdir, original):
    """Post-link facts: what the toolchain cannot reproduce from the inputs, taken from the original, applied
    to relinked.exe (-> final.exe) and counted byte by byte. Writes facts.json.
      rich       DOS stub + Rich header (link writes it from the @comp.id records of the original objects and
                 libraries, which the relink inputs do not have); the PE header follows it (e_lfanew)
      timestamp  TimeDateStamp of the original link
      iat_order  order of the IAT slots inside each DLL's block (a link.exe internal ordering; hint/name
                 entries, descriptors and pass structure come from link.exe itself): slots, lookup tables and
                 every pointer to a slot are permuted
      rsrc       bytes of .rsrc and its VirtualSize where Wine's UpdateResource (mt.exe) differs from Windows'
                 (CodePage 0 instead of the ANSI code page, VirtualSize rounded)
      checksum   recomputed (PE checksum), then compared"""
    a = open(original, 'rb').read()
    b = bytearray(open(os.path.join(outdir, 'relinked.exe'), 'rb').read())
    facts, patched = {}, {}
    only = set(os.environ.get('RELINK_FACTS', 'rich,timestamp,iat_order,rsrc,checksum').split(','))

    def count(k, before, after):
        patched[k] = patched.get(k, 0) + sum(1 for x, y in zip(before, after) if x != y) + abs(len(before) - len(after))
    # 1. Rich header / stub; the PE headers move to the original's e_lfanew
    la, lb = struct.unpack_from('<I', a, 0x3c)[0], struct.unpack_from('<I', b, 0x3c)[0]
    _, _, sb = reassemble.pe_parse(bytes(b))
    hdr_end = sb[0]['raw_ptr']
    nsec = struct.unpack_from('<H', b, lb + 6)[0]
    pe_len = 24 + struct.unpack_from('<H', b, lb + 20)[0] + 40 * nsec
    newh = bytearray(a[:la]) + b[lb:lb + pe_len]
    newh += b'\0' * (hdr_end - len(newh))
    if 'rich' not in only:
        newh = bytes(b[:hdr_end])
        la = lb
    facts['rich'] = dict(e_lfanew=la, stub_and_rich=a[0x40:la].hex())
    count('rich', b[:hdr_end], newh)
    b[:hdr_end] = newh
    pe = la
    # 2. timestamp
    ts = struct.unpack_from('<I', a if 'timestamp' in only else b, pe + 8)[0]
    facts['timestamp'] = ts
    before = bytes(b[pe + 8:pe + 12])
    struct.pack_into('<I', b, pe + 8, ts)
    count('timestamp', before, b[pe + 8:pe + 12])
    # 3. IAT order
    base, da, sa = reassemble.pe_parse(a)
    _, db, sb = reassemble.pe_parse(bytes(b))
    ia, _ = read_imports(a, da, sa)
    ib, _ = read_imports(bytes(b), db, sb)

    def off(secs, rva):
        x = next(s_ for s_ in secs if s_['va'] <= rva < s_['va'] + max(s_['vsize'], s_['raw_size']))
        return x['raw_ptr'] + rva - x['va']
    slot_a = {(d, fn): r for d, fs in ia for _, fn, r in fs}
    slot_b = {(d, fn): r for d, fs in ib for _, fn, r in fs}
    if set(slot_a) != set(slot_b):
        raise SystemExit('import sets differ')
    facts['iat_order'] = {d: [fn for _, fn, r in sorted(fs, key=lambda f: f[2])] for d, fs in ia}
    move = {base + slot_b[k]: base + slot_a[k] for k in slot_a}
    if any(k != v for k, v in move.items()) and 'iat_order' in only:
        before = bytes(b)
        hn = {}
        for i, (d, fs) in enumerate(ib):
            oft = struct.unpack_from('<I', b, off(sb, db[1][0] + 20 * i))[0]
            for k, (_, fn, r) in enumerate(fs):
                hn[(d, fn)] = struct.unpack_from('<I', b, off(sb, oft + 4 * k))[0]
        for i, (d, fs) in enumerate(ib):
            oft, _, _, _, ft = struct.unpack_from('<IIIII', b, off(sb, db[1][0] + 20 * i))
            order = sorted(fs, key=lambda f: slot_a[(d, f[1])])
            for k, (_, fn, _) in enumerate(order):
                struct.pack_into('<I', b, off(sb, oft + 4 * k), hn[(d, fn)])
                struct.pack_into('<I', b, off(sb, ft + 4 * k), hn[(d, fn)])
        rel, _ = reassemble.relocs_of(bytes(b), base, db, sb)
        for site, v in rel.items():
            if v in move:
                struct.pack_into('<I', b, off(sb, site - base), move[v])
        count('iat_order', before, b)
    # 4. .rsrc bytes and VirtualSize (Wine vs Windows UpdateResource)
    if len(da) > 2 and da[2][1]:
        xa = next(s_ for s_ in sa if s_['va'] == da[2][0])
        xb = next(s_ for s_ in sb if s_['va'] == db[2][0])
        ra, rb = a[xa['raw_ptr']:xa['raw_ptr'] + xa['raw_size']], b[xb['raw_ptr']:xb['raw_ptr'] + xb['raw_size']]
        if len(ra) == len(rb) and 'rsrc' in only:
            diffs = [(i, ra[i]) for i in range(len(ra)) if ra[i] != rb[i]]
            facts['rsrc'] = dict(bytes=[[i, v] for i, v in diffs], vsize=xa['vsize'])
            before = bytes(b)
            for i, v in diffs:
                b[xb['raw_ptr'] + i] = v
            k = sb.index(xb)
            sh = pe + 24 + struct.unpack_from('<H', b, pe + 20)[0] + 40 * k
            struct.pack_into('<I', b, sh + 8, xa['vsize'])
            count('rsrc', before, b)
    # 5. checksum
    csum = pe + 24 + 64
    before = bytes(b[csum:csum + 4])
    struct.pack_into('<I', b, csum, pe_checksum(bytes(b), csum))
    count('checksum', before, b[csum:csum + 4])
    json.dump(facts, open(os.path.join(outdir, 'facts.json'), 'w'), indent=1)
    out = os.path.join(outdir, 'final.exe')
    open(out, 'wb').write(b)
    same = bytes(b) == a
    print(json.dumps(dict(patched_bytes=patched, total_patched=sum(patched.values()), file_bytes=len(b),
                          sha256=hashlib.sha256(b).hexdigest(), identical=same), indent=1))
    if not same:
        first = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), None)
        print('first difference at', hex(first) if first is not None else 'length')
    return 0 if same else 1


def check(outdir, original, map_path, listing, index_path):
    """Differential check of a moved (--free) build: every direct branch and every base-relocated pointer of the
    original, outside the edited functions, must reach its target's new address. New addresses come from
    the link map (/MAP: every _A_<va> symbol); data sites move with their section."""
    m = json.load(open(map_path))
    edited = sorted(int(f['va'], 16) for f in m['functions'] if not f.get('identical', True))
    fst = sorted(int(f['address'], 16) for f in json.load(open(index_path))['functions'])
    ext = [(e, fst[bisect.bisect_right(fst, e)] if bisect.bisect_right(fst, e) < len(fst) else e + 1) for e in edited]

    def in_edited(va):
        return any(x <= va < y for x, y in ext)
    O = open(original, 'rb').read()
    E = open(os.path.join(outdir, 'relinked.exe'), 'rb').read()
    sym = {}
    for ln in open(os.path.join(outdir, 'relinked.map'), errors='replace'):
        mm = re.match(r'\s*\S+\s+_A_([0-9a-f]+)\s+([0-9a-f]{8})', ln)
        if mm:
            sym[int(mm.group(1), 16)] = int(mm.group(2), 16)
    xs = sorted(sym)

    def new(va):
        i = bisect.bisect_right(xs, va) - 1
        return sym[xs[i]] + va - xs[i]
    bo, do_, so = reassemble.pe_parse(O)
    be, de, se = reassemble.pe_parse(E)

    def off(secs, va, base):
        x = next(s_ for s_ in secs if s_['va'] <= va - base < s_['va'] + max(s_['vsize'], s_['raw_size']))
        return x['raw_ptr'] + va - base - x['va']
    T = next(s_ for s_ in so if s_['exec'])
    t0, t1 = bo + T['va'], bo + T['va'] + T['vsize']
    n = {'branches': 0, 'pointers': 0}
    bad = []
    with open(listing) as fh:
        next(fh)
        for line in fh:
            a, ln, fn, flow, tg, text = line.rstrip('\n').split('\t', 5)
            a, ln = int(a, 16), int(ln)
            if not tg or flow not in ('call', 'jump', 'cjump', 'ccall', 'cjmp') or in_edited(a):
                continue
            b = O[off(so, a, bo):off(so, a, bo) + ln]
            if b[:1] in (b'\xe8', b'\xe9') and ln == 5:
                k = 1
            elif b[:1] == b'\x0f' and ln == 6 and 0x80 <= b[1] <= 0x8f:
                k = 2
            elif ln == 2 and (b[0] == 0xeb or 0x70 <= b[0] <= 0x7f or b[0] in (0xe0, 0xe1, 0xe2, 0xe3)):
                k = 1
            else:
                continue
            t = int(tg.split(',')[0], 16)
            if not t0 <= t < t1:
                continue
            na, nt = new(a), new(t)
            eb = E[off(se, na, be):off(se, na, be) + ln]
            rel = struct.unpack_from('<i' if ln - k == 4 else '<b', eb, k)[0]
            n['branches'] += 1
            if eb[:k] != b[:k] or na + ln + rel != nt:
                bad.append(f'branch {a:#x} {text}')
    rel, _ = reassemble.relocs_of(O, bo, do_, so)
    for site, v in rel.items():
        if in_edited(site) or not t0 <= v < t1:
            continue
        if t0 <= site < t1:
            ns = new(site)
        else:
            sa = next((x for x in so if x['va'] <= site - bo < x['va'] + x['vsize']), None)
            sb = next((x for x in se if sa and x['name'] == sa['name']), None)
            if sb is None:
                continue
            ns = site - sa['va'] + sb['va']
        n['pointers'] += 1
        if struct.unpack_from('<I', E, off(se, ns, be))[0] != new(v):
            bad.append(f'pointer at {site:#x} -> {v:#x}')
    print(json.dumps(dict(edited_functions=len(edited), checked=n, mismatches=len(bad), first=bad[:10]), indent=1))
    return 0 if not bad else 1


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == 'prepare' and len(sys.argv) >= 6:
        cache = sys.argv[sys.argv.index('--cache') + 1] if '--cache' in sys.argv else None
        libdirs = [sys.argv[i + 1] for i, x in enumerate(sys.argv) if x == '--libdir']
        return prepare(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], cache, libdirs, '--free' in sys.argv)
    if len(sys.argv) == 7 and sys.argv[1] == 'check':
        return check(*sys.argv[2:7])
    if len(sys.argv) == 4 and sys.argv[1] == 'finish':
        return finish(sys.argv[2], sys.argv[3])
    if len(sys.argv) == 4 and sys.argv[1] == 'link':
        return link(sys.argv[2], sys.argv[3])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
