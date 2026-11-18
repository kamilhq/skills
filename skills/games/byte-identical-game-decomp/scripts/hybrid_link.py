#!/usr/bin/env python3
"""Phase 6 hybrid build: rebuild the whole binary with every matched function taken from the compiler's .obj.

The phase-5b text (reassemble.py) gives the full image; for each function that objcmp.py reports identical,
this linker takes the compiled machine code from its COFF object, places it at the function's address,
resolves its relocations by symbol, and regenerates .reloc from the objects' DIR32 relocations (plus the
phase-5b sites of everything still in assembly). Python stdlib only; no link.exe.

  hybrid_link.py map  --pe <original> --src <dir|file>... --obj <dir|file>... [--module M]
                      [--functions index.json] --out symbols.json [--all]
      Linker map, derived once from the original (like the label tables of phase 5b): the identical
      functions (va, obj, symbol) and the address of every symbol their relocations name. Symbols are
      resolved as objcmp.py does (annotations, imports, Ghidra names, same-section); the rest are read from
      the original's relocated fields. A symbol that two sites place at different addresses is an error.
      --all also takes FUNCTIONs that no longer match (edited source) for relink.py --free; see
      resolve_edited().
  hybrid_link.py link <reassembled_dir> <symbols.json> <out_binary> [--cache <file>]
      Reads only the phase-5b dir, the objects and symbols.json. Prints how many bytes of .text came from
      compiled objects. Exit 0 ok.
  hybrid_link.py verify <original> <reassembled_dir> <symbols.json> [--cache <file>]
      link to a temp file and compare SHA-256 with the original.

Limits: functions keep their original addresses (this is a byte-identity proof for compiled code, not a
relinker); data sections, imports, resources and headers come from the phase-5b layout, not from compiled
C++; link.exe with real data from source is a further step.
"""
import argparse, hashlib, json, os, struct, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import objcmp       # noqa: E402
import reassemble   # noqa: E402

DIR32, DIR32NB, REL32 = objcmp.DIR32, objcmp.DIR32NB, objcmp.REL32


def sym_key(obj_path, sym):
    """Externals by name; statics qualified by object and section (several objects have the same statics)."""
    if sym.storage not in (objcmp.CLASS_EXTERNAL, objcmp.CLASS_WEAK) and sym.secnum > 0:   # statics, $LN labels
        return f'{os.path.basename(obj_path)}#{sym.name}#sec{sym.secnum}'
    return sym.name


def cmd_map(a):
    pe = objcmp.PEImage(a.pe)
    objs = [objcmp.read_coff(f) for f in objcmp.collect_objs(a.obj)]
    amap = objcmp.AddrMap(pe)
    flist = objcmp.load_function_list(a.functions) if a.functions else {}
    annots = objcmp.scan_annotations(a.src, a.module)
    all_names = [(o, s) for o in objs for s in o.symbols.values() if not s.is_section_sym and s.storage in
                 (objcmp.CLASS_EXTERNAL, objcmp.CLASS_STATIC, objcmp.CLASS_WEAK)]
    for an in annots:
        if an['kind'] == 'STRING':
            continue
        objcmp.map_annotation(an, objs, all_names)
        if an.get('status') == 'mapped':
            amap.add(an['symbol'], an['va'], f'{an["file"]}:{an["line"]}')
    known_starts = set(flist) | {an['va'] for an in annots}
    by_path = {o.path: o for o in objs}
    functions, symbols, conflicts, inobj, skipped = [], {}, [], [], 0
    edited = []
    for an in annots:
        if an['kind'] != 'FUNCTION' or an.get('status') != 'mapped':
            continue
        obj = by_path.get(an.get('objpath'))
        syms = [s for s in obj.find(an['symbol'])] if obj else []
        if not syms:
            skipped += 1
            continue
        sym = syms[0]
        r = objcmp.compare_function(obj, sym, pe, an['va'], None, amap, known_starts)
        if not r.get('identical'):
            if getattr(a, 'all', False):
                edited.append((an, obj, sym))
            else:
                skipped += 1
            continue
        code, rels = obj.function_bytes(sym)
        orig = pe.read(an['va'], len(code))
        for rel in rels:
            t = rel.symbol
            if rel.type == 0 or t is None:
                continue
            if rel.type not in (DIR32, DIR32NB, REL32):
                raise SystemExit(f'{obj.path} {sym.name}: relocation type {rel.type_name} not supported')
            p = an['va'] + rel.offset
            add = struct.unpack_from('<i', code, rel.offset)[0]
            field = struct.unpack_from('<I', orig, rel.offset)[0]
            if rel.type == DIR32:
                tva = (field - add) & 0xFFFFFFFF
            elif rel.type == DIR32NB:
                tva = (field + pe.image_base - add) & 0xFFFFFFFF
            else:
                tva = (field + p + 4 - add) & 0xFFFFFFFF
            k = sym_key(obj.path, t) if not t.is_section_sym else f'{os.path.basename(obj.path)}#{t.name}#sec{t.secnum}'
            if k in symbols and symbols[k] != tva:
                conflicts.append(dict(symbol=k, addresses=[hex(symbols[k]), hex(tva)], at=hex(p),
                                      obj=os.path.basename(obj.path)))
            symbols.setdefault(k, tva)
            # per-object view: units may declare a global with different layouts (or name two different
            # copies, e.g. two operator delete / two __real constants); each object resolves through its own
            qk = f'{os.path.basename(obj.path)}@{k}'
            if qk in symbols and symbols[qk] != tva:
                inobj.append(dict(symbol=qk, addresses=[hex(symbols[qk]), hex(tva)], at=hex(p)))
            symbols.setdefault(qk, tva)
        functions.append(dict(va=hex(an['va']), obj=os.path.relpath(obj.path), symbol=sym.name,
                              index=sym.index, size=len(code)))
    new, unresolved = {}, []
    if edited:
        resolve_edited(edited, symbols, amap, functions, new, unresolved, a.functions, getattr(a, 'instructions', None))
    out = dict(image_base=pe.image_base, functions=functions, symbols=symbols, conflicts=conflicts,
               conflicts_within_object=inobj, new_sections=new, unresolved=unresolved)
    json.dump(out, open(a.out, 'w'), indent=1)
    if unresolved:
        for u in unresolved[:30]:
            print('UNRESOLVED', u, file=sys.stderr)
    print(json.dumps(dict(functions=len(functions), edited=sum(1 for f in functions if not f.get('identical', True)),
                          new_sections=len(new), unresolved=len(unresolved),
                          symbols=len(symbols), cross_object_conflicts=len(conflicts),
                          conflict_symbols=len({c['symbol'] for c in conflicts}), within_object_conflicts=len(inobj),
                          not_identical_or_unmapped=skipped), indent=1))
    by_sym = {}
    for c in conflicts:
        by_sym[c['symbol']] = by_sym.get(c['symbol'], 0) + 1
    for k, n in sorted(by_sym.items(), key=lambda x: -x[1])[:30]:
        print(f'CONFLICT {k}: {n} site(s)', file=sys.stderr)
    return 1 if inobj or unresolved else 0


def demangle_simple(name):
    """MSVC `?name@Scope@...@@...` -> 'Scope::name' (plain names only; operators/ctors -> None); C `_name` -> 'name'."""
    if name.startswith('?'):
        if name.startswith('??'):
            return None
        head = name[1:].split('@@', 1)[0]
        parts = head.split('@')
        return '::'.join(reversed(parts[1:])) + ('::' if len(parts) > 1 else '') + parts[0]
    if name.startswith('_'):
        return name[1:].split('@')[0]
    return name


def resolve_edited(edited, symbols, amap, functions, new, unresolved, index_path=None, listing=None):
    """Build-from-source mode (--all): functions whose compiled code no longer matches the original (edited
    source) are linked too. Their relocation targets cannot be read from the original's bytes, so they are
    resolved by name: the map of the identical functions, then the address map (annotations of every unit,
    imports, Ghidra names). Targets inside the function's own section stay relative to the function. A
    target that exists nowhere in the original (a new string literal, constant, static, or a helper the
    compiler emitted) is taken from the unit's object: its section is added to the link as a new piece
    (`new_sections`, keyed obj#sec<N>), and that section's own relocations are resolved the same way."""
    todo = []
    # direct calls to imported functions (`call _SDL_Foo`) go through link.exe's jump thunks: jmp [IAT slot]
    pe = amap.pe
    slots = set(pe.imports.values())
    thunk = {}
    for name, va, vsize, rawsize, rawptr, ch in pe.sections:
        if ch & 0x20000000:
            d = pe.data[rawptr:rawptr + min(vsize, rawsize)]
            i = d.find(b'\xff\x25')
            while i >= 0:
                if i + 6 <= len(d):
                    slot = struct.unpack_from('<I', d, i + 2)[0]
                    if slot in slots:
                        thunk.setdefault(slot, pe.image_base + va + i)
                i = d.find(b'\xff\x25', i + 1)

    # read-only constants by content: string literals (??_C@) and floating-point constants (__real@, __xmm@)
    # an edited function still uses resolve to the original's copy when the exact bytes exist in read-only
    # data, outside the IAT/import tables and outside any relocated pointer
    ro = []
    iat = pe.dirs[12] if len(pe.dirs) > 12 else (0, 0)
    imp = pe.dirs[1] if len(pe.dirs) > 1 else (0, 0)
    for name, va, vsize, rawsize, rawptr, ch in pe.sections:
        if not (ch & 0x20000000) and not (ch & 0x80000000) and (ch & 0x40):
            ro.append((pe.image_base + va, pe.data[rawptr:rawptr + min(vsize, rawsize)]))

    def by_content(obj, t):
        if not (t.name.startswith('??_C@') or t.name.startswith('__real@') or t.name.startswith('__xmm@')):
            return None
        sec = t.section if t.section is not None else obj.sections[t.secnum - 1]
        want = bytes(sec.data[t.value:sec.size])
        if not want or sec.relocs:
            return None
        align = 8 if t.name.startswith('__real@') else 16 if t.name.startswith('__xmm@') else 1
        for base_va, d in ro:
            i = d.find(want)
            while i >= 0:
                v = base_va + i
                rva = v - pe.image_base
                clash = any(x in pe.fixups_set for x in range(v - 3, v + len(want)))
                clash = clash or iat[0] <= rva < iat[0] + iat[1] or imp[0] <= rva < imp[0] + imp[1]
                if not clash and v % align == 0:
                    return v
                i = d.find(want, i + 1)
        return None

    # names from the named function index (phase 5): unique qualified names only
    by_name = {}
    fstarts = []
    if index_path:
        for f in json.load(open(index_path)).get('functions', []):
            fstarts.append(int(f['address'], 16))
            n = f.get('name', '').split(':', 1)[1] if f.get('name', '').startswith('FID_conflict:') else f.get('name', '')
            by_name.setdefault(n, set()).add(int(f['address'], 16))
    fstarts.sort()

    def index_name(name):
        q = demangle_simple(name)
        for cand in (q, q.lstrip('_') if q else None, name):
            if cand and len(by_name.get(cand, ())) == 1:
                return next(iter(by_name[cand]))
        return None
    # the original function's direct calls in order (Ghidra listing), to pair calls nothing else names
    calls_of = {}
    if listing and os.path.exists(listing):
        with open(listing) as fh:
            next(fh)
            for line in fh:
                a_, ln, fn, flow, tg, text = line.rstrip('\n').split('\t', 5)
                if flow in ('call', 'ccall') and tg and text.startswith('CALL 0x'):
                    calls_of.setdefault(int(fn, 16), []).append(int(tg.split(',')[0], 16))

    def import_thunk(name):
        if name.startswith('__imp_') or not name.startswith('_'):
            return None
        va, src = amap.resolve('__imp_' + name)
        return thunk.get(va) if src == 'import' else None

    def resolve(obj, t, own_secnum):
        if t.secnum == own_secnum and own_secnum > 0:
            return 'self'
        k = sym_key(obj.path, t) if not t.is_section_sym else f'{os.path.basename(obj.path)}#{t.name}#sec{t.secnum}'
        qk = f'{os.path.basename(obj.path)}@{k}'
        if qk in symbols or k in symbols:
            return 'map'
        if not t.is_section_sym and t.secnum <= 0:
            va, _ = amap.resolve(t.name)
            if va is not None:
                symbols[k] = va
                return 'map'
        if not t.is_section_sym and t.storage in (objcmp.CLASS_EXTERNAL, objcmp.CLASS_WEAK):
            va, _ = amap.resolve(t.name)
            if va is not None:
                symbols[k] = va
                return 'map'
        if not t.is_section_sym and t.secnum <= 0:
            va = import_thunk(t.name)
            if va is not None:
                symbols[k] = va
                return 'map'
        if not t.is_section_sym and t.secnum <= 0:
            va = index_name(t.name)
            if va is not None:
                symbols[k] = va
                return 'map'
        if t.secnum > 0 and not t.is_section_sym:
            va = by_content(obj, t)
            if va is not None:
                symbols[qk] = va
                return 'map'
        if t.secnum > 0:
            nk = f'{os.path.basename(obj.path)}#sec{t.secnum}'
            if nk not in new:
                sec = t.section if t.section is not None else obj.sections[t.secnum - 1]
                new[nk] = dict(obj=os.path.relpath(obj.path), section=t.secnum, name=sec.name,
                               code=bool(sec.is_code), size=sec.size)
                todo.append((obj, t.secnum))
            symbols[qk] = dict(new=nk, offset=t.value if not t.is_section_sym else 0)
            return 'new'
        unresolved.append(f'{os.path.basename(obj.path)}: {t.name}')
        return None
    def known(obj, t):
        k = sym_key(obj.path, t) if not t.is_section_sym else f'{os.path.basename(obj.path)}#{t.name}#sec{t.secnum}'
        v = symbols.get(f'{os.path.basename(obj.path)}@{k}', symbols.get(k))
        if isinstance(v, int):
            return v
        if t.secnum <= 0:
            v = amap.resolve(t.name)[0]
            return v if v is not None else import_thunk(t.name) or index_name(t.name)
        return None if t.is_section_sym else by_content(obj, t)

    def pair_calls(va, obj, sym, rels):
        """Unresolved call targets of an edited function, paired with the original function's calls in
        order: between two calls that resolve to the same targets on both sides, an equal number of calls
        pair one to one (e.g. __chkstk, which no name list holds)."""
        orig = calls_of.get(va)
        if not orig:
            return
        code = obj.function_bytes(sym)[0]
        mine = [r for r in rels if r.type == REL32 and r.symbol is not None and r.offset >= 1
                and code[r.offset - 1] == 0xE8 and r.symbol.secnum <= 0 and not r.symbol.is_section_sym]
        vals = [known(obj, r.symbol) for r in mine]
        import difflib
        sm = difflib.SequenceMatcher(None, [v if v is not None else ('?', i) for i, v in enumerate(vals)], orig,
                                     autojunk=False)
        blocks = sm.get_matching_blocks()
        prev_a = prev_b = 0
        for blk in blocks:
            ga, gb = blk.a - prev_a, blk.b - prev_b
            if ga == gb:
                for k in range(ga):
                    r, v = mine[prev_a + k], vals[prev_a + k]
                    if v is None:
                        key = sym_key(obj.path, r.symbol)
                        if key not in symbols:
                            symbols[key] = orig[prev_b + k]
            prev_a, prev_b = blk.a + blk.size, blk.b + blk.size

    import bisect

    def pair_data(va, obj, sym, rels):
        """Statics of the unit an edited function uses (file or function scope) are the original's variables:
        pair the function's DIR32 references, in order, with the original function's relocated pointers
        (base relocations inside its extent) around the references that already agree."""
        i = bisect.bisect_right(fstarts, va)
        end = fstarts[i] if i < len(fstarts) else va + 0x10000
        orig = [struct.unpack_from('<I', pe.read(x, 4))[0] for x in pe.fixups if va <= x < end]
        orig = [v for v in orig if not va <= v < end]          # its own jump tables / labels
        code = obj.function_bytes(sym)[0]
        mine = [r for r in rels if r.type == DIR32 and r.symbol is not None and r.symbol.secnum != sym.secnum]
        adds = [struct.unpack_from('<i', code, r.offset)[0] for r in mine]
        vals = []
        for r, ad in zip(mine, adds):
            v = known(obj, r.symbol)
            vals.append(None if v is None else (v + ad) & 0xFFFFFFFF)
        import difflib
        sm = difflib.SequenceMatcher(None, [v if v is not None else ('?', i) for i, v in enumerate(vals)], orig,
                                     autojunk=False)
        prev_a = prev_b = 0
        for blk in sm.get_matching_blocks():
            ga, gb = blk.a - prev_a, blk.b - prev_b
            if ga == gb:
                for k in range(ga):
                    r, v = mine[prev_a + k], vals[prev_a + k]
                    t = r.symbol
                    if v is None and t.secnum > 0 and not t.is_section_sym and t.storage == objcmp.CLASS_STATIC:
                        sec = t.section if t.section is not None else obj.sections[t.secnum - 1]
                        if sec.is_code:
                            continue
                        addr = (orig[prev_b + k] - adds[prev_a + k]) & 0xFFFFFFFF
                        qk = f'{os.path.basename(obj.path)}@{sym_key(obj.path, t)}'
                        if qk in symbols and symbols[qk] != addr:
                            unresolved.append(f'{os.path.basename(obj.path)}: {t.name} pairs with two addresses')
                        symbols[qk] = addr
            prev_a, prev_b = blk.a + blk.size, blk.b + blk.size

    for an, obj, sym in edited:
        code, rels = obj.function_bytes(sym)
        pair_calls(an['va'], obj, sym, rels)
        pair_data(an['va'], obj, sym, rels)
        for rel in rels:
            if rel.type != 0 and rel.symbol is not None:
                resolve(obj, rel.symbol, sym.secnum)
        functions.append(dict(va=hex(an['va']), obj=os.path.relpath(obj.path), symbol=sym.name,
                              index=sym.index, size=len(code), identical=False))
    while todo:
        obj, secnum = todo.pop()
        for rel in obj.sections[secnum - 1].relocs:
            if rel.type != 0 and rel.symbol is not None:
                resolve(obj, rel.symbol, secnum)


def cmd_link(reasm_dir, map_path, out_path, cache=None):
    m = json.load(open(map_path))
    tmp = tempfile.mkdtemp()
    base_img = os.path.join(tmp, 'phase5b.bin')
    reassemble.build(reasm_dir, base_img, cache)          # the full image from text (everything in assembly)
    img = bytearray(open(base_img, 'rb').read())
    base, dirs, secs = reassemble.pe_parse(bytes(img))
    rel5b, reloc_name = reassemble.relocs_of(bytes(img), base, dirs, secs)

    def off(va):
        s = next(x for x in secs if x['va'] <= va - base < x['va'] + x['raw_size'])
        return s['raw_ptr'] + va - base - s['va']
    objs = {}
    replaced, sites = [], set()
    nbytes = 0
    if any(not f.get('identical', True) for f in m['functions']):
        raise SystemExit('the map has edited functions (--all): link them with relink.py --free, not here')
    for f in m['functions']:
        va = int(f['va'], 16)
        obj = objs.get(f['obj']) or objs.setdefault(f['obj'], objcmp.read_coff(f['obj']))
        sym = next(s for s in obj.symbols.values() if s.index == f['index'] and s.name == f['symbol'])
        code, rels = obj.function_bytes(sym)
        code = bytearray(code)
        o = off(va)
        img[o:o + len(code)] = b'\xcc' * len(code)          # the slot is filled only from the object below
        for rel in rels:
            t = rel.symbol
            if rel.type == 0 or t is None:
                continue
            k = sym_key(obj.path, t) if not t.is_section_sym else f'{os.path.basename(obj.path)}#{t.name}#sec{t.secnum}'
            tva = m['symbols'].get(f'{os.path.basename(obj.path)}@{k}', m['symbols'].get(k))
            if tva is None:
                raise SystemExit(f'{f["obj"]} {f["symbol"]}: no address for symbol {k}')
            add = struct.unpack_from('<i', code, rel.offset)[0]
            p = va + rel.offset
            if rel.type == DIR32:
                v = tva + add
                sites.add(p - base)
            elif rel.type == DIR32NB:
                v = tva - base + add
            else:
                v = tva + add - (p + 4)
            struct.pack_into('<I', code, rel.offset, v & 0xFFFFFFFF)
        img[o:o + len(code)] = code
        replaced.append((va, va + len(code)))
        nbytes += len(code)
    replaced.sort()
    import bisect
    starts = [r[0] for r in replaced]

    def in_replaced(va):
        i = bisect.bisect_right(starts, va) - 1
        return i >= 0 and va < replaced[i][1]
    for site in rel5b:
        if not in_replaced(site):
            sites.add(site - base)
    rs = next(s for s in secs if s['name'] == reloc_name)
    r = reassemble.make_reloc(sites)
    if len(r) > rs['raw_size']:
        raise SystemExit('.reloc grew beyond its raw size')
    img[rs['raw_ptr']:rs['raw_ptr'] + rs['raw_size']] = r + b'\0' * (rs['raw_size'] - len(r))
    open(out_path, 'wb').write(img)
    text = next(s for s in secs if s['exec'])
    print(json.dumps(dict(functions_from_objects=len(m['functions']), code_bytes_from_objects=nbytes,
                          text_bytes=text['vsize'], share=round(nbytes / text['vsize'], 4),
                          relocation_sites=len(sites)), indent=1))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('map')
    p.add_argument('--pe', required=True)
    p.add_argument('--src', nargs='+', required=True)
    p.add_argument('--obj', nargs='+', required=True)
    p.add_argument('--module')
    p.add_argument('--functions')
    p.add_argument('--out', required=True)
    p.add_argument('--instructions', help='Ghidra instruction listing (instructions.tsv) of the original: '
                   'pairs calls of edited functions that nothing else names')
    p.add_argument('--all', action='store_true',
                   help='also edited FUNCTIONs (not identical any more): build-from-source mode for relink.py')
    p = sub.add_parser('link')
    p.add_argument('reassembled')
    p.add_argument('map')
    p.add_argument('out')
    p.add_argument('--cache')
    p = sub.add_parser('verify')
    p.add_argument('original')
    p.add_argument('reassembled')
    p.add_argument('map')
    p.add_argument('--cache')
    a = ap.parse_args()
    if a.cmd == 'map':
        return cmd_map(a)
    if a.cmd == 'link':
        return cmd_link(a.reassembled, a.map, a.out, a.cache)
    out = os.path.join(tempfile.mkdtemp(), 'hybrid.bin')
    cmd_link(a.reassembled, a.map, out, a.cache)
    x, y = open(a.original, 'rb').read(), open(out, 'rb').read()
    if hashlib.sha256(x).digest() == hashlib.sha256(y).digest():
        print('IDENTICAL', hashlib.sha256(x).hexdigest())
        return 0
    first = next((i for i in range(min(len(x), len(y))) if x[i] != y[i]), min(len(x), len(y)))
    print(f'DIFFERENT: first difference at file offset 0x{first:x}; rebuilt kept at {out}')
    return 1


if __name__ == '__main__':
    sys.exit(main())
