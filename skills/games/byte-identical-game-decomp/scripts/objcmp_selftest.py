#!/usr/bin/env python3
"""objcmp_selftest.py <pe> [--functions index.json] [--work DIR] [--count 20]

Self-test for objcmp.py without a compiler: takes ~20 real functions of <pe> (from Ghidra's index.json, or
found heuristically from call targets without it), turns every original .reloc fixup inside each into a DIR32
relocation (alternately addend 0 with zeroed field, and in-place addend against a rounded base symbol;
IAT slots become __imp__<name>) and every E8/E9 rel32 to a known function start outside the function into a
REL32 relocation to an external symbol, writes /Gy-style, non-/Gy and /bigobj objects with objcmp.write_obj,
reads them back and checks: round trip, every function identical (with and without an address map),
a mutated byte reported at its offset, a wrong REL32 / DIR32 map entry reported, inconsistent targets,
truncation, missing relocation, padding with an explicit size, report mode with annotations
(identical / ambiguous / unmapped), and the CLI exit codes. Exit 0 when every check passes.
Stdlib only; run with -I.
"""
import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import objcmp  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OBJCMP = os.path.join(HERE, 'objcmp.py')
RESULTS = []


def check(name, ok, detail=''):
    RESULTS.append((name, bool(ok)))
    print(f'{"PASS" if ok else "FAIL"}  {name}' + (f'  ({detail})' if detail else ''))
    return ok


def cli(*args):
    p = subprocess.run([sys.executable, '-I', OBJCMP] + [str(a) for a in args], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, universal_newlines=True)
    return p.returncode, p.stdout


def s32(v):
    return v - (1 << 32) if v & 0x80000000 else v


def heuristic_functions(pe):
    """Without index.json: call targets in executable sections preceded by CC/90, ending at ret + CC/90."""
    starts = {}
    for name, sva, vsize, rawsize, rawptr, ch in pe.sections:
        if not ch & (objcmp.SCN_EXEC | objcmp.SCN_CNT_CODE):
            continue
        base = pe.image_base + sva
        blob = pe.read(base, min(vsize, rawsize))
        for p in range(len(blob) - 5):
            if blob[p] == 0xE8:
                t = base + p + 5 + s32(struct.unpack_from('<I', blob, p + 1)[0])
                if base < t < base + len(blob) and blob[t - base - 1] in (0xCC, 0x90):
                    starts[t] = starts.get(t, 0) + 1
    out = {}
    for t, n in starts.items():
        if n < 2:
            continue
        b = pe.read(t, 4096)
        for k in range(len(b) - 3):
            if b[k] == 0xC3 and b[k + 1] in (0xCC, 0x90):
                out[t] = k + 1
                break
            if b[k] == 0xC2 and b[k + 3] in (0xCC, 0x90) and b[k + 2] == 0:
                out[t] = k + 3
                break
    return out


def build_function(pe, va, size, starts, imp_by_slot, style_counter):
    """bytes + relocation list + map entries for one original function."""
    b = bytearray(pe.read(va, size))
    rels, amap = [], {}
    covered = set()
    for f in pe.fixups_in(va, size):
        o = f - va
        if o < 0 or o + 4 > size:
            return None
        tgt = struct.unpack_from('<I', b, o)[0]
        covered.update(range(o, o + 4))
        if tgt in imp_by_slot:
            nm = imp_by_slot[tgt]
            sym = '__imp_' + nm if nm.startswith('?') else '__imp__' + nm
            rels.append({'offset': o, 'type': 'DIR32', 'symbol': sym})
            struct.pack_into('<I', b, o, 0)
            continue
        style_counter[0] += 1
        if style_counter[0] % 2:
            sym = f'_fn_{tgt:08x}' if tgt in starts else f'_g_{tgt:08x}'
            rels.append({'offset': o, 'type': 'DIR32', 'symbol': sym})
            struct.pack_into('<I', b, o, 0)                       # addend 0, field zeroed
            amap[sym] = tgt
        else:
            base = tgt & ~0xFF
            sym = f'_g_{base:08x}'
            rels.append({'offset': o, 'type': 'DIR32', 'symbol': sym})
            struct.pack_into('<I', b, o, tgt - base)              # MSVC style: addend stored in place
            amap[sym] = base
    p = 0
    while p + 5 <= size:
        if b[p] in (0xE8, 0xE9) and not covered.intersection(range(p, p + 5)):
            t = (va + p + 5 + s32(struct.unpack_from('<I', b, p + 1)[0])) & 0xFFFFFFFF
            if t in starts and not (va <= t < va + size):
                sym = f'_fn_{t:08x}'
                rels.append({'offset': p + 1, 'type': 'REL32', 'symbol': sym})
                struct.pack_into('<I', b, p + 1, 0)
                amap[sym] = t
                covered.update(range(p, p + 5))
                p += 5
                continue
        p += 1
    rels.sort(key=lambda r: r['offset'])
    return bytes(b), rels, amap


def find_run(pe, flist, want=8, max_bytes=6000):
    """Adjacent functions [(va, next_va)] whose gaps are only CC/90 padding; prefers runs with internal calls."""
    addrs = sorted(a for a in flist if pe.is_exec(a))
    best, best_score = [], -1
    i = 0
    while i < len(addrs) - want:
        run, ok = [], True
        for k in range(i, i + want):
            va, nxt = addrs[k], addrs[k + 1]
            size = flist[va]
            gap = pe.read(va + size, max(0, nxt - va - size)) if size else b'x'
            if not size or nxt - va > max_bytes or any(c not in (0xCC, 0x90) for c in gap):
                ok = False
                break
            run.append((va, nxt))
        if ok and run[-1][1] - run[0][0] <= max_bytes:
            lo, hi = run[0][0], run[-1][1]
            blob = pe.read(lo, hi - lo)
            score = 0
            for p in range(len(blob) - 5):
                if blob[p] == 0xE8:
                    t = lo + p + 5 + s32(struct.unpack_from('<I', blob, p + 1)[0])
                    score += lo <= t < hi and t in flist
            if score > best_score:
                best, best_score = run, score
            if score >= 3:
                break
            i += want
        else:
            i += 1
    return best


def pick(cands, n):
    if len(cands) <= n:
        return cands
    step = len(cands) / n
    return [cands[int(i * step)] for i in range(n)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pe')
    ap.add_argument('--functions', help='Ghidra index.json (address, size)')
    ap.add_argument('--work', help='scratch directory (default: a new temp dir)')
    ap.add_argument('--count', type=int, default=20)
    args = ap.parse_args()
    work = args.work or tempfile.mkdtemp(prefix='objcmp_selftest_')
    os.makedirs(work, exist_ok=True)
    pe = objcmp.PEImage(args.pe)
    print(f'PE {args.pe}: base 0x{pe.image_base:x}, {len(pe.sections)} sections, {len(pe.fixups)} fixups, '
          f'{len(pe.imports)} imports; work dir {work}')
    flist = objcmp.load_function_list(args.functions) if args.functions else heuristic_functions(pe)
    starts = set(flist)
    imp_by_slot = {v: k for k, v in pe.imports.items() if '#' not in k}

    # ---- choose functions: small / medium / large, preferring ones with fixups and calls
    style = [0]
    built = {}
    buckets = {'small': [], 'medium': [], 'large': []}
    for va, size in sorted(flist.items()):
        if size < 5 or size > 8000 or not pe.is_exec(va):
            continue
        after = pe.read(va + size, 1)
        if not (va + size in starts or (after and after[0] in (0xCC, 0x90))):
            continue
        rich = bool(pe.fixups_in(va, size)) and any(pe.read(va, size)[k] == 0xE8 for k in range(size))
        key = 'small' if size <= 64 else 'medium' if size <= 600 else 'large'
        buckets[key].append((not rich, va, size))
    n = args.count
    chosen = []
    for key, k in (('small', n * 3 // 10), ('medium', n * 4 // 10), ('large', n - n * 3 // 10 - n * 4 // 10)):
        c = sorted(buckets[key])
        rich = [x for x in c if not x[0]]
        poor = [x for x in c if x[0]]
        chosen += pick(rich, max(1, k - 1)) + pick(poor, 1)
    funcs, gmap = [], {}
    for _, va, size in chosen:
        r = build_function(pe, va, size, starts, imp_by_slot, style)
        if r is None:
            continue
        b, rels, amap = r
        funcs.append({'name': f'_fn_{va:08x}', 'bytes': b, 'relocations': rels, 'va': va, 'size': size})
        gmap.update(amap)
    # C++ names for annotation mapping: one method, two overloads
    funcs[1]['name'] = '?Update@CUnit@@QAEXXZ'
    funcs[2]['name'] = '?Foo@@YAXH@Z'
    funcs[3]['name'] = '?Foo@@YAXN@Z'
    for f in funcs:
        gmap[f['name']] = f['va']
    nrel = sum(len(f['relocations']) for f in funcs)
    n32 = sum(1 for f in funcs for r in f['relocations'] if r['type'] == 'REL32')
    nimp = sum(1 for f in funcs for r in f['relocations'] if r['symbol'].startswith('__imp_'))
    print(f'chosen {len(funcs)} functions, sizes {min(f["size"] for f in funcs)}..{max(f["size"] for f in funcs)} '
          f'(total {sum(f["size"] for f in funcs)} bytes); {nrel} relocations: {nrel - n32} DIR32 '
          f'({nimp} to __imp_ IAT slots), {n32} REL32')
    mapfile = os.path.join(work, 'addrmap.txt')

    def writer_funcs(fs):
        return [{'name': f['name'], 'bytes': f['bytes'], 'relocations': f['relocations']} for f in fs]

    # non-/Gy translation unit: a run of adjacent original functions (padding belongs to the preceding one),
    # one .text section; calls inside the run resolve as same-section targets
    run = find_run(pe, flist)
    run_funcs = []
    for va, nxt in run:
        b, rels, amap = build_function(pe, va, nxt - va, starts, imp_by_slot, style)
        run_funcs.append({'name': f'_fn_{va:08x}', 'bytes': b, 'relocations': rels, 'va': va, 'size': nxt - va})
        gmap.update(amap)
    for f in run_funcs:
        gmap[f['name']] = f['va']
    if run_funcs:
        nin = sum(1 for f in run_funcs for r in f['relocations']
                  if r['type'] == 'REL32' and r['symbol'] in {g['name'] for g in run_funcs})
        print(f'non-/Gy run: {len(run_funcs)} adjacent functions 0x{run[0][0]:x}..0x{run[-1][1]:x} '
              f'({run[-1][1] - run[0][0]} bytes incl. padding), {nin} calls inside the run')
    with open(mapfile, 'w') as fh:
        for k, v in sorted(gmap.items()):
            fh.write(f'{k} 0x{v:08x}\n')

    variants = {'gy': dict(comdat=True), 'nogy': dict(comdat=False), 'bigobj': dict(comdat=True, bigobj=True)}
    vfuncs = {'gy': funcs, 'nogy': run_funcs, 'bigobj': funcs}
    objs = {}
    for tag, kw in variants.items():
        if not vfuncs[tag]:
            check(f'{tag}: no suitable functions found', False)
            continue
        p = os.path.join(work, f'selftest_{tag}.obj')
        objcmp.write_obj(p, writer_funcs(vfuncs[tag]), absolutes={'@comp.id': 0x00AB766F}, **kw)
        objs[tag] = p

    # ---- 1. round trip
    for tag, p in objs.items():
        o = objcmp.read_coff(p)
        bad = []
        for f in vfuncs[tag]:
            hit = o.find(f['name'])
            if len(hit) != 1:
                bad.append(f'{f["name"]}: {len(hit)} symbols')
                continue
            s = hit[0]
            data, rels = o.function_bytes(s)
            if data != f['bytes'] or s.size != f['size']:
                bad.append(f'{f["name"]}: bytes/size differ ({s.size} vs {f["size"]})')
            got = [(r.offset, r.type_name, r.symbol.name) for r in rels]
            want = [(r['offset'], r['type'], r['symbol']) for r in f['relocations']]
            if got != want:
                bad.append(f'{f["name"]}: relocations differ')
            if variants[tag]['comdat'] and (s.section.comdat != 1 or s.section.checksum != objcmp.jamcrc(data)):
                bad.append(f'{f["name"]}: COMDAT selection/checksum')
        check(f'round trip {tag} ({"bigobj" if o.bigobj else "COFF"}, {len(o.sections)} sections, '
              f'{len(o.symbols)} symbols)', not bad and o.bigobj == (tag == 'bigobj'), '; '.join(bad[:3]))
        rc, out = cli('dump', p)
        check(f'dump CLI {tag}', rc == 0 and all(f['name'] in out for f in vfuncs[tag]) and 'REL32' in out,
              f'exit {rc}, {len(out.splitlines())} lines')

    # ---- 2. compare every function: with map, without map, per variant
    def compare_all(path, amap, fs=funcs):
        o = objcmp.read_coff(path)
        res = []
        for f in fs:
            res.append(objcmp.compare_function(o, o.find(f['name'])[0], pe, f['va'], None, amap, starts))
        return res

    for tag in objs:
        m = objcmp.AddrMap(pe, auto_names=False)
        m.load(mapfile)
        res = compare_all(objs[tag], m, vfuncs[tag])
        bad = [f'{r["symbol"]}: {objcmp.format_result(r, True)}' for r in res if not r['identical']]
        by = {}
        for r in res:
            for k, v in r['resolved_by'].items():
                by[k] = by.get(k, 0) + v
        check(f'compare {tag} with address map: {sum(r["identical"] for r in res)}/{len(res)} identical, '
              f'{sum(r["relocs_checked"] for r in res)}/{sum(r["relocs"] for r in res)} relocs target-checked '
              f'{by}, '
              f'{sum(r["orig_fixups"] for r in res)} original fixups masked', not bad, bad[0][:600] if bad else '')
    res = compare_all(objs['gy'], objcmp.AddrMap(pe, auto_names=False))
    check(f'compare gy without map: {sum(r["identical"] for r in res)}/{len(res)} identical, '
          f'{sum(r["relocs_checked"] for r in res)} checked (imports), {sum(r["relocs_inferred"] for r in res)} inferred',
          all(r['identical'] for r in res))
    ratio_ok = all(r['ratio'] == 1.0 and r['first_diff'] is None for r in res)
    check('identical results have ratio 1.0 and no first_diff', ratio_ok)

    # CLI compare: exit 0 on a few
    okc = 0
    ffile = os.path.join(work, 'functions.json')      # known starts for the CLI (index.json or heuristic)
    with open(ffile, 'w') as fh:
        json.dump({'functions': [{'address': hex(a), 'size': z} for a, z in sorted(flist.items())]}, fh)
    fopt = ['--functions', ffile]
    for f in funcs[:3] + funcs[-2:]:
        rc, out = cli('compare', objs['bigobj'], f['name'], args.pe, hex(f['va']), '--map', mapfile, *fopt)
        okc += rc == 0 and 'IDENTICAL' in out
    check(f'compare CLI exit 0 ({okc}/5)', okc == 5)
    rc, out = cli('compare', objs['gy'], 'CUnit::Update', args.pe, hex(funcs[1]['va']), '--map', mapfile, *fopt)
    check('compare CLI accepts undecorated Class::Method', rc == 0, out.splitlines()[0] if out else '')
    rc, out = cli('compare', objs['gy'], 'Foo', args.pe, hex(funcs[2]['va']))
    check('compare CLI refuses ambiguous Foo (exit 2)', rc == 2 and 'ambiguous' in out, out.strip()[:120])

    # ---- 3. mutation of a non-relocated byte
    med = max((f for f in funcs if 64 < f['size'] <= 600 and f['relocations']), key=lambda f: len(f['relocations']))
    masked = set()
    for r in med['relocations']:
        masked.update(range(r['offset'], r['offset'] + 4))
    for fx in pe.fixups_in(med['va'], med['size']):
        masked.update(range(fx - med['va'], fx - med['va'] + 4))
    k = next(i for i in range(med['size'] // 2, med['size']) if i not in masked)
    mb = bytearray(med['bytes'])
    mb[k] ^= 0x01
    mut = dict(med, bytes=bytes(mb))
    p = os.path.join(work, 'mutated.obj')
    objcmp.write_obj(p, writer_funcs([mut]))
    o = objcmp.read_coff(p)
    r = objcmp.compare_function(o, o.find(med['name'])[0], pe, med['va'], None, None, starts)
    check(f'mutated byte at +0x{k:x} of {med["name"]} ({med["size"]} bytes) reported at +0x{r["first_diff"]:x}, '
          f'ratio {r["ratio"]}', not r['identical'] and r['first_diff'] == k and r['diff_bytes'] == 1)
    rc, out = cli('compare', p, med['name'], args.pe, hex(med['va']))
    check('compare CLI exit 1 on mutation with hex context', rc == 1 and f'+0x{k:x}' in out and '^^' in out)
    print('\n'.join('      ' + ln for ln in out.splitlines()[:8]))

    # ---- 4. wrong REL32 / DIR32 targets in the address map
    def wrong_map(rtype):
        f = next(f for f in funcs if any(r['type'] == rtype and not r['symbol'].startswith('__imp_')
                                         for r in f['relocations']))
        rr = next(r for r in f['relocations'] if r['type'] == rtype and not r['symbol'].startswith('__imp_'))
        m = objcmp.AddrMap(pe, auto_names=False)
        m.load(mapfile)
        m.names[rr['symbol']] += 0x10
        o = objcmp.read_coff(objs['gy'])
        res = objcmp.compare_function(o, o.find(f['name'])[0], pe, f['va'], None, m, starts)
        iss = [i for i in res['issues'] if i['kind'] == 'target_mismatch']
        return f, rr, res, iss

    for rtype in ('REL32', 'DIR32'):
        f, rr, res, iss = wrong_map(rtype)
        check(f'wrong {rtype} map entry ({rr["symbol"]} +0x10) reported at +0x{rr["offset"]:x}',
              not res['identical'] and len(iss) == 1 and iss[0]['offset'] == rr['offset'],
              iss[0]['detail'] if iss else res['issues'])

    # ---- 5. inconsistent targets without a map (two different callees under one symbol name)
    f = next(f for f in funcs if len({r['symbol'] for r in f['relocations'] if r['type'] == 'REL32'}) >= 2)
    r32 = [r for r in f['relocations'] if r['type'] == 'REL32']
    second = next(r for r in r32 if r['symbol'] != r32[0]['symbol'])
    rels = [dict(r, symbol=r32[0]['symbol']) if r is second else r for r in f['relocations']]
    p = os.path.join(work, 'inconsistent.obj')
    objcmp.write_obj(p, [{'name': f['name'], 'bytes': f['bytes'], 'relocations': rels}])
    o = objcmp.read_coff(p)
    res = objcmp.compare_function(o, o.find(f['name'])[0], pe, f['va'], None, objcmp.AddrMap(pe, False), starts)
    check('same symbol, two different original targets -> inconsistent_target',
          any(i['kind'] == 'inconsistent_target' for i in res['issues']) and not res['identical'])

    # ---- 6. truncated obj function, missing DIR32 relocation, explicit size with padding
    t = funcs[0]
    p = os.path.join(work, 'truncated.obj')
    objcmp.write_obj(p, [{'name': t['name'], 'bytes': t['bytes'][:-1],
                          'relocations': [r for r in t['relocations'] if r['offset'] + 4 <= t['size'] - 1]}])
    o = objcmp.read_coff(p)
    res = objcmp.compare_function(o, o.find(t['name'])[0], pe, t['va'])
    check(f'truncated obj ({t["size"] - 1} of {t["size"]} bytes) -> size issue at +0x{t["size"] - 1:x}',
          not res['identical'] and res['first_diff'] == t['size'] - 1
          and any(i['kind'] == 'size' for i in res['issues']))
    f = next(f for f in funcs if any(r['type'] == 'DIR32' for r in f['relocations']))
    rr = next(r for r in f['relocations'] if r['type'] == 'DIR32')
    fb = bytearray(f['bytes'])
    fb[rr['offset']:rr['offset'] + 4] = pe.read(f['va'] + rr['offset'], 4)
    p = os.path.join(work, 'noreloc.obj')
    objcmp.write_obj(p, [{'name': f['name'], 'bytes': bytes(fb),
                          'relocations': [r for r in f['relocations'] if r is not rr]}])
    o = objcmp.read_coff(p)
    res = objcmp.compare_function(o, o.find(f['name'])[0], pe, f['va'], None, objcmp.AddrMap(pe, False), starts)
    check(f'DIR32 removed (original bytes kept) -> fixup_without_reloc at +0x{rr["offset"]:x}',
          not res['identical'] and res['first_diff'] == rr['offset']
          and any(i['kind'] == 'fixup_without_reloc' for i in res['issues']))
    padded = None
    for f in funcs:
        tail = pe.read(f['va'] + f['size'], 16)
        npad = len(tail) - len(tail.lstrip(bytes([tail[0]]))) if tail and tail[0] in (0xCC, 0x90) else 0
        if npad:
            padded = (f, npad)
            break
    if padded:
        f, npad = padded
        o = objcmp.read_coff(objs['gy'])
        m = objcmp.AddrMap(pe, False)
        m.load(mapfile)
        res = objcmp.compare_function(o, o.find(f['name'])[0], pe, f['va'], f['size'] + npad, m)
        res2 = objcmp.compare_function(o, o.find(f['name'])[0], pe, f['va'], f['size'] + npad + 1, m)
        nxt = pe.read(f['va'] + f['size'] + npad, 1)[0]
        check(f'explicit size {f["size"]}+{npad} padding bytes -> identical; size +1 more -> '
              f'{"different" if not res2["identical"] else "identical"} (next byte {nxt:02x})',
              res['identical'] and res['padding'] == npad and (res2['identical'] == (nxt in (0xCC, 0x90))))
    try:
        objcmp.CoffObj(b'\0\0\xff\xff\x01\x00\x4c\x01' + b'\0' * 64, 'ltcg.obj')
        check('anonymous (/GL) object rejected', False)
    except objcmp.CoffError as e:
        check('anonymous (/GL) object rejected with a clear error', '/GL' in str(e), str(e)[:60])

    # ---- 7. report mode with annotations
    src = os.path.join(work, 'src')
    os.makedirs(src, exist_ok=True)
    lines = ['// objcmp selftest sources', '']
    for f in funcs:
        if f['name'] == '?Update@CUnit@@QAEXXZ':
            lines += [f'// FUNCTION: VVVVVV 0x{f["va"]:x}', 'void CUnit::Update()', '{', '}', '']
        elif f['name'].startswith('?Foo'):
            continue
        elif f is funcs[4]:
            lines += [f'// FUNCTION: VVVVVV 0x{f["va"]:x} {f["name"]}', 'static int helper_with_other_name(int a) {',
                      '}', '']
        elif f is funcs[5]:
            lines += [f'// FUNCTION: 0x{f["va"]:x}', f'int __stdcall {f["name"][1:]}(int a, int b) {{ return 0; }}', '']
        else:
            lines += [f'// FUNCTION: VVVVVV 0x{f["va"]:x}', f'int {f["name"][1:]}(void)', '{', '    return 0;', '}', '']
    gsym = next(r['symbol'] for f in funcs if f['name'].startswith('_fn_') for r in f['relocations']
                if r['symbol'].startswith('_g_') and int(r['symbol'][3:], 16) == gmap[r['symbol']])
    lines += [f'// GLOBAL: VVVVVV 0x{gmap[gsym]:x}', f'extern int {gsym[1:]};', '',
              '// GLOBAL: VVVVVV 0x4a0000', 'int g_counter = 0;', '',
              '// VTABLE: VVVVVV 0x4b0000', 'class CUnit : public CBase {', '};', '',
              '// FUNCTION: OTHERMOD 0x401234', 'void other_module_function() {}', '']
    with open(os.path.join(src, 'game.cpp'), 'w') as fh:
        fh.write('\n'.join(lines))
    jout = os.path.join(work, 'report.json')
    rc, out = cli('report', '--pe', args.pe, '--src', src, '--obj', objs['gy'], '--module', 'VVVVVV',
                  '--json', jout, '-q', *fopt)
    rep = json.load(open(jout))
    sm = rep['summary']
    expect = len(funcs) - 2
    check(f'report (annotations only, no map): {sm["identical"]}/{sm["annotated_functions"]} identical, bytes '
          f'{sm["bytes_identical"]}/{sm["bytes_total"]}, relocs target-checked '
          f'{sum(f.get("relocs_checked") or 0 for f in rep["functions"])}, exit {rc}',
          rc == 0 and sm['identical'] == expect == sm['annotated_functions'], out.strip().splitlines()[-1])
    check(f'report maps GLOBAL {gsym}, lists {len(rep["data"])} GLOBAL/VTABLE and skips the other module',
          len(rep['data']) == 3 and any(d['symbol'] == gsym for d in rep['data'])
          and sum(f.get('relocs_checked') or 0 for f in rep['functions']) >= 1 and all(f['module'] != 'OTHERMOD' for f in rep['functions']))
    with open(os.path.join(src, 'bad.cpp'), 'w') as fh:
        fh.write(f'// FUNCTION: VVVVVV 0x{funcs[2]["va"]:x}\nvoid Foo(int x) {{\n}}\n\n'
                 f'// FUNCTION: VVVVVV 0x{funcs[3]["va"]:x}\nvoid Missing::Thing() {{\n}}\n\n'
                 f'// STUB: VVVVVV 0x{funcs[3]["va"] + 0x1000:x}\nvoid fn_00000000() {{\n}}\n')
    rc, out = cli('report', '--pe', args.pe, '--src', src, '--obj', objs['gy'], '--module', 'VVVVVV',
                  '--json', jout, '-q', *fopt)
    rep = json.load(open(jout))
    st = {f['va']: f['status'] for f in rep['functions']}
    check(f'report with ambiguous + unmapped + stub annotations -> exit {rc}, '
          f'{rep["summary"]["unmapped"]} unmapped/ambiguous, {rep["summary"]["stubs"]} stub',
          rc == 1 and st.get(hex(funcs[2]['va'])) == 'ambiguous' and st.get(hex(funcs[3]['va'])) == 'unmapped'
          and rep['summary']['stubs'] == 1, '; '.join(ln for ln in out.splitlines() if 'AMBIG' in ln or 'UNMAPPED' in ln)[:300])
    print('\n'.join('      ' + ln for ln in out.splitlines() if not ln.startswith(('OK', 'STUB')))[:2000])

    # ---- 8. decorated-name <-> source-name mapping
    cases = [('??0CUnit@@QAE@XZ', 'CUnit::CUnit()'), ('??1CUnit@@UAE@XZ', 'CUnit::~CUnit()'),
             ('??4CUnit@@QAEAAV0@ABV0@@Z', 'CUnit &CUnit::operator=(const CUnit &o)'),
             ('??8@YA_NABUX@@0@Z', 'bool operator==(const X &a, const X &b)'),
             ('?Update@Inner@Outer@@QAEXXZ', 'void Outer::Inner::Update()'),
             ('_foo', 'int foo(void)'), ('_WinMain@16', 'int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d)'),
             ('@fast@8', 'int __fastcall fast(int a, int b)'),
             ('?Bar@CFoo@@QAGHHPAD@Z', 'BOOL __declspec(dllexport) __stdcall CFoo::Bar(int a, char *b)'),
             ('?Get@CUnit@@QBEPAV1@XZ', 'CUnit *CUnit::Get() const'),
             ('??RFunctor@@QAEHH@Z', 'int Functor::operator()(int x)')]
    bad = [(d, src) for d, src in cases
           if objcmp.name_parts(d) != objcmp.source_parts(objcmp.parse_definition(src) or '')]
    bad += [(d, 'None expected') for d in ('??$Max@H@@YAHHH@Z', '?Get@?$Vec@H@@QAEHXZ') if objcmp.name_parts(d)]
    special = objcmp.name_parts('??_7CUnit@@6B@') == ('CUnit', '<vftable>') and \
        objcmp.name_parts('??_GCUnit@@UAEPAXI@Z') == ('CUnit', '<sdtor>')
    check(f'name mapping: {len(cases) + 2 - len(bad)}/{len(cases) + 2} decorated/source pairs, vftable/sdtor',
          not bad and special, str(bad[:3]))

    failed = [n for n, ok in RESULTS if not ok]
    print(f'\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed' + (f'; FAILED: {failed}' if failed else ''))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
