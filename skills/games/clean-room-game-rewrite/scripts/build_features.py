#!/usr/bin/env python3
"""Step 3b prep: per-function features, vtable/pointer tables, and naming chunks.

  build_features.py <decomp_dir> <binary> <analysis_dir> [--chunk-lines 8200] [--force]

<decomp_dir> is a run_recovery.sh output (functions/*.c + index.json). Use one <analysis_dir> per binary
(e.g. analysis/<binary-stem>/): the output names are fixed, so the script refuses (exit 2) to write into a
directory that already holds another binary's features unless --force. Writes into <analysis_dir>:
  features.json        [{addr, name, size, lines, calls[], calls_ambiguous[], strings[], apis[], ncallers}]
                       calls = callee addresses. Taken from index.json "callees" when the exporter wrote them
                       (Ghidra's getCalledFunctions: direct calls, named or not); otherwise recovered from the
                       pseudocode: FUN_/LAB_/thunk_FUN_ references plus calls written with an already-applied
                       name (`Class::Method(`, or `Method(` inside the same class), resolved through the names
                       in index.json. A name that several functions share goes to calls_ambiguous instead.
                       apis = called names that are not functions of this binary (imports, externals) plus the
                       import behind each called thunk (index.json "thunk_of"; else names of <= 8-byte functions).
  pointer_tables.json  tables of code pointers in non-code sections (vtables, callback tables). A scanned run of
                       consecutive code pointers is SPLIT at every address inside it that code references or that
                       an exported vftable symbol (??_7Class@@6B@) names, because MSVC packs vtables back to back:
                       {addr, section, run_start, slots[], slots_known, names[] (exported vftable names),
                        installed_by[] (functions that take the table's address, `= &PTR_...`: ctors/dtors),
                        referenced_by[] (every function that mentions the address)}
                       Runs of >= 2 pointers are kept; a 1-slot table only when something references it.
  chunk_NN.json        address-contiguous groups of functions, ~chunk-lines of pseudocode each (stale chunk files
                       from an earlier run are removed)
  chunks.json          [{id, start, end, functions, lines}]  -> pass this list (not a placeholder!) as Workflow args
  features_meta.json   {binary, binary_sha256, decomp_dir, call_source ("index" | "pseudocode"), counts}
Stdlib only; run with -I.
"""
import collections, glob, hashlib, json, os, re, struct, sys

FUN = re.compile(r'\b(?:FUN|LAB|thunk_FUN)_([0-9a-f]{8})\b')
STR = re.compile(r'\bs_([A-Za-z0-9_]{1,60}?)_([0-9a-f]{8})\b')
# data references; Ghidra prefixes a leading '_' when the item is read as a value (_DAT_1000e280)
REF = re.compile(r'(&)?\s*\b_?(?:PTR_[A-Za-z0-9_]*?|DAT)_([0-9a-f]{8})\b')
# call sites: maximal identifier (qualified names, destructors) followed by '('
CALLTOK = re.compile(r'(?<![\w:~$@?<>])([A-Za-z_~][\w:~$@?<>]*)\s*\(')
# named vtable references as Ghidra prints a demangled `vftable' symbol
VTREF = re.compile(r'(&)?\s*\b((?:[A-Za-z_][\w<>,]*::)+_?v[fb]table_?)(?![\w])')
SKIP = ('FUN_', 'LAB_', 'thunk_FUN', 'CONCAT', 'SUB', 'ZEXT', 'SEXT', 'CARRY', 'SCARRY', 'SBORROW', 'POPCOUNT',
        'NAN', 'ROUND', 'TRUNC', 'FLOAT', 'ABS', 'SQRT', 'undefined', 'sizeof', 'while', 'switch', 'return', 'if', 'for')
THUNK_MAX = 8      # a `jmp [iat]` stub is 6 bytes


class PE:
    def __init__(self, path):
        d = self.d = open(path, 'rb').read()
        if d[:2] != b'MZ' or len(d) < 0x40:
            sys.exit(f'{path}: not a PE file (no MZ header)')
        o = struct.unpack_from('<I', d, 0x3c)[0]
        if d[o:o + 4] != b'PE\0\0':
            sys.exit(f'{path}: not a PE file (no PE signature)')
        n = struct.unpack_from('<H', d, o + 6)[0]
        opt = o + 24
        if struct.unpack_from('<H', d, opt)[0] != 0x10b:
            sys.exit(f'{path}: not a 32-bit PE (PE32+ is out of scope)')
        self.base = struct.unpack_from('<I', d, opt + 28)[0]
        self.nrva = struct.unpack_from('<I', d, opt + 92)[0]
        self.opt = opt
        so = opt + struct.unpack_from('<H', d, o + 20)[0]
        self.secs = []
        for i in range(n):
            nm, vs, va, rs, ro = struct.unpack_from('<8sIIII', d, so + 40 * i)
            ch = struct.unpack_from('<I', d, so + 40 * i + 36)[0]
            self.secs.append(dict(name=nm.rstrip(b'\0').decode('latin1'), va=self.base + va, vs=vs, ro=ro, rs=rs,
                                  code=bool(ch & 0x20000000)))

    def off(self, rva):
        for s in self.secs:
            va = s['va'] - self.base
            if va <= rva < va + s['rs']:
                return s['ro'] + rva - va
        return None

    def cstr(self, rva):
        p = self.off(rva)
        return self.d[p:self.d.index(b'\0', p)].decode('latin1') if p is not None else ''

    def exports(self):
        """[(va, name)] of named exports."""
        if self.nrva < 1:
            return []
        rva, size = struct.unpack_from('<II', self.d, self.opt + 96)
        e = self.off(rva) if rva else None
        if e is None:
            return []
        _, nn, af, an, ao = struct.unpack_from('<IIIII', self.d, e + 20)
        out = []
        for i in range(nn):
            nr = struct.unpack_from('<I', self.d, self.off(an) + 4 * i)[0]
            ordi = struct.unpack_from('<H', self.d, self.off(ao) + 2 * i)[0]
            fr = struct.unpack_from('<I', self.d, self.off(af) + 4 * ordi)[0]
            if not rva <= fr < rva + size:          # skip forwarders
                out.append((self.base + fr, self.cstr(nr)))
        return out


def vftable_name(mangled):
    """??_7Inner@Outer@@6B@ -> Outer::Inner::_vftable_ ; ??_7C@@6BB@@@ -> C::_vftable_ (for B). None if not one."""
    m = re.match(r'\?\?_([78])((?:[A-Za-z_]\w*@)+)@6B(.*)$', mangled)
    if not m:
        return None
    cls = '::'.join(reversed(m.group(2).split('@')[:-1]))
    kind = '_vftable_' if m.group(1) == '7' else '_vbtable_'
    rest = m.group(3).rstrip('@')
    return f'{cls}::{kind}' + (f' (for {"::".join(reversed(rest.split("@")))})' if rest else '')


def parse_callee(c):
    """index.json callee entry -> int address, or a str name for externals, or None."""
    if isinstance(c, dict):
        a = c.get('address', c.get('addr'))
        r = parse_callee(a) if a is not None else None
        return r if isinstance(r, int) else c.get('name') or r
    if isinstance(c, int):
        return c
    if isinstance(c, str):
        s = c.strip()
        try:
            return int(s, 16)
        except ValueError:
            if s.upper().startswith('EXTERNAL:'):         # Ghidra external space address: no name to report
                return None
            return s
    return None


def main():
    args = [a for a in sys.argv[1:] if a != '--force']
    force = '--force' in sys.argv
    target = 8200
    if '--chunk-lines' in args:
        i = args.index('--chunk-lines')
        target = int(args[i + 1]); del args[i:i + 2]
    if len(args) != 3:
        sys.exit(__doc__)
    ddir, binary, adir = args
    pe = PE(binary)
    bsha = hashlib.sha256(pe.d).hexdigest()

    os.makedirs(adir, exist_ok=True)
    meta_p = os.path.join(adir, 'features_meta.json')
    if os.path.exists(meta_p) and not force:
        old = json.load(open(meta_p))
        if old.get('binary_sha256') != bsha:
            print(f'{adir} already holds features of {old.get("binary")} (another binary). Use one analysis dir per '
                  f'binary, e.g. analysis/{os.path.splitext(os.path.basename(binary))[0]}/, or pass --force.',
                  file=sys.stderr)
            sys.exit(2)
    elif os.path.exists(os.path.join(adir, 'features.json')) and not force:
        print(f'note: overwriting features.json in {adir} from an earlier run (no features_meta.json)', file=sys.stderr)

    idx = json.load(open(os.path.join(ddir, 'index.json')))['functions']
    funcs = {}
    for f in idx:
        try:
            a = int(f['address'], 16)
        except (ValueError, TypeError):
            continue
        funcs[a] = f
    by_name, by_suffix = collections.defaultdict(list), collections.defaultdict(list)
    for a, f in funcs.items():
        by_name[f['name']].append(a)
        parts = f['name'].split('::')
        for k in range(1, len(parts)):
            by_suffix['::'.join(parts[k:])].append(a)

    def resolve(tok, caller):
        """Ghidra prints a callee's namespace only when it differs from the caller's, so try the name as
        written, then inside the caller's namespace and its parents, then any unique qualified match."""
        if tok in by_name:
            return by_name[tok]
        ns = caller.split('::')[:-1]
        while ns:
            hit = by_name.get('::'.join(ns + [tok]))
            if hit:
                return hit
            ns.pop()
        return by_suffix.get(tok, [])
    use_index = any('callees' in f for f in idx)
    code_secs = [s for s in pe.secs if s['code']]
    inside = sum(any(s['va'] <= a < s['va'] + s['vs'] for s in code_secs) for a in funcs)
    if funcs and inside < 0.9 * len(funcs):
        print(f'{ddir} does not look like a decompile of {binary}: only {inside} of {len(funcs)} function addresses '
              f'fall in its code sections', file=sys.stderr)
        sys.exit(2)

    # exported data symbols (vftables) -> address, and the names Ghidra prints for them
    vt_named = collections.defaultdict(set)          # address -> {display names}
    vt_by_name = collections.defaultdict(set)        # printed name -> {address}
    for va, nm in pe.exports():
        v = vftable_name(nm)
        if v:
            vt_named[va].add(v)
            vt_by_name[v.split(' (for ')[0]].add(va)

    feat, callers = [], collections.defaultdict(set)
    refs, installs = collections.defaultdict(set), collections.defaultdict(set)
    n_amb = 0
    for a in sorted(funcs):
        f = funcs[a]
        if f.get('status') != 'written':
            continue
        path = os.path.join(ddir, 'functions', f['address'] + '.c')
        if not os.path.exists(path):
            continue
        src = open(path, encoding='utf-8', errors='replace').read()
        body = '\n'.join(l for l in src.split('\n') if not l.startswith('//'))
        calls, amb, apis = set(), set(), set()
        if use_index:
            for c in f.get('callees') or ():
                c = parse_callee(c)
                if isinstance(c, int):
                    if c in funcs:
                        calls.add(c)
                elif c:
                    apis.add(c)
        else:
            # LAB_ targets inside this function's own body are jump labels, not calls
            calls = {c for c in (int(x, 16) for x in FUN.findall(body)) if c in funcs or not a <= c < a + f['size']}
        for tok in CALLTOK.findall(body):
            if tok.startswith(SKIP) or tok in ('if', 'for', 'while'):
                continue
            hits = resolve(tok, f['name'])
            if not hits:
                if not tok.startswith('_'):
                    apis.add(tok)
                continue
            if not use_index:
                if len(hits) == 1:
                    calls.add(hits[0])
                elif a not in hits:
                    amb.add(tok)
        calls.discard(a)
        for c in calls:
            g = funcs.get(c)
            if g is not None:
                t = g.get('thunk_of')
                if isinstance(t, str) and t and not t.startswith('0x'):
                    apis.add(t)                          # thunk of an import/external: report the import's name
                elif 'thunk_of' not in g and g['size'] <= THUNK_MAX and not g['name'].startswith(
                        ('FUN_', 'thunk_FUN_', 'LAB_')):
                    apis.add(g['name'])
            callers[c].add(a)
        n_amb += len(amb)
        for amp, r in REF.findall(body):
            r = int(r, 16)
            refs[r].add(a)
            if amp:
                installs[r].add(a)
        for amp, nm in VTREF.findall(body):
            for va in vt_by_name.get(nm, ()):
                refs[va].add(a)
                if amp:
                    installs[va].add(a)
        feat.append(dict(addr=f['address'], name=f['name'], size=f['size'], lines=body.count('\n'),
                         calls=['0x%x' % c for c in sorted(calls)], calls_ambiguous=sorted(amb),
                         strings=sorted({m[0] for m in STR.findall(body)})[:20], apis=sorted(apis)[:15]))
    for r in feat:
        r['ncallers'] = len(callers.get(int(r['addr'], 16), ()))
    json.dump(feat, open(os.path.join(adir, 'features.json'), 'w'))

    d, secs = pe.d, pe.secs
    starts = {int(r['addr'], 16) for r in feat}
    code = [s for s in secs if s['code']]
    in_code = lambda v: any(s['va'] <= v < s['va'] + s['vs'] for s in code)
    marks = set(refs) | set(vt_named)
    tables = []
    for s in secs:
        if s['code'] or not s['rs'] or s['name'].lower() in ('.rsrc', '.reloc'):
            continue
        i, size = 0, min(s['vs'], s['rs'])
        while i + 4 <= size:
            j, slots = i, []
            while j + 4 <= size:
                q = struct.unpack_from('<I', d, s['ro'] + j)[0]
                if in_code(q):
                    slots.append(q); j += 4
                else:
                    break
            a = s['va'] + i
            if len(slots) >= 2 or (slots and a in marks):
                cuts = sorted({a} | {m for m in marks if a < m < a + 4 * len(slots) and (m - a) % 4 == 0})
                for k, c in enumerate(cuts):
                    end = cuts[k + 1] if k + 1 < len(cuts) else a + 4 * len(slots)
                    piece = slots[(c - a) // 4:(end - a) // 4]
                    if len(piece) < 2 and c not in marks:
                        continue
                    tables.append(dict(addr=hex(c), section=s['name'], run_start=hex(a), slots=[hex(x) for x in piece],
                                       slots_known=sum(x in starts for x in piece), names=sorted(vt_named.get(c, ())),
                                       installed_by=['0x%x' % x for x in sorted(installs.get(c, ()))],
                                       referenced_by=['0x%x' % x for x in sorted(refs.get(c, ()))]))
                i = j
            else:
                i += 4
    json.dump(tables, open(os.path.join(adir, 'pointer_tables.json'), 'w'), indent=0)

    chunks, cur, n = [], [], 0
    for r in feat:
        cur.append(r); n += r['lines'] + 3
        if n >= target:
            chunks.append(cur); cur, n = [], 0
    if cur:
        chunks.append(cur)
    for old in glob.glob(os.path.join(glob.escape(adir), 'chunk_*.json')):
        os.remove(old)
    out = []
    for i, c in enumerate(chunks):
        cid = '%02d' % i if len(chunks) <= 100 else '%03d' % i
        json.dump(c, open(os.path.join(adir, f'chunk_{cid}.json'), 'w'))
        out.append(dict(id=cid, start=c[0]['addr'], end=c[-1]['addr'], functions=len(c), lines=sum(r['lines'] for r in c)))
    json.dump(out, open(os.path.join(adir, 'chunks.json'), 'w'))
    with_callers = sum(1 for r in feat if r['ncallers'])
    counts = dict(functions=len(feat), lines=sum(r['lines'] for r in feat), with_callers=with_callers,
                  call_edges=sum(len(r['calls']) for r in feat), ambiguous_call_names=n_amb,
                  pointer_tables=len(tables), tables_with_installer=sum(1 for t in tables if t['installed_by']),
                  exported_vftables=sum(len(v) for v in vt_named.values()), chunks=len(out))
    json.dump(dict(binary=os.path.basename(binary), binary_sha256=bsha, decomp_dir=os.path.abspath(ddir),
                   call_source='index' if use_index else 'pseudocode', counts=counts), open(meta_p, 'w'), indent=1)
    print(f'{counts["functions"]} functions ({with_callers} with callers, calls from '
          f'{"index.json callees" if use_index else "pseudocode"}), {counts["lines"]} lines, '
          f'{len(tables)} pointer tables ({counts["tables_with_installer"]} with installed_by), {len(out)} chunks')


if __name__ == '__main__':
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    main()
