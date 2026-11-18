#!/usr/bin/env python3
"""Phase-4 check of a Ghidra recovery (scripts/ghidra/run_recovery.sh output) against the PE itself.

Usage: python3 -I scripts/code_coverage_check.py <binary> <decompiled_dir>

Inputs: the PE, and from <decompiled_dir> (run_recovery.sh output) index.json, coverage_gaps.txt,
functions.tsv (exact function bodies) and instructions.tsv (every instruction with its flow targets; both
written by ExportListing.java). No external disassembler.

From the PE itself (independent of Ghidra's analysis decisions):
  * relocation targets: every absolute address the loader fixes up (.reloc). In a PE with relocations,
    every pointer to code - vtables, callback tables, `push offset fn`, switch jump tables - is one.
From Ghidra's instruction decoding (mechanical; independent of which functions it chose to create):
  * direct branch targets: call/jmp/jcc destinations.
Reports:
  functions  - how each function start is reached: called (direct call), pointer (relocated pointer),
               export/entry, jump-only, or unreferenced; for unreferenced ones what precedes/starts them.
  pointers   - every relocated pointer into code: function start, inside a function body, start of a
               jump table, start of a switch index table, pe_metadata (e.g. an IAT slot: `call [IAT]`),
               string, record_table, or UNEXPLAINED (must be 0).
  calls      - direct call targets that are not function starts (must be 0).
  gaps       - each coverage_gaps.txt run, walked byte by byte; every piece needs its own evidence:
               filler; jump_table (relocated code pointers; without relocations: dwords holding instruction
               starts, in a run one of whose addresses an instruction uses); index_bytes (values below the
               preceding table's entry count); pe_metadata (bytes the loader reads: data directories, import
               descriptors/lookup/address tables/hint-names/DLL names, export tables and names, debug data -
               in .text after /MERGE); string (printable, NUL-terminated, at a relocation target - without
               relocations at an instruction operand); record_table (records of a fixed size at a relocation
               target pointed to from data only, whose pointer slot holds a relocated pointer to data or NULL in
               every record, >= 3 pointers); data_read (from an address an instruction uses as a relocated
               memory operand up to the next referenced address or branch target); zero bytes after a
               pe_metadata/string/data_read piece count with it; uninitialized (past the section's file data);
               unreferenced_region (below). Anything else is UNEXPLAINED (must be none).
               unreferenced_region: in a PE with relocations, a gap inside an interval of .text with no
               relocation site, no relocation target and no export/entry, holding >= 32768 bytes that are not
               00/CC/90, that no branch or fall-through enters. Compiled code cannot go that far without an absolute
               address (the largest such run in real code measured 7.2 KB): it is unreferenced data (removed
               protection layers, compressed blobs, stale linker buffers). Same rule as
               scripts/ghidra/UnreferencedRegions.java; its entropy is reported.
  tables     - jump tables Ghidra decoded as instructions inside a function (warning: that function's
               pseudocode is wrong there; reassemble.py treats them as data).
Writes <decompiled_dir>/coverage_check.json, prints a summary, exits 1 if any must-be-zero count is not.
"""
import argparse, json, math, os, re, struct, sys


def pe_parse(d):
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    nsec, = struct.unpack_from('<H', d, pe + 6)
    optsz, = struct.unpack_from('<H', d, pe + 20)
    opt = pe + 24
    entry, = struct.unpack_from('<I', d, opt + 16)
    base, = struct.unpack_from('<I', d, opt + 28)
    ndirs, = struct.unpack_from('<I', d, opt + 92)
    dirs = [struct.unpack_from('<II', d, opt + 96 + 8 * i) for i in range(ndirs)]
    secs = []
    for i in range(nsec):
        o = opt + optsz + 40 * i
        name = d[o:o + 8].rstrip(b'\0').decode('latin-1')
        vsz, va, rsz, rptr = struct.unpack_from('<IIII', d, o + 8)
        ch, = struct.unpack_from('<I', d, o + 36)
        secs.append(dict(name=name, va=va, vsz=vsz, rsz=rsz, rptr=rptr, exec=bool(ch & 0x20000000)))
    return base, entry, dirs, secs


def rva_to_off(secs, rva):
    for s in secs:
        if s['va'] <= rva < s['va'] + max(s['vsz'], s['rsz']):
            return s['rptr'] + rva - s['va'] if rva - s['va'] < s['rsz'] else None
    return None


def relocs(d, base, dirs, secs):
    rva, size = dirs[5] if len(dirs) > 5 else (0, 0)
    out = {}                                   # site VA -> target VA
    off = rva_to_off(secs, rva) if size else None
    if off is None:                            # no relocations (stripped: /FIXED exe)
        return out
    end = off + size
    while off < end:
        page, bsz = struct.unpack_from('<II', d, off)
        if bsz < 8:
            break
        for i in range((bsz - 8) // 2):
            e, = struct.unpack_from('<H', d, off + 8 + 2 * i)
            if e >> 12 == 3:
                site = page + (e & 0xfff)
                so = rva_to_off(secs, site)
                if so is not None:
                    out[base + site] = struct.unpack_from('<I', d, so)[0]
        off += bsz
    return out


def exports(d, base, dirs, secs):
    rva, size = dirs[0]
    if not size:
        return set()
    o = rva_to_off(secs, rva)
    nfun, = struct.unpack_from('<I', d, o + 20)
    afun, = struct.unpack_from('<I', d, o + 28)
    ao = rva_to_off(secs, afun)
    out = set()
    for i in range(nfun):
        r, = struct.unpack_from('<I', d, ao + 4 * i)
        if r and not (rva <= r < rva + size):   # skip forwarders
            out.add(base + r)
    return out


def pe_metadata(d, base, dirs, secs):
    """Sorted VA ranges [lo, hi) of bytes the loader (or a debugger) reads as PE structures: every data directory
    (except the certificate table, which is a file offset) plus what the import, export and debug directories point
    to. Linkers place these in .text when .rdata/.idata are merged into it (/MERGE)."""
    out = []
    def add(rva, n):
        if rva and n > 0 and rva_to_off(secs, rva) is not None:
            out.append((base + rva, base + rva + n))
    def u32(rva):
        o = rva_to_off(secs, rva)
        return struct.unpack_from('<I', d, o)[0] if o is not None and o + 4 <= len(d) else None
    def cstr(rva):                             # length of the C string at rva including its NUL, 0 if none
        o = rva_to_off(secs, rva)
        e = d.find(b'\0', o, o + 4096) if o is not None else -1
        return e - o + 1 if e >= 0 else 0
    for i, (rva, size) in enumerate(dirs):
        if i != 4:
            add(rva, size)
    irva, isize = dirs[1] if len(dirs) > 1 else (0, 0)
    for k in range(4096 if isize else 0):     # import descriptors, up to the all-zero one
        o = rva_to_off(secs, irva + 20 * k)
        if o is None or o + 20 > len(d):
            break
        oft, _, _, name, ft = struct.unpack_from('<IIIII', d, o)
        add(irva + 20 * k, 20)
        if not (oft or name or ft):
            break
        add(name, cstr(name))
        for arr in (oft, ft):
            for j in range(65536 if arr else 0):
                v = u32(arr + 4 * j)
                if v is None:
                    break
                add(arr + 4 * j, 4)
                if not v:
                    break
                if arr == (oft or ft) and not v & 0x80000000:     # hint/name entry (word hint, name, NUL)
                    add(v, 2 + cstr(v + 2))
    erva, esize = dirs[0] if dirs else (0, 0)
    o = rva_to_off(secs, erva) if esize else None
    if o is not None and o + 40 <= len(d):
        name, _, nfun, nnames, afun, anames, aords = struct.unpack_from('<IIIIIII', d, o + 12)
        add(name, cstr(name)); add(afun, 4 * nfun); add(anames, 4 * nnames); add(aords, 2 * nnames)
        for j in range(nnames):
            v = u32(anames + 4 * j)
            if v:
                add(v, cstr(v))
    drva, dsize = dirs[6] if len(dirs) > 6 else (0, 0)
    for k in range(dsize // 28):              # debug directory entries -> their data (CodeView NB10/RSDS ...)
        o = rva_to_off(secs, drva + 28 * k)
        if o is not None and o + 28 <= len(d):
            size, rva = struct.unpack_from('<II', d, o + 16)
            add(rva, size)
    return sorted(out)


def load_listing(ddir):
    """instructions.tsv -> (calls, jumps, instr_func) ; functions.tsv -> sorted body ranges [(lo, hi, entry)]."""
    calls, jumps, ins_fn = set(), set(), {}
    with open(os.path.join(ddir, 'instructions.tsv')) as f:
        next(f)
        for line in f:
            a, ln, fn, flow, targets = line.split('\t', 5)[:5]
            ins_fn[int(a, 16)] = fn
            if targets and flow in ('call', 'jump', 'cjump'):
                for t in targets.split(','):
                    (calls if flow == 'call' else jumps).add(int(t, 16))
    ranges = []
    with open(os.path.join(ddir, 'functions.tsv')) as f:
        next(f)
        for line in f:
            entry, name, body = line.rstrip('\n').split('\t')
            for r in body.split(','):
                if r:
                    lo, hi = r.split('-')
                    ranges.append((int(lo, 16), int(hi, 16), int(entry, 16)))
    ranges.sort()
    return calls, jumps, ins_fn, ranges


PAD = {0xcc, 0x90}


def pad_len(b):
    """Length of MSVC alignment filler at the start of b (same forms as padLen() in scripts/ghidra/*.java), else 0."""
    b = bytes(b[:9]) + b'\xff' * (9 - len(b[:9]))
    if b[0] in (0xcc, 0x90):
        return 1
    if b[0] == 0x8b and b[1] in (0xff, 0xc0, 0xc9, 0xd2, 0xdb, 0xf6):
        return 2
    if b[0] == 0x66 and b[1] == 0x90:
        return 2
    if b[0] == 0x8d:
        mod, reg, rm = b[1] >> 6, (b[1] >> 3) & 7, b[1] & 7
        if reg == rm and rm != 4 and mod == 1 and b[2] == 0:
            return 3
        if reg == rm and rm != 4 and mod == 2 and b[2:6] == b'\0' * 4:
            return 6
        if b[1:4] == b'\x64\x24\x00':
            return 4
        if b[1:3] == b'\xa4\x24' and b[3:7] == b'\0' * 4:
            return 7
    o = 1 if b[0] == 0x66 else 0
    if b[o] == 0x0f and b[o + 1] == 0x1f:
        m = b[o + 2]
        if m == 0:
            return o + 3
        if m == 0x40 and b[o + 3] == 0:
            return o + 4
        if m == 0x44 and b[o + 3:o + 5] == b'\0\0':
            return o + 5
        if m == 0x80 and b[o + 3:o + 7] == b'\0' * 4:
            return o + 7
        if m == 0x84 and b[o + 3:o + 8] == b'\0' * 5:
            return o + 8
    return 0
MIN_REGION_NONFILL = 32768                     # unreferenced_region: non-filler bytes without any relocation


def entropy(b):
    """Shannon entropy of b in bits per byte (byte counts summed in ascending order)."""
    n = len(b)
    hist = [0] * 256
    for c in b:
        hist[c] += 1
    return -sum(c / n * math.log2(c / n) for c in sorted(hist) if c) if n else 0.0


PROLOGUES = [b'\x55\x8b\xec', b'\x8b\xff\x55', b'\x83\xec', b'\x81\xec', b'\x6a', b'\x68', b'\x53', b'\x56',
             b'\x57', b'\x55', b'\x8b\x44\x24', b'\x8b\x4c\x24', b'\x8b\x54\x24', b'\xa1', b'\x8b\x0d',
             b'\x33\xc0', b'\xb8', b'\xe9', b'\xff\x25', b'\x8b\xc1', b'\x51', b'\xc3', b'\xc2', b'\x8b\x01']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary')
    ap.add_argument('decompiled_dir')
    a = ap.parse_args()
    import bisect
    from collections import Counter
    d = open(a.binary, 'rb').read()
    base, entry, dirs, secs = pe_parse(d)
    text = [s for s in secs if s['exec']]
    def in_text(va):
        return any(base + s['va'] <= va < base + s['va'] + s['vsz'] for s in text)
    def byte_at(va):
        o = rva_to_off(secs, va - base)
        return d[o] if o is not None else None
    def bytes_at(va, n):                       # clipped to the file data of va's section
        o = rva_to_off(secs, va - base)
        if o is None:
            return b''
        s_ = next(s for s in secs if s['va'] <= va - base < s['va'] + max(s['vsz'], s['rsz']))
        return d[o:min(o + n, s_['rptr'] + s_['rsz'])]
    rel = relocs(d, base, dirs, secs)
    has_rel = bool(rel)
    reloc_sites = set(rel)
    ptr_targets = {t for t in rel.values() if in_text(t)}
    exp = exports(d, base, dirs, secs) | {base + entry}
    calls, jumps, ins_fn, ranges = load_listing(a.decompiled_dir)
    calls = {t for t in calls if in_text(t)}
    meta = []                                  # PE structures, merged into disjoint [lo, hi]
    for lo, hi in pe_metadata(d, base, dirs, secs):
        if meta and lo <= meta[-1][1]:
            meta[-1][1] = max(meta[-1][1], hi)
        else:
            meta.append([lo, hi])
    mstarts = [m[0] for m in meta]
    def in_meta(va):
        i = bisect.bisect_right(mstarts, va) - 1
        return i >= 0 and va < meta[i][1]
    # addresses in .text that instructions use as operands (op_refs: any operand, only needed without
    # relocations) and as memory operands, i.e. read or written as data (mem_refs: `movzx eax, byte [ecx + T]`)
    ins_lens, op_refs, mem_refs, fall_into = {}, set(), set(), set()
    with open(os.path.join(a.decompiled_dir, 'instructions.tsv')) as f:
        next(f)
        for line in f:
            x, ln = line.split('\t', 2)[:2]
            ins_lens[int(x, 16)] = int(ln)
            fields = line.rstrip('\n').split('\t')
            txt = fields[-1]
            # continues at the next byte (Ghidra gives a tail-call JMP the flow "call": it does not)
            if len(fields) > 3 and fields[3] in ('fall', 'call', 'cjump', 'ccall') and not txt.startswith('JMP'):
                fall_into.add(int(x, 16) + int(ln))
            for h in re.findall(r'\[[^\]]*0x([0-9a-f]+)\]', txt):
                if in_text(int(h, 16)):
                    mem_refs.add(int(h, 16))
            if not has_rel:
                for h in re.findall(r'0x([0-9a-f]+)', txt):
                    if in_text(int(h, 16)):
                        op_refs.add(int(h, 16))
    data_refs = set(rel.values()) if has_rel else op_refs
    if has_rel:                                # with relocations a real address operand is relocated
        mem_refs &= data_refs
    site_list = sorted(rel)
    data_ptr_targets = set(rel.values()) - {t for x, t in rel.items() if in_text(x)}   # pointed to from data only
    def u32_at(va):
        b = bytes_at(va, 4)
        return struct.unpack('<I', b)[0] if len(b) == 4 else None
    def holds_code(va):
        v = u32_at(va)
        return v is not None and ins_fn.get(v, '-') != '-'
    def code_ptr(va, in_table):
        """A code pointer at va: a relocation site pointing into code; without relocations, a dword holding an
        instruction start inside a function that continues a table, or starts a run of such dwords of which one
        is at an address an instruction uses (`jmp [ecx*4 + T]`; T may be inside the table, as in memcpy's)."""
        if has_rel:
            return va in reloc_sites and in_text(rel[va])
        if in_table:
            return holds_code(va)
        k = va
        while holds_code(k):
            if k in op_refs:
                return True
            k += 4
        return False
    def str_len(va):
        """Length (with NUL) of a non-empty printable ASCII C string at va, else 0."""
        b = bytes_at(va, 4096)
        k = 0
        while k < len(b) and (0x20 <= b[k] < 0x7f or b[k] in (9, 10, 13)):
            k += 1
        return k + 1 if k and k < len(b) and b[k] == 0 else 0
    def record_table(p, end):
        """Length of an array of fixed-size records at p (a relocation target pointed to from data only) whose
        pointer slot - one dword per record at a fixed offset - holds a relocated pointer to non-executable data or
        NULL in every record, with >= 3 such pointers (DirectInput c_dfDI* DIOBJECTDATAFORMAT tables); else 0."""
        if p not in data_ptr_targets:
            return 0
        sites = site_list[bisect.bisect_left(site_list, p):bisect.bisect_left(site_list, end)]
        if len(sites) < 3 or any(in_text(rel[x]) for x in sites):
            return 0
        st = 0
        for x, y in zip(sites, sites[1:]):
            st = math.gcd(st, y - x)
        c = (sites[0] - p) % st if st else 0
        if st < 4 or st % 4 or c % 4:
            return 0
        k = 0
        while p + (k + 1) * st <= end and (p + c + k * st in reloc_sites or u32_at(p + c + k * st) == 0):
            k += 1
        if p + k * st <= sites[-1] or \
                bisect.bisect_left(branch_targets, p) != bisect.bisect_left(branch_targets, p + k * st):
            return 0
        return k * st
    # relocation-free intervals of .text (between relocation sites/targets and exports) with >= MIN_REGION_NONFILL
    # non-filler bytes: compiled code cannot run that long without an absolute address
    regions = []
    for s in (text if has_rel else []):
        lo, hi = base + s['va'], base + s['va'] + max(s['vsz'], s['rsz'])     # as Ghidra's memory block
        anchors = sorted({x + k for x in rel if lo <= x < hi for k in range(4)} |
                         {t for t in rel.values() if lo <= t < hi} | {e for e in exp if lo <= e < hi})
        prev = lo
        for x in anchors + [hi]:
            if x - prev >= MIN_REGION_NONFILL:
                raw = bytes_at(prev, x - prev)
                nonfill = sum(1 for c in raw if c not in (0, 0xcc, 0x90))
                if nonfill >= MIN_REGION_NONFILL:
                    regions.append(dict(start=hex(prev), len=x - prev, nonfill=nonfill,
                                        entropy='%.2f' % entropy(raw)))
            prev = max(prev, x + 1)
    rbounds = [(int(r['start'], 16), int(r['start'], 16) + r['len']) for r in regions]
    branch_targets = sorted(calls | jumps)
    branch_set = set(branch_targets)
    entered = sorted(set(branch_targets) | fall_into)       # where execution can arrive: branch or fall-through
    rstarts = [r[0] for r in ranges]
    def containing(va):                        # Ghidra function bodies never overlap
        i = bisect.bisect_right(rstarts, va) - 1
        return ranges[i][2] if i >= 0 and va <= ranges[i][1] else None
    idx = json.load(open(os.path.join(a.decompiled_dir, 'index.json')))['functions']
    funcs = [f for f in idx if not f['name'].startswith(('thunk_', 'EXTERNAL')) and in_text(int(f['address'], 16))]
    fset = {int(f['address'], 16) for f in idx}
    cls = {'called': 0, 'pointer': 0, 'export_or_entry': 0, 'jump_only': 0, 'unreferenced': 0}
    unref = []
    for f in funcs:
        va = int(f['address'], 16)
        if va in calls:
            k = 'called'
        elif va in ptr_targets:
            k = 'pointer'
        elif va in exp:
            k = 'export_or_entry'
        elif va in jumps:
            k = 'jump_only'
        else:
            k = 'unreferenced'
            prev = byte_at(va - 1)
            head = bytes_at(va, 4)
            unref.append(dict(address=hex(va), size=f['size'], starts_with_filler=pad_len(head + bytes_at(va + 4, 5)) > 0,
                              after_padding=prev in PAD or prev in (0xc3, 0xc2) or prev is None,
                              prologue_like=any(head.startswith(p) for p in PROLOGUES),
                              head=head.hex()))
        cls[k] += 1
    calls_not_start = sorted(hex(t) for t in calls if t not in fset)
    # gaps
    gaps, records = [], []
    for line in open(os.path.join(a.decompiled_dir, 'coverage_gaps.txt')):
        m = re.match(r'0x([0-9a-f]+) len=(\d+)', line)
        if not m:
            continue
        g, n = int(m.group(1), 16), int(m.group(2))
        raw = bytes_at(g, n)
        region = any(lo <= g and g + n <= hi for lo, hi in rbounds) and \
            bisect.bisect_left(entered, g) == bisect.bisect_left(entered, g + n)
        # walk: filler | relocated code pointers (jump table) | small bytes after a table (switch index) |
        # PE structures | referenced strings
        parts, i, seen_table, entries, last = [], 0, False, 0, None
        while i < n:
            # a relocated pointer wins over filler: table entries can start with 0x90/0xCC/0x8B
            if i + 4 <= n and code_ptr(g + i, last == 'jump_table'):
                entries = entries + 1 if last == 'jump_table' else 1
                parts.append(('jump_table', 4)); i += 4; seen_table = True; last = 'jump_table'; continue
            prev, last = last, None
            if i >= len(raw):                  # past the section's file data: zero-filled by the loader
                parts.append(('uninitialized', n - i)); break
            if in_meta(g + i):
                parts.append(('pe_metadata', 1)); i += 1; last = 'pe_metadata'; continue
            sl = str_len(g + i) if g + i in data_refs else 0
            if sl and i + sl <= n:
                parts.append(('string', sl)); i += sl; last = 'string'; continue
            pl = pad_len(raw[i:i + 9])
            if pl and i + pl <= n and not any(g + i + k in reloc_sites for k in range(1, pl)):
                parts.append(('filler', pl)); i += pl; continue
            if seen_table and raw[i] < max(entries, 1):    # switch index: selects one of the table's entries
                parts.append(('index_bytes', 1)); i += 1; continue
            rl = record_table(g + i, g + min(n, len(raw)))
            if rl:
                parts.append(('record_table', rl)); records.append((g + i, g + i + rl)); i += rl; continue
            if g + i in mem_refs and g + i not in branch_set:   # read as data: up to the next reference
                k = i + 1
                while k < min(n, len(raw)) and not (g + k in mem_refs or g + k in data_refs or g + k in branch_set
                                                    or in_meta(g + k)):
                    k += 1
                parts.append(('data_read', k - i)); i = k; last = 'data_read'; continue
            if prev in ('pe_metadata', 'string', 'data_read') and raw[i] == 0:   # zero padding after data
                parts.append((prev, 1)); i += 1; last = prev; continue
            parts.append(('unreferenced_region' if region else 'other', 1)); i += 1
        tot = {}
        for k, ln in parts:
            tot[k] = tot.get(k, 0) + ln
        other = tot.get('other', 0)
        kind = '+'.join(k for k in ('jump_table', 'index_bytes', 'pe_metadata', 'string', 'data_read',
                                    'record_table', 'unreferenced_region', 'uninitialized')
                        if k in tot) or 'filler_only'
        if other:
            kind = 'UNEXPLAINED(' + kind + ')'
        nonpad = n - tot.get('filler', 0)
        detail = ' '.join(f'{k}={v}' for k, v in sorted(tot.items()))
        gaps.append(dict(address=hex(g), len=n, nonpad=nonpad, kind=kind, detail=detail, hex=raw[:48].hex()))
        if region:
            gaps[-1]['entropy'] = '%.2f' % entropy(raw)
    gap_unexplained = sum(1 for g in gaps if g['kind'].startswith('UNEXPLAINED'))
    # every relocated pointer into code
    pk = Counter(); ptr_unexplained = []
    for t in sorted(ptr_targets):
        if t in fset:
            pk['function_start'] += 1
        elif containing(t) is not None:
            pk['inside_function'] += 1
        elif t in rel and in_text(rel[t]):
            pk['jump_table_start'] += 1
        elif (t - 4) in rel and in_text(rel[t - 4]):
            pk['index_table_start'] += 1
        elif in_meta(t):
            pk['pe_metadata'] += 1
        elif str_len(t):
            pk['string'] += 1
        elif any(lo <= t < hi for lo, hi in records):
            pk['record_table'] += 1
        else:
            pk['UNEXPLAINED'] += 1
            ptr_unexplained.append(dict(target=hex(t), referenced_from=[hex(x) for x, v in rel.items() if v == t][:4],
                                        bytes=bytes_at(t, 16).hex()))
    # jump tables Ghidra decoded as instructions: runs of >= 2 consecutive relocated code pointers that
    # overlap disassembled instructions (decompile of the containing function is wrong there)
    tsites = sorted(x for x, v in rel.items() if in_text(v) and in_text(x))
    runs, i = [], 0
    while i < len(tsites):
        j = i
        while j + 1 < len(tsites) and tsites[j + 1] == tsites[j] + 4:
            j += 1
        if j > i:
            runs.append((tsites[i], tsites[j] + 4))
        i = j + 1
    istarts = sorted(ins_lens)
    table_as_code = []
    for lo, hi in runs:
        k = max(bisect.bisect_right(istarts, lo) - 1, 0)
        hit = []
        while k < len(istarts) and istarts[k] < hi:
            if istarts[k] + ins_lens[istarts[k]] > lo:
                hit.append(istarts[k])
            k += 1
        if hit:
            table_as_code.append(dict(table=hex(lo), entries=(hi - lo) // 4, instructions=len(hit),
                                      function=hex(containing(hit[0]) or 0)))
    summ = dict(relocations=len(rel), functions=len(funcs), reach=cls,
                unreferenced_starting_with_filler=sum(u['starts_with_filler'] for u in unref),
                unreferenced_prologue_like=sum(u['prologue_like'] for u in unref),
                direct_call_targets=len(calls), direct_call_targets_not_function_start=len(calls_not_start),
                relocated_pointers_into_text=len(ptr_targets), pointers=dict(pk),
                unreferenced_regions=len(regions), gaps=len(gaps), gap_kinds=dict(Counter(g['kind'] for g in gaps)),
                gap_nonpad_bytes_by_kind={k: sum(g['nonpad'] for g in gaps if g['kind'] == k)
                                          for k in set(g['kind'] for g in gaps)})
    summ['jump_tables_decoded_as_code'] = dict(tables=len(table_as_code),
                                               instructions=sum(t['instructions'] for t in table_as_code))
    fails = dict(direct_call_targets_not_function_start=len(calls_not_start),
                 pointers_unexplained=pk.get('UNEXPLAINED', 0), gaps_unexplained=gap_unexplained,
                 unreferenced_starting_with_filler=summ['unreferenced_starting_with_filler'])
    summ['must_be_zero'] = fails
    json.dump(dict(summary=summ, unreferenced=unref, calls_not_function_start=calls_not_start,
                   jump_tables_decoded_as_code=table_as_code,
                   pointers_unexplained=ptr_unexplained, unreferenced_regions=regions, gaps=gaps),
              open(os.path.join(a.decompiled_dir, 'coverage_check.json'), 'w'), indent=1)
    print(json.dumps(summ, indent=1))
    print('PASS' if not any(fails.values()) else 'FAIL: ' + ', '.join(k for k, v in fails.items() if v))
    sys.exit(0 if not any(fails.values()) else 1)


if __name__ == '__main__':
    main()
