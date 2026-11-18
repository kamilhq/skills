#!/usr/bin/env python3
"""Phase 5b: rebuild a PE32 (exe/dll) byte-identically from assembly text. Python stdlib + Ghidra only.

  reassemble.py split <binary> <decompiled_dir> <out_dir> [--names names_apply.json]
      Decode: <decompiled_dir> is run_recovery.sh output (instructions.tsv, functions.tsv). Writes
        out_dir/text/NNNNN_<addr>_<name>.asm   .text as assembly, one file per function start, address order
        out_dir/layout.json                    PE layout: sections, image base, label/fixup tables, stats
        out_dir/raw/headers.bin, raw/<sec>.bin, raw/overlay.bin   non-code bytes (pointers into .text zeroed)
      Every instruction's encoding is checked with Ghidra's assembler (scripts/ghidra/assemble.sh, choose
      mode): the rule's choice needs nothing, another encoding gets `{enc:N}`, none -> `db` (pinned).
  reassemble.py build <out_dir> <binary_out> [--cache <file>]
      Encode from out_dir only: assemble every line (Ghidra for ordinary instructions, Python for direct
      relative branches), lay out .text, resolve labels, write the data sections with code pointers filled
      from labels, regenerate .reloc, write the PE. --cache reuses assembled bytes keyed by instruction text
      (encodings of x86-32 non-branch instructions do not depend on their address); omit it for the gate.
  reassemble.py verify <binary> <out_dir> [--cache <file>]      build to a temp file and compare SHA-256.
  reassemble.py editcheck <binary> <out_dir> <decompiled_dir> [--cache <file>]
      Editability proof (level 3): copy the text, insert a NOP after the first instruction of the first
      function that has two, rebuild, and check against the original that every relocated pointer, every
      .reloc entry and every direct branch moved consistently (targets after the insertion point +1).

Assembly syntax (Ghidra's own instruction syntax; one item per line, `;` starts a comment):
    label:                      code label (function names, L_<hex> branch/pointer targets)
    MOV EAX,dword ptr [g_x]     instruction; labels may replace any numeric operand
    JZ L_401e60                 direct branch: short/near chosen by distance; `{enc:1}` forces the long form
    ADD EAX,ECX {enc:1}         use candidate 1 of Ghidra's encodings (rule order) instead of 0
    db 8d,64,24,00              raw bytes (filler, data in .text, pinned instructions)
    dd L_402a30                 32-bit absolute address of a label (jump tables) - always relocated
Labels named D_<hex> are fixed absolute addresses (data outside .text). `label-0x<n>` is allowed wherever a
label is (pointers into the middle of an instruction, e.g. a jump table whose unused entry 0 overlaps code).
Limits: sections keep their addresses; .text may change size only within its raw size (a bigger .text
would need moving later sections). Exit 0 ok, 1 mismatch/assembly error, 2 bad arguments.
"""
import hashlib, json, os, re, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ASM_SH = os.path.join(HERE, 'ghidra', 'assemble.sh')
HEX = re.compile(r'(?<![\w])0x[0-9a-fA-F]+')
IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
JCC = {'JO': 0, 'JNO': 1, 'JC': 2, 'JB': 2, 'JNAE': 2, 'JNC': 3, 'JAE': 3, 'JNB': 3, 'JZ': 4, 'JE': 4, 'JNZ': 5,
       'JNE': 5, 'JBE': 6, 'JNA': 6, 'JA': 7, 'JNBE': 7, 'JS': 8, 'JNS': 9, 'JP': 10, 'JPE': 10, 'JNP': 11, 'JPO': 11,
       'JL': 12, 'JNGE': 12, 'JGE': 13, 'JNL': 13, 'JLE': 14, 'JNG': 14, 'JG': 15, 'JNLE': 15}
REL8_ONLY = {'LOOPNE': 0xe0, 'LOOPNZ': 0xe0, 'LOOPE': 0xe1, 'LOOPZ': 0xe1, 'LOOP': 0xe2, 'JECXZ': 0xe3}


# ----------------------------------------------------------------------------------------------- PE helpers
def pe_parse(d):
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    if d[pe:pe + 4] != b'PE\0\0' or struct.unpack_from('<H', d, pe + 24)[0] != 0x10b:
        raise ValueError('not a PE32 file')
    nsec, = struct.unpack_from('<H', d, pe + 6)
    optsz, = struct.unpack_from('<H', d, pe + 20)
    opt = pe + 24
    base, = struct.unpack_from('<I', d, opt + 28)
    ndirs, = struct.unpack_from('<I', d, opt + 92)
    dirs = [struct.unpack_from('<II', d, opt + 96 + 8 * i) for i in range(ndirs)]
    secs = []
    for i in range(nsec):
        o = opt + optsz + 40 * i
        vsz, va, rsz, rptr = struct.unpack_from('<IIII', d, o + 8)
        ch, = struct.unpack_from('<I', d, o + 36)
        secs.append(dict(name=d[o:o + 8].rstrip(b'\0').decode('latin-1'), va=va, vsize=vsz, raw_ptr=rptr,
                         raw_size=rsz, exec=bool(ch & 0x20000000)))
    return base, dirs, secs


def relocs_of(d, base, dirs, secs):
    rva, size = dirs[5] if len(dirs) > 5 else (0, 0)
    out = {}
    if not size:
        return out, None
    sec = next(s for s in secs if s['va'] <= rva < s['va'] + max(s['vsize'], s['raw_size']))
    off = sec['raw_ptr'] + rva - sec['va']
    end = off + size
    while off < end:
        page, bsz = struct.unpack_from('<II', d, off)
        if bsz < 8:
            break
        for i in range((bsz - 8) // 2):
            e, = struct.unpack_from('<H', d, off + 8 + 2 * i)
            if e >> 12 == 3:
                site = base + page + (e & 0xfff)
                s = next(x for x in secs if x['va'] <= site - base < x['va'] + x['raw_size'])
                out[site] = struct.unpack_from('<I', d, s['raw_ptr'] + site - base - s['va'])[0]
            elif e >> 12 != 0:
                raise ValueError(f'relocation type {e >> 12} not supported')
        off += bsz
    return out, sec['name']


def make_reloc(sites_rva):
    """IMAGE_BASE_RELOCATION blocks: pages ascending, offsets ascending, one ABSOLUTE pad when odd."""
    pages = {}
    for r in sorted(set(sites_rva)):
        pages.setdefault(r & ~0xfff, []).append(r & 0xfff)
    out = bytearray()
    for p in sorted(pages):
        ents = [0x3000 | o for o in pages[p]]
        if len(ents) & 1:
            ents.append(0)
        out += struct.pack('<II', p, 8 + 2 * len(ents)) + b''.join(struct.pack('<H', e) for e in ents)
    return bytes(out)


# ------------------------------------------------------------------------------------------ Ghidra assembler
def ghidra_assemble(items, choose=False, tmp=None):
    """items: list of (id, text, enc[, orig_hex]). Returns {id: (hex_or_index, ncand)} or {id: ('ERR', msg)}."""
    out = {}
    if not items:
        return out
    d = tempfile.mkdtemp(dir=tmp)
    inp, res = os.path.join(d, 'in.tsv'), os.path.join(d, 'out.tsv')
    with open(inp, 'w') as f:
        for it in items:
            f.write('\t'.join(str(x) for x in it) + '\n')
    p = subprocess.run(['sh', ASM_SH, inp, res] + (['choose'] if choose else []), capture_output=True, text=True)
    if p.returncode != 0 or not os.path.exists(res):
        raise RuntimeError('assemble.sh failed:\n' + p.stdout[-2000:] + p.stderr[-2000:])
    for line in open(res):
        f = line.rstrip('\n').split('\t')
        out[f[0]] = (f[1], f[2])
    return out


# ------------------------------------------------------------------------------------- branch size selection
def br_len(mn, long_):
    if mn in REL8_ONLY:
        return 2
    if mn == 'CALL':
        return 5
    if not long_:
        return 2
    return 5 if mn == 'JMP' else 6


def relax(seq, t0, fixed_value):
    """MSVC-style branch sizing, shared by split (prediction) and build. seq items: ('label', name),
    ('fix', size), ('br', mn, target, force) with force 0 = choose, 1 = long, 2 = short. Start with every
    choosable branch long, then repeatedly shrink each one whose rel8 displacement fits with the current
    layout, until nothing changes. Returns (addresses per item, values per label, long flag per item)."""
    long_ = [it[0] == 'br' and (it[3] != 2) and it[1] not in REL8_ONLY for it in seq]
    while True:
        addr, addrs, values = t0, [], {}
        for i, it in enumerate(seq):
            addrs.append(addr)
            if it[0] == 'label':
                values[it[1]] = addr
            elif it[0] == 'fix':
                addr += it[1]
            else:
                addr += br_len(it[1], long_[i])
        changed = False
        for i, it in enumerate(seq):
            if it[0] == 'br' and long_[i] and it[3] == 0 and it[1] != 'CALL':
                tgt = values.get(it[2], fixed_value(it[2]))
                if tgt is not None and -128 <= tgt - (addrs[i] + 2) <= 127:
                    long_[i] = False
                    changed = True
        if not changed:
            return addrs, values, long_, addr


def fixed_label_value(name):
    m = re.match(r'^(D|A)_([0-9a-f]+)$', name)
    return int(m.group(2), 16) if m else None


# --------------------------------------------------------------------------------------------- split (decode)
def sanitize(name, addr, used):
    n = re.sub(r'[^A-Za-z0-9_]', '_', name.replace('::', '__'))
    if not n or not re.match(r'[A-Za-z_]', n):
        n = 'F_' + n
    if n in used or re.match(r'^(D|A|L)_[0-9a-f]+$', n):
        n = f'{n}_{addr:x}'
    used.add(n)
    return n


def branch_kind(b):
    """'rel8'/'rel32'/'jcc8'/'jcc32'/'call'/'rel8only' for a direct relative branch without prefixes."""
    if b[0] == 0xe8:
        return 'call'
    if b[0] == 0xe9:
        return 'rel32'
    if b[0] == 0xeb:
        return 'rel8'
    if 0x70 <= b[0] <= 0x7f:
        return 'jcc8'
    if b[0] == 0x0f and len(b) > 1 and 0x80 <= b[1] <= 0x8f:
        return 'jcc32'
    if 0xe0 <= b[0] <= 0xe3:
        return 'rel8only'
    return None


def split(binary, ddir, out, names_file=None):
    d = open(binary, 'rb').read()
    base, dirs, secs = pe_parse(d)
    rel, reloc_sec = relocs_of(d, base, dirs, secs)
    texts = [s for s in secs if s['exec']]
    if len(texts) != 1:
        raise ValueError('expected exactly one executable section')
    T = texts[0]
    t0, t_raw_end = base + T['va'], base + T['va'] + T['raw_size']
    in_text = lambda v: t0 <= v < t_raw_end
    # emit up to the section's virtual size; the zero file-alignment padding after it is added by build
    t1 = t0 + min(T['vsize'], T['raw_size']) if T['vsize'] else t_raw_end
    while t1 < t_raw_end and any(d[T['raw_ptr'] + t1 - t0:T['raw_ptr'] + T['raw_size']]):
        t1 = t_raw_end
    ins = {}
    with open(os.path.join(ddir, 'instructions.tsv')) as f:
        next(f)
        for line in f:
            a, ln, fn, flow, targets, text = line.rstrip('\n').split('\t', 5)
            a = int(a, 16)
            if in_text(a):
                ins[a] = (int(ln), flow, targets, text)
    # Instructions that overlap a relocated dword they do not fully contain are data Ghidra disassembled
    # (e.g. an unresolved switch jump table inside a function body): treat them as bytes.
    straddle = set()
    for site in rel:
        for k in range(-14, 4):
            a = site + k
            if a in ins and a < site + 4 and site < a + ins[a][0] and not (a <= site and site + 4 <= a + ins[a][0]):
                straddle.add(a)
    # jump tables Ghidra decoded as instructions: runs of >= 2 consecutive relocated pointers into .text,
    # and instructions that contain a pointer target strictly inside them
    tsites = sorted(x for x, v in rel.items() if t0 <= v < t_raw_end and t0 <= x < t_raw_end)
    runs, i = [], 0
    while i < len(tsites):
        j = i
        while j + 1 < len(tsites) and tsites[j + 1] == tsites[j] + 4:
            j += 1
        if j > i:
            runs.append((tsites[i], tsites[j] + 4))
        i = j + 1
    ins_starts = sorted(ins)
    import bisect as _b
    for lo, hi in runs:
        k = _b.bisect_right(ins_starts, lo) - 1
        k = max(k, 0)
        while k < len(ins_starts) and ins_starts[k] < hi:
            a = ins_starts[k]
            if a + ins[a][0] > lo:
                straddle.add(a)
            k += 1
    for a in straddle:
        ins.pop(a, None)
    fnames = {}
    with open(os.path.join(ddir, 'functions.tsv')) as f:
        next(f)
        for line in f:
            e, n, _ = line.rstrip('\n').split('\t')
            if in_text(int(e, 16)):
                fnames[int(e, 16)] = n.split('::')[-1] if '::' in n and n.startswith(('KERNEL', 'USER')) else n
    if names_file:
        nm = json.load(open(names_file))
        items = nm.items() if isinstance(nm, dict) else ((x['address'], x['name']) for x in nm)
        for a, n in items:
            if int(a, 16) in fnames and n:
                fnames[int(a, 16)] = n
    # boundaries: instruction starts and every byte position of non-instruction runs
    starts = set(ins)
    def raw_at(va, n):
        o = T['raw_ptr'] + va - t0
        return d[o:o + n]
    stats = {}
    # labels
    used, labels = set(), {}
    for a in sorted(fnames):
        labels[a] = sanitize(fnames[a], a, used)
    code_targets = set()
    for a, (ln, flow, targets, text) in ins.items():
        if flow in ('call', 'jump', 'cjump') and targets:
            for t in targets.split(','):
                if in_text(int(t, 16)):
                    code_targets.add(int(t, 16))
    for v in rel.values():
        if in_text(v):
            code_targets.add(v)
    # a label must sit at a line boundary: an instruction start or anywhere in a non-instruction run
    covered = {}
    for a, (ln, *_r) in ins.items():
        for k in range(1, ln):
            covered[a + k] = a
    def label_for(v):
        if not in_text(v):
            return f'D_{v:x}'
        if v in covered:
            # points into the middle of an instruction (e.g. a jump table whose unused entry 0 overlaps the
            # instruction before it): express it relative to the next instruction boundary so it still moves
            a = covered[v]
            b = a + ins[a][0]
            if b not in labels:
                labels[b] = f'L_{b:x}'
            stats['label_offset_operands'] = stats.get('label_offset_operands', 0) + 1
            return f'{labels[b]}-0x{b - v:x}'
        if v not in labels:
            labels[v] = f'L_{v:x}'
        return labels[v]
    for v in sorted(code_targets):
        label_for(v)
    stats.update(instructions_as_data=len(straddle), instructions=0, enc_pinned=0, db_pinned_instructions=0, db_pinned_bytes=0, branches=0,
                 relabelled_operands=0, data_bytes_in_text=0)
    # walk .text
    lines = []          # (addr, kind, payload)  kind: ins / br / db / dd / label
    pending_choose = []
    a = t0
    order = sorted(ins)
    import bisect
    emitted = set()
    def put_label(at):
        if at in labels and at not in emitted:
            emitted.add(at)
            lines.append((at, 'label', labels[at]))
    while a < t1:
        put_label(a)
        if a in ins and a + ins[a][0] <= t1:
            ln, flow, targets, text = ins[a]
            b = raw_at(a, ln)
            stats['instructions'] += 1
            sites = [s for s in range(a, a + ln) if s in rel]
            bk = branch_kind(b)
            if bk and flow in ('call', 'jump', 'cjump') and targets and not sites:
                t = int(targets.split(',')[0], 16)
                if in_text(t) and t not in covered:
                    mn = text.split()[0].upper()
                    # enc decided after the walk by running the same branch sizing as build (relax)
                    lines.append((a, 'br', [mn, label_for(t), 0, b.hex(), bk in ('rel32', 'jcc32', 'call')]))
                    stats['branches'] += 1
                    a += ln
                    continue
            new = text
            ok = True
            for s in sites:
                v = rel[s]
                toks = [m for m in HEX.finditer(new) if int(m.group(0), 16) == v]
                if not toks:
                    ok = False
                    break
                lab = label_for(v)
                new = HEX.sub(lambda m: lab if int(m.group(0), 16) == v else m.group(0), new)
                stats['relabelled_operands'] += 1
            if ok and not bk:
                lines.append((a, 'ins', [new, text, b.hex(), 0]))
                pending_choose.append(len(lines) - 1)
            else:
                lines.append((a, 'pin', (text, b.hex(), [(s - a, label_for(rel[s])) for s in sites])))
            a += ln
            continue
        # non-instruction run up to the next instruction start or section end
        i = bisect.bisect_right(order, a)
        nxt = order[i] if i < len(order) else t1
        nxt = min(nxt, t1)
        if nxt <= a:
            nxt = a + 1
        buf = []
        p = a
        while p < nxt:
            if p in labels and p not in emitted:
                if buf:
                    lines.append((a, 'db', bytes(buf)))
                    buf = []
                put_label(p)
                a = p
            if p in rel and p + 4 <= nxt:
                if buf:
                    lines.append((a, 'db', bytes(buf)))
                    buf = []
                lines.append((p, 'dd', label_for(rel[p])))
                p += 4
                a = p
                continue
            buf.append(raw_at(p, 1)[0])
            stats['data_bytes_in_text'] += 1
            p += 1
        if buf:
            lines.append((a, 'db', bytes(buf)))
        a = nxt
    # encoding choice for ordinary instructions (Ghidra, choose mode, deduplicated by text+bytes)
    uniq = {}
    for li in pending_choose:
        _, _, (new, text, bh, _e) = lines[li]
        uniq.setdefault((text, bh), str(len(uniq)))
    res = ghidra_assemble([(k, t, 0, bh) for (t, bh), k in uniq.items()], choose=True)
    for li in pending_choose:
        a, _, (new, text, bh, _e) = lines[li]
        idx, n = res.get(uniq[(text, bh)], ('ERR', 'missing'))
        if idx == 'ERR' or int(idx) < 0:
            sites = [(s - a, label_for(rel[s])) for s in range(a, a + len(bh) // 2) if s in rel]
            lines[li] = (a, 'pin', (text, bh, sites))
        elif int(idx) > 0:
            lines[li][2][3] = int(idx)
            stats['enc_pinned'] += 1
    # branch sizes: predict with relax() on the original layout, force (enc 1 long / 2 short) where it differs
    def seq_of():
        out_ = []
        for a_, k_, p_ in lines:
            if k_ == 'label':
                out_.append(('label', p_))
            elif k_ == 'br':
                out_.append(('br', p_[0], p_[1], p_[2]))
            elif k_ in ('ins', 'pin'):
                out_.append(('fix', len(p_[2 if k_ == 'ins' else 1]) // 2))
            elif k_ == 'db':
                out_.append(('fix', len(p_)))
            else:
                out_.append(('fix', 4))
        return out_
    for _round in range(20):
        addrs, values, longs, _end = relax(seq_of(), t0, fixed_label_value)
        wrong = 0
        for i, (a_, k_, p_) in enumerate(lines):
            if k_ == 'br' and p_[0] not in REL8_ONLY and p_[0] != 'CALL' and longs[i] != p_[4]:
                p_[2] = 1 if p_[4] else 2
                wrong += 1
        if wrong == 0:
            break
    stats['branch_size_pinned'] = sum(1 for a_, k_, p_ in lines if k_ == 'br' and p_[2])
    for a, k, p in lines:
        if k == 'pin':
            stats['db_pinned_instructions'] += 1
            stats['db_pinned_bytes'] += len(p[1]) // 2
    # write text files: a new file at every function start
    os.makedirs(os.path.join(out, 'text'), exist_ok=True)
    files, cur, cur_name = [], None, None
    def flush():
        if cur is not None:
            files.append((cur_name, cur))
    for a, k, p in lines:
        if k == 'label' and a in fnames and labels[a] == p:
            flush()
            cur, cur_name = [f'; FUNCTION 0x{a:x} {fnames[a]}'], f'{len(files):05d}_{a:x}_{p[:60]}.asm'
        if cur is None:
            cur, cur_name = ['; start of .text'], f'{len(files):05d}_{a:x}_start.asm'
        if k == 'label':
            cur.append(f'{p}:')
        elif k == 'ins':
            new, text, bh, enc = p
            cur.append('    ' + new + (f' {{enc:{enc}}}' if enc else ''))
        elif k == 'br':
            mn, lab, enc, bh, _long = p
            cur.append(f'    {mn} {lab}' + (f' {{enc:{enc}}}' if enc else ''))
        elif k == 'pin':
            text, bh, sites = p
            b = bytes.fromhex(bh)
            parts, i = [], 0
            for off, lab in sites:
                if off > i:
                    parts.append('    db ' + ','.join(f'{x:02x}' for x in b[i:off]))
                parts.append(f'    dd {lab}')
                i = off + 4
            if i < len(b):
                parts.append('    db ' + ','.join(f'{x:02x}' for x in b[i:]))
            parts[0] += f'    ; PINNED {text}'
            cur.extend(parts)
        elif k == 'db':
            for i in range(0, len(p), 16):
                cur.append('    db ' + ','.join(f'{x:02x}' for x in p[i:i + 16]))
        elif k == 'dd':
            cur.append(f'    dd {p}')
    flush()
    for name, content in files:
        with open(os.path.join(out, 'text', name), 'w') as f:
            f.write('\n'.join(content) + '\n')
    # non-code sections: raw bytes, pointers into .text replaced by label fixups (zeroed in the raw file)
    os.makedirs(os.path.join(out, 'raw'), exist_ok=True)
    first_raw = min(s['raw_ptr'] for s in secs if s['raw_size'])
    open(os.path.join(out, 'raw', 'headers.bin'), 'wb').write(d[:first_raw])
    sections, fixups, data_sites = [], [], []
    for s in secs:
        ent = dict(name=s['name'], va=s['va'], raw_ptr=s['raw_ptr'], raw_size=s['raw_size'])
        if s is T:
            ent['kind'] = 'text'
        elif s['name'] == reloc_sec:
            ent['kind'] = 'reloc'
        else:
            ent['kind'] = 'raw'
            raw = bytearray(d[s['raw_ptr']:s['raw_ptr'] + s['raw_size']])
            for site, v in rel.items():
                o = site - base - s['va']
                if 0 <= o < s['raw_size']:
                    if in_text(v):
                        fixups.append(dict(section=s['name'], offset=o, label=label_for(v)))
                        raw[o:o + 4] = b'\0\0\0\0'
                    else:
                        data_sites.append(site - base)
            open(os.path.join(out, 'raw', s['name'].strip('.') + '.bin'), 'wb').write(raw)
            ent['file'] = 'raw/' + s['name'].strip('.') + '.bin'
        sections.append(ent)
    end_raw = max(s['raw_ptr'] + s['raw_size'] for s in secs)
    gaps = []
    spans = sorted([(0, first_raw)] + [(s['raw_ptr'], s['raw_ptr'] + s['raw_size']) for s in secs if s['raw_size']])
    for (a0, a1), (b0, _) in zip(spans, spans[1:]):
        if b0 > a1:
            gaps.append(dict(offset=a1, hex=d[a1:b0].hex()))
    open(os.path.join(out, 'raw', 'overlay.bin'), 'wb').write(d[end_raw:])
    # check the .reloc convention now, so a build failure later is not a surprise
    rs = next((s for s in secs if s['name'] == reloc_sec), None)
    reloc_note = None
    if rs:
        regen = make_reloc([x - base for x in rel])
        orig = d[rs['raw_ptr']:rs['raw_ptr'] + rs['raw_size']]
        tail = orig[len(regen):]
        reloc_note = dict(regenerated_equals_original=orig[:len(regen)] == regen and not any(tail),
                          size=len(regen), dir_size=dirs[5][1])
    layout = dict(image_base=base, text=dict(name=T['name'], va=T['va'], raw_size=T['raw_size']),
                  sections=sections, fixups=fixups, data_reloc_sites=sorted(data_sites), gaps=gaps,
                  overlay='raw/overlay.bin', reloc_section=reloc_sec, reloc_check=reloc_note,
                  files=[n for n, _ in files], stats=stats)
    json.dump(layout, open(os.path.join(out, 'layout.json'), 'w'), indent=1)
    print(json.dumps(dict(files=len(files), **stats, reloc_check=reloc_note), indent=1))
    return 0


# ---------------------------------------------------------------------------------------------- build (encode)
LINE_ENC = re.compile(r'\s*\{enc:(\d+)\}\s*$')


def parse_files(out, layout):
    items = []          # dicts: kind label/ins/br/db/dd
    for fn in layout['files']:
        for raw in open(os.path.join(out, 'text', fn)):
            s = raw.split(';', 1)[0].strip()
            if not s:
                continue
            if s.endswith(':') and IDENT.match(s[:-1]):
                items.append(dict(k='label', name=s[:-1]))
                continue
            enc = 0
            m = LINE_ENC.search(s)
            if m:
                enc = int(m.group(1))
                s = s[:m.start()].strip()
            head, _, rest = s.partition(' ')
            up = head.upper()
            if up == 'DB':
                items.append(dict(k='db', b=bytes(int(x, 16) for x in rest.replace(' ', '').split(','))))
            elif up == 'DD':
                items.append(dict(k='dd', expr=rest.strip()))
            elif (up in JCC or up in REL8_ONLY or up in ('JMP', 'CALL')) and IDENT.match(rest.strip()):
                # a direct branch only if the operand is a label (decided once all labels are known)
                items.append(dict(k='br?', mn=up, target=rest.strip(), enc=enc, text=s))
            else:
                items.append(dict(k='ins', text=s, enc=enc))
    return items


def build(out, binary_out, cache_file=None):
    layout = json.load(open(os.path.join(out, 'layout.json')))
    base = layout['image_base']
    T = layout['text']
    t0 = base + T['va']
    items = parse_files(out, layout)
    cache = {}
    if cache_file and os.path.exists(cache_file):
        cache = json.load(open(cache_file))
    def fixed_value(name):
        m = re.match(r'^(D|A)_([0-9a-f]+)$', name)
        return int(m.group(2), 16) if m else None
    lab_tok = re.compile(r'(?<![\w])([A-Za-z_][A-Za-z0-9_]*)(-0x[0-9a-fA-F]+)?(?![\w])')
    def labels_in(text):
        return [m.group(0) for m in lab_tok.finditer(text)
                if m.group(1) in code_labels or fixed_value(m.group(1)) is not None]
    def value_of(expr, values):
        m = lab_tok.fullmatch(expr.strip())
        if not m:
            return None
        v = values.get(m.group(1), fixed_value(m.group(1)))
        if v is None:
            return None
        return v - int(m.group(2)[1:], 16) if m.group(2) else v
    code_labels = {it['name'] for it in items if it['k'] == 'label'}
    for it in items:
        if it['k'] == 'br?':
            if it['target'] in code_labels or fixed_value(it['target']) is not None:
                it['k'] = 'br'
            else:                                  # e.g. JMP EAX, CALL ESI
                it['k'] = 'ins'
                it['text'] = it['text'] if it['enc'] == 0 else it['text']
    # 1. size every ordinary instruction (label values do not change the length: always 32-bit)
    def resolve(text, values):
        def rep(m):
            v = value_of(m.group(0), values)
            return f'0x{v:x}' if v is not None else m.group(0)
        return lab_tok.sub(rep, text)
    prov = {n: 0x10000000 for n in code_labels}
    todo = {}
    for it in items:
        if it['k'] == 'ins':
            it['prov'] = resolve(it['text'], prov)
            key = f"{it['prov']}\x00{it['enc']}"
            if key not in cache:
                todo[key] = (it['prov'], it['enc'])
    def run(todo):
        if not todo:
            return
        keys = list(todo)
        res = ghidra_assemble([(str(i), todo[k][0], todo[k][1]) for i, k in enumerate(keys)])
        bad = []
        for i, k in enumerate(keys):
            h, n = res.get(str(i), ('ERR', 'missing'))
            if h == 'ERR':
                bad.append(f'{todo[k][0]!r}: {n}')
            else:
                cache[k] = h
        if bad:
            raise RuntimeError(f'{len(bad)} line(s) do not assemble, e.g.: ' + '; '.join(bad[:5]))
    run(todo)
    for it in items:
        if it['k'] == 'ins':
            it['size'] = len(cache[f"{it['prov']}\x00{it['enc']}"]) // 2
    # 2. layout: the same MSVC-style branch sizing split used to predict the original
    seq = []
    for it in items:
        if it['k'] == 'label':
            seq.append(('label', it['name']))
        elif it['k'] == 'br':
            seq.append(('br', it['mn'], it['target'], it['enc']))
        elif it['k'] == 'ins':
            seq.append(('fix', it['size']))
        elif it['k'] == 'db':
            seq.append(('fix', len(it['b'])))
        else:
            seq.append(('fix', 4))
    addrs, values, longs, addr = relax(seq, t0, fixed_value)
    for it, a_, l_ in zip(items, addrs, longs):
        it['addr'] = a_
        if it['k'] == 'br':
            it['long'] = l_
            if not l_ and it['mn'] not in REL8_ONLY and it['mn'] != 'CALL':
                tgt = values.get(it['target'], fixed_value(it['target']))
                if not -128 <= tgt - (a_ + 2) <= 127:
                    raise RuntimeError(f"{it['mn']} {it['target']} {{enc:2}}: target out of rel8 range")
    end = addr
    if os.environ.get('REASM_DEBUG'):
        json.dump(dict(values=values, items=[(it['k'], it.get('name') or it.get('text') or it.get('target') or '', it['addr'],
                                              it.get('size'), it.get('long')) for it in items]),
                  open(os.environ['REASM_DEBUG'], 'w'))
    if end - t0 > T['raw_size']:
        raise RuntimeError(f'.text grew to {end - t0} bytes > raw size {T["raw_size"]}: moving sections is not supported')
    # 3. final bytes
    todo = {}
    for it in items:
        if it['k'] == 'ins':
            it['final'] = resolve(it['text'], values)
            key = f"{it['final']}\x00{it['enc']}"
            if key not in cache:
                todo[key] = (it['final'], it['enc'])
    run(todo)
    text = bytearray()
    code_sites = []
    for it in items:
        k = it['k']
        if k == 'label':
            continue
        if k == 'ins':
            b = bytes.fromhex(cache[f"{it['final']}\x00{it['enc']}"])
            if len(b) != it['size']:
                raise RuntimeError(f"size changed after resolving labels: {it['text']}")
            for lab in set(labels_in(it['text'])):
                v = value_of(lab, values)
                pat = struct.pack('<I', v)
                pos = [i for i in range(len(b) - 3) if b[i:i + 4] == pat]
                if not pos:
                    raise RuntimeError(f"label value of {lab} not found in encoding of {it['text']}")
                code_sites.extend(it['addr'] + p - base for p in pos)
            text += b
        elif k == 'db':
            text += it['b']
        elif k == 'dd':
            v = value_of(it['expr'], values)
            if v is None:
                raise RuntimeError(f"unknown label in dd {it['expr']}")
            code_sites.append(it['addr'] - base)
            text += struct.pack('<I', v)
        else:
            tgt = values.get(it['target'], fixed_value(it['target']))
            mn, a = it['mn'], it['addr']
            if mn in REL8_ONLY:
                text += bytes([REL8_ONLY[mn], (tgt - (a + 2)) & 0xff])
            elif not it['long']:
                op = 0xeb if mn == 'JMP' else 0x70 | JCC[mn]
                text += bytes([op, (tgt - (a + 2)) & 0xff])
            elif mn == 'CALL':
                text += b'\xe8' + struct.pack('<i', tgt - (a + 5))
            elif mn == 'JMP':
                text += b'\xe9' + struct.pack('<i', tgt - (a + 5))
            else:
                text += bytes([0x0f, 0x80 | JCC[mn]]) + struct.pack('<i', tgt - (a + 6))
    text += b'\0' * (T['raw_size'] - len(text))
    # 4. PE
    img = bytearray(open(os.path.join(out, 'raw', 'headers.bin'), 'rb').read())
    secdata = {}
    sites = list(code_sites) + list(layout['data_reloc_sites'])
    for s in layout['sections']:
        if s['kind'] == 'text':
            secdata[s['name']] = bytes(text)
        elif s['kind'] == 'raw':
            raw = bytearray(open(os.path.join(out, s['file']), 'rb').read())
            for fx in (f for f in layout['fixups'] if f['section'] == s['name']):
                v = value_of(fx['label'], values)
                raw[fx['offset']:fx['offset'] + 4] = struct.pack('<I', v)
                sites.append(s['va'] + fx['offset'])
            secdata[s['name']] = bytes(raw)
    for s in layout['sections']:
        if s['kind'] == 'reloc':
            r = make_reloc(sites)
            if len(r) > s['raw_size']:
                raise RuntimeError('.reloc grew beyond its raw size')
            secdata[s['name']] = r + b'\0' * (s['raw_size'] - len(r))
    total = max(s['raw_ptr'] + s['raw_size'] for s in layout['sections'])
    img += b'\0' * (total - len(img))
    for g in layout['gaps']:
        b = bytes.fromhex(g['hex'])
        img[g['offset']:g['offset'] + len(b)] = b
    for s in layout['sections']:
        if s['raw_size']:
            img[s['raw_ptr']:s['raw_ptr'] + s['raw_size']] = secdata[s['name']]
    img += open(os.path.join(out, layout['overlay']), 'rb').read()
    open(binary_out, 'wb').write(img)
    if cache_file:
        json.dump(cache, open(cache_file, 'w'))
    return 0


def editcheck(binary, out, ddir, cache_file=None):
    import shutil
    tmp = tempfile.mkdtemp()
    work = os.path.join(tmp, 'text_copy')
    shutil.copytree(out, work)
    layout = json.load(open(os.path.join(work, 'layout.json')))
    d = open(binary, 'rb').read()
    base, dirs, secs = pe_parse(d)
    rel, _ = relocs_of(d, base, dirs, secs)
    T = next(x for x in secs if x['exec'])
    t0, tend = base + T['va'], base + T['va'] + T['raw_size']
    # find the first function file with >= 2 instructions; insert after its first instruction
    ins = {}
    with open(os.path.join(ddir, 'instructions.tsv')) as f:
        next(f)
        for line in f:
            a, ln, fn, flow, targets, text = line.rstrip('\n').split('\t', 5)
            ins[int(a, 16)] = (int(ln), flow, targets)
    X = None
    for fn in layout['files']:
        p = os.path.join(work, 'text', fn)
        src = open(p).read().split('\n')
        idx = [i for i, l in enumerate(src) if l.startswith('    ') and not l.strip().lower().startswith(('db', 'dd'))]
        if len(idx) >= 2:
            fa = int(fn.split('_')[1], 16)
            first_len = ins[fa][0]
            X = fa + first_len
            src.insert(idx[0] + 1, '    NOP')
            open(p, 'w').write('\n'.join(src))
            break
    outb = os.path.join(tmp, 'edited.bin')
    build(work, outb, cache_file)
    e = open(outb, 'rb').read()
    shift = lambda v: v + 1 if t0 <= v < tend and v >= X else v
    def rd(buf, va):
        sec = next(x for x in secs if x['va'] <= va - base < x['va'] + x['raw_size'])
        return struct.unpack_from('<I', buf, sec['raw_ptr'] + va - base - sec['va'])[0]
    wrong = [(s_, v, rd(e, shift(s_))) for s_, v in rel.items() if rd(e, shift(s_)) != shift(v)]
    bad_ptr = len(wrong)
    erel, _ = relocs_of(e, base, dirs, secs)
    bad_reloc = len(set(erel) ^ {shift(s_) for s_ in rel})
    bad_br = checked = 0
    for a, (ln, flow, targets) in ins.items():
        if flow not in ('call', 'jump', 'cjump') or not targets or not (t0 <= a < tend):
            continue
        b = d[T['raw_ptr'] + a - t0:T['raw_ptr'] + a - t0 + ln]
        bk = branch_kind(b)
        if not bk:
            continue
        t = int(targets.split(',')[0], 16)
        a2 = shift(a)
        o = T['raw_ptr'] + a2 - t0
        nb = e[o:o + 6]
        if nb[0] in (0xe8, 0xe9):
            t2 = a2 + 5 + struct.unpack('<i', nb[1:5])[0]
        elif nb[0] == 0x0f:
            t2 = a2 + 6 + struct.unpack('<i', nb[2:6])[0]
        else:
            t2 = a2 + 2 + struct.unpack('<b', nb[1:2])[0]
        checked += 1
        bad_br += t2 != shift(t)
    res = dict(inserted_after=hex(X - 1), relocated_pointers=len(rel), pointers_wrong=bad_ptr,
               reloc_entries_differing=bad_reloc, branches_checked=checked, branches_wrong=bad_br,
               size_equal=len(e) == len(d),
               wrong_pointer_examples=[f'site 0x{a:x}: original -> 0x{v:x}, edited -> 0x{w:x}' for a, v, w in wrong[:10]])
    print(json.dumps(res, indent=1))
    ok = not bad_ptr and not bad_reloc and not bad_br
    print('EDITABLE' if ok else 'NOT EDITABLE')
    return 0 if ok else 1


def main(argv):
    if len(argv) < 1 or argv[0] in ('-h', '--help'):
        print(__doc__, file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    opt = {}
    for flag in ('--names', '--cache'):
        if flag in rest:
            i = rest.index(flag)
            opt[flag] = rest[i + 1]
            del rest[i:i + 2]
    if cmd == 'split' and len(rest) == 3:
        return split(rest[0], rest[1], rest[2], opt.get('--names'))
    if cmd == 'build' and len(rest) == 2:
        return build(rest[0], rest[1], opt.get('--cache'))
    if cmd == 'editcheck' and len(rest) == 3:
        return editcheck(rest[0], rest[1], rest[2], opt.get('--cache'))
    if cmd == 'verify' and len(rest) == 2:
        tmpd = tempfile.mkdtemp()
        outb = os.path.join(tmpd, 'rebuilt.bin')
        build(rest[1], outb, opt.get('--cache'))
        a = hashlib.sha256(open(rest[0], 'rb').read()).hexdigest()
        b = hashlib.sha256(open(outb, 'rb').read()).hexdigest()
        if a == b:
            print('IDENTICAL', a)
            return 0
        x, y = open(rest[0], 'rb').read(), open(outb, 'rb').read()
        first = next((i for i in range(min(len(x), len(y))) if x[i] != y[i]), min(len(x), len(y)))
        print(f'DIFFERENT: original {len(x)} bytes, rebuilt {len(y)} bytes, first difference at file offset 0x{first:x}')
        print('rebuilt kept at', outb)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
