"""Pure-Python deflate encoder used by fmt_png for streams that the C zlib module cannot reproduce.

Two halves, both ports of zlib 1.2.12:
  * deflate_tokens(): the LZ77 match finder (deflate_fast / deflate_slow, longest_match, fill_window,
    hash chains, window sliding), parameterised so that non-zlib variants can be expressed
    (custom good/lazy/nice/chain, position 0 usable as a match source, a tail of N bytes that is
    never matched into, TOO_FAR distance).
  * emit_blocks(): trees.c - zlib's Huffman tree builder (build_tree / gen_bitlen with its overflow
    fix-up / gen_codes), scan_tree/send_tree code-length RLE, and _tr_flush_block's choice between
    stored, fixed and dynamic blocks.
With zlib's own parameters the port is bit-identical to the C library (checked against Python's zlib
module on real PNG data at levels 1-9, strategies default/filtered).
"""
import zlib

MIN_MATCH, MAX_MATCH = 3, 258
MIN_LOOKAHEAD = MAX_MATCH + MIN_MATCH + 1

# zlib configuration_table: level -> (good_length, max_lazy, nice_length, max_chain, func)
ZLIB_CONFIG = {1: (4, 4, 8, 4, 'fast'), 2: (4, 5, 16, 8, 'fast'), 3: (4, 6, 32, 32, 'fast'),
               4: (4, 4, 16, 16, 'slow'), 5: (8, 16, 32, 32, 'slow'), 6: (8, 16, 128, 128, 'slow'),
               7: (8, 32, 128, 256, 'slow'), 8: (32, 128, 258, 1024, 'slow'), 9: (32, 258, 258, 4096, 'slow')}


def deflate_tokens(data, good, lazy, nice, chain, func, wbits=15, memlevel=8, strategy=0,
                   pos0_matchable=False, too_far=4096, tail_unmatched=0, block_symbols=None):
    """LZ77 stage. Returns [(tokens, input_available, start, end)], token = int literal | (length, distance).
    Emulates feeding the whole input at once (as zlib.compressobj().compress(data) does)."""
    wsize = 1 << wbits
    wmask = wsize - 1
    window_size = 2 * wsize
    hash_bits = memlevel + 7
    hash_size = 1 << hash_bits
    hash_mask = hash_size - 1
    hash_shift = (hash_bits + MIN_MATCH - 1) // MIN_MATCH
    if block_symbols is None:
        block_symbols = (1 << (memlevel + 6)) - 1
    NIL = -1 if pos0_matchable else 0
    window = bytearray(window_size)
    head = [NIL] * hash_size
    prev = [NIL] * wsize
    MAX_DIST = wsize - MIN_LOOKAHEAD
    S = dict(strstart=0, lookahead=0, ins_h=0, insert=0, match_start=0, inpos=0, block_start=0, abs_start=0)
    n_in = len(data)
    blocks = []
    cur = []

    def fill_window():
        while True:
            more = window_size - S['lookahead'] - S['strstart']
            if S['strstart'] >= wsize + MAX_DIST:
                window[0:wsize - more] = window[wsize:wsize + wsize - more]
                S['match_start'] -= wsize
                S['strstart'] -= wsize
                S['block_start'] -= wsize
                if S['insert'] > S['strstart']:
                    S['insert'] = S['strstart']
                for i in range(hash_size):
                    m = head[i]
                    head[i] = m - wsize if m >= wsize else NIL
                for i in range(wsize):
                    m = prev[i]
                    prev[i] = m - wsize if m >= wsize else NIL
                more += wsize
            avail = n_in - S['inpos']
            if avail == 0:
                break
            n = min(avail, more)
            p = S['strstart'] + S['lookahead']
            window[p:p + n] = data[S['inpos']:S['inpos'] + n]
            S['inpos'] += n
            S['lookahead'] += n
            if S['lookahead'] + S['insert'] >= MIN_MATCH:
                s = S['strstart'] - S['insert']
                h = ((window[s] << hash_shift) ^ window[s + 1]) & hash_mask
                while S['insert']:
                    h = ((h << hash_shift) ^ window[s + 2]) & hash_mask
                    prev[s & wmask] = head[h]
                    head[h] = s
                    s += 1
                    S['insert'] -= 1
                    if S['lookahead'] + S['insert'] < MIN_MATCH:
                        break
                S['ins_h'] = h
            if not (S['lookahead'] < MIN_LOOKAHEAD and n_in - S['inpos'] != 0):
                break

    def longest_match(cur_match, prev_length):
        chain_length = chain
        strstart = S['strstart']
        scan = strstart
        best_len = prev_length
        nice_match = nice
        limit = strstart - MAX_DIST if strstart > MAX_DIST else (-1 if pos0_matchable else 0)
        scan_end1 = window[scan + best_len - 1]
        scan_end = window[scan + best_len]
        if prev_length >= good:
            chain_length >>= 2
        if nice_match > S['lookahead']:
            nice_match = S['lookahead']
        w = window
        while True:
            m = cur_match
            if not (w[m + best_len] != scan_end or w[m + best_len - 1] != scan_end1
                    or w[m] != w[scan] or w[m + 1] != w[scan + 1]):
                ln = 2
                while ln < MAX_MATCH and w[scan + ln] == w[m + ln]:
                    ln += 1
                if ln > best_len:
                    S['match_start'] = cur_match
                    best_len = ln
                    if ln >= nice_match:
                        break
                    scan_end1 = w[scan + best_len - 1]
                    scan_end = w[scan + best_len]
            cur_match = prev[cur_match & wmask]
            chain_length -= 1
            if not (cur_match > limit and chain_length != 0):
                break
        la = S['lookahead'] - tail_unmatched
        return best_len if best_len <= la else la

    def insert(s):
        h = ((S['ins_h'] << hash_shift) ^ window[s + 2]) & hash_mask
        S['ins_h'] = h
        hh = head[h]
        prev[s & wmask] = hh
        head[h] = s
        return hh

    def flush():
        # zlib passes the block's input to _tr_flush_block only while block_start >= 0 (not slid away)
        abs_end = S['inpos'] - S['lookahead']
        blocks.append((cur[:], S['block_start'] >= 0, S['abs_start'], abs_end))
        cur.clear()
        S['block_start'] = S['strstart']
        S['abs_start'] = abs_end

    if func == 'fast':
        match_length = 0
        while True:
            if S['lookahead'] < MIN_LOOKAHEAD:
                fill_window()
                if S['lookahead'] == 0:
                    break
            hash_head = NIL
            if S['lookahead'] >= MIN_MATCH:
                hash_head = insert(S['strstart'])
            if hash_head != NIL and S['strstart'] - hash_head <= MAX_DIST:
                match_length = longest_match(hash_head, MIN_MATCH - 1)
            if match_length >= MIN_MATCH:
                cur.append((match_length, S['strstart'] - S['match_start']))
                S['lookahead'] -= match_length
                if match_length <= lazy and S['lookahead'] >= MIN_MATCH:
                    match_length -= 1
                    while True:
                        S['strstart'] += 1
                        insert(S['strstart'])
                        match_length -= 1
                        if match_length == 0:
                            break
                    S['strstart'] += 1
                else:
                    S['strstart'] += match_length
                    match_length = 0
                    s = S['strstart']
                    S['ins_h'] = ((window[s] << hash_shift) ^ window[s + 1]) & hash_mask
            else:
                cur.append(window[S['strstart']])
                S['lookahead'] -= 1
                S['strstart'] += 1
            if len(cur) == block_symbols:
                flush()
    else:
        match_length = MIN_MATCH - 1
        match_available = 0
        while True:
            if S['lookahead'] < MIN_LOOKAHEAD:
                fill_window()
                if S['lookahead'] == 0:
                    break
            hash_head = NIL
            if S['lookahead'] >= MIN_MATCH:
                hash_head = insert(S['strstart'])
            prev_length = match_length
            prev_match = S['match_start']
            match_length = MIN_MATCH - 1
            if hash_head != NIL and prev_length < lazy and S['strstart'] - hash_head <= MAX_DIST:
                match_length = longest_match(hash_head, prev_length)
                if match_length <= 5 and (strategy == 1 or (match_length == MIN_MATCH and
                                                            S['strstart'] - S['match_start'] > too_far)):
                    match_length = MIN_MATCH - 1
            if prev_length >= MIN_MATCH and match_length <= prev_length:
                max_insert = S['strstart'] + S['lookahead'] - MIN_MATCH
                cur.append((prev_length, S['strstart'] - 1 - prev_match))
                S['lookahead'] -= prev_length - 1
                prev_length -= 2
                while True:
                    S['strstart'] += 1
                    if S['strstart'] <= max_insert:
                        insert(S['strstart'])
                    prev_length -= 1
                    if prev_length == 0:
                        break
                match_available = 0
                match_length = MIN_MATCH - 1
                S['strstart'] += 1
                if len(cur) == block_symbols:
                    flush()
            elif match_available:
                cur.append(window[S['strstart'] - 1])
                if len(cur) == block_symbols:
                    flush()
                S['strstart'] += 1
                S['lookahead'] -= 1
            else:
                match_available = 1
                S['strstart'] += 1
                S['lookahead'] -= 1
        if match_available:
            cur.append(window[S['strstart'] - 1])
    flush()
    return blocks


# ---------------------------------------------------------------- trees.c
LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
         4097, 6145, 8193, 12289, 16385, 24577]
DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
BL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
FIXED_L = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
FIXED_D = [5] * 30
LCODE = [0] * 259
for _i in range(28):
    for _l in range(LBASE[_i], LBASE[_i] + (1 << LEXT[_i])):
        if _l <= 258:
            LCODE[_l] = _i
LCODE[258] = 28
DCODE = [0] * 32769
for _i in range(30):
    for _d in range(DBASE[_i], min(32768, DBASE[_i] + (1 << DEXT[_i]) - 1) + 1):
        DCODE[_d] = _i


class BitWriter:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, v, n):
        self.acc |= v << self.n
        self.n += n
        while self.n >= 8:
            self.out.append(self.acc & 255)
            self.acc >>= 8
            self.n -= 8

    def align(self):
        if self.n > 0:
            self.out.append(self.acc & 255)
        self.acc = 0
        self.n = 0


def _rev(c, n):
    r = 0
    for _ in range(n):
        r = (r << 1) | (c & 1)
        c >>= 1
    return r


def gen_codes(lens):
    bl = [0] * 16
    for x in lens:
        bl[x] += 1
    bl[0] = 0
    nxt = [0] * 16
    code = 0
    for b in range(1, 16):
        code = (code + bl[b - 1]) << 1
        nxt[b] = code
    codes = [0] * len(lens)
    for i, x in enumerate(lens):
        if x:
            codes[i] = _rev(nxt[x], x)
            nxt[x] += 1
    return codes


def build_tree(freq, max_length, elems):
    """zlib build_tree + gen_bitlen. Returns (code lengths, max_code)."""
    n = len(freq)
    HEAP_SIZE = 2 * n + 1
    heap = [0] * (2 * n + 2)
    depth = [0] * (2 * n + 2)
    fr = list(freq) + [0] * (n + 2)
    dad = [0] * (2 * n + 2)
    ln = [0] * (2 * n + 2)
    heap_len = 0
    heap_max = HEAP_SIZE
    max_code = -1
    for i in range(elems):
        if fr[i] != 0:
            heap_len += 1
            heap[heap_len] = max_code = i
            depth[i] = 0
    while heap_len < 2:
        heap_len += 1
        if max_code < 2:
            max_code += 1
            node = max_code
        else:
            node = 0
        heap[heap_len] = node
        fr[node] = 1
        depth[node] = 0

    def smaller(a, b):
        return fr[a] < fr[b] or (fr[a] == fr[b] and depth[a] <= depth[b])

    def down(k):
        v = heap[k]
        j = k << 1
        while j <= heap_len:
            if j < heap_len and smaller(heap[j + 1], heap[j]):
                j += 1
            if smaller(v, heap[j]):
                break
            heap[k] = heap[j]
            k = j
            j <<= 1
        heap[k] = v

    for k in range(heap_len // 2, 0, -1):
        down(k)
    node = elems
    while True:
        a = heap[1]
        heap[1] = heap[heap_len]
        heap_len -= 1
        down(1)
        b = heap[1]
        heap_max -= 1
        heap[heap_max] = a
        heap_max -= 1
        heap[heap_max] = b
        fr[node] = fr[a] + fr[b]
        depth[node] = max(depth[a], depth[b]) + 1
        dad[a] = dad[b] = node
        heap[1] = node
        node += 1
        down(1)
        if heap_len < 2:
            break
    heap_max -= 1
    heap[heap_max] = heap[1]
    bl_count = [0] * 16
    ln[heap[heap_max]] = 0
    overflow = 0
    for h in range(heap_max + 1, HEAP_SIZE):
        nn = heap[h]
        bits = ln[dad[nn]] + 1
        if bits > max_length:
            bits = max_length
            overflow += 1
        ln[nn] = bits
        if nn > max_code:
            continue
        bl_count[bits] += 1
    if overflow:
        while True:
            bits = max_length - 1
            while bl_count[bits] == 0:
                bits -= 1
            bl_count[bits] -= 1
            bl_count[bits + 1] += 2
            bl_count[max_length] -= 1
            overflow -= 2
            if overflow <= 0:
                break
        h = HEAP_SIZE
        for bits in range(max_length, 0, -1):
            nn = bl_count[bits]
            while nn != 0:
                h -= 1
                m = heap[h]
                if m > max_code:
                    continue
                if ln[m] != bits:
                    ln[m] = bits
                nn -= 1
    return ln[:elems], max_code


def _tree_runs(lens, max_code):
    """zlib scan_tree/send_tree run splitting: yields (kind, curlen, count)."""
    prevlen = -1
    nextlen = lens[0]
    count = 0
    max_count, min_count = (138, 3) if nextlen == 0 else (7, 4)
    L = list(lens[:max_code + 1]) + [0xffff]
    for n in range(max_code + 1):
        curlen = nextlen
        nextlen = L[n + 1]
        count += 1
        if count < max_count and curlen == nextlen:
            continue
        elif count < min_count:
            yield 'lit', curlen, count, prevlen
        elif curlen != 0:
            yield 'rep', curlen, count, prevlen
        elif count <= 10:
            yield 'z3', curlen, count, prevlen
        else:
            yield 'z11', curlen, count, prevlen
        count = 0
        prevlen = curlen
        if nextlen == 0:
            max_count, min_count = 138, 3
        elif curlen == nextlen:
            max_count, min_count = 6, 3
        else:
            max_count, min_count = 7, 4


def _scan_tree(lens, max_code, blf):
    for kind, cl, cnt, prevlen in _tree_runs(lens, max_code):
        if kind == 'lit':
            blf[cl] += cnt
        elif kind == 'rep':
            if cl != prevlen:
                blf[cl] += 1
            blf[16] += 1
        elif kind == 'z3':
            blf[17] += 1
        else:
            blf[18] += 1


def _send_tree(bw, lens, max_code, blc, bll):
    for kind, cl, cnt, prevlen in _tree_runs(lens, max_code):
        if kind == 'lit':
            for _ in range(cnt):
                bw.put(blc[cl], bll[cl])
        elif kind == 'rep':
            if cl != prevlen:
                bw.put(blc[cl], bll[cl])
                cnt -= 1
            bw.put(blc[16], bll[16])
            bw.put(cnt - 3, 2)
        elif kind == 'z3':
            bw.put(blc[17], bll[17])
            bw.put(cnt - 3, 3)
        else:
            bw.put(blc[18], bll[18])
            bw.put(cnt - 11, 7)


def _freqs(toks):
    lf = [0] * 286
    df = [0] * 30
    for t in toks:
        if t.__class__ is int:
            lf[t] += 1
        else:
            lf[257 + LCODE[t[0]]] += 1
            df[DCODE[t[1]]] += 1
    lf[256] += 1
    return lf, df


def _compress_block(bw, toks, ll, dl):
    lc = gen_codes(ll)
    dc = gen_codes(dl)
    for t in toks:
        if t.__class__ is int:
            bw.put(lc[t], ll[t])
        else:
            L, D = t
            c = LCODE[L]
            bw.put(lc[257 + c], ll[257 + c])
            if LEXT[c]:
                bw.put(L - LBASE[c], LEXT[c])
            d = DCODE[D]
            bw.put(dc[d], dl[d])
            if DEXT[d]:
                bw.put(D - DBASE[d], DEXT[d])
    bw.put(lc[256], ll[256])


def flush_block(bw, toks, stored_bytes, last, strategy=0):
    """zlib _tr_flush_block (level > 0). stored_bytes = block input, or None if not available."""
    lf, df = _freqs(toks)
    ll, lmax = build_tree(lf, 15, 286)
    dl, dmax = build_tree(df, 15, 30)
    blf = [0] * 19
    _scan_tree(ll, lmax, blf)
    _scan_tree(dl, dmax, blf)
    bll, _ = build_tree(blf, 7, 19)
    max_blindex = 18
    while max_blindex >= 3 and bll[BL_ORDER[max_blindex]] == 0:
        max_blindex -= 1
    extra = sum(lf[257 + i] * LEXT[i] for i in range(29)) + sum(df[i] * DEXT[i] for i in range(30))
    opt = sum(lf[i] * ll[i] for i in range(286)) + sum(df[i] * dl[i] for i in range(30)) + extra
    opt += sum(blf[i] * bll[i] for i in range(19)) + 2 * blf[16] + 3 * blf[17] + 7 * blf[18]
    opt += 14 + 3 * (max_blindex + 1)
    stat = sum(lf[i] * FIXED_L[i] for i in range(286)) + 5 * sum(df) + extra
    opt_lenb = (opt + 3 + 7) >> 3
    static_lenb = (stat + 3 + 7) >> 3
    if static_lenb <= opt_lenb or strategy == 4:
        opt_lenb = static_lenb
    if stored_bytes is not None and len(stored_bytes) + 4 <= opt_lenb:
        bw.put(0 | last, 3)
        bw.align()
        n = len(stored_bytes)
        bw.out += bytes([n & 255, n >> 8, ~n & 255, (~n >> 8) & 255]) + stored_bytes
    elif static_lenb == opt_lenb:
        bw.put(2 | last, 3)
        _compress_block(bw, toks, FIXED_L, FIXED_D)
    else:
        bw.put(4 | last, 3)
        bw.put(lmax + 1 - 257, 5)
        bw.put(dmax + 1 - 1, 5)
        bw.put(max_blindex + 1 - 4, 4)
        blc = gen_codes(bll)
        for r in range(max_blindex + 1):
            bw.put(bll[BL_ORDER[r]], 3)
        _send_tree(bw, ll, lmax, blc, bll)
        _send_tree(bw, dl, dmax, blc, bll)
        _compress_block(bw, toks, ll, dl)


def zlib_header(wbits, flevel):
    cmf = ((wbits - 8) << 4) | 8
    h = (cmf << 8) | (flevel << 6)
    h += 31 - (h % 31)          # as zlib's deflate.c: adds 31 when already a multiple
    return bytes([h >> 8, h & 255])


def compress(data, good, lazy, nice, chain, func, wbits=15, memlevel=8, strategy=0, pos0_matchable=False,
             too_far=4096, tail_unmatched=0, flevel=1, block_symbols=None):
    """Full zlib stream (header + deflate blocks + Adler-32)."""
    blocks = deflate_tokens(data, good, lazy, nice, chain, func, wbits, memlevel, strategy, pos0_matchable,
                            too_far, tail_unmatched, block_symbols)
    bw = BitWriter()
    for i, (toks, avail, a, b) in enumerate(blocks):
        flush_block(bw, toks, bytes(data[a:b]) if avail else None, 1 if i == len(blocks) - 1 else 0, strategy)
    bw.align()
    return zlib_header(wbits, flevel) + bytes(bw.out) + (zlib.adler32(data) & 0xffffffff).to_bytes(4, 'big')
