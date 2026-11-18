"""Bit-exact Python port of the p7zip 9.20 Deflate encoder (CPP/7zip/Compress/DeflateEncoder.cpp,
C/HuffEnc.c, C/LzFind.c Bt3Zip match finder).  Used by fmt_zip.py to regenerate the deflate streams of
ZIP members written by p7zip / 7-Zip.

Parameters (7-Zip names): passes (-mpass), fb (-mfb, fast bytes), mc (-mmc, match finder cycles,
0 = default cut value 32), algo (1 = optimal parsing with binary-tree match finder).
"""

# ---------------------------------------------------------------- constants (DeflateConst.h)
kMatchMinLen = 3
kMatchMaxLen = 258
kNumLenSymbols = 256
kNumLenSlots = 29
kSymbolEndOfBlock = 0x100
kSymbolMatch = 0x101
kMainTableSize = kSymbolMatch + kNumLenSlots          # 286
kFixedMainTableSize = kSymbolMatch + 31               # 288
kDistTableSize64 = 32
kFixedDistTableSize = 32
kLevelTableSize = 19
kTableDirectLevels = 16
kTableLevelRepNumber = 16
kTableLevel0Number = 17
kTableLevel0Number2 = 18
kNumLitLenCodesMin = 257
kNumDistCodesMin = 1
kNumLevelCodesMin = 4
kHistorySize = 1 << 15

kLenStart = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
             160, 192, 224, 255, 0, 0]
kLenDirectBits = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0]
kDistStart = [0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
              2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152]
kDistDirectBits = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
                   13, 13, 14, 14]
kLevelDirectBits = [2, 3, 7]
kCodeLengthAlphabetOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

# ---------------------------------------------------------------- DeflateEncoder.cpp constants
kNumDivPassesMax = 10
kFixedHuffmanCodeBlockSizeMax = 1 << 8
kDivideCodeBlockSizeMin = 1 << 7
kDivideBlockSizeMin = 1 << 6
kMaxUncompressedBlockSize = (1 << 16) - 1
kMatchArraySize = kMaxUncompressedBlockSize * 10
kMatchArrayLimit = kMatchArraySize - kMatchMaxLen * 4 * 2
kNumOptsBase = 1 << 12
kNumOpts = kNumOptsBase + kMatchMaxLen
kBlockUncompressedSizeThreshold = kMaxUncompressedBlockSize - kMatchMaxLen - kNumOpts
kMaxLevelBitLength = 7
kNoLiteralStatPrice = 11
kNoLenStatPrice = 11
kNoPosStatPrice = 6
kIfinityPrice = 0xFFFFFFF

# g_LenSlots / g_FastPos
LEN_SLOTS = [0] * kNumLenSymbols
for _i in range(kNumLenSlots):
    _c = kLenStart[_i]
    for _k in range(1 << kLenDirectBits[_i]):
        if _c < kNumLenSymbols:
            LEN_SLOTS[_c] = _i
        _c += 1
_FAST = []
for _s in range(18):
    _FAST += [_s] * (1 << kDistDirectBits[_s])
# full table: dist (0..32767) -> slot
POS_SLOT = [(_FAST[_d] if _d < 0x200 else _FAST[_d >> 8] + 16) for _d in range(1 << 15)]

_CRC = []
for _i in range(256):
    _r = _i
    for _j in range(8):
        _r = (_r >> 1) ^ (0xEDB88320 if _r & 1 else 0)
    _CRC.append(_r)


# ---------------------------------------------------------------- HuffEnc.c
def huffman_generate(freqs, num_symbols, max_len):
    """Returns (codes, lens) exactly as Huffman_Generate (codes not bit-reversed)."""
    MASK = 0x3FF
    lens = [0] * num_symbols
    items = [i | (freqs[i] << 10) for i in range(num_symbols) if freqs[i]]
    # counting sort by min(freq,63) keeping symbol order, last bucket heap-sorted by full key:
    # equivalent to sorting by (min(freq,63), key) with the last bucket ordered by key.
    items.sort(key=lambda v: (min(v >> 10, 63), v if (v >> 10) >= 63 else (v & MASK)))
    num = len(items)
    p = items + [0] * (num_symbols - num)
    if num < 2:
        min_code = 0
        max_code = 1
        if num == 1:
            max_code = p[0] & MASK
            if max_code == 0:
                max_code += 1
        codes = [0] * num_symbols
        codes[min_code] = 0
        codes[max_code] = 1
        lens[min_code] = lens[max_code] = 1
        return codes, lens
    i = b = e = 0
    while True:
        if i != num and (b == e or (p[i] >> 10) <= (p[b] >> 10)):
            n = i; i += 1
        else:
            n = b; b += 1
        freq = p[n] & ~MASK
        p[n] = (p[n] & MASK) | (e << 10)
        if i != num and (b == e or (p[i] >> 10) <= (p[b] >> 10)):
            m = i; i += 1
        else:
            m = b; b += 1
        freq += p[m] & ~MASK
        p[m] = (p[m] & MASK) | (e << 10)
        p[e] = (p[e] & MASK) | freq
        e += 1
        if num - e <= 1:
            break
    len_counters = [0] * 17
    e -= 1
    p[e] &= MASK
    len_counters[1] = 2
    while e > 0:
        e -= 1
        ln = (p[p[e] >> 10] >> 10) + 1
        p[e] = (p[e] & MASK) | (ln << 10)
        if ln >= max_len:
            ln = max_len - 1
            while len_counters[ln] == 0:
                ln -= 1
        len_counters[ln] -= 1
        len_counters[ln + 1] += 2
    i = 0
    for ln in range(max_len, 0, -1):
        for _ in range(len_counters[ln]):
            lens[p[i] & MASK] = ln
            i += 1
    next_codes = [0] * 17
    code = 0
    for ln in range(1, 17):
        code = (code + len_counters[ln - 1]) << 1
        next_codes[ln] = code
    codes = [0] * num_symbols
    for s in range(num_symbols):
        codes[s] = next_codes[lens[s]]
        next_codes[lens[s]] += 1
    return codes, lens


def _rev(code, ln):
    r = 0
    for _ in range(ln):
        r = (r << 1) | (code & 1)
        code >>= 1
    return r


# ---------------------------------------------------------------- bit writer
class BitOut:
    __slots__ = ('buf', 'acc', 'n')

    def __init__(self):
        self.buf = bytearray()
        self.acc = 0
        self.n = 0

    def bits(self, v, k):
        self.acc |= v << self.n
        self.n += k
        if self.n >= 32:
            acc = self.acc
            n = self.n
            buf = self.buf
            while n >= 8:
                buf.append(acc & 0xFF)
                acc >>= 8
                n -= 8
            self.acc = acc
            self.n = n

    def flush_byte(self):
        acc, n, buf = self.acc, self.n, self.buf
        while n > 0:
            buf.append(acc & 0xFF)
            acc >>= 8
            n -= 8
        self.acc = 0
        self.n = 0

    def getvalue(self):
        self.flush_byte()
        return bytes(self.buf)


# ---------------------------------------------------------------- encoder
class Encoder7z:
    def __init__(self, passes=3, fb=64, mc=0):
        nd = passes if passes else 1
        if nd == 1:
            np_ = 1
        elif nd <= kNumDivPassesMax:
            np_ = 2
        else:
            np_ = 2 + (nd - kNumDivPassesMax)
            nd = kNumDivPassesMax
        self.num_div_passes = nd
        self.num_passes = np_
        self.fb = fb
        self.cut = mc if mc else 32
        self.check_static = (np_ != 1 or nd != 1)
        self.multi = self.check_static
        self.value_block_size = (7 << 10) + (1 << 12) * nd
        # stats for honesty/debug
        self.stale_reads = 0

    # ------------------------------------------------------------ match finder (Bt3Zip)
    def _mf_init(self, data):
        self.data = data
        self.n = len(data)
        self.cbs = kHistorySize + 1
        self.hash = [0] * 65536
        self.son = [0] * (2 * self.cbs)
        self.mfpos = 0           # data index of match finder position

    def _mf_get(self, out):
        """Bt3Zip_MatchFinder_GetMatches for data position self.mfpos; appends len,dist pairs to out."""
        data = self.data
        cur = self.mfpos
        self.mfpos = cur + 1
        avail = self.n - cur
        len_limit = self.fb if avail > self.fb else avail
        if len_limit < 3:
            return
        cbs = self.cbs
        pos = cur + cbs
        cbp = cur % cbs
        hv = ((data[cur + 2] | (data[cur] << 8)) ^ _CRC[data[cur + 1]]) & 0xFFFF
        hsh = self.hash
        cur_match = hsh[hv]
        hsh[hv] = pos
        son = self.son
        ptr0 = (cbp << 1) + 1
        ptr1 = cbp << 1
        len0 = len1 = 0
        max_len = 2
        cut = self.cut
        while True:
            delta = pos - cur_match
            if cut == 0 or delta >= cbs:
                son[ptr0] = son[ptr1] = 0
                return
            cut -= 1
            pair = ((cbp - delta + (cbs if delta > cbp else 0)) << 1)
            pb = cur - delta
            ln = len0 if len0 < len1 else len1
            if data[pb + ln] == data[cur + ln]:
                ln += 1
                if ln != len_limit and data[pb + ln] == data[cur + ln]:
                    ln += 1
                    while ln != len_limit and data[pb + ln] == data[cur + ln]:
                        ln += 1
                if max_len < ln:
                    max_len = ln
                    out.append(ln)
                    out.append(delta - 1)
                    if ln == len_limit:
                        son[ptr1] = son[pair]
                        son[ptr0] = son[pair + 1]
                        return
            if data[pb + ln] < data[cur + ln]:
                son[ptr1] = cur_match
                ptr1 = pair + 1
                cur_match = son[ptr1]
                len1 = ln
            else:
                son[ptr0] = cur_match
                ptr0 = pair
                cur_match = son[ptr0]
                len0 = ln

    def _mf_skip(self, num):
        data = self.data
        cbs = self.cbs
        hsh = self.hash
        son = self.son
        for _ in range(num):
            cur = self.mfpos
            self.mfpos = cur + 1
            avail = self.n - cur
            len_limit = self.fb if avail > self.fb else avail
            if len_limit < 3:
                continue
            pos = cur + cbs
            cbp = cur % cbs
            hv = ((data[cur + 2] | (data[cur] << 8)) ^ _CRC[data[cur + 1]]) & 0xFFFF
            cur_match = hsh[hv]
            hsh[hv] = pos
            ptr0 = (cbp << 1) + 1
            ptr1 = cbp << 1
            len0 = len1 = 0
            cut = self.cut
            while True:
                delta = pos - cur_match
                if cut == 0 or delta >= cbs:
                    son[ptr0] = son[ptr1] = 0
                    break
                cut -= 1
                pair = ((cbp - delta + (cbs if delta > cbp else 0)) << 1)
                pb = cur - delta
                ln = len0 if len0 < len1 else len1
                if data[pb + ln] == data[cur + ln]:
                    ln += 1
                    while ln != len_limit and data[pb + ln] == data[cur + ln]:
                        ln += 1
                    if ln == len_limit:
                        son[ptr1] = son[pair]
                        son[ptr0] = son[pair + 1]
                        break
                if data[pb + ln] < data[cur + ln]:
                    son[ptr1] = cur_match
                    ptr1 = pair + 1
                    cur_match = son[ptr1]
                    len1 = ln
                else:
                    son[ptr0] = cur_match
                    ptr0 = pair
                    cur_match = son[ptr0]
                    len0 = ln

    # ------------------------------------------------------------ CCoder::GetMatches, pass 1 only
    def _gm1(self, mp):
        """First-pass GetMatches: runs the match finder, stores the record at mem[mp]; returns new m_Pos.
        (In later passes the record is just read back: m_Pos += mem[m_Pos] + 1.)"""
        mem = self.mem
        tmp = []
        self._mf_get(tmp)
        num_pairs = len(tmp)
        mem[mp] = num_pairs
        if num_pairs:
            mem[mp + 1:mp + 1 + num_pairs] = tmp
            ln = tmp[num_pairs - 2]
            fb = self.fb
            if ln == fb and fb != kMatchMaxLen:
                cur = self.mfpos - 1
                pb = cur - (tmp[num_pairs - 1] + 1)
                num_avail = self.n - cur
                if num_avail > kMatchMaxLen:
                    num_avail = kMatchMaxLen
                data = self.data
                while ln < num_avail and data[cur + ln] == data[pb + ln]:
                    ln += 1
                mem[mp + num_pairs - 1] = ln
        mp += num_pairs + 1
        if mp > self.written:
            self.written = mp
        return mp

    def _backward(self, cur):
        opt_pp = self.opt_pp
        opt_bp = self.opt_bp
        self.opt_end = cur
        pos_mem = opt_pp[cur]
        back_mem = opt_bp[cur]
        while True:
            pos_prev = pos_mem
            back_cur = back_mem
            back_mem = opt_bp[pos_prev]
            pos_mem = opt_pp[pos_prev]
            opt_bp[pos_prev] = back_cur
            opt_pp[pos_prev] = cur
            cur = pos_prev
            if cur <= 0:
                break
        self.back_res = opt_bp[0]
        self.opt_cur = opt_pp[0]
        return self.opt_cur

    def _get_optimal_rest(self, md, ndp, dp):
        """GetOptimal after its first GetMatches returned a non-empty record at mem[md].
        dp = data position of the decision.  self.m_pos already points after that record."""
        opt_pp = self.opt_pp
        opt_bp = self.opt_bp
        opt_pr = self.opt_pr
        mem = self.mem
        sp = self.second_pass
        len_main = mem[md + ndp - 1]
        fb = self.fb
        if len_main > fb:
            self.back_res = mem[md + ndp]
            if not sp:
                self._mf_skip(len_main - 1)
            return len_main
        lit_p = self.lit_prices
        len_p = self.len_prices
        pos_p = self.pos_prices
        PS = POS_SLOT
        data = self.data
        opt_pr[1] = lit_p[data[dp]]
        opt_pp[1] = 0
        opt_pr[2] = kIfinityPrice
        opt_pp[2] = 1
        offs = md + 1
        nxt = mem[offs]
        distance = mem[offs + 1]
        dprice = pos_p[PS[distance]]
        for i in range(kMatchMinLen, len_main + 1):
            opt_pp[i] = 0
            opt_bp[i] = distance
            opt_pr[i] = len_p[i - kMatchMinLen] + dprice
            if i == nxt:
                offs += 2
                if offs < md + 1 + ndp:
                    nxt = mem[offs]
                    distance = mem[offs + 1]
                    dprice = pos_p[PS[distance]]
        cur = 0
        len_end = len_main
        m_pos = self.m_pos
        while True:
            cur += 1
            if cur == len_end or cur == kNumOptsBase or m_pos >= kMatchArrayLimit:
                self.m_pos = m_pos
                return self._backward(cur)
            md = m_pos
            if sp:
                ndp = mem[md]
                m_pos = md + ndp + 1
            else:
                m_pos = self._gm1(md)
                ndp = mem[md]
            cur_price = opt_pr[cur]
            c1 = cur_price + lit_p[data[dp + cur]]
            if c1 < opt_pr[cur + 1]:
                opt_pr[cur + 1] = c1
                opt_pp[cur + 1] = cur
            if ndp == 0:
                continue
            new_len = mem[md + ndp - 1]
            if new_len > fb:
                self.m_pos = m_pos
                # note: C checks the long match before the literal update; the literal update above
                # only touches opt[cur+1], which Backward(cur) never reads.
                ln = self._backward(cur)
                opt_bp[cur] = mem[md + ndp]
                self.opt_end = cur + new_len
                opt_pp[cur] = self.opt_end
                if not sp:
                    self._mf_skip(new_len - 1)
                return ln
            while len_end < cur + new_len:
                len_end += 1
                opt_pr[len_end] = kIfinityPrice
            end = md + 1 + ndp
            offs = md + 1
            distance = mem[offs + 1]
            cp = cur_price + pos_p[PS[distance]]
            nxt = mem[offs]
            j = cur + kMatchMinLen
            for lp in len_p:
                p = cp + lp
                if p < opt_pr[j]:
                    opt_pr[j] = p
                    opt_pp[j] = cur
                    opt_bp[j] = distance
                if j - cur == nxt:
                    offs += 2
                    if offs == end:
                        break
                    distance = mem[offs + 1]
                    cp = cur_price + pos_p[PS[distance]]
                    nxt = mem[offs]
                j += 1

    # ------------------------------------------------------------ TryBlock (fused with GetOptimal)
    def _try_block(self):
        main_freqs = [0] * kFixedMainTableSize
        dist_freqs = [0] * kDistTableSize64
        values = []
        app = values.append
        block_size = self.block_size_res
        bsr = 0
        data = self.data
        mem = self.mem
        sp = self.second_pass
        vbs = self.value_block_size
        n = self.n
        LS = LEN_SLOTS
        PS = POS_SLOT
        opt_pp = self.opt_pp
        opt_bp = self.opt_bp
        dp0 = self.mfpos - self.addoff     # data position of block start
        dp = dp0
        m_pos = self.m_pos
        nv = 0
        limit = kMatchArrayLimit
        while True:
            oc = self.opt_cur
            if oc == self.opt_end:
                if m_pos >= limit or bsr >= block_size or (not sp and (n == self.mfpos or nv >= vbs)):
                    break
                self.opt_cur = self.opt_end = 0
                md = m_pos
                if sp:
                    ndp = mem[md]
                    if ndp == 0:
                        # Run of empty match records: each is a literal decision.  The C loop re-checks
                        # its stop conditions before every decision; the run length is capped so
                        # that the same decision sequence results.
                        kmax = block_size - bsr
                        if limit - md < kmax:
                            kmax = limit - md
                        e = md + 1
                        stop = md + kmax
                        while e < stop and mem[e] == 0:
                            e += 1
                        k = e - md
                        seg = data[dp:dp + k]
                        values.extend(seg)
                        for b in seg:
                            main_freqs[b] += 1
                        nv += k
                        dp += k
                        bsr += k
                        m_pos = e
                        continue
                    m_pos = md + ndp + 1
                else:
                    m_pos = self._gm1(md)
                    ndp = mem[md]
                if ndp == 0:
                    b = data[dp]
                    main_freqs[b] += 1
                    app(b)
                    nv += 1
                    dp += 1
                    bsr += 1
                    continue
                self.m_pos = m_pos
                ln = self._get_optimal_rest(md, ndp, dp)
                m_pos = self.m_pos
            else:
                ln = opt_pp[oc] - oc
                self.back_res = opt_bp[oc]
                self.opt_cur = opt_pp[oc]
            if ln >= kMatchMinLen:
                nl = ln - kMatchMinLen
                pos = self.back_res
                main_freqs[kSymbolMatch + LS[nl]] += 1
                dist_freqs[PS[pos]] += 1
                app((nl, pos))
            else:
                b = data[dp]
                main_freqs[b] += 1
                app(b)
            nv += 1
            dp += ln
            bsr += ln
        if sp and m_pos > self.written:
            self.stale_reads += 1
        self.m_pos = m_pos
        main_freqs[kSymbolEndOfBlock] += 1
        self.addoff = self.mfpos - dp0
        self.second_pass = True
        self.block_size_res = bsr
        self.main_freqs = main_freqs
        self.dist_freqs = dist_freqs
        self.values = values

    def _set_prices(self, ll, dl):
        self.lit_prices = [(ll[i] if ll[i] else kNoLiteralStatPrice) for i in range(256)]
        lp = []
        for i in range(kNumLenSymbols):
            slot = LEN_SLOTS[i]
            pr = ll[kSymbolMatch + slot]
            lp.append(((pr if pr else kNoLenStatPrice) + kLenDirectBits[slot]) & 0xFF)
        self.len_prices = lp
        self.pos_prices = [(((dl[i] if dl[i] else kNoPosStatPrice) + kDistDirectBits[i]) & 0xFF)
                           for i in range(kDistTableSize64)]

    def _make_tables(self, max_huff_len):
        self.main_codes, self.new_ll = huffman_generate(self.main_freqs, kFixedMainTableSize, max_huff_len)
        self.dist_codes, self.new_dl = huffman_generate(self.dist_freqs, kDistTableSize64, max_huff_len)

    def _lz_block_price(self):
        ll, dl = self.new_ll, self.new_dl
        mf, df = self.main_freqs, self.dist_freqs
        price = 0
        for i in range(kFixedMainTableSize):
            price += ll[i] * mf[i]
        for i in range(kSymbolMatch, kFixedMainTableSize):
            price += mf[i] * kLenDirectBits[i - kSymbolMatch]
        for i in range(kDistTableSize64):
            price += (dl[i] + kDistDirectBits[i]) * df[i]
        return price

    @staticmethod
    def _level_table_dummy(levels, num_levels, freqs):
        prev_len = 0xFF
        next_len = levels[0]
        count = 0
        max_count, min_count = (138, 3) if next_len == 0 else (7, 4)
        for n in range(num_levels):
            cur_len = next_len
            next_len = levels[n + 1] if n < num_levels - 1 else 0xFF
            count += 1
            if count < max_count and cur_len == next_len:
                continue
            if count < min_count:
                freqs[cur_len] += count
            elif cur_len != 0:
                if cur_len != prev_len:
                    freqs[cur_len] += 1
                    count -= 1
                freqs[kTableLevelRepNumber] += 1
            elif count <= 10:
                freqs[kTableLevel0Number] += 1
            else:
                freqs[kTableLevel0Number2] += 1
            count = 0
            prev_len = cur_len
            if next_len == 0:
                max_count, min_count = 138, 3
            elif cur_len == next_len:
                max_count, min_count = 6, 3
            else:
                max_count, min_count = 7, 4

    def _level_table_code(self, levels, num_levels, lens, codes):
        w = self.out.bits
        prev_len = 0xFF
        next_len = levels[0]
        count = 0
        max_count, min_count = (138, 3) if next_len == 0 else (7, 4)
        for n in range(num_levels):
            cur_len = next_len
            next_len = levels[n + 1] if n < num_levels - 1 else 0xFF
            count += 1
            if count < max_count and cur_len == next_len:
                continue
            if count < min_count:
                for _ in range(count):
                    w(codes[cur_len], lens[cur_len])
            elif cur_len != 0:
                if cur_len != prev_len:
                    w(codes[cur_len], lens[cur_len])
                    count -= 1
                w(codes[kTableLevelRepNumber], lens[kTableLevelRepNumber])
                w(count - 3, 2)
            elif count <= 10:
                w(codes[kTableLevel0Number], lens[kTableLevel0Number])
                w(count - 3, 3)
            else:
                w(codes[kTableLevel0Number2], lens[kTableLevel0Number2])
                w(count - 11, 7)
            count = 0
            prev_len = cur_len
            if next_len == 0:
                max_count, min_count = 138, 3
            elif cur_len == next_len:
                max_count, min_count = 6, 3
            else:
                max_count, min_count = 7, 4

    def _try_dyn_block(self, ti, num_passes):
        t = self.tables[ti]
        self.block_size_res = t['bsr']
        pos_temp = t['pos']
        self._set_prices(t['ll'], t['dl'])
        for _ in range(num_passes):
            self.m_pos = pos_temp
            self._try_block()
            nv = len(self.values)
            nhb = 12 if nv > 18000 else (11 if nv > 7000 else (10 if nv > 2000 else 9))
            self._make_tables(nhb)
            self._set_prices(self.new_ll, self.new_dl)
        t['ll'] = list(self.new_ll)
        t['dl'] = list(self.new_dl)
        ll, dl = self.new_ll, self.new_dl
        nll = kMainTableSize
        while nll > kNumLitLenCodesMin and ll[nll - 1] == 0:
            nll -= 1
        ndl = kDistTableSize64
        while ndl > kNumDistCodesMin and dl[ndl - 1] == 0:
            ndl -= 1
        self.num_ll, self.num_dl = nll, ndl
        lf = [0] * kLevelTableSize
        self._level_table_dummy(ll, nll, lf)
        self._level_table_dummy(dl, ndl, lf)
        self.level_codes, self.level_lens = huffman_generate(lf, kLevelTableSize, kMaxLevelBitLength)
        nlc = kNumLevelCodesMin
        ll_levels = []
        for i in range(kLevelTableSize):
            lv = self.level_lens[kCodeLengthAlphabetOrder[i]]
            if lv > 0 and i >= nlc:
                nlc = i + 1
            ll_levels.append(lv)
        self.num_level_codes = nlc
        self.level_levels = ll_levels
        price = self._lz_block_price()
        for i in range(kLevelTableSize):
            price += lf[i] * self.level_lens[i]
        for i in range(kTableDirectLevels, kLevelTableSize):
            price += lf[i] * kLevelDirectBits[i - kTableDirectLevels]
        return price + 5 + 5 + 4 + nlc * 3 + 1 + 2

    def _set_fixed_levels(self):
        ll = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
        dl = [5] * kFixedDistTableSize
        return ll, dl

    def _try_fixed_block(self, ti):
        t = self.tables[ti]
        self.block_size_res = t['bsr']
        self.m_pos = t['pos']
        self.new_ll, self.new_dl = self._set_fixed_levels()
        self._set_prices(self.new_ll, self.new_dl)
        self._try_block()
        return 1 + 2 + self._lz_block_price()

    @staticmethod
    def _store_price(block_size, bit_position):
        price = 0
        while True:
            nbp = (bit_position + 3) & 7
            align = (8 - nbp) if nbp > 0 else 0
            cur = block_size if block_size < (1 << 16) else (1 << 16) - 1
            price += 3 + align + 32 + cur * 8
            bit_position = 0
            block_size -= cur
            if block_size == 0:
                return price

    def _table(self, ti):
        t = self.tables.get(ti)
        if t is None:
            t = self.tables[ti] = {}
        return t

    def _get_block_price(self, ti, num_div_passes):
        t = self.tables[ti]
        t['static'] = False
        price = self._try_dyn_block(ti, self.num_passes)
        t['bsr'] = self.block_size_res
        num_values = len(self.values)
        pos_temp = self.m_pos
        add_end = self.addoff
        if self.check_static and num_values <= kFixedHuffmanCodeBlockSizeMax:
            fixed_price = self._try_fixed_block(ti)
            t['static'] = fixed_price < price
            if t['static']:
                price = fixed_price
        store_price = self._store_price(self.block_size_res, 0)
        t['store'] = store_price <= price
        if t['store']:
            price = store_price
        t['sub'] = False
        if num_div_passes > 1 and num_values >= kDivideCodeBlockSizeMin:
            t0 = self._table(ti << 1)
            t0['ll'] = list(t['ll']); t0['dl'] = list(t['dl'])
            t0['bsr'] = t['bsr'] >> 1
            t0['pos'] = t['pos']
            sub_price = self._get_block_price(ti << 1, num_div_passes - 1)
            bs2 = t['bsr'] - t0['bsr']
            if t0['bsr'] >= kDivideBlockSizeMin and bs2 >= kDivideBlockSizeMin:
                t1 = self._table((ti << 1) + 1)
                t1['ll'] = list(t['ll']); t1['dl'] = list(t['dl'])
                t1['bsr'] = bs2
                t1['pos'] = self.m_pos
                self.addoff -= t0['bsr']
                sub_price += self._get_block_price((ti << 1) + 1, num_div_passes - 1)
                t['sub'] = sub_price < price
                if t['sub']:
                    price = sub_price
        self.addoff = add_end
        self.m_pos = pos_temp
        return price

    def _write_block(self):
        w = self.out.bits
        ll, dl = self.new_ll, self.new_dl
        mc = [_rev(self.main_codes[i], ll[i]) for i in range(kFixedMainTableSize)]
        dc = [_rev(self.dist_codes[i], dl[i]) for i in range(kDistTableSize64)]
        for v in self.values:
            if type(v) is int:
                w(mc[v], ll[v])
            else:
                ln, dist = v
                slot = LEN_SLOTS[ln]
                s = kSymbolMatch + slot
                w(mc[s], ll[s])
                w(ln - kLenStart[slot], kLenDirectBits[slot])
                ps = POS_SLOT[dist]
                w(dc[ps], dl[ps])
                w(dist - kDistStart[ps], kDistDirectBits[ps])
        w(mc[kSymbolEndOfBlock], ll[kSymbolEndOfBlock])

    def _write_store_block(self, block_size, add_off, final):
        out = self.out
        data = self.data
        while True:
            cur = block_size if block_size < (1 << 16) else (1 << 16) - 1
            block_size -= cur
            out.bits(1 if (final and block_size == 0) else 0, 1)
            out.bits(0, 2)
            out.flush_byte()
            out.bits(cur, 16)
            out.bits((~cur) & 0xFFFF, 16)
            start = self.mfpos - add_off
            out.flush_byte()
            out.buf += data[start:start + cur]
            add_off -= cur
            if block_size == 0:
                return

    def _code_block(self, ti, final):
        t = self.tables[ti]
        if t['sub']:
            self._code_block(ti << 1, False)
            self._code_block((ti << 1) + 1, final)
            return
        if t['store']:
            self._write_store_block(t['bsr'], self.addoff, final)
        else:
            w = self.out.bits
            w(1 if final else 0, 1)
            if t['static']:
                w(1, 2)
                self._try_fixed_block(ti)
                self.main_freqs = [1 << (9 - self.new_ll[i]) for i in range(kFixedMainTableSize)]
                self.dist_freqs = [1 << (9 - self.new_dl[i]) for i in range(kFixedDistTableSize)]
                values = self.values
                self._make_tables(9)
                self.values = values
            else:
                if self.num_div_passes > 1 or self.check_static:
                    self._try_dyn_block(ti, 1)
                w(2, 2)
                w(self.num_ll - kNumLitLenCodesMin, 5)
                w(self.num_dl - kNumDistCodesMin, 5)
                w(self.num_level_codes - kNumLevelCodesMin, 4)
                for i in range(self.num_level_codes):
                    w(self.level_levels[i], 3)
                lc = [_rev(self.level_codes[i], self.level_lens[i]) for i in range(kLevelTableSize)]
                self._level_table_code(self.new_ll, self.num_ll, self.level_lens, lc)
                self._level_table_code(self.new_dl, self.num_dl, self.level_lens, lc)
            self._write_block()
        self.addoff -= t['bsr']

    def compress(self, data):
        if not self.multi:
            raise NotImplementedError('single-pass mode not ported (not used by this archive)')
        self._mf_init(data)
        self.out = BitOut()
        self.mem = [0] * (kMatchArraySize + 2 * kMatchMaxLen + 8)
        self.written = 0
        self.opt_pp = [0] * (kNumOpts + 2)
        self.opt_bp = [0] * (kNumOpts + 2)
        self.opt_pr = [0] * (kNumOpts + 2)
        self.opt_end = self.opt_cur = 0
        self.back_res = 0
        self.addoff = 0
        self.tables = {}
        t = self._table(1)
        t['pos'] = 0
        ll = [8] * 256 + [13] + [5] * (kFixedMainTableSize - 257)
        t['ll'] = ll
        t['dl'] = [5] * kFixedDistTableSize
        while True:
            t['bsr'] = kBlockUncompressedSizeThreshold
            self.second_pass = False
            self.written = 0
            self._get_block_price(1, self.num_div_passes)
            self._code_block(1, self.n - self.mfpos == 0)
            if self.n - self.mfpos == 0:
                break
        return self.out.getvalue()


def deflate_7z(data, passes=3, fb=64, mc=0):
    return Encoder7z(passes, fb, mc).compress(bytes(data))
