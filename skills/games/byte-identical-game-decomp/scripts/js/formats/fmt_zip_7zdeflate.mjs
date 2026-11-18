// Bit-exact JavaScript port of scripts/formats/fmt_zip_7zdeflate.py: the p7zip 9.20 Deflate encoder
// (CPP/7zip/Compress/DeflateEncoder.cpp, C/HuffEnc.c, C/LzFind.c Bt3Zip match finder). Used by fmt_zip.mjs to
// regenerate the deflate streams of ZIP members written by p7zip / 7-Zip.
//
// Parameters (7-Zip names): passes (-mpass), fb (-mfb, fast bytes), mc (-mmc, match finder cycles,
// 0 = default cut value 32), algo (1 = optimal parsing with binary-tree match finder).
//
// Same decisions as the Python port, written for speed: typed arrays for every table, match records written
// straight into the match memory, and block values packed into an Int32Array (literal: byte value;
// match: ((len - 3 + 1) << 16) | distance).

// ---------------------------------------------------------------- constants (DeflateConst.h)
const kMatchMinLen = 3
const kMatchMaxLen = 258
const kNumLenSymbols = 256
const kNumLenSlots = 29
const kSymbolEndOfBlock = 0x100
const kSymbolMatch = 0x101
const kMainTableSize = kSymbolMatch + kNumLenSlots          // 286
const kFixedMainTableSize = kSymbolMatch + 31               // 288
const kDistTableSize64 = 32
const kFixedDistTableSize = 32
const kLevelTableSize = 19
const kTableDirectLevels = 16
const kTableLevelRepNumber = 16
const kTableLevel0Number = 17
const kTableLevel0Number2 = 18
const kNumLitLenCodesMin = 257
const kNumDistCodesMin = 1
const kNumLevelCodesMin = 4
const kHistorySize = 1 << 15

const kLenStart = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
  160, 192, 224, 255, 0, 0]
const kLenDirectBits = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0]
const kDistStart = [0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
  2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152]
const kDistDirectBits = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
  13, 13, 14, 14]
const kLevelDirectBits = [2, 3, 7]
const kCodeLengthAlphabetOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

// ---------------------------------------------------------------- DeflateEncoder.cpp constants
const kNumDivPassesMax = 10
const kFixedHuffmanCodeBlockSizeMax = 1 << 8
const kDivideCodeBlockSizeMin = 1 << 7
const kDivideBlockSizeMin = 1 << 6
const kMaxUncompressedBlockSize = (1 << 16) - 1
const kMatchArraySize = kMaxUncompressedBlockSize * 10
const kMatchArrayLimit = kMatchArraySize - kMatchMaxLen * 4 * 2
const kNumOptsBase = 1 << 12
const kNumOpts = kNumOptsBase + kMatchMaxLen
const kBlockUncompressedSizeThreshold = kMaxUncompressedBlockSize - kMatchMaxLen - kNumOpts
const kMaxLevelBitLength = 7
const kNoLiteralStatPrice = 11
const kNoLenStatPrice = 11
const kNoPosStatPrice = 6
const kIfinityPrice = 0xFFFFFFF

// g_LenSlots / g_FastPos
const LEN_SLOTS = new Uint8Array(kNumLenSymbols)
for (let i = 0; i < kNumLenSlots; i++) {
  let c = kLenStart[i]
  for (let k = 0; k < (1 << kLenDirectBits[i]); k++) {
    if (c < kNumLenSymbols) LEN_SLOTS[c] = i
    c++
  }
}
const FAST = []
for (let s = 0; s < 18; s++) for (let k = 0; k < (1 << kDistDirectBits[s]); k++) FAST.push(s)
// full table: dist (0..32767) -> slot
const POS_SLOT = new Uint8Array(1 << 15)
for (let d = 0; d < (1 << 15); d++) POS_SLOT[d] = d < 0x200 ? FAST[d] : FAST[d >> 8] + 16

const CRC = new Int32Array(256)
for (let i = 0; i < 256; i++) {
  let r = i
  for (let j = 0; j < 8; j++) r = (r & 1) ? ((r >>> 1) ^ 0xEDB88320) : (r >>> 1)
  CRC[i] = r
}

// ---------------------------------------------------------------- HuffEnc.c
// Fills codes/lens (length num_symbols) exactly as Huffman_Generate (codes not bit-reversed).
const H_P = new Int32Array(kFixedMainTableSize + 32)
const H_BUCKET = new Int32Array(64)
const H_LEN_COUNTERS = new Int32Array(18)
const H_NEXT_CODES = new Int32Array(17)
function huffmanGenerateInto(freqs, numSymbols, maxLen, codes, lens) {
  const MASK = 0x3FF
  lens.fill(0, 0, numSymbols)
  codes.fill(0, 0, numSymbols)
  const p = H_P
  p.fill(0, 0, numSymbols)
  // counting sort by min(freq,63) keeping symbol order, last bucket sorted by full key (freq << 10 | symbol):
  // the order the Python port gets from sorting by (min(freq,63), key).
  const bucket = H_BUCKET
  bucket.fill(0)
  let num = 0
  for (let i = 0; i < numSymbols; i++) {
    const f = freqs[i]
    if (f) { bucket[f < 63 ? f : 63]++; num++ }
  }
  let start = 0
  for (let k = 0; k < 64; k++) { const c = bucket[k]; bucket[k] = start; start += c }
  const start63 = bucket[63]
  for (let i = 0; i < numSymbols; i++) {
    const f = freqs[i]
    if (f) p[bucket[f < 63 ? f : 63]++] = i | (f << 10)
  }
  if (num - start63 > 1) p.subarray(start63, num).sort()      // typed-array sort: numeric
  if (num < 2) {
    const minCode = 0
    let maxCode = 1
    if (num === 1) {
      maxCode = p[0] & MASK
      if (maxCode === 0) maxCode += 1
    }
    codes[minCode] = 0
    codes[maxCode] = 1
    lens[minCode] = 1
    lens[maxCode] = 1
    return
  }
  let i = 0, b = 0, e = 0
  for (;;) {
    let n, m
    if (i !== num && (b === e || (p[i] >> 10) <= (p[b] >> 10))) { n = i; i++ } else { n = b; b++ }
    let freq = p[n] & ~MASK
    p[n] = (p[n] & MASK) | (e << 10)
    if (i !== num && (b === e || (p[i] >> 10) <= (p[b] >> 10))) { m = i; i++ } else { m = b; b++ }
    freq += p[m] & ~MASK
    p[m] = (p[m] & MASK) | (e << 10)
    p[e] = (p[e] & MASK) | freq
    e++
    if (num - e <= 1) break
  }
  const lenCounters = H_LEN_COUNTERS
  lenCounters.fill(0)
  e--
  p[e] &= MASK
  lenCounters[1] = 2
  while (e > 0) {
    e--
    let ln = (p[p[e] >> 10] >> 10) + 1
    p[e] = (p[e] & MASK) | (ln << 10)
    if (ln >= maxLen) {
      ln = maxLen - 1
      while (lenCounters[ln] === 0) ln--
    }
    lenCounters[ln]--
    lenCounters[ln + 1] += 2
  }
  i = 0
  for (let ln = maxLen; ln > 0; ln--) {
    for (let k = lenCounters[ln]; k > 0; k--) {
      lens[p[i] & MASK] = ln
      i++
    }
  }
  const nextCodes = H_NEXT_CODES
  nextCodes.fill(0)
  let code = 0
  for (let ln = 1; ln < 17; ln++) {
    code = (code + lenCounters[ln - 1]) << 1
    nextCodes[ln] = code
  }
  for (let s = 0; s < numSymbols; s++) {
    codes[s] = nextCodes[lens[s]]
    nextCodes[lens[s]]++
  }
}

// Same result shape as the Python function: [codes, lens] as plain arrays.
export function huffman_generate(freqs, numSymbols, maxLen) {
  const codes = new Int32Array(numSymbols)
  const lens = new Int32Array(numSymbols)
  huffmanGenerateInto(freqs, numSymbols, maxLen, codes, lens)
  return [Array.from(codes), Array.from(lens)]
}

function rev(code, ln) {
  let r = 0
  for (let k = 0; k < ln; k++) {
    r = (r << 1) | (code & 1)
    code >>>= 1
  }
  return r
}

// ---------------------------------------------------------------- bit writer
class BitOut {
  constructor(cap) {
    this.buf = new Uint8Array(Math.max(cap, 1024))
    this.len = 0
    this.acc = 0
    this.n = 0
  }

  grow(need) {
    if (this.len + need <= this.buf.length) return
    let c = this.buf.length * 2
    while (c < this.len + need) c *= 2
    const nb = new Uint8Array(c)
    nb.set(this.buf.subarray(0, this.len))
    this.buf = nb
  }

  bits(v, k) {
    let acc = this.acc | (v << this.n)
    let n = this.n + k
    if (n >= 8) {
      if (this.len + 4 > this.buf.length) this.grow(4)
      const buf = this.buf
      while (n >= 8) {
        buf[this.len++] = acc & 0xFF
        acc >>>= 8
        n -= 8
      }
    }
    this.acc = acc
    this.n = n
  }

  flushByte() {
    if (this.n > 0) {
      this.grow(1)
      this.buf[this.len++] = this.acc & 0xFF
    }
    this.acc = 0
    this.n = 0
  }

  appendBytes(src) {
    this.grow(src.length)
    this.buf.set(src, this.len)
    this.len += src.length
  }

  getvalue() {
    this.flushByte()
    return Buffer.from(this.buf.buffer, this.buf.byteOffset, this.len)
  }
}

function newTable() {
  return { ll: new Int32Array(kFixedMainTableSize), dl: new Int32Array(kDistTableSize64), bsr: 0, pos: 0,
    static: false, store: false, sub: false }
}

// ---------------------------------------------------------------- encoder
export class Encoder7z {
  constructor(passes = 3, fb = 64, mc = 0) {
    let nd = passes ? passes : 1
    let np
    if (nd === 1) np = 1
    else if (nd <= kNumDivPassesMax) np = 2
    else {
      np = 2 + (nd - kNumDivPassesMax)
      nd = kNumDivPassesMax
    }
    this.num_div_passes = nd
    this.num_passes = np
    this.fb = fb
    this.cut = mc ? mc : 32
    this.check_static = (np !== 1 || nd !== 1)
    this.multi = this.check_static
    this.value_block_size = (7 << 10) + (1 << 12) * nd
    this.stale_reads = 0
  }

  // ------------------------------------------------------------ match finder (Bt3Zip)
  mfInit(data) {
    this.data = data
    this.n = data.length
    this.cbs = kHistorySize + 1
    this.hash = new Int32Array(65536)
    this.son = new Int32Array(2 * this.cbs)
    this.mfpos = 0
  }

  // CCoder::GetMatches, pass 1 only: Bt3Zip_MatchFinder_GetMatches for data position mfpos, record stored
  // at mem[mp] (count, then len/dist-1 pairs); returns the new m_Pos.
  gm1(mp) {
    const data = this.data
    const mem = this.mem
    const cur = this.mfpos
    this.mfpos = cur + 1
    const avail = this.n - cur
    const fb = this.fb
    const lenLimit = avail > fb ? fb : avail
    let o = mp + 1
    if (lenLimit >= 3) {
      const cbs = this.cbs
      const pos = cur + cbs
      const cbp = cur % cbs
      const hv = ((data[cur + 2] | (data[cur] << 8)) ^ CRC[data[cur + 1]]) & 0xFFFF
      const hsh = this.hash
      let curMatch = hsh[hv]
      hsh[hv] = pos
      const son = this.son
      let ptr0 = (cbp << 1) + 1
      let ptr1 = cbp << 1
      let len0 = 0, len1 = 0
      let maxLen = 2
      let cut = this.cut
      for (;;) {
        const delta = pos - curMatch
        if (cut === 0 || delta >= cbs) {
          son[ptr0] = 0
          son[ptr1] = 0
          break
        }
        cut--
        const pair = (cbp - delta + (delta > cbp ? cbs : 0)) << 1
        const pb = cur - delta
        let ln = len0 < len1 ? len0 : len1
        if (data[pb + ln] === data[cur + ln]) {
          ln++
          if (ln !== lenLimit && data[pb + ln] === data[cur + ln]) {
            ln++
            while (ln !== lenLimit && data[pb + ln] === data[cur + ln]) ln++
          }
          if (maxLen < ln) {
            maxLen = ln
            mem[o++] = ln
            mem[o++] = delta - 1
            if (ln === lenLimit) {
              son[ptr1] = son[pair]
              son[ptr0] = son[pair + 1]
              break
            }
          }
        }
        if (data[pb + ln] < data[cur + ln]) {
          son[ptr1] = curMatch
          ptr1 = pair + 1
          curMatch = son[ptr1]
          len1 = ln
        } else {
          son[ptr0] = curMatch
          ptr0 = pair
          curMatch = son[ptr0]
          len0 = ln
        }
      }
    }
    const numPairs = o - mp - 1
    mem[mp] = numPairs
    if (numPairs) {
      let ln = mem[mp + numPairs - 1]
      if (ln === fb && fb !== kMatchMaxLen) {
        const pb = cur - (mem[mp + numPairs] + 1)
        let numAvail = this.n - cur
        if (numAvail > kMatchMaxLen) numAvail = kMatchMaxLen
        while (ln < numAvail && data[cur + ln] === data[pb + ln]) ln++
        mem[mp + numPairs - 1] = ln
      }
    }
    mp += numPairs + 1
    if (mp > this.written) this.written = mp
    return mp
  }

  mfSkip(num) {
    const data = this.data
    const cbs = this.cbs
    const hsh = this.hash
    const son = this.son
    const fb = this.fb
    const n = this.n
    for (let it = 0; it < num; it++) {
      const cur = this.mfpos
      this.mfpos = cur + 1
      const avail = n - cur
      const lenLimit = avail > fb ? fb : avail
      if (lenLimit < 3) continue
      const pos = cur + cbs
      const cbp = cur % cbs
      const hv = ((data[cur + 2] | (data[cur] << 8)) ^ CRC[data[cur + 1]]) & 0xFFFF
      let curMatch = hsh[hv]
      hsh[hv] = pos
      let ptr0 = (cbp << 1) + 1
      let ptr1 = cbp << 1
      let len0 = 0, len1 = 0
      let cut = this.cut
      for (;;) {
        const delta = pos - curMatch
        if (cut === 0 || delta >= cbs) {
          son[ptr0] = 0
          son[ptr1] = 0
          break
        }
        cut--
        const pair = (cbp - delta + (delta > cbp ? cbs : 0)) << 1
        const pb = cur - delta
        let ln = len0 < len1 ? len0 : len1
        if (data[pb + ln] === data[cur + ln]) {
          ln++
          while (ln !== lenLimit && data[pb + ln] === data[cur + ln]) ln++
          if (ln === lenLimit) {
            son[ptr1] = son[pair]
            son[ptr0] = son[pair + 1]
            break
          }
        }
        if (data[pb + ln] < data[cur + ln]) {
          son[ptr1] = curMatch
          ptr1 = pair + 1
          curMatch = son[ptr1]
          len1 = ln
        } else {
          son[ptr0] = curMatch
          ptr0 = pair
          curMatch = son[ptr0]
          len0 = ln
        }
      }
    }
  }

  backward(cur) {
    const optPP = this.optPP
    const optBP = this.optBP
    this.optEnd = cur
    let posMem = optPP[cur]
    let backMem = optBP[cur]
    for (;;) {
      const posPrev = posMem
      const backCur = backMem
      backMem = optBP[posPrev]
      posMem = optPP[posPrev]
      optBP[posPrev] = backCur
      optPP[posPrev] = cur
      cur = posPrev
      if (cur <= 0) break
    }
    this.backRes = optBP[0]
    this.optCur = optPP[0]
    return this.optCur
  }

  // GetOptimal after its first GetMatches returned a non-empty record at mem[md].
  // dp = data position of the decision. this.mPos already points after that record.
  getOptimalRest(md, ndp, dp) {
    const optPP = this.optPP
    const optBP = this.optBP
    const optPR = this.optPR
    const mem = this.mem
    const sp = this.secondPass
    const lenMain = mem[md + ndp - 1]
    const fb = this.fb
    if (lenMain > fb) {
      this.backRes = mem[md + ndp]
      if (!sp) this.mfSkip(lenMain - 1)
      return lenMain
    }
    const litP = this.litPrices
    const lenP = this.lenPrices
    const posP = this.posPrices
    const PS = POS_SLOT
    const data = this.data
    optPR[1] = litP[data[dp]]
    optPP[1] = 0
    optPR[2] = kIfinityPrice
    optPP[2] = 1
    let offs = md + 1
    let nxt = mem[offs]
    let distance = mem[offs + 1]
    let dprice = posP[PS[distance]]
    for (let i = kMatchMinLen; i <= lenMain; i++) {
      optPP[i] = 0
      optBP[i] = distance
      optPR[i] = lenP[i - kMatchMinLen] + dprice
      if (i === nxt) {
        offs += 2
        if (offs < md + 1 + ndp) {
          nxt = mem[offs]
          distance = mem[offs + 1]
          dprice = posP[PS[distance]]
        }
      }
    }
    let cur = 0
    let lenEnd = lenMain
    let mPos = this.mPos
    for (;;) {
      cur++
      if (cur === lenEnd || cur === kNumOptsBase || mPos >= kMatchArrayLimit) {
        this.mPos = mPos
        return this.backward(cur)
      }
      md = mPos
      if (sp) {
        ndp = mem[md]
        mPos = md + ndp + 1
      } else {
        mPos = this.gm1(md)
        ndp = mem[md]
      }
      const curPrice = optPR[cur]
      const c1 = curPrice + litP[data[dp + cur]]
      if (c1 < optPR[cur + 1]) {
        optPR[cur + 1] = c1
        optPP[cur + 1] = cur
      }
      if (ndp === 0) continue
      const newLen = mem[md + ndp - 1]
      if (newLen > fb) {
        this.mPos = mPos
        // C checks the long match before the literal update; the literal update above only touches
        // opt[cur+1], which Backward(cur) never reads.
        const ln = this.backward(cur)
        optBP[cur] = mem[md + ndp]
        this.optEnd = cur + newLen
        optPP[cur] = this.optEnd
        if (!sp) this.mfSkip(newLen - 1)
        return ln
      }
      while (lenEnd < cur + newLen) {
        lenEnd++
        optPR[lenEnd] = kIfinityPrice
      }
      const end = md + 1 + ndp
      offs = md + 1
      distance = mem[offs + 1]
      let cp = curPrice + posP[PS[distance]]
      nxt = mem[offs]
      let j = cur + kMatchMinLen
      for (let li = 0; li < kNumLenSymbols; li++) {
        const p = cp + lenP[li]
        if (p < optPR[j]) {
          optPR[j] = p
          optPP[j] = cur
          optBP[j] = distance
        }
        if (j - cur === nxt) {
          offs += 2
          if (offs === end) break
          distance = mem[offs + 1]
          cp = curPrice + posP[PS[distance]]
          nxt = mem[offs]
        }
        j++
      }
    }
  }

  // ------------------------------------------------------------ TryBlock (fused with GetOptimal)
  tryBlock() {
    const mainFreqs = this.mainFreqs
    const distFreqs = this.distFreqs
    mainFreqs.fill(0)
    distFreqs.fill(0)
    const values = this.values
    let nvals = 0
    const blockSize = this.blockSizeRes
    let bsr = 0
    const data = this.data
    const mem = this.mem
    const sp = this.secondPass
    const vbs = this.value_block_size
    const n = this.n
    const LS = LEN_SLOTS
    const PS = POS_SLOT
    const optPP = this.optPP
    const optBP = this.optBP
    const dp0 = this.mfpos - this.addoff      // data position of block start
    let dp = dp0
    let mPos = this.mPos
    let nv = 0
    const limit = kMatchArrayLimit
    for (;;) {
      const oc = this.optCur
      let ln
      if (oc === this.optEnd) {
        if (mPos >= limit || bsr >= blockSize || (!sp && (n === this.mfpos || nv >= vbs))) break
        this.optCur = this.optEnd = 0
        const md = mPos
        let ndp
        if (sp) {
          ndp = mem[md]
          if (ndp === 0) {
            // Run of empty match records: each is a literal decision. The C loop re-checks its stop
            // conditions before every decision; the run length is capped so that the same decision
            // sequence results.
            let kmax = blockSize - bsr
            if (limit - md < kmax) kmax = limit - md
            let e = md + 1
            const stop = md + kmax
            while (e < stop && mem[e] === 0) e++
            const k = e - md
            const segEnd = dp + k < n ? dp + k : n     // Python slice data[dp:dp+k] stops at the end
            for (let q = dp; q < segEnd; q++) {
              const b = data[q]
              values[nvals++] = b
              mainFreqs[b]++
            }
            nv += k
            dp += k
            bsr += k
            mPos = e
            continue
          }
          mPos = md + ndp + 1
        } else {
          mPos = this.gm1(md)
          ndp = mem[md]
        }
        if (ndp === 0) {
          if (dp >= n) throw new RangeError('index out of range')
          const b = data[dp]
          mainFreqs[b]++
          values[nvals++] = b
          nv++
          dp++
          bsr++
          continue
        }
        this.mPos = mPos
        ln = this.getOptimalRest(md, ndp, dp)
        mPos = this.mPos
      } else {
        ln = optPP[oc] - oc
        this.backRes = optBP[oc]
        this.optCur = optPP[oc]
      }
      if (ln >= kMatchMinLen) {
        const nl = ln - kMatchMinLen
        const pos = this.backRes
        mainFreqs[kSymbolMatch + LS[nl]]++
        distFreqs[PS[pos]]++
        values[nvals++] = ((nl + 1) << 16) | pos
      } else {
        if (dp >= n) throw new RangeError('index out of range')
        const b = data[dp]
        mainFreqs[b]++
        values[nvals++] = b
      }
      nv++
      dp += ln
      bsr += ln
    }
    if (sp && mPos > this.written) this.stale_reads++
    this.mPos = mPos
    mainFreqs[kSymbolEndOfBlock]++
    this.addoff = this.mfpos - dp0
    this.secondPass = true
    this.blockSizeRes = bsr
    this.nvals = nvals
  }

  setPrices(ll, dl) {
    const lit = this.litPrices, lenP = this.lenPrices, posP = this.posPrices
    for (let i = 0; i < 256; i++) lit[i] = ll[i] ? ll[i] : kNoLiteralStatPrice
    for (let i = 0; i < kNumLenSymbols; i++) {
      const slot = LEN_SLOTS[i]
      const pr = ll[kSymbolMatch + slot]
      lenP[i] = ((pr ? pr : kNoLenStatPrice) + kLenDirectBits[slot]) & 0xFF
    }
    for (let i = 0; i < kDistTableSize64; i++) posP[i] = ((dl[i] ? dl[i] : kNoPosStatPrice) + kDistDirectBits[i]) & 0xFF
  }

  makeTables(maxHuffLen) {
    huffmanGenerateInto(this.mainFreqs, kFixedMainTableSize, maxHuffLen, this.mainCodes, this.newLL)
    huffmanGenerateInto(this.distFreqs, kDistTableSize64, maxHuffLen, this.distCodes, this.newDL)
  }

  lzBlockPrice() {
    const ll = this.newLL, dl = this.newDL, mf = this.mainFreqs, df = this.distFreqs
    let price = 0
    for (let i = 0; i < kFixedMainTableSize; i++) price += ll[i] * mf[i]
    for (let i = kSymbolMatch; i < kFixedMainTableSize; i++) price += mf[i] * kLenDirectBits[i - kSymbolMatch]
    for (let i = 0; i < kDistTableSize64; i++) price += (dl[i] + kDistDirectBits[i]) * df[i]
    return price
  }

  static levelTableDummy(levels, numLevels, freqs) {
    let prevLen = 0xFF
    let nextLen = levels[0]
    let count = 0
    let maxCount = 7, minCount = 4
    if (nextLen === 0) { maxCount = 138; minCount = 3 }
    for (let n = 0; n < numLevels; n++) {
      const curLen = nextLen
      nextLen = n < numLevels - 1 ? levels[n + 1] : 0xFF
      count++
      if (count < maxCount && curLen === nextLen) continue
      if (count < minCount) freqs[curLen] += count
      else if (curLen !== 0) {
        if (curLen !== prevLen) {
          freqs[curLen]++
          count--
        }
        freqs[kTableLevelRepNumber]++
      } else if (count <= 10) freqs[kTableLevel0Number]++
      else freqs[kTableLevel0Number2]++
      count = 0
      prevLen = curLen
      if (nextLen === 0) { maxCount = 138; minCount = 3 }
      else if (curLen === nextLen) { maxCount = 6; minCount = 3 }
      else { maxCount = 7; minCount = 4 }
    }
  }

  levelTableCode(levels, numLevels, lens, codes) {
    const out = this.out
    let prevLen = 0xFF
    let nextLen = levels[0]
    let count = 0
    let maxCount = 7, minCount = 4
    if (nextLen === 0) { maxCount = 138; minCount = 3 }
    for (let n = 0; n < numLevels; n++) {
      const curLen = nextLen
      nextLen = n < numLevels - 1 ? levels[n + 1] : 0xFF
      count++
      if (count < maxCount && curLen === nextLen) continue
      if (count < minCount) {
        for (let k = 0; k < count; k++) out.bits(codes[curLen], lens[curLen])
      } else if (curLen !== 0) {
        if (curLen !== prevLen) {
          out.bits(codes[curLen], lens[curLen])
          count--
        }
        out.bits(codes[kTableLevelRepNumber], lens[kTableLevelRepNumber])
        out.bits(count - 3, 2)
      } else if (count <= 10) {
        out.bits(codes[kTableLevel0Number], lens[kTableLevel0Number])
        out.bits(count - 3, 3)
      } else {
        out.bits(codes[kTableLevel0Number2], lens[kTableLevel0Number2])
        out.bits(count - 11, 7)
      }
      count = 0
      prevLen = curLen
      if (nextLen === 0) { maxCount = 138; minCount = 3 }
      else if (curLen === nextLen) { maxCount = 6; minCount = 3 }
      else { maxCount = 7; minCount = 4 }
    }
  }

  tryDynBlock(ti, numPasses) {
    const t = this.tables[ti]
    this.blockSizeRes = t.bsr
    const posTemp = t.pos
    this.setPrices(t.ll, t.dl)
    for (let k = 0; k < numPasses; k++) {
      this.mPos = posTemp
      this.tryBlock()
      const nv = this.nvals
      const nhb = nv > 18000 ? 12 : (nv > 7000 ? 11 : (nv > 2000 ? 10 : 9))
      this.makeTables(nhb)
      this.setPrices(this.newLL, this.newDL)
    }
    t.ll.set(this.newLL)
    t.dl.set(this.newDL)
    const ll = this.newLL, dl = this.newDL
    let nll = kMainTableSize
    while (nll > kNumLitLenCodesMin && ll[nll - 1] === 0) nll--
    let ndl = kDistTableSize64
    while (ndl > kNumDistCodesMin && dl[ndl - 1] === 0) ndl--
    this.numLL = nll
    this.numDL = ndl
    const lf = new Int32Array(kLevelTableSize)
    Encoder7z.levelTableDummy(ll, nll, lf)
    Encoder7z.levelTableDummy(dl, ndl, lf)
    huffmanGenerateInto(lf, kLevelTableSize, kMaxLevelBitLength, this.levelCodes, this.levelLens)
    let nlc = kNumLevelCodesMin
    for (let i = 0; i < kLevelTableSize; i++) {
      const lv = this.levelLens[kCodeLengthAlphabetOrder[i]]
      if (lv > 0 && i >= nlc) nlc = i + 1
      this.levelLevels[i] = lv
    }
    this.numLevelCodes = nlc
    let price = this.lzBlockPrice()
    for (let i = 0; i < kLevelTableSize; i++) price += lf[i] * this.levelLens[i]
    for (let i = kTableDirectLevels; i < kLevelTableSize; i++) price += lf[i] * kLevelDirectBits[i - kTableDirectLevels]
    return price + 5 + 5 + 4 + nlc * 3 + 1 + 2
  }

  setFixedLevels() {
    const ll = this.newLL, dl = this.newDL
    for (let i = 0; i < 144; i++) ll[i] = 8
    for (let i = 144; i < 256; i++) ll[i] = 9
    for (let i = 256; i < 280; i++) ll[i] = 7
    for (let i = 280; i < 288; i++) ll[i] = 8
    dl.fill(5)
  }

  tryFixedBlock(ti) {
    const t = this.tables[ti]
    this.blockSizeRes = t.bsr
    this.mPos = t.pos
    this.setFixedLevels()
    this.setPrices(this.newLL, this.newDL)
    this.tryBlock()
    return 1 + 2 + this.lzBlockPrice()
  }

  static storePrice(blockSize, bitPosition) {
    let price = 0
    for (;;) {
      const nbp = (bitPosition + 3) & 7
      const align = nbp > 0 ? 8 - nbp : 0
      const cur = blockSize < (1 << 16) ? blockSize : (1 << 16) - 1
      price += 3 + align + 32 + cur * 8
      bitPosition = 0
      blockSize -= cur
      if (blockSize === 0) return price
    }
  }

  table(ti) {
    let t = this.tables[ti]
    if (t === undefined) t = this.tables[ti] = newTable()
    return t
  }

  getBlockPrice(ti, numDivPasses) {
    const t = this.tables[ti]
    t.static = false
    let price = this.tryDynBlock(ti, this.num_passes)
    t.bsr = this.blockSizeRes
    const numValues = this.nvals
    const posTemp = this.mPos
    const addEnd = this.addoff
    if (this.check_static && numValues <= kFixedHuffmanCodeBlockSizeMax) {
      const fixedPrice = this.tryFixedBlock(ti)
      t.static = fixedPrice < price
      if (t.static) price = fixedPrice
    }
    const storePrice = Encoder7z.storePrice(this.blockSizeRes, 0)
    t.store = storePrice <= price
    if (t.store) price = storePrice
    t.sub = false
    if (numDivPasses > 1 && numValues >= kDivideCodeBlockSizeMin) {
      const t0 = this.table(ti << 1)
      t0.ll.set(t.ll)
      t0.dl.set(t.dl)
      t0.bsr = t.bsr >> 1
      t0.pos = t.pos
      let subPrice = this.getBlockPrice(ti << 1, numDivPasses - 1)
      const bs2 = t.bsr - t0.bsr
      if (t0.bsr >= kDivideBlockSizeMin && bs2 >= kDivideBlockSizeMin) {
        const t1 = this.table((ti << 1) + 1)
        t1.ll.set(t.ll)
        t1.dl.set(t.dl)
        t1.bsr = bs2
        t1.pos = this.mPos
        this.addoff -= t0.bsr
        subPrice += this.getBlockPrice((ti << 1) + 1, numDivPasses - 1)
        t.sub = subPrice < price
        if (t.sub) price = subPrice
      }
    }
    this.addoff = addEnd
    this.mPos = posTemp
    return price
  }

  writeBlock() {
    const out = this.out
    const ll = this.newLL, dl = this.newDL
    const mc = new Int32Array(kFixedMainTableSize)
    const dc = new Int32Array(kDistTableSize64)
    for (let i = 0; i < kFixedMainTableSize; i++) mc[i] = rev(this.mainCodes[i], ll[i])
    for (let i = 0; i < kDistTableSize64; i++) dc[i] = rev(this.distCodes[i], dl[i])
    const values = this.values
    const nvals = this.nvals
    out.grow(nvals * 6 + 64)
    // inlined bit writer (same bytes as BitOut.bits)
    const buf = out.buf
    let len = out.len, acc = out.acc, n = out.n
    for (let k = 0; k < nvals; k++) {
      const v = values[k]
      if (v < 0x10000) {
        acc |= mc[v] << n; n += ll[v]
      } else {
        const ln = (v >>> 16) - 1
        const dist = v & 0xFFFF
        const slot = LEN_SLOTS[ln]
        const s = kSymbolMatch + slot
        acc |= mc[s] << n; n += ll[s]
        while (n >= 8) { buf[len++] = acc & 0xFF; acc >>>= 8; n -= 8 }
        acc |= (ln - kLenStart[slot]) << n; n += kLenDirectBits[slot]
        while (n >= 8) { buf[len++] = acc & 0xFF; acc >>>= 8; n -= 8 }
        const ps = POS_SLOT[dist]
        acc |= dc[ps] << n; n += dl[ps]
        while (n >= 8) { buf[len++] = acc & 0xFF; acc >>>= 8; n -= 8 }
        acc |= (dist - kDistStart[ps]) << n; n += kDistDirectBits[ps]
      }
      while (n >= 8) { buf[len++] = acc & 0xFF; acc >>>= 8; n -= 8 }
    }
    out.len = len
    out.acc = acc
    out.n = n
    out.bits(mc[kSymbolEndOfBlock], ll[kSymbolEndOfBlock])
  }

  writeStoreBlock(blockSize, addOff, final) {
    const out = this.out
    const data = this.data
    for (;;) {
      const cur = blockSize < (1 << 16) ? blockSize : (1 << 16) - 1
      blockSize -= cur
      out.bits((final && blockSize === 0) ? 1 : 0, 1)
      out.bits(0, 2)
      out.flushByte()
      out.bits(cur, 16)
      out.bits((~cur) & 0xFFFF, 16)
      const start = this.mfpos - addOff
      out.flushByte()
      // Python: out.buf += data[start:start + cur] (slice clamps to the data)
      const s = Math.max(0, Math.min(start, this.n))
      const e = Math.max(s, Math.min(start + cur, this.n))
      out.appendBytes(data.subarray(s, e))
      addOff -= cur
      if (blockSize === 0) return
    }
  }

  codeBlock(ti, final) {
    const t = this.tables[ti]
    if (t.sub) {
      this.codeBlock(ti << 1, false)
      this.codeBlock((ti << 1) + 1, final)
      return
    }
    if (t.store) {
      this.writeStoreBlock(t.bsr, this.addoff, final)
    } else {
      const out = this.out
      out.bits(final ? 1 : 0, 1)
      if (t.static) {
        out.bits(1, 2)
        this.tryFixedBlock(ti)
        for (let i = 0; i < kFixedMainTableSize; i++) this.mainFreqs[i] = 1 << (9 - this.newLL[i])
        for (let i = 0; i < kFixedDistTableSize; i++) this.distFreqs[i] = 1 << (9 - this.newDL[i])
        this.makeTables(9)
      } else {
        if (this.num_div_passes > 1 || this.check_static) this.tryDynBlock(ti, 1)
        out.bits(2, 2)
        out.bits(this.numLL - kNumLitLenCodesMin, 5)
        out.bits(this.numDL - kNumDistCodesMin, 5)
        out.bits(this.numLevelCodes - kNumLevelCodesMin, 4)
        for (let i = 0; i < this.numLevelCodes; i++) out.bits(this.levelLevels[i], 3)
        const lc = new Int32Array(kLevelTableSize)
        for (let i = 0; i < kLevelTableSize; i++) lc[i] = rev(this.levelCodes[i], this.levelLens[i])
        this.levelTableCode(this.newLL, this.numLL, this.levelLens, lc)
        this.levelTableCode(this.newDL, this.numDL, this.levelLens, lc)
      }
      this.writeBlock()
    }
    this.addoff -= t.bsr
  }

  compress(data) {
    if (!this.multi) throw new Error('NotImplementedError: single-pass mode not ported (not used by this archive)')
    this.mfInit(data)
    this.out = new BitOut(data.length + (data.length >> 3) + 1024)
    this.mem = new Int32Array(kMatchArraySize + 2 * kMatchMaxLen + 8)
    this.written = 0
    this.optPP = new Int32Array(kNumOpts + 2)
    this.optBP = new Int32Array(kNumOpts + 2)
    this.optPR = new Int32Array(kNumOpts + 2)
    this.optEnd = this.optCur = 0
    this.backRes = 0
    this.addoff = 0
    this.mPos = 0
    this.secondPass = false
    this.blockSizeRes = 0
    this.values = new Int32Array(1 << 17)
    this.nvals = 0
    this.mainFreqs = new Int32Array(kFixedMainTableSize)
    this.distFreqs = new Int32Array(kDistTableSize64)
    this.mainCodes = new Int32Array(kFixedMainTableSize)
    this.distCodes = new Int32Array(kDistTableSize64)
    this.newLL = new Int32Array(kFixedMainTableSize)
    this.newDL = new Int32Array(kDistTableSize64)
    this.litPrices = new Int32Array(256)
    this.lenPrices = new Int32Array(kNumLenSymbols)
    this.posPrices = new Int32Array(kDistTableSize64)
    this.levelCodes = new Int32Array(kLevelTableSize)
    this.levelLens = new Int32Array(kLevelTableSize)
    this.levelLevels = new Int32Array(kLevelTableSize)
    this.numLL = this.numDL = this.numLevelCodes = 0
    this.tables = []
    const t = this.table(1)
    t.pos = 0
    t.ll.fill(8, 0, 256)
    t.ll[256] = 13
    t.ll.fill(5, 257)
    t.dl.fill(5)
    for (;;) {
      t.bsr = kBlockUncompressedSizeThreshold
      this.secondPass = false
      this.written = 0
      this.getBlockPrice(1, this.num_div_passes)
      this.codeBlock(1, this.n - this.mfpos === 0)
      if (this.n - this.mfpos === 0) break
    }
    return this.out.getvalue()
  }
}

export function deflate_7z(data, passes = 3, fb = 64, mc = 0) {
  const u8 = data instanceof Uint8Array ? data : Uint8Array.from(data)
  return new Encoder7z(passes, fb, mc).compress(u8)
}
