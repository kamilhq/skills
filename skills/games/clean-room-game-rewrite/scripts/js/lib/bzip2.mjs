// bzip2 decompressor (Node built-ins only), written from the bzip2 format as libbzip2 1.0.8 decodes it.
// It stands in for Python's bz2.BZ2Decompressor:
//   - decompress(data, maxLength=-1): output so far (at most maxLength bytes); eof, needs_input and
//     unused_data as in Python (one stream: data after its end is unused_data)
//   - a block's output appears once all of the block's bits are there (libbzip2 needs the whole block for
//     the inverse BWT), so any prefix of a stream gives the same output as libbzip2
//   - libbzip2's checks, in its order: magic, block header, origPtr, symbol map, groups, selectors, code
//     lengths, run lengths, block size, cftab, per-block CRC (after the block's output), combined CRC.
//     Errors raise BZ2Error('Invalid data stream') (Python: OSError); decompress() after the end raises
//     EOFError('End of stream already reached')
//   - randomised blocks (bzip2 0.9.0) are decoded with BZ2_rNums
//   Test hooks (parity/bzip2.mjs builds randomised streams with them): d._ignoreCrc = true skips the CRC checks,
//   d._blocks = [] collects {start: bit offset of each block header, crc: its computed CRC}, d._endBitPos is the
//   bit offset of the end-of-stream marker.

export class BZ2Error extends Error {
  constructor(m) { super(m); this.name = 'OSError' }
}
export class EOFError extends Error {
  constructor(m) { super(m); this.name = 'EOFError' }
}
const INVALID = 'Invalid data stream'
const NEED = Symbol('need input')
const bad = () => { throw new BZ2Error(INVALID) }

const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i << 24
    for (let k = 0; k < 8; k++) c = c & 0x80000000 ? (c << 1) ^ 0x04C11DB7 : c << 1
    t[i] = c >>> 0
  }
  return t
})()

// BZ2_rNums (randomised blocks)
const R_NUMS = [
  619, 720, 127, 481, 931, 816, 813, 233, 566, 247, 985, 724, 205, 454, 863, 491, 741, 242, 949, 214, 733, 859,
  335, 708, 621, 574, 73, 654, 730, 472, 419, 436, 278, 496, 867, 210, 399, 680, 480, 51, 878, 465, 811, 169,
  869, 675, 611, 697, 867, 561, 862, 687, 507, 283, 482, 129, 807, 591, 733, 623, 150, 238, 59, 379, 684, 877,
  625, 169, 643, 105, 170, 607, 520, 932, 727, 476, 693, 425, 174, 647, 73, 122, 335, 530, 442, 853, 695, 249,
  445, 515, 909, 545, 703, 919, 874, 474, 882, 500, 594, 612, 641, 801, 220, 162, 819, 984, 589, 513, 495, 799,
  161, 604, 958, 533, 221, 400, 386, 867, 600, 782, 382, 596, 414, 171, 516, 375, 682, 485, 911, 276, 98, 553,
  163, 354, 666, 933, 424, 341, 533, 870, 227, 730, 475, 186, 263, 647, 537, 686, 600, 224, 469, 68, 770, 919,
  190, 373, 294, 822, 808, 206, 184, 943, 795, 384, 383, 461, 404, 758, 839, 887, 715, 67, 618, 276, 204, 918,
  873, 777, 604, 560, 951, 160, 578, 722, 79, 804, 96, 409, 713, 940, 652, 934, 970, 447, 318, 353, 859, 672,
  112, 785, 645, 863, 803, 350, 139, 93, 354, 99, 820, 908, 609, 772, 154, 274, 580, 184, 79, 626, 630, 742,
  653, 282, 762, 623, 680, 81, 927, 626, 789, 125, 411, 521, 938, 300, 821, 78, 343, 175, 128, 250, 170, 774,
  972, 275, 999, 639, 495, 78, 352, 126, 857, 956, 358, 619, 580, 124, 737, 594, 701, 612, 669, 112, 134, 694,
  363, 992, 809, 743, 168, 974, 944, 375, 748, 52, 600, 747, 642, 182, 862, 81, 344, 805, 988, 739, 511, 655,
  814, 334, 249, 515, 897, 955, 664, 981, 649, 113, 974, 459, 893, 228, 433, 837, 553, 268, 926, 240, 102, 654,
  459, 51, 686, 754, 806, 760, 493, 403, 415, 394, 687, 700, 946, 670, 656, 610, 738, 392, 760, 799, 887, 653,
  978, 321, 576, 617, 626, 502, 894, 679, 243, 440, 680, 879, 194, 572, 640, 724, 926, 56, 204, 700, 707, 151,
  457, 449, 797, 195, 791, 558, 945, 679, 297, 59, 87, 824, 713, 663, 412, 693, 342, 606, 134, 108, 571, 364,
  631, 212, 174, 643, 304, 329, 343, 97, 430, 751, 497, 314, 983, 374, 822, 928, 140, 206, 73, 263, 980, 736,
  876, 478, 430, 305, 170, 514, 364, 692, 829, 82, 855, 953, 676, 246, 369, 970, 294, 750, 807, 827, 150, 790,
  288, 923, 804, 378, 215, 828, 592, 281, 565, 555, 710, 82, 896, 831, 547, 261, 524, 462, 293, 465, 502, 56,
  661, 821, 976, 991, 658, 869, 905, 758, 745, 193, 768, 550, 608, 933, 378, 286, 215, 979, 792, 961, 61, 688,
  793, 644, 986, 403, 106, 366, 905, 644, 372, 567, 466, 434, 645, 210, 389, 550, 919, 135, 780, 773, 635, 389,
  707, 100, 626, 958, 165, 504, 920, 176, 193, 713, 857, 265, 203, 50, 668, 108, 645, 990, 626, 197, 510, 357,
  358, 850, 858, 364, 936, 638,
]

const MAX_GROUPS = 6
const MAX_SELECTORS = 18002
const MAX_ALPHA = 258
const MAX_CODE_LEN = 23
const G_SIZE = 50

class Bits {
  constructor() { this.buf = Buffer.alloc(0); this.bp = 0 }      // bp: absolute bit position in buf
  avail() { return this.buf.length * 8 - this.bp }
  bit() {
    const bp = this.bp
    if (bp >= this.buf.length * 8) throw NEED
    this.bp = bp + 1
    return (this.buf[bp >>> 3] >> (7 - (bp & 7))) & 1
  }
  bits(n) {
    if (this.bp + n > this.buf.length * 8) throw NEED
    let v = 0
    for (let k = 0; k < n; k++) {
      const bp = this.bp++
      v = v * 2 + ((this.buf[bp >>> 3] >> (7 - (bp & 7))) & 1)
    }
    return v
  }
}

// One block, parsed in two stages so that input arriving in small pieces costs no re-parsing of the bulk:
//   stage 0  block header and coding tables (small): restarted from the header start when input runs out
//   stage 1  the MTF/Huffman symbols: resumable at every symbol (state kept between calls)
// step(br) returns true when the block is complete (tt holds the vector for the inverse BWT), throws NEED
// (with br.bp back at the restart point) when input runs out, and throws BZ2Error on invalid data.
class BlockParser {
  constructor(blockSize100k, tt) {
    this.blockSize100k = blockSize100k
    this.tt = tt
    this.stage = 0
  }

  step(br) {
    if (this.stage === 0) {
      const start = br.bp
      try { this.header(br) } catch (e) { if (e === NEED) br.bp = start; throw e }
      this.stage = 1
    }
    this.symbols(br)
    this.finish()
    return true
  }

  header(br) {
    // block magic (first byte 0x31 already consumed by the caller)
    for (const b of [0x41, 0x59, 0x26, 0x53, 0x59]) if (br.bits(8) !== b) bad()
    this.storedCrc = br.bits(32)
    this.randomised = br.bit()
    this.origPtr = br.bits(24)
    if (this.origPtr > 10 + 100000 * this.blockSize100k) bad()
    const inUse16 = br.bits(16)
    const seqToUnseq = []
    for (let i = 0; i < 16; i++) {
      if (inUse16 & (0x8000 >> i)) {
        const w = br.bits(16)
        for (let j = 0; j < 16; j++) if (w & (0x8000 >> j)) seqToUnseq.push(i * 16 + j)
      }
    }
    const nInUse = seqToUnseq.length
    if (nInUse === 0) bad()
    const alphaSize = nInUse + 2
    const nGroups = br.bits(3)
    if (nGroups < 2 || nGroups > MAX_GROUPS) bad()
    let nSelectors = br.bits(15)
    if (nSelectors < 1) bad()
    const selectorMtf = []
    for (let i = 0; i < nSelectors; i++) {
      let j = 0
      while (br.bit()) { j++; if (j >= nGroups) bad() }
      if (i < MAX_SELECTORS) selectorMtf.push(j)
    }
    if (nSelectors > MAX_SELECTORS) nSelectors = MAX_SELECTORS
    const pos = [0, 1, 2, 3, 4, 5].slice(0, nGroups)
    const selector = new Uint8Array(nSelectors)
    for (let i = 0; i < nSelectors; i++) {
      let v = selectorMtf[i]
      const tmp = pos[v]
      while (v > 0) { pos[v] = pos[v - 1]; v-- }
      pos[0] = tmp
      selector[i] = tmp
    }
    const limit = [], base = [], perm = [], minLens = []
    for (let t = 0; t < nGroups; t++) {
      const len = new Uint8Array(alphaSize)
      let curr = br.bits(5)
      for (let i = 0; i < alphaSize; i++) {
        for (;;) {
          if (curr < 1 || curr > 20) bad()
          if (!br.bit()) break
          if (!br.bit()) curr++; else curr--
        }
        len[i] = curr
      }
      let minLen = 32, maxLen = 0
      for (let i = 0; i < alphaSize; i++) { if (len[i] > maxLen) maxLen = len[i]; if (len[i] < minLen) minLen = len[i] }
      // BZ2_hbCreateDecodeTables
      const lim = new Int32Array(MAX_CODE_LEN), bs = new Int32Array(MAX_CODE_LEN), pm = new Int32Array(MAX_ALPHA)
      let pp = 0
      for (let i = minLen; i <= maxLen; i++) for (let j = 0; j < alphaSize; j++) if (len[j] === i) pm[pp++] = j
      for (let i = 0; i < alphaSize; i++) bs[len[i] + 1]++
      for (let i = 1; i < MAX_CODE_LEN; i++) bs[i] += bs[i - 1]
      let vec = 0
      for (let i = minLen; i <= maxLen; i++) {
        vec += bs[i + 1] - bs[i]
        lim[i] = vec - 1
        vec <<= 1
      }
      for (let i = minLen + 1; i <= maxLen; i++) bs[i] = ((lim[i - 1] + 1) << 1) - bs[i]
      limit.push(lim); base.push(bs); perm.push(pm); minLens.push(minLen)
    }
    Object.assign(this, { seqToUnseq, nInUse, nSelectors, selector, limit, base, perm, minLens })
    // symbol stage state
    this.EOB = nInUse + 1
    this.nblockMax = 100000 * this.blockSize100k
    this.unzftab = new Int32Array(256)
    this.mtf = new Uint8Array(256)
    for (let i = 0; i < 256; i++) this.mtf[i] = i
    this.groupNo = -1; this.groupPos = 0
    this.nblock = 0
    this.inRun = false; this.es = 0; this.N = 0
  }

  nextSym(br) {
    const save = br.bp, gNo = this.groupNo, gPos = this.groupPos
    try {
      if (this.groupPos === 0) {
        this.groupNo++
        if (this.groupNo >= this.nSelectors) bad()
        this.groupPos = G_SIZE
      }
      this.groupPos--
      const g = this.selector[this.groupNo]
      const gLimit = this.limit[g], gBase = this.base[g]
      let zn = this.minLens[g]
      let zvec = br.bits(zn)
      for (;;) {
        if (zn > 20) bad()
        if (zvec <= gLimit[zn]) break
        zn++
        zvec = (zvec << 1) | br.bit()
      }
      const k = zvec - gBase[zn]
      if (k < 0 || k >= MAX_ALPHA) bad()
      return this.perm[g][k]
    } catch (e) {
      if (e === NEED) { br.bp = save; this.groupNo = gNo; this.groupPos = gPos }
      throw e
    }
  }

  symbols(br) {
    const tt = this.tt, mtf = this.mtf, seq = this.seqToUnseq, nblockMax = this.nblockMax
    for (;;) {
      const sym = this.nextSym(br)
      if (this.inRun) {
        if (sym === 0 || sym === 1) {
          if (this.N >= 2 * 1024 * 1024) bad()
          this.es += (sym + 1) * this.N
          this.N *= 2
          continue
        }
        let es = this.es + 1
        const uc = seq[mtf[0]]
        this.unzftab[uc] += es
        while (es > 0) {
          if (this.nblock >= nblockMax) bad()
          tt[this.nblock++] = uc
          es--
        }
        this.inRun = false
      }
      if (sym === this.EOB) return
      if (sym === 0 || sym === 1) {
        this.inRun = true
        this.es = -1; this.N = 1
        this.es += (sym + 1) * this.N
        this.N *= 2
        continue
      }
      if (this.nblock >= nblockMax) bad()
      let nn = sym - 1
      const v = mtf[nn]
      while (nn > 0) { mtf[nn] = mtf[nn - 1]; nn-- }
      mtf[0] = v
      const uc = seq[v]
      this.unzftab[uc]++
      tt[this.nblock++] = uc
    }
  }

  finish() {
    const nblock = this.nblock, tt = this.tt, unzftab = this.unzftab
    if (this.origPtr >= nblock) bad()
    for (let i = 0; i < 256; i++) if (unzftab[i] < 0 || unzftab[i] > nblock) bad()
    const cftab = new Int32Array(257)
    for (let i = 1; i <= 256; i++) cftab[i] = unzftab[i - 1]
    for (let i = 1; i <= 256; i++) cftab[i] += cftab[i - 1]
    for (let i = 0; i <= 256; i++) if (cftab[i] < 0 || cftab[i] > nblock) bad()
    for (let i = 1; i <= 256; i++) if (cftab[i - 1] > cftab[i]) bad()
    for (let i = 0; i < nblock; i++) {
      const uc = tt[i] & 0xff
      tt[cftab[uc]] |= i << 8
      cftab[uc]++
    }
  }
}

// inverse BWT + RLE1 decoding, as libbzip2's unRLE_obuf_to_output_FAST does it (including what it does with
// a stream that ends inside a run). Returns { out: Buffer, crc, corrupt }.
function unrle(blk, tt, nblockMax) {
  const n = blk.nblock
  let tPos = tt[blk.origPtr] >>> 8
  let used = 0
  let corrupt = false
  let rToGo = 0, rTPos = 0
  const fetch = () => {
    if (tPos >= nblockMax) { corrupt = true; return 0 }
    tPos = tt[tPos]
    let c = tPos & 0xff
    tPos >>>= 8
    if (blk.randomised) {
      if (rToGo === 0) { rToGo = R_NUMS[rTPos]; rTPos = (rTPos + 1) & 511 }
      rToGo--
      c ^= rToGo === 1 ? 1 : 0
    }
    used++
    return c
  }
  let out = Buffer.allocUnsafe(Math.max(n, 16))
  let op = 0
  let crc = 0xFFFFFFFF
  const emit = (ch, cnt) => {
    if (op + cnt > out.length) {
      const nb = Buffer.allocUnsafe(Math.max(out.length * 2, op + cnt))
      out.copy(nb, 0, 0, op)
      out = nb
    }
    out.fill(ch, op, op + cnt)
    op += cnt
    for (let k = 0; k < cnt; k++) crc = ((crc << 8) ^ CRC_TABLE[((crc >>> 24) ^ ch) & 0xff]) >>> 0
  }
  let k0 = fetch()
  for (;;) {
    if (corrupt) break
    if (used === n + 1) break
    if (used > n + 1) { corrupt = true; break }
    let len = 1
    const ch = k0
    let k1 = fetch()
    if (corrupt) break
    if (used === n + 1 || k1 !== k0) { emit(ch, 1); k0 = k1; continue }
    len = 2
    k1 = fetch()
    if (corrupt) break
    if (used === n + 1 || k1 !== k0) { emit(ch, 2); k0 = k1; continue }
    len = 3
    k1 = fetch()
    if (corrupt) break
    if (used === n + 1 || k1 !== k0) { emit(ch, 3); k0 = k1; continue }
    k1 = fetch()
    if (corrupt) break
    len = k1 + 4
    k0 = fetch()
    if (corrupt) break
    emit(ch, len)
  }
  return { out: out.subarray(0, op), crc: (~crc) >>> 0, corrupt }
}

const ST_MAGIC = 0, ST_BLOCK = 1, ST_OUTPUT = 2, ST_END = 3

export class BZ2Decompressor {
  constructor() {
    this.br = new Bits()
    this.state = ST_MAGIC
    this.blockSize100k = 0
    this.tt = null
    this.parser = null
    this.combined = 0
    this.blockOut = null; this.outPos = 0; this.blockInfo = null
    this.eof = false
    this.needs_input = true
    this.unused_data = Buffer.alloc(0)
  }

  decompress(data, maxLength = -1) {
    if (this.eof) throw new EOFError('End of stream already reached')
    const br = this.br
    if (data && data.length) {
      // keep only the bytes from the one holding the current bit onwards
      const keep = br.bp >>> 3
      const rest = br.buf.subarray(keep)
      br.buf = rest.length ? Buffer.concat([rest, data]) : Buffer.from(data)
      br.bp -= keep * 8
    }
    // CPython's decompress_buf: an output buffer of 8192 bytes (or max_length if smaller) growing by 1/8 + 6;
    // each time libbzip2 fills it, Python stops if libbzip2 has used up all the input (returning what it has,
    // with more output pending and needs_input True), or if max_length is reached; otherwise it grows the buffer
    let pyBuf = maxLength < 0 || maxLength >= 8192 ? 8192 : maxLength
    const out = []
    let produced = 0
    const allInputUsed = () => Math.ceil(br.bp / 8) >= br.buf.length
    for (;;) {
      if (this.state === ST_OUTPUT) {
        const left = this.blockOut.length - this.outPos
        if (left > 0) {
          const space = pyBuf - produced
          if (space <= 0) {
            if (allInputUsed()) break
            if (produced === maxLength) break
            let nb = pyBuf + (pyBuf >> 3) + 6
            if (maxLength > 0 && nb > maxLength) nb = maxLength
            pyBuf = nb
            continue
          }
          const n = Math.min(left, space)
          out.push(this.blockOut.subarray(this.outPos, this.outPos + n))
          this.outPos += n; produced += n
          continue
        }
        const info = this.blockInfo
        if (!this._ignoreCrc && (info.corrupt || info.crc !== info.storedCrc)) bad()
        this.combined = (((this.combined << 1) | (this.combined >>> 31)) ^ info.crc) >>> 0
        this.blockOut = null; this.blockInfo = null
        this.state = ST_BLOCK
        continue
      }
      const start = br.bp
      try {
        if (this.state === ST_MAGIC) {
          if (br.bits(8) !== 0x42) bad()
          if (br.bits(8) !== 0x5A) bad()
          if (br.bits(8) !== 0x68) bad()
          const b = br.bits(8)
          if (b < 0x31 || b > 0x39) bad()
          this.blockSize100k = b - 0x30
          this.tt = new Uint32Array(100000 * this.blockSize100k)
          this.state = ST_BLOCK
          continue
        }
        if (this.state === ST_BLOCK) {
          if (!this.parser) {
            const b = br.bits(8)
            if (b === 0x17) { this.state = ST_END; continue }
            if (b !== 0x31) bad()
            this.blockStart = br.bp - 8
            this.parser = new BlockParser(this.blockSize100k, this.tt)
          }
          const blk = this.parser
          blk.step(br)
          this.parser = null
          const r = unrle(blk, this.tt, 100000 * this.blockSize100k)
          if (this._blocks) this._blocks.push({ start: this.blockStart, crc: r.crc })   // test hook
          this.blockOut = r.out; this.outPos = 0
          this.blockInfo = { corrupt: r.corrupt, crc: r.crc, storedCrc: blk.storedCrc }
          this.state = ST_OUTPUT
          continue
        }
        // ST_END
        this._endBitPos = br.bp - 8
        for (const b of [0x72, 0x45, 0x38, 0x50, 0x90]) if (br.bits(8) !== b) bad()
        const stored = br.bits(32)
        if (stored !== this.combined && !this._ignoreCrc) bad()
        this.eof = true
        break
      } catch (e) {
        if (e !== NEED) throw e
        // a wrong byte is rejected as soon as it is there (bits are read in order), so input running out only
        // means: wait. Inside a block the parser has put br.bp at its restart point.
        if (!this.parser) br.bp = start
        break
      }
    }
    const consumed = Math.ceil(br.bp / 8)
    if (this.eof) {
      this.needs_input = false
      this.unused_data = Buffer.from(br.buf.subarray(consumed))
      br.buf = Buffer.alloc(0); br.bp = 0
    } else if (this.state === ST_OUTPUT) {
      // libbzip2 has read the block's bits; Python asks for input only when none is left over
      this.needs_input = consumed >= br.buf.length
    } else {
      this.needs_input = true
    }
    return out.length === 1 ? Buffer.from(out[0]) : Buffer.concat(out)
  }
}

export function decompress(data) {
  const d = new BZ2Decompressor()
  return d.decompress(data)
}
