// Raw LZMA1 / LZMA2 decoder (Node built-ins only), written from the LZMA specification (LzmaSpec / xz format
// documentation). It stands in for Python's
//   lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": FILTER_LZMA1, "dict_size", "lc", "lp", "pb"}])
//   lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": FILTER_LZMA2, "dict_size"}])
// with the same results as liblzma:
//   - decompress(data, maxLength=-1) returns everything decodable so far (at most maxLength bytes); eof,
//     needs_input and unused_data behave like Python's attributes
//   - input that stops in the middle of a symbol keeps the symbol pending (like liblzma's resumable decoder):
//     the output for any prefix of a stream equals liblzma's output for that prefix
//   - errors raise LZMAError('Corrupt input data'); invalid lc/lp/pb raise LZMAError('Internal error') (liblzma
//     5.4's LZMA_PROG_ERROR for a raw decoder), the messages Python gives; decompress() after the end raises
//     EOFError('Already at end of stream')
//   - liblzma's checks: first range-coder byte 0, distances inside the dictionary (dict_size rounded up to a
//     multiple of 16, at least 4096), rep match on an empty dictionary, end-of-payload marker followed by a
//     finished range coder (LZMA1), LZMA2 control/property/reset rules, chunk sizes exact
//
// Range coder: normalisation happens before each bit (as liblzma does), so a symbol is complete when all of
// its bits are; at the tail of the available input each symbol is first decoded in a dry run that changes
// nothing, and committed only when the input holds all of it.

export class LZMAError extends Error {
  constructor(m) { super(m); this.name = 'LZMAError' }
}
export class EOFError extends Error {
  constructor(m) { super(m); this.name = 'EOFError' }
}
export const FORMAT_RAW = 'raw'
export const FILTER_LZMA1 = 'lzma1'
export const FILTER_LZMA2 = 'lzma2'

const CORRUPT = 'Corrupt input data'
const BAD_OPTIONS = 'Invalid or unsupported options'
const PROG_ERROR = 'Internal error'       // liblzma 5.4 LZMA_PROG_ERROR: invalid lc/lp/pb given to a raw decoder
const TOP = 0x1000000
const NEED = Symbol('need input')
const REQUIRED_INPUT_MAX = 20     // bytes one symbol can need at most

// probability array layout
const IS_MATCH = 0                // [state << 4 | posState] 192
const IS_REP = 192
const IS_REP_G0 = 204
const IS_REP_G1 = 216
const IS_REP_G2 = 228
const IS_REP0_LONG = 240          // 192
const POS_SLOT = 432              // [lenState][64] 256
const SPEC_POS = 688              // 115 (index 1 + dist - posSlot - 1 ...)
const ALIGN = 803                 // 16
const LEN = 819                   // choice, choice2, low[16][8], mid[16][8], high[256] = 514
const REP_LEN = 1333              // 514
const LITERAL = 1847
const L_CHOICE = 0, L_CHOICE2 = 1, L_LOW = 2, L_MID = 130, L_HIGH = 258

// ---------------------------------------------------------------------------------------------------------
// Dictionary / output window
// ---------------------------------------------------------------------------------------------------------
class Window {
  constructor(dictSize) {
    // liblzma: at least 4096, rounded up to a multiple of 16
    this.size = Math.ceil(Math.max(dictSize, 4096) / 16) * 16
    this.buf = Buffer.allocUnsafe(Math.min(this.size, 1 << 16))
    this.pos = 0          // write position in buf
    this.full = 0         // valid history bytes (<= size)
    this.total = 0        // bytes since the last dictionary reset (position for lp/pb)
    this.flushPos = 0     // start of output not yet handed out
    this.out = null       // array collecting output pieces
  }
  reset() {
    this.flush()
    this.pos = 0; this.full = 0; this.total = 0; this.flushPos = 0
  }
  flush() {
    if (this.pos > this.flushPos) {
      this.out.push(Buffer.from(this.buf.subarray(this.flushPos, this.pos)))
    }
    this.flushPos = this.pos
  }
  // make room for at least one byte at pos
  room() {
    this.flush()
    if (this.buf.length < this.size) {
      const nb = Buffer.allocUnsafe(Math.min(this.size, this.buf.length * 2))
      this.buf.copy(nb, 0, 0, this.pos)
      this.buf = nb
    } else {
      this.pos = 0
      this.flushPos = 0
    }
  }
  put(b) {
    if (this.pos === this.buf.length) this.room()
    this.buf[this.pos++] = b
    this.total++
    if (this.full < this.size) this.full++
  }
  get(dist) {             // dist >= 1: the byte dist positions back
    let i = this.pos - dist
    if (i < 0) i += this.buf.length
    return this.buf[i]
  }
  copyMatch(dist, len) {  // dist >= 1
    while (len > 0) {
      if (this.pos === this.buf.length) this.room()
      let src = this.pos - dist
      if (src < 0) src += this.buf.length
      // copy a run that stays inside the buffer on both sides
      let n = Math.min(len, this.buf.length - this.pos, this.buf.length - src)
      if (src + n > this.pos && src < this.pos) {
        // overlapping forward copy: byte by byte
        const b = this.buf
        let d = this.pos
        for (let k = 0; k < n; k++) b[d + k] = b[src + k]
      } else {
        this.buf.copy(this.buf, this.pos, src, src + n)
      }
      this.pos += n
      this.total += n
      this.full = Math.min(this.size, this.full + n)
      len -= n
    }
  }
  write(src, start, n) {  // uncompressed bytes (LZMA2 stored chunk)
    while (n > 0) {
      if (this.pos === this.buf.length) this.room()
      const k = Math.min(n, this.buf.length - this.pos)
      src.copy(this.buf, this.pos, start, start + k)
      this.pos += k; this.total += k; this.full = Math.min(this.size, this.full + k)
      start += k; n -= k
    }
  }
}

// ---------------------------------------------------------------------------------------------------------
// LZMA symbol decoder
// ---------------------------------------------------------------------------------------------------------
class LzmaCore {
  constructor(win) {
    this.win = win
    this.lc = this.lp = this.pb = -1
    this.probs = null
    this.inp = null; this.ip = 0; this.iend = 0
  }
  setProps(lc, lp, pb) {
    if (lc !== this.lc || lp !== this.lp) this.probs = new Uint16Array(LITERAL + (0x300 << (lc + lp)))
    this.lc = lc; this.lp = lp; this.pb = pb
  }
  resetState() {
    this.probs.fill(1024)
    this.state = 0
    this.rep0 = this.rep1 = this.rep2 = this.rep3 = 0
    this.pendLen = 0
    this.eopm = false
  }
  rcInit() { this.initLeft = 5; this.range = 0xFFFFFFFF; this.code = 0 }

  // ---- range coder primitives (dry: do not touch probabilities) ----
  bit(i, dry) {
    let range = this.range, code = this.code
    if (range < TOP) {
      if (this.ip >= this.iend) throw NEED
      range = (range << 8) >>> 0
      code = ((code << 8) | this.inp[this.ip++]) >>> 0
    }
    const p = this.probs[i]
    const bound = (range >>> 11) * p
    if (code < bound) {
      this.range = bound; this.code = code
      if (!dry) this.probs[i] = p + ((2048 - p) >> 5)
      return 0
    }
    this.range = range - bound; this.code = code - bound
    if (!dry) this.probs[i] = p - (p >> 5)
    return 1
  }
  direct(n) {
    let r = 0
    for (; n > 0; n--) {
      let range = this.range, code = this.code
      if (range < TOP) {
        if (this.ip >= this.iend) throw NEED
        range = (range << 8) >>> 0
        code = ((code << 8) | this.inp[this.ip++]) >>> 0
      }
      range >>>= 1
      if (code >= range) { code -= range; r = r * 2 + 1 } else r = r * 2
      this.range = range; this.code = code
    }
    return r
  }
  normalize() {           // returns false when a byte is needed and none is available
    if (this.range < TOP) {
      if (this.ip >= this.iend) return false
      this.range = (this.range << 8) >>> 0
      this.code = ((this.code << 8) | this.inp[this.ip++]) >>> 0
    }
    return true
  }
  tree(base, nbits, dry) {
    let m = 1
    for (let k = 0; k < nbits; k++) m = (m << 1) | this.bit(base + m, dry)
    return m - (1 << nbits)
  }
  rtree(base, nbits, dry) {
    let m = 1, sym = 0
    for (let k = 0; k < nbits; k++) {
      const b = this.bit(base + m, dry)
      m = (m << 1) | b
      sym |= b << k
    }
    return sym
  }
  len(base, posState, dry) {
    if (this.bit(base + L_CHOICE, dry) === 0) return this.tree(base + L_LOW + (posState << 3), 3, dry)
    if (this.bit(base + L_CHOICE2, dry) === 0) return 8 + this.tree(base + L_MID + (posState << 3), 3, dry)
    return 16 + this.tree(base + L_HIGH, 8, dry)
  }

  // Decode one symbol. dry: compute only (throws NEED if the input does not hold all of it).
  // Returns: -1 literal written, 0 eopm, >0 match length (written up to the limits by the caller)
  // For a dry run the result is meaningless except that it did not throw.
  symbol(dry) {
    const win = this.win
    const posState = win.total & ((1 << this.pb) - 1)
    const state = this.state
    if (this.bit(IS_MATCH + (state << 4) + posState, dry) === 0) {
      // literal
      const prev = win.total > 0 ? win.get(1) : 0
      const lit = LITERAL + 0x300 * ((((win.total & ((1 << this.lp) - 1))) << this.lc) + (prev >> (8 - this.lc)))
      let sym = 1
      if (state >= 7) {
        let mb = win.get(this.rep0 + 1)
        do {
          const mbit = (mb >> 7) & 1
          mb <<= 1
          const b = this.bit(lit + ((1 + mbit) << 8) + sym, dry)
          sym = (sym << 1) | b
          if (mbit !== b) break
        } while (sym < 0x100)
      }
      while (sym < 0x100) sym = (sym << 1) | this.bit(lit + sym, dry)
      if (!dry) {
        win.put(sym - 0x100)
        this.state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6
      }
      return -1
    }
    let len
    if (this.bit(IS_REP + state, dry) !== 0) {
      if (win.full === 0) throw new LZMAError(CORRUPT)
      if (this.bit(IS_REP_G0 + state, dry) === 0) {
        if (this.bit(IS_REP0_LONG + (state << 4) + posState, dry) === 0) {
          if (!dry) {
            this.state = state < 7 ? 9 : 11
            win.put(win.get(this.rep0 + 1))
          }
          return -1
        }
        len = this.len(REP_LEN, posState, dry)
        if (!dry) this.state = state < 7 ? 8 : 11
      } else {
        let dist
        if (this.bit(IS_REP_G1 + state, dry) === 0) {
          dist = this.rep1
          len = this.len(REP_LEN, posState, dry)
          if (!dry) { this.rep1 = this.rep0 }
        } else if (this.bit(IS_REP_G2 + state, dry) === 0) {
          dist = this.rep2
          len = this.len(REP_LEN, posState, dry)
          if (!dry) { this.rep2 = this.rep1; this.rep1 = this.rep0 }
        } else {
          dist = this.rep3
          len = this.len(REP_LEN, posState, dry)
          if (!dry) { this.rep3 = this.rep2; this.rep2 = this.rep1; this.rep1 = this.rep0 }
        }
        if (!dry) { this.rep0 = dist; this.state = state < 7 ? 8 : 11 }
      }
      return len + 2
    }
    // match
    len = this.len(LEN, posState, dry)
    const lenState = len < 3 ? len : 3
    const slot = this.tree(POS_SLOT + (lenState << 6), 6, dry)
    let dist
    if (slot < 4) dist = slot
    else {
      const nd = (slot >> 1) - 1
      dist = (2 | (slot & 1)) * 2 ** nd
      if (slot < 14) dist += this.rtree(SPEC_POS + dist - slot - 1, nd, dry)
      else dist += this.direct(nd - 4) * 16 + this.rtree(ALIGN - 1, 4, dry)
    }
    if (!dry) {
      this.rep3 = this.rep2; this.rep2 = this.rep1; this.rep1 = this.rep0
      this.rep0 = dist
      this.state = state < 7 ? 7 : 10
    }
    if (dist === 0xFFFFFFFF) return 0
    return len + 2
  }

  // Run the decoder on inp[ip, iend).
  //   budget: bytes it may write (Infinity = no limit); sized: LZMA2 chunk (this.unpack bytes left)
  // Returns 'need' (input exhausted), 'limit' (budget used up), 'end' (eopm / chunk finished)
  run(inp, ip, iend, budget, sized) {
    this.inp = inp; this.ip = ip; this.iend = iend
    const win = this.win
    while (this.initLeft > 0) {
      if (this.ip >= iend) return 'need'
      if (this.initLeft === 5 && inp[this.ip] !== 0) throw new LZMAError(CORRUPT)
      this.code = ((this.code << 8) | inp[this.ip++]) >>> 0
      this.initLeft--
    }
    if (this.eopm) return this.finishEopm()
    for (;;) {
      if (this.pendLen > 0) {
        if (budget <= 0) return 'limit'
        const n = Math.min(this.pendLen, budget)
        win.copyMatch(this.rep0 + 1, n)
        this.pendLen -= n; budget -= n
        if (sized) this.unpack -= n
        continue
      }
      if (sized && this.unpack === 0) {
        if (!this.normalize()) return 'need'
        if (this.code !== 0) throw new LZMAError(CORRUPT)
        return 'end'
      }
      if (budget <= 0) return 'limit'
      if (this.iend - this.ip < REQUIRED_INPUT_MAX) {
        const r = this.range, c = this.code, p = this.ip
        let complete = true
        try {
          this.symbol(true)
        } catch (e) {
          if (e !== NEED) throw e
          complete = false
        }
        this.range = r; this.code = c; this.ip = p
        if (!complete) return 'need'
      }
      const len = this.symbol(false)
      if (len === -1) {
        budget -= 1
        if (sized) this.unpack -= 1
        continue
      }
      if (len === 0) {          // end of payload marker
        if (sized) throw new LZMAError(CORRUPT)
        this.eopm = true
        return this.finishEopm()
      }
      if (this.rep0 >= win.full) throw new LZMAError(CORRUPT)
      if (sized && len > this.unpack) throw new LZMAError(CORRUPT)
      this.pendLen = len
    }
  }
  finishEopm() {
    if (!this.normalize()) return 'need'
    if (this.code !== 0) throw new LZMAError(CORRUPT)
    return 'end'
  }
}

// ---------------------------------------------------------------------------------------------------------
// Raw LZMA1 stream
// ---------------------------------------------------------------------------------------------------------
class Lzma1Stream {
  constructor(f) {
    const lc = f.lc ?? 3, lp = f.lp ?? 0, pb = f.pb ?? 2
    if (!(lc >= 0 && lc <= 4 && lp >= 0 && lp <= 4 && lc + lp <= 4 && pb >= 0 && pb <= 4)) {
      throw new LZMAError(PROG_ERROR)
    }
    this.win = new Window(f.dict_size ?? (1 << 23))
    this.core = new LzmaCore(this.win)
    this.core.setProps(lc, lp, pb)
    this.core.resetState()
    this.core.rcInit()
  }
  // returns [newIp, status]
  step(inp, ip, iend, budget) {
    const st = this.core.run(inp, ip, iend, budget, false)
    return [this.core.ip, st === 'end' ? 'eof' : st]
  }
}

// ---------------------------------------------------------------------------------------------------------
// Raw LZMA2 stream
// ---------------------------------------------------------------------------------------------------------
const S_CONTROL = 0, S_U1 = 1, S_U2 = 2, S_P1 = 3, S_P2 = 4, S_PROPS = 5, S_LZMA = 6, S_COPY = 7

class Lzma2Stream {
  constructor(f) {
    this.win = new Window(f.dict_size ?? (1 << 23))
    this.core = new LzmaCore(this.win)
    this.seq = S_CONTROL
    this.needDictReset = true
    this.needProps = true
    this.unpack = 0; this.packed = 0; this.next = 0; this.mode = 0
  }
  step(inp, ip, iend, budget) {
    const win = this.win
    for (;;) {
      switch (this.seq) {
        case S_CONTROL: {
          if (ip >= iend) return [ip, 'need']
          const c = inp[ip++]
          if (c === 0) return [ip, 'eof']
          if (c >= 0xE0 || c === 1) {
            this.needProps = true
            this.needDictReset = false
            win.reset()
          } else if (this.needDictReset) throw new LZMAError(CORRUPT)
          if (c >= 0x80) {
            this.unpack = (c & 0x1F) << 16
            this.mode = (c >> 5) & 3
            if (this.mode <= 1 && this.needProps) throw new LZMAError(CORRUPT)
            if (this.mode >= 2) this.needProps = false
            if (this.mode === 1) this.core.resetState()
            this.next = S_LZMA
            this.seq = S_U1
          } else {
            if (c > 2) throw new LZMAError(CORRUPT)
            this.unpack = 0
            this.next = S_COPY
            this.seq = S_U1
          }
          break
        }
        case S_U1:
          if (ip >= iend) return [ip, 'need']
          this.unpack += inp[ip++] << 8; this.seq = S_U2; break
        case S_U2:
          if (ip >= iend) return [ip, 'need']
          this.unpack += inp[ip++] + 1
          if (this.next === S_COPY) { this.packed = this.unpack; this.seq = S_COPY }
          else this.seq = S_P1
          break
        case S_P1:
          if (ip >= iend) return [ip, 'need']
          this.packed = inp[ip++] << 8; this.seq = S_P2; break
        case S_P2:
          if (ip >= iend) return [ip, 'need']
          this.packed += inp[ip++] + 1
          if (this.mode >= 2) this.seq = S_PROPS
          else { this.startChunk(); this.seq = S_LZMA }
          break
        case S_PROPS: {
          if (ip >= iend) return [ip, 'need']
          let b = inp[ip++]
          if (b > (4 * 5 + 4) * 9 + 8) throw new LZMAError(CORRUPT)
          const pb = Math.floor(b / 45); b -= pb * 45
          const lp = Math.floor(b / 9), lc = b - lp * 9
          if (lc + lp > 4) throw new LZMAError(CORRUPT)
          this.core.setProps(lc, lp, pb)
          this.core.resetState()
          this.startChunk()
          this.seq = S_LZMA
          break
        }
        case S_LZMA: {
          const lim = Math.min(iend, ip + this.packed)
          const core = this.core
          core.unpack = this.unpack
          const st = core.run(inp, ip, lim, budget, true)
          const used = core.ip - ip
          budget -= this.unpack - core.unpack
          this.unpack = core.unpack
          this.packed -= used
          ip = core.ip
          if (st === 'end') {
            if (this.packed !== 0) throw new LZMAError(CORRUPT)
            this.seq = S_CONTROL
            break
          }
          if (st === 'limit') return [ip, 'limit']
          // need: more input, unless this chunk's input is all there
          if (this.packed === 0) throw new LZMAError(CORRUPT)
          return [ip, 'need']
        }
        case S_COPY: {
          if (this.packed === 0) { this.seq = S_CONTROL; break }
          if (budget <= 0) return [ip, 'limit']
          if (ip >= iend) return [ip, 'need']
          const n = Math.min(this.packed, iend - ip, budget)
          win.write(inp, ip, n)
          ip += n; this.packed -= n; budget -= n
          break
        }
      }
    }
  }
  startChunk() {
    this.core.rcInit()
    this.core.pendLen = 0
  }
}

// ---------------------------------------------------------------------------------------------------------
// Python-compatible decompressor object
// ---------------------------------------------------------------------------------------------------------
export class LZMADecompressor {
  // new LZMADecompressor({format: FORMAT_RAW, filters: [{id: FILTER_LZMA1|FILTER_LZMA2, dict_size, lc, lp, pb}]})
  constructor({ format = FORMAT_RAW, filters } = {}) {
    if (format !== FORMAT_RAW) throw new TypeError('only FORMAT_RAW is implemented')
    if (!filters || filters.length !== 1) throw new LZMAError(BAD_OPTIONS)
    const f = filters[0]
    if (f.id === FILTER_LZMA1) this.s = new Lzma1Stream(f)
    else if (f.id === FILTER_LZMA2) this.s = new Lzma2Stream(f)
    else throw new LZMAError(BAD_OPTIONS)
    this.eof = false
    this.needs_input = true
    this.unused_data = Buffer.alloc(0)
    this.pending = Buffer.alloc(0)    // input not yet consumed by the decoder
  }

  decompress(data, maxLength = -1) {
    if (this.eof) throw new EOFError('Already at end of stream')
    if (data == null) data = Buffer.alloc(0)
    else if (!Buffer.isBuffer(data)) data = Buffer.from(data.buffer, data.byteOffset, data.byteLength)
    const inp = !this.pending.length ? data : !data.length ? this.pending : Buffer.concat([this.pending, data])
    const win = this.s.win
    const out = []
    win.out = out
    const budget = maxLength < 0 ? Infinity : maxLength
    let ip, st
    try {
      [ip, st] = this.s.step(inp, 0, inp.length, budget)
      win.flush()
    } finally {
      win.out = null
    }
    if (st === 'eof') {
      this.eof = true
      this.needs_input = false
      this.unused_data = Buffer.from(inp.subarray(ip))
      this.pending = Buffer.alloc(0)
    } else {
      // keep the unread input (a copy when it is the caller's buffer)
      this.pending = ip >= inp.length ? Buffer.alloc(0) : inp === data ? Buffer.from(inp.subarray(ip)) : inp.subarray(ip)
    }
    const res = out.length === 1 ? out[0] : Buffer.concat(out)
    // Python: needs_input only when the decoder used up the input with output space left
    if (!this.eof) this.needs_input = st === 'need' && res.length < budget
    return res
  }
}

// whole-buffer helper: decompress everything (errors raise)
export function decompressRaw(data, filter) {
  const d = new LZMADecompressor({ format: FORMAT_RAW, filters: [filter] })
  return d.decompress(data)
}
