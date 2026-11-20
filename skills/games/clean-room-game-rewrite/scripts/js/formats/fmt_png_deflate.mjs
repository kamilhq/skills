// Hand-written deflate encoder used by fmt_png for streams that the C zlib module cannot reproduce.
// Port of fmt_png_deflate.py (itself a port of zlib 1.2.12).
//
// Two halves:
//   * deflate_tokens(): the LZ77 match finder (deflate_fast / deflate_slow, longest_match, fill_window,
//     hash chains, window sliding), parameterised so that non-zlib variants can be expressed
//     (custom good/lazy/nice/chain, position 0 usable as a match source, a tail of N bytes that is
//     never matched into, TOO_FAR distance).
//   * emit_blocks(): trees.c - zlib's Huffman tree builder (build_tree / gen_bitlen with its overflow
//     fix-up / gen_codes), scan_tree/send_tree code-length RLE, and _tr_flush_block's choice between
//     stored, fixed and dynamic blocks.
// With zlib's own parameters the port is bit-identical to the C library.
//
// Tokens: a literal is its byte value (0..255); a match is (length << 16) | distance.
import { adler32 } from '../lib/pyzlib.mjs'

export const MIN_MATCH = 3
export const MAX_MATCH = 258
const MIN_LOOKAHEAD = MAX_MATCH + MIN_MATCH + 1

// zlib configuration_table: level -> [good_length, max_lazy, nice_length, max_chain, func]
export const ZLIB_CONFIG = { 1: [4, 4, 8, 4, 'fast'], 2: [4, 5, 16, 8, 'fast'], 3: [4, 6, 32, 32, 'fast'],
  4: [4, 4, 16, 16, 'slow'], 5: [8, 16, 32, 32, 'slow'], 6: [8, 16, 128, 128, 'slow'],
  7: [8, 32, 128, 256, 'slow'], 8: [32, 128, 258, 1024, 'slow'], 9: [32, 258, 258, 4096, 'slow'] }

const isLit = (t) => t < 256
const tokLen = (t) => t >>> 16
const tokDist = (t) => t & 0xffff
const mkMatch = (len, dist) => (len << 16) | dist

// LZ77 stage. Returns [[tokens, input_available, start, end]].
// Emulates feeding the whole input at once (as zlib.compressobj().compress(data) does).
export function deflate_tokens(data, good, lazy, nice, chain, func, wbits = 15, memlevel = 8, strategy = 0,
  pos0_matchable = false, too_far = 4096, tail_unmatched = 0, block_symbols = null) {
  const wsize = 1 << wbits
  const wmask = wsize - 1
  const window_size = 2 * wsize
  const hash_bits = memlevel + 7
  const hash_size = 1 << hash_bits
  const hash_mask = hash_size - 1
  const hash_shift = Math.floor((hash_bits + MIN_MATCH - 1) / MIN_MATCH)
  if (block_symbols === null || block_symbols === undefined) block_symbols = (1 << (memlevel + 6)) - 1
  const NIL = pos0_matchable ? -1 : 0
  const window = new Uint8Array(window_size)
  const head = new Int32Array(hash_size).fill(NIL)
  const prev = new Int32Array(wsize).fill(NIL)
  const MAX_DIST = wsize - MIN_LOOKAHEAD
  let strstart = 0, lookahead = 0, ins_h = 0, insert = 0, match_start = 0, inpos = 0, block_start = 0,
    abs_start = 0
  const n_in = data.length
  const blocks = []
  let cur = []
  const w = window

  function fill_window() {
    for (;;) {
      let more = window_size - lookahead - strstart
      if (strstart >= wsize + MAX_DIST) {
        window.copyWithin(0, wsize, wsize + wsize - more)
        match_start -= wsize
        strstart -= wsize
        block_start -= wsize
        if (insert > strstart) insert = strstart
        for (let i = 0; i < hash_size; i++) {
          const m = head[i]
          head[i] = m >= wsize ? m - wsize : NIL
        }
        for (let i = 0; i < wsize; i++) {
          const m = prev[i]
          prev[i] = m >= wsize ? m - wsize : NIL
        }
        more += wsize
      }
      const avail = n_in - inpos
      if (avail === 0) break
      const n = Math.min(avail, more)
      const p = strstart + lookahead
      window.set(data.subarray(inpos, inpos + n), p)
      inpos += n
      lookahead += n
      if (lookahead + insert >= MIN_MATCH) {
        let s = strstart - insert
        let h = ((window[s] << hash_shift) ^ window[s + 1]) & hash_mask
        while (insert) {
          h = ((h << hash_shift) ^ window[s + 2]) & hash_mask
          prev[s & wmask] = head[h]
          head[h] = s
          s += 1
          insert -= 1
          if (lookahead + insert < MIN_MATCH) break
        }
        ins_h = h
      }
      if (!(lookahead < MIN_LOOKAHEAD && n_in - inpos !== 0)) break
    }
  }

  function longest_match(cur_match, prev_length) {
    let chain_length = chain
    const scan = strstart
    let best_len = prev_length
    let nice_match = nice
    const limit = strstart > MAX_DIST ? strstart - MAX_DIST : (pos0_matchable ? -1 : 0)
    let scan_end1 = w[scan + best_len - 1]
    let scan_end = w[scan + best_len]
    if (prev_length >= good) chain_length >>= 2
    if (nice_match > lookahead) nice_match = lookahead
    for (;;) {
      const m = cur_match
      if (!(w[m + best_len] !== scan_end || w[m + best_len - 1] !== scan_end1 ||
            w[m] !== w[scan] || w[m + 1] !== w[scan + 1])) {
        let ln = 2
        while (ln < MAX_MATCH && w[scan + ln] === w[m + ln]) ln += 1
        if (ln > best_len) {
          match_start = cur_match
          best_len = ln
          if (ln >= nice_match) break
          scan_end1 = w[scan + best_len - 1]
          scan_end = w[scan + best_len]
        }
      }
      cur_match = prev[cur_match & wmask]
      chain_length -= 1
      if (!(cur_match > limit && chain_length !== 0)) break
    }
    const la = lookahead - tail_unmatched
    return best_len <= la ? best_len : la
  }

  function ins(s) {
    const h = ((ins_h << hash_shift) ^ window[s + 2]) & hash_mask
    ins_h = h
    const hh = head[h]
    prev[s & wmask] = hh
    head[h] = s
    return hh
  }

  function flush() {
    // zlib passes the block's input to _tr_flush_block only while block_start >= 0 (not slid away)
    const abs_end = inpos - lookahead
    blocks.push([cur, block_start >= 0, abs_start, abs_end])
    cur = []
    block_start = strstart
    abs_start = abs_end
  }

  if (func === 'fast') {
    let match_length = 0
    for (;;) {
      if (lookahead < MIN_LOOKAHEAD) {
        fill_window()
        if (lookahead === 0) break
      }
      let hash_head = NIL
      if (lookahead >= MIN_MATCH) hash_head = ins(strstart)
      if (hash_head !== NIL && strstart - hash_head <= MAX_DIST) match_length = longest_match(hash_head, MIN_MATCH - 1)
      if (match_length >= MIN_MATCH) {
        cur.push(mkMatch(match_length, strstart - match_start))
        lookahead -= match_length
        if (match_length <= lazy && lookahead >= MIN_MATCH) {
          match_length -= 1
          for (;;) {
            strstart += 1
            ins(strstart)
            match_length -= 1
            if (match_length === 0) break
          }
          strstart += 1
        } else {
          strstart += match_length
          match_length = 0
          const s = strstart
          ins_h = ((window[s] << hash_shift) ^ window[s + 1]) & hash_mask
        }
      } else {
        cur.push(window[strstart])
        lookahead -= 1
        strstart += 1
      }
      if (cur.length === block_symbols) flush()
    }
  } else {
    let match_length = MIN_MATCH - 1
    let match_available = 0
    for (;;) {
      if (lookahead < MIN_LOOKAHEAD) {
        fill_window()
        if (lookahead === 0) break
      }
      let hash_head = NIL
      if (lookahead >= MIN_MATCH) hash_head = ins(strstart)
      let prev_length = match_length
      const prev_match = match_start
      match_length = MIN_MATCH - 1
      if (hash_head !== NIL && prev_length < lazy && strstart - hash_head <= MAX_DIST) {
        match_length = longest_match(hash_head, prev_length)
        if (match_length <= 5 && (strategy === 1 || (match_length === MIN_MATCH &&
                                                     strstart - match_start > too_far))) {
          match_length = MIN_MATCH - 1
        }
      }
      if (prev_length >= MIN_MATCH && match_length <= prev_length) {
        const max_insert = strstart + lookahead - MIN_MATCH
        cur.push(mkMatch(prev_length, strstart - 1 - prev_match))
        lookahead -= prev_length - 1
        prev_length -= 2
        for (;;) {
          strstart += 1
          if (strstart <= max_insert) ins(strstart)
          prev_length -= 1
          if (prev_length === 0) break
        }
        match_available = 0
        match_length = MIN_MATCH - 1
        strstart += 1
        if (cur.length === block_symbols) flush()
      } else if (match_available) {
        cur.push(window[strstart - 1])
        if (cur.length === block_symbols) flush()
        strstart += 1
        lookahead -= 1
      } else {
        match_available = 1
        strstart += 1
        lookahead -= 1
      }
    }
    if (match_available) cur.push(window[strstart - 1])
  }
  flush()
  return blocks
}

// ---------------------------------------------------------------- trees.c
const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195,
  227, 258]
const LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
  4097, 6145, 8193, 12289, 16385, 24577]
const DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
const BL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
const FIXED_L = [...Array(144).fill(8), ...Array(112).fill(9), ...Array(24).fill(7), ...Array(8).fill(8)]
const FIXED_D = Array(30).fill(5)
const LCODE = new Array(259).fill(0)
for (let i = 0; i < 28; i++) {
  for (let l = LBASE[i]; l < LBASE[i] + (1 << LEXT[i]); l++) if (l <= 258) LCODE[l] = i
}
LCODE[258] = 28
const DCODE = new Array(32769).fill(0)
for (let i = 0; i < 30; i++) {
  for (let d = DBASE[i]; d < Math.min(32768, DBASE[i] + (1 << DEXT[i]) - 1) + 1; d++) DCODE[d] = i
}

export class BitWriter {
  constructor() {
    this.buf = new Uint8Array(1 << 16)
    this.len = 0
    this.acc = 0
    this.n = 0
  }

  _byte(b) {
    if (this.len === this.buf.length) {
      const nb = new Uint8Array(this.buf.length * 2)
      nb.set(this.buf)
      this.buf = nb
    }
    this.buf[this.len++] = b
  }

  bytes(arr) {
    for (let i = 0; i < arr.length; i++) this._byte(arr[i])
  }

  put(v, n) {
    this.acc |= v << this.n
    this.n += n
    while (this.n >= 8) {
      this._byte(this.acc & 255)
      this.acc >>>= 8
      this.n -= 8
    }
  }

  align() {
    if (this.n > 0) this._byte(this.acc & 255)
    this.acc = 0
    this.n = 0
  }

  get out() { return Buffer.from(this.buf.buffer, 0, this.len) }
}

function rev(c, n) {
  let r = 0
  for (let k = 0; k < n; k++) {
    r = (r << 1) | (c & 1)
    c >>= 1
  }
  return r
}

export function gen_codes(lens) {
  const bl = new Array(16).fill(0)
  for (const x of lens) bl[x] += 1
  bl[0] = 0
  const nxt = new Array(16).fill(0)
  let code = 0
  for (let b = 1; b < 16; b++) {
    code = (code + bl[b - 1]) << 1
    nxt[b] = code
  }
  const codes = new Array(lens.length).fill(0)
  lens.forEach((x, i) => {
    if (x) {
      codes[i] = rev(nxt[x], x)
      nxt[x] += 1
    }
  })
  return codes
}

// zlib build_tree + gen_bitlen. Returns [code lengths, max_code].
export function build_tree(freq, max_length, elems) {
  const n = freq.length
  const HEAP_SIZE = 2 * n + 1
  const heap = new Array(2 * n + 2).fill(0)
  const depth = new Array(2 * n + 2).fill(0)
  const fr = [...freq, ...new Array(n + 2).fill(0)]
  const dad = new Array(2 * n + 2).fill(0)
  const ln = new Array(2 * n + 2).fill(0)
  let heap_len = 0
  let heap_max = HEAP_SIZE
  let max_code = -1
  for (let i = 0; i < elems; i++) {
    if (fr[i] !== 0) {
      heap_len += 1
      heap[heap_len] = max_code = i
      depth[i] = 0
    }
  }
  while (heap_len < 2) {
    heap_len += 1
    let node
    if (max_code < 2) {
      max_code += 1
      node = max_code
    } else node = 0
    heap[heap_len] = node
    fr[node] = 1
    depth[node] = 0
  }
  const smaller = (a, b) => fr[a] < fr[b] || (fr[a] === fr[b] && depth[a] <= depth[b])
  const down = (k) => {
    const v = heap[k]
    let j = k << 1
    while (j <= heap_len) {
      if (j < heap_len && smaller(heap[j + 1], heap[j])) j += 1
      if (smaller(v, heap[j])) break
      heap[k] = heap[j]
      k = j
      j <<= 1
    }
    heap[k] = v
  }
  for (let k = Math.floor(heap_len / 2); k > 0; k--) down(k)
  let node = elems
  for (;;) {
    const a = heap[1]
    heap[1] = heap[heap_len]
    heap_len -= 1
    down(1)
    const b = heap[1]
    heap_max -= 1
    heap[heap_max] = a
    heap_max -= 1
    heap[heap_max] = b
    fr[node] = fr[a] + fr[b]
    depth[node] = Math.max(depth[a], depth[b]) + 1
    dad[a] = dad[b] = node
    heap[1] = node
    node += 1
    down(1)
    if (heap_len < 2) break
  }
  heap_max -= 1
  heap[heap_max] = heap[1]
  const bl_count = new Array(16).fill(0)
  ln[heap[heap_max]] = 0
  let overflow = 0
  for (let h = heap_max + 1; h < HEAP_SIZE; h++) {
    const nn = heap[h]
    let bits = ln[dad[nn]] + 1
    if (bits > max_length) {
      bits = max_length
      overflow += 1
    }
    ln[nn] = bits
    if (nn > max_code) continue
    bl_count[bits] += 1
  }
  if (overflow) {
    for (;;) {
      let bits = max_length - 1
      while (bl_count[bits] === 0) bits -= 1
      bl_count[bits] -= 1
      bl_count[bits + 1] += 2
      bl_count[max_length] -= 1
      overflow -= 2
      if (overflow <= 0) break
    }
    let h = HEAP_SIZE
    for (let bits = max_length; bits > 0; bits--) {
      let nn = bl_count[bits]
      while (nn !== 0) {
        h -= 1
        const m = heap[h]
        if (m > max_code) continue
        if (ln[m] !== bits) ln[m] = bits
        nn -= 1
      }
    }
  }
  return [ln.slice(0, elems), max_code]
}

// zlib scan_tree/send_tree run splitting: [[kind, curlen, count, prevlen]]
function tree_runs(lens, max_code) {
  const out = []
  let prevlen = -1
  let nextlen = lens[0]
  let count = 0
  let [max_count, min_count] = nextlen === 0 ? [138, 3] : [7, 4]
  const L = [...lens.slice(0, max_code + 1), 0xffff]
  for (let n = 0; n <= max_code; n++) {
    const curlen = nextlen
    nextlen = L[n + 1]
    count += 1
    if (count < max_count && curlen === nextlen) continue
    else if (count < min_count) out.push(['lit', curlen, count, prevlen])
    else if (curlen !== 0) out.push(['rep', curlen, count, prevlen])
    else if (count <= 10) out.push(['z3', curlen, count, prevlen])
    else out.push(['z11', curlen, count, prevlen])
    count = 0
    prevlen = curlen
    if (nextlen === 0) [max_count, min_count] = [138, 3]
    else if (curlen === nextlen) [max_count, min_count] = [6, 3]
    else [max_count, min_count] = [7, 4]
  }
  return out
}

function scan_tree(lens, max_code, blf) {
  for (const [kind, cl, cnt, prevlen] of tree_runs(lens, max_code)) {
    if (kind === 'lit') blf[cl] += cnt
    else if (kind === 'rep') {
      if (cl !== prevlen) blf[cl] += 1
      blf[16] += 1
    } else if (kind === 'z3') blf[17] += 1
    else blf[18] += 1
  }
}

function send_tree(bw, lens, max_code, blc, bll) {
  for (let [kind, cl, cnt, prevlen] of tree_runs(lens, max_code)) {
    if (kind === 'lit') {
      for (let k = 0; k < cnt; k++) bw.put(blc[cl], bll[cl])
    } else if (kind === 'rep') {
      if (cl !== prevlen) {
        bw.put(blc[cl], bll[cl])
        cnt -= 1
      }
      bw.put(blc[16], bll[16])
      bw.put(cnt - 3, 2)
    } else if (kind === 'z3') {
      bw.put(blc[17], bll[17])
      bw.put(cnt - 3, 3)
    } else {
      bw.put(blc[18], bll[18])
      bw.put(cnt - 11, 7)
    }
  }
}

function freqs(toks) {
  const lf = new Array(286).fill(0)
  const df = new Array(30).fill(0)
  for (const t of toks) {
    if (isLit(t)) lf[t] += 1
    else {
      lf[257 + LCODE[tokLen(t)]] += 1
      df[DCODE[tokDist(t)]] += 1
    }
  }
  lf[256] += 1
  return [lf, df]
}

function compress_block(bw, toks, ll, dl) {
  const lc = gen_codes(ll)
  const dc = gen_codes(dl)
  for (const t of toks) {
    if (isLit(t)) bw.put(lc[t], ll[t])
    else {
      const L = tokLen(t)
      const D = tokDist(t)
      const c = LCODE[L]
      bw.put(lc[257 + c], ll[257 + c])
      if (LEXT[c]) bw.put(L - LBASE[c], LEXT[c])
      const d = DCODE[D]
      bw.put(dc[d], dl[d])
      if (DEXT[d]) bw.put(D - DBASE[d], DEXT[d])
    }
  }
  bw.put(lc[256], ll[256])
}

const sum = (a) => a.reduce((x, y) => x + y, 0)

// zlib _tr_flush_block (level > 0). stored_bytes = block input, or null if not available.
export function flush_block(bw, toks, stored_bytes, last, strategy = 0) {
  const [lf, df] = freqs(toks)
  const [ll, lmax] = build_tree(lf, 15, 286)
  const [dl, dmax] = build_tree(df, 15, 30)
  const blf = new Array(19).fill(0)
  scan_tree(ll, lmax, blf)
  scan_tree(dl, dmax, blf)
  const [bll] = build_tree(blf, 7, 19)
  let max_blindex = 18
  while (max_blindex >= 3 && bll[BL_ORDER[max_blindex]] === 0) max_blindex -= 1
  let extra = 0
  for (let i = 0; i < 29; i++) extra += lf[257 + i] * LEXT[i]
  for (let i = 0; i < 30; i++) extra += df[i] * DEXT[i]
  let opt = 0
  for (let i = 0; i < 286; i++) opt += lf[i] * ll[i]
  for (let i = 0; i < 30; i++) opt += df[i] * dl[i]
  opt += extra
  for (let i = 0; i < 19; i++) opt += blf[i] * bll[i]
  opt += 2 * blf[16] + 3 * blf[17] + 7 * blf[18]
  opt += 14 + 3 * (max_blindex + 1)
  let stat = 0
  for (let i = 0; i < 286; i++) stat += lf[i] * FIXED_L[i]
  stat += 5 * sum(df) + extra
  let opt_lenb = Math.floor((opt + 3 + 7) / 8)
  const static_lenb = Math.floor((stat + 3 + 7) / 8)
  if (static_lenb <= opt_lenb || strategy === 4) opt_lenb = static_lenb
  if (stored_bytes !== null && stored_bytes.length + 4 <= opt_lenb) {
    bw.put(0 | last, 3)
    bw.align()
    const n = stored_bytes.length
    if (n > 0xffff) throw new Error('ValueError: bytes must be in range(0, 256)')
    bw.bytes([n & 255, n >> 8, ~n & 255, (~n >> 8) & 255])
    bw.bytes(stored_bytes)
  } else if (static_lenb === opt_lenb) {
    bw.put(2 | last, 3)
    compress_block(bw, toks, FIXED_L, FIXED_D)
  } else {
    bw.put(4 | last, 3)
    bw.put(lmax + 1 - 257, 5)
    bw.put(dmax + 1 - 1, 5)
    bw.put(max_blindex + 1 - 4, 4)
    const blc = gen_codes(bll)
    for (let r = 0; r <= max_blindex; r++) bw.put(bll[BL_ORDER[r]], 3)
    send_tree(bw, ll, lmax, blc, bll)
    send_tree(bw, dl, dmax, blc, bll)
    compress_block(bw, toks, ll, dl)
  }
}

export function zlib_header(wbits, flevel) {
  const cmf = ((wbits - 8) << 4) | 8
  let h = (cmf << 8) | (flevel << 6)
  h += 31 - (h % 31)          // as zlib's deflate.c: adds 31 when already a multiple
  return Buffer.from([h >> 8, h & 255])
}

// Full zlib stream (header + deflate blocks + Adler-32).
export function compress(data, good, lazy, nice, chain, func, wbits = 15, memlevel = 8, strategy = 0,
  pos0_matchable = false, too_far = 4096, tail_unmatched = 0, flevel = 1, block_symbols = null) {
  const blocks = deflate_tokens(data, good, lazy, nice, chain, func, wbits, memlevel, strategy, pos0_matchable,
    too_far, tail_unmatched, block_symbols)
  const bw = new BitWriter()
  blocks.forEach(([toks, avail, a, b], i) => {
    flush_block(bw, toks, avail ? data.subarray(a, b) : null, i === blocks.length - 1 ? 1 : 0, strategy)
  })
  bw.align()
  const tail = Buffer.alloc(4)
  tail.writeUInt32BE(adler32(data))
  return Buffer.concat([zlib_header(wbits, flevel), bw.out, tail])
}
