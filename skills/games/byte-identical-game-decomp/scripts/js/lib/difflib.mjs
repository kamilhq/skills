// Port of the SequenceMatcher part of Python 3.9's difflib (Node built-ins only).
//
//   new SequenceMatcher(isjunk = null, a = [], b = [], autojunk = true)
//     .set_seqs(a, b) / .set_seq1(a) / .set_seq2(b)
//     .find_longest_match(alo = 0, ahi = null, blo = 0, bhi = null) -> Match {a, b, size}
//     .get_matching_blocks()  -> [Match ...] ending with the (len(a), len(b), 0) sentinel
//     .get_opcodes()          -> [[tag, i1, i2, j1, j2] ...]
//     .get_grouped_opcodes(n = 3), .ratio(), .quick_ratio(), .real_quick_ratio()
//
// Results equal Python's exactly: same algorithm, same iteration order, same tie-breaking, the same "popular
// element" autojunk heuristic (b of 200+ items: elements occurring more than len(b) // 100 + 1 times are
// dropped from b2j) and the same isjunk handling.
//
// Sequences: arrays (or typed arrays / Buffers) of numbers, strings, booleans, null, BigInt or nested arrays
// (Python tuples, e.g. ['?', 3]); a JS string is a sequence of its code points (like a Python str).
// Equality and hashing follow Python: 1 == 1.0 == True, ('?', 1) == ('?', 1); elements are compared through a
// canonical key, so two distinct arrays with the same contents are equal (as tuples are in Python).
// isjunk(elt) is called with the original element, once per distinct element of b (like Python).

export class Match {
  constructor(a, b, size) { this.a = a; this.b = b; this.size = size }
  // Python's Match is a namedtuple: iterable and indexable
  *[Symbol.iterator]() { yield this.a; yield this.b; yield this.size }
  get 0() { return this.a }
  get 1() { return this.b }
  get 2() { return this.size }
  get length() { return 3 }
  toJSON() { return [this.a, this.b, this.size] }
}

// canonical key: equal keys <=> equal Python values (for ints, floats, bools, None, str, tuples of those)
export function eltKey(x) {
  switch (typeof x) {
    case 'number':
      if (Number.isInteger(x)) return Number.isSafeInteger(x) ? (x === 0 ? 0 : x) : 'i:' + BigInt(x).toString()
      if (Number.isNaN(x)) return 'nan'          // Python: nan != nan, but a dict finds the same object
      return 'f:' + String(x)
    case 'bigint':
      return (x >= -9007199254740991n && x <= 9007199254740991n) ? Number(x) : 'i:' + x.toString()
    case 'boolean':
      return x ? 1 : 0
    case 'string':
      return 's:' + x
    case 'undefined':
      return 'N'
    case 'object':
      if (x === null) return 'N'
      if (typeof x.valueOf === 'function' && typeof x.valueOf() === 'number' && !Array.isArray(x)) return eltKey(x.valueOf())
      if (Array.isArray(x) || ArrayBuffer.isView(x)) {
        return 't:' + JSON.stringify(Array.from(x, eltKey))
      }
      break
  }
  throw new TypeError(`unhashable element: ${Object.prototype.toString.call(x)}`)
}

function toSeq(s) {
  if (s === null || s === undefined) return []
  if (typeof s === 'string') return Array.from(s)
  return s
}

function keysOf(seq) {
  const n = seq.length
  // fast path: plain small integers (bytes, opcodes, addresses) are their own keys
  if (ArrayBuffer.isView(seq) && !(seq instanceof BigInt64Array) && !(seq instanceof BigUint64Array) &&
      !(seq instanceof Float32Array) && !(seq instanceof Float64Array)) return seq
  const out = new Array(n)
  for (let i = 0; i < n; i++) out[i] = eltKey(seq[i])
  return out
}

function calculateRatio(matches, length) {
  return length ? 2.0 * matches / length : 1.0
}

export class SequenceMatcher {
  constructor(isjunk = null, a = '', b = '', autojunk = true) {
    this.isjunk = isjunk
    this.a = this.b = null
    this.autojunk = autojunk
    this.set_seqs(a, b)
  }

  set_seqs(a, b) {
    this.set_seq1(a)
    this.set_seq2(b)
  }

  set_seq1(a) {
    if (a === this._a_src && this.a !== null) return
    this._a_src = a
    this.a = toSeq(a)
    this._ak = keysOf(this.a)
    this.matching_blocks = this.opcodes = null
  }

  set_seq2(b) {
    if (b === this._b_src && this.b !== null) return
    this._b_src = b
    this.b = toSeq(b)
    this._bk = keysOf(this.b)
    this.matching_blocks = this.opcodes = null
    this.fullbcount = null
    this._chain_b()
  }

  _chain_b() {
    const b = this.b, bk = this._bk
    const b2j = new Map()           // key -> [j ...] (insertion order = first occurrence, like Python's dict)
    const firstElt = new Map()      // key -> an original element (for isjunk)
    for (let i = 0; i < bk.length; i++) {
      const k = bk[i]
      let idx = b2j.get(k)
      if (idx === undefined) { idx = []; b2j.set(k, idx); firstElt.set(k, b[i]) }
      idx.push(i)
    }
    const junk = new Set()
    if (this.isjunk) {
      for (const k of b2j.keys()) if (this.isjunk(firstElt.get(k))) junk.add(k)
      for (const k of junk) b2j.delete(k)
    }
    const popular = new Set()
    const n = b.length
    if (this.autojunk && n >= 200) {
      const ntest = Math.floor(n / 100) + 1
      for (const [k, idxs] of b2j) if (idxs.length > ntest) popular.add(k)
      for (const k of popular) b2j.delete(k)
    }
    this.b2j = b2j
    this._bjunk = junk
    this._bpopular = popular
    this._firstElt = firstElt
  }

  // Python exposes these sets of elements
  get bjunk() { return new Set([...this._bjunk].map((k) => this._firstElt.get(k))) }
  get bpopular() { return new Set([...this._bpopular].map((k) => this._firstElt.get(k))) }

  find_longest_match(alo = 0, ahi = null, blo = 0, bhi = null) {
    const ak = this._ak, bk = this._bk, b2j = this.b2j, junk = this._bjunk
    if (ahi === null || ahi === undefined) ahi = ak.length
    if (bhi === null || bhi === undefined) bhi = bk.length
    let besti = alo, bestj = blo, bestsize = 0
    // j2len[j + 1] = length of the match ending at a[i-1], b[j] (the previous row); newj2len for the row of i
    const lb = bk.length
    if (!this._j2a || this._j2a.length < lb + 1) {
      this._j2a = new Int32Array(lb + 1)
      this._j2b = new Int32Array(lb + 1)
    }
    let j2len = this._j2a, newj2len = this._j2b
    let touched = [], newTouched = []
    const nothing = []
    for (let i = alo; i < ahi; i++) {
      const idxs = b2j.get(ak[i]) || nothing
      for (let t = 0; t < idxs.length; t++) {
        const j = idxs[t]
        if (j < blo) continue
        if (j >= bhi) break
        const k = j2len[j] + 1
        newj2len[j + 1] = k
        newTouched.push(j + 1)
        if (k > bestsize) { besti = i - k + 1; bestj = j - k + 1; bestsize = k }
      }
      for (let t = 0; t < touched.length; t++) j2len[touched[t]] = 0
      const tmp = j2len; j2len = newj2len; newj2len = tmp
      touched = newTouched; newTouched = []
    }
    for (let t = 0; t < touched.length; t++) j2len[touched[t]] = 0

    const isbjunk = (k) => junk.has(k)
    while (besti > alo && bestj > blo && !isbjunk(bk[bestj - 1]) && ak[besti - 1] === bk[bestj - 1]) {
      besti--; bestj--; bestsize++
    }
    while (besti + bestsize < ahi && bestj + bestsize < bhi && !isbjunk(bk[bestj + bestsize]) &&
           ak[besti + bestsize] === bk[bestj + bestsize]) {
      bestsize++
    }
    while (besti > alo && bestj > blo && isbjunk(bk[bestj - 1]) && ak[besti - 1] === bk[bestj - 1]) {
      besti--; bestj--; bestsize++
    }
    while (besti + bestsize < ahi && bestj + bestsize < bhi && isbjunk(bk[bestj + bestsize]) &&
           ak[besti + bestsize] === bk[bestj + bestsize]) {
      bestsize++
    }
    return new Match(besti, bestj, bestsize)
  }

  get_matching_blocks() {
    if (this.matching_blocks !== null) return this.matching_blocks
    const la = this.a.length, lb = this.b.length
    const queue = [[0, la, 0, lb]]
    const blocks = []
    while (queue.length) {
      const [alo, ahi, blo, bhi] = queue.pop()
      const x = this.find_longest_match(alo, ahi, blo, bhi)
      const i = x.a, j = x.b, k = x.size
      if (k) {
        blocks.push([i, j, k])
        if (alo < i && blo < j) queue.push([alo, i, blo, j])
        if (i + k < ahi && j + k < bhi) queue.push([i + k, ahi, j + k, bhi])
      }
    }
    blocks.sort((p, q) => (p[0] - q[0]) || (p[1] - q[1]) || (p[2] - q[2]))
    let i1 = 0, j1 = 0, k1 = 0
    const nonAdjacent = []
    for (const [i2, j2, k2] of blocks) {
      if (i1 + k1 === i2 && j1 + k1 === j2) k1 += k2
      else {
        if (k1) nonAdjacent.push([i1, j1, k1])
        i1 = i2; j1 = j2; k1 = k2
      }
    }
    if (k1) nonAdjacent.push([i1, j1, k1])
    nonAdjacent.push([la, lb, 0])
    this.matching_blocks = nonAdjacent.map(([a, b, s]) => new Match(a, b, s))
    return this.matching_blocks
  }

  get_opcodes() {
    if (this.opcodes !== null) return this.opcodes
    let i = 0, j = 0
    const answer = this.opcodes = []
    for (const { a: ai, b: bj, size } of this.get_matching_blocks()) {
      let tag = ''
      if (i < ai && j < bj) tag = 'replace'
      else if (i < ai) tag = 'delete'
      else if (j < bj) tag = 'insert'
      if (tag) answer.push([tag, i, ai, j, bj])
      i = ai + size; j = bj + size
      if (size) answer.push(['equal', ai, i, bj, j])
    }
    return answer
  }

  get_grouped_opcodes(n = 3) {
    let codes = this.get_opcodes().map((c) => c.slice())
    if (!codes.length) codes = [['equal', 0, 1, 0, 1]]
    if (codes[0][0] === 'equal') {
      const [tag, i1, i2, j1, j2] = codes[0]
      codes[0] = [tag, Math.max(i1, i2 - n), i2, Math.max(j1, j2 - n), j2]
    }
    if (codes[codes.length - 1][0] === 'equal') {
      const [tag, i1, i2, j1, j2] = codes[codes.length - 1]
      codes[codes.length - 1] = [tag, i1, Math.min(i2, i1 + n), j1, Math.min(j2, j1 + n)]
    }
    const nn = n + n
    const out = []
    let group = []
    for (let [tag, i1, i2, j1, j2] of codes) {
      if (tag === 'equal' && i2 - i1 > nn) {
        group.push([tag, i1, Math.min(i2, i1 + n), j1, Math.min(j2, j1 + n)])
        out.push(group)
        group = []
        i1 = Math.max(i1, i2 - n); j1 = Math.max(j1, j2 - n)
      }
      group.push([tag, i1, i2, j1, j2])
    }
    if (group.length && !(group.length === 1 && group[0][0] === 'equal')) out.push(group)
    return out
  }

  ratio() {
    let matches = 0
    for (const m of this.get_matching_blocks()) matches += m.size
    return calculateRatio(matches, this.a.length + this.b.length)
  }

  quick_ratio() {
    if (this.fullbcount === null) {
      const c = new Map()
      for (const k of this._bk) c.set(k, (c.get(k) || 0) + 1)
      this.fullbcount = c
    }
    const fullbcount = this.fullbcount
    const avail = new Map()
    let matches = 0
    for (const k of this._ak) {
      const numb = avail.has(k) ? avail.get(k) : (fullbcount.get(k) || 0)
      avail.set(k, numb - 1)
      if (numb > 0) matches++
    }
    return calculateRatio(matches, this.a.length + this.b.length)
  }

  real_quick_ratio() {
    const la = this.a.length, lb = this.b.length
    return calculateRatio(Math.min(la, lb), la + lb)
  }
}
