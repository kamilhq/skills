// zlib-stream profiles for fmt_png: find the encoder parameters that regenerate a stored zlib stream
// from its decompressed payload, and recompress with them. Port of fmt_png_zlib.py.
//
// Profiles (JSON dicts):
//   {"engine": "zlib", "level", "window_bits", "mem_level", "strategy", "finish"}
//       Python's zlib module (C zlib) = lib/pyzlib.mjs. finish = "finish" (one Z_FINISH) or
//       "sync_flush+finish" (Z_SYNC_FLUSH after the data, then Z_FINISH: leaves an empty stored block + empty
//       fixed block).
//   {"engine": "py_deflate", ...}
//       fmt_png_deflate: zlib's match finder / trees.c ported, with the variant switches below.
//   {"engine": "raw", "file": ...}
//       last resort, handled by the caller (stream kept verbatim, counted as opaque).
import { compressobj, DEFLATED, Z_FINISH, Z_SYNC_FLUSH } from '../lib/pyzlib.mjs'
import * as fmt_png_deflate from './fmt_png_deflate.mjs'

export const STRATEGY_NAMES = { 0: 'default', 1: 'filtered', 2: 'huffman_only', 3: 'rle', 4: 'fixed' }
export const STRATEGY_IDS = Object.fromEntries(Object.entries(STRATEGY_NAMES).map(([k, v]) => [v, Number(k)]))

// Non-zlib match finder seen in one game's sprite sheets (two images of one localisation):
// greedy parsing (lazy matching off), hash chain cut at 5 probes, position 0 usable as a match
// source, last 2 input bytes never matched, zlib's TOO_FAR rule, zlib hash and trees.c Huffman coding.
export const GREEDY5_PROFILE = { engine: 'py_deflate', variant: 'greedy_chain5',
  good_length: 258, max_lazy: 3, nice_length: 258, max_chain: 5, func: 'slow',
  window_bits: 15, mem_level: 8, strategy: 'default', pos0_matchable: true,
  too_far: 4096, tail_unmatched: 2, block_symbols: 16383 }

const FLEVEL_LEVELS = { 0: [1, 0], 1: [2, 3, 4, 5], 2: [6], 3: [9, 7, 8] }

function strategyId(name) {
  if (!(name in STRATEGY_IDS)) throw new Error(`KeyError: '${name}'`)
  return STRATEGY_IDS[name]
}

export function compress(raw, prof) {
  const eng = prof.engine
  if (eng === 'zlib') {
    const co = compressobj(prof.level, DEFLATED, prof.window_bits, prof.mem_level, strategyId(prof.strategy))
    const parts = [co.compress(raw)]
    if ((prof.finish ?? 'finish') === 'sync_flush+finish') parts.push(co.flush(Z_SYNC_FLUSH))
    parts.push(co.flush(Z_FINISH))
    return Buffer.concat(parts)
  }
  if (eng === 'py_deflate') {
    return fmt_png_deflate.compress(
      raw, prof.good_length, prof.max_lazy, prof.nice_length, prof.max_chain, prof.func,
      prof.window_bits, prof.mem_level, strategyId(prof.strategy), prof.pos0_matchable,
      prof.too_far, prof.tail_unmatched, prof.header_flevel, prof.block_symbols)
  }
  throw new Error(`ValueError: cannot compress with engine ${eng}`)
}

// Return a profile dict that regenerates `stream` from `raw`, or null.
export function find_profile(stream, raw) {
  if (stream.length < 2) return null
  const cmf = stream[0]
  const flg = stream[1]
  if ((cmf & 15) !== 8 || ((cmf << 8) | flg) % 31 || flg & 0x20) return null
  const wbits = (cmf >> 4) + 8
  const flevel = flg >> 6
  if (wbits > 15) return null
  const wbTry = wbits > 8 ? [wbits] : [9]
  const levels = FLEVEL_LEVELS[flevel]
  const combos = []
  for (const ml of [8, 9, 7, 6, 5, 4, 3, 2, 1]) {
    for (const fin of ['finish', 'sync_flush+finish']) {
      for (const lv of levels) for (const st of [0, 1]) combos.push([lv, ml, st, fin])
      if (flevel === 0) for (const st of [2, 3]) combos.push([6, ml, st, fin])
    }
  }
  for (const wb of wbTry) {
    for (const [lv, ml, st, fin] of combos) {
      const prof = { engine: 'zlib', level: lv, window_bits: wb, mem_level: ml, strategy: STRATEGY_NAMES[st],
        finish: fin }
      if (compress(raw, prof).equals(stream)) return prof
    }
  }
  // non-zlib variants (slower): only the one identified so far (GREEDY5_PROFILE)
  const prof = { ...GREEDY5_PROFILE, window_bits: wbits, header_flevel: flevel }
  if (raw.length <= 4 << 20 && compress(raw, prof).equals(stream)) return prof
  return null
}

export function describe(prof) {
  if (prof.engine === 'zlib') {
    let s = `zlib level ${prof.level} wbits ${prof.window_bits} memLevel ${prof.mem_level} ${prof.strategy}`
    if (prof.finish !== 'finish') s += ' + ' + (prof.finish ?? 'None')
    return s
  }
  if (prof.engine === 'py_deflate') return `py_deflate ${prof.variant ?? ''}`
  return prof.engine
}
