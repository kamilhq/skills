"""zlib-stream profiles for fmt_png: find the encoder parameters that regenerate a stored zlib stream
from its decompressed payload, and recompress with them.

Profiles (JSON dicts):
  {"engine": "zlib", "level", "window_bits", "mem_level", "strategy", "finish"}
      Python's zlib module (C zlib). finish = "finish" (one Z_FINISH) or "sync_flush+finish"
      (Z_SYNC_FLUSH after the data, then Z_FINISH: leaves an empty stored block + empty fixed block).
  {"engine": "py_deflate", ...}
      fmt_png_deflate: zlib's match finder / trees.c ported to Python with the variant switches below.
  {"engine": "raw", "file": ...}
      last resort, handled by the caller (stream kept verbatim, counted as opaque).
"""
import zlib

import fmt_png_deflate

STRATEGY_NAMES = {0: 'default', 1: 'filtered', 2: 'huffman_only', 3: 'rle', 4: 'fixed'}
STRATEGY_IDS = {v: k for k, v in STRATEGY_NAMES.items()}

# Non-zlib match finder seen in one game's sprite sheets (two images of one localisation):
# greedy parsing (lazy matching off), hash chain cut at 5 probes, position 0 usable as a match
# source, last 2 input bytes never matched, zlib's TOO_FAR rule, zlib hash and trees.c Huffman coding.
GREEDY5_PROFILE = dict(engine='py_deflate', variant='greedy_chain5',
                       good_length=258, max_lazy=3, nice_length=258, max_chain=5, func='slow',
                       window_bits=15, mem_level=8, strategy='default', pos0_matchable=True,
                       too_far=4096, tail_unmatched=2, block_symbols=16383)

FLEVEL_LEVELS = {0: [1, 0], 1: [2, 3, 4, 5], 2: [6], 3: [9, 7, 8]}


def compress(raw, prof):
    eng = prof['engine']
    if eng == 'zlib':
        co = zlib.compressobj(prof['level'], zlib.DEFLATED, prof['window_bits'], prof['mem_level'],
                              STRATEGY_IDS[prof['strategy']])
        out = co.compress(raw)
        if prof.get('finish', 'finish') == 'sync_flush+finish':
            out += co.flush(zlib.Z_SYNC_FLUSH)
        return out + co.flush(zlib.Z_FINISH)
    if eng == 'py_deflate':
        return fmt_png_deflate.compress(
            raw, prof['good_length'], prof['max_lazy'], prof['nice_length'], prof['max_chain'], prof['func'],
            prof['window_bits'], prof['mem_level'], STRATEGY_IDS[prof['strategy']], prof['pos0_matchable'],
            prof['too_far'], prof['tail_unmatched'], prof['header_flevel'], prof['block_symbols'])
    raise ValueError(f'cannot compress with engine {eng}')


def find_profile(stream, raw):
    """Return a profile dict that regenerates `stream` from `raw`, or None."""
    if len(stream) < 2:
        return None
    cmf, flg = stream[0], stream[1]
    if cmf & 15 != 8 or ((cmf << 8) | flg) % 31 or flg & 0x20:
        return None
    wbits = (cmf >> 4) + 8
    flevel = flg >> 6
    if wbits > 15:
        return None
    wb_try = [wbits] if wbits > 8 else [9]
    levels = FLEVEL_LEVELS[flevel]
    combos = []
    for ml in [8, 9, 7, 6, 5, 4, 3, 2, 1]:
        for fin in ('finish', 'sync_flush+finish'):
            for lv in levels:
                for st in (0, 1):
                    combos.append((lv, ml, st, fin))
            if flevel == 0:
                for st in (2, 3):
                    combos.append((6, ml, st, fin))
    for wb in wb_try:
        for lv, ml, st, fin in combos:
            prof = dict(engine='zlib', level=lv, window_bits=wb, mem_level=ml, strategy=STRATEGY_NAMES[st],
                        finish=fin)
            if compress(raw, prof) == stream:
                return prof
    # non-zlib variants (pure Python, slower): only the one identified so far (GREEDY5_PROFILE)
    prof = dict(GREEDY5_PROFILE, window_bits=wbits, header_flevel=flevel)
    if len(raw) <= 4 << 20 and compress(raw, prof) == stream:
        return prof
    return None


def describe(prof):
    if prof['engine'] == 'zlib':
        s = f"zlib level {prof['level']} wbits {prof['window_bits']} memLevel {prof['mem_level']} {prof['strategy']}"
        if prof.get('finish') != 'finish':
            s += ' + ' + prof['finish']
        return s
    if prof['engine'] == 'py_deflate':
        return f"py_deflate {prof.get('variant', '')}"
    return prof['engine']
