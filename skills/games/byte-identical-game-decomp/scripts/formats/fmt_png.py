"""PNG decoder/encoder (byte-identical round trip).

Decoded directory:
  png.json        IHDR fields, every chunk in file order with its fields decoded, the zlib profile that
                  regenerates the IDAT stream, IDAT split policy, row-filter policy (+ per-row exceptions),
                  non-zero padding bits of low-bit-depth rows.
  pixels.png      8-bit canonical image (L / LA / RGB / RGBA). Source of truth for non-palette images
                  (low-bit gray is scaled to 0..255: 1-bit -> 0/255, 2-bit -> x85, 4-bit -> x17).
                  For palette images it is an RGBA preview only (not read by the encoder).
  indices.png     palette images: 8-bit L image of palette indices (source of truth).
  palette.json    palette images: RGBA entries (PLTE rgb + tRNS alpha) and how many alphas tRNS carries.
  NN_iCCP.icc     decompressed ICC profile of an iCCP chunk (NN = chunk index); its zlib profile is in png.json.
  NN_eXIf.exif    the eXIf chunk body (TIFF-structured Exif, source of truth) + NN_eXIf.json (parsed IFD0).
Encode reads only these files; lengths and CRCs are recomputed.
"""
import json
import os
import struct
import zlib

import pngio
import fmt_png_zlib

EXTS = ['.png']
SIG = b'\x89PNG\r\n\x1a\n'
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
CT_NAMES = {0: 'gray', 2: 'rgb', 3: 'palette', 4: 'gray_alpha', 6: 'rgba'}
CANON_MODE = {0: 'L', 2: 'RGB', 4: 'LA', 6: 'RGBA'}
ADAM7 = [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]
SRGB_INTENTS = ['perceptual', 'relative_colorimetric', 'saturation', 'absolute_colorimetric']
CHRM_FIELDS = ['white_x', 'white_y', 'red_x', 'red_y', 'green_x', 'green_y', 'blue_x', 'blue_y']
FILTER_NAMES = ['none', 'sub', 'up', 'average', 'paeth']
ABS_TABLE = bytes(v if v < 128 else 256 - v for v in range(256))


# ------------------------------------------------------------------ geometry / rows
def passes(w, h, interlace):
    """[(x0, y0, dx, dy, pass_w, pass_h)] for the non-empty passes."""
    if not interlace:
        return [(0, 0, 1, 1, w, h)]
    out = []
    for x0, y0, dx, dy in ADAM7:
        pw = (w - x0 + dx - 1) // dx if w > x0 else 0
        ph = (h - y0 + dy - 1) // dy if h > y0 else 0
        if pw and ph:
            out.append((x0, y0, dx, dy, pw, ph))
    return out


def _paeth(a, b, c):
    pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
    return a if pa <= pb and pa <= pc else (b if pb <= pc else c)


def unfilter(ft, line, prev, bpp):
    n = len(line)
    if ft == 0:
        return bytearray(line)
    if ft == 2:
        return bytearray((x + y) & 255 for x, y in zip(line, prev))
    out = bytearray(line)
    if ft == 1:
        for i in range(bpp, n):
            out[i] = (out[i] + out[i - bpp]) & 255
    elif ft == 3:
        for i in range(n):
            a = out[i - bpp] if i >= bpp else 0
            out[i] = (out[i] + ((a + prev[i]) >> 1)) & 255
    elif ft == 4:
        for i in range(n):
            if i >= bpp:
                out[i] = (out[i] + _paeth(out[i - bpp], prev[i], prev[i - bpp])) & 255
            else:
                out[i] = (out[i] + prev[i]) & 255
    else:
        raise ValueError(f'bad filter type {ft}')
    return out


def filter_row(ft, line, prev, bpp):
    if ft == 0:
        return bytes(line)
    if ft == 1:
        return bytes(line[:bpp]) + bytes((x - y) & 255 for x, y in zip(line[bpp:], line))
    if ft == 2:
        return bytes((x - y) & 255 for x, y in zip(line, prev))
    n = len(line)
    out = bytearray(n)
    if ft == 3:
        for i in range(n):
            a = line[i - bpp] if i >= bpp else 0
            out[i] = (line[i] - ((a + prev[i]) >> 1)) & 255
    elif ft == 4:
        for i in range(n):
            if i >= bpp:
                out[i] = (line[i] - _paeth(line[i - bpp], prev[i], prev[i - bpp])) & 255
            else:
                out[i] = (line[i] - prev[i]) & 255
    else:
        raise ValueError(f'bad filter type {ft}')
    return bytes(out)


def minsum_filter(line, prev, bpp):
    """libpng png_write_find_filter with all five filters enabled: minimum sum of |signed byte|,
    candidates tried in order none, sub, up, average, paeth; a later one wins only if strictly smaller."""
    best_ft, best_sum, best_row = 0, sum(bytes(line).translate(ABS_TABLE)), None
    for ft in (1, 2, 3, 4):
        r = filter_row(ft, line, prev, bpp)
        s = sum(r.translate(ABS_TABLE))
        if s < best_sum:
            best_ft, best_sum, best_row = ft, s, r
    return best_ft, (best_row if best_row is not None else bytes(line))


# ------------------------------------------------------------------ sample packing
def _unpack_table(bd):
    per = 8 // bd
    mask = (1 << bd) - 1
    return [bytes((b >> (8 - bd * (k + 1))) & mask for k in range(per)) for b in range(256)]


def unpack_row(row, bd, n):
    """row bytes -> (n samples as bytes, padding value)."""
    if bd == 8:
        return bytes(row), 0
    tab = _unpack_table(bd)
    s = b''.join(tab[b] for b in row)[:n]
    rem = (n * bd) % 8
    pad = row[-1] & ((1 << (8 - rem)) - 1) if rem else 0
    return s, pad


def pack_row(samples, bd, pad):
    if bd == 8:
        return bytes(samples)
    per = 8 // bd
    out = bytearray()
    for i in range(0, len(samples), per):
        v = 0
        grp = samples[i:i + per]
        for k, s in enumerate(grp):
            v |= (s & ((1 << bd) - 1)) << (8 - bd * (k + 1))
        out.append(v)
    if (len(samples) * bd) % 8:
        out[-1] |= pad
    return bytes(out)


# ------------------------------------------------------------------ chunks
def _chunk(t, body, crc=None):
    c = zlib.crc32(t + body) & 0xffffffff if crc is None else crc
    return struct.pack('>I', len(body)) + t + body + struct.pack('>I', c)


def parse_chunks(data):
    if data[:8] != SIG:
        raise ValueError('not a PNG')
    pos, out = 8, []
    while pos + 12 <= len(data):
        ln, t = struct.unpack('>I4s', data[pos:pos + 8])
        if pos + 12 + ln > len(data):
            break
        body = data[pos + 8:pos + 8 + ln]
        crc = struct.unpack('>I', data[pos + 8 + ln:pos + 12 + ln])[0]
        out.append((t.decode('latin-1'), body, crc))
        pos += 12 + ln
        if t == b'IEND':
            break
    return out, data[pos:]


def _latin(b):
    return b.decode('latin-1')


def parse_exif(b):
    """Parse a TIFF-structured Exif blob's IFD0. Returns (json, bytes_accounted_for)."""
    if len(b) < 8 or b[:2] not in (b'II', b'MM'):
        return {'error': 'not TIFF-structured'}, 0
    e = '<' if b[:2] == b'II' else '>'
    magic, ifd = struct.unpack(e + 'HI', b[2:8])
    info = {'byte_order': _latin(b[:2]), 'magic': magic, 'ifd0_offset': ifd, 'ifd0': []}
    covered = 8
    if ifd + 2 > len(b):
        return info, covered
    n = struct.unpack(e + 'H', b[ifd:ifd + 2])[0]
    covered += 2
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
    for i in range(n):
        o = ifd + 2 + 12 * i
        if o + 12 > len(b):
            return info, covered
        tag, typ, cnt = struct.unpack(e + 'HHI', b[o:o + 8])
        size = sizes.get(typ, 1) * cnt
        if size <= 4:
            val = b[o + 8:o + 8 + size]
        else:
            off = struct.unpack(e + 'I', b[o + 8:o + 12])[0]
            val = b[off:off + size]
            covered += len(val)
        info['ifd0'].append({'tag': tag, 'type': typ, 'count': cnt, 'value_hex': val.hex()})
        covered += 12
    if ifd + 2 + 12 * n + 4 <= len(b):
        info['next_ifd'] = struct.unpack(e + 'I', b[ifd + 2 + 12 * n:ifd + 6 + 12 * n])[0]
        covered += 4
    return info, min(covered, len(b))


# ------------------------------------------------------------------ decode
def decode_to_dir(data, outdir):
    chunks, trailing = parse_chunks(data)
    notes, opaque = [], 0
    ih = next(b for t, b, _ in chunks if t == 'IHDR')
    w, h, bd, ct, cm, fm, il = struct.unpack('>IIBBBBB', ih)
    if bd == 16 or ct not in CHANNELS:
        raise NotImplementedError(f'bit depth {bd} / color type {ct} not supported')
    ch = CHANNELS[ct]
    bits = bd * ch
    bpp = max(1, bits // 8)
    meta = {'format': 'PNG', 'chunks': [], 'zlib_runtime_used_for_check': zlib.ZLIB_RUNTIME_VERSION}
    palette_rgb, trns = None, None

    # --- chunks
    idat_sizes, idat_seen = [], False
    for idx, (t, body, crc) in enumerate(chunks):
        ent = {'type': t}
        good = True
        if t == 'IHDR' and len(body) == 13:
            ent.update(width=w, height=h, bit_depth=bd, color_type=ct, color_type_name=CT_NAMES[ct],
                       compression_method=cm, filter_method=fm, interlace_method=il,
                       interlace_name='adam7' if il == 1 else ('none' if il == 0 else 'unknown'))
        elif t == 'IDAT':
            idat_sizes.append(len(body))
            if idat_seen:
                if meta['chunks'][-1]['type'] != 'IDAT':
                    raise ValueError('non-consecutive IDAT chunks')
                if crc != zlib.crc32(b'IDAT' + body) & 0xffffffff:
                    raise ValueError('IDAT CRC mismatch')
                continue
            idat_seen = True
        elif t == 'IEND' and not body:
            pass
        elif t == 'gAMA' and len(body) == 4:
            g = struct.unpack('>I', body)[0]
            ent.update(gamma=g, gamma_float=g / 100000)
        elif t == 'cHRM' and len(body) == 32:
            vals = struct.unpack('>8I', body)
            ent.update({k: v for k, v in zip(CHRM_FIELDS, vals)})
            ent['float'] = {k: v / 100000 for k, v in zip(CHRM_FIELDS, vals)}
        elif t == 'sRGB' and len(body) == 1 and body[0] < 4:
            ent.update(intent=body[0], intent_name=SRGB_INTENTS[body[0]])
        elif t == 'pHYs' and len(body) == 9:
            x, y, u = struct.unpack('>IIB', body)
            ent.update(pixels_per_unit_x=x, pixels_per_unit_y=y, unit=u,
                       unit_name={0: 'unknown', 1: 'metre'}.get(u, 'unknown'))
            if u == 1:
                ent['dpi_x'], ent['dpi_y'] = round(x * 0.0254, 3), round(y * 0.0254, 3)
        elif t == 'tIME' and len(body) == 7:
            ent.update(dict(zip(['year', 'month', 'day', 'hour', 'minute', 'second'], struct.unpack('>HBBBBB', body))))
        elif t == 'tEXt' and b'\0' in body:
            k, v = body.split(b'\0', 1)
            ent.update(keyword=_latin(k), text=_latin(v))
        elif t == 'iCCP' and b'\0' in body[:80] and body.index(b'\0') + 2 <= len(body):
            i = body.index(b'\0')
            name, method, stream = body[:i], body[i + 1], body[i + 2:]
            ent.update(profile_name=_latin(name), compression_method=method)
            try:
                d = zlib.decompressobj()
                icc = d.decompress(stream)
                if not d.eof or d.unused_data:
                    raise zlib.error('trailing data')
            except zlib.error:
                good = False
            if good:
                fn = f'{idx:02d}_iCCP.icc'
                open(os.path.join(outdir, fn), 'wb').write(icc)
                ent['profile_file'] = fn
                prof = fmt_png_zlib.find_profile(stream, icc)
                if prof is None:
                    zf = f'{idx:02d}_iCCP.zlib'
                    open(os.path.join(outdir, zf), 'wb').write(stream)
                    prof = {'engine': 'raw', 'file': zf}
                    opaque += len(stream)
                    notes.append(f'iCCP zlib stream kept raw ({len(stream)} bytes, encoder not identified)')
                ent['zlib'] = prof
                notes.append(f'iCCP "{_latin(name)}": {len(icc)}-byte ICC profile, {fmt_png_zlib.describe(prof)}')
        elif t == 'eXIf':
            fn = f'{idx:02d}_eXIf.exif'
            open(os.path.join(outdir, fn), 'wb').write(body)
            info, cov = parse_exif(body)
            json.dump(info, open(os.path.join(outdir, fn[:-5] + '.json'), 'w'), indent=1)
            ent.update(file=fn, parsed=fn[:-5] + '.json')
            opaque += len(body) - cov
            notes.append(f'eXIf: {len(body)}-byte TIFF Exif kept as {fn} (source of truth), IFD0 parsed to JSON; '
                         f'{len(body) - cov} bytes not covered by the parse')
        elif t == 'PLTE' and len(body) % 3 == 0 and ct == 3:
            palette_rgb = [list(body[i:i + 3]) for i in range(0, len(body), 3)]
            ent['source'] = 'palette.json'
        elif t == 'PLTE' and len(body) % 3 == 0:
            ent['entries'] = [list(body[i:i + 3]) for i in range(0, len(body), 3)]
        elif t == 'tRNS' and ct == 3 and palette_rgb is not None and len(body) <= len(palette_rgb):
            trns = body
            ent['source'] = 'palette.json'
        elif t == 'tRNS' and ct == 0 and len(body) == 2:
            ent['gray'] = struct.unpack('>H', body)[0]
        elif t == 'tRNS' and ct == 2 and len(body) == 6:
            ent['rgb'] = list(struct.unpack('>3H', body))
        else:
            good = False
        if not good:
            ent = {'type': t, 'data_hex': body.hex(), 'opaque': True}
            opaque += len(body)
            notes.append(f'chunk {t} ({len(body)} bytes) kept as hex')
        if crc != zlib.crc32(t.encode('latin-1') + body) & 0xffffffff:
            ent['crc_hex'] = '%08x' % crc
            opaque += 4
            notes.append(f'chunk {t}: stored CRC does not match, kept')
        meta['chunks'].append(ent)
    if trailing:
        meta['trailing_hex'] = trailing.hex()
        opaque += len(trailing)
        notes.append(f'{len(trailing)} bytes after IEND kept as hex')

    # --- image data
    stream = b''.join(b for t, b, _ in chunks if t == 'IDAT')
    dobj = zlib.decompressobj()
    raw = dobj.decompress(stream)
    if not dobj.eof or dobj.unused_data:
        raise ValueError('IDAT zlib stream has trailing data or is truncated')
    pl = passes(w, h, il)
    U = ch if bd == 8 else 1                       # bytes per pixel in the unit buffer
    units = bytearray(w * h * U)
    filters, padding = [], {}
    actual_policy_rows = []                        # (line, prev) for the policy check
    p = 0
    rowno = 0
    for x0, y0, dx, dy, pw, ph in pl:
        rb = (pw * bits + 7) // 8
        prev = bytes(rb)
        for py in range(ph):
            ft = raw[p]
            line = bytes(unfilter(ft, raw[p + 1:p + 1 + rb], prev, bpp))
            p += 1 + rb
            filters.append(ft)
            actual_policy_rows.append((line, prev))
            samples, pad = unpack_row(line, bd, pw * ch)
            if pad:
                padding[str(rowno)] = pad
            y = y0 + py * dy
            if dx == 1:
                units[(y * w) * U:(y * w + pw) * U] = samples
            else:
                for px in range(pw):
                    x = x0 + px * dx
                    units[(y * w + x) * U:(y * w + x + 1) * U] = samples[px * U:(px + 1) * U]
            prev = line
            rowno += 1
    if p != len(raw):
        raise ValueError(f'IDAT payload has {len(raw) - p} extra bytes')
    if padding:
        meta['padding_bits'] = padding
        opaque += len(padding)
        notes.append(f'{len(padding)} rows with non-zero padding bits kept (counted 1 opaque byte each)')

    # --- filter policy
    cand = {'none': [0] * len(filters)}
    if any(filters):
        cand['libpng_minsum'] = [minsum_filter(l, pv, bpp)[0] for l, pv in actual_policy_rows]
    best = min(cand, key=lambda k: (sum(a != b for a, b in zip(filters, cand[k])), k != 'none'))
    exc = {str(i): f for i, (f, g) in enumerate(zip(filters, cand[best])) if f != g}
    if len(exc) * 4 > len(filters):
        meta['filters'] = {'policy': 'explicit', 'per_row': ''.join(str(f) for f in filters)}
        notes.append('row filters not predictable: stored as an explicit per-row list (encoder choice, not opaque)')
    else:
        meta['filters'] = {'policy': best, 'exceptions': exc}
        notes.append(f'row filters: {best} policy, {len(exc)} exceptions')

    # --- zlib profile + IDAT split
    prof = fmt_png_zlib.find_profile(stream, raw)
    if prof is None:
        open(os.path.join(outdir, 'idat.zlib'), 'wb').write(stream)
        prof = {'engine': 'raw', 'file': 'idat.zlib'}
        opaque += len(stream)
        notes.append(f'IDAT zlib stream kept raw ({len(stream)} bytes): encoder not identified; used only while it '
                     f'still decompresses to the rebuilt scanlines')
    else:
        notes.append(f'IDAT: {fmt_png_zlib.describe(prof)}')
    if len(idat_sizes) == 1:
        split = {'policy': 'single'}
    elif all(s == idat_sizes[0] for s in idat_sizes[:-1]) and idat_sizes[-1] <= idat_sizes[0]:
        split = {'policy': 'max_chunk', 'max': idat_sizes[0]}
    else:
        split = {'policy': 'explicit'}
    split['sizes'] = idat_sizes
    meta['idat'] = {'zlib': prof, 'split': split}

    # --- pixel files
    img = {}
    if ct == 3:
        pal = [list(c) + [255] for c in (palette_rgb or [])]
        if trns is not None:
            for i, a in enumerate(trns):
                pal[i][3] = a
        json.dump({'entries': pal, 'trns_count': len(trns) if trns is not None else 0,
                   'comment': 'RGBA per index; PLTE = rgb of every entry, tRNS = alpha of the first trns_count '
                              'entries (extended automatically if a later alpha is not 255)'},
                  open(os.path.join(outdir, 'palette.json'), 'w'), indent=1)
        pngio.write_png(os.path.join(outdir, 'indices.png'), w, h, 'L', bytes(units))
        rgba = bytearray()
        for v in units:
            rgba += bytes(pal[v]) if v < len(pal) else b'\0\0\0\0'
        pngio.write_png(os.path.join(outdir, 'pixels.png'), w, h, 'RGBA', bytes(rgba))
        img = {'indices': 'indices.png', 'palette': 'palette.json', 'preview': 'pixels.png'}
        notes.append(f'palette image ({len(pal)} entries, {bd}-bit indices): indices.png + palette.json are the '
                     f'source; pixels.png is an RGBA preview the encoder ignores')
    else:
        mode = CANON_MODE[ct]
        buf = bytes(units)
        if bd < 8:
            scale = 255 // ((1 << bd) - 1)
            buf = bytes(v * scale for v in units)
            notes.append(f'{bd}-bit gray scaled x{scale} into 8-bit L pixels.png')
        pngio.write_png(os.path.join(outdir, 'pixels.png'), w, h, mode, buf)
        img = {'pixels': 'pixels.png', 'mode': mode}
    meta['image'] = img
    json.dump(meta, open(os.path.join(outdir, 'png.json'), 'w'), indent=1)
    return {'opaque_bytes': opaque, 'notes': notes}


# ------------------------------------------------------------------ encode
def _recompress(outdir, raw, prof):
    if prof['engine'] == 'raw':
        stream = open(os.path.join(outdir, prof['file']), 'rb').read()
        try:
            if zlib.decompress(stream) == raw:
                return stream
        except zlib.error:
            pass
        return zlib.compress(raw, 9)              # payload was edited: the kept stream no longer applies
    return fmt_png_zlib.compress(raw, prof)


def encode_from_dir(outdir):
    meta = json.load(open(os.path.join(outdir, 'png.json')))
    ihdr = next(c for c in meta['chunks'] if c['type'] == 'IHDR')
    bd, ct, il = ihdr['bit_depth'], ihdr['color_type'], ihdr['interlace_method']
    ch = CHANNELS[ct]
    bits = bd * ch
    bpp = max(1, bits // 8)
    img = meta['image']
    pal = None
    if ct == 3:
        w, h, mode, units = pngio.read_png(os.path.join(outdir, img['indices']))
        if mode != 'L':
            raise ValueError('indices.png must be 8-bit L')
        pj = json.load(open(os.path.join(outdir, img['palette'])))
        pal = pj['entries']
        limit = min(len(pal), 1 << bd)
        bad = max(units) if units else 0
        if bad >= limit:
            raise ValueError(f'indices.png uses palette index {bad}, but only 0..{limit - 1} are valid '
                             f'({len(pal)} palette entries, {bd}-bit indices)')
        tcount = pj.get('trns_count', 0)
        for i, e in enumerate(pal):
            if len(e) > 3 and e[3] != 255:
                tcount = max(tcount, i + 1)
    else:
        w, h, mode, units = pngio.read_png(os.path.join(outdir, img['pixels']))
        if mode != CANON_MODE[ct]:
            raise ValueError(f'pixels.png must be {CANON_MODE[ct]}, got {mode}')
        if bd < 8:
            mx = (1 << bd) - 1
            units = bytes((v * mx + 127) // 255 for v in units)
    U = ch if bd == 8 else 1
    padding = meta.get('padding_bits', {})
    fp = meta['filters']
    exc = {int(k): v for k, v in fp.get('exceptions', {}).items()}
    per_row = fp.get('per_row')

    out = bytearray()
    rowno = 0
    for x0, y0, dx, dy, pw, ph in passes(w, h, il):
        rb = (pw * bits + 7) // 8
        prev = bytes(rb)
        for py in range(ph):
            y = y0 + py * dy
            if dx == 1:
                samples = units[(y * w) * U:(y * w + pw) * U]
            else:
                samples = b''.join(units[(y * w + x0 + px * dx) * U:(y * w + x0 + px * dx + 1) * U] for px in range(pw))
            line = pack_row(samples, bd, padding.get(str(rowno), 0))
            if per_row is not None and rowno < len(per_row):
                ft = int(per_row[rowno])
            elif rowno in exc:
                ft = exc[rowno]
            elif fp['policy'] == 'libpng_minsum':
                ft, frow = minsum_filter(line, prev, bpp)
                out.append(ft)
                out += frow
                prev = line
                rowno += 1
                continue
            else:
                ft = 0
            out.append(ft)
            out += filter_row(ft, line, prev, bpp)
            prev = line
            rowno += 1
    raw = bytes(out)
    stream = _recompress(outdir, raw, meta['idat']['zlib'])
    split = meta['idat']['split']
    sizes = split.get('sizes', [])
    if split['policy'] == 'explicit' and sum(sizes) == len(stream):
        parts, o = [], 0
        for s in sizes:
            parts.append(stream[o:o + s])
            o += s
    elif split['policy'] == 'max_chunk':
        m = split['max']
        parts = [stream[i:i + m] for i in range(0, len(stream), m)] or [b'']
    else:
        parts = [stream]

    chunk_list = list(meta['chunks'])
    if ct == 3 and tcount and not any(c['type'] == 'tRNS' for c in chunk_list):
        # palette.json gained a non-opaque alpha: tRNS goes right after PLTE
        i = next(i for i, c in enumerate(chunk_list) if c['type'] == 'PLTE')
        chunk_list.insert(i + 1, {'type': 'tRNS', 'source': 'palette.json'})
    res = bytearray(SIG)
    for c in chunk_list:
        t = c['type']
        tb = t.encode('latin-1')
        crc = int(c['crc_hex'], 16) if 'crc_hex' in c else None
        if 'data_hex' in c:
            body = bytes.fromhex(c['data_hex'])
        elif t == 'IHDR':
            body = struct.pack('>IIBBBBB', w, h, bd, ct, c['compression_method'], c['filter_method'], il)
        elif t == 'IDAT':
            for part in parts:
                res += _chunk(b'IDAT', part)
            continue
        elif t == 'IEND':
            body = b''
        elif t == 'gAMA':
            body = struct.pack('>I', c['gamma'])
        elif t == 'cHRM':
            body = struct.pack('>8I', *[c[k] for k in CHRM_FIELDS])
        elif t == 'sRGB':
            body = bytes([c['intent']])
        elif t == 'pHYs':
            body = struct.pack('>IIB', c['pixels_per_unit_x'], c['pixels_per_unit_y'], c['unit'])
        elif t == 'tIME':
            body = struct.pack('>HBBBBB', c['year'], c['month'], c['day'], c['hour'], c['minute'], c['second'])
        elif t == 'tEXt':
            body = c['keyword'].encode('latin-1') + b'\0' + c['text'].encode('latin-1')
        elif t == 'iCCP':
            icc = open(os.path.join(outdir, c['profile_file']), 'rb').read()
            body = (c['profile_name'].encode('latin-1') + b'\0' + bytes([c['compression_method']])
                    + _recompress(outdir, icc, c['zlib']))
        elif t == 'eXIf':
            body = open(os.path.join(outdir, c['file']), 'rb').read()
        elif t == 'PLTE' and c.get('source') == 'palette.json':
            body = b''.join(bytes(e[:3]) for e in pal)
        elif t == 'PLTE':
            body = b''.join(bytes(e) for e in c['entries'])
        elif t == 'tRNS' and c.get('source') == 'palette.json':
            body = bytes((e[3] if len(e) > 3 else 255) for e in pal[:tcount])
        elif t == 'tRNS' and 'gray' in c:
            body = struct.pack('>H', c['gray'])
        elif t == 'tRNS' and 'rgb' in c:
            body = struct.pack('>3H', *c['rgb'])
        else:
            raise ValueError(f'cannot rebuild chunk {t}')
        res += _chunk(tb, body, crc)
    res += bytes.fromhex(meta.get('trailing_hex', ''))
    return bytes(res)
