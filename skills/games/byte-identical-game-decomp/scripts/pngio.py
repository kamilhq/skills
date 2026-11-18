"""Minimal stdlib PNG writer/reader (8-bit, non-interlaced) shared by format decoders.

write_png(path, width, height, mode, pixels)   mode in {'L','LA','RGB','RGBA'}; pixels = bytes, row-major
read_png(path) -> (width, height, mode, pixels)  supports all 5 filter types, so images edited
                                                  and re-saved by ordinary tools still load.
"""
import struct, zlib

_CT = {'L': (0, 1), 'LA': (4, 2), 'RGB': (2, 3), 'RGBA': (6, 4)}
_CT_REV = {v[0]: (k, v[1]) for k, v in _CT.items()}


def _chunk(t, d):
    return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)


def write_png(path, width, height, mode, pixels):
    ct, bpp = _CT[mode]
    stride = width * bpp
    if len(pixels) != stride * height:
        raise ValueError(f'pixel buffer {len(pixels)} != {stride}*{height}')
    raw = b''.join(b'\x00' + pixels[y * stride:(y + 1) * stride] for y in range(height))
    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, ct, 0, 0, 0)))
        f.write(_chunk(b'IDAT', zlib.compress(raw, 6)))
        f.write(_chunk(b'IEND', b''))


def read_png(path):
    data = open(path, 'rb').read()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('not a PNG')
    pos, idat, hdr = 8, [], None
    while pos < len(data):
        ln, t = struct.unpack('>I4s', data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + ln]
        if t == b'IHDR':
            hdr = struct.unpack('>IIBBBBB', body)
        elif t == b'IDAT':
            idat.append(body)
        elif t == b'IEND':
            break
        pos += 12 + ln
    w, h, depth, ct, _, _, interlace = hdr
    if depth != 8 or interlace != 0 or ct not in _CT_REV:
        raise ValueError(f'unsupported PNG (depth={depth}, colortype={ct}, interlace={interlace})')
    mode, bpp = _CT_REV[ct]
    raw = zlib.decompress(b''.join(idat))
    stride = w * bpp
    out = bytearray(stride * h)
    prev = bytearray(stride)
    p = 0
    for y in range(h):
        ft = raw[p]; line = bytearray(raw[p + 1:p + 1 + stride]); p += 1 + stride
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if ft == 1: line[i] = (line[i] + a) & 255
            elif ft == 2: line[i] = (line[i] + b) & 255
            elif ft == 3: line[i] = (line[i] + ((a + b) >> 1)) & 255
            elif ft == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        out[y * stride:(y + 1) * stride] = line
        prev = line
    return w, h, mode, bytes(out)
