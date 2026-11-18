"""ZIP archives (.zip, GOG's goggame-*.hashdb; add other ZIP-based extensions to EXTS) -> member files + manifest;
rebuilt byte-identically.

Decoded layout (outdir):
    zip.json            manifest: every field of every local header, central record and the EOCD,
                        decoded (DOS date/time fields, attributes, extra fields, per-member codec)
    members/<path>      every member as an ordinary file (directory entries as directories)
    raw_streams/<n>.deflate   only for members whose deflate stream no known encoder reproduces
                        (counted as opaque); used only while members/<path> still equals its content

CRC-32, compressed/uncompressed sizes, local header offsets, central directory size/offset and entry
counts are recomputed on encode; a stored value is kept only if it disagrees with the recomputation.
Deflate encoders tried: zlib profiles and the 7-Zip port (fmt_zip_7zdeflate); see formats/README.md.
"""
import json
import os
import struct
import zlib

import fmt_zip_7zdeflate as p7

EXTS = ['.zip', '.hashdb']

SIG_LOCAL = 0x04034b50
SIG_CENTRAL = 0x02014b50
SIG_EOCD = 0x06054b50

HOST_NAMES = {0: 'MS-DOS/FAT', 3: 'Unix', 10: 'NTFS', 11: 'VFAT', 19: 'OS X'}
DOS_BITS = [(0x01, 'READONLY'), (0x02, 'HIDDEN'), (0x04, 'SYSTEM'), (0x08, 'VOLUME'), (0x10, 'DIRECTORY'),
            (0x20, 'ARCHIVE'), (0x8000, 'UNIX_EXTENSION')]   # 0x8000: p7zip FILE_ATTRIBUTE_UNIX_EXTENSION

# Deflate profiles tried on decode, in order.  Each is a dict stored verbatim in the manifest.
P7ZIP_PROFILES = [
    {'encoder': 'p7zip-9.20-deflate', 'passes': 3, 'fast_bytes': 64, 'mf_cycles': 0},   # 7z a -tzip -mx=7
    {'encoder': 'p7zip-9.20-deflate', 'passes': 10, 'fast_bytes': 128, 'mf_cycles': 0},  # -mx=9
]
ZLIB_PROFILES = [{'encoder': 'zlib', 'level': lv, 'mem_level': ml, 'wbits': -15}
                 for lv in (6, 9, 1, 2, 3, 4, 5, 7, 8) for ml in (8, 9)]


# ---------------------------------------------------------------- codecs
def compress(data, prof):
    enc = prof['encoder']
    if enc == 'zlib':
        c = zlib.compressobj(prof['level'], zlib.DEFLATED, prof['wbits'], prof['mem_level'])
        return c.compress(data) + c.flush()
    if enc == 'p7zip-9.20-deflate':
        return p7.deflate_7z(data, prof['passes'], prof['fast_bytes'], prof['mf_cycles'])
    raise ValueError('unknown encoder %r' % enc)


def inflate(stream):
    d = zlib.decompressobj(-15)
    out = d.decompress(stream) + d.flush()
    if not d.eof or d.unused_data:
        raise ValueError('deflate stream does not end exactly at the compressed size')
    return out


# ---------------------------------------------------------------- field helpers
def dos_time_dec(t, d):
    return {'year': 1980 + (d >> 9), 'month': (d >> 5) & 15, 'day': d & 31,
            'hour': t >> 11, 'minute': (t >> 5) & 63, 'second': (t & 31) * 2}


def dos_time_enc(x):
    if x['second'] & 1:
        raise ValueError('DOS time seconds must be even')
    d = ((x['year'] - 1980) << 9) | (x['month'] << 5) | x['day']
    t = (x['hour'] << 11) | (x['minute'] << 5) | (x['second'] >> 1)
    return t, d


def ver_dec(v):
    return {'version': '%d.%d' % ((v & 0xFF) // 10, (v & 0xFF) % 10), 'host': v >> 8,
            'host_name': HOST_NAMES.get(v >> 8, 'unknown')}


def ver_enc(x):
    a, b = x['version'].split('.')
    return (x['host'] << 8) | (int(a) * 10 + int(b))


def attr_dec(ext):
    low = ext & 0xFFFF
    names = [nm for bit, nm in DOS_BITS if low & bit]
    known = 0
    for bit, nm in DOS_BITS:
        known |= bit
    r = {'unix_mode': '0%o' % (ext >> 16), 'dos_attributes': names}
    if low & ~known:
        r['dos_other_bits'] = low & ~known
    return r


def attr_enc(x):
    low = x.get('dos_other_bits', 0)
    bits = dict((nm, bit) for bit, nm in DOS_BITS)
    for nm in x['dos_attributes']:
        low |= bits[nm]
    return (int(x['unix_mode'], 8) << 16) | low


def extra_dec(raw, opaque):
    """Parse extra field into a list of blocks. Unknown blocks are kept as hex and counted opaque."""
    out = []
    p = 0
    while p < len(raw):
        if p + 4 > len(raw):
            out.append({'trailing_hex': raw[p:].hex()})
            opaque[0] += len(raw) - p
            break
        hid, sz = struct.unpack_from('<HH', raw, p)
        body = raw[p + 4:p + 4 + sz]
        blk = None
        if hid == 0x000a and len(body) >= 4 and sz == len(body):
            reserved = struct.unpack_from('<I', body, 0)[0]
            tags = []
            q = 4
            ok = True
            while q < len(body):
                if q + 4 > len(body):
                    ok = False
                    break
                tag, tsz = struct.unpack_from('<HH', body, q)
                tb = body[q + 4:q + 4 + tsz]
                if tag == 1 and tsz == 24:
                    m, a, c = struct.unpack('<QQQ', tb)
                    tags.append({'tag': 1, 'mtime_filetime': m, 'atime_filetime': a, 'ctime_filetime': c})
                else:
                    ok = False
                    break
                q += 4 + tsz
            if ok:
                blk = {'id': '0x000a', 'name': 'NTFS', 'reserved': reserved, 'tags': tags}
        if blk is None:
            blk = {'id': '0x%04x' % hid, 'size': sz, 'data_hex': body.hex()}
            opaque[0] += len(body)
        out.append(blk)
        p += 4 + sz
    return out


def extra_enc(blocks):
    b = bytearray()
    for blk in blocks:
        if 'trailing_hex' in blk:
            b += bytes.fromhex(blk['trailing_hex'])
            continue
        hid = int(blk['id'], 16)
        if blk.get('name') == 'NTFS':
            body = struct.pack('<I', blk['reserved'])
            for t in blk['tags']:
                body += struct.pack('<HHQQQ', 1, 24, t['mtime_filetime'], t['atime_filetime'],
                                    t['ctime_filetime'])
            b += struct.pack('<HH', hid, len(body)) + body
        else:
            body = bytes.fromhex(blk['data_hex'])
            b += struct.pack('<HH', hid, blk['size']) + body
    return bytes(b)


def name_dec(raw, utf8):
    try:
        s = raw.decode('utf-8' if utf8 else 'cp437')
        if s.encode('utf-8' if utf8 else 'cp437') == raw:
            return s, None
    except UnicodeError:
        pass
    return raw.decode('latin-1'), raw.hex()


def safe_rel(name):
    parts = [x for x in name.replace('\\', '/').split('/') if x not in ('', '.')]
    if any(x == '..' for x in parts) or not parts:
        raise ValueError('unsafe member name %r' % name)
    return os.path.join(*parts)


# ---------------------------------------------------------------- decode
def decode_to_dir(data, outdir):
    opaque = [0]
    notes = []
    e = data.rfind(b'PK\x05\x06')
    if e < 0:
        raise ValueError('no EOCD')
    (_, disk, cd_disk, n_disk, n_total, cd_size, cd_off, clen) = struct.unpack_from('<IHHHHIIH', data, e)
    if n_total == 0xFFFF or cd_off == 0xFFFFFFFF:
        raise NotImplementedError('zip64')
    comment = data[e + 22:e + 22 + clen]
    trailing = data[e + 22 + clen:]
    # central directory
    entries = []
    p = cd_off
    for idx in range(n_total):
        f = struct.unpack_from('<IHHHHHHIIIHHHHHII', data, p)
        if f[0] != SIG_CENTRAL:
            raise ValueError('bad central signature at %d' % p)
        (_, made_by, need, flags, method, mt, md, crc, csz, usz, nl, xl, cl, dstart, iattr, eattr, loff) = f
        name_raw = data[p + 46:p + 46 + nl]
        cextra = data[p + 46 + nl:p + 46 + nl + xl]
        ccomment = data[p + 46 + nl + xl:p + 46 + nl + xl + cl]
        entries.append(dict(made_by=made_by, need=need, flags=flags, method=method, mt=mt, md=md, crc=crc,
                            csz=csz, usz=usz, name_raw=name_raw, extra=cextra, comment=ccomment,
                            dstart=dstart, iattr=iattr, eattr=eattr, loff=loff))
        p += 46 + nl + xl + cl
    if p != e:
        raise ValueError('central directory does not end at EOCD (%d != %d)' % (p, e))

    members_dir = os.path.join(outdir, 'members')
    os.makedirs(members_dir, exist_ok=True)
    order = sorted(range(len(entries)), key=lambda i: entries[i]['loff'])
    man_entries = [None] * len(entries)
    pos = 0
    gaps = []
    for li, i in enumerate(order):
        ce = entries[i]
        o = ce['loff']
        if o != pos:
            if o < pos:
                raise ValueError('overlapping local records')
            gaps.append({'before_local_index': li, 'hex': data[pos:o].hex()})
            opaque[0] += o - pos
        f = struct.unpack_from('<IHHHHHIIIHH', data, o)
        if f[0] != SIG_LOCAL:
            raise ValueError('bad local signature at %d' % o)
        (_, l_need, l_flags, l_method, l_mt, l_md, l_crc, l_csz, l_usz, l_nl, l_xl) = f
        l_name = data[o + 30:o + 30 + l_nl]
        l_extra = data[o + 30 + l_nl:o + 30 + l_nl + l_xl]
        ds = o + 30 + l_nl + l_xl
        if (l_flags | ce['flags']) & 0x0008:
            raise NotImplementedError('data descriptors')
        csz = ce['csz']
        stream = data[ds:ds + csz]
        pos = ds + csz

        utf8 = bool(ce['flags'] & 0x0800)
        name, name_hex = name_dec(ce['name_raw'], utf8)
        m = {'name': name}
        if name_hex:
            m['name_raw_hex'] = name_hex
        is_dir = name.endswith('/')
        m['is_dir'] = is_dir
        m['central'] = {
            'made_by': ver_dec(ce['made_by']), 'version_needed': ver_dec(ce['need']), 'flags': ce['flags'],
            'method': ce['method'], 'mtime': dos_time_dec(ce['mt'], ce['md']),
            'disk_start': ce['dstart'], 'internal_attr': ce['iattr'], 'external_attr': attr_dec(ce['eattr']),
            'extra': extra_dec(ce['extra'], opaque), 'comment': ce['comment'].decode('latin-1'),
        }
        m['local'] = {
            'version_needed': ver_dec(l_need), 'flags': l_flags, 'method': l_method,
            'mtime': dos_time_dec(l_mt, l_md), 'extra': extra_dec(l_extra, opaque),
        }
        if l_name != ce['name_raw']:
            m['local']['name_raw_hex'] = l_name.hex()
            opaque[0] += 0  # name bytes are interpreted (kept as hex only for mismatch); not opaque content
        if ce['method'] != l_method:
            raise ValueError('local/central method mismatch')

        # content
        if ce['method'] == 0:
            content = stream
        elif ce['method'] == 8:
            content = inflate(stream)
        else:
            raise NotImplementedError('method %d' % ce['method'])
        crc = zlib.crc32(content) & 0xFFFFFFFF
        # sizes/CRC: recomputed on encode; keep overrides only where the header disagrees
        ov = {}
        for k, v, want in (('central_crc', ce['crc'], crc), ('local_crc', l_crc, crc),
                           ('central_usize', ce['usz'], len(content)), ('local_usize', l_usz, len(content)),
                           ('local_csize', l_csz, csz)):
            if v != want:
                ov[k] = v
        if ov:
            m['header_overrides'] = ov
            notes.append('%s: header values differ from recomputation: %s' % (name, sorted(ov)))

        if is_dir:
            if content:
                raise ValueError('directory entry with data')
            os.makedirs(os.path.join(members_dir, safe_rel(name)), exist_ok=True)
        else:
            path = os.path.join(members_dir, safe_rel(name))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as fh:
                fh.write(content)
        m['path'] = None if is_dir else 'members/' + safe_rel(name).replace(os.sep, '/')

        if ce['method'] == 8:
            m['codec'] = find_codec(content, stream, ce, m, outdir, opaque, notes, li)
        man_entries[i] = m
        m['_li'] = li

    if pos != cd_off:
        if cd_off < pos:
            raise ValueError('central directory overlaps member data')
        gaps.append({'before_central_directory': True, 'hex': data[pos:cd_off].hex()})
        opaque[0] += cd_off - pos

    local_order = [man_entries[i]['_li'] for i in range(len(entries))]
    for m in man_entries:
        del m['_li']
    eocd = {'disk': disk, 'cd_disk': cd_disk, 'comment': comment.decode('latin-1')}
    if n_disk != n_total or n_total != len(entries):
        eocd['entries_on_disk'] = n_disk
    if cd_size != e - cd_off:
        eocd['cd_size_override'] = cd_size
    man = {'format': 'zip', 'entries': man_entries, 'eocd': eocd}
    if local_order != sorted(local_order) or local_order != list(range(len(entries))):
        man['local_order'] = local_order
    if gaps:
        man['gaps'] = gaps
    if trailing:
        man['trailing_hex'] = trailing.hex()
        opaque[0] += len(trailing)
    with open(os.path.join(outdir, 'zip.json'), 'w') as fh:
        json.dump(man, fh, indent=1, ensure_ascii=False)
    return {'opaque_bytes': opaque[0], 'notes': notes}


def find_codec(content, stream, ce, m, outdir, opaque, notes, li):
    host, ver = ce['made_by'] >> 8, ce['made_by'] & 0xFF
    if host == 3 and ver == 63:          # p7zip (7-Zip for POSIX) made-by signature
        order = P7ZIP_PROFILES + ZLIB_PROFILES
    else:
        order = ZLIB_PROFILES + P7ZIP_PROFILES
    for prof in order:
        if prof['encoder'] == 'p7zip-9.20-deflate' and len(content) > 4_000_000 and prof['passes'] != 3:
            continue                       # only the profile actually observed is tried on large members
        if compress(content, prof) == stream:
            return dict(prof)
    # not reproduced: keep the raw stream (opaque) beside the member file
    os.makedirs(os.path.join(outdir, 'raw_streams'), exist_ok=True)
    rel = 'raw_streams/%03d.deflate' % li
    with open(os.path.join(outdir, rel), 'wb') as fh:
        fh.write(stream)
    opaque[0] += len(stream)
    notes.append('%s: deflate stream (%d bytes) not reproduced by any known encoder; kept raw in %s'
                 % (m['name'], len(stream), rel))
    return {'encoder': 'raw', 'raw_stream': rel,
            'fallback_if_member_edited': {'encoder': 'zlib', 'level': 6, 'mem_level': 8, 'wbits': -15}}


# ---------------------------------------------------------------- encode
def encode_from_dir(outdir):
    man = json.load(open(os.path.join(outdir, 'zip.json'), encoding='utf-8'))
    ents = man['entries']
    n = len(ents)
    local_order = man.get('local_order', list(range(n)))
    by_local = sorted(range(n), key=lambda i: local_order[i])
    gaps_before = {}
    gap_cd = b''
    for g in man.get('gaps', []):
        if g.get('before_central_directory'):
            gap_cd = bytes.fromhex(g['hex'])
        else:
            gaps_before[g['before_local_index']] = bytes.fromhex(g['hex'])
    out = bytearray()
    info = [None] * n
    for li, i in enumerate(by_local):
        m = ents[i]
        out += gaps_before.get(li, b'')
        c, l = m['central'], m['local']
        utf8 = bool(c['flags'] & 0x0800)
        name_raw = bytes.fromhex(m['name_raw_hex']) if 'name_raw_hex' in m else \
            m['name'].encode('utf-8' if utf8 else 'cp437')
        l_name = bytes.fromhex(l['name_raw_hex']) if 'name_raw_hex' in l else name_raw
        content = b'' if m['is_dir'] else open(os.path.join(outdir, m['path']), 'rb').read()
        method = c['method']
        if method == 0:
            stream = content
        else:
            codec = m['codec']
            if codec['encoder'] == 'raw':
                raw = open(os.path.join(outdir, codec['raw_stream']), 'rb').read()
                stream = raw if inflate(raw) == content else compress(content, codec['fallback_if_member_edited'])
            else:
                stream = compress(content, codec)
        crc = zlib.crc32(content) & 0xFFFFFFFF
        ov = m.get('header_overrides', {})
        l_extra = extra_enc(l['extra'])
        lt, ld = dos_time_enc(l['mtime'])
        offset = len(out)
        out += struct.pack('<IHHHHHIIIHH', SIG_LOCAL, ver_enc(l['version_needed']), l['flags'], l['method'],
                           lt, ld, ov.get('local_crc', crc), ov.get('local_csize', len(stream)),
                           ov.get('local_usize', len(content)), len(l_name), len(l_extra))
        out += l_name + l_extra + stream
        info[i] = (offset, crc, len(stream), len(content), name_raw)
    out += gap_cd
    cd_off = len(out)
    for i in range(n):
        m = ents[i]
        c = m['central']
        offset, crc, csz, usz, name_raw = info[i]
        ov = m.get('header_overrides', {})
        cx = extra_enc(c['extra'])
        cc = c['comment'].encode('latin-1')
        ct, cdd = dos_time_enc(c['mtime'])
        out += struct.pack('<IHHHHHHIIIHHHHHII', SIG_CENTRAL, ver_enc(c['made_by']), ver_enc(c['version_needed']),
                           c['flags'], c['method'], ct, cdd, ov.get('central_crc', crc), csz,
                           ov.get('central_usize', usz), len(name_raw), len(cx), len(cc), c['disk_start'],
                           c['internal_attr'], attr_enc(c['external_attr']), offset)
        out += name_raw + cx + cc
    cd_size = len(out) - cd_off
    eo = man['eocd']
    com = eo['comment'].encode('latin-1')
    out += struct.pack('<IHHHHIIH', SIG_EOCD, eo['disk'], eo['cd_disk'], eo.get('entries_on_disk', n), n,
                       eo.get('cd_size_override', cd_size), cd_off, len(com))
    out += com
    if 'trailing_hex' in man:
        out += bytes.fromhex(man['trailing_hex'])
    return bytes(out)
