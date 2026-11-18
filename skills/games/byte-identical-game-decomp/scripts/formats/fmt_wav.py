"""RIFF WAVE sounds (.wav).

Decoded form (outdir):
  audio.wav   canonical 44-byte-header PCM WAV with the same fmt and samples (plays/edits anywhere)
  wav.json    RIFF chunk order and every non-audio chunk: fmt fields, LIST/INFO entries as text,
              any other chunk as hex (counted as opaque), odd-size pad bytes

RIFF size, chunk sizes and pad positions are recomputed. audio.wav is the source of truth for format and
samples; the fmt fields in wav.json are informational only. Opaque bytes: bodies of unknown chunks,
non-zero pad bytes, and stale bytes after the NUL of INFO strings.
"""
import json, os, struct

EXTS = ['.wav']


def _chunks(buf, pos, end):
    out = []
    while pos + 8 <= end:
        cid, ln = struct.unpack('<4sI', buf[pos:pos + 8])
        body = buf[pos + 8:pos + 8 + ln]
        if len(body) != ln:
            raise ValueError('truncated chunk')
        pad = buf[pos + 8 + ln:pos + 9 + ln] if ln & 1 else b''
        out.append((cid, body, pad))
        pos += 8 + ln + len(pad)
    if pos != end:
        raise ValueError(f'{end - pos} trailing bytes after chunks')
    return out


def _text_field(b):
    """INFO text: string up to the first NUL. What follows is NUL padding, or stale bytes left by the
    writing tool (kept as stale_hex, counted as opaque)."""
    nul = b.find(b'\0')
    if nul < 0:
        return dict(text=b.decode('latin-1'), nul_count=0)
    rest = b[nul:]
    if any(rest):
        return dict(text=b[:nul].decode('latin-1'), stale_hex=rest.hex())
    return dict(text=b[:nul].decode('latin-1'), nul_count=len(rest))


def _text_bytes(e):
    t = e['text'].encode('latin-1')
    return t + (bytes.fromhex(e['stale_hex']) if 'stale_hex' in e else b'\0' * e['nul_count'])


def decode_to_dir(data, outdir):
    if data[:4] != b'RIFF' or data[8:12] != b'WAVE':
        raise ValueError('not RIFF WAVE')
    if struct.unpack('<I', data[4:8])[0] + 8 != len(data):
        raise ValueError('RIFF size does not match file size')
    fmt = pcm = None
    layout, opaque = [], 0
    for cid, body, pad in _chunks(data, 12, len(data)):
        ent = dict(id=cid.decode('latin-1'))
        if pad and pad != b'\0':
            ent['pad_hex'] = pad.hex()
            opaque += 1
        elif pad:
            ent['pad'] = True
        if cid == b'fmt ':
            if len(body) != 16:
                raise ValueError('fmt chunk with extension not handled')
            tag, ch, rate, bps, align, bits = struct.unpack('<HHIIHH', body)
            fmt = body
            ent.update(informational=True, format_tag=tag, channels=ch, sample_rate=rate, byte_rate=bps, block_align=align,
                       bits_per_sample=bits)
        elif cid == b'data':
            if pcm is not None:
                raise ValueError('two data chunks')
            pcm = body
            ent['samples_in'] = 'audio.wav'
        elif cid == b'LIST':
            ent['list_type'] = body[:4].decode('latin-1')
            ent['entries'] = [dict(id=s.decode('latin-1'), **_text_field(b),
                                   **({'pad_hex': p.hex()} if p and p != b'\0' else {'pad': True} if p else {}))
                              for s, b, p in _chunks(body, 4, len(body))]
            for e in ent['entries']:
                opaque += sum(1 for x in bytes.fromhex(e.get('stale_hex', '')) if x)
                opaque += 1 if 'pad_hex' in e else 0
        else:
            ent['body_hex'] = body.hex()
            opaque += len(body)
        layout.append(ent)
    if fmt is None or pcm is None:
        raise ValueError('missing fmt or data')
    with open(os.path.join(outdir, 'audio.wav'), 'wb') as f:
        f.write(b'RIFF' + struct.pack('<I', 36 + len(pcm) + (len(pcm) & 1)) + b'WAVEfmt ' +
                struct.pack('<I', 16) + fmt + b'data' + struct.pack('<I', len(pcm)) + pcm +
                (b'\0' if len(pcm) & 1 else b''))
    json.dump(dict(chunks=layout), open(os.path.join(outdir, 'wav.json'), 'w'), indent=1)
    return dict(opaque_bytes=opaque, notes=[c['id'] for c in layout])


def _chunk(cid, body, ent):
    pad = b''
    if len(body) & 1:
        pad = bytes.fromhex(ent['pad_hex']) if 'pad_hex' in ent else b'\0'
    return cid.encode('latin-1') + struct.pack('<I', len(body)) + body + pad


def encode_from_dir(outdir):
    layout = json.load(open(os.path.join(outdir, 'wav.json')))['chunks']
    w = open(os.path.join(outdir, 'audio.wav'), 'rb').read()
    if w[:4] != b'RIFF' or w[8:12] != b'WAVE':
        raise ValueError('audio.wav is not RIFF/WAVE')
    sub = {c: b for c, b, _ in _chunks(w, 12, len(w))}
    if len(sub.get(b'fmt ', b'')) != 16 or b'data' not in sub:
        raise ValueError('audio.wav must be plain PCM: a 16-byte fmt chunk and a data chunk '
                         '(re-export without extensible format)')
    out = []
    for ent in layout:
        cid = ent['id']
        if cid == 'fmt ':
            body = sub[b'fmt ']        # audio.wav's fmt is the source of truth (edited samples stay consistent)
        elif cid == 'data':
            body = sub[b'data']
        elif cid == 'LIST':
            body = ent['list_type'].encode('latin-1') + b''.join(
                _chunk(e['id'], _text_bytes(e), e) for e in ent['entries'])
        else:
            body = bytes.fromhex(ent['body_hex'])
        out.append(_chunk(cid, body, ent))
    payload = b'WAVE' + b''.join(out)
    return b'RIFF' + struct.pack('<I', len(payload)) + payload
