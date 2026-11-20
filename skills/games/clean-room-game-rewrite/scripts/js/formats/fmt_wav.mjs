// RIFF WAVE sounds (.wav). Port of fmt_wav.py.
//
// Decoded form (outdir):
//   audio.wav   canonical 44-byte-header PCM WAV with the same fmt and samples (plays/edits anywhere)
//   wav.json    RIFF chunk order and every non-audio chunk: fmt fields, LIST/INFO entries as text,
//               any other chunk as hex (counted as opaque), odd-size pad bytes
//
// RIFF size, chunk sizes and pad positions are recomputed. audio.wav is the source of truth for format and
// samples; the fmt fields in wav.json are informational only. Opaque bytes: bodies of unknown chunks,
// non-zero pad bytes, and stale bytes after the NUL of INFO strings.
import { readFileSync, writeFileSync } from 'node:fs'
import { dump, load, plain } from '../lib/pyjson.mjs'
import { pyEncode, pyFromHex, pyJoin } from '../lib/pycompat.mjs'

export const EXTS = ['.wav']

const latin = (b) => Buffer.from(b).toString('latin1')
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b }
const isZeroPad = (p) => p.length === 1 && p[0] === 0

function chunks(buf, pos, end) {
  const out = []
  while (pos + 8 <= end) {
    const cid = buf.subarray(pos, pos + 4)
    const ln = buf.readUInt32LE(pos + 4)
    const body = buf.subarray(pos + 8, pos + 8 + ln)
    if (body.length !== ln) throw new Error('ValueError: truncated chunk')
    const pad = ln & 1 ? buf.subarray(pos + 8 + ln, pos + 9 + ln) : Buffer.alloc(0)
    out.push([cid, body, pad])
    pos += 8 + ln + pad.length
  }
  if (pos !== end) throw new Error(`ValueError: ${end - pos} trailing bytes after chunks`)
  return out
}

// INFO text: string up to the first NUL. What follows is NUL padding, or stale bytes left by the
// writing tool (kept as stale_hex, counted as opaque).
function textField(b) {
  const nul = b.indexOf(0)
  if (nul < 0) return { text: latin(b), nul_count: 0 }
  const rest = b.subarray(nul)
  if (rest.some((x) => x)) return { text: latin(b.subarray(0, nul)), stale_hex: rest.toString('hex') }
  return { text: latin(b.subarray(0, nul)), nul_count: rest.length }
}

function textBytes(e) {
  const t = pyEncode(e.text, 'latin-1')
  return Buffer.concat([t, 'stale_hex' in e ? pyFromHex(e.stale_hex) : Buffer.alloc(e.nul_count)])
}

export function decode_to_dir(data, outdir) {
  if (latin(data.subarray(0, 4)) !== 'RIFF' || latin(data.subarray(8, 12)) !== 'WAVE') {
    throw new Error('ValueError: not RIFF WAVE')
  }
  if (data.readUInt32LE(4) + 8 !== data.length) throw new Error('ValueError: RIFF size does not match file size')
  let fmt = null
  let pcm = null
  const layout = []
  let opaque = 0
  for (const [cid, body, pad] of chunks(data, 12, data.length)) {
    const id = latin(cid)
    const ent = { id }
    if (pad.length && !isZeroPad(pad)) {
      ent.pad_hex = pad.toString('hex')
      opaque += 1
    } else if (pad.length) {
      ent.pad = true
    }
    if (id === 'fmt ') {
      if (body.length !== 16) throw new Error('ValueError: fmt chunk with extension not handled')
      fmt = body
      Object.assign(ent, { informational: true, format_tag: body.readUInt16LE(0), channels: body.readUInt16LE(2),
        sample_rate: body.readUInt32LE(4), byte_rate: body.readUInt32LE(8), block_align: body.readUInt16LE(12),
        bits_per_sample: body.readUInt16LE(14) })
    } else if (id === 'data') {
      if (pcm !== null) throw new Error('ValueError: two data chunks')
      pcm = body
      ent.samples_in = 'audio.wav'
    } else if (id === 'LIST') {
      ent.list_type = latin(body.subarray(0, 4))
      ent.entries = chunks(body, 4, body.length).map(([s, b, p]) => ({ id: latin(s), ...textField(b),
        ...(p.length && !isZeroPad(p) ? { pad_hex: p.toString('hex') } : p.length ? { pad: true } : {}) }))
      for (const e of ent.entries) {
        if ('stale_hex' in e) opaque += pyFromHex(e.stale_hex).filter((x) => x).length
        opaque += 'pad_hex' in e ? 1 : 0
      }
    } else {
      ent.body_hex = body.toString('hex')
      opaque += body.length
    }
    layout.push(ent)
  }
  if (fmt === null || pcm === null) throw new Error('ValueError: missing fmt or data')
  writeFileSync(pyJoin(outdir, 'audio.wav'), Buffer.concat([Buffer.from('RIFF'), u32(36 + pcm.length + (pcm.length & 1)),
    Buffer.from('WAVEfmt '), u32(16), fmt, Buffer.from('data'), u32(pcm.length), pcm,
    pcm.length & 1 ? Buffer.alloc(1) : Buffer.alloc(0)]))
  dump({ chunks: layout }, pyJoin(outdir, 'wav.json'), { indent: 1 })
  return { opaque_bytes: opaque, notes: layout.map((c) => c.id) }
}

function chunk(cid, body, ent) {
  let pad = Buffer.alloc(0)
  if (body.length & 1) pad = 'pad_hex' in ent ? pyFromHex(ent.pad_hex) : Buffer.alloc(1)
  return Buffer.concat([pyEncode(cid, 'latin-1'), u32(body.length), body, pad])
}

export function encode_from_dir(outdir) {
  const layout = plain(load(pyJoin(outdir, 'wav.json'))).chunks
  const w = readFileSync(pyJoin(outdir, 'audio.wav'))
  if (latin(w.subarray(0, 4)) !== 'RIFF' || latin(w.subarray(8, 12)) !== 'WAVE') {
    throw new Error('ValueError: audio.wav is not RIFF/WAVE')
  }
  const sub = new Map()
  for (const [c, b] of chunks(w, 12, w.length)) sub.set(latin(c), b)
  if ((sub.get('fmt ') ?? Buffer.alloc(0)).length !== 16 || !sub.has('data')) {
    throw new Error('ValueError: audio.wav must be plain PCM: a 16-byte fmt chunk and a data chunk ' +
      '(re-export without extensible format)')
  }
  const out = []
  for (const ent of layout) {
    const cid = ent.id
    let body
    if (cid === 'fmt ') body = sub.get('fmt ')     // audio.wav's fmt is the source of truth (edited samples stay consistent)
    else if (cid === 'data') body = sub.get('data')
    else if (cid === 'LIST') {
      body = Buffer.concat([pyEncode(ent.list_type, 'latin-1'), ...ent.entries.map((e) => chunk(e.id, textBytes(e), e))])
    } else body = pyFromHex(ent.body_hex)
    out.push(chunk(cid, body, ent))
  }
  const payload = Buffer.concat([Buffer.from('WAVE'), ...out])
  return Buffer.concat([Buffer.from('RIFF'), u32(payload.length), payload])
}
