// archive.mjs - the tar / tar.gz / zip reading build_libs.mjs needs (what Python's tarfile and zipfile do
// for build_libs.py). Node built-ins only.
import zlib from 'node:zlib'

const cstr = (b, o, n) => { const s = b.subarray(o, o + n); const z = s.indexOf(0); return s.toString('utf8', 0, z < 0 ? n : z) }
const octal = (b, o, n) => { const s = cstr(b, o, n).trim(); return s ? parseInt(s, 8) : 0 }

// [{name, kind: 'file' | 'dir' | 'other', data}] in archive order (pax/GNU long names applied)
export function readTar (buf, gz) {
  const d = gz ? zlib.gunzipSync(buf) : buf
  const out = []
  let off = 0; let longName = null; let paxPath = null
  while (off + 512 <= d.length) {
    const h = d.subarray(off, off + 512)
    if (h.every(x => x === 0)) break
    let name = cstr(h, 0, 100)
    const size = octal(h, 124, 12)
    const type = String.fromCharCode(h[156] || 0x30)
    const magic = h.toString('latin1', 257, 263)
    if (magic.startsWith('ustar')) {
      const prefix = cstr(h, 345, 155)
      if (prefix) name = prefix + '/' + name
    }
    const data = d.subarray(off + 512, off + 512 + size)
    off += 512 + Math.ceil(size / 512) * 512
    if (type === 'L') { longName = cstr(data, 0, data.length); continue }
    if (type === 'x' || type === 'g') {
      if (type === 'x') {
        let i = 0
        while (i < data.length) {
          const sp = data.indexOf(0x20, i)
          if (sp < 0) break
          const len = parseInt(data.toString('latin1', i, sp), 10)
          if (!len) break
          const rec = data.toString('utf8', sp + 1, i + len - 1)
          const eq = rec.indexOf('=')
          if (rec.slice(0, eq) === 'path') paxPath = rec.slice(eq + 1)
          i += len
        }
      }
      continue
    }
    if (paxPath !== null) name = paxPath
    else if (longName !== null) name = longName
    paxPath = null; longName = null
    if (type === '5') out.push({ name: name.replace(/\/+$/, ''), kind: 'dir', data: null })
    else if (type === '0' || type === '\0' || type === '7') out.push({ name, kind: 'file', data: Buffer.from(data) })
    else out.push({ name, kind: 'other', data: null })
  }
  return out
}

// [{name, kind: 'file' | 'dir' | 'link', data}] from the central directory
export function readZip (d) {
  let eocd = -1
  for (let i = d.length - 22; i >= Math.max(0, d.length - 65557); i--) {
    if (d.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
  }
  if (eocd < 0) throw new Error('File is not a zip file')
  const n = d.readUInt16LE(eocd + 10)
  let off = d.readUInt32LE(eocd + 16)
  const out = []
  for (let k = 0; k < n; k++) {
    if (d.readUInt32LE(off) !== 0x02014b50) throw new Error('Bad magic number for central directory')
    const method = d.readUInt16LE(off + 10)
    const csize = d.readUInt32LE(off + 20)
    const nlen = d.readUInt16LE(off + 28); const xlen = d.readUInt16LE(off + 30); const clen = d.readUInt16LE(off + 32)
    const ext = d.readUInt32LE(off + 38)
    const lho = d.readUInt32LE(off + 42)
    const flags = d.readUInt16LE(off + 8)
    const name = d.toString(flags & 0x800 ? 'utf8' : 'latin1', off + 46, off + 46 + nlen)
    off += 46 + nlen + xlen + clen
    const mode = (ext >>> 16) & 0o170000
    if (mode === 0o120000) { out.push({ name, kind: 'link', data: null }); continue }
    if (name.endsWith('/')) { out.push({ name, kind: 'dir', data: null }); continue }
    const lnlen = d.readUInt16LE(lho + 26); const lxlen = d.readUInt16LE(lho + 28)
    const raw = d.subarray(lho + 30 + lnlen + lxlen, lho + 30 + lnlen + lxlen + csize)
    let data
    if (method === 0) data = Buffer.from(raw)
    else if (method === 8) data = zlib.inflateRawSync(raw)
    else throw new Error(`compression method ${method} not supported`)
    out.push({ name, kind: 'file', data })
  }
  return out
}
