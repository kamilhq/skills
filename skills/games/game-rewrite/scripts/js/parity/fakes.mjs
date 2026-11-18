// fakes.mjs - synthetic inputs for the parity test: made-up traces, replays, a fake game run by a fake
// "wine", fake cl/link/lib (msvc.sh), clang and rust-lld, tiny PE DLLs, COFF objects and archives. Nothing
// here comes from a real game or a real toolchain.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'

export const w = (p, data, mode) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, data); if (mode) fs.chmodSync(p, mode) }

// ------------------------------------------------------------------------------------- traces
function traceLine (f, o = {}) {
  const x = o.x !== undefined ? o.x : f * 2
  const vx = o.vx !== undefined ? o.vx : (f % 3 === 0 ? '3f800000' : 'bf000000')
  const fields = [['f', f], ['gs', o.gs !== undefined ? o.gs : (f < 5 ? 1 : 0)], ['p', `${x},${100 - f}`], ['v', `${vx},00000000`],
    ['flags', f > 6 ? '1,7' : '-'], ['tb', `0,811c9dc5`], ['fb', o.fb || (0x1000 + f * 17).toString(16).padStart(8, '0')]]
  const order = o.order || fields.map(([k]) => k)
  const m = new Map(fields)
  return order.map(k => `${k}=${m.get(k)}`).join(' ')
}
export function makeTraces (dir) {
  const H = 'TEST-TRACE 1'
  const lines = (n, mod = () => ({})) => [H, ...Array.from({ length: n }, (_, f) => traceLine(f, mod(f)))].join('\n') + '\n'
  w(path.join(dir, 'a.trace'), lines(12))
  w(path.join(dir, 'a_crlf.trace'), lines(12).replaceAll('\n', '\r\n'))
  w(path.join(dir, 'b.trace'), lines(12, f => (f === 4 ? { x: 9, vx: '3f000000' } : f >= 9 ? { fb: 'deadbeef' } : f === 7 ? { gs: 3 } : {})))
  w(path.join(dir, 'short.trace'), lines(8))
  w(path.join(dir, 'long.trace'), lines(14, f => (f === 13 ? { x: 1 } : {})))
  w(path.join(dir, 'order.trace'), lines(12, () => ({ order: ['f', 'gs', 'v', 'p', 'flags', 'tb', 'fb'] })))
  w(path.join(dir, 'other_header.trace'), lines(12).replace(H, 'OTHER 2'))
  w(path.join(dir, 'bad_frame.trace'), lines(5) + 'f=3 gs=0\n')
  w(path.join(dir, 'bad_token.trace'), lines(3) + 'f=3 gs\n')
  w(path.join(dir, 'weird_float.trace'), lines(12, f => (f === 2 ? { vx: 'zz' } : f === 3 ? { vx: '7f800000' } : f === 5 ? { vx: '00000001' } : {})))
  w(path.join(dir, 'empty.trace'), '')
}

// --------------------------------------------------------------------------- fake programs (Python)
const FAKE_GAME = String.raw`import os, sys, random
def host(p):
    return p[2:].replace('\\', '/') if p.startswith('Z:') else p
mode = os.environ.get('FAKE_MODE', 'game')
args = sys.argv[2:]
if mode == 'hello':
    res = os.environ.get('FAKE_RESULT', 'OK')
    with open('hello.log', 'w', newline='') as f:
        f.write('step one\r\nstep two\r\nRESULT: %s\r\n' % res)
    print('fake hello output', ' '.join(args))
    sys.exit(0 if res == 'OK' else 4)
if mode == 'crash':
    print('wine: Unhandled page fault on read access to 00004DC9 at address 7BF2123D')
    sys.exit(5)
if mode == 'flaky' and not os.path.exists('.started'):
    open('.started', 'w').close()
    sys.exit(5)
if mode == 'never':
    sys.exit(0)
replay = host(os.environ['GAME_REPLAY'])
trace = host(os.environ['GAME_TRACE'])
exit_frame = int(os.environ['GAME_EXIT_FRAME'])
fb = os.environ.get('GAME_TRACE_FB', '1') != '0'
basedir = host(args[args.index('-basedir') + 1]).rstrip('/') if '-basedir' in args else None
seen = []
if basedir and os.path.isdir(basedir):
    for root, dirs, files in os.walk(basedir):
        for n in files:
            fp = os.path.join(root, n)
            with open(fp) as sf:
                seen.append(os.path.relpath(fp, basedir).replace(os.sep, '/') + ' ' + sf.read().strip())
    seen.sort()
plain_args = [x for i, x in enumerate(args) if not (i > 0 and args[i - 1] == '-basedir')]
events = []
header = False
for line in open(replay):
    s = line.split('#')[0].strip()
    if not s:
        continue
    if not header:
        assert s == 'TEST-REPLAY 1', s
        header = True
        continue
    fr, keys = s.split()[:2]
    events.append((int(fr), [] if keys == '-' else keys.split('+')))
x, held = 0, []
out = open(trace, 'w', newline='\n')
out.write('TEST-TRACE 1\n')
for f in range(exit_frame + 1):
    for fr, keys in events:
        if fr <= f:
            held = keys
    if 'right' in held:
        x += 1
    if 'left' in held:
        x -= 1
    extra = ' rnd=%d' % random.randint(0, 9) if mode == 'random' else ''
    out.write('f=%d p=%d,0 keys=%s%s extra=%s fb=%s\n' % (f, x, '+'.join(held) or '-', extra,
              os.environ.get('FAKE_EXTRA', '-'), ('%08x' % (0x811c9dc5 ^ (x * 2654435761 & 0xffffffff))) if fb else '-'))
out.close()
if basedir:
    os.makedirs(os.path.join(basedir, 'saves'), exist_ok=True)
    with open(os.path.join(basedir, 'saves', 'settings.sav'), 'w') as f:
        f.write('x=%d\n' % x)
    with open(os.path.join(basedir, 'saves', 'unlock.sav'), 'w') as f:
        f.write('frames=%d\n' % (exit_frame + 1))
    with open(os.path.join(basedir, 'log.txt'), 'w') as f:
        f.write('basedir file, not a save\n')
    with open(os.path.join(basedir, 'saves', 'seen.sav'), 'w') as f:
        f.write('args=%s\n' % ' '.join(plain_args))
        for line in seen:
            f.write(line + '\n')
`

// msvc.sh stand-in: logs each call, writes the objects / libraries / DLLs the real tools would
const FAKE_MSVC = String.raw`import json, os, shutil, sys
tool, args = sys.argv[1], sys.argv[2:]
with open(os.environ['FAKE_LOG'], 'a') as f:
    f.write(json.dumps([tool] + args) + '\n')
def host(p):
    return p.replace('\\', '/')
if os.environ.get('FAKE_FAIL_TOOL') == tool:
    print('fatal error C1083: Cannot open include file')
    sys.exit(2)
if tool == 'cl':
    fo = [a for a in args if a.startswith('/Fo')]
    d = host(fo[0][3:]) if fo else '.'
    for a in args:
        if not a.startswith('/') and a.endswith(('.c', '.cpp')):
            print(os.path.basename(host(a)))
            shutil.copyfile(os.environ['FAKE_OBJ'], os.path.join(d, os.path.splitext(os.path.basename(host(a)))[0] + '.obj'))
    print('warning C4996: fake warning kept in the output')
elif tool == 'lib':
    out = [host(a[5:]) for a in args if a.startswith('/OUT:')][0]
    with open(out, 'w') as f:
        f.write('LIB ' + ' '.join(a for a in args if not a.startswith('/')) + '\n')
elif tool == 'link':
    out = [host(a[5:]) for a in args if a.startswith('/OUT:')][0]
    imp = [host(a[8:]) for a in args if a.startswith('/IMPLIB:')]
    if '/DLL' in args:
        shutil.copyfile(os.environ['FAKE_DLL'], out)
    else:
        with open(out, 'w') as f:
            f.write('EXE\n')
    base = os.path.splitext(imp[0] if imp else out)[0]
    for ext in ('.lib', '.exp'):
        with open(base + ext, 'w') as f:
            f.write(ext)
    print('   Creating library %s.lib and object %s.exp' % (base, base))
`
const FAKE_CLANG = String.raw`import json, os, shutil, sys
with open(os.environ['FAKE_LOG'], 'a') as f:
    f.write(json.dumps(['clang'] + sys.argv[1:]) + '\n')
out = sys.argv[sys.argv.index('-o') + 1]
src = os.environ.get('FAKE_OBJ')
if out.endswith('.o') or not src:
    open(out, 'wb').write(b'OBJ')
else:
    shutil.copyfile(src, out)
`
// rust-lld stand-in: /lib /def: writes an llvm-lib style import library (descriptor object + short imports)
const FAKE_LLD = String.raw`import json, os, struct, sys
args = sys.argv[1:]
if os.environ.get('FAKE_LOG'):
    with open(os.environ['FAKE_LOG'], 'a') as f:
        f.write(json.dumps(['rust-lld'] + args) + '\n')
out = [a[5:] for a in args if a.startswith('/out:')][0]
defs = [a[5:] for a in args if a.startswith('/def:')]
members = []
if defs:
    dll, names = 'X.dll', []
    for line in open(defs[0]).read().splitlines():
        s = line.strip()
        if s.upper().startswith('LIBRARY'):
            dll = s.split()[1]
        elif s and not s.upper().startswith('EXPORTS'):
            names.append(s.split(' == ')[0])
    sym = b'__IMPORT_DESCRIPTOR_' + dll.split('.')[0].encode()
    strtab = sym + b'\0'
    coff = struct.pack('<HHIIIHH', 0x14c, 0, 0, 20, 1, 0, 0)
    coff += struct.pack('<IIIhHBB', 0, 4, 0, 1, 0, 2, 0) + struct.pack('<I', 4 + len(strtab)) + strtab
    members.append((dll.encode() + b'/', coff))
    for n in names:
        sname = n if '@' in n else '_' + n
        rest = sname.encode() + b'\0' + dll.encode() + b'\0'
        hdr = struct.pack('<HHHHIIHH', 0, 0xffff, 0, 0x14c, 0, len(rest), 0, (3 << 2) | 0)
        members.append((dll.encode() + b'/', hdr + rest))
data = b'!<arch>\n'
for name, body in members:
    data += b'%-16s%-12s%-6s%-6s%-8s%-10d' % (name, b'0', b'0', b'0', b'644', len(body)) + b'\x60\n' + body
    if len(body) & 1:
        data += b'\n'
open(out, 'wb').write(data)
`
const FAKE_PIPELINE_PY = String.raw`import json, os, sys
a = sys.argv[1:]
out = a[a.index('--out') + 1]
proj = a[a.index('--project') + 1]
cfg = json.load(open(os.path.join(proj, 'decomp.json')))
b = [x for x in cfg['binaries'] if x['src'].startswith('src/')][0]
open(os.path.join(out, b['file']), 'w').write('built from ' + b['src'] + '\n')
sys.stderr.write('fake pipeline log\n')
print(json.dumps({'ok': True, 'mode': a[a.index('--mode') + 1], 'n': 1.0}, indent=1))
`
const FAKE_PIPELINE_MJS = `import fs from 'node:fs'
const a = process.argv.slice(2)
const out = a[a.indexOf('--out') + 1]; const proj = a[a.indexOf('--project') + 1]
const cfg = JSON.parse(fs.readFileSync(proj + '/decomp.json', 'utf8'))
const b = cfg.binaries.find(x => x.src.startsWith('src/'))
fs.writeFileSync(out + '/' + b.file, 'built from ' + b.src + '\\n')
process.stderr.write('fake pipeline log\\n')
process.stdout.write('{\\n "ok": true,\\n "mode": "' + a[a.indexOf('--mode') + 1] + '",\\n "n": 1.0\\n}\\n')
`

// --------------------------------------------------------------------------- binary fixtures
// PE32 DLL with an export table (named exports) and an import table (names and one ordinal)
export function makePE (exports, imports, dllName = 'fake.dll') {
  const sect = Buffer.alloc(0x800)
  const VA = 0x1000
  let cur = 0
  const alloc = n => { const o = cur; cur += (n + 3) & ~3; return o }
  const str = s => { const o = alloc(s.length + 1); sect.write(s, o, 'latin1'); return o }
  // export directory
  const ed = alloc(40)
  const names = exports.map(n => str(n))
  const nameArr = alloc(4 * exports.length)
  const ords = alloc(2 * exports.length)
  const funcs = alloc(4 * exports.length)
  exports.forEach((_, i) => {
    sect.writeUInt32LE(VA + names[i], nameArr + 4 * i); sect.writeUInt16LE(i, ords + 2 * i); sect.writeUInt32LE(VA + 0x700 + i, funcs + 4 * i)
  })
  const dn = str(dllName)
  sect.writeUInt32LE(VA + dn, ed + 12); sect.writeUInt32LE(1, ed + 16); sect.writeUInt32LE(exports.length, ed + 20)
  sect.writeUInt32LE(exports.length, ed + 24); sect.writeUInt32LE(VA + funcs, ed + 28); sect.writeUInt32LE(VA + nameArr, ed + 32)
  sect.writeUInt32LE(VA + ords, ed + 36)
  // import descriptors
  const entries = Object.entries(imports)
  const idt = alloc(20 * (entries.length + 1))
  entries.forEach(([dll, fns], k) => {
    const thunks = alloc(4 * (fns.length + 1))
    fns.forEach((fn, i) => {
      if (typeof fn === 'number') sect.writeUInt32LE((0x80000000 | fn) >>> 0, thunks + 4 * i)
      else { const hn = alloc(2 + fn.length + 1); sect.writeUInt16LE(i, hn); sect.write(fn, hn + 2, 'latin1'); sect.writeUInt32LE(VA + hn, thunks + 4 * i) }
    })
    const nm = str(dll)
    sect.writeUInt32LE(VA + thunks, idt + 20 * k); sect.writeUInt32LE(VA + nm, idt + 20 * k + 12); sect.writeUInt32LE(VA + thunks, idt + 20 * k + 16)
  })
  const hdr = Buffer.alloc(0x200)
  hdr.write('MZ', 0, 'latin1'); hdr.writeUInt32LE(0x80, 0x3c); hdr.write('PE\0\0', 0x80, 'latin1')
  hdr.writeUInt16LE(0x14c, 0x84); hdr.writeUInt16LE(1, 0x86); hdr.writeUInt16LE(224, 0x94); hdr.writeUInt16LE(0x2102, 0x96)
  const opt = 0x98
  hdr.writeUInt16LE(0x10b, opt); hdr.writeUInt32LE(0x10000000, opt + 28); hdr.writeUInt32LE(16, opt + 92)
  hdr.writeUInt32LE(VA + ed, opt + 96); hdr.writeUInt32LE(40, opt + 100)
  hdr.writeUInt32LE(VA + idt, opt + 104); hdr.writeUInt32LE(20 * (entries.length + 1), opt + 108)
  const sh = opt + 224
  hdr.write('.rdata', sh, 'latin1'); hdr.writeUInt32LE(0x800, sh + 8); hdr.writeUInt32LE(VA, sh + 12)
  hdr.writeUInt32LE(0x800, sh + 16); hdr.writeUInt32LE(0x200, sh + 20)
  return Buffer.concat([hdr, sect])
}
// COFF object: [name, {sec, type, sclass, aux}] symbols; long names go to the string table
export function makeCOFF (syms) {
  const recs = []; let strtab = Buffer.alloc(0)
  for (const [name, o] of syms) {
    const r = Buffer.alloc(18)
    if (name.length <= 8) r.write(name, 0, 'latin1')
    else { r.writeUInt32LE(0, 0); r.writeUInt32LE(4 + strtab.length, 4); strtab = Buffer.concat([strtab, Buffer.from(name + '\0', 'latin1')]) }
    r.writeInt16LE(o.sec, 12); r.writeUInt16LE(o.type || 0, 14); r[16] = o.sclass; r[17] = o.aux || 0
    recs.push(r)
    for (let i = 0; i < (o.aux || 0); i++) recs.push(Buffer.alloc(18, 0x41))
  }
  const h = Buffer.alloc(20)
  h.writeUInt16LE(0x14c, 0); h.writeUInt32LE(20, 8); h.writeUInt32LE(recs.length, 12)
  const st = Buffer.alloc(4); st.writeUInt32LE(4 + strtab.length)
  return Buffer.concat([h, ...recs, st, strtab])
}
export function makeAr (members) {      // GNU ar with '/' and '//' members
  let longnames = ''
  const hdr = (n, size) => Buffer.from(n.padEnd(16) + '0'.padEnd(12) + '0'.padEnd(6) + '0'.padEnd(6) + '644'.padEnd(8) + String(size).padEnd(10) + '`\n', 'latin1')
  const names = members.map(([n]) => { if (n.length + 1 > 16) { const o = longnames.length; longnames += n + '/\n'; return '/' + o } return n + '/' })
  const parts = [Buffer.from('!<arch>\n'), hdr('/', 4), Buffer.alloc(4)]
  if (longnames) { parts.push(hdr('//', longnames.length), Buffer.from(longnames, 'latin1')); if (longnames.length & 1) parts.push(Buffer.from('\n')) }
  members.forEach(([, body], i) => { parts.push(hdr(names[i], body.length), body); if (body.length & 1) parts.push(Buffer.from('\n')) })
  return Buffer.concat(parts)
}

// ------------------------------------------------------------------------------------ the fixtures
export function makeFixtures (FIX, python) {
  makeTraces(path.join(FIX, 'traces'))
  const sh = (name, py) => {
    w(path.join(FIX, 'bin', name + '.py'), py)
    w(path.join(FIX, 'bin', name), `#!/bin/sh\nexec ${python} -I "${path.join(FIX, 'bin', name + '.py')}" "$@"\n`, 0o755)
  }
  sh('wine', FAKE_GAME)
  w(path.join(FIX, 'bin', 'wineserver'), '#!/bin/sh\nexit 0\n', 0o755)
  sh('msvc.sh', FAKE_MSVC)
  sh('clang', FAKE_CLANG)
  sh('rust-lld', FAKE_LLD)
  w(path.join(FIX, 'decomp_scripts', 'pipeline.py'), FAKE_PIPELINE_PY)
  w(path.join(FIX, 'decomp_scripts', 'js', 'pipeline.mjs'), FAKE_PIPELINE_MJS)
  w(path.join(FIX, 'bin', 'game.exe'), 'MZ fake game exe\n')
  const obj = makeCOFF([['.text', { sec: 1, sclass: 3, aux: 1 }], ['_lib_init', { sec: 1, type: 0x20, sclass: 2 }],
    ['_lib_a_rather_long_function_name', { sec: 1, type: 0x20, sclass: 2 }], ['_lib_table', { sec: 2, sclass: 2 }],
    ['_other_fn', { sec: 1, type: 0x20, sclass: 2 }], ['_lib_undefined', { sec: 0, type: 0x20, sclass: 2 }],
    ['_static_fn', { sec: 1, type: 0x20, sclass: 3 }]])
  w(path.join(FIX, 'bin', 'template.obj'), obj)
  w(path.join(FIX, 'bin', 'template.dll'), makePE(['lib_init', 'lib_table', 'zeta'], { 'KERNEL32.dll': ['ExitProcess', 'GetLastError', 7], 'SDL2.dll': ['SDL_Init'] }, 'template.dll'))
  w(path.join(FIX, 'bin', 'objs.lib'), makeAr([['short.obj', obj], ['a_member_with_a_long_name.obj', makeCOFF([['_second', { sec: 1, type: 0x20, sclass: 2 }]])]]))
  // a syswow64 folder for gen_defs
  const sys = path.join(FIX, 'syswow64')
  w(path.join(sys, 'kernel32.dll'), makePE(['GetLastError', 'TlsAlloc', 'ExitProcess', 'memcpy'], {}, 'kernel32.dll'))
  w(path.join(sys, 'msvcrt.dll'), makePE(['memcpy', 'strlen'], {}, 'msvcrt.dll'))
  w(path.join(sys, 'ntdll.dll'), makePE(['memcpy', 'NtWriteFile'], {}, 'ntdll.dll'))
  w(path.join(sys, 'kernelbase.dll'), makePE(['WaitOnAddress'], {}, 'kernelbase.dll'))
  w(path.join(FIX, 'link_output.txt'), 'rust-lld: error: undefined symbol: _GetLastError@0\n>>> referenced by std\n' +
    'rust-lld: error: undefined symbol: _memcpy\nrust-lld: error: undefined symbol: _NtWriteFile@36\n' +
    'rust-lld: error: undefined symbol: _WaitOnAddress@16\nrust-lld: error: undefined symbol: _mainCRTStartup\n' +
    'rust-lld: error: undefined symbol: __Unwind_Resume\nrust-lld: error: undefined symbol: _NoSuchFunction@4\n')
  w(path.join(FIX, 'link_ok.txt'), 'undefined symbol: _TlsAlloc@0\nundefined symbol: _strlen\n')
  w(path.join(FIX, 'raw.def'), 'LIBRARY SDL2.dll\nEXPORTS\nSDL_Init\nSDL_Quit\nSDL_GetTicks@0\n')
  // library archives (made by Python's tarfile/zipfile so they are real archives)
  const arc = path.join(FIX, 'archives')
  fs.mkdirSync(arc, { recursive: true })
  const r = spawnSync(python, ['-I', '-c', String.raw`
import io, os, sys, tarfile, zipfile
d = sys.argv[1]
def add(t, name, data):
    i = tarfile.TarInfo(name); i.size = len(data); i.mtime = 1; t.addfile(i, io.BytesIO(data))
with tarfile.open(os.path.join(d, 'alpha-1.2.tar.gz'), 'w:gz', format=tarfile.PAX_FORMAT) as t:
    i = tarfile.TarInfo('alpha-1.2'); i.type = tarfile.DIRTYPE; i.mtime = 1; t.addfile(i)
    add(t, 'alpha-1.2/src/alpha.c', b'int alpha;\n')
    add(t, 'alpha-1.2/src/beta.c', b'int beta;\n')
    add(t, 'alpha-1.2/include/alpha.h', b'#define ALPHA 1\n')
    add(t, 'alpha-1.2/include/alpha_extra.h', b'#define EXTRA 1\n')
    add(t, 'alpha-1.2/' + 'deep/' * 25 + 'long_name_file.txt', b'pax path\n')
    l = tarfile.TarInfo('alpha-1.2/link.h'); l.type = tarfile.SYMTYPE; l.linkname = 'include/alpha.h'; t.addfile(l)
with tarfile.open(os.path.join(d, 'flat.tar'), 'w', format=tarfile.GNU_FORMAT) as t:
    add(t, 'one.c', b'int one;\n')
    add(t, 'two/' + 'x' * 120 + '.h', b'gnu long name\n')
with tarfile.open(os.path.join(d, 'evil.tar.gz'), 'w:gz') as t:
    add(t, '../escape.c', b'no\n')
with zipfile.ZipFile(os.path.join(d, 'gamma-3.zip'), 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('gamma-3/', '')
    z.writestr('gamma-3/lib/x86/gamma.lib', b'GAMMALIB' * 50)
    z.writestr('gamma-3/lib/x86/gamma.dll', b'GAMMADLL')
    z.writestr('gamma-3/include/gamma.h', b'#define GAMMA 3\n')
    z.writestr(zipfile.ZipInfo('gamma-3/stored.txt'), b'stored')
open(os.path.join(d, 'single-abc.c'), 'w').write('int single;\n')
`, arc])
  if (r.status !== 0) throw new Error('fixture archives: ' + r.stderr)
}
