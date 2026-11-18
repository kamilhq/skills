// Synthetic inputs for the parity cases of scripts/cpp (made-up matched units with matching scaffolding, a
// shared header, a rewrite tree, a names index, a cpp config, and tiny PE32 / PE32+ images built here).
// Nothing here comes from a game.
import path from 'node:path'
import { w } from './fakes.mjs'

const UNIT_MAIN = `// CLFLAGS: /O2 /MT /GS
// Translation-unit guess 1: main (made up for the parity test)
#include "include/Game.h"
#pragma include_alias(<ammintrin.h>, <crtdefs.h>)
#include <string>

typedef unsigned int uint32_t_;
struct StrRef { std::string* p; };
struct LocalThing
{
    int a; // { not a brace
};
enum { MODE_IDLE = 0, MODE_RUN = 2, MODE_JUMP = 1, MODE_SWIM = 9 };
#define FLAG_BIG (1 << 4)
#define LOCAL_LIMIT 40
#define OLD_SPEED top_speed
#define SQUARE(x) ((x) * (x))
#define MULTI(a, b) \\
    ((a) + \\
     (b))

extern int g_score;
void tick(int frames, bool fast = false);
static int helper_sum(int a, int b);
class Player;

// not in this unit's range: tick's real body, so that the call below gets its convention
static __declspec(noinline) void tick(int frames, bool fast)
{
    g_score += frames;
}

// FUNCTION: GAME 0x401000
// main loop step (descriptive comment, dropped)
int __fastcall run_frame(StrRef r, int n)
{
    tick(n);
    if (FLAG_BIG & n)
    {
        return MODE_RUN + LOCAL_LIMIT; /* comment kept */
    }
    const char* s = "OLD_SPEED { MODE_RUN";
    return OLD_SPEED + SQUARE(n) + MODE_JUMP + MODE_SWIM + MULTI(1, 2) + (int) s[0];
}

// FUNCTION: GAME 0x401080
void Player::update(int dt)
{
    x += dt * OLD_SPEED;
}

// NONMATCHING: same code, different register allocation
// FUNCTION: GAME 0x401100
__forceinline int Player::score() const
{
    return (int) "a{b}"[0] + '}';
}

static int run_frame_caller(int n)
{
    StrRef r = {0};
    return run_frame(r, n);
}

namespace ui
{
// FUNCTION: GAME 0x401200
void draw_text(const char* s, int x = 0, int y = 0)
{
    tick(x + y, s != 0);
}
}

// FUNCTION: GAME 0x401300 ??__Eg_player@@YAXXZ
Player g_player;

// GLOBAL: GAME 0x405000
int g_lives = 3;

// FUNCTION: OTHER 0x500000
void other_module_fn()
{
}

// STUB: GAME 0x401050
// NOTE: fragment of 0x401000
`

const UNIT_UTIL = `#include "include/Game.h"
#define FLAG_BIG 0x10
#define DUP_MACRO 1
int g_score;

// FUNCTION: GAME 0x402000
void tick(int frames, bool fast)
{
    g_score += fast ? frames * 2 : frames;
}

// FUNCTION: GAME 0x402040
static int helper_sum(int a, int b)
{
    return a + b + (FLAG_BIG ? 1 : 0);
}

static inline int clamp_small(int v) { return v < 0 ? 0 : v; }

extern "C" {
// FUNCTION: GAME 0x402080
int c_entry(int v)
{
    return helper_sum(v, clamp_small(v));
}
}

// FUNCTION: GAME 0x4020c0
void Player::reset()
{
    x = 0;
}

static inline int clamp_small(int v) { return v < 0 ? 0 : v; }

template class std::vector<int>;
int g_lives = 3;
static int s_counter = 0;
static int s_counter = 0;
`

const UNIT_CRT = `// FUNCTION: GAME 0x403000 ??1bad_alloc@std@@UAE@XZ
void crt_thing()
{
}
// STUB: GAME 0x403010
`

const UNIT_EXTRA = `struct Extra { int v; };
// FUNCTION: GAME 0x404000
void lonely(Extra* e)
{
    e->v = 1;
}
// FUNCTION: GAME 0x404040
void implicit_member_note_only();
`

const HEADER = `// Game.h - shared definitions (made up)
#ifndef GAME_H
#define GAME_H
#pragma once
#include <vector>
#include "SDLTypes.h"

typedef char check_Player_size[sizeof(int) == 4 ? 1 : -1];
enum Mode { MODE_IDLE, MODE_RUN, MODE_JUMP, MODE_SWIM };
#define FLAG_SMALL (1 << 4)
#define GAME_FEATURE

class Player
{
public:
    int x;
    int top_speed;
    void update(int dt);
    int score() const;
    void reset();
};

extern Player g_player;
void tick(int frames, bool fast = false);

#endif // GAME_H
`

export const CPP_CONFIG = {
  module: 'GAME',
  units: 'src_matched/GAME',
  unit_id: '^([0-9]{3})_',
  library_units: ['003'],
  unit_dest: { 'main/Main.cpp': ['001'], 'util/Util.cpp': ['002'] },
  class_dest: { Player: 'game/Player.cpp' },
  name_dest: { draw_text: 'ui/Text.cpp' },
  addr_dest: { '0x402080': 'util/CApi.cpp' },
  default_dest: 'misc/Misc.cpp',
  namespaces: ['ui'],
  type_aliases: { Uint8: 'unsigned char' },
  drop: {
    lines: ['^\\s*//\\s*CLFLAGS:'],
    functions: ['\\w+_caller'],
    keys: [],
    types: ['StrRef', 'check_.*', 'uint32_t_'],
    macros: ['DUP_.*'],
    includes: [],
    declspecs: ['noinline'],
    keywords: { __fastcall: '', __forceinline: 'inline' }
  },
  renames: { members: {}, global: {}, units: { '002': { g_score: 'g_score' } } },
  constants: { canonical: { FLAG_BIG: '(1 << 17)', MODE_SWIM: '3' }, headers: [], families: {}, ignore: ['SDL_.*'] },
  headers: { 'include/Game.h': 'game/Game.h' },
  type_home: { LocalThing: 'main/Types.h' },
  includes: ['#include <stdio.h>'],
  system_includes: { '<string>': '\\bstd::string\\b', '<string.h>': '\\bmemcpy\\s*\\(' },
  guard_prefix: 'GAME_',
  banner: 'From the made-up units {units}.',
  dropped: { '0x404000': 'replaced by a library call' }
}

export function cppProject (W, opts = {}) {
  const u = path.join(W, 'src_matched', 'GAME')
  w(path.join(u, '001_main.cpp'), opts.crlf ? UNIT_MAIN.replaceAll('\n', '\r\n') : UNIT_MAIN)
  w(path.join(u, '002_util.cpp'), UNIT_UTIL)
  w(path.join(u, '003_crt.cpp'), UNIT_CRT)
  w(path.join(u, '004_extra.cpp'), UNIT_EXTRA)
  w(path.join(u, 'notes.txt'), 'not a unit\n')
  w(path.join(u, 'include', 'Game.h'), HEADER)
  const cfg = { ...CPP_CONFIG, ...(opts.cfg || {}) }
  w(path.join(W, 'cpp.json'), JSON.stringify(cfg, null, 1) + '\n')
  // the rewrite tree: every placed function has its address comment, except 0x4020c0 (lost) when opts.lose
  const t = path.join(W, 'rewrite', 'src')
  w(path.join(t, 'main', 'Main.cpp'), '// Main.cpp\n\n// 0x401000\nint run_frame(int n) { return n; }\n  /* 0x401200 */\n// 0x409999\nint WinMain() { return 0; }\n')
  w(path.join(t, 'game', 'Player.cpp'), '// 0x401080\n// 0x401100\n' + (opts.lose ? '' : '// 0x4020C0\n') + '// 0x401080 again\n')
  w(path.join(t, 'util', 'Util.cpp'), '//0x402000\n// 0x402040\n// 0x402080\n// 0x403010\n')
  w(path.join(t, 'util', 'notes.md'), '// 0x404040\n')
  w(path.join(t, 'aaa.h'), '    // 0x401000 in a header, first by walk order? no: root files come first\n')
  w(path.join(W, 'names.json'), JSON.stringify({
    functions: [{ address: '0x401000', name: 'run_frame' }, { address: '0x401300', name: 'dynamic_initializer_for_g_player' },
      { address: '0x4020C0', name: 'Player::reset' }, { address: '0x403000', name: 'std::bad_alloc::~bad_alloc' }]
  }, null, 1))
}

// ------------------------------------------------------------------------------------------ tiny PE
function peImage ({ magic = 0x10b, base = 0x400000, sections }) {
  const optsz = magic === 0x20b ? 0xf0 : 0xe0
  const hdr = Buffer.alloc(0x400)
  hdr.write('MZ', 0, 'latin1')
  hdr.writeUInt32LE(0x40, 0x3c)
  hdr.write('PE\0\0', 0x40, 'latin1')
  hdr.writeUInt16LE(magic === 0x20b ? 0x8664 : 0x14c, 0x44)
  hdr.writeUInt16LE(sections.length, 0x46)
  hdr.writeUInt16LE(optsz, 0x54)
  hdr.writeUInt16LE(0x102, 0x56)
  hdr.writeUInt16LE(magic, 0x58)
  if (magic === 0x20b) hdr.writeBigUInt64LE(BigInt(base), 0x58 + 24)
  else hdr.writeUInt32LE(base, 0x58 + 28)
  let off = 0x58 + optsz
  let raw = 0x400
  const bodies = []
  for (const s of sections) {
    hdr.write(s.name.padEnd(8, '\0'), off, 'latin1')
    hdr.writeUInt32LE(s.vsize, off + 8)
    hdr.writeUInt32LE(s.rva, off + 12)
    const size = Math.ceil(s.data.length / 0x200) * 0x200
    hdr.writeUInt32LE(s.rawsize === undefined ? size : s.rawsize, off + 16)
    hdr.writeUInt32LE(raw, off + 20)
    const body = Buffer.alloc(size)
    s.data.copy(body)
    bodies.push(body)
    raw += size
    off += 40
  }
  return Buffer.concat([hdr, ...bodies])
}

function rdata (base, ptr) {
  const d = Buffer.alloc(0x200)
  const ints = [1, -2, 300, 0x7fffffff, -2147483648, 42]
  ints.forEach((v, i) => d.writeInt32LE(v, i * 4))
  ;[-1, 2, 0x1234, -300].forEach((v, i) => d.writeInt16LE(v, 0x18 + i * 2))
  ;[0, 1, 2, 255, 16, 17, 18, 19].forEach((v, i) => d.writeUInt8(v, 0x20 + i))
  ;[0.5, 1.015625, 0.1, -0, 3.4028234663852886e38, 1e-45, 123456.789, 0.0009765625].forEach((v, i) => d.writeFloatLE(v, 0x28 + i * 4))
  ;[0.1, 1 / 3, 1e300, 5e-324].forEach((v, i) => d.writeDoubleLE(v, 0x48 + i * 8))
  d.writeBigUInt64LE(2n ** 63n + 5n, 0x68)
  d.writeBigUInt64LE(1n, 0x70)
  d.writeBigInt64LE(-5n, 0x78)
  const strs = [[0x80, Buffer.from('hello\0', 'latin1')], [0x88, Buffer.from('quote"back\\slash\ttab\n\0', 'latin1')],
    [0xa0, Buffer.from([0xc3, 0xa9, 0x41, 0x00])], [0xa8, Buffer.from([0])]]
  for (const [o, b] of strs) b.copy(d, o)
  const rva = 0x1000
  const ptrs = [base + rva + 0x80, 0, base + rva + 0x88, base + rva + 0xa0, base + rva + 0xa8, base + 0x2000 + 2 * 2, base + 0x3000]
  ptrs.forEach((v, i) => (ptr === 8 ? d.writeBigUInt64LE(BigInt(v), 0xc0 + i * 8) : d.writeUInt32LE(v, 0xc0 + i * 4)))
  // struct array at 0x100: {uint16, bool, int8, int32} x 3, stride 8
  ;[[0x41, 1, -3, 70000], [0xbeef, 0, 127, -1], [7, 2, 0, 0]].forEach(([a, b, c, e], i) => {
    d.writeUInt16LE(a, 0x100 + i * 8); d.writeUInt8(b, 0x102 + i * 8); d.writeInt8(c, 0x103 + i * 8); d.writeInt32LE(e, 0x104 + i * 8)
  })
  for (let i = 0; i < 12; i++) d.writeInt8(i - 4, 0x120 + i)
  d.writeFloatLE(NaN, 0x130)
  return d
}

export function writePEs (W) {
  const base = 0x400000
  const data = Buffer.alloc(0x10)
  for (let i = 0; i < 4; i++) data.writeInt32LE(100 + i, i * 4)
  w(path.join(W, 'game', 'Game.exe'), peImage({
    base,
    sections: [{ name: '.text', rva: 0x1000 - 0x1000 + 0x0800, vsize: 0x10, data: Buffer.from([0xc3]) },
      { name: '.rdata', rva: 0x1000, vsize: 0x200, data: rdata(base, 4) },
      { name: '.data', rva: 0x2000, vsize: 0x40, rawsize: 0x10, data }]
  }))
  w(path.join(W, 'game', 'Game64.exe'), peImage({
    magic: 0x20b, base: 0x140000000, sections: [{ name: '.rdata', rva: 0x1000, vsize: 0x200, data: rdata(0x140000000, 8) }]
  }))
  w(path.join(W, 'game', 'notpe.exe'), Buffer.from('MZ' + '\0'.repeat(0x3e) + 'nothing here'))
  const items = [
    { name: 'ints', va: '0x401000', type: 'int32', count: 6, per_line: 4, width: 11, decl: 'static const int ints[6]', file: 'game/Tables.cpp' },
    { name: 'shorts', va: '0x401018', type: 'int16', count: 4 },
    { name: 'shorts_hex', va: '0x401018', type: 'uint16', count: 4, format: 'hex4' },
    { name: 'neg_hex', va: '0x401018', type: 'int16', count: 4, format: 'hex' },
    { name: 'bytes', va: 0x401020, type: 'uint8', dims: [2, 4], format: 'hex2' },
    { name: 'flags', va: '0x401020', type: 'bool', count: 8, per_line: 8 },
    { name: 'floats', va: '0x401028', type: 'float32', count: 8, per_line: 2 },
    { name: 'doubles', va: '0x401048', type: 'float64', count: 4 },
    { name: 'bigs', va: '0x401068', type: 'uint64', count: 2, format: 'hex' },
    { name: 'neg64', va: '0x401078', type: 'int64', count: 1 },
    { name: 'names', va: '0x4010c0', type: 'cstr', count: 6, decl: 'const char* names[]' },
    { name: 'ptrs', va: '0x4010d4', type: 'ptr', count: 2 },
    { name: 'records', va: '0x401100', type: 'struct', fields: ['uint16:hex4', 'bool', 'int8', 'int32'], stride: 8, count: 3, decl: 'static const Record records[]' },
    { name: 'cube', va: '0x401120', type: 'int8', dims: [2, 2, 3], width: 2 },
    { name: 'partial', va: '0x402008', type: 'int32', count: 8 },
    { name: 'zeros', va: '0x402020', type: 'int32', count: 4, decl: 'int zeros[4]', file: 'game/State.cpp' }
  ]
  const symbols = [{ base: '0x402000', stride: 2, count: 4, expr: 'table[{i}]' }]
  w(path.join(W, 'data.json'), JSON.stringify({ pe: 'game/Game.exe', symbols, items }, null, 1) + '\n')
  w(path.join(W, 'data64.json'), JSON.stringify({
    data: { pe: 'game/Game64.exe', items: [{ name: 'names64', va: '0x1400010c0', type: 'cstr', count: 5 }, { name: 'ints64', va: '0x140001000', type: 'int32', count: 2 }] }
  }, null, 1) + '\n')
  const bad = (name, it) => w(path.join(W, name + '.json'), JSON.stringify({ pe: 'game/Game.exe', items: [it] }) + '\n')
  bad('bad_addr', { name: 'x', va: '0x409000', type: 'int32', count: 1 })
  bad('bad_range', { name: 'x', va: '0x4011fc', type: 'int32', count: 4 })
  bad('bad_type', { name: 'x', va: '0x401000', type: 'int128', count: 1 })
  bad('bad_format', { name: 'x', va: '0x401000', type: 'int32', count: 1, format: 'octal' })
  bad('bad_key', { va: '0x401000', type: 'int32', count: 1 })
  bad('bad_number', { name: 'x', va: '0x40zz00', type: 'int32', count: 1 })
  bad('bad_nan', { name: 'x', va: '0x401130', type: 'float32', count: 1 })
  bad('bad_struct', { name: 'x', va: '0x401100', type: 'struct', fields: ['int32'], count: 1 })
  bad('bad_perline', { name: 'x', va: '0x401000', type: 'int32', count: 2, per_line: 0 })
}
