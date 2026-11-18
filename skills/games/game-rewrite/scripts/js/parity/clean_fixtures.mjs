// Fixtures for the cleanroom and release_check parity cases: a made-up project with "decompiled" and "matched"
// code, a names map, a game folder, a clean rewrite tree and a bad one (copied code, address annotations,
// Ghidra names, embedded tables, a copied asset), specs good and bad. Nothing here comes from a real game.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import * as L from '../lib/rwlib.mjs'
import { w } from './fakes.mjs'

export const EPOCH = '1700000000'

const GHIDRA_FN = `void FUN_00401000(int param_1)
{
  int iVar1;
  iVar1 = *(int *)(param_1 + 0x1c);
  if (iVar1 < 0x140) {
    *(int *)(param_1 + 0x1c) = iVar1 + 0x2d;
  }
  FUN_00402000("Press ENTER to start the game", 0x1e0, 0x168, 0x7d0);
  return;
}
`
const MATCHED = `// FUNCTION: 0x401000
void Player::updatePosition(int dt) {
    if (m_x < 320) { m_x = m_x + 45; }
    showMessage("Press ENTER to start the game", 480, 360, 2000);
    applyGravity(m_vy, 1234, 5678, 9012, 3456, 7890, 4321);
    table[0] = 1111; table[1] = 2222; table[2] = 3333; table[3] = 4444; table[4] = 5555;
}

// FUNCTION: 0x402000
void showMessage(const char *text, int x, int y, int ms) {
    drawText(text, x + 100, y + 200, 0xffcc00, 0.75f, 1.5e3, 0x7fff_ffff);
    playSound("Message shown on screen", 440, 880, 1760, 3520);
}
`
const CLEAN_RS = `//! Movement of the player (written from cleanroom/specs/player.md).
pub struct Body { pub x: i32, pub vy: f32 }

/// Moves the body one step; the cap comes from the spec.
pub fn advance_body(b: &mut Body, cap: i32) {
    if b.x < cap { b.x += 3; }
    b.vy = (b.vy + 0.5).min(10.0);
}

pub fn render_banner(text: &str) -> String {
    format!("[{}] {}", 7, text) // colour 0xFFFFFF is white
}

fn wrap_around(v: i32, lo: i32, hi: i32) -> i32 { if v < lo { hi } else if v > hi { lo } else { v } }
pub const LIMITS: [i32; 7] = [4096, 8192, 16384, 32768, 65535, 99999, 123_456];
pub fn tint(c: u32) -> u32 { mix(c, 0x00ff_8800, 0.375, 2.5e-3, 1_000_000, "tinted surface colour", 640) }
`
const CLEAN_CPP = `#include "body.h"
// address of the window in pixels: 0x10 from the left
static int clampSpeed(int v, int cap) {
    return v > cap ? cap : v;
}
int stepWorld(World &w) const {
    for (auto &b : w.bodies) { b.y = clampSpeed(b.y + 7, 99); }
    return w.bodies.size();
}
`

export function cleanProject (W, o = {}) {
  const rw = {
    libraries: 'libraries.json', oracle: { dir: 'build/oracle' },
    cleanroom: { thresholds: { names_min: 2, string_bytes: 20, file_min: 3 }, ...(o.cleanroom || {}) }
  }
  w(path.join(W, 'decomp.json'), L.dumps({
    game: 'Test 1.0',
    paths: { game: 'gamedir', src: 'src_matched', analysis: 'analysis', extracted: 'extracted', decoded: 'decoded' },
    binaries: [{ name: 'GAME', file: 'GAME.exe', decompiled: 'decompiled_exe', named: 'decompiled_named_exe' }],
    rewrite: rw
  }) + '\n')
  w(path.join(W, 'decompiled_exe', 'functions', '0x401000.c'), GHIDRA_FN)
  w(path.join(W, 'decompiled_exe', 'functions', 'build', 'ignored.c'), MATCHED)
  w(path.join(W, 'src_matched', 'GAME', '010_player.cpp'), MATCHED)
  w(path.join(W, 'src_matched', 'MATCHING_NOTES.md'), '# notes\n')
  w(path.join(W, 'analysis', 'GAME', 'names_apply.json'), L.dumps({ '0x401000': 'Player::updatePosition', '0x402000': 'showMessage', '0x403000': 'FUN_00403000', '0x404000': 'Physics::applyGravity', '0x405000': 'tiny' }) + '\n')
  w(path.join(W, 'analysis', 'GAME', 'names.tsv'), '0x401000\tPlayer::updatePosition\n0x402000\tshowMessage\r\nbad line\n')
  w(path.join(W, 'gamedir', 'data', 'level1.dat'), 'LEVEL DATA 1\x00\x01\x02 not code\n')
  w(path.join(W, 'gamedir', 'empty.bin'), '')
  w(path.join(W, 'extracted', 'text', 'intro.txt'), 'Welcome to the game\n')
  w(path.join(W, 'libraries.json'), L.dumps({ libraries: [{ name: 'alpha' }] }) + '\n')
  // the clean tree
  const C = path.join(W, 'rewrite', 'clean')
  w(path.join(C, 'LICENSE'), 'MIT License\n')
  w(path.join(C, 'README.md'), '# A rewrite\n\nNeeds the original game.\n')
  w(path.join(C, 'THIRD_PARTY_NOTICES.md'), 'alpha: zlib licence\n')
  w(path.join(C, 'src', 'body.rs'), CLEAN_RS)
  w(path.join(C, 'src', 'world.cpp'), CLEAN_CPP)
  w(path.join(C, 'src', 'empty.rs'), '')
  w(path.join(C, 'assets', 'icon.bin'), 'ICON\x00\x01')
  w(path.join(C, 'third_party', 'lib', 'copied.cpp'), MATCHED)   // excluded from the checks
  w(path.join(C, 'target', 'debug', 'x.rs'), MATCHED)          // excluded
  // the bad tree
  const B = path.join(W, 'rewrite', 'bad')
  w(path.join(B, 'src', 'copy.cpp'), MATCHED + '\n// 0x00401000\nvoid helper() { int iVar1 = 0; stub!(0x401000); }\n' +
    '/* a block comment\n   STUB: 0x00402000 still here */\n')
  w(path.join(B, 'src', 'copy.rs'), '// 0x00402000\nfn show_message(t: &str) { draw("Press ENTER to start the game", 480, 360, 2000, 1234, 5678, 9012); }\n' +
    'fn update_position() {}\nfn apply_gravity() {}\nfn unrelated_function() {}\nfn go() {}\n')
  const nums = Array.from({ length: 1100 }, (_, i) => String((i * 37) % 1000)).join(', ')
  const strs = Array.from({ length: 70 }, (_, i) => `"line ${i}"`).join(', ')
  w(path.join(B, 'src', 'tables.rs'), `static LEVEL: [u16; 1100] = [${nums}];\nstatic TEXT: [&str; 70] = [${strs}];\nstatic SMALL: [u8; 4] = [1, 2, 3, 4];\n`)
  w(path.join(B, 'src', 'blob.c'), 'int x;\0binary')
  w(path.join(B, 'data', 'level1.dat'), 'LEVEL DATA 1\x00\x01\x02 not code\n')
  w(path.join(B, 'data', 'empty.bin'), '')
  if (o.many) w(path.join(B, 'src', 'many.c'), Array.from({ length: 230 }, (_, i) => `int iVar${i} = ${i};`).join('\n') + '\n')
  // specs
  w(path.join(W, 'cleanroom', 'specs', 'player.md'), '# Player\n\nEach frame the vertical speed grows by 0.5, capped at 10.\n' +
    'Undefined behaviour of the original is kept.\n\n```json\n{"cap": 10}\n```\n\n| field | size |\n|---|---|\n| x | 4 |\n')
  w(path.join(W, 'cleanroom', 'specs', 'more', 'world.md'), '# World\n\nBodies wrap around at the screen edges.\n')
  w(path.join(W, 'specs_bad', 'ghidra.md'), '# Copied\n\n```c\n' + GHIDRA_FN + '```\n')
  w(path.join(W, 'specs_bad', 'untagged.md'), '# Copied\n\n```\nif (x) {\n  y = 1;\n}\nz = 2;\n```\n\n~~~text\nfoo;\nbar;\nbaz;\n~~~\n')
  w(path.join(W, 'specs_bad', 'loose.md'), '# Notes\n\n' + MATCHED.split('\n').map(l => l.trim()).join('\n'))
  w(path.join(W, 'specs_bad', 'unclosed.md'), '# x\n\n```rust\nfn a() {}\n')
  w(path.join(W, 'specs_bad', 'notes.txt'), 'call showMessage("Press ENTER to start the game", 480, 360, 2000); and applyGravity(m_vy, 1234, 5678, 9012, 3456, 7890, 4321);\n')
  w(path.join(W, '..', 'outside.md'), '# outside\n')
  fs.rmSync(path.join(W, '..', 'ws_out'), { recursive: true, force: true })
  try { fs.symlinkSync(path.join(W, 'decompiled_exe', 'functions', '0x401000.c'), path.join(W, 'cleanroom', 'link.md')) } catch {}
  if (o.log) cleanroomLog(W, o.log)
  if (o.allow) w(path.join(W, 'cleanroom', 'allow.json'), typeof o.allow === 'string' ? o.allow : L.dumps(o.allow) + '\n')
}

// a log made by the Python script (the same bytes for both sides of a case)
export function cleanroomLog (W, kind) {
  const py = process.env.PARITY_PYTHON || 'python3'
  const run = (...args) => spawnSync(py, ['-I', path.join(L.SCRIPTS, 'cleanroom.py'), ...args], { cwd: W, env: { ...process.env, SOURCE_DATE_EPOCH: EPOCH }, encoding: 'utf8' })
  run('init')
  if (kind === 'init') return
  run('pack', '--wave', 'physics', '--out', 'cleanroom/workspaces/physics', 'cleanroom/specs')
  run('record', '--wave', 'physics', '--event', 'question', '--note', 'what happens at the edge?')
  const p = path.join(W, 'cleanroom', 'log.jsonl')
  const lines = fs.readFileSync(p, 'utf8').split('\n')
  if (kind === 'tampered') fs.writeFileSync(p, lines.map((l, i) => (i === 1 ? l.replace('"physics"', '"physicz"') : l)).join('\n'))
  if (kind === 'garbage') fs.writeFileSync(p, lines[0] + '\nnot json\n[1,2]\n' + lines.slice(1).join('\n'))
  if (kind === 'noinit') fs.writeFileSync(p, lines.slice(1).join('\n'))
}
