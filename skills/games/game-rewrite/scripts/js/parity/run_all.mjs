#!/usr/bin/env node
// Parity test: runs every Python script of the skill and its JavaScript port on the same synthetic inputs
// (made-up traces and replays, a fake game behind a fake "wine", fake cl/link/lib, clang and rust-lld, tiny
// PE/COFF files: parity/fakes.mjs) and compares exit code, stdout, stderr and every file written.
//
//   node scripts/js/parity/run_all.mjs [--only NAME[,NAME]] [--python python3] [--keep] [--sync-docs]
//
// Each case runs twice in the same fresh work folder (Python first, then the JS port), so paths agree.
// Masked before comparing: timings ("seconds", "after N.N s"), timestamps ("recorded") and random temp names.
// --sync-docs copies each Python script's --help text into its port's DOC constant first (run it after
// editing a docstring). Prints one JSON summary {"script", "cases", "identical", "different", ...};
// exit 0 only when every case is identical.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import * as L from '../lib/rwlib.mjs'
import { makeFixtures, w } from './fakes.mjs'
import { CPP_CONFIG, cppProject, writePEs } from './cpp_fixtures.mjs'
import { rustProject, rustBadInputs, replaceProject } from './rust_fixtures.mjs'

const argv = process.argv.slice(2)
const opt = (k, d) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d }
const PY = opt('--python', 'python3')
const ONLY = opt('--only', null)
const KEEP = argv.includes('--keep')
const SCRIPTS = L.SCRIPTS
const JS = L.JS_DIR

const PORTS = {
  compare_traces: 'compare_traces', run_scenario: 'run_scenario', record_oracle: 'record_oracle', run_wine: 'run_wine',
  wintools: 'wintools', build_libs: 'build_libs', cpp_build: 'cpp_build', build_oracle: 'build_oracle',
  'rust_gnu/gen_defs': 'rust_gnu/gen_defs', 'rust_gnu/dlltool': 'rust_gnu/dlltool',
  'cpp/cppsplit': 'cpp/cppsplit', 'cpp/account': 'cpp/account', 'cpp/emit': 'cpp/emit', 'cpp/gen_data': 'cpp/gen_data',
  'rust/gen_skeleton': 'rust/gen_skeleton', 'rust/replace_fn': 'rust/replace_fn'
}

if (argv.includes('--sync-docs')) {
  for (const [py, js] of Object.entries(PORTS)) {
    if (py.endsWith('dlltool')) continue
    const r = spawnSync(PY, ['-I', path.join(SCRIPTS, py + '.py'), ...(py === 'wintools' ? [] : ['--help'])], { encoding: 'utf8' })
    const doc = r.stdout.replace(/\n$/, '')
    const f = path.join(JS, js + '.mjs')
    const t = fs.readFileSync(f, 'utf8')
    fs.writeFileSync(f, t.replace(/^const DOC = .*$/m, () => 'const DOC = ' + JSON.stringify(doc)))
  }
}

const T = fs.mkdtempSync(path.join(os.tmpdir(), 'rewrite_parity_'))
const FIX = path.join(T, 'fix')
const W = path.join(T, 'work')
makeFixtures(FIX, PY)
const BIN = path.join(FIX, 'bin')
const TR = path.join(FIX, 'traces')
const ENV = {
  WINE: path.join(BIN, 'wine'), WINESERVER: path.join(BIN, 'wineserver'), WINEPREFIX: path.join(T, 'prefix'),
  MSVC_SH: path.join(BIN, 'msvc.sh'), CLANG: path.join(BIN, 'clang'), RUST_LLD: path.join(BIN, 'rust-lld'),
  RUST_GNU_LLD: path.join(BIN, 'rust-lld'), FAKE_OBJ: path.join(BIN, 'template.obj'), FAKE_DLL: path.join(BIN, 'template.dll'),
  FAKE_LOG: path.join(W, 'tool.log'), DECOMP_SCRIPTS: path.join(FIX, 'decomp_scripts'), MSVC_PREFIX: path.join(T, 'vsprefix')
}

// ------------------------------------------------------------------------------------- project setups
const REWRITE = {
  exe_name: 'GAME.exe', env: { replay: 'GAME_REPLAY', trace: 'GAME_TRACE', exit_frame: 'GAME_EXIT_FRAME', fb: 'GAME_TRACE_FB' },
  args: ['-savedir', '{basedir}\\'], saves: 'saves', fps: 30,
  trace: { header: 'TEST-TRACE 1', frame_field: 'f', fields: ['gs', 'p', 'v', 'flags', 'tb', 'fb'], decode: { v: 'f32' } },
  scenarios: 'harness/scenarios', oracle: { exe: 'bin/game.exe', traces: 'harness/oracle' }, libraries: 'libraries.json'
}
const decomp = (rw, extra = {}) => w(path.join(W, 'decomp.json'), L.dumps({ game: 'Test 1.0', paths: { game: 'gamedir' }, ...extra, rewrite: rw }) + '\n')
function gameProject (rwOver = {}) {
  decomp({ ...REWRITE, trace: { header: 'TEST-TRACE 1' }, ...rwOver })
  w(path.join(W, 'gamedir', 'data', 'level1.dat'), 'level data\n')
  w(path.join(W, 'gamedir', 'readme.txt'), 'game folder\n')
  w(path.join(W, 'gamedir', 'old.trace'), 'skipped by the copy\n')
  w(path.join(W, 'bin', 'game.exe'), 'MZ fake game exe\n')
  w(path.join(W, 'harness', 'scenarios', '01_walk.txt'), '# walk right then left\n#! exit_frame=20\nTEST-REPLAY 1\n0 -\n3 right  # go\n9 right+z\n12 left\n15 -\n')
  w(path.join(W, 'harness', 'scenarios', '02_idle.txt'), '#! exit_frame=6\nTEST-REPLAY 1\n0 -\n')
  w(path.join(W, 'harness', 'scenarios', 'no_exit.txt'), 'TEST-REPLAY 1\n0 -\n')
}
function seededProject () {
  gameProject()
  w(path.join(W, 'harness', 'levels', 'test_a.lvl'), 'level a\n')
  w(path.join(W, 'harness', 'seed_progress.sav'), 'level=2\n')
  w(path.join(W, 'harness', 'scenarios', '03_seeded.txt'), '#! exit_frame=4\n#! seed=levels/test_a.lvl:../levels/test_a.lvl\n#! seed=saves/progress.sav:../seed_progress.sav\n#! arg=-level\n#! arg=test_a\nTEST-REPLAY 1\n0 right\n')
  w(path.join(W, 'harness', 'scenarios', '04_bad_seed.txt'), '#! exit_frame=4\n#! seed=levels/x.lvl:../levels/missing.lvl\nTEST-REPLAY 1\n0 -\n')
}
const LIBS = {
  defaults: { dll_syslibs: ['kernel32.lib'] },
  generate: { 'alpha_config.h': ['/* generated */', '#define ALPHA_CONFIGURED 1'] },
  libraries: [
    { name: 'alpha', version: '1.2', commit: '0123456789abcdef0123', url: 'file://' + path.join(FIX, 'archives', 'alpha-1.2.tar.gz'), sha256: 'SHA_ALPHA', lang: 'c', srcs: ['src/alpha.c', 'src/beta.c'], defines: ['ALPHA_STATIC_AND_DLL'], dll_defines: ['ALPHA_EXPORT'], incs: ['include'], dll_srcs: ['{skill}/capi/lodepng_alloc.c'], exports: ['_lib_'], headers: { 'include/alpha*.h': '', 'include/alpha.h': ['sub', 'renamed.h'] }, evidence: 'made up' },
    { name: 'flat', version: '0.1', url: 'file://' + path.join(FIX, 'archives', 'flat.tar'), lang: 'c++', srcs: ['one.c'], dll: 'flatlib.dll', lib: 'flatlib.lib' },
    { name: 'c99lib', url: 'file://' + path.join(FIX, 'archives', 'single-abc.c'), archive: 'single-abc.c', file: 'single.c', sha256: 'SHA_SINGLE', lang: 'c99', srcs: ['single.c'], exports: ['_lib_', '_other'] },
    { name: 'gamma', kind: 'prebuilt', version: '3', url: 'file://' + path.join(FIX, 'archives', 'gamma-3.zip'), sha256: '00', static_libs: ['lib/x86/gamma.lib'], dlls: ['lib/x86/gamma.dll'], include: 'include' },
    { name: 'hdr', kind: 'headers', headers: { '{src}/gamma/include/gamma.h': 'hdr' } }
  ]
}
function libsProject (state) {
  const libs = JSON.parse(JSON.stringify(LIBS))
  const sha = f => L.sha256File(path.join(FIX, 'archives', f))
  libs.libraries[0].sha256 = sha('alpha-1.2.tar.gz')
  libs.libraries[2].sha256 = sha('single-abc.c')
  w(path.join(W, 'libraries.json'), L.dumps(libs) + '\n')
  decomp({ libraries: 'libraries.json', paths: { downloads: 'tp/dl', src: 'tp/src', build: 'tp/build' } }, { toolchain: { wineprefix: '~/.wine-test' } })
  if (state === 'extracted' || state === 'fetched') {
    for (const [f, d] of [['alpha-1.2.tar.gz', 'alpha-1.2.tar.gz'], ['flat.tar', 'flat.tar'], ['single-abc.c', 'single-abc.c'], ['gamma-3.zip', 'gamma-3.zip']]) {
      w(path.join(W, 'tp', 'dl', d), fs.readFileSync(path.join(FIX, 'archives', f)))
    }
  }
  if (state === 'extracted') {
    w(path.join(W, 'tp', 'src', 'alpha', 'src', 'alpha.c'), 'int alpha;\n')
    w(path.join(W, 'tp', 'src', 'alpha', 'src', 'beta.c'), 'int beta;\n')
    w(path.join(W, 'tp', 'src', 'alpha', 'include', 'alpha.h'), '#define ALPHA 1\n')
    w(path.join(W, 'tp', 'src', 'alpha', 'include', 'alpha_extra.h'), '#define EXTRA 1\n')
    w(path.join(W, 'tp', 'src', 'flat', 'one.c'), 'int one;\n')
    w(path.join(W, 'tp', 'src', 'c99lib', 'single.c'), 'int single;\n')
    w(path.join(W, 'tp', 'src', 'gamma', 'lib', 'x86', 'gamma.lib'), 'GAMMALIB')
    w(path.join(W, 'tp', 'src', 'gamma', 'lib', 'x86', 'gamma.dll'), 'GAMMADLL')
    w(path.join(W, 'tp', 'src', 'gamma', 'include', 'gamma.h'), '#define GAMMA 3\n')
    w(path.join(W, 'src', 'main.cpp'), 'int main() { return 0; }\n')
    w(path.join(W, 'src', 'util.c'), 'int util;\n')
    w(path.join(W, 'src', 'sub', 'main.c'), 'int dup;\n')
  }
}
function oracleProject (badEdit = false) {
  decomp({
    oracle: {
      binary: 'GAME', dir: 'build/oracle', files: ['harness/hooks.h'],
      edits: badEdit ? [{ unit: '010_main.cpp', old: 'not there', new: 'x' }] : 'harness/edits.json'
    }
  }, {
    paths: { game: 'work/game', src: 'src_matched', analysis: 'analysis' },
    binaries: [{ name: 'GAME', file: 'GAME.exe', decompiled: 'decompiled_exe', matching: true },
      { name: 'helper', file: 'helper.dll', reassembled: 'reassembled/helper', matching: false }],
    toolchain: { compiler: 'msvc', flags: '/O2' }
  })
  w(path.join(W, 'src_matched', 'GAME', '010_main.cpp'), '#include "a.h"\r\nvoid poll();\r\nvoid loop() {\r\n    poll();\r\n    render();\r\n}\r\nvoid loop2() {\r\n    poll();\r\n}\r\n')
  w(path.join(W, 'src_matched', 'GAME', '020_other.cpp'), 'int other;\n')
  w(path.join(W, 'src_matched', 'GAME', 'include', 'a.h'), '#pragma once\n')
  w(path.join(W, 'harness', 'hooks.h'), '// hooks\n')
  w(path.join(W, 'harness', 'edits.json'), L.dumps([
    { unit: '010_main.cpp', desc: 'include the hooks', old: '#include "a.h"\n', new: '#include "a.h"\n#include "hooks.h"\n' },
    { unit: '010_main.cpp', desc: 'after each poll', old: 'poll();\n', new: 'poll(); hook_after_poll();\n', count: 3 }]))
  w(path.join(W, 'work', 'game', 'GAME.exe'), 'original exe\n')
  w(path.join(W, 'work', 'game', 'data', 'x.dat'), 'data\n')
  w(path.join(W, 'work', 'game', 'helper.dll'), 'dll\n')
}

// ------------------------------------------------------------------------------------------- cases
const t = n => path.join(TR, n)
const cases = []
const add = (script, name, args, o = {}) => cases.push({ script, name, args, ...o })
// compare_traces
add('compare_traces', 'identical', [t('a.trace'), t('a.trace')])
add('compare_traces', 'crlf identical', [t('a.trace'), t('a_crlf.trace')])
add('compare_traces', 'different', [t('a.trace'), t('b.trace'), '--show', '3', '--json', 'out.json'])
add('compare_traces', 'ignore fb', [t('a.trace'), t('b.trace'), '--ignore', 'fb,gs'])
add('compare_traces', 'only p,v', [t('a.trace'), t('b.trace'), '--only=p,v', '--quiet'])
add('compare_traces', 'shorter B', [t('a.trace'), t('short.trace')])
add('compare_traces', 'longer B', [t('a.trace'), t('long.trace'), '--show', '9'])
add('compare_traces', 'config decode', [t('a.trace'), t('weird_float.trace'), '--show', '5'], { setup: () => decomp(REWRITE) })
add('compare_traces', 'config field order', [t('a.trace'), t('order.trace')], { setup: () => decomp(REWRITE) })
add('compare_traces', 'config header', [t('a.trace'), t('other_header.trace')], { setup: () => decomp(REWRITE) })
add('compare_traces', 'header mismatch', [t('a.trace'), t('other_header.trace')])
add('compare_traces', 'bad frame', [t('a.trace'), t('bad_frame.trace')])
add('compare_traces', 'bad token', [t('bad_token.trace'), t('a.trace')])
add('compare_traces', 'empty', [t('empty.trace'), t('a.trace')])
add('compare_traces', 'missing file', [t('a.trace'), t('nope.trace')])
add('compare_traces', 'bad config', [t('a.trace'), t('a.trace')], { setup: () => w(path.join(W, 'decomp.json'), '{"rewrite": ') })
add('compare_traces', 'usage: missing arg', [t('a.trace')])
add('compare_traces', 'usage: bad int', [t('a.trace'), t('a.trace'), '--show', 'x'])
add('compare_traces', 'usage: unknown option', [t('a.trace'), t('a.trace'), '--bogus'])
add('compare_traces', 'usage: flag with value', [t('a.trace'), t('a.trace'), '--quiet=1'])
add('compare_traces', 'help', ['--help'])
// run_scenario
const rs = ['--exe', 'bin/game.exe', '--scenario', 'harness/scenarios/01_walk.txt', '--out', 'out/walk.trace', '--settle', '0']
add('run_scenario', 'walk + saves', [...rs, '--saves-out', 'out/saves', '--game', 'gamedir'], { setup: () => gameProject() })
add('run_scenario', 'flaky start retried', [...rs, '--saves-out', 'out/saves'], { setup: () => gameProject(), env: { FAKE_MODE: 'flaky' } })
add('run_scenario', 'no fb, args, env', [...rs, '--no-fb', '--exit-frame', '5', '--arg', '-extra', '--env', 'FAKE_EXTRA=yes'], { setup: () => gameProject() })
add('run_scenario', 'seeded files and scenario args', ['--exe', 'bin/game.exe', '--scenario', 'harness/scenarios/03_seeded.txt', '--out', 'out/seeded.trace', '--saves-out', 'out/saves', '--arg', '-extra'], { setup: () => seededProject() })
add('run_scenario', 'missing seed file', ['--exe', 'bin/game.exe', '--scenario', 'harness/scenarios/04_bad_seed.txt', '--out', 'out/x.trace'], { setup: () => seededProject() })
add('run_scenario', 'never writes a trace', [...rs, '--tries', '2', '--stall', '1'], { setup: () => gameProject(), env: { FAKE_MODE: 'never' } })
add('run_scenario', 'no exit frame', ['--exe', 'bin/game.exe', '--scenario', 'harness/scenarios/no_exit.txt', '--out', 'x.trace'], { setup: () => gameProject() })
add('run_scenario', 'usage: missing --exe', ['--scenario', 'x', '--out', 'y'])
add('run_scenario', 'help', ['-h'])
// record_oracle
add('record_oracle', 'two scenarios', ['--runs', '2', '--settle', '0', 'harness/scenarios/01_walk.txt', 'harness/scenarios/02_idle.txt'], { setup: () => gameProject() })
add('record_oracle', 'default scenarios', ['--runs', '2', '--settle', '0', '--tries', '2'], { setup: () => { gameProject(); fs.rmSync(path.join(W, 'harness', 'scenarios', 'no_exit.txt')) } })
add('record_oracle', 'not deterministic', ['--runs', '3', '--settle', '0', '--out', 'rec', 'harness/scenarios/02_idle.txt'], { setup: () => gameProject(), env: { FAKE_MODE: 'random' }, randomOut: true })
add('record_oracle', 'failing runs', ['--runs', '2', '--settle', '0', '--tries', '1', 'harness/scenarios/no_exit.txt'], { setup: () => gameProject() })
add('record_oracle', 'no exe', ['--exe', 'missing.exe'], { setup: () => gameProject() })
// run_wine
add('run_wine', 'hello ok', ['bin/game.exe', '--log', 'hello.log', '--log-out', 'out/hello.log', '--expect', 'RESULT: OK', '--extra', 'gamedir/readme.txt', '--extra-dir', 'gamedir/data', '--', 'a1', 'a2'], { setup: () => gameProject(), env: { FAKE_MODE: 'hello' } })
add('run_wine', 'hello fails twice', ['bin/game.exe', '--log', 'hello.log', '--expect', 'RESULT: OK', '--tries', '2'], { setup: () => gameProject(), env: { FAKE_MODE: 'hello', FAKE_RESULT: 'FAIL' } })
add('run_wine', 'crash without log', ['bin/game.exe', '--log', 'none.log', '--tries', '1', '--workdir', 'wd', '--keep'], { setup: () => gameProject(), env: { FAKE_MODE: 'crash' } })
add('run_wine', 'exit code only', ['bin/game.exe', '--game', 'gamedir', '--tries', '1'], { setup: () => gameProject(), env: { FAKE_MODE: 'hello' } })
// wintools
const tpl = path.join(BIN, 'template.dll')
add('wintools', 'exports', ['exports', tpl])
add('wintools', 'imports', ['imports', tpl])
add('wintools', 'externals obj', ['externals', path.join(BIN, 'template.obj')])
add('wintools', 'externals lib', ['externals', path.join(BIN, 'objs.lib'), path.join(BIN, 'template.obj')])
add('wintools', 'def stdout', ['def', tpl])
add('wintools', 'def file', ['def', tpl, 'x.def'])
add('wintools', 'usage', ['bogus', tpl])
add('wintools', 'help', [])
// gen_defs / dlltool
add('rust_gnu/gen_defs', 'new defs', [path.join(FIX, 'link_output.txt'), '--syswow64', path.join(FIX, 'syswow64'), '--defs', 'defs'],
  { setup: () => w(path.join(W, 'defs', 'kernel32.def'), 'LIBRARY kernel32.dll\nEXPORTS\n    _TlsAlloc@0 == TlsAlloc\n    _ExitProcess@4 == ExitProcess\n') })
add('rust_gnu/gen_defs', 'all known', [path.join(FIX, 'link_ok.txt'), '--syswow64', path.join(FIX, 'syswow64')])
add('rust_gnu/gen_defs', 'help', ['--help'])
add('rust_gnu/dlltool', 'import library', ['-d', path.join(FIX, 'raw.def'), '-D', 'SDL2.dll', '-l', 'libSDL2.a', '-m', 'i386', '-f', '--32', '--no-leading-underscore', '--temp-prefix', 'tmp'])
add('rust_gnu/dlltool', 'bad machine', ['-d', path.join(FIX, 'raw.def'), '-l', 'x.a', '-m', 'i386:x86-64'])
add('rust_gnu/dlltool', 'usage', ['-l', 'x.a'])
// build_libs
add('build_libs', 'list', ['list'], { setup: () => libsProject('fetched') })
add('build_libs', 'fetch', ['fetch'], { setup: () => libsProject('none') })
add('build_libs', 'fetch --check', ['fetch', '--check', '--only', 'alpha,c99lib'], { setup: () => libsProject('none') })
add('build_libs', 'extract', ['extract'], { setup: () => libsProject('fetched') })
add('build_libs', 'extract present + force', ['extract', '--force', '--only', 'gamma'], { setup: () => libsProject('extracted') })
add('build_libs', 'extract unsafe', ['extract', '--libraries', 'evil.json'], {
  setup: () => { libsProject('none'); w(path.join(W, 'evil.json'), L.dumps({ libraries: [{ name: 'evil', url: 'file://x/evil.tar.gz' }] })); w(path.join(W, 'tp', 'dl', 'evil.tar.gz'), fs.readFileSync(path.join(FIX, 'archives', 'evil.tar.gz'))) }
})
add('build_libs', 'build all', ['build', '--keep-obj'], { setup: () => libsProject('extracted') })
add('build_libs', 'build static only', ['build', '--flavour', 'static', '--only', 'alpha,gamma,hdr'], { setup: () => libsProject('extracted') })
add('build_libs', 'build dll', ['build', '--flavour=dll'], { setup: () => libsProject('extracted') })
add('build_libs', 'build: cl fails', ['build', '--flavour', 'static'], { setup: () => libsProject('extracted'), env: { FAKE_FAIL_TOOL: 'cl' } })
add('build_libs', 'build: bad flavour', ['build', '--flavour', 'arm'], { setup: () => libsProject('extracted') })
add('build_libs', 'unknown library', ['list', '--only', 'nope'], { setup: () => libsProject('none') })
add('build_libs', 'runtime', ['runtime'], { setup: () => libsProject('none') })
add('build_libs', 'no command', [])
add('build_libs', 'no libraries file', ['list'])
// cpp_build
const cb = ['--out', 'out/app.exe', 'src/main.cpp', 'src/util.c']
add('cpp_build', 'default (temp objects)', cb, { setup: () => libsProject('extracted') })
add('cpp_build', 'options', ['--obj-dir', 'obj', '--subsystem', 'windows', '--define', 'X=1', '--include', 'src', '--cflag', '/W4', '--lib', 'winmm.lib', ...cb], { setup: () => libsProject('extracted') })
add('cpp_build', 'winmain debug no libs', ['--obj-dir', 'obj', '--subsystem', 'windows', '--winmain', '--debug', '--no-default-libs', ...cb], { setup: () => libsProject('extracted') })
add('cpp_build', 'duplicate names', ['--out', 'o.exe', 'src/main.cpp', 'src/sub/main.c'], { setup: () => libsProject('extracted') })
add('cpp_build', 'link fails', ['--obj-dir', 'obj', ...cb], { setup: () => libsProject('extracted'), env: { FAKE_FAIL_TOOL: 'link' } })
add('cpp_build', 'bad subsystem', ['--subsystem', 'gui', ...cb])
add('cpp_build', 'usage: no sources', ['--out', 'x.exe'])
// build_oracle
add('build_oracle', 'prepare only', ['--prepare-only'], { setup: () => oracleProject() })
add('build_oracle', 'full (fake pipeline)', [], { setup: () => oracleProject() })
add('build_oracle', 'edit not found', ['--prepare-only'], { setup: () => oracleProject(true) })
// cpp/cppsplit
const U = n => 'src_matched/GAME/' + n
add('cpp/cppsplit', 'items, module', ['--items', '--module', 'GAME', U('001_main.cpp')], { setup: () => cppProject(W) })
add('cpp/cppsplit', 'summary, json', [U('001_main.cpp'), U('002_util.cpp'), U('003_crt.cpp'), U('include/Game.h'), '--json', 'out/split.json'], { setup: () => cppProject(W) })
add('cpp/cppsplit', 'crlf, all modules', ['--items', U('001_main.cpp')], { setup: () => cppProject(W, { crlf: true }) })
add('cpp/cppsplit', 'missing file', [U('001_main.cpp'), 'nope.cpp'], { setup: () => cppProject(W) })
add('cpp/cppsplit', 'usage: no files', [])
add('cpp/cppsplit', 'help', ['--help'])
// cpp/account
add('cpp/account', 'tree, names, map', ['--config', 'cpp.json', '--tree', 'rewrite/src', '--names', 'names.json', '--map', 'out/map.json'], { setup: () => cppProject(W) })
add('cpp/account', 'planned (no tree)', ['--config', 'cpp.json', '--names', 'names.json'], { setup: () => cppProject(W) })
add('cpp/account', 'lost function', ['--config', 'cpp.json', '--tree', 'rewrite/src'], { setup: () => cppProject(W, { lose: true }) })
add('cpp/account', 'no destination', ['--config', 'cpp.json', '--map', 'map.json'], { setup: () => cppProject(W, { cfg: { default_dest: null } }) })
add('cpp/account', 'units option', ['--config', 'cpp.json', '--units', 'src_matched/GAME', '--project', 'nowhere'], { setup: () => cppProject(W) })
add('cpp/account', 'bad config', ['--config', 'broken.json'], { setup: () => { cppProject(W); w(path.join(W, 'broken.json'), '{"units": ') } })
add('cpp/account', 'no units', ['--config', 'cpp.json', '--project', 'nowhere'], { setup: () => cppProject(W) })
add('cpp/account', 'no tree', ['--config', 'cpp.json', '--tree', 'missing'], { setup: () => cppProject(W) })
add('cpp/account', 'bad names', ['--config', 'cpp.json', '--names', 'cpp'], { setup: () => { cppProject(W); w(path.join(W, 'cpp'), 'not json') } })
add('cpp/account', 'usage: no config', ['--tree', 'x'])
// cpp/emit
add('cpp/emit', 'generate + report', ['--config', 'cpp.json', '--out', 'out/src', '--report', 'out/report.json'], { setup: () => cppProject(W) })
add('cpp/emit', 'crlf units', ['--config', 'cpp.json', '--out', 'gen'], { setup: () => cppProject(W, { crlf: true }) })
add('cpp/emit', 'unplaced function', ['--config', 'cpp.json', '--out', 'gen', '--report', 'r.json'], { setup: () => cppProject(W, { cfg: { default_dest: null } }) })
add('cpp/emit', 'constants header', ['--config', 'cpp.json', '--out', 'gen'], {
  setup: () => {
    cppProject(W, { cfg: { constants: { ...CPP_CONFIG.constants, headers: ['extra/consts.h'] }, headers: {} } })
    w(path.join(W, 'extra', 'consts.h'), '#define FLAG_SMALL (1 << 4)\nenum Mode { MODE_IDLE, MODE_RUN, MODE_JUMP };\n#define BAD (1 / 0)\n#define CAST ((int) 7 + 0x10 - 010 + \'A\')\n')
  }
})
add('cpp/emit', 'missing constants header', ['--config', 'cpp.json', '--out', 'gen'], { setup: () => cppProject(W, { cfg: { constants: { headers: ['nope.h'] } } }) })
add('cpp/emit', 'missing shared header', ['--config', 'cpp.json', '--out', 'gen'], { setup: () => cppProject(W, { cfg: { headers: { 'include/Nope.h': 'x/Nope.h' } } }) })
add('cpp/emit', 'bad config', ['--config', 'nope.json', '--out', 'gen'])
add('cpp/emit', 'usage: no --out', ['--config', 'cpp.json'])
add('cpp/emit', 'help', ['-h'])
// cpp/gen_data
add('cpp/gen_data', 'all types, stdout', ['--config', 'data.json'], { setup: () => writePEs(W) })
add('cpp/gen_data', 'to a file', ['--config', 'data.json', '--out', 'out/tables.inc'], { setup: () => writePEs(W) })
add('cpp/gen_data', 'only', ['--config', 'data.json', '--only', 'zeros,names'], { setup: () => writePEs(W) })
add('cpp/gen_data', 'only: no such item', ['--config', 'data.json', '--only', 'nope'], { setup: () => writePEs(W) })
add('cpp/gen_data', 'PE32+, data section', ['--config', 'data64.json'], { setup: () => writePEs(W) })
add('cpp/gen_data', 'not a PE', ['--config', 'data.json', '--pe', 'game/notpe.exe'], { setup: () => writePEs(W) })
add('cpp/gen_data', 'missing exe', ['--config', 'data.json', '--pe', 'game/none.exe'], { setup: () => writePEs(W) })
add('cpp/gen_data', 'no exe in config', ['--config', 'empty.json'], { setup: () => { writePEs(W); w(path.join(W, 'empty.json'), '{"items": []}') } })
add('cpp/gen_data', 'bad config', ['--config', 'missing.json'])
for (const b of ['bad_addr', 'bad_range', 'bad_type', 'bad_format', 'bad_key', 'bad_number', 'bad_nan', 'bad_struct', 'bad_perline']) {
  add('cpp/gen_data', b, ['--config', b + '.json'], { setup: () => writePEs(W) })
}
add('cpp/gen_data', 'help', ['--help'])
// rust/gen_skeleton
const GU = ['index', '--units', 'src_matched/GAME']
add('rust/gen_skeleton', 'index from units', [...GU, '--cpp-config', 'cpp.json', '--names', 'names.json', '--headers', 'src_matched/GAME/include', '--out', 'out/index.json'], { setup: () => cppProject(W) })
add('rust/gen_skeleton', 'index: module option, crlf', [...GU, '--module', 'GAME', '--out', 'idx.json'], { setup: () => cppProject(W, { crlf: true }) })
add('rust/gen_skeleton', 'index: no units folder', ['index', '--units', 'nope', '--out', 'x.json'])
add('rust/gen_skeleton', 'index: missing --out', GU, { setup: () => cppProject(W) })
add('rust/gen_skeleton', 'index: bad names', [...GU, '--names', 'bad.json', '--out', 'x.json'], { setup: () => { cppProject(W); rustBadInputs(W) } })
add('rust/gen_skeleton', 'index: bad cpp config', [...GU, '--cpp-config', 'bad.json', '--out', 'x.json'], { setup: () => { cppProject(W); rustBadInputs(W) } })
add('rust/gen_skeleton', 'index: no headers folder', [...GU, '--headers', 'nope', '--out', 'x.json'], { setup: () => cppProject(W) })
const GG = ['generate', '--config', 'rust.json', '--index', 'rindex.json', '--crate', 'crate']
add('rust/gen_skeleton', 'generate: new crate', GG, { setup: () => rustProject(W) })
add('rust/gen_skeleton', 'generate: hand edits kept', [...GG, '--names-out', 'out/names.tsv'], { setup: () => rustProject(W, { crate: true, removeOne: true }) })
add('rust/gen_skeleton', 'generate: dry run', [...GG, '--dry-run'], { setup: () => rustProject(W, { crate: true }) })
add('rust/gen_skeleton', 'generate: cx all, no statics', GG, { setup: () => rustProject(W, { cfg: { cx: { mode: 'all' }, statics: null } }) })
add('rust/gen_skeleton', 'generate: cx none', GG, { setup: () => rustProject(W, { cfg: { cx: { mode: 'none' } } }) })
add('rust/gen_skeleton', 'generate: methods always', GG, { setup: () => rustProject(W, { cfg: { cx: { mode: 'analyse', methods: 'always', state: ['world\\.'] } } }) })
add('rust/gen_skeleton', 'generate: list index, empty config', ['generate', '--config', 'empty.json', '--index', 'list.json', '--crate', 'c2'], { setup: () => rustBadInputs(W) })
add('rust/gen_skeleton', 'generate: bad config', ['generate', '--config', 'bad.json', '--index', 'list.json', '--crate', 'c'], { setup: () => rustBadInputs(W) })
add('rust/gen_skeleton', 'generate: bad regex', ['generate', '--config', 'badrx.json', '--index', 'list.json', '--crate', 'c'], { setup: () => rustBadInputs(W) })
add('rust/gen_skeleton', 'generate: bad cx regex', GG, { setup: () => rustProject(W, { cfg: { cx: { mode: 'analyse', state: ['(open'] } } }) })
add('rust/gen_skeleton', 'generate: bad skip_globals regex', GG, { setup: () => rustProject(W, { cfg: { skip_globals: { names: ['[x'] } } }) })
add('rust/gen_skeleton', 'generate: index entry without address', ['generate', '--config', 'empty.json', '--index', 'badidx.json', '--crate', 'c'], { setup: () => rustBadInputs(W) })
add('rust/gen_skeleton', 'generate: bad globals', ['generate', '--config', 'empty.json', '--index', 'badglob.json', '--crate', 'c'], { setup: () => rustBadInputs(W) })
add('rust/gen_skeleton', 'generate: bad manifest', ['generate', '--config', 'empty.json', '--index', 'list.json', '--crate', 'badman'], { setup: () => rustBadInputs(W) })
add('rust/gen_skeleton', 'generate: missing index', ['generate', '--config', 'empty.json', '--index', 'nope.json', '--crate', 'c'], { setup: () => rustBadInputs(W) })
add('rust/gen_skeleton', 'generate: missing options', ['generate', '--config', 'empty.json'])
add('rust/gen_skeleton', 'unknown command', ['build'])
add('rust/gen_skeleton', 'usage: no command', [])
add('rust/gen_skeleton', 'help', ['--help'])
// rust/replace_fn
add('rust/replace_fn', 'replace (impl, re-indent, duplicates, missing)', ['src/m.rs', 'new.rs'], { setup: () => replaceProject(W) })
add('rust/replace_fn', 'crlf target', ['src/m.rs', 'new.rs'], { setup: () => replaceProject(W, { crlf: true }) })
add('rust/replace_fn', 'dry run', ['src/m.rs', 'new.rs', '--dry-run'], { setup: () => replaceProject(W) })
add('rust/replace_fn', 'one block', ['src/m.rs', 'one.rs'], { setup: () => replaceProject(W) })
add('rust/replace_fn', 'no address lines', ['src/m.rs', 'none.rs'], { setup: () => replaceProject(W) })
add('rust/replace_fn', 'missing target', ['nope.rs', 'new.rs'], { setup: () => replaceProject(W) })
add('rust/replace_fn', 'usage', ['src/m.rs'])
add('rust/replace_fn', 'help', ['-h'])

// ------------------------------------------------------------------------------------------ running
const MASKS = [
  [/("seconds": )(\[[^\]]*\]|[0-9.]+)/g, '$1<t>'], [/after [0-9]+\.[0-9] s/g, 'after <t> s'],
  [/"recorded": "[^"]*"/g, '"recorded": "<time>"'], [/\.obj-[A-Za-z0-9_]+/g, '.obj-<tmp>'],
  [/rewrite_(run|wine|record)_[A-Za-z0-9_]+/g, 'rewrite_$1_<tmp>']
]
const mask = s => MASKS.reduce((acc, [re, r]) => acc.replace(re, r), s)
function snapshot (dir) {
  const files = new Map()
  const walk = rel => {
    for (const n of fs.readdirSync(path.join(dir, rel)).sort(L.cmp)) {
      const r = rel ? rel + '/' + n : n
      const st = fs.lstatSync(path.join(dir, r))
      if (st.isDirectory()) { files.set(r + '/', 'dir'); walk(r) } else {
        const b = fs.readFileSync(path.join(dir, r))
        files.set(r, /\.(json|log|txt|trace|def|h|cpp|inc|md|rs|tsv)$/.test(n) ? mask(b.toString('utf8')) : b.toString('base64'))
      }
    }
  }
  walk('')
  return files
}
function runSide (c, side) {
  fs.rmSync(W, { recursive: true, force: true })
  fs.mkdirSync(W, { recursive: true })
  if (c.setup) c.setup()
  const cmd = side === 'py' ? [PY, '-I', path.join(SCRIPTS, c.script + '.py')] : [process.execPath, path.join(JS, PORTS[c.script] + '.mjs')]
  const t0 = Date.now()
  const r = spawnSync(cmd[0], [...cmd.slice(1), ...c.args], { cwd: W, env: { ...process.env, ...ENV, ...(c.env || {}) }, encoding: 'utf8', maxBuffer: 1 << 28 })
  const files = snapshot(W)
  if (c.randomOut) for (const k of [...files.keys()]) if (/\.(trace|json)$/.test(k)) files.set(k, '<random>')
  return { rc: r.status, stdout: c.randomOut ? mask(r.stdout).replace(/"(trace_sha256|first_diff_frame)": [^\n]*/g, '"$1": <random>') : mask(r.stdout), stderr: mask(r.stderr), files, ms: Date.now() - t0 }
}
const results = []; let pyMs = 0; let jsMs = 0
for (const c of cases) {
  if (ONLY && !ONLY.split(',').includes(c.script.replace(/^(rust_gnu|cpp|rust)\//, ''))) continue
  const p = runSide(c, 'py'); const j = runSide(c, 'js')
  pyMs += p.ms; jsMs += j.ms
  const diffs = []
  if (p.rc !== j.rc) diffs.push(`exit ${p.rc} vs ${j.rc}`)
  if (p.stdout !== j.stdout) diffs.push('stdout')
  if (p.stderr !== j.stderr) diffs.push('stderr')
  for (const k of new Set([...p.files.keys(), ...j.files.keys()])) if (p.files.get(k) !== j.files.get(k)) diffs.push('file ' + k)
  results.push({ script: c.script, name: c.name, rc: p.rc, diffs })
  if (process.env.PARITY_SHOW && c.name.includes(process.env.PARITY_SHOW)) {
    process.stderr.write(`=== ${c.script}: ${c.name} (python side)\n${p.stdout}${p.stderr}\n`)
  }
  if (diffs.length || process.env.PARITY_VERBOSE) {
    process.stderr.write(`${diffs.length ? 'DIFF' : 'ok  '} rc=${p.rc} ${c.script}: ${c.name}${diffs.length ? ' -> ' + diffs.join(', ') : ''}\n`)
    if (diffs.length && process.env.PARITY_VERBOSE) {
      if (diffs.includes('stdout')) process.stderr.write(`--- py stdout\n${p.stdout}\n--- js stdout\n${j.stdout}\n`)
      if (diffs.includes('stderr')) process.stderr.write(`--- py stderr\n${p.stderr}\n--- js stderr\n${j.stderr}\n`)
      for (const d of diffs.filter(x => x.startsWith('file '))) process.stderr.write(`--- ${d}\npy: ${String(p.files.get(d.slice(5))).slice(0, 2000)}\njs: ${String(j.files.get(d.slice(5))).slice(0, 2000)}\n`)
    }
  }
}
if (!KEEP) fs.rmSync(T, { recursive: true, force: true })
const different = results.filter(r => r.diffs.length).map(r => `${r.script}: ${r.name} (${r.diffs.join(', ')})`)
const scripts = [...new Set(results.map(r => r.script))]
process.stdout.write(L.dumps(new Map([['script', 'run_all'], ['scripts', scripts.length], ['cases', results.length],
  ['identical', results.length - different.length], ['different', different],
  ['exit_codes_seen', [...new Set(results.map(r => r.rc))].sort((a, b) => a - b)],
  ['python_seconds', L.round1(pyMs / 1000)], ['js_seconds', L.round1(jsMs / 1000)], ['kept', KEEP ? T : null]])) + '\n')
process.exitCode = different.length ? 1 : 0
