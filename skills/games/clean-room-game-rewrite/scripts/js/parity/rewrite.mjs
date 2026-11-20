#!/usr/bin/env node
// Parity test for the rewrite-side scripts (run_all.mjs runs it with the others): runs each Python script
// and its JavaScript port on the same synthetic inputs
// (made-up traces and replays, a fake game behind a fake "wine", fake cl/link/lib, clang and rust-lld, tiny
// PE/COFF files: parity/fakes.mjs) and compares exit code, stdout, stderr and every file written.
//
//   node scripts/js/parity/rewrite.mjs [--only NAME[,NAME]] [--python python3] [--keep] [--sync-docs]
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
import { cleanProject, EPOCH } from './clean_fixtures.mjs'

const argv = process.argv.slice(2)
const opt = (k, d) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d }
const PY = opt('--python', 'python3')
process.env.PARITY_PYTHON = PY
const ONLY = opt('--only', null)
const KEEP = argv.includes('--keep')
const SCRIPTS = L.SCRIPTS
const JS = L.JS_DIR

const PORTS = {
  compare_traces: 'compare_traces', run_scenario: 'run_scenario', record_oracle: 'record_oracle', run_wine: 'run_wine',
  wintools: 'wintools', build_libs: 'build_libs', cpp_build: 'cpp_build',
  'rust_gnu/gen_defs': 'rust_gnu/gen_defs', 'rust_gnu/dlltool': 'rust_gnu/dlltool',
  cleanroom: 'cleanroom', release_check: 'release_check'
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
  FAKE_LOG: path.join(W, 'tool.log'), MSVC_PREFIX: path.join(T, 'vsprefix')
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
add('wintools', 'proxy stdout', ['proxy', tpl, 'template_orig'])
add('wintools', 'proxy file, hooks', ['proxy', tpl, 'template_orig', '--hook', 'lib_init,', 'x.def'])
add('wintools', 'proxy: hook not exported', ['proxy', tpl, 'orig', '--hook', 'nope,lib_init'])
add('wintools', 'proxy: --hook without value', ['proxy', tpl, 'orig', '--hook'])
add('wintools', 'proxy: missing target', ['proxy', tpl])
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
// cleanroom
const CE = { env: { SOURCE_DATE_EPOCH: EPOCH } }
const cr = (name, args, o = {}) => add('cleanroom', name, args, { ...CE, setup: () => cleanProject(W, o) })
for (const [n, a] of [['no command', []], ['help', ['-h']], ['unknown', ['bogus']], ['sub help', ['pack', '--help']],
  ['init extra arg', ['init', 'x']], ['pack: missing --out', ['pack', '--wave', 'w']], ['record: missing --event', ['record', '--wave', 'w']],
  ['bad option', ['verify', '--bogus']]]) cr('usage: ' + n, a)
cr('init', ['init'])
cr('init twice', ['init'], { log: 'init' })
cr('init: custom dir and log', ['init'], { cleanroom: { dir: 'cr', log: 'cr/history/log.jsonl', specs: 'cr/s' } })
cr('verify: no log', ['verify'])
cr('verify: intact', ['verify'], { log: 'full' })
cr('verify: tampered line', ['verify'], { log: 'tampered' })
cr('verify: garbage lines', ['verify'], { log: 'garbage' })
cr('verify: no init', ['verify'], { log: 'noinit' })
cr('lint: clean specs', ['lint', 'cleanroom/specs/player.md', 'cleanroom/specs/more/world.md'])
cr('lint: bad specs', ['lint', 'specs_bad/ghidra.md', 'specs_bad/untagged.md', 'specs_bad/loose.md', 'specs_bad/unclosed.md', 'specs_bad/notes.txt', '--json', 'lint.json'])
cr('lint: no files', ['lint'])
cr('lint: missing file', ['lint', 'nope.md'])
cr('lint: folder', ['lint', 'cleanroom/specs'])
cr('lint: thresholds', ['lint', 'specs_bad/loose.md', 'specs_bad/notes.txt'], { cleanroom: { thresholds: { spec_overlap: 1000, spec_code_lines: 1000 } } })
cr('pack: no log', ['pack', '--wave', 'w', '--out', 'ws', 'cleanroom/specs'])
cr('pack: folder and file', ['pack', '--wave', 'physics', '--out', 'ws/physics', '--note', 'first wave, "quoted" é', 'cleanroom/specs', 'gamedir/data/level1.dat', 'cleanroom/specs/player.md'], { log: 'init' })
cr('pack: out outside the project', ['pack', '--wave', 'w', '--out', '../ws_out', 'cleanroom/specs/player.md'], { log: 'init' })
cr('pack: forbidden inputs', ['pack', '--wave', 'w', '--out', 'ws', 'cleanroom/specs', 'src_matched/MATCHING_NOTES.md', 'decompiled_exe', 'analysis/GAME/names.tsv', 'build/oracle'], { log: 'init' })
cr('pack: failing lint', ['pack', '--wave', 'w', '--out', 'ws', 'specs_bad'], { log: 'init' })
cr('pack: outside and symlink', ['pack', '--wave', 'w', '--out', 'ws', '../outside.md', 'cleanroom/link.md'], { log: 'init' })
cr('pack: missing input', ['pack', '--wave', 'w', '--out', 'ws', 'nope.md'], { log: 'init' })
cr('pack: no inputs', ['pack', '--wave', 'w', '--out', 'ws'], { log: 'init' })
cr('pack: out not empty', ['pack', '--wave', 'w', '--out', 'cleanroom', 'cleanroom/specs'], { log: 'init' })
cr('pack: out in forbidden area', ['pack', '--wave', 'w', '--out', 'src_matched/ws', 'cleanroom/specs'], { log: 'init' })
cr('pack: custom forbidden', ['pack', '--wave', 'w', '--out', 'ws', 'cleanroom/specs', 'gamedir'], { log: 'init', cleanroom: { forbidden: ['game*', '**/*.md'] } })
cr('record: question with files', ['record', '--wave', 'physics', '--event', 'answer', '--note', 'see the spec', 'cleanroom/specs/more'], { log: 'full' })
cr('record: no files', ['record', '--wave', 'physics', '--event', 'handoff'], { log: 'full' })
cr('record: reserved event', ['record', '--wave', 'w', '--event', 'pack'], { log: 'full' })
cr('record: bad event', ['record', '--wave', 'w', '--event', 'Ask!'], { log: 'full' })
cr('record: refused file', ['record', '--wave', 'w', '--event', 'answer', 'specs_bad/ghidra.md'], { log: 'full' })
cr('record: no log', ['record', '--wave', 'w', '--event', 'answer'])
// release_check
const rc = (name, args, o = {}) => add('release_check', name, args, { ...CE, setup: () => cleanProject(W, o) })
rc('clean tree passes', [], { log: 'full' })
rc('clean tree, json and quiet', ['--json', 'report.json', '--quiet'], { log: 'full' })
rc('clean tree without log', [])
rc('clean tree, tampered log', [], { log: 'tampered' })
rc('clean tree, log without pack', [], { log: 'init' })
rc('clean tree, log not required', [], { cleanroom: { require_log: false } })
rc('bad tree fails every check', ['rewrite/bad'], { log: 'full' })
rc('bad tree, more than 200 findings', ['rewrite/bad'], { log: 'full', many: true })
rc('bad tree, names from TSV', ['rewrite/bad'], { log: 'full', cleanroom: { names: ['analysis/GAME/names.tsv'] } })
rc('bad tree, allow-list', ['rewrite/bad', '--quiet'], {
  log: 'full',
  allow: { findings: [{ check: 'assets', file: 'rewrite/bad/data/level1.dat', reason: 'our own test level' },
    { check: 'tables', file: 'rewrite/bad/src/tables.rs', line: 2, reason: 'generated fonts' },
    { check: 'tables', file: 'rewrite/bad/src/tables.rs', line: 99, reason: 'wrong line: not applied' }]
  }
})
rc('allow-list without reason', ['rewrite/bad'], { allow: { findings: [{ check: 'assets', file: 'x', reason: ' ' }] } })
rc('allow-list not JSON', ['rewrite/bad'], { allow: '{not json' })
rc('allow-list wrong shape', ['rewrite/bad'], { allow: { items: [] } })
rc('names file not JSON', [], { cleanroom: { names: ['libraries.json', 'gamedir/data/level1.dat.json'] }, log: 'full' })
rc('custom thresholds and excludes', ['rewrite/bad'], { log: 'full', cleanroom: { thresholds: { code_pct: 100, const_pct: 100, file_pct: 100, table_items: 2000, string_items: 100, string_bytes: 100000, names_pct: 100 }, tree_exclude: ['data/**', 'src/copy.*'] } })
rc('no reference', [], { log: 'full', cleanroom: { reference: ['nowhere', 'also/missing'] } })
rc('tree in a forbidden area', ['src_matched'], { log: 'full' })
rc('tree is a file', ['libraries.json'])
rc('tree outside the project', ['..'])
rc('missing tree', ['nope'])
rc('default tree missing', [], { cleanroom: { tree: 'rewrite/none' } })
rc('help', ['--help'])
rc('unknown option', ['--bogus'])

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
  if (ONLY && !ONLY.split(',').includes(c.script.replace(/^rust_gnu\//, ''))) continue
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
process.stdout.write(L.dumps(new Map([['script', 'rewrite'], ['scripts', scripts.length], ['cases', results.length],
  ['identical', results.length - different.length], ['different', different],
  ['exit_codes_seen', [...new Set(results.map(r => r.rc))].sort((a, b) => a - b)],
  ['python_seconds', L.round1(pyMs / 1000)], ['js_seconds', L.round1(jsMs / 1000)], ['kept', KEEP ? T : null]])) + '\n')
process.exitCode = different.length ? 1 : 0
