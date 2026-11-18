// Synthetic inputs for the parity cases of scripts/rust (a made-up function index with classes, namespaces,
// globals and bodies, a gen_skeleton config that uses every key, Rust files for replace_fn). Nothing here
// comes from a game.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { w } from './fakes.mjs'

const fn = (address, name, signature, unit, extra = {}) => ({ address, name, signature, unit, body: '', ...extra })

export const RUST_INDEX = {
  functions: [
    fn('0x401000', 'World::World', 'World::World()', '010_401000_world', { class: 'World', body: '{ count = 0; }' }),
    fn('0x401040', 'World::step', 'void World::step(int frames, float dt = 1.0f)', '010_401000_world', { class: 'World', body: '{ count += frames; tick(); }' }),
    fn('0x401080', 'World::lookup', 'int World::lookup(const char* name) const', '010_401000_world', { class: 'World', body: '{ return 0; }' }),
    fn('0x4010c0', 'World::draw', 'void World::draw(Renderer& r, const Rect* clip, std::vector<Ent>& ents)', '011_4010c0_world_render', { class: 'World', body: '{ if (clip == NULL) return; r.go(); }' }),
    fn('0x401100', 'Ent::Ent', 'Ent::Ent(int kind)', '012_401100_ent', { class: 'Ent', body: '{ this->kind = kind; }' }),
    fn('0x401140', 'Ent::move', 'bool Ent::move(int dx, int dy)', '012_401100_ent', { class: 'Ent', body: '{ x += dx; y += dy; return true; }' }),
    fn('0x401180', 'Ent::speed', 'float Ent::speed() const', '012_401100_ent', { class: 'Ent', body: '{ return vx; }' }),
    fn('0x4011c0', 'Ent::~Ent', 'Ent::~Ent()', '012_401100_ent', { class: 'Ent' }),
    fn('0x401200', 'Rect::Rect', 'Rect::Rect()', '013_401200_util', { class: 'Rect' }),
    fn('0x401240', 'Rect::area', 'int Rect::area() const', '013_401200_util', { class: 'Rect', body: '{ return w * h; }' }),
    fn('0x401280', 'Tower::scroll', 'void Tower::scroll(int by)', '014_401280_world', { class: 'Tower', body: '{ pos += by; }' }),
    fn('0x4012c0', 'text::print', 'void text::print(int x, int y, const std::string& s, unsigned char r = 255)', '015_4012c0_text', { class: null, namespace: 'text', body: '{ font_draw(x, y); }' }),
    fn('0x401300', 'text::measure', 'int text::measure(const char* s, int* out_w, int* out_h)', '015_4012c0_text', { class: null, namespace: 'text', body: '{ if (out_h) *out_h = 8; return 0; }' }),
    fn('0x401340', 'FS_readFile', 'bool FS_readFile(const char* path, unsigned char** mem, size_t* len)', '016_401340_file', { body: '{ return g_fsInited; }' }),
    fn('0x401380', 'FS_getPath', 'void FS_getPath(char* buffer, size_t buffer_size)', '016_401340_file', { body: '{ buffer[0] = 0; }' }),
    fn('0x4013c0', 'FS_list', 'const char* FS_list(char names[], int count)', '016_401340_file', { body: '{ return NULL; }' }),
    fn('0x401400', 'font_draw', 'void font_draw(int x, int y)', '015_4012c0_text', { body: '{ world.count++; }' }),
    fn('0x401440', 'tick', 'static void tick(void)', '010_401000_world', { body: '{ font_draw(0, 0); }' }),
    fn('0x401480', 'pure_math', 'int __cdecl pure_math(int a, int b)', '017_401480_math', { body: '{ return a * b + rand(); }' }),
    fn('0x4014c0', 'vlog_info', 'void vlog_info(const char* fmt, ...)', '018_4014c0_log', { body: '{ }' }),
    fn('0x401500', 'ui_button_textbox_translate', 'void ui_button_textbox_translate(Ent* e)', '019_401500_ui', { body: '{ e->kind = 1; }' }),
    fn('0x401540', 'make_mode', 'Mode make_mode(Mode m, int (*cb)(int), Mode** out)', '019_401500_ui', { body: '{ return m; }' }),
    fn('0x401580', 'std::vector<int>::push_back', 'void std::vector<int>::push_back(const int& v)', '020_401580_crt', { class: 'std::vector<int>' }),
    fn('0x4015c0', 'dynamic_initializer_for_world', null, '010_401000_world', { code: 'variable' }),
    fn('0x401600', '', null, '010_401000_world', { code: 'none' }),
    fn('0x401640', 'random_float', 'float random_float()', '017_401480_math', { body: '{ return rand() / 32767.0f; }' }),
    fn('0x401680', 'step', 'void step()', '021_401680_misc', { body: '{ }' }),
    fn('0x4016c0', 'Other::step', 'void Other::step()', '021_401680_misc', { class: 'Other', body: '{ }' }),
    fn('0x401700', 'helper', 'Ent* helper(World& w, void* data, const void* src, std::map<std::string, int> m, std::vector<Unknown> v)', '021_401680_misc', { body: '{ return 0; }' }),
    fn('0x401740', 'renamed_one', 'int renamed_one(bool flag)', '021_401680_misc', { body: '{ return flag; }' }),
    fn('0x401780', 'moved_by_address', 'void moved_by_address(std::string& out, std::string* maybe)', '021_401680_misc', { body: '{ if (!maybe) return; }' }),
    fn('0x4017c0', 'Ent::move', 'bool Ent::move(int dx)', '012_401100_ent', { class: 'Ent', body: '{ return move(dx, 0); }' }),
    fn('0x401800', 'counter_get', 'int counter_get()', '022_401800_counter', { body: '{ return s_counter; }' }),
    fn('0X401840', 'World::reset', 'void World::reset() throw()', '010_401000_world', { class: 'World', body: '{ }' })
  ],
  globals: [
    { address: '0x500000', name: 'g_fsInited', type: 'bool', dims: [], init: '', unit: '016_401340_file', namespace: null, static: false },
    { address: '0x500004', name: 'g_path', type: 'char', dims: ['MAX_PATH'], init: '', unit: '016_401340_file', namespace: null, static: true },
    { address: '0x500108', name: 'g_grid', type: 'short', dims: ['ROWS', 'COLS * 2'], init: '', unit: '010_401000_world', namespace: null, static: false },
    { address: '0x500200', name: 'g_small', type: 'int', dims: ['4'], init: '{1, 2, 3, 4}', unit: '010_401000_world', namespace: null, static: false },
    { address: null, name: 'g_names', type: 'std::string', dims: ['3'], init: '', unit: '015_4012c0_text', namespace: 'text', static: false },
    { address: '0x500300', name: 'g_big', type: 'Ent', dims: ['300'], init: '', unit: '012_401100_ent', namespace: null, static: false },
    { address: '0x500400', name: 'g_bad', type: 'Mystery*', dims: [], init: '', unit: '012_401100_ent', namespace: null, static: false },
    { address: '0x500404', name: 'g_baddim', type: 'int', dims: ['UNKNOWN_N'], init: '', unit: '012_401100_ent', namespace: null, static: false },
    { address: '0x500408', name: 'World::instances', type: 'int', dims: [], init: '0', unit: '010_401000_world', namespace: null, static: false },
    { address: '0x50040c', name: 's_counter', type: 'int', dims: [], init: '', unit: '022_401800_counter', namespace: null, static: true },
    { address: '0x500410', name: 'world', type: 'World', dims: [], init: '', unit: '010_401000_world', namespace: null, static: false },
    { address: '0x500414', name: 'g_label', type: 'const char*', dims: [], init: '"a very long initialiser that goes on and on and on"', unit: '021_401680_misc', namespace: null, static: false },
    { address: '0x500418', name: 'g_mode', type: 'Mode', dims: [], init: '', unit: '019_401500_ui', namespace: null, static: false },
    { address: '0x50041c', name: 'g_mode', type: 'float', dims: ['(8 + 2) / 3', '7 % 4'], init: '', unit: '019_401500_ui', namespace: null, static: true },
    { address: '0x500420', name: 'g_floaty', type: 'int', dims: ['FLOATY'], init: '', unit: '099_401900_gone', namespace: null, static: false },
    { address: '0x500424', name: 'g_floaty2', type: 'int', dims: ['FLOATY - 1'], init: '', unit: '021_401680_misc', namespace: null, static: false },
    { address: '0x500428', name: 'g_neg', type: 'int', dims: ['-(3 - 1) * 2', '(1'], init: '', unit: '021_401680_misc', namespace: null, static: false },
    { address: '0x50042c', name: 'g_div0', type: 'char', dims: ['8 / 0'], init: '', unit: '021_401680_misc', namespace: null, static: false },
    { address: '0x500430', name: 'g_vec', type: 'std::vector<std::map<int, std::string> >', dims: [], init: '', unit: '021_401680_misc', namespace: null, static: false }
  ],
  classes: { World: ['count', 'tower'], Ent: ['kind', 'x', 'y', 'vx'], Tower: ['pos'] }
}

export const RUST_CONFIG = {
  default_module: 'app',
  modules: { app: 'everything else', world: 'class World', entity: 'class Ent', text: 'namespace text' },
  skip: [
    { units: ['_crt$'], reason: 'runtime library' },
    { names: ['^dynamic_initializer_for_'], reason: 'static initializer' },
    { bases: ['area'], reason: 'inlined everywhere' }
  ],
  handwritten: { '0x401640': 'maths::random_float' },
  rename: { '0x401740': 'renamed_two' },
  classes: {
    World: { rust: 'World', module: 'world', role: 'singleton', files: [['_render$', 'render'], ['.', 'world']] },
    Tower: { rust: 'Tower', module: 'world', role: 'subobject', prefix: 'tower_', file: 'tower' },
    Ent: { rust: 'Ent', module: 'entity', role: 'element', file: 'ent' },
    Rect: { module: 'util' },
    Renderer: { rust: 'Renderer' }
  },
  namespaces: { text: 'text' },
  names: { font_draw: 'text/font' },
  name_patterns: [['_textbox_translate$', 'ui/textboxes']],
  prefixes: [['FS_', 'filesystem', true], ['vlog_', 'log', false]],
  addresses: { '0x401780': 'misc/moved' },
  units: [['_math$', 'maths'], ['_misc$', 'misc'], ['_ui$', 'ui']],
  module_files: { misc: [['^021_', 'misc_a'], ['.', 'misc']] },
  cx: {
    type: 'Ctx', name: 'ctx', mode: 'analyse', methods: 'analyse',
    state: ['(?<![\\w.>:])world\\s*(?:\\.|->)'], globals: true, global_min_len: 5, ignore_globals: ['g_names'],
    pure: ['tick'], needs: ['pure_math']
  },
  skip_globals: { names: ['^text::g_names$'], units: ['^099_'] },
  global_modules: { g_small: 'maths' },
  types: { Uint8: 'u8', 'Renderer&': 'RendererSel' },
  param_types: { 'unsigned char**': '&mut Option<Vec<u8>>' },
  return_types: { 'Ent*': 'Option<usize>' },
  drop_params: { 'World&': 'the global world: ctx.world' },
  enums: { Mode: 'Mode' },
  varargs: '&[Arg]',
  constants: { MAX_PATH: 260, ROWS: 40, COLS: 30, FLOATY: 1.5 },
  imports: ['use crate::ctx::Ctx;', 'use crate::stub;'],
  statics: 'src/state/statics.rs',
  keep: ['src/maths.rs']
}

function writeIndexConfig (W, cfgOver = {}) {
  w(path.join(W, 'rindex.json'), JSON.stringify(RUST_INDEX, null, 1) + '\n')
  w(path.join(W, 'rust.json'), JSON.stringify({ ...RUST_CONFIG, ...cfgOver }, null, 1) + '\n')
}

export function rustProject (W, opts = {}) {
  if (opts.crate) {
    // a crate generated once (by the JS port: deterministic) with an older config, then edited by hand
    writeIndexConfig(W, { modules: { ...RUST_CONFIG.modules, world: 'old description' } })
    const gen = path.join(path.dirname(path.dirname(new URL(import.meta.url).pathname)), 'rust', 'gen_skeleton.mjs')
    spawnSync(process.execPath, [gen, 'generate', '--config', 'rust.json', '--index', 'rindex.json', '--crate', 'crate'], { cwd: W })
    w(path.join(W, 'crate', 'src', 'text', 'text.rs'), '// translated by hand\n')
    w(path.join(W, 'crate', 'src', 'main.rs'), 'fn main() {}\n')
    w(path.join(W, 'crate', 'src', 'maths.rs'), '// kept by the config\n')
    const man = path.join(W, 'crate', '.gen_skeleton.json')
    const m = JSON.parse(fs.readFileSync(man, 'utf8'))
    delete m.files['src/log.rs']
    w(man, JSON.stringify(m, null, 1) + '\n')
    w(path.join(W, 'crate', 'src', 'log.rs'), '// written by hand, not in the manifest\n// 0x4014c0\npub fn vlog_info() {}\n')
    fs.rmSync(path.join(W, 'crate', 'src', 'filesystem.rs'))
    if (opts.removeOne) w(path.join(W, 'crate', 'src', 'ui', 'mod.rs'), '')
  }
  writeIndexConfig(W, opts.cfg)
}

export function rustBadInputs (W) {
  w(path.join(W, 'bad.json'), '{"modules": ')
  w(path.join(W, 'badrx.json'), JSON.stringify({ units: [['(unclosed', 'x']] }))
  w(path.join(W, 'badidx.json'), JSON.stringify({ functions: [{ name: 'no address' }] }))
  w(path.join(W, 'badglob.json'), JSON.stringify({ functions: [], globals: [{ name: 'x' }] }))
  w(path.join(W, 'list.json'), JSON.stringify([{ address: '0x1000', name: 'only', signature: 'void only(void)' }]))
  w(path.join(W, 'empty.json'), '{}')
  w(path.join(W, 'badman', '.gen_skeleton.json'), '[1, 2]')
}

const TARGET = `//! a module
use crate::x;

// 0x401000
/// old doc
pub fn first(cx: &mut Cx) -> i32 {
    stub!(0x401000, "first")
}

impl Thing {
    // 0x401040
    /// \`void Thing::go()\`
    pub fn go(&mut self) {
        stub!(0x401040, "Thing::go")
    }

    // 0x401080
    pub fn inner(&self) {
        if true {
        }
    }
}

// 0x4010c0
pub fn dup_a() {}
// 0x4010C0
pub fn dup_b() {}

// 0x401100
pub fn no_end() {
`

const REPLACEMENT = `this text before the first address line is ignored

// 0x401000
/// new doc
pub fn first(cx: &mut Cx) -> i32 {
    42
}


// 0X401040
pub fn go(&mut self) {
    self.n += 1;
}
// 0x401080
    pub fn inner(&self) {}
// 0x4010c0
pub fn dup() {}
// 0x401100
pub fn no_end() {}
// 0x409999
pub fn missing() {}
`

export function replaceProject (W, opts = {}) {
  const t = opts.crlf ? TARGET.replaceAll('\n', '\r\n') : TARGET
  w(path.join(W, 'src', 'm.rs'), t)
  w(path.join(W, 'new.rs'), opts.crlf ? REPLACEMENT.replaceAll('\n', '\r\n') : REPLACEMENT)
  w(path.join(W, 'one.rs'), '// 0x401000\npub fn first(cx: &mut Cx) -> i32 {\n    1\n}\n')
  w(path.join(W, 'none.rs'), 'pub fn nothing() {}\n')
}
