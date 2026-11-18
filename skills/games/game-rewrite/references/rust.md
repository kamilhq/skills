# Step 4 (Rust) - A Rust rewrite that behaves bit for bit

**Private mode only.** This translates the matched code, so the result is a derivative work of the original: it
stays on the user's machine and is never published. For a rewrite others may download, see `cleanroom.md`.

Output: the game's code as a Rust crate, one module per subsystem, every function of the original translated
under its address, that builds for 32-bit Windows against the step-1 libraries (as DLLs) and runs with the
game's own data. Gate: **it builds, no stub is left, and every scenario is identical to the oracle (traces
with the framebuffer hash, and the save files)**.

Scale of a validated run (an SDL2 game, translated from its C++ rewrite (`cpp.md`) into
`i686-pc-windows-gnu` with rust-lld, no MinGW): about 950 functions (all but 15 from generated stubs; those 15
written by hand in the foundation), about 30 modules, about 80,000 lines (a third of them generated data
tables), `unsafe` only in `src/ffi/`. Every scenario was byte-identical to the oracle, framebuffer hash and
save folders included, and dozens of extra replays against the C++ rewrite (about 140,000 frames) were
identical too, except where both exes quit by themselves before the exit frame (random input chose "quit").

## 1. Translate from what
| Source | Use it when | Notes |
|---|---|---|
| the C++ rewrite (`cpp.md`), frame-proven | it exists and passes the scenarios | **the best source**: clean names, one definition per class, no scaffolding, already corrected where the matched units were wrong |
| matched units (decomp phase 6) | no C++ rewrite | compile-proven, but full of scaffolding (`cpp.md` section 1), and their local class copies can name members wrongly (section 9) |
| pseudocode (`decompiled_named_exe/functions/0x<addr>.c`) | neither | the truth when the C++ is unclear; read it for every doubtful member access |

Do the C++ rewrite first when the user wants Rust: it cost about an hour of agent time on top of a matched
decomp of about a thousand functions, it becomes the second reference for divergences (`orchestration.md` section 5), and a C++
fix found by a scenario reaches both rewrites.

## 2. Crate layout
```
rewrite/rust/
  Cargo.toml  build.sh  DESIGN.md (the translation rules of this game)  README.md (status, results)
  tools/names.tsv            address -> C++ name -> Rust path -> Rust signature (+ globals -> Cx paths)
  tools/gen_*.py             generators of the large data tables (section 12), with count checks
  src/main.rs                the C++ main / WinMain: options, start-up order, the main loop call
  src/cx.rs                  Cx: all game state (section 3)
  src/state/                 the C++ classes as Rust structs, enums, statics.rs (per-module globals)
  src/ffi/                   one file per library (raw-dylib), the only place with `unsafe`
  src/harness.rs             the harness contract (harness.md section 10)
  src/cnum.rs  src/cbuf.rs  src/stub.rs   from scripts/rust/template (C numerics, char arrays, stubs + log)
  src/<module>.rs or src/<module>/{mod.rs,<file>.rs}   one module per subsystem, functions in address order
```
Every translated function keeps its address line directly above its doc comment:
```rust
// 0x401a20
/// `int Game::frame_time(void)`
pub fn frame_time(cx: &mut Cx) -> i32 {
```
The address line ties the function to the decompile, the matched unit, the C++ rewrite, `names.tsv` and
`replace_fn.py`. Rust-only helpers get no address line. Progress is `grep -rn 'stub!(0x' src | wc -l`.

Naming: C++ names in `snake_case` (`loadFileToMemory` -> `load_file_to_memory`), class prefix dropped
(`Game::open_menu` -> `game::open_menu`), a prefix equal to the module dropped (`FILESYSTEM_init` ->
`filesystem::init`), methods of a member object prefixed (`world.camera.at` -> `world::camera_at`), overloads by the
names the decomp gave them, keywords with a trailing `_`. Types in CamelCase. C++ enums as `i32` newtypes with
associated consts (every value C++ could store stays representable, and they work as `match` patterns).

## 3. State: one context struct
Games of this era keep their state in global singletons whose methods call each other freely. In Rust all of
it lives in one struct, created once in `main` and passed as the first parameter to every function that
touches game state:
```rust
pub struct Cx {
    pub game: Game, pub renderer: Renderer, pub world: World, pub ents: EntityList, // the singletons
    pub statics: Statics,          // every other global and file-static, per module (state/statics.rs)
    pub mainloop: MainLoop, pub harness: Harness,
}
```
| C++ | Rust |
|---|---|
| `game.state = 3;` | `cx.game.state = 3;` |
| `game.set_state(3);` (method of a singleton) | `game::set_state(cx, 3);` |
| `ents.list[i].x += 2;` | `cx.ents.list[i].x += 2;` |
| `int p = ents.find_player();` | `let p = entity::find_player(cx);` |
| `util.parse_int(s)` (touches no state) | `util::parse_int(s)` (no cx: the generator found it pure) |
| `static int counter;` in a function | a field of `cx.statics.<module>` |

**The borrow rule: never hold a reference into `cx` across a call that takes `cx`.** Field paths are cheap;
re-borrow after every call. Everything else follows from it:
1. A C++ reference used across calls (`Entity& e = ents.list[i]; e.x = 1; music.play_sound(2); e.y = 2;`)
   becomes field paths around the call; a local reference between calls is fine. Copy read-only data out first.
   A C++ reference that `push_back` would invalidate (UB) becomes an index: comment it when you rely on it.
2. Loops over vectors are index loops that re-read the length every iteration, as the C++ does
   (`while i < cx.ents.list.len()`), unless the C++ cached the size.
3. **Element methods** (methods of objects stored in vectors: entities, text boxes, tracks) are `impl`
   methods; those that also need globals take `(&mut self, cx: &mut Cx, ...)`. Take the element out, call,
   put it back: `let mut tb = std::mem::take(&mut cx.renderer.text_boxes[i]); tb.resize(cx);
   cx.renderer.text_boxes[i] = tb;`. Valid only when the method never reaches its own slot through `cx`:
   check each one. Example: two text-box callbacks compared `&text_boxes[other] != box`; with the box taken
   out they had to recognise their own (empty) slot. A creator that fills a reused slot takes it out the same
   way and must put it back on every early return.
4. **Pointers into state** become selectors or indices: a `Background&` parameter becomes an enum naming which
   of the two backgrounds, an `int*` pointing at one of two volume fields becomes an enum of the two, a
   `std::string*` text-entry target becomes an enum of the fields it can point at (with an index where needed).
5. Function-local statics move into `cx.statics.<module>` (log-once flags may stay process-wide statics).
6. Construction: `Default` of each struct is the zero-initialised storage plus the constant assignments of
   its constructor; `Cx::new` runs the singleton constructors in the exe's static-initialiser order (the same
   order `cpp.md` section 7 uses for the link).
7. Process-wide, not in `Cx`: what is per thread or per process in the original too (MSVC `rand()` state,
   log switches as atomics, the audio thread's mirrors, section 5).
8. The game's exit function becomes `fn exit(cx: &mut Cx, code: i32) -> !` (cleanup, then
   `std::process::exit`).

## 4. Signatures
`gen_skeleton.py` writes a first signature for every stub (section 11); fix it where the C++ needs something
else and record the change (`orchestration.md`: WAVE_NOTES). Expect a few percent to change (60 of about 950).

| C++ parameter | Rust |
|---|---|
| `int`, `bool`, `float`, `Uint8`, `size_t` | `i32`, `bool`, `f32`, `u8`, `usize` (on x86: 32-bit; `usize` is 32-bit on i686 too) |
| `const char*`, `const std::string&` | `&str` (`Option<&str>` where the C++ tests for NULL) |
| `std::string&` (out), `char* buf, size_t size` | `&mut String`, `&mut [u8]` or `&mut CBuf<N>` |
| `int*` out / maybe NULL | `&mut i32` / `Option<&mut i32>` |
| `const T*` read-only, maybe NULL (`SDL_Rect*` passed on to the library) | `Option<&T>` |
| `std::vector<T>&` / `const std::vector<T>&` | `&mut Vec<T>` / `&[T]` |
| `unsigned char** mem` the callee allocates | `&mut Option<Vec<u8>>` |
| a reference that is always the same global (`EntityList& ents`) | dropped: it is `cx.ents` |
| `...` / `va_list` | `&[VArg]`, a small enum of the argument kinds the game formats |
| return `const char*` into game storage | `String` (a borrowed `&str` would lock `cx` for the caller) |
| return a pointer to a static table | `&'static [T]` |
| C function pointers / callbacks | `fn(&mut Cx, ...)`; closures `&mut dyn FnMut(...)` for enumerate-style callbacks |

## 5. FFI: the libraries as DLLs
Each library of the inventory is a DLL built from the pinned source (`toolchains.md`: one DLL per library,
each with its own static CRT). Bind them with `raw-dylib`, no import libraries:
```rust
#[link(name = "physfs", kind = "raw-dylib", import_name_type = "undecorated")]
extern "C" {
    fn PHYSFS_init(argv0: *const c_char) -> c_int;
}
```
- `unsafe` only in `src/ffi/`; the game calls small safe wrappers. No global-state accessor anywhere: `cx`
  is passed explicitly, so no `static mut`.
- Handles (`Texture`, `XmlDoc`, `PhysfsFile`) are `Copy` newtypes over the pointer with `NULL`/`is_null()`,
  never freed by `Drop`: free them where the C++ frees them, **with the library that allocated them** (each
  DLL has its own heap). Buffers a library keeps pointing into (a surface created from pixels, a decoder
  over memory, queued audio buffers) live in the owning struct and are never reallocated while in use.
- Packed structs (`#pragma pack`) are `#[repr(C, packed)]`; check struct returns by value and C99 `bool`
  returns in the hello program (`toolchains.md`).
- **C++ libraries** need a C API in their DLL (`scripts/capi/tinyxml2_capi.*`). When a translation needs a
  call the shim lacks, extend the shim rather than reading the C++ object's layout from Rust. Two gaps seen
  with tinyxml2: no boolean attribute query (rebuilt from the integer query plus the library's own spellings of
  true/false) and no "document of this node" (read from the node's second word in `ffi/`, a layout
  dependency that is pinned by the library version).
- **C maths** (`fmodf`, `floor`, `pow`, `sin`): on `i686-pc-windows-gnu` without MinGW, Rust's `f32 % f32`,
  `floor()`, `powf()` need a C maths library that is not linked (`undefined symbol: _fmodf`). Call the same
  implementation the original called: an SDL game usually calls SDL's (`SDL_fmodf`, `SDL_floor`, ...) through SDL2.dll.
  `abs()` and `sqrt()` compile to instructions and link either way.
- **Windows API** calls (`SHGetFolderPathW`, console, time zone conversion) are `extern "system"` + raw-dylib
  in `ffi/win32.rs`.
- **Callbacks on other threads.** An audio library (FAudio) calls buffer callbacks on its mixer thread with a
  pointer the game gave it. In Rust: each track (its callback struct and streaming buffers) lives in a
  `Box` with a stable address (`Vec<Box<Track>>`, never `Vec<Track>`), the library gets the boxed pointer,
  `extern "C"` trampolines in `ffi/` handle the callback, and what the callback must read from game state is
  mirrored in atomics written by the game thread. `Cx` itself never crosses threads. Callbacks the library
  calls on the game thread during a call from the game (enumerate, parse) take `&mut dyn FnMut`.

## 6. Numeric fidelity checklist
Behaviour must match bit for bit: a last-bit float difference becomes a different position some frames later,
a different branch, a different `rand()` count. Go through this list for every function.

**Floating point: find out which unit the original used.** Count x87 versus SSE instructions in the game's
own code (not the CRT): a VS2010 game without `/arch:SSE2` has thousands of x87 instructions and no SSE in
game code. VS2012 and later default to SSE2.
- *x87 original:* evaluate every expression in `f64` (with the default 53-bit precision control, `f64` is
  exact for this) and round to `f32` **only where the C++ stores into a float, passes a float argument,
  returns a float or casts `(float)`**. `e.vx = e.vx * 0.5f + e.ax;` is
  `e.vx = (e.vx as f64 * 0.5 + e.ax as f64) as f32;`; `if (a * b > c)` compares in `f64`. Literals keep
  their C type: `1.1f` is `1.1f32 as f64`, `1.1` is `1.1f64`. A function returning `float` rounds once, at
  the return.
- *SSE2 original:* compute in `f32` (each operation rounds), `double` in `f64`.
- *A different precision control* (a game that sets 24-bit with `_controlfp`): `f64` is no longer the model;
  emulate the rounding per operation.

**Float to int.** `(int) x` is never `x as i32` (Rust saturates). Use `cnum::ftol(x as f64)`: truncation,
and `0x80000000` for NaN and out-of-range values, like `__ftol2_sse` / `cvttsd2si` or `fistp` with
truncation. `(unsigned char) f` is `ftol` then the low byte. Find which helper the exe calls (`__ftol2`,
`__ftol2_sse`, `__ftoui3`) before relying on out-of-range results.

**Integers.**
- `overflow-checks = false` in every profile: `+ - *` wrap like the MSVC code; write `wrapping_*` where the
  wrap is intended (hashes, timers, LCGs).
- C promotes `char`/`short`/`u8` operands to `int`: cast to `i32` first, compute, cast back where C stores
  (`as u8` truncates like C).
- **`char` is signed in MSVC.** A byte >= 0x80 read as `char` is negative (`cnum::schar`); a game that prints
  a `char` value 128..255 prints a negative number. Map `char` to `i8`, or keep `u8` and convert at each use.
- Division and remainder truncate toward zero in both languages; `i32::MIN / -1` panics in Rust and traps
  in C. Shifts: x86 masks the count to 5 bits (`wrapping_shl`), `>>` on signed is arithmetic.
- Unsigned arithmetic the C++ did on `size_t` stays unsigned: `(size_t) i < v.size()`, `v.size() - 1` with an
  empty vector, `SDL_min(n, (size_t) len - 1)`.
- `abs(INT_MIN)` is `INT_MIN` (`wrapping_abs`); `Ord::clamp` panics when min > max, the C macro does not
  (`cnum::c_clamp`).

**Evaluation order.**
- **Function arguments: MSVC x86 evaluates them right to left** (it pushes the last argument first). Rust
  evaluates left to right. `draw(rand() % 3, rand() % 5)` calls the second `rand()` first in the original:
  hoist the calls into locals in the original's order. This changes the `rand()` sequence, so it matters
  wherever an argument has a side effect (RNG, a counter, a stream read). Read the disassembly when unsure.
- **Macros evaluate arguments more than once.** `SDL_clamp(x, a, b)` expands to
  `x < a ? a : (x > b ? b : x)`: with `x = random_float() * 255`, `random_float()` runs once when the value is
  below `a`, twice when above `b`, three times otherwise, each time with a new random value. One Rust
  translation of an editor menu called it once per colour channel; the harness found it (text colour and the
  `rand()` sequence differed). Translate such a macro by expanding it, call by call. Same for `SDL_min`/`SDL_max`, `MIN`/`MAX`,
  and any project macro with a repeated parameter.
- Short-circuit operators and the comma operator keep their order in Rust; `x = y = f()` assignments do too.

**Randomness.** The MSVC CRT `rand()` is per thread, seed 1, `state = state * 214013 + 2531011; return
(state >> 16) & 0x7fff` (`cnum::rand`). The game's own generators are ported bit for bit (e.g. a
xoshiro128+ seeded from the frame counter). Every call of the original happens in the same order and number,
renders included.

**Formatting.** `printf("%f")` into compared output (saves, rendered text) goes through the same printf the
original used (SDL has its own): reimplement that one, not Rust's `format!`.

## 7. Strings
- `std::string` -> `String`, `const char*` parameters -> `&str`. Trace and save bytes come from these strings:
  no trimming, no normalisation, `\n` stays `\n`.
- Fixed `char buf[N]` (fields, globals, locals the C code truncates into) -> `CBuf<N>`
  (`scripts/rust/template/cbuf.rs`): `set` = `strlcpy`, `push_str` = `strlcat`, `snprintf(buf, N, ...)` =
  `buf.set(&format!(...))`; truncation at a byte boundary like C.
- **UTF-8 cut behaviour.** A C truncation can cut a multi-byte character; C keeps the partial bytes, while a
  Rust `&str` cannot hold them. `CBuf::as_str` returns the longest valid prefix (one character shorter
  there); output that is compared or rendered reads `as_bytes()`. Byte-oriented C code (UTF-8 decoders,
  bidi, glyph lookups) works on `&[u8]`, keys of maps built from file text are `Vec<u8>`.
- Strings from C libraries: lossy conversion where only text matters, raw bytes where they are compared.
- `strcmp(a, b) == 0` -> `a == b`; `strcasecmp` -> `eq_ignore_ascii_case` (ASCII only, like the C one);
  `std::string::find`/`substr` work on byte indices; `atoi`/`strtol` -> the parser the original called
  (SDL's wraps and does not clamp).

## 8. Containers
- `std::vector<T>` -> `Vec<T>`; `erase(begin() + i)` -> `remove(i)`; `resize` with `Default` values.
- `std::map<K, V>` -> `BTreeMap<K, V>`: same ordering (`String` compares bytewise like `std::string`).
  **`m[k]` inserts a default entry when `k` is missing**: a read through `operator[]` is
  `*m.entry(k).or_default()`, not `get`. The insertion changes `size()` and later iterations.
- C hash maps from a library (c-hashmap): iteration order is the library's. Replace with a Rust `HashMap` only
  where the game never iterates or iterates order-independently (e.g. translation tables: lookups only).
- Fixed arrays keep their sizes; arrays over a few KiB are `Box<[T; N]>` so state is never built on the stack.
- Erase-while-iterating macros keep their quirks (e.g. a remove macro that skips the element after each
  erased one: reproduce it).

## 9. Undefined behaviour the original relies on
Rust aborts (`panic = "abort"`) where C reads garbage. Decide per case and write the decision into
`DESIGN.md`:

| Case | What to do | Example |
|---|---|---|
| out-of-bounds read the game reaches, result defined by the memory layout | reproduce what the exe reads, comment it | an array of 100 flags read up to 120: indices 100+ read the next field's array |
| static data the code patches in place before returning it | emit every variant it can produce, pick by the same condition | a room table patched by a setting |
| uninitialised local the C++ reads | zero (or a neutral value); document | a record filled only when a player exists; colour alpha of a missing level attribute |
| unchecked index reachable only with corrupt state | plain indexing (aborts); document as unreachable | editor room properties for levels wider than the editor allows |
| dangling reference after a reallocation | an index; comment | |

Field names from matched units: **compare offsets, not names.** A unit's local copy of a class can name
members differently from the shared header while compiling to the same bytes. In one project a render unit
named four adjacent timer members of the game class differently; the C++ rewrite used the header names, so
two functions counted down the wrong timers. The Rust waves translated before the C++ was corrected and copied
the mistake. An oracle scenario for a play mode showed it (`fb` from frame 1408), the extra Rust-vs-C++ runs
had not (both had it). Rule: when a translated function touches members of a class copy, check each offset against the
shared header (the decompile shows offsets).

## 10. Build and run
`scripts/rust_build.sh` (`toolchains.md`): `i686-pc-windows-gnu`, rust-lld, no MinGW. Profiles:
```toml
[profile.release]
panic = "abort"
overflow-checks = false
[profile.dev]
panic = "abort"
overflow-checks = false
```
No crates. The DLLs of `build_libs.py` sit next to the exe with the game's own shipped DLLs.
`main` calls `stub::init_log("<GAME>_RUST_LOG")` and `stub::install_panic_hook()` first: the exe is a GUI
program without a console, and an abort would otherwise leave nothing behind.

## 11. The skeleton generator
`scripts/rust/gen_skeleton.py` writes one stub per function, so the crate builds from the first hour and
every wave fills bodies in place.
```bash
S=<skill>/scripts
python3 -I $S/rust/gen_skeleton.py index --units src_matched/GAME --headers src_matched/GAME/include \
    --cpp-config rewrite/cpp/config.json --names decompiled_named_exe/index.json --out rewrite/rust/tools/functions.json
python3 -I $S/rust/gen_skeleton.py generate --config rewrite/rust/tools/skeleton.json \
    --index rewrite/rust/tools/functions.json --crate rewrite/rust
cp $S/rust/template/{stub,cnum,cbuf}.rs rewrite/rust/src/
python3 -I $S/rust/replace_fn.py rewrite/rust/src/game/game.rs scratch.rs   # swap bodies by address line
```
- **index** reads the matched units (or the C++ rewrite's tree, same annotations) with `cpp/cppsplit.py`: per
  annotation the address, name (the decomp's, unless it is a Ghidra default), C++ head, unit, class,
  namespace, body; the file-scope variables (definitions and extern-only declarations, with addresses from
  `// GLOBAL:` or trailing `// 0x...` comments); the data members of every class (for the cx analysis). Any
  index with `address` and `name` per function works (e.g. made from pseudocode).
- **generate** places each function, maps its signature, decides `cx`, and writes the stub files,
  `src/state/statics.rs` (one `<Module>Statics` struct per module) and `tools/names.tsv`.
- **Never overwrites hand edits.** `<crate>/.gen_skeleton.json` keeps the SHA-256 of every file it wrote. A
  file is rewritten only while it still has that hash; edited files, files it did not write and the config's
  `keep` list are reported and left alone. `names.tsv` is always rewritten (it describes the C++ side).
  After the translation, rerunning it reports what is missing (`tree.missing`) and how many stubs are left.
- **Stubs log, they do not panic**: `stub!(0x..., "name")` logs `unimplemented: 0x... name` once and returns
  `Default::default()`, so a partly translated exe runs, and the log of a harness run lists the stubs a
  scenario reaches, in order: translate those next.
- Templates (`scripts/rust/template/`, generic, unit-tested on the host with `rustc --test`): `stub.rs` (the
  macro, the log file, the panic hook), `cnum.rs` (`rand`/`srand`, `ftol`, `ftoui`, C clamp/min/max/abs,
  signed char, truncating stores, shifts), `cbuf.rs` (`CBuf<N>`).

Config (`scripts/examples/rust_config_example.json` is a small made-up config that uses every key):

| Key | Meaning |
|---|---|
| `modules`, `default_module` | module names with a doc line; where unplaced functions go (`app`) |
| `classes` | `{C++ class: {rust, module, role, file, files, prefix}}`; roles `singleton` (free functions with `cx`), `subobject` (a member object of a singleton: free functions with `prefix`), `element` (impl methods, constructor = `new`), `value` (data; constructor skipped, other methods free functions `class_method`); `files` = `[[unit regex, file]]` |
| `namespaces`, `names`, `name_patterns`, `prefixes`, `addresses`, `units`, `module_files` | placement: namespace -> module; exact name -> `module[/file]`; `[[name regex, dest]]`; `[[prefix, dest, strip]]`; address -> dest (overrides the rest); `[[unit regex, dest]]`; `{module: [[unit regex, file]]}` |
| `skip` | `[{names, units, bases, reason}]`; built in: annotations on variables and on no code, destructors, value-type constructors |
| `handwritten`, `rename` | `{address: "module::name"}` written by hand (no stub); `{address: rust name}` |
| `cx` | `{type, name, mode: all | none | analyse, methods: always | analyse, state: [regex], globals, global_min_len, ignore_globals, pure, needs}`; `analyse` gives `cx` to a function whose body matches a state regex, uses a global (any of its module, or a longer name elsewhere), or (methods) uses `this` or a member, and to every function that calls one of those |
| `types`, `param_types`, `return_types`, `drop_params`, `enums`, `varargs`, `constants` | type mapping on top of the built-in C types (`char` -> `i8` by default); keys are normalised C types, `const ` prefixed where it matters; `constants` for array dimensions (expressions allowed) |
| `skip_globals`, `global_modules`, `statics`, `statics_imports`, `imports`, `stub_macro`, `keep` | globals left out (`{names, units}`), module overrides, the statics file (null: none), use lines, macro name, files never written |

Against a project's own hand-written generator (about 1,500 lines with every mapping hard-coded), the
generic one indexed about 1,300 annotations from about 270 units in 2.5 s (Node 0.6 s) and generated in
0.7 s: every function at the same Rust path, 96% with the same signature (the rest: `cx` decided differently,
or nullable pointers as `Option` where the project had plain references, which the waves themselves changed
to `Option` in several places). Its `names.tsv` is longer: the generic index also lists the annotations on
library code, variables and fragments.

## 12. Data tables: by script, with counts
Large data (room tables, maps, built-in scripts, credits lists, localisation tables) is converted by a script
from the C++ (or the exe, `cpp/gen_data.py`), never typed by an agent. Each generator checks counts against
the source and has a `--check` mode. In one project about a third of the lines were generated: room tables
of several level classes (hundreds of rooms, about a thousand entity and block creations, counts checked),
large tile maps (tens of thousands of tiles), about 200 built-in scripts with 5,000 lines in three lookup
chains, the credits lists, the area-map and text shaping tables, the editor tables, a music table. A table
the C++ patches at run time gets one static per variant (section 9).

## 13. Testing without unit tests
- The crate builds only for Windows (raw-dylib), stable cargo refuses test builds with `panic = "abort"`, and
  `-Zpanic-abort-tests` needs symbols the runtime shim lacks: `#[cfg(test)]` blocks document behaviour but
  do not run in the crate. Pure modules (the templates, a parser, a hash) can be tested on the host with
  `rustc --test` on the file.
- Behaviour is proven by the harness (`harness.md`), with the C++ rewrite as a second reference
  (`orchestration.md` section 5). `<GAME>_RUST_LOG` collects the log, every `unimplemented:` line and a
  panic's message and location. A framebuffer dump option (every N-th hashed frame as a picture) shows what
  a differing `fb` looks like.
- Without the harness variables the exe plays in real time like the original: check it once (window up,
  `<GAME>_TRACE` + `<GAME>_EXIT_FRAME=300`, exit code 0, no panic in the log).

## 14. Deliberate differences
Record each in the project's `DESIGN.md` with the reason behaviour is unchanged. Typical ones: a library's
allocator not redirected (the DLL keeps its own heap), `WinMain`'s command-line parsing replaced by
`std::env::args_os` (same conversion), uninitialised locals as zero, unreachable out-of-bounds reads aborting,
the element-take-out pattern, the log file and panic hook.

## Checklist
- [ ] C++ rewrite done first (or the reason it is not), and chosen as the translation source.
- [ ] x87 or SSE decided from the binary; `cnum.rs`, `cbuf.rs`, `stub.rs` in the crate; profiles with
      `panic = "abort"`, `overflow-checks = false`.
- [ ] Index and config written; `gen_skeleton.py generate` run; the crate builds with every stub.
- [ ] `Cx`, the state structs, `ffi/`, `harness.rs` and the main loop written and building before any wave
      starts (`orchestration.md`).
- [ ] Every function: argument order, macros with repeated arguments, `ftol`, signed `char`, `operator[]`
      inserts, unsigned `size_t` arithmetic, member offsets of class copies checked.
- [ ] Data tables generated with count checks.
- [ ] No `stub!(0x` left; `unsafe` only in `ffi/`; `gen_skeleton.py generate` reports `missing: 0`.
- [ ] Every scenario identical with `fb`, every save file identical; real-time run checked; deliberate
      differences and untested subsystems written down.
