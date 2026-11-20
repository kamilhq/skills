# Step 7 (Rust) - Writing the rewrite in Rust

For implementers: fresh agent sessions (or people) who never saw the decompilation. You write the game as a
Rust crate from behaviour specs, format docs, the oracle's per-frame traces and the game's own data files,
read at run time. The design, the module structure and the names are yours.

Output: the clean tree (`rewrite/clean` by default, usually its own repository outside the private
project), a crate with one module per subsystem, that builds for 32-bit Windows against the step-6 libraries
(as DLLs) and runs with the user's game data. Gate: **it builds, no `todo_spec!` is left in code a scenario
reaches, every scenario is identical to the oracle (traces with the framebuffer hash, and the save files)
or the remaining divergence is documented and accepted by the user, and `release_check.py` passes on the
tree.** Step 8 (`harness.md`) is the comparison.

## 1. Your workspace, and asking questions
`cleanroom.py pack` builds the workspace: `RULES.md` (read it first), `INPUTS.json`, the specs
(`cleanroom/specs/`), the format docs (`docs/formats/`), the trace contract, the scenarios with the
oracle's traces and saves, and `rewrite/libraries.json`. `cpp.md` section 1 lists it in full, with what
you may use besides (the installed game, public documentation, the upstream libraries, this skill's
generic tools) and what you never open (decompiled code, Ghidra projects, the analysts' tools, names maps,
private rewrites, the original executable's bytes, other people's decompilations or ports of this game).

Questions go in writing (`questions/<wave>-NN.md`) to the coordinator, who records them with `cleanroom.py
record --wave W --event question FILE`; answers come back as spec sections in a new pack. Name the
scenario, frame, field, both values and the spec section; ask about behaviour, not code.

## 2. Crate layout
```
Cargo.toml  build.sh  README.md  DESIGN.md (your design, the fidelity rules, deliberate differences)
src/main.rs                entry point: options, start-up order, the main loop
src/cx.rs                  the context struct: all game state (section 3)
src/state/                 state structs and enums of each subsystem
src/ffi/                   one file per library (raw-dylib), the only place with `unsafe`
src/harness.rs             the trace contract (harness.md)
src/cnum.rs  src/cbuf.rs  src/stub.rs   copied from scripts/rust/template
src/<module>.rs or src/<module>/{mod.rs, <file>.rs}   one module per subsystem from the specs
```
- **Design first.** Read every spec of the first waves, then decide modules, state and names in `DESIGN.md`;
  later waves extend it.
- **Unwritten behaviour is `todo_spec!`** (its argument is a spec section, never an address). Write the
  module and function structure early so the crate builds from the first day, and fill bodies in place:
  ```rust
  pub fn travel_time(cx: &mut Cx, floors: i32) -> i32 {
      todo_spec!("specs/lifts.md#timing")
  }
  ```
  It logs `unimplemented: specs/lifts.md#timing` once and returns `Default::default()`: a partial exe runs,
  and a harness run's log lists, in order, what a scenario reaches. Progress: `grep -rn 'todo_spec!(' src`.
- **Names are yours**, in Rust style (`snake_case` functions, `CamelCase` types). Values a field can hold
  beyond the named ones (a state number from a save file) stay representable: an `i32` newtype with
  associated consts works as `match` patterns and never rejects a value.
- **No address-like or decompiler-like text**: no `// 0x4013f0` lines, no `stub!(0x...)`, no identifiers
  such as `fun_...`, `ivar1`, `param_1`, `undefined4`. `release_check.py` flags them, and fails a tree where
  more than 30 % of function definitions carry the analysts' names for the original.

## 3. State: one context struct
Games of this era keep their state in global singletons that call each other freely, and the specs describe
behaviour in those terms ("the room changes, the music restarts, the player's checkpoint is set"). In Rust
all of it lives in one struct, created once in `main` and passed first to every function that touches state:
```rust
pub struct Cx {
    pub game: GameState, pub render: Render, pub world: World, pub entities: Entities,
    pub audio: Audio, pub input: Input, pub harness: Harness,
}
```
**The borrow rule: never hold a reference into `cx` across a call that takes `cx`.** Field paths are cheap;
re-borrow after every call. Everything else follows from it:
1. Work on an element across calls with its index and field paths (`cx.entities.list[i].x += 1;
   audio::play(cx, 2); cx.entities.list[i].y = 0;`); copy read-only data out first.
2. Loops over a list that the body can grow or shrink are index loops that re-read the length each time
   (`while i < cx.entities.list.len()`), unless the spec says the count is taken once at the start.
3. **Element methods** that also need global state take `(&mut self, cx: &mut Cx, ...)`: take the element
   out, call, put it back (`let mut tb = std::mem::take(&mut cx.render.text_boxes[i]); tb.layout(cx);
   cx.render.text_boxes[i] = tb;`). Valid only when the method never reaches its own slot through `cx`
   (a search over all boxes now sees an empty slot): check each one, and put the element back on every
   early return.
4. A parameter that names "one of these fields" (which of two backgrounds, which volume setting, which text
   field a text entry edits) is an enum selector or an index, not a reference.
5. Persistent counters and flags of a function live in its module's state in `Cx`; only what is per
   thread or per process in the original too stays outside (the CRT `rand()` state, log switches as
   atomics, the audio thread's mirrors, section 5).
6. `Default` of each struct is its zero state plus the spec's initial values; `Cx::new` sets things up in
   the start-up order the spec gives. Quitting is `fn exit(cx: &mut Cx, code: i32) -> !`.

## 4. Signatures
| What a function needs | Rust |
|---|---|
| C integers and floats | `i32`, `u8`, `f32`, `usize` (32-bit on i686, like `size_t`) |
| text in (possibly absent) / out / into a fixed-size C buffer | `&str` (`Option<&str>`) / `&mut String` / `&mut CBuf<N>` |
| optional out value; a list read / changed | `Option<&mut i32>`; `&[T]` / `&mut Vec<T>` |
| text the caller keeps | return `String` (a borrowed `&str` would lock `cx`) |
| formatted text with a few argument kinds | `&[Arg]`, a small enum |
| callbacks | `fn(&mut Cx, ...)`; `&mut dyn FnMut(...)` for enumerate-style callbacks |

## 5. FFI: the libraries as DLLs
Each library in `libraries.json` is a DLL built from the pinned source (`toolchains.md`: one DLL per
library, each with its own static CRT). Bind them with `raw-dylib`, no import libraries:
```rust
#[link(name = "physfs", kind = "raw-dylib", import_name_type = "undecorated")]
extern "C" {
    fn PHYSFS_init(argv0: *const c_char) -> c_int;
}
```
- `unsafe` only in `src/ffi/`; the game calls small safe wrappers. No `static mut`: `cx` is passed explicitly.
- Handles (textures, documents, files) are `Copy` newtypes over the pointer with `is_null()`, never freed by
  `Drop`: free them where your design frees them, **with the library that allocated them** (each DLL has
  its own heap). Memory a library keeps pointing into (pixels behind a surface, a decoder over a buffer,
  queued audio) lives in an owning struct and is never reallocated while in use.
- Packed structs are `#[repr(C, packed)]`; check struct returns by value and C99 `bool` returns in the
  hello program (`toolchains.md`).
- **C++ libraries** need a C API in their DLL (`scripts/capi/tinyxml2_capi.*`). When you need a call the
  shim lacks, extend the shim instead of reading the C++ object's layout from Rust.
- **C maths**: on `i686-pc-windows-gnu` without MinGW, `f32 % f32`, `floor()`, `powf()` need a C maths
  library that is not linked (`undefined symbol: _fmodf`). Call the implementation the spec says the
  original used, usually the game's support library (`SDL_fmodf`, `SDL_floor`, ...). `abs()` and `sqrt()`
  are instructions and link either way.
- **Windows API** (`SHGetFolderPathW`, console, time zones): `extern "system"` + raw-dylib in `ffi/win32.rs`.
- **Callbacks on other threads.** An audio library (FAudio) calls buffer callbacks on its mixer thread with
  a pointer you gave it. Each track (callback struct and streaming buffers) lives in a `Box` with a stable
  address (`Vec<Box<Track>>`, never `Vec<Track>`), `extern "C"` trampolines in `ffi/` handle the callback,
  and what it must read from game state is mirrored in atomics written by the game thread. `Cx` never
  crosses threads.

## 6. Behaviour an MSVC-built x86 game demands
The traces compare float bits, random sequences and hashes: a last-bit float difference becomes a different
position some frames later, then a different branch, then a different `rand()` count. The specs state the
facts; this list is what to look for when writing each function and when a trace first differs.

**Floating point: which unit.** The specs or the toolchain notes say how the original computed floats; if
they do not, ask. A VS2010-era game without `/arch:SSE2` used x87; VS2012 and later default to SSE2.
- *x87 original:* evaluate each expression in `f64` (exact under the default 53-bit precision control) and
  round to `f32` **only where the value is stored in a float, passed or returned as one, or cast**:
  `vx = (vx as f64 * 0.5 + ax as f64) as f32;`, comparisons in `f64`. A constant the spec gives as a
  single-precision value is `1.1f32 as f64`, a double one `1.1f64`.
- *SSE2 original:* compute in `f32`, doubles in `f64`.
- *A different precision control* (a game that sets 24-bit): emulate the rounding per operation.

**Float to int.** Never `x as i32` (Rust saturates). `cnum::ftol(x as f64)` truncates toward zero and gives
`0x80000000` for NaN and out-of-range values, like MSVC's conversion; `ftol_u8` and `ftoui` for the narrow
and unsigned cases.

**Integers.**
- `overflow-checks = false` in every profile, so `+ - *` wrap like MSVC code; write `wrapping_*` where the
  spec says a value wraps (timers, hashes, generators).
- Small types are promoted in C: compute in `i32`, store back with `as u8`/`as i16` (truncation).
- **`char` is signed in MSVC.** A byte >= 0x80 used as a number is negative (`cnum::schar`): a spec that
  says "printed as -56" means exactly that.
- Division truncates toward zero in both; `i32::MIN / -1` panics. Shift counts are masked to 5 bits on x86
  (`cnum::c_shl`/`c_shr`); `>>` on signed values is arithmetic.
- Unsigned size arithmetic stays unsigned where the spec says a "length minus one" of an empty list
  becomes huge.
- `abs(INT_MIN)` is `INT_MIN` (`cnum::c_abs`); C's clamp does not panic when min > max (`cnum::c_clamp`).

**Order of side effects.**
- MSVC x86 usually evaluates function arguments right to left; Rust evaluates left to right. When a spec
  gives the order of random draws (or stream reads, counter increments), hoist each into a local in that
  order: `let dy = cnum::rand() % 5; let dx = cnum::rand() % 3; place(cx, dx, dy);`.
- **Values drawn more than once.** A clamp written as a C macro evaluates its argument once per comparison;
  a spec will say so ("a new random value for each comparison: once when below the minimum, twice when
  above the maximum, three times otherwise"). Write it draw by draw; `cnum::c_clamp` evaluates once and is
  wrong there.

**Randomness.** The MSVC CRT `rand()` is per thread, seed 1, `state = state * 214013 + 2531011; return
(state >> 16) & 0x7fff` (`cnum::rand`). The game's own generators are ported from the spec bit for bit.
Every draw happens in the same order and number, renders included.

**Formatting.** Numbers written into saves or rendered text use the formatter the spec names (SDL has its
own printf): reimplement that one, not Rust's `format!`, where the output is compared.

## 7. Strings
- Text is `String` / `&str`; trace and save bytes come from it, so no trimming or normalisation.
- Fixed-size C buffers the spec describes ("names are cut to 31 bytes") are `CBuf<N>`
  (`scripts/rust/template/cbuf.rs`): `set` = `strlcpy`, `push_str` = `strlcat`, truncation at a byte.
- **UTF-8 cuts.** A byte cut can split a character; C keeps the partial bytes, a `&str` cannot.
  `CBuf::as_str` returns the longest valid prefix; output that is compared or rendered reads `as_bytes()`.
  Byte-oriented work (UTF-8 decoding, glyph lookups, keys of maps built from file text) uses `&[u8]`.
- Case-insensitive comparison of C libraries is ASCII only (`eq_ignore_ascii_case`); number parsing follows
  the spec (SDL's `atoi` wraps instead of clamping).

## 8. Containers
- Lists are `Vec<T>`; arrays over a few KiB are `Box<[T; N]>`, so state is never built on the stack.
- Sorted maps are `BTreeMap` (`String` keys compare bytewise like C++ strings). When a spec says that
  looking up a missing key creates an entry (which changes counts and later iteration), use
  `entry(k).or_default()`, not `get`.
- A library hash map's iteration order is the library's; a Rust `HashMap` is fine only where the spec says
  order never matters (lookups only).
- Quirks the spec describes are behaviour: "the entity after a removed one is skipped that frame" is
  reproduced, not fixed.

## 9. Undefined behaviour the original relies on
Rust aborts (`panic = "abort"`) where C reads garbage. The specs describe what the original does in such
cases; decide per case and write the decision into `DESIGN.md`:

| The spec says | What to do |
|---|---|
| an index past the end reads a neighbouring value, with a defined result | reproduce the result the spec gives, comment it |
| a table is changed in place by a setting before use | build each variant, choose by the same condition |
| a value is never set on some path and reads as garbage | zero or a neutral value; documented divergence |
| the case is reachable only with corrupt state | plain indexing (aborts); documented as unreachable |

## 10. Build and run
`scripts/rust_build.sh` (`toolchains.md`): `i686-pc-windows-gnu`, rust-lld, no MinGW; on Windows
`cargo build --target i686-pc-windows-msvc`. Profiles:
```toml
[profile.release]
panic = "abort"
overflow-checks = false
[profile.dev]
panic = "abort"
overflow-checks = false
```
No crates. The DLLs of `build_libs.py` sit next to the exe with the game's own shipped DLLs. `main` calls
`stub::init_log("<GAME>_RUST_LOG")` and `stub::install_panic_hook()` first: the exe is a GUI program
without a console, and an abort would otherwise leave nothing behind.

## 11. Data tables
Everything the game shows or plays comes from the user's installation at run time, decoded by your own
readers from the format docs: graphics, sound, music, text, levels, room and entity tables.
- Constants a spec states as facts (speeds, timings, a short colour list) are named `const`s, typed by hand.
- Large tables are never typed into the source: the gate fails numeric tables of 1,024 or more items and
  string tables of 64 or more. Read them from the game's files.
- Data a spec places inside the original executable: follow the spec (typically read from the user's own
  copy at run time, at the given location, after a hash check); never open the exe to look, never copy its
  bytes into the tree.

## 12. Testing without unit tests
- The crate builds only for Windows (raw-dylib), and stable cargo refuses test builds with
  `panic = "abort"`: `#[cfg(test)]` blocks do not run in the crate. Pure modules (the templates, your
  format readers, a hash) can be tested on the host with `rustc --test` on the file.
- Behaviour is proven by the harness (step 8): `run_scenario.py` + `compare_traces.py` (`--ignore fb` first,
  then with `fb`) and `cmp` of every save file. `<GAME>_RUST_LOG` collects every `unimplemented:` line and a
  panic's message and location; a framebuffer dump (every N-th frame as a picture) shows a differing `fb`.
- Without the harness variables the exe plays in real time: check it once (window up, trace variable plus
  an exit frame of 300, exit code 0, no panic in the log), and with real key presses
  (`scripts/harness/keysend.cpp`, `cpp.md` section 7).

## 13. Deliberate differences
Record each in `DESIGN.md` with the reason behaviour is unchanged, or as a divergence the user accepted:
a library's allocator not redirected (the DLL keeps its own heap), `std::env::args_os` for the command
line, never-set values as zero, unreachable out-of-bounds reads aborting, the log file and panic hook.
The toolchain (`i686-pc-windows-gnu`, rust-lld, DLLs) and harness were validated on a 2010s SDL2 game.

## Checklist
- [ ] `RULES.md` read; only the workspace, the clean tree and the installed game used.
- [ ] Design in `DESIGN.md` before the first wave's code; `Cx`, `ffi/`, `harness.rs` and the main loop build
      with `todo_spec!` bodies.
- [ ] Float model known from the specs (x87 or SSE2); `cnum.rs`, `cbuf.rs`, `stub.rs` in the crate;
      profiles with `panic = "abort"`, `overflow-checks = false`.
- [ ] Every function: order of draws, values drawn more than once, `ftol`, signed `char`, lookups that
      insert, unsigned size arithmetic.
- [ ] Game data read from the user's files at run time; no large table in the source.
- [ ] Every open point asked in writing through the coordinator; answers came back as specs.
- [ ] No `todo_spec!` left in code a scenario reaches; `unsafe` only in `ffi/`.
- [ ] Every scenario identical with `fb`, every save file identical (or divergences documented and
      accepted); real-time run checked; untested subsystems listed.
- [ ] LICENSE, README and third-party notices at the top of the tree.
- [ ] The coordinator ran `release_check.py <tree>` (default `rewrite/clean`) and it passes.
