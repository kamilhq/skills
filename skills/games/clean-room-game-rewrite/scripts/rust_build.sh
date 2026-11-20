#!/bin/sh
# Build a Rust crate for i686-pc-windows-gnu (32-bit Windows) on macOS or Linux without MinGW.
#
# Usage: rust_build.sh [cargo build args...]   e.g.  rust_build.sh --release --manifest-path rewrite/rust/Cargo.toml
# Run it from the project root. On a Windows PC use the native target instead (cargo build --target
# i686-pc-windows-msvc, with the Visual Studio Build Tools); this script is the cross build.
#
# How: rustc links with the Rust toolchain's own rust-lld (GNU/MinGW flavour, -C linker-flavor=ld.lld) and
# -C link-self-contained=no; the MinGW pieces the target expects (crt startup, libmingw32/libgcc/libgcc_eh,
# kernel32/ntdll/ws2_32/userenv/msvcrt import libraries) come from <rtlib>, made by
# `build_libs.py runtime` (crt shim from rust_gnu/crt_shim.c, import libraries from the .def files).
# There is no unwinder, so panics must abort: -C panic=abort is forced here.
# C libraries are DLLs bound with #[link(name = "...", kind = "raw-dylib", import_name_type = "undecorated")]:
# no import library has to exist; rustc makes one through i686-w64-mingw32-dlltool, which here is the
# stand-in in rust_gnu/bin (rust-lld /lib /def: plus a symbol rewrite, rust_gnu/dlltool.py).
#
# Env: RUST_GNU_RTLIB (default rewrite/third_party/build/rust-gnu/rtlib, relative to the current folder),
#      RUST_GNU_EXTRA_RUSTFLAGS (appended, space-separated), CARGO / RUSTC (default from ~/.cargo/bin or PATH),
#      REWRITE_DLLTOOL=node (use the JavaScript port of the dlltool stand-in).
# If a link fails with "undefined symbol: _Foo@N" (a newer std needing another system function), save the
# output and run: python3 -I <skill>/scripts/rust_gnu/gen_defs.py <saved-output>; then build_libs.py runtime.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
RTLIB=${RUST_GNU_RTLIB:-rewrite/third_party/build/rust-gnu/rtlib}
RTLIB=$(cd "$RTLIB" 2>/dev/null && pwd) || { echo "no runtime at $RTLIB: run build_libs.py runtime" >&2; exit 2; }
[ -f "$RTLIB/libmingw32.a" ] || { echo "no $RTLIB/libmingw32.a: run build_libs.py runtime" >&2; exit 2; }
export PATH="$HOME/.cargo/bin:$PATH"
CARGO=${CARGO:-cargo}
RUSTC=${RUSTC:-rustc}
SYSROOT=$("$RUSTC" --print sysroot)
HOST=$("$RUSTC" -vV | sed -n 's/^host: //p')
LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
[ -x "$LLD" ] || { echo "rust-lld not found at $LLD" >&2; exit 2; }
TLIB=$("$RUSTC" --print target-libdir --target i686-pc-windows-gnu 2>/dev/null) && [ -d "$TLIB" ] ||
  { echo "target missing: rustup target add i686-pc-windows-gnu" >&2; exit 2; }

export CARGO_TARGET_I686_PC_WINDOWS_GNU_LINKER="$LLD"
export PATH="$HERE/rust_gnu/bin:$PATH" RUST_GNU_LLD="$LLD"
# CARGO_ENCODED_RUSTFLAGS (0x1f-separated) keeps paths with spaces intact; with --target it only applies
# to the target's crates, not to build scripts or proc-macros.
SEP=$(printf '\037')
FLAGS="-Clinker-flavor=ld.lld${SEP}-Clink-self-contained=no${SEP}-Cpanic=abort${SEP}-L${SEP}native=$RTLIB"
for f in ${RUST_GNU_EXTRA_RUSTFLAGS:-}; do FLAGS="$FLAGS$SEP$f"; done
export CARGO_ENCODED_RUSTFLAGS="$FLAGS"
export CARGO_PROFILE_DEV_PANIC=abort CARGO_PROFILE_RELEASE_PANIC=abort
"$CARGO" build --target i686-pc-windows-gnu "$@"
