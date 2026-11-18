//! C numeric semantics of an MSVC-built x86 game, for a Rust translation that must behave bit for bit.
//!
//! * `rand`/`srand`: the MSVC CRT's generator (per thread, seed 1).
//! * `ftol`: `(int) x` of a float/double as MSVC code does it (`__ftol2_sse`, `__ftol2`, `cvttsd2si`,
//!   `fistp` with truncation): toward zero, and 0x80000000 ("integer indefinite") for NaN and values out of
//!   range, where Rust's `as i32` saturates.
//! * `c_clamp`/`c_min`/`c_max`/`c_abs`: the C macros and functions without Rust's panics (`Ord::clamp` panics
//!   when min > max, `i32::abs` overflows on `i32::MIN`). Macros evaluate an argument more than once: when an
//!   argument has a side effect (a call to `rand()`), evaluate it as often as the macro does instead of
//!   calling these (references/rust.md).
//! * `schar`, `trunc_u8`, `trunc_i16`: `char` is signed in MSVC; stores into narrow types truncate.
//!
//! x87 float evaluation (VS2010 and older default; check the binary): compute expressions in `f64` and
//! round to `f32` only where C stores a float, passes or returns one, or casts `(float)`. SSE2 builds
//! (`/arch:SSE2`, VS2012+ default) round every float operation to `f32`: then compute in `f32`.
//!
//! Generic template of the game-rewrite skill: copy into the crate (e.g. `src/cnum.rs`).

use std::cell::Cell;

/// RAND_MAX of the MSVC CRT.
pub const RAND_MAX: i32 = 0x7fff;

thread_local! {
    /// `_getptd()->_holdrand`: one state per thread, 1 in a new thread.
    static HOLDRAND: Cell<u32> = const { Cell::new(1) };
}

/// MSVC `rand()`: `holdrand = holdrand * 214013 + 2531011; return (holdrand >> 16) & 0x7fff`.
/// The number and order of calls is behaviour: keep every call of the original, renders included.
pub fn rand() -> i32 {
    HOLDRAND.with(|h| {
        let next = h.get().wrapping_mul(214013).wrapping_add(2531011);
        h.set(next);
        ((next >> 16) & 0x7fff) as i32
    })
}

/// MSVC `srand(seed)`.
pub fn srand(seed: u32) {
    HOLDRAND.with(|h| h.set(seed));
}

/// `(int) x` for a floating value (pass floats as `x as f64`: exact). Truncates toward zero; NaN and
/// values outside the int range give `i32::MIN` like the x86 conversion instructions.
#[inline]
pub fn ftol(x: f64) -> i32 {
    if x.is_nan() || x >= 2147483648.0 || x <= -2147483649.0 {
        i32::MIN
    } else {
        x as i32
    }
}

/// `(unsigned char) x` / `(Uint8) x` of a floating value: the int conversion, then the low byte.
#[inline]
pub fn ftol_u8(x: f64) -> u8 {
    ftol(x) as u8
}

/// `(unsigned int) x` of a floating value as VS2010-era x86 code does it: a 64-bit conversion (`__ftol2`)
/// whose low 32 bits are kept, so -1.0 gives 0xffffffff and values beyond the 64-bit range give 0. Newer CRTs
/// use other helpers (`__ftoui3`): read the call in the binary before relying on out-of-range results.
#[inline]
pub fn ftoui(x: f64) -> u32 {
    if x.is_nan() || x >= 9223372036854775808.0 || x <= -9223372036854775809.0 {
        0
    } else {
        (x as i64) as u32
    }
}

/// `SDL_clamp`-style `x < a ? a : (x > b ? b : x)` (never panics).
#[inline]
pub fn c_clamp<T: PartialOrd>(x: T, a: T, b: T) -> T {
    if x < a {
        a
    } else if x > b {
        b
    } else {
        x
    }
}

/// `x < y ? x : y` (the C macro's choice when the values are equal or unordered).
#[inline]
pub fn c_min<T: PartialOrd>(x: T, y: T) -> T {
    if x < y {
        x
    } else {
        y
    }
}

/// `x > y ? x : y`.
#[inline]
pub fn c_max<T: PartialOrd>(x: T, y: T) -> T {
    if x > y {
        x
    } else {
        y
    }
}

/// C `abs(int)`: `abs(INT_MIN)` is `INT_MIN` on x86.
#[inline]
pub fn c_abs(x: i32) -> i32 {
    x.wrapping_abs()
}

/// A C `char` (signed in MSVC) read as an int: bytes 0x80..0xff are negative.
#[inline]
pub fn schar(b: u8) -> i32 {
    b as i8 as i32
}

/// Store of an int into `unsigned char`: keeps the low byte.
#[inline]
pub fn trunc_u8(x: i32) -> u8 {
    x as u8
}

/// Store of an int into `short`: keeps the low 16 bits.
#[inline]
pub fn trunc_i16(x: i32) -> i16 {
    x as i16
}

/// C `a << n` on x86: the count is masked to 5 bits (C leaves larger counts undefined).
#[inline]
pub fn c_shl(a: i32, n: i32) -> i32 {
    a.wrapping_shl(n as u32)
}

/// C `a >> n` of a signed int on x86: arithmetic shift, count masked to 5 bits.
#[inline]
pub fn c_shr(a: i32, n: i32) -> i32 {
    a.wrapping_shr(n as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msvc_rand_sequence() {
        srand(1);
        assert_eq!([rand(), rand(), rand(), rand(), rand()], [41, 18467, 6334, 26500, 19169]);
        srand(1);
        assert_eq!(rand(), 41);
    }

    #[test]
    fn rand_is_per_thread() {
        srand(1);
        let _ = rand();
        let other = std::thread::spawn(rand).join().unwrap();
        assert_eq!(other, 41);
    }

    #[test]
    fn ftol_like_x86() {
        assert_eq!(ftol(2.9), 2);
        assert_eq!(ftol(-2.9), -2);
        assert_eq!(ftol(f64::NAN), i32::MIN);
        assert_eq!(ftol(3e9), i32::MIN);
        assert_eq!(ftol(-2147483648.9), i32::MIN + 0);
        assert_eq!(ftol(-2147483649.0), i32::MIN);
        assert_eq!(ftol(2147483647.9), i32::MAX);
        assert_eq!(ftol_u8(300.5), 44);
        assert_eq!(ftol_u8(-1.0), 255);
        assert_eq!(ftoui(4294967295.0), u32::MAX);
        assert_eq!(ftoui(-1.0), u32::MAX);
    }

    #[test]
    fn c_helpers() {
        assert_eq!(c_clamp(5, 10, 0), 10);
        assert_eq!(c_min(1.0, f32::NAN).is_nan(), true);
        assert_eq!(c_max(2, 3), 3);
        assert_eq!(c_abs(i32::MIN), i32::MIN);
        assert_eq!(schar(0xe9), -23);
        assert_eq!(trunc_u8(257), 1);
        assert_eq!(trunc_i16(70000), 4464);
        assert_eq!(c_shl(1, 33), 2);
        assert_eq!(c_shr(-8, 1), -4);
    }

    #[test]
    fn x87_vs_sse_example() {
        // x87: (a * b) / c in extended precision, rounded once at the store
        let (a, b, c) = (16777217.0f64, 3.0f32, 3.0f32);
        let x87 = ((a * b as f64) / c as f64) as f32;
        // SSE2: every step rounded to float
        let sse = (((a as f32) * b) / c) as f32;
        assert_eq!(x87, 16777216.0);
        assert_eq!(sse, 16777216.0);
        let (p, q) = (0.1f32, 3.0f32);
        let x87b = (p as f64 * q as f64 - 0.3f32 as f64) as f32;
        let sseb = p * q - 0.3f32;
        assert_ne!(x87b.to_bits(), sseb.to_bits());
    }
}
