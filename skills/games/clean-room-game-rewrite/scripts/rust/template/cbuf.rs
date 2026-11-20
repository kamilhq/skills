//! `CBuf<N>`: a C `char buf[N]` (fixed capacity, NUL-terminated, byte-exact truncation).
//!
//! Use it for fixed char arrays of the original (fields, globals, locals the C code truncates into). Writes
//! behave like `strlcpy`/`strlcat`/`snprintf` into the array: at most N-1 bytes are kept, cut at a *byte*
//! boundary as in C. [`CBuf::as_bytes`] gives the exact bytes; [`CBuf::as_str`] gives the longest valid
//! UTF-8 prefix, which differs from C only when a truncation cut a multi-byte character (C keeps the partial
//! bytes): code whose output is compared (saves, traces, rendered text) reads `as_bytes` there.
//!
//! Generic template of the clean-room-game-rewrite skill: copy into `src/cbuf.rs`.

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CBuf<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> CBuf<N> {
    /// An empty buffer (all zero, like C static storage).
    pub const fn new() -> Self {
        Self { bytes: [0; N] }
    }

    /// `strlcpy(buf, s, N)` into a new buffer.
    pub fn from_str(s: &str) -> Self {
        let mut b = Self::new();
        b.set(s);
        b
    }

    /// `strlcpy(buf, s, N)`: copy at most N-1 bytes and terminate; returns the length of `s` like strlcpy.
    /// `snprintf(buf, N, ...)` is `buf.set(&format!(...))`.
    pub fn set(&mut self, s: &str) -> usize {
        self.set_bytes(s.as_bytes())
    }

    /// Byte version of [`CBuf::set`]; stops at an embedded NUL like C.
    pub fn set_bytes(&mut self, s: &[u8]) -> usize {
        let src_len = s.iter().position(|&c| c == 0).unwrap_or(s.len());
        if N == 0 {
            return src_len;
        }
        let n = src_len.min(N - 1);
        self.bytes[..n].copy_from_slice(&s[..n]);
        self.bytes[n] = 0;
        src_len
    }

    /// `strlcat(buf, s, N)`; returns what strlcat returns.
    pub fn push_str(&mut self, s: &str) -> usize {
        self.push_bytes(s.as_bytes())
    }

    /// Byte version of [`CBuf::push_str`].
    pub fn push_bytes(&mut self, s: &[u8]) -> usize {
        let cur = self.len();
        let src_len = s.iter().position(|&c| c == 0).unwrap_or(s.len());
        if N == 0 || cur >= N - 1 {
            return cur + src_len;
        }
        let n = src_len.min(N - 1 - cur);
        self.bytes[cur..cur + n].copy_from_slice(&s[..n]);
        self.bytes[cur + n] = 0;
        cur + src_len
    }

    /// `strlen(buf)`.
    pub fn len(&self) -> usize {
        self.bytes.iter().position(|&c| c == 0).unwrap_or(N)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `buf[0] = '\0'`.
    pub fn clear(&mut self) {
        if N > 0 {
            self.bytes[0] = 0;
        }
    }

    /// The bytes before the NUL.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    /// The whole array, for code that indexes it like C (bytes after the NUL included).
    pub fn raw(&self) -> &[u8; N] {
        &self.bytes
    }

    pub fn raw_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    /// The contents as text: the longest valid UTF-8 prefix (see the module comment).
    pub fn as_str(&self) -> &str {
        let b = self.as_bytes();
        match std::str::from_utf8(b) {
            Ok(s) => s,
            Err(e) => std::str::from_utf8(&b[..e.valid_up_to()]).unwrap_or(""),
        }
    }

    pub const fn capacity(&self) -> usize {
        N
    }
}

impl<const N: usize> Default for CBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Debug for CBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CBuf<{}>({:?})", N, String::from_utf8_lossy(self.as_bytes()))
    }
}

impl<const N: usize> fmt::Display for CBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_like_strlcpy() {
        let mut b = CBuf::<4>::new();
        assert_eq!(b.set("abcdef"), 6);
        assert_eq!(b.as_bytes(), b"abc");
        b.set("a");
        assert_eq!(b.push_str("bcdef"), 6);
        assert_eq!(b.as_str(), "abc");
        b.clear();
        assert!(b.is_empty());
    }

    #[test]
    fn cut_inside_a_character() {
        let mut b = CBuf::<3>::new();
        b.set("a\u{e9}"); // 'a', 0xc3 0xa9: the cut keeps 'a' and 0xc3
        assert_eq!(b.as_bytes(), &[b'a', 0xc3]);
        assert_eq!(b.as_str(), "a");
    }

    #[test]
    fn embedded_nul_stops() {
        let mut b = CBuf::<8>::new();
        assert_eq!(b.set_bytes(b"ab\0cd"), 2);
        assert_eq!(b.as_bytes(), b"ab");
    }
}
