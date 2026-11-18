//! `stub!(address, "C++ name")`: the body of a function that is not translated yet, plus the program's
//! log file and the panic hook.
//!
//! A generated stub (gen_skeleton.py) logs `unimplemented: 0x<address> <C++ name>` the first time it runs and
//! returns `Default::default()`, so the program keeps running while the translation is incomplete; the log of
//! a harness run lists the stubs a scenario reaches, in order. `grep -rn 'stub!(0x' src | wc -l` counts
//! what is left.
//!
//! The program is built with `panic = "abort"` and is a GUI program without a console, so a panic would
//! vanish without a trace: `install_panic_hook` writes the message and location to the log first.
//! Call `stub::init_log("<GAME>_RUST_LOG")` and `stub::install_panic_hook()` at the start of `main`.
//!
//! Generic template of the game-rewrite skill: copy into `src/stub.rs`, declare `mod stub;` in `main.rs`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

static LOG: Mutex<Option<File>> = Mutex::new(None);

/// Opens (appends to) the file named by the environment variable `var`, if it is set.
pub fn init_log(var: &str) {
    if let Some(path) = std::env::var_os(var) {
        if let Ok(f) = OpenOptions::new().create(true).append(true).open(path) {
            if let Ok(mut g) = LOG.lock() {
                *g = Some(f);
            }
        }
    }
}

/// One line to stderr and, when open, to the log file.
pub fn log(line: &str) {
    eprintln!("{}", line);
    if let Ok(mut g) = LOG.lock() {
        if let Some(f) = g.as_mut() {
            let _ = writeln!(f, "{}", line);
            let _ = f.flush();
        }
    }
}

/// Writes a panic's message and location to the log before the process aborts.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let text = format!("[panic] {}", info);
        eprintln!("{}", text);
        // try_lock: the panic may have happened while the log was being written
        if let Ok(mut g) = LOG.try_lock() {
            if let Some(f) = g.as_mut() {
                let _ = writeln!(f, "{}", text);
                let _ = f.flush();
            }
        }
    }));
}

/// What `stub!` reports (once per function).
pub fn unimplemented(address: u32, name: &str) {
    log(&format!("unimplemented: {:#x} {}", address, name));
}

/// The body of a function not translated yet: logs once, then returns `Default::default()`.
#[macro_export]
macro_rules! stub {
    ($addr:expr, $name:expr) => {{
        static ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !ONCE.swap(true, std::sync::atomic::Ordering::Relaxed) {
            $crate::stub::unimplemented($addr as u32, $name);
        }
        #[allow(unreachable_code)]
        Default::default()
    }};
}

#[cfg(test)]
mod tests {
    fn not_done(x: i32) -> i32 {
        let _ = x;
        crate::stub!(0x401000, "Game::not_done")
    }

    fn not_done_unit() {
        crate::stub!(0x401010, "Game::not_done_unit")
    }

    #[test]
    fn stub_returns_default() {
        assert_eq!(not_done(5), 0);
        assert_eq!(not_done(6), 0);
        not_done_unit();
    }
}
