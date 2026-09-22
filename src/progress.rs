//! Terminal styling and the build-progress reporter for the `mdbcc` driver.
//!
//! No external crates: TTY detection is `std::io::IsTerminal`, colour is raw
//! ANSI SGR, and on Windows we flip `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on the
//! console handles ourselves so the escapes render on classic `conhost` too.
//!
//! The reporter prints a single status line that updates in place (carriage
//! return) as each source moves preprocess -> parse -> codegen, plus a running
//! line counter. When the output is *not* a terminal (piped, redirected, CI,
//! the `tests/project_config.rs` subprocess), it falls back to one plain line
//! per file so logs still show what happened, and emits no escapes.

use std::io::{IsTerminal, Write};
use std::sync::Once;

use crate::compile::CompilePhase;

/// Conditional ANSI painter. Colour is enabled only when the chosen stream is a
/// terminal and `NO_COLOR` is unset; otherwise every helper returns the text
/// untouched, so redirected output stays clean.
#[derive(Clone, Copy)]
pub struct Painter {
    enabled: bool,
}

impl Painter {
    /// Painter for stdout (the final build summary lives there).
    pub fn stdout() -> Self {
        Self {
            enabled: color_enabled(std::io::stdout().is_terminal()),
        }
    }

    /// Painter for stderr (the live progress line lives there).
    pub fn stderr() -> Self {
        Self {
            enabled: color_enabled(std::io::stderr().is_terminal()),
        }
    }

    fn sgr(&self, codes: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{codes}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, t: &str) -> String {
        self.sgr("1", t)
    }
    pub fn dim(&self, t: &str) -> String {
        self.sgr("2", t)
    }
    pub fn red(&self, t: &str) -> String {
        self.sgr("1;31", t)
    }
    pub fn green(&self, t: &str) -> String {
        self.sgr("1;32", t)
    }
    pub fn yellow(&self, t: &str) -> String {
        self.sgr("33", t)
    }
    pub fn cyan(&self, t: &str) -> String {
        self.sgr("1;36", t)
    }
}

fn color_enabled(is_tty: bool) -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if !is_tty {
        return false;
    }
    enable_vt();
    true
}

/// Enable ANSI escape interpretation on the Windows console (idempotent). A
/// no-op on non-Windows and harmless if VT is already on.
#[cfg(windows)]
fn enable_vt() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
        const STD_ERROR_HANDLE: u32 = -12i32 as u32;
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
        unsafe extern "system" {
            fn GetStdHandle(n: u32) -> *mut core::ffi::c_void;
            fn GetConsoleMode(h: *mut core::ffi::c_void, mode: *mut u32) -> i32;
            fn SetConsoleMode(h: *mut core::ffi::c_void, mode: u32) -> i32;
        }
        for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            unsafe {
                let handle = GetStdHandle(which);
                let mut mode = 0u32;
                if GetConsoleMode(handle, &mut mode) != 0 {
                    SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                }
            }
        }
    });
}

#[cfg(not(windows))]
fn enable_vt() {}

fn phase_label(phase: CompilePhase) -> &'static str {
    match phase {
        CompilePhase::Preprocess => "preprocessing",
        CompilePhase::Parse => "parsing",
        CompilePhase::Codegen => "codegen",
    }
}

/// Group digits into thousands with commas: `98765 -> "98,765"`.
pub fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let len = s.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, b) in s.bytes().enumerate() {
        if i != 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

/// Build one status frame: the (optionally coloured) text and its *visible*
/// column width. Pure so the padding maths can be tested without a terminal.
#[allow(clippy::too_many_arguments)]
fn frame(
    paint: &Painter,
    idx_w: usize,
    index: usize,
    total: usize,
    name: &str,
    phase: CompilePhase,
    file_lines: u64,
    lines_total: u64,
) -> (String, usize) {
    let counter = format!("[{index:>idx_w$}/{total}]");
    let phase = phase_label(phase);
    let file_n = fmt_num(file_lines);
    let total_n = fmt_num(lines_total);
    // The plain form is the source of truth for the visible width; colour codes
    // must never be counted against the pad.
    let plain = format!("{counter} {name}  {phase:<13}  {file_n} lines  ({total_n} total)");
    let colored = format!(
        "{} {}  {}  {} {}  ({} {})",
        paint.dim(&counter),
        paint.cyan(name),
        paint.dim(&format!("{phase:<13}")),
        paint.bold(&file_n),
        paint.dim("lines"),
        paint.bold(&total_n),
        paint.dim("total"),
    );
    (colored, plain.chars().count())
}

/// Live per-file build progress. One instance per `build_manifest` run.
pub struct Reporter {
    total: usize,
    index: usize,
    name: String,
    file_lines: u64,
    lines_total: u64,
    phase: CompilePhase,
    tty: bool,
    paint: Painter,
    last_cols: usize,
}

impl Reporter {
    pub fn new(total: usize) -> Self {
        let tty = std::io::stderr().is_terminal();
        if tty {
            enable_vt();
        }
        Self {
            total,
            index: 0,
            name: String::new(),
            file_lines: 0,
            lines_total: 0,
            phase: CompilePhase::Preprocess,
            tty,
            paint: Painter::stderr(),
            last_cols: 0,
        }
    }

    /// Cumulative source lines seen so far.
    pub fn lines_total(&self) -> u64 {
        self.lines_total
    }

    /// Begin a new source. `index` is 1-based; `file_lines` is that file's
    /// line count (added to the running total).
    pub fn start_file(&mut self, index: usize, name: &str, file_lines: u64) {
        self.index = index;
        self.name = name.to_string();
        self.file_lines = file_lines;
        self.lines_total += file_lines;
        self.phase = CompilePhase::Preprocess;
        if self.tty {
            self.render();
        } else {
            // Non-terminal: one durable line per file, announced up front.
            eprintln!(
                "[{:>width$}/{}] {} ({} lines)",
                index,
                self.total,
                name,
                fmt_num(file_lines),
                width = self.total.to_string().len(),
            );
        }
    }

    /// Update the live line as the compiler moves through a phase. No-op when
    /// not attached to a terminal.
    pub fn phase(&mut self, phase: CompilePhase) {
        self.phase = phase;
        if self.tty {
            self.render();
        }
    }

    fn render(&mut self) {
        let idx_w = self.total.to_string().len();
        let (colored, cols) = frame(
            &self.paint,
            idx_w,
            self.index,
            self.total,
            &self.name,
            self.phase,
            self.file_lines,
            self.lines_total,
        );
        // Pad with spaces to erase any leftover from a previously longer line;
        // `cols` is the *visible* width (colour codes excluded) so the maths
        // stays correct whether or not colour is enabled.
        let pad = self.last_cols.saturating_sub(cols);
        self.last_cols = cols;
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "\r{colored}{}", " ".repeat(pad));
        let _ = err.flush();
    }

    /// Erase the live line (terminal mode) ahead of the final summary.
    pub fn finish(&mut self) {
        if self.tty && self.last_cols > 0 {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r{}\r", " ".repeat(self.last_cols));
            let _ = err.flush();
            self.last_cols = 0;
        }
    }

    /// Move the cursor off the live line on the error path so the caller's
    /// message starts on a fresh row.
    pub fn abort(&mut self) {
        if self.tty && self.last_cols > 0 {
            let _ = writeln!(std::io::stderr());
            self.last_cols = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_num_groups_thousands() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(7), "7");
        assert_eq!(fmt_num(42), "42");
        assert_eq!(fmt_num(999), "999");
        assert_eq!(fmt_num(1_234), "1,234");
        assert_eq!(fmt_num(98_765), "98,765");
        assert_eq!(fmt_num(1_000_000), "1,000,000");
    }

    #[test]
    fn painter_disabled_is_passthrough() {
        let p = Painter { enabled: false };
        assert_eq!(p.cyan("LAYOUT.CPP"), "LAYOUT.CPP");
        assert_eq!(p.green("ok"), "ok");
    }

    #[test]
    fn painter_enabled_wraps_sgr() {
        let p = Painter { enabled: true };
        assert_eq!(p.bold("x"), "\x1b[1mx\x1b[0m");
    }

    #[test]
    fn frame_plain_matches_reported_width() {
        // With colour off the rendered text equals the plain form, and the
        // reported column count must equal that text's visible length — this is
        // the invariant the in-place padding relies on.
        let off = Painter { enabled: false };
        let (text, cols) = frame(&off, 2, 12, 47, "LAYOUT.CPP", CompilePhase::Codegen, 1234, 98765);
        assert_eq!(text.chars().count(), cols);
        assert!(text.contains("[12/47]"));
        assert!(text.contains("LAYOUT.CPP"));
        assert!(text.contains("codegen"));
        assert!(text.contains("1,234 lines"));
        assert!(text.contains("(98,765 total)"));
    }

    #[test]
    fn frame_width_ignores_colour_codes() {
        // Colour on must not change the reported (visible) width: a longer line
        // followed by a shorter one is erased by padding computed from this.
        let on = Painter { enabled: true };
        let off = Painter { enabled: false };
        let (_, cols_on) =
            frame(&on, 2, 3, 21, "RAILC.CPP", CompilePhase::Parse, 1370, 1370);
        let (_, cols_off) =
            frame(&off, 2, 3, 21, "RAILC.CPP", CompilePhase::Parse, 1370, 1370);
        assert_eq!(cols_on, cols_off);
    }
}
