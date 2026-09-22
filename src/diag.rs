//! Compiler diagnostic-note routing.
//!
//! The `note:` lines emitted during codegen — the deferred/pruned inline
//! forest (S4.2h/S4.2q) and the not-yet-instantiable template calls (S4.2g) —
//! are *informational*, not errors: the build still succeeds. On a large
//! translation unit (OWL/BIDS) they run to hundreds of function names per file
//! and drown the terminal.
//!
//! By default a note goes straight to stderr, which keeps `bcc`, the test
//! suite, and every byte-identity fixture behaving exactly as before. The
//! `mdbcc` project driver instead calls [`begin_capture`], collecting the notes
//! into an in-memory tally so it can spill them to a build log and print a
//! single one-line summary. [`end_capture`] restores the stderr default.
//!
//! The sink is thread-local: the project driver compiles translation units on
//! worker threads (`project::build_manifest`), and each thread captures its own
//! notes, so a note is recorded lock-free with no cross-TU interleaving. `bcc`
//! and the test suite run on a single thread and see the stderr default.

use std::cell::RefCell;

/// Which bucket a note counts toward in the one-line driver summary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoteKind {
    /// Work the compiler put off (S4.2g template calls, S4.2h inline bodies).
    Deferred,
    /// Vague-linkage inline bodies skipped as unreachable (S4.2q).
    Pruned,
}

/// Running totals plus the not-yet-flushed note lines (capture mode).
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct NoteTally {
    pub deferred: usize,
    pub pruned: usize,
    lines: Vec<String>,
}

impl NoteTally {
    /// Total number of functions mentioned across every captured note.
    pub fn total(&self) -> usize {
        self.deferred + self.pruned
    }
}

enum Sink {
    /// Default: pass notes straight to stderr (legacy behaviour).
    Stderr,
    /// Driver mode: accumulate counts and pending lines.
    Capture(NoteTally),
}

thread_local! {
    /// Per-thread note sink. Thread-local (not a global `Mutex`) so the parallel
    /// project build — one worker thread per translation unit — keeps each TU's
    /// notes separate and lock-free; `note()` never contends. A single-threaded
    /// caller (`bcc`, the tests) sees the stderr default.
    static SINK: RefCell<Sink> = const { RefCell::new(Sink::Stderr) };
}

/// Record one diagnostic note. `count` is the number of functions the note
/// covers (used for the summary buckets); `line` is the full, already-formatted
/// text — written verbatim to the build log in capture mode, or to stderr
/// otherwise.
pub fn note(kind: NoteKind, count: usize, line: impl Into<String>) {
    let line = line.into();
    SINK.with_borrow_mut(|sink| match sink {
        Sink::Stderr => eprintln!("{line}"),
        Sink::Capture(tally) => {
            match kind {
                NoteKind::Deferred => tally.deferred += count,
                NoteKind::Pruned => tally.pruned += count,
            }
            tally.lines.push(line);
        }
    });
}

/// Switch the sink into capture mode, discarding any prior capture state.
pub fn begin_capture() {
    SINK.with_borrow_mut(|sink| *sink = Sink::Capture(NoteTally::default()));
}

/// Take the note lines accumulated so far, leaving the running counts intact.
/// Lets the driver spill notes to the log between files without holding the
/// whole forest in memory. Returns empty when not capturing.
pub fn drain_lines() -> Vec<String> {
    SINK.with_borrow_mut(|sink| match sink {
        Sink::Capture(tally) => std::mem::take(&mut tally.lines),
        Sink::Stderr => Vec::new(),
    })
}

/// Restore the stderr default and return the final tally (counts only; any
/// un-drained lines are returned too). Returns an empty tally if capture was
/// never started.
pub fn end_capture() -> NoteTally {
    SINK.with_borrow_mut(|sink| match std::mem::replace(sink, Sink::Stderr) {
        Sink::Capture(tally) => tally,
        Sink::Stderr => NoteTally::default(),
    })
}

/// RAII capture session: [`begin_capture`] on construction, [`end_capture`] on
/// drop. This is the safe way to capture — an early `return` *or a panic* that
/// unwinds past it still restores the stderr default, so the process-global
/// sink can never get stuck in capture mode and silently swallow a later
/// build's notes. Use [`Capture::finish`] on the success path to read the
/// final tally exactly once (which disarms the drop).
pub struct Capture {
    armed: bool,
}

impl Capture {
    pub fn begin() -> Self {
        begin_capture();
        Self { armed: true }
    }

    /// Normal-path completion: return the final tally and disarm the guard so
    /// drop does not call [`end_capture`] a second time.
    pub fn finish(mut self) -> NoteTally {
        self.armed = false;
        end_capture()
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if self.armed {
            let _ = end_capture();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The sink is thread-local, so tests on different threads are already
    // isolated; this lock just keeps the begin/note/end sequences from
    // interleaving if the harness ever reuses a worker thread across tests.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn capture_buckets_and_drains() {
        let _g = TEST_LOCK.lock().unwrap();
        begin_capture();
        note(NoteKind::Deferred, 5, "note: deferred 5 fn(s)");
        note(NoteKind::Pruned, 686, "note: pruned 686 fn(s)");
        note(NoteKind::Deferred, 3, "note: deferred 3 inline fn(s)");

        let lines = drain_lines();
        assert_eq!(lines.len(), 3);
        assert!(drain_lines().is_empty(), "drain should leave the buffer empty");

        let tally = end_capture();
        assert_eq!(tally.deferred, 8);
        assert_eq!(tally.pruned, 686);
        assert_eq!(tally.total(), 694);
    }

    #[test]
    fn end_without_begin_is_empty() {
        let _g = TEST_LOCK.lock().unwrap();
        // Make sure we are not mid-capture from another test ordering.
        let _ = end_capture();
        let tally = end_capture();
        assert_eq!(tally, NoteTally::default());
    }

    #[test]
    fn capture_guard_finish_returns_tally_once() {
        let _g = TEST_LOCK.lock().unwrap();
        let cap = Capture::begin();
        note(NoteKind::Pruned, 5, "note: pruned 5");
        let tally = cap.finish();
        assert_eq!(tally.pruned, 5);
        // After finish() the sink is back to stderr: a second end_capture sees
        // nothing (proves finish disarmed the drop — no double end_capture).
        assert_eq!(end_capture(), NoteTally::default());
    }

    #[test]
    fn capture_guard_restores_on_drop() {
        let _g = TEST_LOCK.lock().unwrap();
        {
            let _cap = Capture::begin();
            note(NoteKind::Deferred, 1, "note: deferred 1");
            // dropped here without finish() — must restore stderr default
        }
        // Already restored, so end_capture finds the default (not a stuck
        // Capture holding the deferred note above).
        assert_eq!(end_capture(), NoteTally::default());
    }
}
