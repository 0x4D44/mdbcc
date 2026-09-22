//! Win64 OWL overlay materialiser.
//!
//! The Win64 OWL build needs six Borland/Microsoft sources carrying mdbcc's
//! static-dispatcher and pointer-width changes. Those originals are
//! copyrighted third-party code, so the repository stores only mdbcc's *own*
//! edits, as unified diffs under `wrk_owl_win64/patches/`. This module applies
//! them to the user's own BC4.52 tree at build time and writes the result into
//! a generated directory laid out exactly as the old checked-in overlay was:
//!
//! ```text
//! <out_dir>/OWL.CPP                  <- SOURCE/OWL/OWL.CPP      + patch
//! <out_dir>/WINDOW.CPP               <- SOURCE/OWL/WINDOW.CPP   + patch
//! <out_dir>/DISPATCH.CPP             <- SOURCE/OWL/DISPATCH.CPP + patch
//! <out_dir>/DIALOG.CPP               <- SOURCE/OWL/DIALOG.CPP   + patch
//! <out_dir>/include64/OWL/DISPATCH.H <- INCLUDE/OWL/DISPATCH.H  + patch
//! <out_dir>/include64/WINDEF.H       <- INCLUDE/WINDEF.H        + patch
//! <out_dir>/include64/STDARG.H       <- copied from wrk_owl_win64 (mdbcc-authored)
//! <out_dir>/mdwin64thunk.h           <- copied from wrk_owl_win64 (mdbcc-authored)
//! ```
//!
//! Each patch names both ends in its headers: `---` is the original's path
//! relative to the BC4.52 root, `+++` is the output's path relative to
//! `out_dir`. The mapping therefore lives in the patches, not in this code.
//!
//! The applier is deliberately strict: every hunk lands at its stated old-line
//! position and every context and deleted line must match exactly. There is no
//! fuzz and no offset search, because a silently-relocated hunk in a compiler's
//! own runtime sources is worse than a hard failure. A mismatch names the
//! patch, the hunk and the source line.
//!
//! Line endings: the BC4.52 sources are CRLF. Matching strips one trailing
//! `\r` per line, and the output is re-joined with the original file's own
//! terminator, so a CRLF input yields a CRLF output.
//!
//! [`materialize`] always regenerates. The whole overlay is ~110 KB of text,
//! so a staleness check would cost more than the work it saves — and a wrong
//! staleness answer would silently compile last week's overlay.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// mdbcc-authored overlay files copied through verbatim, as `/`-separated
/// paths relative to both `wrk_owl_win64/` and `out_dir`.
const OWNED_FILES: &[&str] = &["mdwin64thunk.h", "include64/STDARG.H"];

/// Anything that can stop the overlay being built.
#[derive(Debug)]
pub enum OverlayError {
    /// A filesystem operation failed.
    Io { path: PathBuf, source: io::Error },
    /// `wrk_owl_win64/patches/` is missing or holds no `*.patch`.
    NoPatches(PathBuf),
    /// A patch file is not a unified diff this applier understands.
    Malformed { patch: String, detail: String },
    /// A hunk's context or deleted lines do not match the original.
    Mismatch {
        patch: String,
        hunk: String,
        original: PathBuf,
        line: usize,
        expected: String,
        found: String,
    },
}

impl fmt::Display for OverlayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::NoPatches(dir) => write!(
                f,
                "no `*.patch` files under {} — the Win64 OWL overlay cannot be built",
                dir.display()
            ),
            Self::Malformed { patch, detail } => write!(f, "{patch}: malformed patch: {detail}"),
            Self::Mismatch {
                patch,
                hunk,
                original,
                line,
                expected,
                found,
            } => write!(
                f,
                "{patch}: hunk `{hunk}` does not apply to {} at line {line}: expected `{expected}`, found `{found}`. \
                 The BC4.52 tree does not match the one these patches were cut against.",
                original.display()
            ),
        }
    }
}

impl std::error::Error for OverlayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn io_err(path: &Path, source: io::Error) -> OverlayError {
    OverlayError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The committed overlay sources: the patches plus the mdbcc-authored files.
/// This is what a build-cache fingerprint must hash — never the generated dir.
pub fn source_dir(repo: &Path) -> PathBuf {
    repo.join("wrk_owl_win64")
}

/// The directory holding the unified diffs.
pub fn patches_dir(repo: &Path) -> PathBuf {
    source_dir(repo).join("patches")
}

/// Resolve the user's BC4.52 source tree: `$MDBCC_BC45_ROOT` if set, else the
/// first existing of `<repo>/wrk_oracle/bc452/BC45` or `C:\tmp\bc45`. A
/// candidate counts only if it actually holds `INCLUDE` and `SOURCE/OWL`.
///
/// The tree is third-party and copyrighted, so it is never in the repository;
/// every consumer (the library builder and the OWL/RailC test harnesses) must
/// agree on where to look, which is why this lives here and not in a binary.
pub fn resolve_bc45_root(repo: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(env) = std::env::var_os("MDBCC_BC45_ROOT") {
        candidates.push(PathBuf::from(env));
    }
    candidates.push(repo.join("wrk_oracle").join("bc452").join("BC45"));
    candidates.push(PathBuf::from(r"C:\tmp\bc45"));
    candidates
        .into_iter()
        .find(|root| root.join("INCLUDE").is_dir() && root.join("SOURCE").join("OWL").is_dir())
}

/// Build the Win64 OWL overlay under `out_dir` and return `out_dir`.
///
/// Applies every `wrk_owl_win64/patches/*.patch` to its named original under
/// `bc45_root`, then copies the mdbcc-authored files across. Always
/// regenerates; safe to call on every build.
pub fn materialize(repo: &Path, bc45_root: &Path, out_dir: &Path) -> Result<PathBuf, OverlayError> {
    let patches = patches_dir(repo);
    let mut patch_files: Vec<PathBuf> = match fs::read_dir(&patches) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("patch"))
            })
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(OverlayError::NoPatches(patches));
        }
        Err(e) => return Err(io_err(&patches, e)),
    };
    if patch_files.is_empty() {
        return Err(OverlayError::NoPatches(patches));
    }
    patch_files.sort();

    fs::create_dir_all(out_dir).map_err(|e| io_err(out_dir, e))?;

    for patch_path in &patch_files {
        let name = file_name(patch_path);
        let raw = fs::read(patch_path).map_err(|e| io_err(patch_path, e))?;
        let patch = Patch::parse(&raw, &name)?;
        let original = join_rel(bc45_root, &patch.old_path);
        let bytes = fs::read(&original).map_err(|e| io_err(&original, e))?;
        let patched = patch.apply(&bytes, &original)?;
        let dest = join_rel(out_dir, &patch.new_path);
        write_file(&dest, &patched)?;
    }

    let owned_src = source_dir(repo);
    for rel in OWNED_FILES {
        let from = join_rel(&owned_src, rel);
        let bytes = fs::read(&from).map_err(|e| io_err(&from, e))?;
        write_file(&join_rel(out_dir, rel), &bytes)?;
    }

    Ok(out_dir.to_path_buf())
}

fn write_file(dest: &Path, bytes: &[u8]) -> Result<(), OverlayError> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    }
    fs::write(dest, bytes).map_err(|e| io_err(dest, e))
}

/// Resolve a `/`-separated relative path against `base`.
fn join_rel(base: &Path, rel: &str) -> PathBuf {
    let mut path = base.to_path_buf();
    for part in rel.split('/').filter(|p| !p.is_empty() && *p != ".") {
        path.push(part);
    }
    path
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

// ---- unified-diff model -----------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Context,
    Delete,
    Add,
}

#[derive(Debug)]
struct Hunk {
    /// Verbatim `@@ … @@` header, for error messages.
    header: String,
    /// 1-based first old line the hunk covers (0 when `old_len` is 0).
    old_start: usize,
    old_len: usize,
    lines: Vec<(Op, Vec<u8>)>,
}

#[derive(Debug)]
struct Patch {
    name: String,
    /// `---` header: the original, relative to the BC4.52 root.
    old_path: String,
    /// `+++` header: the output, relative to the overlay's out dir.
    new_path: String,
    hunks: Vec<Hunk>,
}

impl Patch {
    fn parse(raw: &[u8], name: &str) -> Result<Self, OverlayError> {
        let bad = |detail: String| OverlayError::Malformed {
            patch: name.to_string(),
            detail,
        };
        let (lines, _) = split_lines(raw);
        let lines: Vec<&[u8]> = lines.into_iter().map(strip_cr).collect();

        let old_path = header_path(lines.first().copied(), b"--- ")
            .ok_or_else(|| bad("first line is not a `--- <path>` header".to_string()))?;
        let new_path = header_path(lines.get(1).copied(), b"+++ ")
            .ok_or_else(|| bad("second line is not a `+++ <path>` header".to_string()))?;

        let mut hunks = Vec::new();
        let mut i = 2usize;
        while i < lines.len() {
            let line = lines[i];
            if line.is_empty() {
                i += 1;
                continue;
            }
            if !line.starts_with(b"@@") {
                return Err(bad(format!(
                    "line {}: expected a `@@` hunk header, found `{}`",
                    i + 1,
                    show(line)
                )));
            }
            let header = show(line);
            let (old_start, old_len, new_len) = parse_hunk_header(line)
                .ok_or_else(|| bad(format!("line {}: bad hunk header `{header}`", i + 1)))?;
            i += 1;

            let mut body = Vec::new();
            let (mut rem_old, mut rem_new) = (old_len, new_len);
            while rem_old > 0 || rem_new > 0 {
                let Some(line) = lines.get(i).copied() else {
                    return Err(bad(format!("hunk `{header}` is truncated at end of patch")));
                };
                i += 1;
                if line.starts_with(b"\\") {
                    // `\ No newline at end of file`. Supporting it would mean
                    // tracking per-side EOF newline state; no overlay patch
                    // needs it, so refuse loudly rather than guess.
                    return Err(bad(format!(
                        "hunk `{header}`: `{}` is not supported",
                        show(line)
                    )));
                }
                // GNU diff writes a bare space for an empty context line, but
                // trailing whitespace does not survive every editor; treat an
                // empty body line as empty context.
                let (op, text): (Op, &[u8]) = match line.first() {
                    None => (Op::Context, b""),
                    Some(b' ') => (Op::Context, &line[1..]),
                    Some(b'-') => (Op::Delete, &line[1..]),
                    Some(b'+') => (Op::Add, &line[1..]),
                    Some(_) => {
                        return Err(bad(format!(
                            "hunk `{header}`: line {} starts with neither ' ', '-' nor '+': `{}`",
                            i,
                            show(line)
                        )));
                    }
                };
                match op {
                    Op::Context => {
                        rem_old = dec(rem_old, &header, &bad)?;
                        rem_new = dec(rem_new, &header, &bad)?;
                    }
                    Op::Delete => rem_old = dec(rem_old, &header, &bad)?,
                    Op::Add => rem_new = dec(rem_new, &header, &bad)?,
                }
                body.push((op, text.to_vec()));
            }
            hunks.push(Hunk {
                header,
                old_start,
                old_len,
                lines: body,
            });
        }
        if hunks.is_empty() {
            return Err(bad("no hunks".to_string()));
        }
        Ok(Patch {
            name: name.to_string(),
            old_path,
            new_path,
            hunks,
        })
    }

    /// Apply every hunk to `original`, in order, at its stated position.
    /// `original_path` only appears in error messages.
    fn apply(&self, original: &[u8], original_path: &Path) -> Result<Vec<u8>, OverlayError> {
        let (src, trailing_newline) = split_lines(original);
        let crlf = first_terminator_is_crlf(original);
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(src.len() + 64);
        let mut idx = 0usize; // next unconsumed source line, 0-based

        for hunk in &self.hunks {
            // A zero-length old side inserts *after* `old_start`; otherwise
            // `old_start` is the 1-based first line the hunk covers.
            let target = if hunk.old_len == 0 {
                hunk.old_start
            } else {
                hunk.old_start - 1
            };
            if target < idx {
                return Err(OverlayError::Malformed {
                    patch: self.name.clone(),
                    detail: format!(
                        "hunk `{}` starts at line {} but line {} was already consumed — hunks must not overlap",
                        hunk.header,
                        target + 1,
                        idx
                    ),
                });
            }
            if target > src.len() {
                return Err(self.mismatch(hunk, original_path, target + 1, "", "<end of file>"));
            }
            for line in &src[idx..target] {
                out.push(strip_cr(line).to_vec());
            }
            idx = target;

            for (op, text) in &hunk.lines {
                match op {
                    Op::Add => out.push(text.clone()),
                    Op::Context | Op::Delete => {
                        let Some(line) = src.get(idx) else {
                            return Err(self.mismatch(
                                hunk,
                                original_path,
                                idx + 1,
                                &show(text),
                                "<end of file>",
                            ));
                        };
                        let found = strip_cr(line);
                        if found != text.as_slice() {
                            return Err(self.mismatch(
                                hunk,
                                original_path,
                                idx + 1,
                                &show(text),
                                &show(found),
                            ));
                        }
                        if *op == Op::Context {
                            out.push(found.to_vec());
                        }
                        idx += 1;
                    }
                }
            }
        }
        for line in &src[idx..] {
            out.push(strip_cr(line).to_vec());
        }

        let eol: &[u8] = if crlf { b"\r\n" } else { b"\n" };
        let mut bytes = Vec::with_capacity(original.len() + 8192);
        for (n, line) in out.iter().enumerate() {
            if n > 0 {
                bytes.extend_from_slice(eol);
            }
            bytes.extend_from_slice(line);
        }
        if trailing_newline && !out.is_empty() {
            bytes.extend_from_slice(eol);
        }
        Ok(bytes)
    }

    fn mismatch(
        &self,
        hunk: &Hunk,
        original: &Path,
        line: usize,
        expected: &str,
        found: &str,
    ) -> OverlayError {
        OverlayError::Mismatch {
            patch: self.name.clone(),
            hunk: hunk.header.clone(),
            original: original.to_path_buf(),
            line,
            expected: expected.to_string(),
            found: found.to_string(),
        }
    }
}

fn dec(
    n: usize,
    header: &str,
    bad: &impl Fn(String) -> OverlayError,
) -> Result<usize, OverlayError> {
    n.checked_sub(1)
        .ok_or_else(|| bad(format!("hunk `{header}`: line counts exceed the header")))
}

fn header_path(line: Option<&[u8]>, tag: &[u8]) -> Option<String> {
    let line = line?;
    let rest = line.strip_prefix(tag)?;
    // Drop a trailing timestamp column if a generator added one.
    let rest = match rest.iter().position(|b| *b == b'\t') {
        Some(t) => &rest[..t],
        None => rest,
    };
    let text = String::from_utf8_lossy(rest).trim().replace('\\', "/");
    if text.is_empty() { None } else { Some(text) }
}

/// Parse `@@ -old_start[,old_len] +new_start[,new_len] @@ …`, returning
/// `(old_start, old_len, new_len)`.
fn parse_hunk_header(line: &[u8]) -> Option<(usize, usize, usize)> {
    let text = std::str::from_utf8(line).ok()?;
    let inner = text.strip_prefix("@@")?;
    let inner = inner.split("@@").next()?;
    let mut parts = inner.split_whitespace();
    let old = parts.next()?.strip_prefix('-')?;
    let new = parts.next()?.strip_prefix('+')?;
    let (old_start, old_len) = split_range(old)?;
    let (_, new_len) = split_range(new)?;
    if old_len > 0 && old_start == 0 {
        return None;
    }
    Some((old_start, old_len, new_len))
}

fn split_range(text: &str) -> Option<(usize, usize)> {
    match text.split_once(',') {
        Some((start, len)) => Some((start.parse().ok()?, len.parse().ok()?)),
        None => Some((text.parse().ok()?, 1)),
    }
}

/// Split on `\n`, keeping each line's own bytes. Returns the lines and whether
/// the input ended with a terminator.
fn split_lines(data: &[u8]) -> (Vec<&[u8]>, bool) {
    if data.is_empty() {
        return (Vec::new(), false);
    }
    let trailing = data.ends_with(b"\n");
    let body = if trailing {
        &data[..data.len() - 1]
    } else {
        data
    };
    (body.split(|b| *b == b'\n').collect(), trailing)
}

fn strip_cr(line: &[u8]) -> &[u8] {
    match line.strip_suffix(b"\r") {
        Some(rest) => rest,
        None => line,
    }
}

/// Does the file's *first* line terminator carry a `\r`? The BC4.52 sources
/// are uniformly CRLF, so one sample decides the whole file.
fn first_terminator_is_crlf(data: &[u8]) -> bool {
    match data.iter().position(|b| *b == b'\n') {
        Some(0) | None => false,
        Some(i) => data[i - 1] == b'\r',
    }
}

/// Render bytes for a human-readable error, without assuming UTF-8.
fn show(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch_of(body: &str) -> Patch {
        Patch::parse(body.as_bytes(), "test.patch").expect("patch parses")
    }

    fn apply(body: &str, original: &[u8]) -> Result<Vec<u8>, OverlayError> {
        patch_of(body).apply(original, Path::new("ORIG.C"))
    }

    #[test]
    fn applies_a_hunk_in_the_middle_of_a_file() {
        let original = b"alpha\nbravo\ncharlie\ndelta\necho\nfoxtrot\n";
        let out = apply(
            "--- SOURCE/ORIG.C\n\
             +++ ORIG.C\n\
             @@ -2,3 +2,3 @@\n\
             \x20bravo\n\
             -charlie\n\
             +CHARLIE\n\
             \x20delta\n",
            original,
        )
        .expect("hunk applies");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "alpha\nbravo\nCHARLIE\ndelta\necho\nfoxtrot\n"
        );
    }

    #[test]
    fn header_paths_name_both_ends() {
        let patch = patch_of(
            "--- INCLUDE/OWL/DISPATCH.H\n\
             +++ include64/OWL/DISPATCH.H\n\
             @@ -1,1 +1,1 @@\n\
             -a\n\
             +b\n",
        );
        assert_eq!(patch.old_path, "INCLUDE/OWL/DISPATCH.H");
        assert_eq!(patch.new_path, "include64/OWL/DISPATCH.H");
    }

    #[test]
    fn rejects_a_hunk_whose_context_does_not_match() {
        let original = b"alpha\nbravo\ncharlie\n";
        let err = apply(
            "--- SOURCE/ORIG.C\n\
             +++ ORIG.C\n\
             @@ -2,2 +2,2 @@\n\
             -WRONG\n\
             +right\n\
             \x20charlie\n",
            original,
        )
        .expect_err("context mismatch must be rejected");
        match &err {
            OverlayError::Mismatch {
                line,
                expected,
                found,
                hunk,
                ..
            } => {
                assert_eq!(*line, 2, "must name the offending source line");
                assert_eq!(expected, "WRONG");
                assert_eq!(found, "bravo");
                assert_eq!(hunk, "@@ -2,2 +2,2 @@");
            }
            other => panic!("expected a context mismatch, got {other:?}"),
        }
        let text = err.to_string();
        assert!(
            text.contains("ORIG.C"),
            "message must name the file: {text}"
        );
        assert!(
            text.contains("line 2"),
            "message must name the line: {text}"
        );
    }

    #[test]
    fn crlf_input_yields_crlf_output() {
        let original = b"alpha\r\nbravo\r\ncharlie\r\n";
        let out = apply(
            "--- SOURCE/ORIG.C\n\
             +++ ORIG.C\n\
             @@ -1,3 +1,4 @@\n\
             \x20alpha\n\
             +inserted\n\
             \x20bravo\n\
             \x20charlie\n",
            original,
        )
        .expect("hunk applies to a CRLF file");
        assert_eq!(out, b"alpha\r\ninserted\r\nbravo\r\ncharlie\r\n");
        // And an LF original must stay LF.
        let lf = apply(
            "--- SOURCE/ORIG.C\n\
             +++ ORIG.C\n\
             @@ -1,3 +1,4 @@\n\
             \x20alpha\n\
             +inserted\n\
             \x20bravo\n\
             \x20charlie\n",
            b"alpha\nbravo\ncharlie\n",
        )
        .expect("hunk applies to an LF file");
        assert_eq!(lf, b"alpha\ninserted\nbravo\ncharlie\n");
    }

    #[test]
    fn applies_a_hunk_at_end_of_file() {
        let original = b"alpha\r\nbravo\r\ncharlie\r\n";
        let out = apply(
            "--- SOURCE/ORIG.C\n\
             +++ ORIG.C\n\
             @@ -2,2 +2,3 @@\n\
             \x20bravo\n\
             -charlie\n\
             +CHARLIE\n\
             +omega\n",
            original,
        )
        .expect("end-of-file hunk applies");
        assert_eq!(out, b"alpha\r\nbravo\r\nCHARLIE\r\nomega\r\n");
    }

    #[test]
    fn several_hunks_apply_in_order() {
        let original = b"1\n2\n3\n4\n5\n6\n7\n8\n";
        let out = apply(
            "--- SOURCE/ORIG.C\n\
             +++ ORIG.C\n\
             @@ -1,2 +1,2 @@\n\
             -1\n\
             +ONE\n\
             \x202\n\
             @@ -6,2 +6,2 @@\n\
             \x206\n\
             -7\n\
             +SEVEN\n",
            original,
        )
        .expect("both hunks apply");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "ONE\n2\n3\n4\n5\n6\nSEVEN\n8\n"
        );
    }

    #[test]
    fn a_crlf_patch_file_parses() {
        // The repo runs with `core.autocrlf=true`, so a fresh Windows checkout
        // hands the applier CRLF patch files even though they are stored as LF.
        let patch =
            "--- SOURCE/ORIG.C\r\n+++ ORIG.C\r\n@@ -1,2 +1,2 @@\r\n-alpha\r\n+ALPHA\r\n bravo\r\n";
        let out = Patch::parse(patch.as_bytes(), "crlf.patch")
            .expect("a CRLF patch file parses")
            .apply(b"alpha\r\nbravo\r\n", Path::new("ORIG.C"))
            .expect("and applies");
        assert_eq!(out, b"ALPHA\r\nbravo\r\n");
    }

    #[test]
    fn rejects_a_no_newline_marker() {
        let err = Patch::parse(
            b"--- SOURCE/ORIG.C\n+++ ORIG.C\n@@ -1,1 +1,1 @@\n-a\n\\ No newline at end of file\n+b\n",
            "test.patch",
        )
        .expect_err("the no-newline marker is unsupported");
        let text = err.to_string();
        assert!(text.contains("No newline"), "must name the marker: {text}");
        assert!(
            text.contains("is not supported"),
            "must refuse it as unsupported rather than as stray junk: {text}"
        );
    }

    #[test]
    fn rejects_a_hunk_that_runs_past_end_of_file() {
        let err = apply(
            "--- SOURCE/ORIG.C\n\
             +++ ORIG.C\n\
             @@ -3,2 +3,2 @@\n\
             \x20charlie\n\
             -delta\n\
             +DELTA\n",
            b"alpha\nbravo\ncharlie\n",
        )
        .expect_err("a hunk reaching past EOF must be rejected");
        assert!(
            err.to_string().contains("end of file"),
            "message must say the file ended: {err}"
        );
    }

    #[test]
    fn materialize_applies_every_patch_and_copies_owned_files() {
        let dir = std::env::temp_dir().join(format!("mdbcc_overlay_mat_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let repo = dir.join("repo");
        let bc45 = dir.join("bc45");
        let out = dir.join("out");

        fs::create_dir_all(bc45.join("SOURCE").join("OWL")).unwrap();
        fs::write(
            bc45.join("SOURCE").join("OWL").join("OWL.CPP"),
            b"one\r\ntwo\r\nthree\r\n",
        )
        .unwrap();

        let patches = patches_dir(&repo);
        fs::create_dir_all(&patches).unwrap();
        fs::write(
            patches.join("SOURCE-OWL-OWL.CPP.patch"),
            b"--- SOURCE/OWL/OWL.CPP\n+++ OWL.CPP\n@@ -1,2 +1,3 @@\n one\n+MDBCC\n two\n",
        )
        .unwrap();
        fs::create_dir_all(source_dir(&repo).join("include64")).unwrap();
        fs::write(source_dir(&repo).join("mdwin64thunk.h"), b"thunk").unwrap();
        fs::write(
            source_dir(&repo).join("include64").join("STDARG.H"),
            b"stdarg",
        )
        .unwrap();

        let got = materialize(&repo, &bc45, &out).expect("materialize");
        assert_eq!(got, out);
        assert_eq!(
            fs::read(out.join("OWL.CPP")).unwrap(),
            b"one\r\nMDBCC\r\ntwo\r\nthree\r\n"
        );
        assert_eq!(fs::read(out.join("mdwin64thunk.h")).unwrap(), b"thunk");
        assert_eq!(
            fs::read(out.join("include64").join("STDARG.H")).unwrap(),
            b"stdarg"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_patches_dir_is_an_error() {
        let dir = std::env::temp_dir().join(format!("mdbcc_overlay_none_{}", std::process::id()));
        let err = materialize(&dir.join("repo"), &dir.join("bc45"), &dir.join("out"))
            .expect_err("an absent patches dir must fail");
        assert!(matches!(err, OverlayError::NoPatches(_)), "got {err:?}");
    }
}
