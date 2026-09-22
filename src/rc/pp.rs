//! W5 (rc gap 4): the `.rc` PREPROCESSOR — the directive subset a real
//! Borland resource script uses, as a TEXT pass ahead of the lexer:
//!
//! - `#define NAME [value]` — OBJECT macros only (`#define DIGITAL 800`,
//!   RAILC.RC:1). Expanded by whole-identifier substitution in active text
//!   (outside string literals and comments) — Borland rc expands macros in
//!   ID positions, which is exactly how `DIGITAL BITMAP "digital.bmp"`
//!   becomes ordinal #800 (golden-verified).
//! - `#include "file"` — resolved relative to the INCLUDING file's
//!   directory (ABOUTBOX.RC sits next to RAILC.RC), read as raw bytes
//!   (Latin-1 clean) and recursively preprocessed, then spliced inline.
//! - `#ifdef NAME` / `#else` / `#endif` — conditional regions (RAILC.RC's
//!   `#ifdef _DEBUG` VERSIONINFO branch; `_DEBUG` is undefined in the
//!   golden profile, so the `#else` branch is taken).
//!
//! Kept BYTE-oriented end-to-end: the input may be Latin-1 (see
//! `lexer::lex_string`), so no UTF-8 validation happens here. Unknown
//! directives are a loud error — never silently dropped.

use super::RcError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Preprocess `src` (the contents of a file living in `dir`), expanding the
/// directive subset above. `defines` seeds the macro table (the CLI `-D`
/// analogue; empty for the railc golden profile) and accumulates `#define`s
/// as they are seen.
pub fn preprocess(
    src: &[u8],
    dir: &Path,
    defines: &mut HashMap<String, String>,
) -> Result<Vec<u8>, RcError> {
    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    // Conditional stack: each entry = is this region ACTIVE (taking lines)?
    // Parent inactivity propagates (an `#ifdef` inside a dead region is
    // tracked for nesting but never activates).
    let mut conds: Vec<bool> = Vec::new();
    let mut line_no: u32 = 0;

    for line in src.split(|&b| b == b'\n') {
        line_no += 1;
        let active = conds.iter().all(|&a| a);
        let trimmed = trim_ascii(line);
        if let Some(rest) = strip_hash(trimmed) {
            let (word, arg) = split_word(rest);
            match word.as_str() {
                "define" => {
                    if active {
                        let (name, value) = split_word(arg);
                        if name.is_empty() {
                            return err("#define expects a name", line_no);
                        }
                        defines.insert(
                            name,
                            String::from_utf8_lossy(trim_ascii(value)).into_owned(),
                        );
                    }
                }
                "include" => {
                    if active {
                        let arg = trim_ascii(arg);
                        let inner = match (arg.first(), arg.last()) {
                            (Some(b'"'), Some(b'"')) if arg.len() >= 2 => &arg[1..arg.len() - 1],
                            _ => {
                                return err("#include expects a \"file\" form", line_no);
                            }
                        };
                        let rel: PathBuf = String::from_utf8_lossy(inner).into_owned().into();
                        let full = dir.join(&rel);
                        let bytes = std::fs::read(&full).map_err(|e| RcError {
                            message: format!("#include {:?}: {e}", full.display()),
                            line: line_no,
                            col: 1,
                        })?;
                        let sub_dir = full.parent().map(Path::to_path_buf).unwrap_or_default();
                        let expanded = preprocess(&bytes, &sub_dir, defines)?;
                        out.extend_from_slice(&expanded);
                        out.push(b'\n');
                    }
                }
                "ifdef" => {
                    let (name, _) = split_word(arg);
                    conds.push(defines.contains_key(&name));
                }
                "ifndef" => {
                    let (name, _) = split_word(arg);
                    conds.push(!defines.contains_key(&name));
                }
                "else" => match conds.last_mut() {
                    Some(c) => *c = !*c,
                    None => return err("#else without #ifdef", line_no),
                },
                "endif" => {
                    if conds.pop().is_none() {
                        return err("#endif without #ifdef", line_no);
                    }
                }
                "undef" => {
                    if active {
                        let (name, _) = split_word(arg);
                        defines.remove(&name);
                    }
                }
                other => {
                    return err(format!("unknown directive #{other}"), line_no);
                }
            }
            // A directive contributes a blank line so lexer line numbers in
            // diagnostics stay roughly aligned with the source.
            out.push(b'\n');
            continue;
        }
        if !active {
            out.push(b'\n');
            continue;
        }
        substitute_line(line, defines, &mut out);
        out.push(b'\n');
    }
    Ok(out)
}

/// Whole-identifier macro substitution over one ACTIVE line, skipping
/// string literals (`"…"` with `\"` escapes), raw-hex literals (`'…'`) and
/// `//` comments. Identifier = `[A-Za-z_][A-Za-z0-9_]*`, matched exactly
/// (macro names are case-SENSITIVE, like the C preprocessor — brc32
/// folds keywords but not user macros).
fn substitute_line(line: &[u8], defines: &HashMap<String, String>, out: &mut Vec<u8>) {
    let mut i = 0;
    while i < line.len() {
        let b = line[i];
        match b {
            b'"' | b'\'' => {
                let quote = b;
                out.push(b);
                i += 1;
                while i < line.len() {
                    let c = line[i];
                    out.push(c);
                    i += 1;
                    if c == b'\\' && quote == b'"' && i < line.len() {
                        out.push(line[i]);
                        i += 1;
                        continue;
                    }
                    if c == quote {
                        break;
                    }
                }
            }
            b'/' if line.get(i + 1) == Some(&b'/') => {
                out.extend_from_slice(&line[i..]);
                break;
            }
            _ if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                while i < line.len() && (line[i].is_ascii_alphanumeric() || line[i] == b'_') {
                    i += 1;
                }
                let ident = &line[start..i];
                match std::str::from_utf8(ident).ok().and_then(|s| defines.get(s)) {
                    Some(value) => out.extend_from_slice(value.as_bytes()),
                    None => out.extend_from_slice(ident),
                }
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace());
    let end = b.iter().rposition(|c| !c.is_ascii_whitespace());
    match (start, end) {
        (Some(s), Some(e)) => &b[s..=e],
        _ => &[],
    }
}

/// `#  word rest` → Some("word rest") with the leading `#` and surrounding
/// whitespace stripped; None when the line is not a directive.
fn strip_hash(trimmed: &[u8]) -> Option<&[u8]> {
    let rest = trimmed.strip_prefix(b"#")?;
    Some(trim_ascii(rest))
}

/// Split the FIRST whitespace-delimited word off `b` → (word, rest).
fn split_word(b: &[u8]) -> (String, &[u8]) {
    let b = trim_ascii(b);
    let end = b
        .iter()
        .position(|c| c.is_ascii_whitespace())
        .unwrap_or(b.len());
    (
        String::from_utf8_lossy(&b[..end]).into_owned(),
        trim_ascii(&b[end..]),
    )
}

fn err<T>(msg: impl Into<String>, line: u32) -> Result<T, RcError> {
    Err(RcError {
        message: msg.into(),
        line,
        col: 1,
    })
}
