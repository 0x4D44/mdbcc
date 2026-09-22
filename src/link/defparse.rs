//! S1c.9 — minimum-viable `.def` file parser (module-definition files).
//!
//! Per HLD §6: recognise `NAME`, `DESCRIPTION`, `STACKSIZE`, `HEAPSIZE`,
//! and `EXPORTS` (with `<name>[=<internal>][@<ordinal>][NONAME][DATA]`
//! decoration). For S1c minimum viable: parse + honour
//! `STACKSIZE`/`HEAPSIZE` (override the `LinkOpts` values during link),
//! store `EXPORTS` for S8 DLL output, accept everything else
//! syntactically with a no-op.
//!
//! Format reference: Microsoft Module-Definition File documentation
//! (link.exe `/DEF:` source). Borland TLINK32 accepts a near-identical
//! superset; we target the MS-compatible intersection.

use std::fmt;

/// Parsed representation of one `.def` file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefFile {
    /// `NAME <module-name>` — the output module name (usually the .exe
    /// basename). For .exe outputs we honour but don't enforce; for DLL
    /// output (S8) this is the DLL name in its export header.
    pub name: Option<String>,
    /// `DESCRIPTION "<text>"` — informational string baked into the
    /// PE description directory (S8 DLL feature; stored for future use).
    pub description: Option<String>,
    /// `STACKSIZE <reserve>[,<commit>]` — stack reserve + optional
    /// commit (in bytes). Applied to `LinkOpts` during link if present.
    pub stack_reserve: Option<u64>,
    pub stack_commit: Option<u64>,
    /// `HEAPSIZE <reserve>[,<commit>]` — heap reserve + optional commit.
    pub heap_reserve: Option<u64>,
    pub heap_commit: Option<u64>,
    /// `EXPORTS` entries. Stored for S8 DLL output; the linker does
    /// nothing with them today (.exe outputs have no export table).
    pub exports: Vec<DefExport>,
}

/// One `EXPORTS` entry: `<name>[=<internal>][@<ordinal>][NONAME][DATA]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefExport {
    /// External name (as seen by importers).
    pub name: String,
    /// Internal name being exported under the external name (renaming).
    /// `EXPORTS foo=_real_foo` → `Some("_real_foo")`. None when no `=`.
    pub internal: Option<String>,
    /// Ordinal slot. `EXPORTS foo @1` → `Some(1)`. None when ordinal
    /// is left to the linker.
    pub ordinal: Option<u16>,
    /// `NONAME` suffix — present only in the ordinal table, not the
    /// name table. (Reduces DLL size.)
    pub noname: bool,
    /// `DATA` suffix — export is a data symbol, not a function.
    pub data: bool,
}

#[derive(Debug)]
pub enum DefParseError {
    /// Generic parse failure with a 1-based line number + message.
    Syntax { line: u32, message: String },
}

impl fmt::Display for DefParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DefParseError::Syntax { line, message } => {
                write!(f, "line {line}: {message}")
            }
        }
    }
}

impl std::error::Error for DefParseError {}

/// Parse a `.def` file's text into a [`DefFile`]. Returns the first
/// syntax error encountered; everything after a failed line is skipped.
pub fn parse(text: &str) -> Result<DefFile, DefParseError> {
    let mut def = DefFile::default();
    let mut in_exports = false;
    for (line_idx, raw) in text.lines().enumerate() {
        let line_no = (line_idx + 1) as u32;
        // Strip `;` comments and trim. (TLINK32 also allows `//` but
        // we mirror MS link.exe and accept only `;`.)
        let stripped = raw.split(';').next().unwrap_or("").trim();
        if stripped.is_empty() {
            continue;
        }
        let keyword_upper = stripped
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        match keyword_upper.as_str() {
            "EXPORTS" => {
                in_exports = true;
                continue;
            }
            "NAME" => {
                in_exports = false;
                let rest = stripped[4..].trim();
                if !rest.is_empty() {
                    // `NAME <module>` — take the first whitespace token.
                    let name = rest.split_whitespace().next().unwrap_or("");
                    def.name = Some(strip_quotes(name).to_string());
                }
            }
            "DESCRIPTION" => {
                in_exports = false;
                let rest = stripped[11..].trim();
                def.description = Some(strip_quotes(rest).to_string());
            }
            "STACKSIZE" => {
                in_exports = false;
                let (r, c) = parse_size_pair(&stripped[9..], line_no)?;
                def.stack_reserve = Some(r);
                def.stack_commit = c;
            }
            "HEAPSIZE" => {
                in_exports = false;
                let (r, c) = parse_size_pair(&stripped[8..], line_no)?;
                def.heap_reserve = Some(r);
                def.heap_commit = c;
            }
            // Recognised but ignored (HLD §6 — store for future use,
            // S1c.9 doesn't act on them).
            "LIBRARY" | "VERSION" | "SECTIONS" | "SEGMENTS" | "STUB" | "CODE" | "DATA"
            | "IMPORTS" => {
                in_exports = false;
            }
            _ => {
                if in_exports {
                    def.exports.push(parse_export_entry(stripped, line_no)?);
                }
                // Unknown directive outside EXPORTS: silently ignored
                // (TLINK32 accepts many vendor-specific extensions; we
                // tolerate forward-compatibly).
            }
        }
    }
    Ok(def)
}

/// Parse a single EXPORTS entry: `<name>[=<internal>] [@<ord>] [NONAME] [DATA]`.
fn parse_export_entry(line: &str, line_no: u32) -> Result<DefExport, DefParseError> {
    let mut tokens = line.split_whitespace();
    let first = tokens.next().ok_or_else(|| DefParseError::Syntax {
        line: line_no,
        message: "empty EXPORTS entry".to_string(),
    })?;
    let (name, internal) = if let Some(eq) = first.find('=') {
        (first[..eq].to_string(), Some(first[eq + 1..].to_string()))
    } else {
        (first.to_string(), None)
    };
    let mut export = DefExport {
        name,
        internal,
        ordinal: None,
        noname: false,
        data: false,
    };
    for tok in tokens {
        let tok_upper = tok.to_ascii_uppercase();
        if let Some(ord_str) = tok.strip_prefix('@') {
            let n: u16 = ord_str.parse().map_err(|_| DefParseError::Syntax {
                line: line_no,
                message: format!("bad ordinal '@{ord_str}'"),
            })?;
            export.ordinal = Some(n);
        } else if tok_upper == "NONAME" {
            export.noname = true;
        } else if tok_upper == "DATA" {
            export.data = true;
        } else if tok_upper == "PRIVATE" {
            // Accepted, no-op for S1c.9 — affects export visibility, S8.
        } else {
            return Err(DefParseError::Syntax {
                line: line_no,
                message: format!("unknown EXPORTS modifier '{tok}'"),
            });
        }
    }
    Ok(export)
}

/// Parse `<reserve>[,<commit>]` — both decimal, accept underscore separators.
fn parse_size_pair(s: &str, line_no: u32) -> Result<(u64, Option<u64>), DefParseError> {
    let trimmed = s.trim();
    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.is_empty() || parts[0].is_empty() {
        return Err(DefParseError::Syntax {
            line: line_no,
            message: "STACKSIZE/HEAPSIZE expects <reserve>[,<commit>]".to_string(),
        });
    }
    let reserve = parse_u64(parts[0]).ok_or_else(|| DefParseError::Syntax {
        line: line_no,
        message: format!("bad size value '{}'", parts[0]),
    })?;
    let commit = if parts.len() > 1 && !parts[1].is_empty() {
        Some(parse_u64(parts[1]).ok_or_else(|| DefParseError::Syntax {
            line: line_no,
            message: format!("bad commit value '{}'", parts[1]),
        })?)
    } else {
        None
    };
    Ok((reserve, commit))
}

/// Parse a u64 in decimal or hex (`0x` prefix). Accepts `_` separators.
fn parse_u64(s: &str) -> Option<u64> {
    let cleaned: String = s.chars().filter(|c| *c != '_').collect();
    if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        cleaned.parse().ok()
    }
}

/// Strip a single layer of surrounding double-quotes if present. Returns
/// the inner text trimmed of whitespace.
fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_file() {
        let def = parse("").unwrap();
        assert_eq!(def, DefFile::default());
    }

    #[test]
    fn parses_name_only() {
        let def = parse("NAME mylib\n").unwrap();
        assert_eq!(def.name.as_deref(), Some("mylib"));
    }

    #[test]
    fn parses_description_quoted() {
        let def = parse("DESCRIPTION \"My great library\"\n").unwrap();
        assert_eq!(def.description.as_deref(), Some("My great library"));
    }

    #[test]
    fn parses_stacksize_reserve_only() {
        let def = parse("STACKSIZE 0x200000\n").unwrap();
        assert_eq!(def.stack_reserve, Some(0x200000));
        assert_eq!(def.stack_commit, None);
    }

    #[test]
    fn parses_stacksize_reserve_and_commit() {
        let def = parse("STACKSIZE 4096,1024\n").unwrap();
        assert_eq!(def.stack_reserve, Some(4096));
        assert_eq!(def.stack_commit, Some(1024));
    }

    #[test]
    fn parses_heapsize_with_underscore_separators() {
        let def = parse("HEAPSIZE 1_000_000\n").unwrap();
        assert_eq!(def.heap_reserve, Some(1_000_000));
    }

    #[test]
    fn parses_exports_single_simple_name() {
        let text = "EXPORTS\n  foo\n";
        let def = parse(text).unwrap();
        assert_eq!(def.exports.len(), 1);
        assert_eq!(def.exports[0].name, "foo");
        assert_eq!(def.exports[0].internal, None);
        assert_eq!(def.exports[0].ordinal, None);
        assert!(!def.exports[0].noname);
        assert!(!def.exports[0].data);
    }

    #[test]
    fn parses_exports_with_rename_ordinal_noname_data() {
        let text = "EXPORTS\n  foo=_real_foo @42 NONAME DATA\n";
        let def = parse(text).unwrap();
        assert_eq!(def.exports.len(), 1);
        let e = &def.exports[0];
        assert_eq!(e.name, "foo");
        assert_eq!(e.internal.as_deref(), Some("_real_foo"));
        assert_eq!(e.ordinal, Some(42));
        assert!(e.noname);
        assert!(e.data);
    }

    #[test]
    fn parses_multiple_exports() {
        let text = "EXPORTS\n  foo @1\n  bar @2\n  baz @3 NONAME\n";
        let def = parse(text).unwrap();
        assert_eq!(def.exports.len(), 3);
        assert_eq!(def.exports[0].ordinal, Some(1));
        assert_eq!(def.exports[1].ordinal, Some(2));
        assert_eq!(def.exports[2].ordinal, Some(3));
        assert!(def.exports[2].noname);
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let text = "; this is a comment\n\
                    \n\
                    NAME mylib  ; trailing comment\n\
                    \n\
                    ; another comment\n\
                    EXPORTS\n\
                    ; comment inside exports\n\
                    foo\n";
        let def = parse(text).unwrap();
        assert_eq!(def.name.as_deref(), Some("mylib"));
        assert_eq!(def.exports.len(), 1);
        assert_eq!(def.exports[0].name, "foo");
    }

    #[test]
    fn case_insensitive_keywords() {
        let text = "name MyLib\nexports\n  Foo\n";
        let def = parse(text).unwrap();
        assert_eq!(def.name.as_deref(), Some("MyLib"));
        assert_eq!(def.exports.len(), 1);
        assert_eq!(def.exports[0].name, "Foo");
    }

    #[test]
    fn bad_ordinal_returns_error() {
        let text = "EXPORTS\n  foo @notanumber\n";
        let err = parse(text).expect_err("should reject bad ordinal");
        match err {
            DefParseError::Syntax { line, message } => {
                assert_eq!(line, 2);
                assert!(message.contains("ordinal"), "got: {message}");
            }
        }
    }

    #[test]
    fn unknown_exports_modifier_errors() {
        let text = "EXPORTS\n  foo BOGUS\n";
        let err = parse(text).expect_err("should reject unknown modifier");
        match err {
            DefParseError::Syntax { line, message } => {
                assert_eq!(line, 2);
                assert!(message.contains("BOGUS"), "got: {message}");
            }
        }
    }

    #[test]
    fn library_directive_recognised_and_ignored() {
        // LIBRARY is for DLL-style .def files; we accept it but do
        // nothing with it (DLL output is S8).
        let def = parse("LIBRARY mylib\nEXPORTS\n  foo\n").unwrap();
        assert_eq!(def.exports.len(), 1);
    }

    #[test]
    fn full_def_file_round_trip() {
        let text = "\
            ; Module definition file for the foo library\n\
            NAME foolib\n\
            DESCRIPTION \"foo helper functions\"\n\
            STACKSIZE 0x100000,0x1000\n\
            HEAPSIZE 0x200000\n\
            EXPORTS\n\
              public_foo\n\
              alias=internal_alias @2\n\
              wrapper @3 NONAME DATA\n\
        ";
        let def = parse(text).unwrap();
        assert_eq!(def.name.as_deref(), Some("foolib"));
        assert_eq!(def.description.as_deref(), Some("foo helper functions"));
        assert_eq!(def.stack_reserve, Some(0x100000));
        assert_eq!(def.stack_commit, Some(0x1000));
        assert_eq!(def.heap_reserve, Some(0x200000));
        assert_eq!(def.exports.len(), 3);
        assert_eq!(def.exports[1].internal.as_deref(), Some("internal_alias"));
        assert!(def.exports[2].data);
    }
}
