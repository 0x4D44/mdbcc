//! Phase H9: adjacent string-literal concatenation (C89 §6.4.5 /
//! translation phase 6).
//!
//! Two or more string literals separated only by whitespace, line
//! splices, or comments are concatenated into one. The transformation
//! happens at the lexer so the parser sees a single `Str` token — no
//! AST or parser change is required.
//!
//! Coverage:
//!   * 2-way / 3-way / multi-line via newline / through a /*comment*/.
//!   * Escape sequences honoured fragment-locally; bytes joined verbatim.
//!   * Initialiser context: `const char s[] = "ab" "cd";` (the global-init
//!     case the HLD calls out — exercises the parser declaration path,
//!     not just the expression path).
//!   * Single-fragment regression: the concat path is a no-op when no
//!     adjacent literal follows.
//!   * cl /MT differential for two representative programs.

#![cfg(windows)]

mod support;

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::compile_to_pe;
use support::{Lang, msvc_ref, normalize_newlines, o2_active};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);
impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn build(src: &str) -> TempExe {
    let exe = compile_to_pe(src.as_bytes()).expect("mdbcc compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_strcat_{}_{}.exe", std::process::id(), n));
    let t = TempExe(p);
    std::fs::write(&t.0, &exe).expect("write exe");
    t
}

fn out(src: &str) -> (String, i32) {
    let t = build(src);
    let o = Command::new(&t.0).output().expect("launch");
    let s = String::from_utf8_lossy(&o.stdout).into_owned();
    let c = o.status.code().expect("exit code");
    (s, c)
}

/// Behavioural differential against `cl /MT`: compile the same source with
/// MSVC, run it, assert stdout (after `\r\n` → `\n` normalisation) and
/// exit-code match. cl absent ⇒ silent skip (the mdbcc-side assertion has
/// already run in the caller).
fn differential_against_cl(src: &str, mdbcc_stdout: &str, mdbcc_exit: i32) {
    if !o2_active() {
        return;
    }
    let r = msvc_ref(src, Lang::C);
    if !r.launched {
        return;
    }
    let cl_stdout = String::from_utf8_lossy(&normalize_newlines(&r.stdout)).into_owned();
    assert_eq!(
        cl_stdout, mdbcc_stdout,
        "cl differential FAIL (stdout): cl={cl_stdout:?} mdbcc={mdbcc_stdout:?}"
    );
    assert_eq!(
        r.exit,
        Some(mdbcc_exit),
        "cl differential FAIL (exit): cl={:?} mdbcc={mdbcc_exit}",
        r.exit
    );
}

// ---- Behavioural tests ----------------------------------------------------

#[test]
fn two_adjacent_strings_in_call_arg() {
    // printf("ab" "cd") must observe a single "abcd" argument.
    let src = "#include <stdio.h>\n\
               int main(void) { printf(\"ab\" \"cd\"); return 0; }\n";
    let (s, c) = out(src);
    assert_eq!(s, "abcd");
    assert_eq!(c, 0);
    differential_against_cl(src, &s, c);
}

#[test]
fn three_adjacent_strings_in_call_arg() {
    let src = "#include <stdio.h>\n\
               int main(void) { printf(\"a\" \"b\" \"c\"); return 0; }\n";
    let (s, c) = out(src);
    assert_eq!(s, "abc");
    assert_eq!(c, 0);
    differential_against_cl(src, &s, c);
}

#[test]
fn multi_line_string_concat_via_newline() {
    // The line-continuation idiom: two fragments separated by a real newline.
    let src = "#include <stdio.h>\n\
               int main(void) {\n\
                   printf(\"hello \"\n\
                          \"world\");\n\
                   return 0;\n\
               }\n";
    let (s, c) = out(src);
    assert_eq!(s, "hello world");
    assert_eq!(c, 0);
}

#[test]
fn escapes_survive_concatenation() {
    // \n in the first fragment must be a literal newline in the merged
    // string — escapes are resolved per fragment, then joined.
    let src = "#include <stdio.h>\n\
               int main(void) { printf(\"a\\n\" \"b\"); return 0; }\n";
    let (s, c) = out(src);
    assert_eq!(s, "a\nb");
    assert_eq!(c, 0);
}

#[test]
fn global_array_initialiser_concatenates() {
    // const char s[] = "ab" "cd"; — exercises the parser declaration init
    // path (Parser::initializer line ~1418), which historically consumed
    // only ONE string token. With H9 the lexer merges first, so this path
    // sees a single `Str { bytes: "abcd" }` regardless.
    let src = "#include <stdio.h>\n\
               const char s[] = \"ab\" \"cd\";\n\
               int main(void) { printf(\"%s\", s); return 0; }\n";
    let (s, c) = out(src);
    assert_eq!(s, "abcd");
    assert_eq!(c, 0);
}

#[test]
fn single_fragment_unchanged_regression() {
    // No adjacent literal follows ⇒ concat loop is a no-op. Guards the
    // "leave-it-green" contract: end_to_end byte-identical relies on the
    // non-concat path being exactly the pre-H9 behaviour.
    let src = "#include <stdio.h>\n\
               int main(void) { printf(\"abc\"); return 0; }\n";
    let (s, c) = out(src);
    assert_eq!(s, "abc");
    assert_eq!(c, 0);
}

#[test]
fn concat_across_block_comment() {
    // Standard C: a block comment between fragments is whitespace, so
    // "a" /*x*/ "b" concatenates. Our lexer's `skip_trivia` already
    // handles comments, so the concat-peek treats them the same.
    let src = "#include <stdio.h>\n\
               int main(void) { printf(\"a\" /* mid */ \"b\"); return 0; }\n";
    let (s, c) = out(src);
    assert_eq!(s, "ab");
    assert_eq!(c, 0);
}

// ---- Wide-string rejection (MAJOR-1 from Phase H code review) -------------
//
// #53: wide-string literals (`L"..."`) are now SUPPORTED. The H9 lexer carries
// a `wide` flag on `TokenKind::Str`; the parser encodes the body to UTF-16LE and
// produces `Expr::WideStr` (type `wchar_t[n]`), and codegen emits the UTF-16
// bytes. Both parser consumption sites — the initializer arm
// (`const wchar_t *s = L"abc";`) and the primary-expression arm — are exercised
// here; value-level RUN coverage lives in `end_to_end::wide_string_literals`.
// (Earlier this pair PINNED the loud rejection that replaced an even-earlier
// silent narrow-miscompile; the feature now supersedes the rejection.)

#[test]
fn wide_string_in_expression_position_compiles() {
    // A wide literal used as a `const wchar_t*` expression compiles.
    let src = "int main(void) { const wchar_t* p = L\"ABC\"; return (int)p[0]; }";
    compile_to_pe(src.as_bytes())
        .expect("a wide string literal in expression position must now compile");
}

#[test]
fn wide_string_in_initializer_position_compiles() {
    // The initializer arm is a separate parser path from the expression arm.
    let src = "const wchar_t *s = L\"abc\"; int main(void) { return (int)s[0]; }";
    compile_to_pe(src.as_bytes())
        .expect("a wide string literal in initializer position must now compile");
}
