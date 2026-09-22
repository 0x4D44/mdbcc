//! Phase H H4a — exception SYNTAX (`throw` / `try` / `catch`) and the
//! Win64 SEH runtime for integer-only throw/catch.
//!
//! H3 ticked the parser + AST. H4a lights the actual codegen: a `throw
//! <int-expr>;` lowers to `RaiseException(0xE0000001, 0, 1, &slot)`, a
//! `try { … } catch (int <name>) { … }` records a scope-table entry and
//! a catch landing pad, and the PE writer emits `.pdata` + `.xdata` plus
//! a synthesised personality function so the Windows unwinder can
//! transfer control on a match. Class-type catches (`catch (Tag &e)`),
//! `catch (...)`, bare `throw;` (rethrow), and non-int throws are H4b.
//!
//! Test shape:
//!   1-8   parser happy paths — assert the produced AST has the expected
//!         shape (no PE built; in-process). Unchanged from H3.
//!   9-11  parser error paths — assert `Parser::parse` returns Err with
//!         a useful message. Unchanged from H3.
//!   12-14 codegen rejection — H4b-deferred shapes (`catch (Tag&)`,
//!         `catch (...)`, bare `throw;`) reject with H4b-pointing
//!         diagnostics so the H4b brief can find these sites.
//!   15    structural — a TU WITHOUT try/catch emits no `.pdata` /
//!         `.xdata` and `DataDirectory[3]` stays `(0, 0)`. This is the
//!         aggressive-scope contract that keeps non-throwing programs
//!         structurally minimal.
//!   16    structural — a TU WITH try/catch DOES emit `.pdata` /
//!         `.xdata`; `DataDirectory[3]` carries `(pdata_rva,
//!         pdata_size)`; the section table includes both new sections.
//!   17-20 runtime — gated on Windows; compile + run + assert exit code.
//!         These exercise the full SEH path end-to-end (RaiseException →
//!         personality → RtlUnwindEx → catch landing pad). H4a-i may
//!         leave these failing while structural plumbing is locked
//!         down; H4a-ii's job is to make them pass.

use mdbcc::ast::*;
use mdbcc::compile_to_pe;
use mdbcc::lexer::Lexer;
use mdbcc::parser::Parser;

/// Tokenise and parse `src`, panicking on lex/parse failure.
fn parse_ok(src: &str) -> TranslationUnit {
    let toks = Lexer::tokenize(src.as_bytes()).expect("lex ok");
    Parser::parse(&toks).expect("parse ok")
}

/// Parse `src` and return the [`ParseError`] (panics on success — caller
/// only invokes this when an error is expected).
fn parse_err(src: &str) -> mdbcc::parser::ParseError {
    let toks = Lexer::tokenize(src.as_bytes()).expect("lex ok");
    Parser::parse(&toks).expect_err("expected a parse error")
}

/// The (single) body of the function named `main` in `tu`. Test fixtures
/// always put the exception construct under test inside `int main(...)`.
fn main_body(tu: &TranslationUnit) -> &[Stmt] {
    tu.items
        .iter()
        .find_map(|i| match i {
            Item::Func(f) if f.name == "main" => Some(f.body.as_slice()),
            _ => None,
        })
        .expect("main function")
}

// =====================================================================
// Parser happy paths (1-8)
// =====================================================================

/// `throw 1;` → `Stmt::Throw(Some(Expr::Int(1)))`.
#[test]
fn t01_throw_int_literal() {
    let tu = parse_ok("int main(void) { throw 1; return 0; }");
    let body = main_body(&tu);
    assert!(
        matches!(&body[0], Stmt::Throw(Some(Expr::Int(1)), _)),
        "expected Throw(Some(Int(1))), got {:?}",
        body[0]
    );
}

/// Bare `throw;` (a rethrow) → `Stmt::Throw(None, _)`.
/// H3 doesn't check it's inside a `catch` — that's a runtime concern.
#[test]
fn t02_bare_throw_is_rethrow() {
    let tu = parse_ok("int main(void) { throw; return 0; }");
    let body = main_body(&tu);
    assert!(
        matches!(&body[0], Stmt::Throw(None, _)),
        "expected Throw(None), got {:?}",
        body[0]
    );
}

/// `try { } catch (int e) { }` → `Stmt::Try` with empty body + one Typed
/// catch holding the parameter name.
#[test]
fn t03_empty_try_typed_catch_with_name() {
    let tu = parse_ok("int main(void) { try { } catch (int e) { } return 0; }");
    let body = main_body(&tu);
    let (try_body, catches) = match &body[0] {
        Stmt::Try { body, catches, .. } => (body, catches),
        other => panic!("expected Stmt::Try, got {other:?}"),
    };
    assert!(try_body.is_empty(), "try body should be empty");
    assert_eq!(catches.len(), 1);
    match &catches[0].kind {
        CatchKind::Typed { ty, name } => {
            assert_eq!(*ty, Type::int());
            assert_eq!(name.as_deref(), Some("e"));
        }
        other => panic!("expected Typed catch, got {other:?}"),
    }
    assert!(catches[0].body.is_empty(), "catch body should be empty");
}

/// `catch (int) { }` — typed but unnamed. Legal C++ ("match the type but
/// don't bind the value"); name slot is `None`.
#[test]
fn t04_typed_catch_without_name() {
    let tu = parse_ok("int main(void) { try { } catch (int) { } return 0; }");
    let body = main_body(&tu);
    let catches = match &body[0] {
        Stmt::Try { catches, .. } => catches,
        other => panic!("expected Stmt::Try, got {other:?}"),
    };
    assert_eq!(catches.len(), 1);
    match &catches[0].kind {
        CatchKind::Typed { ty, name } => {
            assert_eq!(*ty, Type::int());
            assert!(name.is_none(), "unnamed catch param should be None");
        }
        other => panic!("expected Typed catch, got {other:?}"),
    }
}

/// Multiple typed handlers (`catch (int) … catch (double)`) — H3 parses
/// any number ≥ 1; order is preserved (matters for first-match-wins in
/// H4a/H4b).
#[test]
fn t05_multiple_typed_catches() {
    let tu =
        parse_ok("int main(void) { try { } catch (int e) { } catch (double d) { } return 0; }");
    let catches = match &main_body(&tu)[0] {
        Stmt::Try { catches, .. } => catches,
        other => panic!("expected Stmt::Try, got {other:?}"),
    };
    assert_eq!(catches.len(), 2);
    match &catches[0].kind {
        CatchKind::Typed { ty, name } => {
            assert_eq!(*ty, Type::int());
            assert_eq!(name.as_deref(), Some("e"));
        }
        other => panic!("expected Typed int, got {other:?}"),
    }
    match &catches[1].kind {
        CatchKind::Typed { ty, name } => {
            assert_eq!(*ty, Type::Float { bytes: 8 });
            assert_eq!(name.as_deref(), Some("d"));
        }
        other => panic!("expected Typed double, got {other:?}"),
    }
}

/// `catch (...)` — the catch-all form. Represented as `CatchKind::All`
/// (no type / no name; matches any thrown value at runtime).
#[test]
fn t06_catch_all() {
    let tu = parse_ok("int main(void) { try { } catch (...) { } return 0; }");
    let catches = match &main_body(&tu)[0] {
        Stmt::Try { catches, .. } => catches,
        other => panic!("expected Stmt::Try, got {other:?}"),
    };
    assert_eq!(catches.len(), 1);
    assert!(
        matches!(catches[0].kind, CatchKind::All),
        "expected CatchKind::All, got {:?}",
        catches[0].kind
    );
}

/// `catch (MyException&)` — reference type in catch (the standard
/// recommendation: bind by reference to dodge slicing). H3 must accept
/// the `&` after a user-defined tag name; the AST stores `Type::Ref(…)`.
#[test]
fn t07_catch_reference_to_class() {
    let src = "\
        class MyException { int x; };\n\
        int main(void) { try { } catch (MyException&) { } return 0; }\n";
    let tu = parse_ok(src);
    let catches = match &main_body(&tu)[0] {
        Stmt::Try { catches, .. } => catches,
        other => panic!("expected Stmt::Try, got {other:?}"),
    };
    assert_eq!(catches.len(), 1);
    match &catches[0].kind {
        CatchKind::Typed { ty, name } => {
            assert!(
                matches!(ty, Type::Ref(inner) if matches!(**inner, Type::Record { .. })),
                "expected reference-to-record, got {ty:?}"
            );
            assert!(name.is_none(), "no name in this fixture");
        }
        other => panic!("expected Typed catch, got {other:?}"),
    }
}

/// `try { throw 1; } catch (int e) { }` — throw nested inside try.
/// Tests that the try body itself accepts arbitrary statements (just
/// `block()` recursion — but pinning it down catches future regressions).
#[test]
fn t08_throw_inside_try() {
    let tu = parse_ok("int main(void) { try { throw 1; } catch (int e) { } return 0; }");
    let (try_body, catches) = match &main_body(&tu)[0] {
        Stmt::Try { body, catches, .. } => (body, catches),
        other => panic!("expected Stmt::Try, got {other:?}"),
    };
    assert_eq!(try_body.len(), 1);
    assert!(
        matches!(&try_body[0], Stmt::Throw(Some(Expr::Int(1)), _)),
        "expected nested Throw(Some(Int(1))), got {:?}",
        try_body[0]
    );
    assert_eq!(catches.len(), 1);
}

// =====================================================================
// Parser error paths (9-11)
// =====================================================================

/// `try { }` with no following `catch` is a parse error — the grammar
/// requires at least one handler.
#[test]
fn t09_try_without_catch_is_error() {
    let err = parse_err("int main(void) { try { } return 0; }");
    let msg = err.message.to_lowercase();
    assert!(
        msg.contains("catch") && msg.contains("try"),
        "diagnostic should mention both 'try' and 'catch'; got: {}",
        err.message
    );
}

/// A `catch` clause without a preceding `try` is a parse error.
#[test]
fn t10_lone_catch_is_error() {
    let err = parse_err("int main(void) { catch (int e) { } return 0; }");
    let msg = err.message.to_lowercase();
    assert!(
        msg.contains("catch") && msg.contains("try"),
        "diagnostic should mention both 'catch' and 'try'; got: {}",
        err.message
    );
}

/// `throw` followed neither by `;` nor by a valid expression is a parse
/// error. We use `throw }` so the very next token is illegal at the
/// expression boundary — exercises the `expr()` path.
#[test]
fn t11_throw_without_expr_or_semi_is_error() {
    let _err = parse_err("int main(void) { throw } return 0; }");
    // Don't pin the exact wording — it bubbles up from the expression
    // parser. The contract is just "this doesn't crash and isn't Ok".
}

// =====================================================================
// Codegen rejection (12-14, 28-29) — H4b lifts class-typed catches into
// real runtime support; what stays rejected: `catch (...)` (catch-all,
// deferred to H-future), bare `throw;` (rethrow needs current-exception
// state — H-future), by-value class catch (needs copy-ctor invocation —
// H-future), and non-int / non-class throws (Phase H4 only supports int
// and polymorphic class types).
// =====================================================================

/// `catch (MyException&)` (class-typed catch on a polymorphic class)
/// — H4b lights this up. Compiles cleanly; t21-t25 exercise the
/// runtime behaviour. The test is preserved (rather than deleted) as
/// the explicit "what used to reject now works" pin.
#[test]
fn t12_class_typed_catch_now_compiles_under_h4b() {
    let src = "\
        class MyException { public: virtual ~MyException() {} int x; };\n\
        int main(void) { try { } catch (MyException& e) { } return 0; }\n";
    let _ = compile_to_pe(src.as_bytes())
        .expect("class-typed catch (by reference) must compile under H4b");
}

/// S6: `catch (...)` (the catch-all form) now COMPILES. The personality adds a
/// kind=4 (CatchAll) branch that matches ANY in-range exception with no type
/// check and TERMINATES the search (a real handler, unlike Cleanup's re-raise).
/// Preserved (rather than deleted) as the explicit "what used to reject now
/// works" pin; the runtime behaviour (catches; not fired on normal completion;
/// typed handlers tried first) is RUN-verified in end_to_end. A catch-all that
/// itself `throw;`-rethrows is still a clean error (no exception delivered to
/// re-raise) — that sub-case is the next EH increment.
#[test]
fn t13_catch_all_now_compiles_under_s6() {
    let src = "int main(void) { int r = 0; try { throw 5; } catch (...) { r = 1; } return r; }";
    let _ = compile_to_pe(src.as_bytes()).expect("catch-all (no rethrow) must compile under S6");
}

/// J-7: bare `throw;` (rethrow) used OUTSIDE any `catch` clause must
/// remain a clean compile-time error. Inside a catch it's legal (the
/// runtime cases live in t38/t39/t40), but a top-level `throw;` has no
/// "current exception" to re-raise — the new diagnostic spells that
/// out so users get a directly actionable message.
#[test]
fn t14_bare_throw_outside_catch_is_error() {
    let src = "int main(void) { throw; return 0; }";
    let err = compile_to_pe(src.as_bytes()).expect_err("must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("rethrow") && msg.contains("catch"),
        "rejection should mention 'rethrow' AND 'catch' (the J-7 \
         diagnostic phrase); got: {msg}"
    );
}

/// `catch (Tag e)` (by-value class catch, no `&` or `*`) → Err pointing
/// at H-future. By-value would need a copy-constructor invocation that
/// Phase H has not built out yet; the diagnostic steers the user to
/// `catch (Tag& e)` (the C++ best-practice anyway).
#[test]
fn t28_codegen_rejects_by_value_class_catch_with_hfuture() {
    let src = "\
        class MyException { public: virtual ~MyException(){} int x; };\n\
        int main(void) { try { } catch (MyException e) { } return 0; }\n";
    let err = compile_to_pe(src.as_bytes()).expect_err("must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("H-future") && (msg.contains("by-value") || msg.contains("by value")),
        "rejection must mention 'H-future' AND 'by-value' so the \
         H-future brief can find the site; got: {msg}"
    );
}

/// `throw 1.5;` (FP throw) → Err pointing at Phase H4 supporting only
/// int + class types. The wording explicitly names the supported set
/// so the diagnostic is actionable.
#[test]
fn t29_codegen_rejects_throw_double_with_h4_marker() {
    let src = "int main(void) { try { throw 1.5; } catch (int e) { } return 0; }";
    let err = compile_to_pe(src.as_bytes()).expect_err("must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("H4")
            && msg.contains("int")
            && (msg.contains("class") || msg.contains("Class")),
        "rejection must mention 'H4', 'int', and 'class' (the supported \
         set); got: {msg}"
    );
}

// =====================================================================
// Structural (15-16) — aggressive-scope contract for `.pdata`/`.xdata`
// emission. Always-on (in-process; no exe is executed).
// =====================================================================

#[cfg(windows)]
mod structural {
    use super::*;

    const PE_OFF: usize = 0x80;
    const SIZEOF_OPT: usize = 0xF0;
    const SECT_HDR_LEN: usize = 40;
    const DIR_EXCEPTION: usize = 3;

    fn parse_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }

    /// `(rva, size)` of `DataDirectory[idx]`. `(0, 0)` ⇒ absent.
    fn data_dir(pe: &[u8], idx: usize) -> (u32, u32) {
        // Data directories start at: PE_OFF + 4 (sig) + 20 (file hdr) +
        // 0x70 (PE32+ optional fields up to NumberOfRvaAndSizes) + 16
        // (NumberOfRvaAndSizes' two leading u32s for ImageBase etc are
        // already counted). The simplest robust offset is "the byte
        // after NumberOfRvaAndSizes" which lives at PE_OFF+4+20+0x70.
        let dirs = PE_OFF + 4 + 20 + 0x70;
        let off = dirs + idx * 8;
        (parse_u32(pe, off), parse_u32(pe, off + 4))
    }

    /// Returns true iff a section with name `name` is present.
    fn has_section(pe: &[u8], name: &[u8]) -> bool {
        let coff = PE_OFF + 4;
        let nsec = u16::from_le_bytes([pe[coff + 2], pe[coff + 3]]) as usize;
        let tbl = PE_OFF + 4 + 20 + SIZEOF_OPT;
        (0..nsec).any(|i| {
            let h = tbl + i * SECT_HDR_LEN;
            let mut want = [0u8; 8];
            want[..name.len()].copy_from_slice(name);
            pe[h..h + 8] == want
        })
    }

    /// A non-throwing TU emits NO `.pdata` / `.xdata`, and
    /// `DataDirectory[3]` stays `(0, 0)`. This is the structural side
    /// of the aggressive-scope contract.
    #[test]
    fn t15_non_throwing_program_emits_no_pdata_xdata() {
        let src = "int main(void){ return 0; }";
        let pe = compile_to_pe(src.as_bytes()).expect("compile ok");
        assert!(
            !has_section(&pe, b".pdata"),
            "non-throwing TU must NOT carry a `.pdata` section"
        );
        assert!(
            !has_section(&pe, b".xdata"),
            "non-throwing TU must NOT carry a `.xdata` section"
        );
        assert_eq!(
            data_dir(&pe, DIR_EXCEPTION),
            (0, 0),
            "DataDirectory[EXCEPTION] must be (0, 0) for a non-throwing TU"
        );
    }

    /// A TU with a `try`/`catch` (regardless of whether the catch ever
    /// fires) DOES emit `.pdata` + `.xdata`, and `DataDirectory[3]`
    /// carries a non-zero `(rva, size)`.
    #[test]
    fn t16_try_bearing_program_emits_pdata_xdata() {
        let src = "int main(void){ try { } catch (int e) { } return 0; }";
        let pe = compile_to_pe(src.as_bytes()).expect("compile ok");
        assert!(
            has_section(&pe, b".pdata"),
            "TU containing `try`/`catch` must emit a `.pdata` section"
        );
        assert!(
            has_section(&pe, b".xdata"),
            "TU containing `try`/`catch` must emit a `.xdata` section"
        );
        let (rva, size) = data_dir(&pe, DIR_EXCEPTION);
        assert_ne!(rva, 0, "DataDirectory[EXCEPTION].rva must be non-zero");
        assert_ne!(size, 0, "DataDirectory[EXCEPTION].size must be non-zero");
        // Size must be a multiple of 12 (sizeof(RUNTIME_FUNCTION)).
        assert_eq!(
            size % 12,
            0,
            "`.pdata` size {size} must be a whole number of \
             RUNTIME_FUNCTION (12 B) entries"
        );
    }

    /// t26 — H4b: a TU that throws a class instance carries the
    /// `.mdbcc_eh_buffer` global in `.data` (sized to the largest
    /// polymorphic class), and `.rdata` carries at least one vtable
    /// + the typeinfo table.
    ///
    /// We can't directly probe the typeinfo table's RVA from the PE
    /// bytes (it's private to the personality fn), but the structural
    /// witness is: `.data` is meaningfully larger than for an int-only
    /// TU because the exception buffer got allocated.
    #[test]
    fn t26_class_throw_inflates_data_section() {
        let int_only = "\
            int main(void) { try { throw 1; } catch (int e) { return e; } return 0; }";
        let class_throw = "\
            class TX { public: virtual ~TX(){} int code; };\n\
            int main(void) {\n\
              TX e;\n\
              e.code = 1;\n\
              try { throw e; }\n\
              catch (TX& x) { return x.code; }\n\
              return 0;\n\
            }\n";
        let pe_int = compile_to_pe(int_only.as_bytes()).expect("compile ok");
        let pe_cls = compile_to_pe(class_throw.as_bytes()).expect("compile ok");
        assert!(has_section(&pe_int, b".pdata"));
        assert!(has_section(&pe_cls, b".pdata"));
        // .data is section index 3 (0-based) — text/idata/rdata/data.
        let tbl = PE_OFF + 4 + 20 + SIZEOF_OPT;
        let data_int_vsize = parse_u32(&pe_int, tbl + 3 * SECT_HDR_LEN + 8);
        let data_cls_vsize = parse_u32(&pe_cls, tbl + 3 * SECT_HDR_LEN + 8);
        // Int-only: .data = 1 byte (empty-section guard).
        // Class-throw: .data holds .mdbcc_eh_buffer (16-byte aligned;
        // smallest polymorphic class is 16 bytes: vptr+int+pad).
        assert!(
            data_cls_vsize > data_int_vsize,
            "class-throw TU's .data ({data_cls_vsize}) must exceed \
             int-only TU's .data ({data_int_vsize}) — the exception \
             buffer global lives in .data",
        );
        assert!(
            data_cls_vsize >= 16,
            ".mdbcc_eh_buffer should be at least 16 bytes (got \
             {data_cls_vsize})",
        );
    }

    /// t27 — H4b: an int-only throw/catch TU has the SAME structural
    /// shape as an H4a-era build. No typeinfo, no `.mdbcc_eh_buffer`
    /// (the `compile_module` pre-pass skips them when no polymorphic
    /// class exists in the TU). The pin: `.data` should be small —
    /// no class exception buffer means no large `.data` allocation.
    /// We assert by structural similarity: the int-only TU produces
    /// the same section count as a pure non-throwing TU PLUS the
    /// H4a-mandatory `.pdata` + `.xdata`.
    ///
    /// Tick 69 (J-11b / J-15b): adds a fixed-size 24-byte
    /// `.mdbcc_eh_save` global to every TU with try/throw so cleanup
    /// landing pads can re-raise from a stable source. This is
    /// per-MODULE (not per-class), so it appears even in an int-only
    /// TU. The size budget is widened accordingly; the lock that
    /// `.mdbcc_eh_buffer` (the class-throw object buffer) is NOT
    /// inflated remains via `t26_class_throw_inflates_data_section`.
    #[test]
    fn t27_int_only_throw_program_has_no_class_eh_overhead() {
        let int_only = "\
            int main(void) { try { throw 1; } catch (int e) { return e; } return 0; }";
        let pe = compile_to_pe(int_only.as_bytes()).expect("compile ok");
        // Int-only TU: should have .text, .idata, .rdata, .data,
        // .pdata, .xdata (the H4a 6-section shape). No `.mdbcc_eh_buffer`
        // global means `.data` content is small (the tick-69
        // `.mdbcc_eh_save` global only, plus the section guard).
        let coff = PE_OFF + 4;
        let nsec = u16::from_le_bytes([pe[coff + 2], pe[coff + 3]]);
        assert_eq!(
            nsec, 6,
            "int-only throw/catch TU must have exactly 6 sections \
             (text, idata, rdata, data, pdata, xdata) — class-EH \
             structure must NOT be present",
        );
        // .data should fit `.mdbcc_eh_save` (24 bytes, tick 69) plus
        // any small alignment / guard padding. 64 is a generous upper
        // bound that still catches `.mdbcc_eh_buffer` inflation
        // (>=16 bytes per class object, often more).
        let tbl = PE_OFF + 4 + 20 + SIZEOF_OPT;
        let data_hdr_off = tbl + 3 * SECT_HDR_LEN; // .data is section 4
        let data_vsize = parse_u32(&pe, data_hdr_off + 8);
        assert!(
            data_vsize <= 64,
            ".data should be small for an int-only throw/catch TU \
             (got vsize {data_vsize}); class-EH overhead (object \
             buffer) must NOT be present (tick 69 adds 24 bytes for \
             `.mdbcc_eh_save` — accounted for in the upper bound)",
        );
    }
}

// =====================================================================
// Runtime (17-20) — gated on Windows; compile, run, assert exit code.
// These exercise the full SEH dispatch path end-to-end.
// =====================================================================

#[cfg(windows)]
mod runtime {
    use mdbcc::compile_to_pe;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TempExe(PathBuf);
    impl TempExe {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut p = std::env::temp_dir();
            p.push(format!("mdbcc_seh_{}_{}.exe", std::process::id(), n));
            TempExe(p)
        }
    }
    impl Drop for TempExe {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Compile `src`, run the produced exe, return its exit code.
    fn run_src(src: &str) -> i32 {
        let exe = compile_to_pe(src.as_bytes()).expect("compile ok");
        let tmp = TempExe::new();
        std::fs::write(&tmp.0, &exe).expect("write exe");
        let status = Command::new(&tmp.0)
            .status()
            .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
        status.code().expect("process returned an exit code")
    }

    const PROG_H4A_THROW_CATCH_INT_EXIT_CODE: &str =
        "int main(void){ try { throw 5; } catch (int e) { return e; } return 0; }";

    const PROG_H4A_THROW_CATCH_NESTED: &str = "\
        int main(void) { \
            try { \
                try { throw 7; } \
                catch (int e1) { throw e1 + 1; } \
            } catch (int e2) { return e2; } \
            return 0; \
        }";

    const PROG_H4A_THROW_FROM_NESTED_FN: &str = "\
        int boom(void) { throw 42; return 0; } \
        int main(void) { \
            try { boom(); } \
            catch (int e) { return e; } \
            return 0; \
        }";

    const PROG_H4A_NO_THROW: &str = "\
        int main(void) { \
            int x = 0; \
            try { x = 11; } \
            catch (int e) { x = -1; } \
            return x; \
        }";

    /// t17 — the headline test. Throw an int, catch an int, return its
    /// value. If `.xdata`'s UNWIND_INFO encoding is wrong, this fails
    /// with STATUS_BAD_FUNCTION_TABLE (exit code something like
    /// `-1073740940`) before the personality function is even reached.
    /// If the personality function does not dispatch, the OS terminates
    /// with the exception code `0xE0000001` (exit code `-536870911`).
    /// Either of those is a SCOPE-SPLIT signal — the structural pieces
    /// are landed, but the dispatcher needs another tick.
    #[test]
    fn t17_throw_catch_int_returns_value() {
        let code = run_src(PROG_H4A_THROW_CATCH_INT_EXIT_CODE);
        assert_eq!(
            code, 5,
            "expected exit code 5; got {code:#x} ({code}). If this is \
             0xC0000000-ish, the unwind tables are malformed; if it is \
             0xE0000001 ({}), the personality function isn't dispatching",
            -536870911i32
        );
    }

    /// t18 — nested try, both catches active.
    #[test]
    fn t18_throw_catch_nested() {
        let code = run_src(PROG_H4A_THROW_CATCH_NESTED);
        assert_eq!(code, 8, "got {code:#x} ({code})");
    }

    /// t19 — throw across a frame boundary (catch in main, throw in a
    /// callee). Exercises the OS unwinder's frame walk, not just the
    /// single-frame path.
    #[test]
    fn t19_throw_from_nested_fn() {
        let code = run_src(PROG_H4A_THROW_FROM_NESTED_FN);
        assert_eq!(code, 42, "got {code:#x} ({code})");
    }

    /// t20 — a try block that does NOT throw. The catch must NOT fire;
    /// the try body's effect must be visible. This is the "happy
    /// fall-through" path — must work even before the personality
    /// dispatcher is in (the catch is simply unreachable).
    #[test]
    fn t20_try_without_throw_falls_through() {
        let code = run_src(PROG_H4A_NO_THROW);
        assert_eq!(code, 11, "got {code:#x} ({code})");
    }

    // =================================================================
    // H4b runtime: class throw + class catch + catch-by-base hierarchy
    // walk + first-match-wins across int+class catches.
    //
    // Every fixture uses a polymorphic class (virtual destructor on the
    // root) — H4b's type matching uses the vtable RVA as the type tag,
    // so a non-polymorphic class is rejected at codegen time. The OWL
    // idiom (`TXBase { virtual ~TXBase() {} }`) is exactly what these
    // classes mirror.
    // =================================================================

    /// t21 — throw a class instance, catch by reference. Exit code via
    /// a member of the caught instance proves the buffer-address path
    /// (catch RAX → ref → field read) survives the unwind end-to-end.
    #[test]
    fn t21_throw_class_catch_class_byref() {
        let src = "\
            class TX { public: virtual ~TX(){} int code; };\n\
            int main(void) {\n\
              TX e;\n\
              e.code = 17;\n\
              try { throw e; }\n\
              catch (TX& x) { return x.code; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(code, 17, "got {code:#x} ({code})");
    }

    /// B-08: Win64 class throws must copy-construct the exception object
    /// into `.mdbcc_eh_buffer`; a raw byte copy would leave `v == 41`.
    #[test]
    fn t21b_throw_class_runs_copy_ctor() {
        let src = "\
            struct E {\n\
              int v;\n\
              E(int x) : v(x) {}\n\
              E(const E& o) { v = o.v + 1; }\n\
            };\n\
            int main(void) {\n\
              try { throw E(41); }\n\
              catch (E& caught) { return caught.v; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(code, 42, "copy ctor should publish v=42; got {code}");
    }

    /// B-08: synthesized memberwise copy ctors must be used too. This is the
    /// real `xmsg` shape: the thrown class owns a member with a copy ctor but
    /// does not declare its own copy ctor.
    #[test]
    fn t21c_throw_class_runs_synth_memberwise_copy_ctor() {
        let src = "\
            struct M {\n\
              int v;\n\
              M(int x) : v(x) {}\n\
              M(const M& o) { v = o.v + 1; }\n\
            };\n\
            struct E {\n\
              M m;\n\
              E(int x) : m(x) {}\n\
            };\n\
            int main(void) {\n\
              try { throw E(41); }\n\
              catch (E& caught) { return caught.m.v; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(code, 42, "member copy ctor should publish v=42; got {code}");
    }

    #[test]
    fn t21d_caught_object_destructs_on_handler_fallthrough() {
        let src = "\
            int g = 0;\n\
            struct E {\n\
              int v;\n\
              E(int x) : v(x) {}\n\
              E(const E& o) { v = o.v; }\n\
              ~E() { g = v; }\n\
            };\n\
            void f(void) {\n\
              try { throw E(1); }\n\
              catch (E& caught) { }\n\
            }\n\
            int main(void) { f(); return g; }\n";
        let code = run_src(src);
        assert_eq!(code, 1, "caught object dtor should set g=1; got {code}");
    }

    #[test]
    fn t21e_caught_object_destructs_on_handler_return() {
        let src = "\
            int g = 0;\n\
            struct E {\n\
              int v;\n\
              E(int x) : v(x) {}\n\
              E(const E& o) { v = o.v; }\n\
              ~E() { g = v; }\n\
            };\n\
            int f(void) {\n\
              try { throw E(1); }\n\
              catch (E& caught) { return caught.v; }\n\
              return 0;\n\
            }\n\
            int main(void) { int r = f(); return g * 10 + r; }\n";
        let code = run_src(src);
        assert_eq!(
            code, 11,
            "return from handler should run caught dtor before epilogue; got {code}"
        );
    }

    #[test]
    fn t21f_rethrow_does_not_destroy_caught_object_before_outer_catch() {
        let src = "\
            int g = 0;\n\
            struct E {\n\
              int v;\n\
              E(int x) : v(x) {}\n\
              E(const E& o) { v = o.v; }\n\
              ~E() { g = 99; }\n\
            };\n\
            void inner(void) {\n\
              try { throw E(5); }\n\
              catch (E& caught) { throw; }\n\
            }\n\
            int main(void) {\n\
              try { inner(); }\n\
              catch (E& outer) { return (g == 0 && outer.v == 5) ? 42 : 7; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 42,
            "rethrow must propagate a still-live exception object; got {code}"
        );
    }

    /// t22 — the catch-by-base headline. Throw a derived; the catch is
    /// declared as the base reference. Without the hierarchy walk this
    /// fails (catch_type_rva ≠ thrown_vtable_rva at the first compare).
    /// The exit code reads a base-class field of the buffer (the bytes
    /// the derived class wrote land at the base's offset because of the
    /// shared layout — base subobject at +0 / +8-after-vptr).
    #[test]
    fn t22_throw_derived_catch_base_byref() {
        let src = "\
            class Base { public: virtual ~Base(){} int code; };\n\
            class Der : public Base { public: Der(){} };\n\
            int main(void) {\n\
              Der d;\n\
              d.code = 23;\n\
              try { throw d; }\n\
              catch (Base& b) { return b.code; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(code, 23, "got {code:#x} ({code}) — catch-by-base");
    }

    /// t23 — throw a pointer to a class; catch by pointer. The buffer-
    /// address path delivers the same `T*` value the user expects to
    /// dereference. (Note: H4b copies the instance into the buffer; the
    /// caught pointer addresses the BUFFER, not the original object —
    /// the field reads still work because the bytes were copied.)
    #[test]
    fn t23_throw_class_catch_by_pointer() {
        let src = "\
            class TX { public: virtual ~TX(){} int code; };\n\
            int main(void) {\n\
              TX e;\n\
              e.code = 31;\n\
              try { throw &e; }\n\
              catch (TX* p) { return p->code; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(code, 31, "got {code:#x} ({code})");
    }

    /// t24 — first-match-wins between an int catch and a (later) class
    /// catch. Throw an int; the int catch must fire and the class
    /// catch must be untouched.
    #[test]
    fn t24_first_match_wins_with_int_and_class_catches() {
        let src = "\
            class TX { public: virtual ~TX(){} int code; };\n\
            int main(void) {\n\
              try { throw 13; }\n\
              catch (int n) { return n; }\n\
              catch (TX& e) { return -1; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(code, 13, "got {code:#x} ({code})");
    }

    /// t25 — deep hierarchy A ← B ← C ← D. Throw a D; catch by A&. The
    /// hierarchy walk takes three hops (D.base=C, C.base=B, B.base=A)
    /// to land on a match. Exit code via the base's field proves the
    /// derived bytes survived the buffer copy.
    #[test]
    fn t25_multi_level_hierarchy_catch_grandparent() {
        let src = "\
            class A { public: virtual ~A(){} int code; };\n\
            class B : public A { public: B(){} };\n\
            class C : public B { public: C(){} };\n\
            class D : public C { public: D(){} };\n\
            int main(void) {\n\
              D d;\n\
              d.code = 41;\n\
              try { throw d; }\n\
              catch (A& a) { return a.code; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(code, 41, "got {code:#x} ({code})");
    }

    // =================================================================
    // Phase H code-review MAJOR-2: cross-feature SEH integration tests
    // for the highest-value Phase-I-likely cases that the H4a/H4b
    // per-feature suite did not exercise. Each is additive (no
    // implementation change required for any to be possible).
    //
    // Bare `throw;` (rethrow with no expression) remains H-future per
    // t14; the cases here are explicit-rethrow (`throw e;` of a caught
    // reference), indirect-call frames, deep multi-frame scope-tables,
    // and H1+H4b cross-feature integration (class containing a struct).
    // =================================================================

    /// t30 — explicit rethrow `throw e;` (the caught reference, NOT
    /// bare `throw;`). The user catches by reference, then re-throws
    /// the same exception. The outer catch sees the same value because
    /// `throw e;` runs `gen_throw_class` against `e`'s declared type
    /// (`Tag&`), which matches the original throw's value. This is the
    /// canonical OWL idiom — bare `throw;` (which needs current-
    /// exception state) is H-future, but `throw e;` is just a normal
    /// throw of an expression and SHOULD work end-to-end.
    #[test]
    fn t30_explicit_rethrow_of_caught_reference() {
        let src = "\
            class TX { public: virtual ~TX(){} int code; };\n\
            int main(void) {\n\
              TX e;\n\
              e.code = 51;\n\
              try {\n\
                try { throw e; }\n\
                catch (TX& inner) { throw inner; }\n\
              }\n\
              catch (TX& outer) { return outer.code; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 51,
            "explicit rethrow should deliver code 51 to the outer \
             handler; got {code:#x} ({code})"
        );
    }

    /// t31 — throw across a function-pointer indirect call. The callee
    /// is reached via `(*fp)()` (an `Expr::CallPtr`, which lowers to
    /// `call rax` rather than `call rel32`). The personality function
    /// walks frames by RIP/RSP — it should be call-mode-agnostic — but
    /// the case is never exercised by the per-feature suite. Phase-I
    /// OWL apps use function pointers for message-handler dispatch.
    #[test]
    fn t31_throw_across_function_pointer_indirect_call() {
        let src = "\
            void boom(void) { throw 71; }\n\
            int main(void) {\n\
              void (*fp)(void) = &boom;\n\
              try { (*fp)(); }\n\
              catch (int e) { return e; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 71,
            "throw across an indirect call should propagate the same \
             way as a direct call; got {code:#x} ({code})"
        );
    }

    /// t32 — three nested try-catch frames in one function, throw from
    /// the innermost, caught at the outermost. Tests the scope-table
    /// walk handles multi-frame correctly when several `try` ranges
    /// stack within one PC range, and the personality function must
    /// skip over the two intermediate (non-matching) catches.
    /// We use class catches at the inner levels — they don't match an
    /// int throw (different exception code), so the walk must continue
    /// out to the outermost int handler. Phase H4 only supports `int`,
    /// class-ref, and class-ptr catches; FP and `long` are rejected, so
    /// we use class refs as the "guaranteed non-matching" sentinels.
    #[test]
    fn t32_deep_nested_try_three_levels_one_function() {
        let src = "\
            class TX1 { public: virtual ~TX1(){} int x; };\n\
            class TX2 { public: virtual ~TX2(){} int x; };\n\
            int main(void) {\n\
              try {\n\
                try {\n\
                  try { throw 91; }\n\
                  catch (TX1& a) { return 1; }\n\
                }\n\
                catch (TX2& b) { return 2; }\n\
              }\n\
              catch (int e) { return e; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 91,
            "three-level nested try should walk past two non-matching \
             class catches and land on the outermost int handler; got \
             {code:#x} ({code})"
        );
    }

    /// t33 — H1+H4b cross-feature integration. A polymorphic class
    /// contains a by-value struct field. Throw the class object,
    /// catch by reference, read the struct field through the caught
    /// reference. Verifies that:
    ///   (a) H1 struct-by-value layout survives the H4b buffer copy
    ///       (the struct's bytes land at the correct offset in the
    ///       buffer);
    ///   (b) field access through `caught.struct_field.member` works
    ///       (the caught reference dereferences to the buffer, then
    ///       member access reads the right offsets).
    /// This is the cross-product MINOR-3 calls out — at least one
    /// real H1+H4b test exists so a future regression in either is
    /// caught by an integration witness.
    #[test]
    fn t33_throw_class_containing_struct_by_value_caught_field_access() {
        let src = "\
            struct Pt { int x; int y; };\n\
            class TX {\n\
              public:\n\
                virtual ~TX(){}\n\
                struct Pt where;\n\
                int code;\n\
            };\n\
            int main(void) {\n\
              TX e;\n\
              e.where.x = 100;\n\
              e.where.y = 23;\n\
              e.code = 0;\n\
              try { throw e; }\n\
              catch (TX& c) { return c.where.x + c.where.y; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 123,
            "H1 struct-field access through an H4b caught reference \
             should yield 100+23 = 123; got {code:#x} ({code}). A \
             nonzero-but-wrong code suggests struct layout drift; \
             a STATUS_ACCESS_VIOLATION suggests the buffer copy \
             missed the struct bytes."
        );
    }

    // =================================================================
    // Tick 50 (gap-report J-2 / J-3 / J-4) — three SEH coverage gaps
    // from the H10 review MAJOR-2 (cases 7, 4, 8). The H4a/H4b runtime
    // already supports all three; these tests close the test-coverage
    // gap so a future regression in any of these silent-but-working
    // paths is caught. Pure additions — no implementation change.
    // =================================================================

    /// t34 (J-2, H10 MAJOR-2 case 7) — empty catch body. `catch (int e)
    /// {}` is legal C++: the exception is caught, the (empty) handler
    /// runs, and control falls through to the statement after the
    /// `try`/`catch` block. The `e` parameter is unused — the parser
    /// names it but the codegen never reads it. The runtime must still
    /// (a) match the int type, (b) transfer control to the handler,
    /// and (c) let control flow continue past the construct.
    ///
    /// Exit code 99 (returned AFTER the empty catch, NOT from inside
    /// it) proves all three: a miscompile that returned the thrown 7
    /// (because the empty handler accidentally re-emitted the throw
    /// value), or a STATUS_BAD_FUNCTION_TABLE crash (because the
    /// scope-table entry was malformed for the zero-statement body)
    /// would both fail this assertion.
    #[test]
    fn t34_empty_catch_body_falls_through() {
        let src = "\
            int main(void) {\n\
              try { throw 7; }\n\
              catch (int e) {}\n\
              return 99;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 99,
            "an empty catch body must catch the int and fall through \
             to `return 99`; got {code:#x} ({code}). Code 7 would mean \
             the handler somehow forwarded the thrown value; a \
             STATUS_BAD_FUNCTION_TABLE-like negative number means the \
             scope-table or .xdata is malformed for a zero-statement \
             handler."
        );
    }

    /// t35 (J-3, H10 MAJOR-2 case 4) — throw across a virtual-method
    /// dispatch. The thrown call goes through the vtable: `ptr->boom()`
    /// lowers to `call qword ptr [rax+disp]` (vtable indirection), not
    /// `call rel32`. Tick 47's t31 covered the function-pointer
    /// analogue; this is the vtable analogue.
    ///
    /// The personality function is supposed to be location-agnostic —
    /// it walks frames by RIP/RSP and consults the scope-table — so
    /// indirection mode shouldn't matter. But OWL apps reach throwing
    /// code almost entirely through virtual dispatch (event-handler
    /// chains, response-table dispatch), so this is the throwing-call
    /// shape most likely to break in Phase I if any vtable-specific
    /// RIP-decoding shortcut is hiding in the unwinder.
    ///
    /// `e + 1` (41 → 42) proves the caught int actually arrived in
    /// the outer handler and was read correctly through the local.
    #[test]
    fn t35_throw_across_virtual_dispatch() {
        let src = "\
            class Boom {\n\
              public:\n\
                virtual ~Boom(){}\n\
                virtual int boom(void) { throw 41; return 0; }\n\
            };\n\
            int main(void) {\n\
              Boom b;\n\
              Boom* p = &b;\n\
              try { p->boom(); }\n\
              catch (int e) { return e + 1; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 42,
            "throw across a virtual-method (vtable) dispatch should \
             propagate the same way as a direct call; got {code:#x} \
             ({code}). 41 would mean the catch fired but the +1 was \
             dropped; 0 would mean the catch never fired."
        );
    }

    /// t36 (J-4, H10 MAJOR-2 case 8) — deeply nested try/catch. Five
    /// levels of `try` stacked in one function, throw from the
    /// innermost (level 5), the matching handler sits at level 3 so
    /// levels 5 and 4 must skip past (non-matching catches) and the
    /// walk lands on level 3's int handler. Levels 2 and 1 also have
    /// catches but are never reached (level-3 catch returns).
    ///
    /// HLD risk #2 calls the scope-table format "intricate"; deep
    /// nesting stresses the per-frame entries' ordering and the
    /// personality function's linear walk through them. Five levels
    /// matches Phase-I OWL handlers that pile guarded resource
    /// acquisitions (paint device → font → brush → pen → callback).
    ///
    /// The non-matching catches at levels 4 and 5 use class refs (an
    /// int throw will never match a class catch under H4b's type-tag
    /// model), so the walk MUST continue outward.
    #[test]
    fn t36_deep_nested_try_five_levels_catch_at_three() {
        let src = "\
            class TX1 { public: virtual ~TX1(){} int x; };\n\
            class TX2 { public: virtual ~TX2(){} int x; };\n\
            int main(void) {\n\
              try {\n\
                try {\n\
                  try {\n\
                    try {\n\
                      try { throw 53; }\n\
                      catch (TX1& a) { return 1; }\n\
                    }\n\
                    catch (TX2& b) { return 2; }\n\
                  }\n\
                  catch (int e) { return e; }\n\
                }\n\
                catch (int f) { return f * 10; }\n\
              }\n\
              catch (int g) { return g * 100; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 53,
            "5-level nested try should walk past the two innermost \
             (non-matching) class catches and land at level 3's int \
             handler; got {code:#x} ({code}). 530 would mean the walk \
             went one level too far (level-2 caught it); 5300 means it \
             unwound all the way to level 1; 1 or 2 means a class-vs-\
             int type mismatch was treated as a match."
        );
    }

    /// t37 (bonus cross-feature) — throw across virtual dispatch INTO
    /// a deeply nested try-catch. Combines J-3 (vtable indirection at
    /// the throw site) with J-4 (multi-level scope-table walk). The
    /// vtable call lands inside the innermost try; the matching
    /// handler is three levels up. This is the closest single test to
    /// a real OWL `TWindow::EvCommand` doing virtual dispatch to a
    /// handler nested inside several guarded resource scopes.
    ///
    /// Exit code 67 proves the caught int (66 thrown) arrived intact
    /// at the level-3 handler after both the vtable call AND the
    /// multi-frame scope-table walk.
    #[test]
    fn t37_throw_across_virtual_into_deep_nest() {
        let src = "\
            class Boom {\n\
              public:\n\
                virtual ~Boom(){}\n\
                virtual int boom(void) { throw 66; return 0; }\n\
            };\n\
            class TX1 { public: virtual ~TX1(){} int x; };\n\
            class TX2 { public: virtual ~TX2(){} int x; };\n\
            int main(void) {\n\
              Boom b;\n\
              Boom* p = &b;\n\
              try {\n\
                try {\n\
                  try {\n\
                    try { p->boom(); }\n\
                    catch (TX1& a) { return 1; }\n\
                  }\n\
                  catch (TX2& c) { return 2; }\n\
                }\n\
                catch (int e) { return e + 1; }\n\
              }\n\
              catch (int g) { return g * 100; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 67,
            "throw across a vtable call + 4-level nested try should \
             land at the level-3 int handler with e=66 → 67; got \
             {code:#x} ({code}). 6600 would mean the walk over-shot \
             to the outermost; 1 or 2 means a type-mismatch was \
             treated as a match."
        );
    }

    // =================================================================
    // J-7 — bare `throw;` (rethrow) inside a catch handler. The inner
    // catch reads its caught exception and re-raises it; an enclosing
    // catch picks it up. Pre-J-7 the codegen rejected `Stmt::Throw(None)`
    // outright; J-7 lifts the rejection ONLY when the throw is inside a
    // catch body, lowering it to the same RaiseException path as the
    // value-throw forms (`gen_throw_int` / `gen_throw_class`) but
    // sourced from the catch's parameter slot rather than a fresh
    // evaluation.
    // =================================================================

    /// t38 — bare `throw;` inside an int catch. The inner catch catches
    /// the int 7, rethrows it; the outer catch picks it up unchanged.
    /// Exit 7 proves: (a) the rethrow took the int path
    /// (EXCEPTION_MDBCC_INT), (b) the value travelled intact through
    /// two RaiseException calls, (c) the outer catch's slot binding
    /// works correctly after a second unwind.
    #[test]
    fn t38_bare_throw_inside_int_catch_propagates() {
        let src = "\
            int main(void) {\n\
              try {\n\
                try { throw 7; }\n\
                catch (int e) { throw; }\n\
              }\n\
              catch (int e2) { return e2; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 7,
            "bare 'throw;' inside int catch should re-raise the same int \
             7 to the outer catch; got {code:#x} ({code})"
        );
    }

    /// t39 — bare `throw;` inside a class catch. The inner catch catches
    /// `TX&` and rethrows; the outer catch (also `TX&`) picks it up and
    /// reads the same field value. Exit 41 proves: (a) the rethrow took
    /// the class path (EXCEPTION_MDBCC_CLASS, 2-slot args array),
    /// (b) the buffer-pointer identity survives the round trip,
    /// (c) the catch's static-type vtable feeds args[0] for the type
    /// match at the outer catch.
    #[test]
    fn t39_bare_throw_inside_class_catch_propagates() {
        let src = "\
            class TX { public: virtual ~TX(){} int code; };\n\
            int main(void) {\n\
              TX e;\n\
              e.code = 41;\n\
              try {\n\
                try { throw e; }\n\
                catch (TX& inner) { throw; }\n\
              }\n\
              catch (TX& outer) { return outer.code; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 41,
            "bare 'throw;' inside class catch should re-raise the same \
             buffer to the outer catch; got {code:#x} ({code})"
        );
    }

    /// t40 — double rethrow. Three nested try/catch frames; innermost
    /// rethrows, middle rethrows, outermost catches. Exit 17 proves the
    /// rethrow path doesn't accumulate transformations — the value
    /// arrives at the third handler identical to the original throw.
    #[test]
    fn t40_bare_throw_double_rethrow() {
        let src = "\
            int main(void) {\n\
              try {\n\
                try {\n\
                  try { throw 17; }\n\
                  catch (int a) { throw; }\n\
                }\n\
                catch (int b) { throw; }\n\
              }\n\
              catch (int c) { return c; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 17,
            "two consecutive rethrows should deliver the original 17 \
             to the outermost catch; got {code:#x} ({code})"
        );
    }

    /// t41 — bare `throw;` in an anonymous-typed catch (`catch (int)`,
    /// no name) must still work. Pre-J-7 the only spill of RAX into a
    /// slot happened when the catch param was named; J-7 must allocate
    /// a fresh tmp for anonymous catches whose body contains a rethrow,
    /// otherwise there's nowhere to read the caught value from.
    /// Exit 23 proves the anonymous-catch rethrow path.
    #[test]
    fn t41_bare_throw_inside_anonymous_int_catch() {
        let src = "\
            int main(void) {\n\
              try {\n\
                try { throw 23; }\n\
                catch (int) { throw; }\n\
              }\n\
              catch (int e) { return e; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 23,
            "anonymous int catch + rethrow should still deliver the \
             original 23 to the outer catch; got {code:#x} ({code})"
        );
    }

    // =================================================================
    // Tick 59 (gap-report J-11 / J-12) — two SEH coverage gaps from the
    // H10 review MAJOR-2 cases 1 and 2: throw during a constructor and
    // throw during a destructor. The expected outcomes (per the v1
    // scope of the brief):
    //
    //   J-11 plain-class ctor-throw: catch fires; the partial object's
    //   own dtor must NOT run (the object was never fully constructed).
    //   Survives "for free" because dtors are fall-through code, NOT
    //   unwind callbacks — when the unwinder skips past the post-ctor
    //   scope-exit point, the dtor's bytes are skipped along with it.
    //
    //   J-12 dtor-throw-during-normal-exit: the dtor body runs at the
    //   scope-exit fall-through; its `throw` raises a fresh exception
    //   whose PC is still inside the enclosing try's [begin, end)
    //   range, so the catch fires. The standard's terminate-on-
    //   already-unwinding case is OUT of v1 scope.
    // =================================================================

    /// t42 (J-11, H10 MAJOR-2 case 1) — throw during the constructor of
    /// a local. The ctor body throws BEFORE the assignment to `x`
    /// completes; the matching catch fires and returns the value.
    ///
    /// Exit code 42 proves: (a) the catch fires (so the SEH machinery
    /// dispatched even though the throw originated inside a ctor body,
    /// not a plain function body or a try-block top-level), (b) the
    /// thrown int travelled intact through RaiseException →
    /// personality → catch-landing-pad.
    ///
    /// CRITICAL non-assertion (t43 below covers it): the partially-
    /// constructed object's dtor must NOT run. v1 leans on the fact
    /// that dtors are fall-through code (NOT scope-table unwind
    /// callbacks), so the unwinder simply skips the bytes the dtor
    /// would have lived in.
    #[test]
    fn t42_throw_during_ctor_plain_class() {
        let src = "\
            class C {\n\
              public:\n\
                int x;\n\
                C(int v) { if (v < 0) throw 42; x = v; }\n\
                ~C() {}\n\
            };\n\
            int main(void) {\n\
              try { C c(-1); return 99; }\n\
              catch (int e) { return e; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 42,
            "throw inside a ctor body should propagate to the enclosing \
             catch; got {code:#x} ({code}). 99 would mean the ctor \
             didn't throw (or threw and was swallowed); a STATUS_* \
             negative code means the personality function refused the \
             ctor-frame throw."
        );
    }

    /// t43 (J-11 reinforcement) — proves the partially-constructed
    /// object's dtor does NOT run on the catch path. A global counter
    /// bumps once per dtor call; if the bug were ever to creep in
    /// (e.g. a future "register dtor at slot-allocation, not at
    /// post-ctor track_dtor" refactor), the counter would read 1
    /// instead of 0.
    ///
    /// We encode the counter check as `return ctors - dtors`. Both
    /// counters start at 0; if the ctor threw before incrementing
    /// `ctors`, the test would still pass (we only require dtors == 0
    /// AND the catch fires). We do bump `ctors` immediately on entry,
    /// BEFORE the throw, so the counter encodes "ctor was entered".
    ///
    /// Exit code 1 proves: (a) ctor entered (`ctors` = 1),
    /// (b) ctor threw before completing (the `x = 0` line never ran;
    /// we don't read x, but the throw aborted body execution),
    /// (c) dtor did NOT run on the partial object (`dtors` = 0),
    /// (d) catch fired and returned `ctors - dtors` = 1.
    #[test]
    fn t43_throw_during_ctor_dtor_side_effect_proves_not_called() {
        let src = "\
            int ctors = 0;\n\
            int dtors = 0;\n\
            class C {\n\
              public:\n\
                int x;\n\
                C(int v) { ctors = ctors + 1; if (v < 0) throw 42; x = v; }\n\
                ~C() { dtors = dtors + 1; }\n\
            };\n\
            int main(void) {\n\
              try { C c(-1); return 99; }\n\
              catch (int e) { return ctors - dtors; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 1,
            "ctor must be entered (ctors=1) but the partial object's \
             dtor must NOT run (dtors=0), so ctors-dtors = 1; got \
             {code:#x} ({code}). 0 would mean the dtor DID run on the \
             partial object (the J-11 bug). 99 would mean the catch \
             never fired."
        );
    }

    /// t45 (J-11b, tick 69) — throw during a derived-class ctor where
    /// the base WAS fully constructed before the throw. Per the C++
    /// standard (now implemented), the base's dtor MUST run on the
    /// catch path since the base subobject is fully constructed at the
    /// point the derived body throws.
    ///
    /// Implementation: tick 69's `Gen::run` injects a
    /// `CatchPolicy::Cleanup` scope around the post-base-ctor portion
    /// of every derived ctor whose base has a dtor. The cleanup pad
    /// invokes `Base::~Base(this)` then re-raises via `RaiseException`
    /// reading code+args from `.mdbcc_eh_save` (the personality fn
    /// stashed them there before unwinding).
    ///
    /// The encoded exit `(base_ctors * 1000) + (base_dtors * 100) +
    /// (der_ctors * 10) + der_dtors`:
    ///   * pre-tick-69 (sub-standard): 1010 (base_dtors=0) — silent leak.
    ///   * tick-69 (standard):         1110 (base_dtors=1) — base dtor ran.
    ///
    /// SCOPE NOTE: tick 69's half-step covers the BASE-chain only.
    /// Class-typed member subobjects with their own dtors are not yet
    /// included in the partial-construction unwind; a future tick can
    /// extend this by tracking member-init milestones similarly.
    #[test]
    fn t45_throw_during_ctor_with_base_runs_base_dtor() {
        let src = "\
            int base_ctors = 0;\n\
            int base_dtors = 0;\n\
            int der_ctors = 0;\n\
            int der_dtors = 0;\n\
            class Base { public: int b; Base() { base_ctors = base_ctors + 1; b = 99; } ~Base() { base_dtors = base_dtors + 1; } };\n\
            class Derived : public Base { public: int d; Derived(int v) { der_ctors = der_ctors + 1; if (v < 0) throw 42; d = v; } ~Derived() { der_dtors = der_dtors + 1; } };\n\
            int main(void) {\n\
              try { Derived c(-1); return 99; }\n\
              catch (int e) { return (base_ctors * 1000) + (base_dtors * 100) + (der_ctors * 10) + der_dtors; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 1110,
            "tick-69 J-11b: derived ctor threw AFTER its base was \
             fully constructed; the standard (now implemented) calls \
             the base's dtor on the unwind path (base_dtors=1, total \
             = 1*1000 + 1*100 + 1*10 + 0 = 1110). Got {code} \
             (base_ctors*1000 + base_dtors*100 + der_ctors*10 + \
             der_dtors). 1010 means base dtor didn't fire (pre-tick-69 \
             behaviour); 99 means the catch never fired."
        );
    }

    /// t46 (J-11b, tick 69) — variant proving the cleanup pad does
    /// NOT fire when the derived ctor completes successfully.
    /// Sanity check: the cleanup scope's PC range must not match
    /// non-throwing exits. Without this lock, a buggy try_end > body
    /// could double-destroy.
    #[test]
    fn t46_base_dtor_fires_only_via_dtor_when_no_throw() {
        let src = "\
            int base_ctors = 0;\n\
            int base_dtors = 0;\n\
            int der_ctors = 0;\n\
            int der_dtors = 0;\n\
            class Base { public: int b; Base() { base_ctors = base_ctors + 1; b = 0; } ~Base() { base_dtors = base_dtors + 1; } };\n\
            class Derived : public Base { public: int d; Derived(int v) { der_ctors = der_ctors + 1; d = v; } ~Derived() { der_dtors = der_dtors + 1; } };\n\
            int main(void) {\n\
              { Derived c(5); }\n\
              return (base_ctors * 1000) + (base_dtors * 100) + (der_ctors * 10) + der_dtors;\n\
            }\n";
        let code = run_src(src);
        // Each counter should be exactly 1: one ctor + dtor on the
        // normal path. NOT 2 (would mean cleanup fired AND normal
        // dtor fired).
        assert_eq!(
            code, 1111,
            "tick-69 J-11b regression guard: a clean ctor+scope-exit \
             must NOT trigger the cleanup pad. Each counter should be \
             exactly 1 (1*1000 + 1*100 + 1*10 + 1 = 1111). Got {code}."
        );
    }

    /// t47 (J-11b-members, tick 70) — throw during a ctor body AFTER its
    /// class-typed member subobjects have been fully constructed.
    ///
    /// Per the C++ standard, when an exception escapes a constructor
    /// after one or more member subobjects have been fully constructed,
    /// those members' destructors MUST run during the unwind (in
    /// reverse construction order). Tick 70 wires this up by emitting
    /// a `CatchPolicy::Cleanup` scope per constructed class-typed
    /// member; the cleanup pad calls each constructed member's dtor in
    /// reverse order and re-raises.
    ///
    /// `Outer`:
    ///   * has two `Inner` members `a` and `b`
    ///   * its ctor body sets `z` and then throws 99
    ///   * at throw time, `a` and `b` are both fully constructed
    ///
    /// Exit code = (ictors * 1000) + idtors. Standard behaviour:
    /// `ictors = 2` (both Inner members constructed), `idtors = 2`
    /// (both run on unwind). Result: 2002.
    ///
    /// Pre-tick-70 (sub-standard): ictors=2, idtors=0 → 2000.
    #[test]
    fn t47_throw_during_ctor_runs_member_dtors() {
        let src = "\
            int ictors = 0;\n\
            int idtors = 0;\n\
            class Inner { public: int v; Inner() { ictors = ictors + 1; v = 0; } ~Inner() { idtors = idtors + 1; } };\n\
            class Outer { public: Inner a; Inner b; int z; Outer() { z = 0; throw 99; } ~Outer() { } };\n\
            int main(void) {\n\
              try { Outer o; return 1; }\n\
              catch (int e) { return (ictors * 1000) + idtors; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 2002,
            "tick-70 J-11b-members: both Inner members were constructed \
             before Outer's body threw; both Inner dtors must run on \
             the unwind path. Expected ictors=2, idtors=2 → 2002. Got \
             {code}. 2000 means dtors didn't fire (pre-tick-70). 1 \
             means the throw never fired."
        );
    }

    /// t48 (J-11b-members, tick 70) — partial-member-construction: the
    /// SECOND member's ctor throws. Per the C++ standard, the first
    /// member (already fully constructed) MUST be destroyed; the
    /// second member (still under construction when it threw) MUST
    /// NOT be destroyed.
    ///
    /// `Outer`:
    ///   * `Inner1 a` (always succeeds): ictors1+=1 in ctor, idtors1+=1 in dtor
    ///   * `Inner2 b` (always throws):   ictors2+=1 then throw 88
    ///
    /// Expected: ictors1=1, idtors1=1, ictors2=1, idtors2=0
    /// Encoded as (1000*ictors1) + (100*idtors1) + (10*ictors2) + idtors2
    /// = 1110.
    ///
    /// Pre-tick-70: 1010 (idtors1=0; the first member's dtor leaks).
    #[test]
    fn t48_throw_during_member_ctor_chain() {
        let src = "\
            int ictors1 = 0; int idtors1 = 0;\n\
            int ictors2 = 0; int idtors2 = 0;\n\
            class Inner1 { public: int v; Inner1() { ictors1 = ictors1 + 1; v = 0; } ~Inner1() { idtors1 = idtors1 + 1; } };\n\
            class Inner2 { public: int v; Inner2() { ictors2 = ictors2 + 1; throw 88; } ~Inner2() { idtors2 = idtors2 + 1; } };\n\
            class Outer { public: Inner1 a; Inner2 b; Outer() { } ~Outer() { } };\n\
            int main(void) {\n\
              try { Outer o; return 1; }\n\
              catch (int e) { return (1000*ictors1) + (100*idtors1) + (10*ictors2) + idtors2; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 1110,
            "tick-70 J-11b-members: Inner1 ctor ran (ictors1=1), \
             Inner2 ctor entered and threw (ictors2=1); the partially \
             constructed Inner2 must NOT be destroyed (idtors2=0); \
             the fully constructed Inner1 MUST be destroyed (idtors1=1). \
             Expected 1*1000 + 1*100 + 1*10 + 0 = 1110. Got {code}. \
             1010 means Inner1's dtor leaked (pre-tick-70). 1111 \
             means Inner2's dtor wrongly ran on a partial object."
        );
    }

    /// t48b (B-13) — same partial-member-construction rule as t48, but the
    /// member constructors are reached through an explicit member-initializer
    /// list with arguments. The cleanup counter must advance after
    /// `a(5)` succeeds even though it is not a zero-argument implicit default
    /// ctor call; when `b(6)` throws, only `a` is fully constructed and must be
    /// destroyed.
    #[test]
    fn t48b_throw_during_member_init_arg_ctor_chain() {
        let src = "\
            int ictors1 = 0; int idtors1 = 0;\n\
            int ictors2 = 0; int idtors2 = 0;\n\
            class Inner1 { public: int v; Inner1(int x) { ictors1 = ictors1 + 1; v = x; } ~Inner1() { idtors1 = idtors1 + 1; } };\n\
            class Inner2 { public: int v; Inner2(int x) { ictors2 = ictors2 + 1; v = x; throw 88; } ~Inner2() { idtors2 = idtors2 + 1; } };\n\
            class Outer { public: Inner1 a; Inner2 b; Outer() : a(5), b(6) { } ~Outer() { } };\n\
            int main(void) {\n\
              try { Outer o; return 1; }\n\
              catch (int e) { return (1000*ictors1) + (100*idtors1) + (10*ictors2) + idtors2; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 1110,
            "B-13: member-init ctor a(5) completed and must be destroyed \
             when member-init ctor b(6) throws. Expected ictors1=1, \
             idtors1=1, ictors2=1, idtors2=0 -> 1110. Got {code}. \
             1010 means the member-init ctor call did not advance the \
             partial-construction cleanup counter."
        );
    }

    /// t49 (J-11b-members, tick 70) — combined base + member partial-
    /// construction: a derived class with BOTH a base and a class-
    /// typed member. The user body throws after both are constructed.
    /// Per the C++ standard, member dtors run first (reverse
    /// construction order), then the base dtor.
    ///
    /// We only check that both dtors fire (not the order between them
    /// — that would require side-effect ordering, brittle to assert
    /// here). Encoded exit = base_dtors*100 + inner_dtors*10 + 1
    /// (caught). Expected: 100 + 10 + 1 = 111.
    ///
    /// Pre-tick-70 (base-only J-11b from tick 69): base_dtors=1,
    /// inner_dtors=0 → 101.
    #[test]
    fn t49_throw_during_ctor_with_base_and_members() {
        let src = "\
            int base_ctors = 0; int base_dtors = 0;\n\
            int inner_ctors = 0; int inner_dtors = 0;\n\
            class Base { public: int b; Base() { base_ctors = base_ctors + 1; b = 0; } ~Base() { base_dtors = base_dtors + 1; } };\n\
            class Inner { public: int v; Inner() { inner_ctors = inner_ctors + 1; v = 0; } ~Inner() { inner_dtors = inner_dtors + 1; } };\n\
            class Derived : public Base { public: Inner m; int d; Derived() { d = 0; throw 7; } ~Derived() { } };\n\
            int main(void) {\n\
              try { Derived c; return 0; }\n\
              catch (int e) { return base_dtors*100 + inner_dtors*10 + 1; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 111,
            "tick-70 J-11b-members: Derived's ctor threw AFTER its \
             Base AND its Inner member were both fully constructed. \
             Both Base::~Base and Inner::~Inner must run on the unwind \
             path. Expected base_dtors=1, inner_dtors=1, caught=1 → \
             100 + 10 + 1 = 111. Got {code}. 101 means inner_dtor \
             didn't fire (pre-tick-70 had base only)."
        );
    }

    /// t44 (J-12, H10 MAJOR-2 case 2) — throw inside a destructor that
    /// runs during NORMAL scope exit (i.e. not already unwinding). The
    /// dtor's emission site sits inside the try-body's
    /// [try_begin, try_end) PC range (see `gen_try`: `exit_scope` is
    /// called before `try_end` is captured), so the fresh exception's
    /// PC matches the scope-table entry and the catch fires.
    ///
    /// Exit code 9 proves: (a) the dtor body executed at scope exit,
    /// (b) the throw inside the dtor raised correctly, (c) the
    /// scope-table entry for the surrounding try caught it.
    ///
    /// Standard caveat (NOT exercised by v1): if the dtor throws while
    /// ALREADY unwinding (e.g. another exception is in flight), the
    /// behaviour is `std::terminate`. v1 does not implement the
    /// in-flight-exception detection — that case will surface as a
    /// STATUS_* process kill and is documented as a future J-12b.
    #[test]
    fn t44_dtor_throws_during_normal_scope_exit() {
        let src = "\
            class C {\n\
              public:\n\
                int x;\n\
                C() { x = 0; }\n\
                ~C() { throw 9; }\n\
            };\n\
            int main(void) {\n\
              try { C c; }\n\
              catch (int e) { return e; }\n\
              return 0;\n\
            }\n";
        let code = run_src(src);
        assert_eq!(
            code, 9,
            "dtor body's throw during normal scope exit must be caught \
             by the surrounding try; got {code:#x} ({code}). 0 would \
             mean the dtor never threw (or fell through); a STATUS_* \
             negative code means the throw escaped the scope-table's \
             PC range (the dtor's bytes landed AFTER try_end)."
        );
    }
}
