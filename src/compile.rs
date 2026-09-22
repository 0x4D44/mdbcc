//! End-to-end driver: C source bytes -> Win64 PE executable bytes.

use crate::codegen::{self, CodegenError};
use crate::coff;
use crate::lexer::{LexError, Lexer};
use crate::link::{self, LinkError, LinkOpts};
use crate::parser::{ParseError, Parser};
use crate::pp::{self, IncludeResolver, PpError};
use crate::rc::RcUnit;

/// Any failure in the compile pipeline, tagged with its phase.
#[derive(Debug)]
pub enum CompileError {
    Lex(LexError),
    Preprocess(PpError),
    Parse(ParseError),
    Codegen(CodegenError),
    Link(LinkError),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::Lex(e) => write!(f, "{e}"),
            CompileError::Preprocess(e) => write!(f, "{e}"),
            CompileError::Parse(e) => write!(f, "{e}"),
            CompileError::Codegen(e) => write!(f, "{e}"),
            CompileError::Link(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CompileError {}

impl From<LexError> for CompileError {
    fn from(e: LexError) -> Self {
        CompileError::Lex(e)
    }
}
impl From<PpError> for CompileError {
    fn from(e: PpError) -> Self {
        CompileError::Preprocess(e)
    }
}
impl From<ParseError> for CompileError {
    fn from(e: ParseError) -> Self {
        CompileError::Parse(e)
    }
}
impl From<CodegenError> for CompileError {
    fn from(e: CodegenError) -> Self {
        CompileError::Codegen(e)
    }
}
impl From<LinkError> for CompileError {
    fn from(e: LinkError) -> Self {
        CompileError::Link(e)
    }
}

/// S4.2-pre: is `file_name` a C++ translation unit (by extension)? Borland
/// treats `.cpp`/`.cc`/`.cxx`/`.C` as C++ and `.c` as C; the extension-less
/// `"<input>"` name used by the in-process byte-identity fixtures is C (so
/// those programs preprocess exactly as before — no `__cplusplus`). Drives
/// the `cplusplus` argument to [`pp::preprocess`] across the compile entry
/// points, mirroring the bcc32 driver's source-kind selection.
pub fn is_cxx_source(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower.ends_with(".cpp")
        || lower.ends_with(".cc")
        || lower.ends_with(".cxx")
        // `.C` (uppercase) is C++ to Borland; lowercased it collides with `.c`,
        // so test the original case for that one spelling.
        || file_name.ends_with(".C")
}

/// Lex the `(name, value)` command-line `-D` definitions into the
/// `(name, body-tokens)` form [`pp::preprocess_with_defines`] expects. The
/// value string is lexed as preprocessor tokens (so `-DFOO=1+2` is a
/// three-token body); the trailing `Eof` is dropped. An empty value
/// (`-DFOO=`) yields an empty body (expands to nothing). This is the one place
/// the value text meets the `Lexer`, keeping the preprocessor lexer-free.
fn lex_cli_defines(
    defines: &[(String, String)],
) -> Result<Vec<(String, Vec<crate::lexer::Token>)>, CompileError> {
    defines
        .iter()
        .map(|(name, value)| {
            let mut toks = Lexer::tokenize(value.as_bytes())?;
            toks.retain(|t| t.kind != crate::lexer::TokenKind::Eof);
            Ok((name.clone(), toks))
        })
        .collect()
}

/// Compile a translation unit to a runnable Win64 PE executable image.
/// `#include` "..." is resolved relative to the current directory; system
/// `<...>` headers are stubbed (our libc subset is intrinsic).
pub fn compile_to_pe(src: &[u8]) -> Result<Vec<u8>, CompileError> {
    let resolver = pp::DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    compile_to_pe_with(src, "<input>", &resolver)
}

/// As [`compile_to_pe`] but with an explicit translation-unit name and
/// `#include` resolver (used by the driver to search the input's directory).
pub fn compile_to_pe_with(
    src: &[u8],
    file_name: &str,
    resolver: &dyn IncludeResolver,
) -> Result<Vec<u8>, CompileError> {
    compile_to_pe_with_rc(src, file_name, resolver, None)
}

/// Full-control entry point: compile a translation unit, optionally with an
/// already-parsed `.rc` resource unit (Phase G / G3). When `rc_unit` is
/// `Some` and the unit carries at least one STRINGTABLE / MENU / DIALOG /
/// ACCEL entry, the linker emits a `.rsrc` section and fills
/// `DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE = 2]`. The CLI driver
/// (`src/main.rs`) wires sibling-`.rc` auto-detection here.
///
/// ## Pipeline (post-S1c.3)
///
/// `source → tokens → AST → Module → coff::Object → link::link_single → PE`
///
/// Prior to S1c.3 the path was `Module → PE` direct via
/// `pe::write_pe_with_rsrc`; that legacy entry point still exists for one
/// tick (per HLD §9 row S1c.3) for in-flight callers, but the production
/// pipeline now flows through the Object IR. The 88 e2e tests catch any
/// behavioural divergence; the SipHash baseline stripe in
/// `tests/o1_byte_identity.rs` was re-blessed in lockstep (the byte shift
/// is from §F (Object emits 16-byte function alignment) + module-wide
/// string dedup + unified relocation processing).
pub fn compile_to_pe_with_rc(
    src: &[u8],
    file_name: &str,
    resolver: &dyn IncludeResolver,
    rc_unit: Option<&RcUnit>,
) -> Result<Vec<u8>, CompileError> {
    compile_to_pe_with_rc_defines(src, file_name, resolver, rc_unit, &[])
}

/// As [`compile_to_pe_with_rc`] but with command-line `-D` object-macro
/// definitions (the `bcc -DWIN31 -o app.exe app.cpp` form). Existing callers
/// reach this with an empty `defines` slice, so they stay byte-identical.
pub fn compile_to_pe_with_rc_defines(
    src: &[u8],
    file_name: &str,
    resolver: &dyn IncludeResolver,
    rc_unit: Option<&RcUnit>,
    defines: &[(String, String)],
) -> Result<Vec<u8>, CompileError> {
    let tokens = Lexer::tokenize(src)?;
    // S4.2-pre: dialect from the source extension (see
    // `compile_to_object_with_target`). A `.cpp`/`.cc`/`.cxx`/`.C` source
    // defines `__cplusplus`; the extension-less `"<input>"` used by the 88
    // x64 SipHash baselines stays C mode ⇒ byte-identical.
    let defs = lex_cli_defines(defines)?;
    let tokens =
        pp::preprocess_with_defines(tokens, file_name, resolver, is_cxx_source(file_name), &defs)?;
    let tu = Parser::parse(&tokens)?;
    let module = codegen::compile_module(&tu)?;
    let object = module.to_object();
    let opts = LinkOpts {
        machine: coff::Machine::Amd64,
        subsystem: link::auto_subsystem(&object),
        entry: None,
        image_base: 0x1_4000_0000,
        stack_reserve: 0x100_000,
        stack_commit: 0x1000,
        heap_reserve: 0x100_000,
        heap_commit: 0x1000,
        synthesise_crt: false, // S1c.3 keeps the codegen-emitted entry path
        warnings_as_errors: false,
        archive_origin: Vec::new(),
        map: None,
        archive_trace: None,
    };
    let exe = link::link_single(&object, &opts)?;
    let exe = if let Some(rc) = rc_unit {
        link::merge_rsrc_unit(exe, rc)?
    } else {
        exe
    };
    Ok(exe)
}

/// S3 (`-E`) — run translation phases 1–4 only (lex + preprocess) and return
/// the resulting token stream. Used by the driver's `-E` preprocess-only mode:
/// success (returning `Ok`) means the preprocessor accepted the TU without
/// error; the caller decides how to render the tokens. The O15 header-
/// acceptance harness uses this same `lex → pp::preprocess` path through the
/// public [`pp::preprocess`] entry directly.
///
/// `cplusplus` selects the dialect (C++-mode predefines `__cplusplus` /
/// `__BCPLUSPLUS__`); the `-E` driver passes `false` (C mode).
pub fn preprocess_to_tokens(
    src: &[u8],
    file_name: &str,
    resolver: &dyn IncludeResolver,
    cplusplus: bool,
) -> Result<Vec<crate::lexer::Token>, CompileError> {
    let tokens = Lexer::tokenize(src)?;
    let tokens = pp::preprocess(tokens, file_name, resolver, cplusplus)?;
    Ok(tokens)
}

/// S1b.4 — compile a single translation unit straight to a COFF
/// [`coff::Object`] suitable for linking by `mdlink` (S1c) or a
/// third-party COFF linker (lld-link / link.exe).
///
/// The pipeline is identical to [`compile_to_pe`] through codegen,
/// then forks at the Module → IR seam:
/// ```text
///   source ─► tokens ─► preprocessed tokens ─► AST ─► Module ─► Object
///                                                              ▲
///                                                              this fn
/// ```
/// `compile_to_pe` continues with `pe::write_pe_with_rsrc(&module, ..)`
/// (the in-process single-TU fast path, kept for the 88 e2e and 17
/// determinism fixtures); `compile_to_object` instead converts to the
/// new COFF Object IR and stops, leaving linking to mdlink.
///
/// Per HLD §1.4 this is the entry point the `bcc -c` CLI flag will
/// wire through (S1b.5). The existing pe-emitting path stays unchanged
/// in S1b.4 — equivalence between the two paths is enforced by S1b.6
/// (O13 oracle) and S1b.8 (OBJ byte-identity stripe), not by this
/// function.
pub fn compile_to_object(src: &[u8]) -> Result<coff::Object, CompileError> {
    let resolver = pp::DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    compile_to_object_with(src, "<input>", &resolver)
}

/// As [`compile_to_object`] but with an explicit TU name and `#include`
/// resolver (mirrors [`compile_to_pe_with`]).
pub fn compile_to_object_with(
    src: &[u8],
    file_name: &str,
    resolver: &dyn IncludeResolver,
) -> Result<coff::Object, CompileError> {
    compile_to_object_with_target(
        src,
        file_name,
        resolver,
        crate::codegen::target::TargetKind::Win64,
    )
}

/// As [`compile_to_object_with`] but for an explicit `target` (S2b.2).
/// `Win64` is the historical default; `Win32` emits an i386 COFF object
/// (machine `IMAGE_FILE_MACHINE_I386`) the linker turns into a PE32 with
/// `mdlink -m32`. The driver's `-m32` flag routes here.
pub fn compile_to_object_with_target(
    src: &[u8],
    file_name: &str,
    resolver: &dyn IncludeResolver,
    target: crate::codegen::target::TargetKind,
) -> Result<coff::Object, CompileError> {
    compile_to_object_with_target_defines(src, file_name, resolver, target, &[])
}

/// As [`compile_to_object_with_target`] but with command-line `-D` object-macro
/// definitions (the `bcc -c -DWIN31 ...` form). Existing callers reach this
/// with an empty `defines` slice, so the i386/x64 byte-identity stripes and
/// every test caller stay byte-identical.
pub fn compile_to_object_with_target_defines(
    src: &[u8],
    file_name: &str,
    resolver: &dyn IncludeResolver,
    target: crate::codegen::target::TargetKind,
    defines: &[(String, String)],
) -> Result<coff::Object, CompileError> {
    compile_to_object_reported(src, file_name, resolver, target, defines, &mut |_| {})
}

/// Coarse pipeline stages reported to a driver's progress callback. They match
/// the user-visible work order; sub-steps (lexing folds into preprocess,
/// monomorphisation folds into codegen) are deliberately not surfaced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompilePhase {
    Preprocess,
    Parse,
    Codegen,
}

/// Fractional milliseconds for an elapsed `Duration`. `MDBCC_TIME` prints at
/// this resolution so sub-millisecond phases don't floor to `0 ms`.
fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// As [`compile_to_object_with_target_defines`] but ticks `on_phase` as the
/// translation unit moves through preprocess -> parse -> codegen, so the
/// `mdbcc` driver can show a live status line. The callback is the only
/// difference; byte output is identical.
pub fn compile_to_object_reported(
    src: &[u8],
    file_name: &str,
    resolver: &dyn IncludeResolver,
    target: crate::codegen::target::TargetKind,
    defines: &[(String, String)],
    on_phase: &mut dyn FnMut(CompilePhase),
) -> Result<coff::Object, CompileError> {
    use crate::codegen::target::TargetKind;
    let time = std::env::var_os("MDBCC_TIME").is_some();
    on_phase(CompilePhase::Preprocess);
    let t_lex = std::time::Instant::now();
    let tokens = Lexer::tokenize(src)?;
    if time {
        eprintln!("[MDBCC_TIME] lex: {:.3} ms", ms(t_lex.elapsed()));
    }
    // S4.2-pre: select the dialect from the source extension. A C++ source
    // (`.cpp`/`.cc`/`.cxx`/`.C`) preprocesses with `__cplusplus` defined so
    // the C++-only header branches compile (OWL/BIDS guard with
    // `#error Must use C++`); a `.c` source — and the extension-less
    // `"<input>"` used by every byte-identity fixture — stays C mode, so the
    // 88 x64 SipHash baselines are unchanged.
    let defs = lex_cli_defines(defines)?;
    let t_pp = std::time::Instant::now();
    let tokens =
        pp::preprocess_with_defines(tokens, file_name, resolver, is_cxx_source(file_name), &defs)?;
    if time {
        eprintln!("[MDBCC_TIME] preprocess: {:.3} ms", ms(t_pp.elapsed()));
    }
    // Lay records out for the target's pointer width: Win32 is ILP32 (4-byte
    // pointers, so a pointer member / the polymorphic vptr is 4 bytes and
    // struct `sizeof`/offsets match bcc32's i386 ABI); Win64 is LLP64 (8-byte
    // pointers — byte-for-byte the historical `Parser::parse`). Codegen's
    // pointer-size-dependent sites (sizeof folding, index/pointer-arith
    // scaling) read the same width via `Gen::target_ptr_bytes`.
    let ptr_bytes = match target {
        TargetKind::Win64 => 8,
        TargetKind::Win32 => 4,
    };
    let t0 = std::time::Instant::now();
    on_phase(CompilePhase::Parse);
    let tu = Parser::parse_for(&tokens, ptr_bytes)?;
    if time {
        eprintln!("[MDBCC_TIME] parse: {:.3} ms", ms(t0.elapsed()));
    }
    let t1 = std::time::Instant::now();
    on_phase(CompilePhase::Codegen);
    let module = codegen::compile_module_for(&tu, target)?;
    if time {
        eprintln!("[MDBCC_TIME] codegen: {:.3} ms", ms(t1.elapsed()));
    }
    let t2 = std::time::Instant::now();
    let object = module.to_object();
    if time {
        eprintln!("[MDBCC_TIME] to_object: {:.3} ms", ms(t2.elapsed()));
    }
    Ok(object)
}
