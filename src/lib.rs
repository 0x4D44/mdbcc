//! mdbcc — a from-scratch reimplementation of the Borland C++ compiler toolchain.
//!
//! The crate is organised as a classic compiler pipeline. Components are added
//! as vertical slices; each slice is expected to actually work end-to-end and
//! be covered by tests. See `notes/scratchpad.md` for the roadmap.

pub mod ast;
pub mod codegen;
pub mod coff;
pub mod compile;
pub mod diag;
pub mod eh;
pub mod lexer;
pub mod link;
pub mod overlay;
pub mod parser;
pub mod pp;
pub mod progress;
pub mod project;
pub mod rc;

pub use compile::{CompileError, compile_to_object, compile_to_pe};
pub use lexer::{LexError, Lexer, Token, TokenKind};
pub use parser::{ParseError, Parser};
pub use pp::{PpError, preprocess};

/// Borland C++ 4.52 symbol-mangling helpers (HLD 2026-05-27 §3). These
/// are crate-internal in everyday use (called by `codegen.rs` when it
/// emits an overloaded-function or member-function symbol), but they're
/// exposed here so the regression suite in `tests/borland_mangling.rs`
/// can exercise each row of HLD §3.1's table against the BCC 4.52
/// reference encoding without having to spin up the full codegen.
pub mod mangling {
    pub use crate::codegen::cpp::{
        borland_c_symbol, borland_mangle_type, borland_mangle_type_with_records,
        borland_operator_special_name, borland_typeinfo_symbol, borland_vtable_symbol,
        overload_symbol, type_code,
    };
}

/// S2a: public re-export of the table-driven instruction encoder for the
/// `tests/encoder_table.rs` integration suite. The encoder itself lives
/// at `crate::codegen::encoder` and stays `pub(crate)` for everyday
/// internal use; this aliased re-export is the (narrow) public surface
/// the regression-test file exercises. If/when S8 stands up a real
/// disassembler that needs the table, this re-export gets promoted to
/// a proper top-level `pub mod encoder` declaration.
pub mod encoder_api {
    pub use crate::codegen::encoder::{
        ArchSet, DispKind, EncodeError, Encoded, ImmKind, Op, Operand, RegClass, RegId, ScaleKind,
        builders, encode_x64,
    };
}
