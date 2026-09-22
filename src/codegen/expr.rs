//! Expression-level codegen support helpers.
//!
//! The bulk of expression lowering — `Gen::gen_expr`, `Gen::gen_addr`,
//! `Gen::gen_binary`, `Gen::gen_call_with_lead`, `Gen::marshal_args`,
//! `Gen::expr_type`, the printf machinery (`Gen::gen_io_builtin`,
//! `Gen::fmt_*`, `Gen::int_token`, `Gen::float_token`), and so on —
//! still lives on `impl Gen` in `src/codegen.rs` because every one of
//! those methods threads through the full per-function code stream,
//! slot allocator, FP literal pool, RipRef table, and call-site list.
//! Splitting them into a separate file would require making roughly
//! two dozen `Gen` fields and at least as many helper methods
//! `pub(crate)` for a marginal readability win; the eh.rs precedent
//! already demonstrated that pattern works, but we land it incrementally
//! if/when a later S1 sub-phase needs the seam.
//!
//! What lives HERE:
//!
//! * [`FmtSpec`] / [`parse_fmt`] — the printf-format-spec parser pair
//!   used by `Gen::gen_io_builtin` to decode `%<flags><width>.<prec><conv>`
//!   into a per-call-site spec. Pure functions over `&[u8]`; no `Gen`
//!   state.
//! * [`binop_spelling`] — operator-overload spelling map (`+`, `-`, …)
//!   used to build the synthesised `operator+`-style method-call
//!   expression. Pure function over `BinOp`.
//! * [`libc_ret`] — return-type lookup table for the libc intrinsics
//!   (`strlen`, `strcmp`, `strcpy`, `memcpy`, etc.) the codegen
//!   emits inline. Pure function over `&str`.
//!
//! All three are pure / no-state helpers, so they extract cleanly.
//!
//! ## O1 byte-identity invariant
//!
//! Pure refactor. The format-spec decisions, operator spellings, and
//! libc return types are identical to before the split, so the
//! emission they gate is unchanged.

use crate::ast::{BinOp, Type};
use crate::codegen::CodegenError;

/// A parsed `printf` conversion specification (the bits between `%` and the
/// conversion letter). Flags/width/precision are *compile-time constants*
/// (from the literal format string), so emission is specialised per call
/// site. `*` (runtime width/precision) is rejected explicitly.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FmtSpec {
    pub(crate) left: bool,
    pub(crate) zero: bool,
    pub(crate) plus: bool,
    pub(crate) space: bool,
    pub(crate) alt: bool,
    pub(crate) width: Option<u32>,
    pub(crate) prec: Option<u32>,
}

impl FmtSpec {
    /// No formatting requested — use the original fast path unchanged.
    pub(crate) fn is_plain(&self) -> bool {
        !self.left
            && !self.zero
            && !self.plus
            && !self.space
            && !self.alt
            && self.width.is_none()
            && self.prec.is_none()
    }
}

/// Parse a conversion specifier starting at `fmt[at] == b'%'`. Returns the
/// spec, the conversion byte, and the index just past the conversion.
pub(crate) fn parse_fmt(fmt: &[u8], at: usize) -> Result<(FmtSpec, u8, usize), CodegenError> {
    let mut k = at + 1;
    let mut s = FmtSpec::default();
    while k < fmt.len() {
        match fmt[k] {
            b'-' => s.left = true,
            b'0' => s.zero = true,
            b'+' => s.plus = true,
            b' ' => s.space = true,
            b'#' => s.alt = true,
            _ => break,
        }
        k += 1;
    }
    if k < fmt.len() && fmt[k] == b'*' {
        return Err(CodegenError("printf: '*' width not supported".into()));
    }
    let mut w: u32 = 0;
    let mut have_w = false;
    while k < fmt.len() && fmt[k].is_ascii_digit() {
        have_w = true;
        w = w * 10 + (fmt[k] - b'0') as u32;
        if w > 256 {
            return Err(CodegenError("printf: field width > 256 unsupported".into()));
        }
        k += 1;
    }
    if have_w {
        s.width = Some(w);
    }
    if k < fmt.len() && fmt[k] == b'.' {
        k += 1;
        if k < fmt.len() && fmt[k] == b'*' {
            return Err(CodegenError("printf: '*' precision not supported".into()));
        }
        let mut p: u32 = 0;
        while k < fmt.len() && fmt[k].is_ascii_digit() {
            p = p * 10 + (fmt[k] - b'0') as u32;
            if p > 256 {
                return Err(CodegenError("printf: precision > 256 unsupported".into()));
            }
            k += 1;
        }
        s.prec = Some(p);
    }
    // Length modifiers (h, hh, l, ll, L, j, z, t): long==int==4 on every
    // target here, so they are accepted and ignored.
    while k < fmt.len() && matches!(fmt[k], b'h' | b'l' | b'L' | b'j' | b'z' | b't') {
        k += 1;
    }
    if k >= fmt.len() {
        return Err(CodegenError("printf: truncated format specifier".into()));
    }
    let conv = fmt[k];
    // Phase F-4: 'f' joins the v1 conversion set; 'g'/'G'/'e'/'E' are
    // explicit "Phase F-5 deferred" errors (HLD §F-h — `%g` chooses between
    // `%e`/`%f` and strips trailing zeros, layered on top of the proven `%f`).
    if matches!(conv, b'g' | b'G' | b'e' | b'E') {
        return Err(CodegenError(format!(
            "printf: '%{}' is Phase F-5 deferred (v1 ships '%f' only)",
            conv as char
        )));
    }
    if !b"diouxXcspf".contains(&conv) {
        return Err(CodegenError(format!(
            "printf: unsupported conversion '%{}'",
            conv as char
        )));
    }
    Ok((s, conv, k + 1))
}

/// The canonical spelling of an overloadable binary `op`, or `None` if we
/// don't lower that operator to a member call yet.
pub(crate) fn binop_spelling(op: BinOp) -> Option<&'static str> {
    use BinOp::*;
    Some(match op {
        Add => "+",
        Sub => "-",
        Mul => "*",
        Div => "/",
        Mod => "%",
        Eq => "==",
        Ne => "!=",
        Lt => "<",
        Le => "<=",
        Gt => ">",
        Ge => ">=",
        // Shift + bitwise operators are overloadable too — the stream classes
        // spell extraction/insertion as `operator>>` / `operator<<` (IOSTREAM.H),
        // and BIDS containers overload the bitwise ops. Only consulted for a
        // RECORD left operand (see `overloaded_binop`); an integer `a >> b`
        // never reaches here.
        Shl => "<<",
        Shr => ">>",
        BitAnd => "&",
        BitOr => "|",
        BitXor => "^",
        _ => return None,
    })
}

/// Return type of an intrinsic libc function, or `None` if `name` is not
/// one we provide as a builtin.
pub(crate) fn libc_ret(name: &str) -> Option<Type> {
    Some(match name {
        "strlen" | "strcmp" | "memcmp" | "abs" | "atoi" => Type::int(),
        "strcpy" | "strcat" => Type::Ptr(Box::new(Type::char_())),
        "memcpy" | "memset" => Type::Ptr(Box::new(Type::Void)),
        _ => return None,
    })
}
