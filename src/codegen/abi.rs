//! Win64 ABI encoding constants and aggregate-classification helpers.
//!
//! This module centralises the Win64 calling-convention surface that was
//! previously interleaved with general codegen in `src/codegen.rs`:
//!
//! * Positional-register byte sequences for the four argument GPRs
//!   ([`ARG_SPILL`], [`ARG_LOAD`]) and the four argument XMMs
//!   ([`ARG_SPILL_XMM`], [`ARG_LOAD_XMM`]). Each entry is the opcode
//!   prefix at the `disp32` slot; emit sites append a 32-bit displacement.
//! * SSE2 scalar (double-precision) instruction byte literals for the
//!   FP arithmetic path (`MOVSD_*`, `ADDSD_*`, `SUBSD_*`, `MULSD_*`,
//!   `DIVSD_*`, `UCOMISD_*`, `XORPD_*`, `CVTSI2SD_*`, `CVTTSD2SI_*`).
//! * The Win64 aggregate-by-value classifier
//!   ([`classify_struct_for_win64`] + [`StructAbiClass`]) — one-rule
//!   "size 1/2/4/8 → InReg; everything else → HiddenPtr" function used
//!   by the call-site marshalling code and the return-value lowering.
//!
//! All items are crate-private (`pub(crate)`) so they can be referenced
//! uniformly from `codegen.rs` and the sibling `codegen/*.rs` modules
//! without leaking through the crate's public API surface.
//!
//! ## O1 byte-identity invariant
//!
//! This module is a pure refactor of pre-existing constants and a pure
//! function with no Gen state — every byte the codegen emits via these
//! constants is identical to before the split. `tests/o1_byte_identity.rs`
//! (88 SipHash baselines) is the regression lock.

/// Win64 argument-register **store** encodings (callee-side spill of an
/// incoming arg into the locals frame). Slot `i` ∈ 0..4 gives the
/// `MOV [rbp+disp32], <regI>` instruction's prefix bytes (the `disp32`
/// must be appended by the emit site). Register order matches Win64
/// positional ABI: RCX, RDX, R8, R9.
pub(crate) const ARG_SPILL: [&[u8]; 4] = [
    &[0x48, 0x89, 0x8D], // mov [rbp+d], rcx
    &[0x48, 0x89, 0x95], // mov [rbp+d], rdx
    &[0x4C, 0x89, 0x85], // mov [rbp+d], r8
    &[0x4C, 0x89, 0x8D], // mov [rbp+d], r9
];

/// Win64 argument-register **load** encodings (caller-side load of a
/// temp slot into an argument register before a call). Slot `i` ∈ 0..4
/// gives the `MOV <regI>, [rbp+disp32]` instruction's prefix bytes.
pub(crate) const ARG_LOAD: [&[u8]; 4] = [
    &[0x48, 0x8B, 0x8D], // mov rcx, [rbp+d]
    &[0x48, 0x8B, 0x95], // mov rdx, [rbp+d]
    &[0x4C, 0x8B, 0x85], // mov r8,  [rbp+d]
    &[0x4C, 0x8B, 0x8D], // mov r9,  [rbp+d]
];

// Phase F-3: Win64 positional FP register ABI (§F-c). Slot `i` is xmmI if the
// declared parameter at position `i` is `Type::Float`, otherwise the GPR via
// `ARG_LOAD[i]`/`ARG_SPILL[i]`. Slot index is param POSITION — a mixed
// signature like `void f(int, double, int, double)` uses rcx, xmm1, r8, xmm3
// (xmm0/rdx/xmm2/r9 are skipped at those positions). xmm regs ≥ 8 are not
// used — every encoding is REX-free. ModR/M for `[rbp+disp32]` is
// `mod=10 reg=N rm=101` ⇒ byte `0x85 | (N << 3)`: 0x85, 0x8D, 0x95, 0x9D for
// xmm0..xmm3. The 4-byte `float` case shares the 8-byte movsd path (mirrors
// F-2's storage discipline; genuine movss/cvtss2sd deferred to F-future).
//
// `movsd xmmN, [rbp+disp32]` — F2 0F 10 /N [rbp+disp32].
pub(crate) const ARG_LOAD_XMM: [&[u8]; 4] = [
    &[0xF2, 0x0F, 0x10, 0x85], // movsd xmm0, [rbp+d]
    &[0xF2, 0x0F, 0x10, 0x8D], // movsd xmm1, [rbp+d]
    &[0xF2, 0x0F, 0x10, 0x95], // movsd xmm2, [rbp+d]
    &[0xF2, 0x0F, 0x10, 0x9D], // movsd xmm3, [rbp+d]
];
/// `movsd [rbp+disp32], xmmN` — F2 0F 11 /N [rbp+disp32].
pub(crate) const ARG_SPILL_XMM: [&[u8]; 4] = [
    &[0xF2, 0x0F, 0x11, 0x85], // movsd [rbp+d], xmm0
    &[0xF2, 0x0F, 0x11, 0x8D], // movsd [rbp+d], xmm1
    &[0xF2, 0x0F, 0x11, 0x95], // movsd [rbp+d], xmm2
    &[0xF2, 0x0F, 0x11, 0x9D], // movsd [rbp+d], xmm3
];

/// 4-byte `float` parameter spill (companions to `ARG_SPILL_XMM`). The Win64
/// caller passes an FP arg in xmmN as an 8-byte f64; a `float` (4-byte) param's
/// home slot must instead hold the 4-byte f32 IMAGE so the body's
/// `load_rax(Float{bytes:4})` (a `movss`) reads it back correctly. So the
/// callee narrows the register in place (`cvtsd2ss xmmN,xmmN`, register-only,
/// no disp) then stores 4 bytes (`movss [rbp+disp32], xmmN`). Without this the
/// slot keeps an f64 and the narrowed read yields garbage (the DrawDelayBox-
/// style float-param miscompile).
/// `cvtsd2ss xmmN,xmmN` — F2 0F 5A /N N (mod=11): C0, C9, D2, DB for xmm0..3.
pub(crate) const CVTSD2SS_XMM_SELF: [&[u8]; 4] = [
    &[0xF2, 0x0F, 0x5A, 0xC0], // cvtsd2ss xmm0,xmm0
    &[0xF2, 0x0F, 0x5A, 0xC9], // cvtsd2ss xmm1,xmm1
    &[0xF2, 0x0F, 0x5A, 0xD2], // cvtsd2ss xmm2,xmm2
    &[0xF2, 0x0F, 0x5A, 0xDB], // cvtsd2ss xmm3,xmm3
];
/// `movss [rbp+disp32], xmmN` — F3 0F 11 /N [rbp+disp32]; modrm 0x85|(N<<3).
pub(crate) const ARG_SPILL_XMM_SS: [&[u8]; 4] = [
    &[0xF3, 0x0F, 0x11, 0x85], // movss [rbp+d], xmm0
    &[0xF3, 0x0F, 0x11, 0x8D], // movss [rbp+d], xmm1
    &[0xF3, 0x0F, 0x11, 0x95], // movss [rbp+d], xmm2
    &[0xF3, 0x0F, 0x11, 0x9D], // movss [rbp+d], xmm3
];

// ---- SSE2 scalar (Phase F-2; migrated to encoder in S2a) --------------------
//
// The full SSE2 scalar instruction set previously lived here as inline
// byte-literal `&[u8]` constants. As of S2a (HLD 2026-05-27 §3) those
// encodings are owned by `crate::codegen::encoder` and consumed from
// `src/codegen.rs` through the `Gen::encode()` table-driven helper:
//
// - `movsd` / `addsd` / `subsd` / `mulsd` / `divsd` rows in
//   [`crate::codegen::encoder::patterns::PATTERN_TABLE`].
// - `ucomisd` / `xorpd` / `cvtsi2sd` / `cvttsd2si` same.
//
// The Win64 ABI positional-register arrays (`ARG_*` below) remain here
// because their per-slot indexing is a separate ABI concern from the
// instruction encoding (S2b adds the Win32 `__fastcall` slot table
// alongside; both will move to the `Target` trait in S2b).

/// Phase H1: Win64 ABI classification for an aggregate (struct/union/class)
/// argument or parameter, keyed *only* on byte size. The Microsoft x64 ABI
/// (NOT SysV) has a single rule: sizes 1, 2, 4, or 8 are passed packed in
/// the positional integer register; **all other sizes** — including the
/// silent-trap cases 3, 5, 6, 7 and anything > 8 — are passed by hidden
/// pointer to a caller-allocated copy. No field-class classification, no
/// FP/SSE consideration for aggregates. Pure function, hence unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructAbiClass {
    /// Packed into the positional integer register (zero-extended in the
    /// caller); slot width is always 8 bytes on the stack/in the GPR.
    /// `bytes` ∈ {1, 2, 4, 8} — the *actual* struct size, not 8.
    InReg(u8),
    /// Passed as a pointer to a caller-allocated copy. The callee may write
    /// freely through the pointer without affecting the caller's original.
    HiddenPtr,
}

pub(crate) fn classify_struct_for_win64(size: usize) -> StructAbiClass {
    match size {
        1 | 2 | 4 | 8 => StructAbiClass::InReg(size as u8),
        _ => StructAbiClass::HiddenPtr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase H1: the Win64 aggregate ABI is *only* keyed on byte size, NOT
    /// on field count / FP membership / SysV-style eightbyte classification.
    /// 1/2/4/8 ⇒ InReg; the silent-trap quartet 3/5/6/7 and every size > 8
    /// ⇒ HiddenPtr. Exhaustively pinning these protects against accidental
    /// pad-to-power-of-two miscompiles (the well-known Win64 footgun).
    #[test]
    fn classify_struct_for_win64_rules() {
        use StructAbiClass::*;
        assert_eq!(classify_struct_for_win64(1), InReg(1));
        assert_eq!(classify_struct_for_win64(2), InReg(2));
        assert_eq!(classify_struct_for_win64(4), InReg(4));
        assert_eq!(classify_struct_for_win64(8), InReg(8));
        // The four sizes that MUST go HiddenPtr (NOT zero-padded to 4 or 8).
        assert_eq!(classify_struct_for_win64(3), HiddenPtr);
        assert_eq!(classify_struct_for_win64(5), HiddenPtr);
        assert_eq!(classify_struct_for_win64(6), HiddenPtr);
        assert_eq!(classify_struct_for_win64(7), HiddenPtr);
        // Everything > 8.
        assert_eq!(classify_struct_for_win64(9), HiddenPtr);
        assert_eq!(classify_struct_for_win64(12), HiddenPtr);
        assert_eq!(classify_struct_for_win64(16), HiddenPtr);
        assert_eq!(classify_struct_for_win64(24), HiddenPtr);
        assert_eq!(classify_struct_for_win64(64), HiddenPtr);
        assert_eq!(classify_struct_for_win64(1024), HiddenPtr);
    }
}
