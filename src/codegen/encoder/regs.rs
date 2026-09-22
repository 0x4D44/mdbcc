//! Register identifiers and the per-arch register-number map (S2a).
//!
//! The encoder's table refers to operands by [`RegId`] — a flat enum over
//! the registers mdbcc emits today. Each variant maps to a 4-bit register
//! number `0..=15` via [`RegId::number`], the value that goes into the
//! ModR/M `reg`/`rm` field (low 3 bits) and the REX `R`/`B`/`X` extension
//! bit (bit 3). Register *width* is not encoded here — that's a property
//! of the [`RegClass`] in the [`Pattern`](super::table::Pattern), so an
//! operand of `Reg(Gpr32, Rax)` means EAX while `Reg(Gpr64, Rax)` means
//! RAX. Same register number, different opcode width.
//!
//! XMM registers share the namespace but their numbers do not overlap with
//! GPR numbers in any single encoding — XMM uses a separate opcode family
//! (the `0F` escape prefix + SSE prefix). mdbcc only uses XMM0/XMM1 today.

/// A register identifier. Values mirror Intel's encoding (RAX=0 … R15=15
/// for GPR; XMM0=0 … XMM15=15 for SSE registers). The two groups share
/// numeric values but never share encoding context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegId {
    // GPR (16-register file; the low 8 are encodable without REX.[R|B]=1).
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    // XMM (SSE/SSE2; we never use XMM8+ today — every encoding is REX-free).
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
}

impl RegId {
    /// The 4-bit register number (0..=15). Low 3 bits go into ModR/M
    /// `reg`/`rm`; bit 3 sets REX.[R|B|X] depending on context.
    pub const fn number(self) -> u8 {
        match self {
            RegId::Rax => 0,
            RegId::Rcx => 1,
            RegId::Rdx => 2,
            RegId::Rbx => 3,
            RegId::Rsp => 4,
            RegId::Rbp => 5,
            RegId::Rsi => 6,
            RegId::Rdi => 7,
            RegId::R8 => 8,
            RegId::R9 => 9,
            RegId::R10 => 10,
            RegId::R11 => 11,
            RegId::R12 => 12,
            RegId::R13 => 13,
            RegId::R14 => 14,
            RegId::R15 => 15,
            RegId::Xmm0 => 0,
            RegId::Xmm1 => 1,
            RegId::Xmm2 => 2,
            RegId::Xmm3 => 3,
            RegId::Xmm4 => 4,
            RegId::Xmm5 => 5,
            RegId::Xmm6 => 6,
            RegId::Xmm7 => 7,
            RegId::Xmm8 => 8,
            RegId::Xmm9 => 9,
            RegId::Xmm10 => 10,
            RegId::Xmm11 => 11,
            RegId::Xmm12 => 12,
            RegId::Xmm13 => 13,
            RegId::Xmm14 => 14,
            RegId::Xmm15 => 15,
        }
    }

    /// True for R8..R15 / XMM8..XMM15 — the "extended" half that needs
    /// REX.[R|B|X]=1 to be reachable.
    pub const fn needs_rex_extension(self) -> bool {
        self.number() >= 8
    }

    /// True for the GPR half of the namespace.
    pub const fn is_gpr(self) -> bool {
        matches!(
            self,
            RegId::Rax
                | RegId::Rcx
                | RegId::Rdx
                | RegId::Rbx
                | RegId::Rsp
                | RegId::Rbp
                | RegId::Rsi
                | RegId::Rdi
                | RegId::R8
                | RegId::R9
                | RegId::R10
                | RegId::R11
                | RegId::R12
                | RegId::R13
                | RegId::R14
                | RegId::R15
        )
    }
}
