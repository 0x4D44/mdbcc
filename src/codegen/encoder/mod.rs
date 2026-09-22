//! Table-driven x86 instruction encoder (S2a). Per HLD §3.
//!
//! Replaces the historical hand-rolled byte literals in `src/codegen.rs`
//! (~800 emit sites baked into the file as `self.emit(&[0x48, 0x8B,
//! 0x85])` followed by `self.emit_disp32(off)`) with a [`Pattern`]-driven
//! interface. The caller names a logical operation + operands; the
//! encoder consults [`patterns::PATTERN_TABLE`] for the canonical bytes.
//!
//! ## API surface
//!
//! ```ignore
//! use crate::codegen::encoder::{encode_x64, builders::*, Op};
//!
//! let enc = encode_x64(Op::Mov, &[
//!     reg64(Rax),
//!     mem64(Rbp, -16, Disp32),
//! ])?;
//! self.code.extend_from_slice(&enc.bytes);
//! if let Some(at) = enc.riprel_at {
//!     self.riprefs.push(RipReloc { at: code_start + at, target });
//! }
//! ```
//!
//! S2a is x64-only — the encoder always passes `ArchSet::X64Only` as the
//! target. S2b retrofits a `target_arch` parameter when the Win32 stripe
//! lands.
//!
//! ## Byte-identity invariant
//!
//! The encoder MUST emit bytes equal to the hand-rolled bytes the
//! pre-S2a codegen produced at every migrated call site. The 88-fixture
//! O1 SipHash stripe in `tests/o1_byte_identity.rs` is the regression
//! gate. Any divergence is a hard failure.

pub mod emit;
pub mod patterns;
pub mod regs;
pub mod table;

pub use regs::RegId;
pub use table::{
    ArchSet, DispKind, EncodeError, Encoded, ImmKind, Op, Operand, RegClass, ScaleKind,
};

/// Encode `op` against the table for the **x64** target (`ArchSet::X64Only`):
/// `Both` + `X64Only` rows match; REX prefixes are emitted per row policy.
pub fn encode_x64(op: Op, operands: &[Operand]) -> Result<Encoded, EncodeError> {
    emit::encode(patterns::PATTERN_TABLE, op, operands, ArchSet::X64Only)
}

/// Encode `op` against the table for the **x86** target (`ArchSet::X86Only`,
/// S2b.4): `Both` + `X86Only` rows match; the REX byte is suppressed (32-bit
/// mode has none). Absolute `[disp32]` operands ([`Operand::MemAbs`]) report
/// their fixup slot via [`Encoded::abs_at`] instead of `riprel_at`.
pub fn encode_x86(op: Op, operands: &[Operand]) -> Result<Encoded, EncodeError> {
    emit::encode(patterns::PATTERN_TABLE, op, operands, ArchSet::X86Only)
}

/// Ergonomic operand builders. Hand-rolled call sites translate to
/// `encode_x64(Op::Foo, &[reg64(Rax), mem64(Rbp, -8, Disp32)])` etc.
pub mod builders {
    use super::*;

    pub fn reg64(r: RegId) -> Operand {
        Operand::Reg(RegClass::Gpr64, r)
    }
    pub fn reg32(r: RegId) -> Operand {
        Operand::Reg(RegClass::Gpr32, r)
    }
    pub fn reg8(r: RegId) -> Operand {
        Operand::Reg(RegClass::Gpr8, r)
    }
    pub fn xmm(r: RegId) -> Operand {
        Operand::Reg(RegClass::Xmm, r)
    }
    pub fn mem64(base: RegId, disp: i32, kind: DispKind) -> Operand {
        Operand::Mem {
            class: RegClass::Gpr64,
            base,
            disp,
            kind,
        }
    }
    pub fn mem32(base: RegId, disp: i32, kind: DispKind) -> Operand {
        Operand::Mem {
            class: RegClass::Gpr32,
            base,
            disp,
            kind,
        }
    }
    pub fn imm32(v: i32) -> Operand {
        Operand::Imm(ImmKind::Imm32, v as i64)
    }
    pub fn imm64(v: i64) -> Operand {
        Operand::Imm(ImmKind::Imm64, v)
    }
    pub fn riprel() -> Operand {
        Operand::MemRipRel
    }
    /// x86 absolute `[disp32]` operand (S2b.4). The address is a link-time
    /// fixup; the encoder emits a 4-byte zero slot and reports its offset
    /// in [`Encoded::abs_at`].
    pub fn memabs() -> Operand {
        Operand::MemAbs
    }
    pub fn rel32() -> Operand {
        Operand::Rel32
    }
}

#[cfg(test)]
mod tests;
