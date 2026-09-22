// `0b00 << 6` is intentional bit-pattern documentation when constructing
// ModR/M / SIB bytes (it documents that the mod-field is zero); rewriting
// loses readability in a wire-encoding context.
#![allow(clippy::identity_op)]

//! Bytes-assembly engine (S2a). Per HLD §3 + §3.6.
//!
//! Takes a matched [`Pattern`] + the call's [`Operand`] list and produces
//! the wire bytes the calling [`crate::codegen::Gen`] appends. The flow is
//! straightforward — for each row:
//!
//! 1. Emit opcode prefixes (legacy / SSE — `66`/`F2`/`F3`).
//! 2. Compute & emit the REX byte if the policy demands one.
//! 3. Emit opcode bytes; OR the operand-0 register low 3 bits into the
//!    last opcode byte if [`Pattern::opcode_reg`] is set.
//! 4. Assemble & emit ModR/M + SIB (when [`Pattern::modrm`] is `Some`).
//! 5. Emit displacement bytes (disp8 / disp32 / RIP-relative zero-slot).
//! 6. Emit immediate bytes (imm8 / imm16 / imm32 / imm64).
//!
//! Two cross-cutting concerns:
//!
//! - **REX byte computation**. A REX byte is `0x40 | (W<<3) | (R<<2) |
//!   (X<<1) | B`. `W` comes from the [`RexPolicy`] (W or WithW ⇒ 1). `R`
//!   extends the `reg` field's register number bit-3; `B` extends `rm`'s
//!   bit-3; `X` extends the SIB `index`'s bit-3. mdbcc only references
//!   registers 0..15 today so the math is bounded.
//! - **Memory operand specials**. RBP / R13 as base force a disp byte
//!   (mod=00 rm=101 is the RIP-rel encoding on x64 / `[disp32]` on x86;
//!   never `[rbp]`). RSP / R12 as base force a SIB byte (mod=00 rm=100
//!   means "SIB follows"). The encoder honours both.

use super::regs::RegId;
use super::table::{
    ArchSet, DispKind, EncodeError, Encoded, ImmKind, ModRMTemplate, Op, Operand,
    OperandKindSnapshot, Pattern, RegClass, RegOrOpcodeExt, RexPolicy,
};

/// Which fixup slot (if any) a ModR/M `mod=00 rm=101` form allocated.
/// The disp32 bytes are the same; only the relocation kind the caller
/// records differs (RIP-relative REL32 on x64 vs absolute DIR32 on x86).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispSlot {
    /// No `[disp32]`-only slot (ordinary reg/mem operand).
    None,
    /// `[rip+disp32]` — x64 RIP-relative; caller records `riprel_at`.
    Rip,
    /// `[disp32]` absolute — x86; caller records `abs_at`.
    Abs,
}

/// Look up the encoding for `op` given the actual operand list, then
/// emit the bytes. `target` filters the table by [`ArchSet`] (S2b.4) and
/// suppresses the REX prefix on x86 (32-bit mode has no REX byte). Returns
/// the assembled `Encoded` block.
pub fn encode(
    table: &[Pattern],
    op: Op,
    operands: &[Operand],
    target: ArchSet,
) -> Result<Encoded, EncodeError> {
    // First pass: find a matching row. Table ordering is significant —
    // narrower forms (e.g. disp8 mem) come before wider ones (disp32 mem).
    let row = table
        .iter()
        .filter(|r| r.op == op)
        .filter(|r| r.arch.matches(target))
        .filter(|r| r.operands.len() == operands.len())
        .find(|r| {
            r.operands
                .iter()
                .zip(operands.iter())
                .all(|(k, o)| o.matches(k))
        })
        .ok_or_else(|| {
            EncodeError::NoMatchingRow(op, operands.iter().map(OperandKindSnapshot::from).collect())
        })?;
    emit_row(row, operands, target)
}

/// Build the byte sequence for a matched row + concrete operands.
fn emit_row(row: &Pattern, operands: &[Operand], target: ArchSet) -> Result<Encoded, EncodeError> {
    let mut out: Vec<u8> = Vec::with_capacity(16);
    // 32-bit mode has no REX byte (the 0x40-0x4F range is INC/DEC r16/r32);
    // suppress it entirely on x86. x86 rows reference only registers 0..7,
    // so no REX-extension information is ever lost.
    let is_x86 = target == ArchSet::X86Only;

    // (1) Opcode prefixes (legacy / SSE).
    out.extend_from_slice(row.opcode_prefix);

    // (2) REX byte (x64 only).
    // Compute REX bits from operands, then prepend if non-zero or the
    // policy forces emission.
    if !is_x86 {
        let (rex_byte, force_emit) = compute_rex(row, operands)?;
        if (force_emit || rex_byte != 0x40) && rex_byte != 0 {
            out.push(rex_byte);
        }
    }

    // (3) Opcode bytes — OR opcode-register into last byte if needed.
    let mut opcode = row.opcode.to_vec();
    if row.opcode_reg {
        let reg = operand_register(operands, 0)?;
        let last = opcode.len() - 1;
        opcode[last] |= reg.number() & 0x07;
    }
    out.extend_from_slice(&opcode);

    // (4) ModR/M + SIB.
    let mut riprel_at: Option<usize> = None;
    let mut abs_at: Option<usize> = None;
    let mut needs_disp: Option<(DispKind, i32)> = None;
    if let Some(t) = row.modrm {
        let (modrm_byte, sib, disp_info, slot) = assemble_modrm(row, &t, operands)?;
        out.push(modrm_byte);
        if let Some(sib_byte) = sib {
            out.push(sib_byte);
        }
        needs_disp = disp_info;
        match slot {
            DispSlot::None => {}
            DispSlot::Rip => {
                riprel_at = Some(out.len());
                out.extend_from_slice(&[0u8; 4]);
            }
            DispSlot::Abs => {
                abs_at = Some(out.len());
                out.extend_from_slice(&[0u8; 4]);
            }
        }
    }

    // (5) Displacement bytes (only when a memory operand carried one).
    if let Some((kind, value)) = needs_disp {
        match kind {
            DispKind::None => {}
            DispKind::Disp8 => {
                let v = i8::try_from(value)
                    .map_err(|_| EncodeError::OperandOutOfRange("disp8 out of range"))?;
                out.push(v as u8);
            }
            DispKind::Disp32 => {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }

    // (6) Trailing rel32 slot for call/jmp rel32 (when no ModR/M).
    let mut rel_at = riprel_at;
    if row.modrm.is_none() {
        for (i, k) in row.operands.iter().enumerate() {
            if matches!(k, super::table::OperandKind::Rel32) {
                rel_at = Some(out.len());
                out.extend_from_slice(&[0u8; 4]);
                let _ = i; // index unused — by construction we expect 1 Rel32
                break;
            }
        }
    }

    // (7) Immediate bytes.
    if let Some(width) = row.imm {
        let imm_value =
            find_imm(operands).ok_or(EncodeError::OperandOutOfRange("expected an Imm operand"))?;
        match width {
            ImmKind::Imm8 => {
                let v = imm_value as i8;
                out.push(v as u8);
            }
            ImmKind::Imm16 => {
                let v = imm_value as i16;
                out.extend_from_slice(&v.to_le_bytes());
            }
            ImmKind::Imm32 => {
                out.extend_from_slice(&(imm_value as i32).to_le_bytes());
            }
            ImmKind::Imm64 => {
                out.extend_from_slice(&imm_value.to_le_bytes());
            }
        }
    }

    Ok(Encoded {
        bytes: out,
        riprel_at: rel_at,
        abs_at,
    })
}

/// Compute the REX byte (`0x40 | WRXB`) and whether the policy forces
/// emission even if WRXB is zero. The returned byte is either 0 (don't
/// emit) or `>= 0x40`.
fn compute_rex(row: &Pattern, operands: &[Operand]) -> Result<(u8, bool), EncodeError> {
    let mut w: u8 = 0;
    let mut r: u8 = 0;
    let mut x: u8 = 0;
    let mut b: u8 = 0;
    let force = matches!(row.rex, RexPolicy::W | RexPolicy::WithW);

    if matches!(row.rex, RexPolicy::W | RexPolicy::WithW) {
        w = 1;
    }

    // Walk operands and accumulate REX-extension bits per their roles.
    // The role of each operand (reg vs rm vs index) is fixed by the
    // ModR/M template; for operands that don't enter ModR/M (immediate,
    // rel32) we contribute nothing.
    if let Some(t) = row.modrm {
        // reg field source
        let reg_op_idx = match t.reg_field {
            RegOrOpcodeExt::FromOperand(i) => Some(i as usize),
            RegOrOpcodeExt::Fixed(_) => None,
        };
        if let Some(i) = reg_op_idx
            && let Some(rid) = operand_to_reg(&operands[i])
            && rid.needs_rex_extension()
        {
            r = 1;
        }
        // rm field source — could be a register (mod=11) or a mem-base.
        let rm_op_idx = match t.rm_field {
            RegOrOpcodeExt::FromOperand(i) => Some(i as usize),
            RegOrOpcodeExt::Fixed(_) => None,
        };
        if let Some(i) = rm_op_idx {
            if let Some(rid) = operand_to_rm_register(&operands[i])
                && rid.needs_rex_extension()
            {
                b = 1;
            }
            if let Operand::MemSib { index, .. } = operands[i]
                && index.needs_rex_extension()
            {
                x = 1;
            }
        }
    } else if row.opcode_reg {
        // Opcode-register encoding: `PUSH r8` etc. — REX.B extends.
        if let Some(rid) = operand_to_reg(&operands[0])
            && rid.needs_rex_extension()
        {
            b = 1;
        }
    }

    let rex = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
    let policy_force = match row.rex {
        RexPolicy::None => false,
        RexPolicy::W | RexPolicy::WithW => true,
        RexPolicy::Auto => false,
    };
    let emit = policy_force || (rex & 0x0F) != 0;
    Ok((if emit { rex } else { 0 }, force))
}

/// Tuple returned by [`assemble_modrm`]: `(modrm_byte, sib?, disp?, slot)`.
/// `slot` is the [`DispSlot`] the `mod=00 rm=101` form (if any) allocated.
/// Factored out (clippy::type_complexity) for readability of the
/// internal encoder helpers — the public encode() return type stays
/// [`Encoded`].
type AssembledModRM = (u8, Option<u8>, Option<(DispKind, i32)>, DispSlot);

/// Build the ModR/M byte (and a SIB byte if needed) and produce the
/// displacement metadata the outer loop needs to actually emit disp bytes.
fn assemble_modrm(
    row: &Pattern,
    t: &ModRMTemplate,
    operands: &[Operand],
) -> Result<AssembledModRM, EncodeError> {
    let reg = match t.reg_field {
        RegOrOpcodeExt::FromOperand(i) => {
            let rid = operand_register(operands, i as usize)?;
            rid.number() & 0x07
        }
        RegOrOpcodeExt::Fixed(v) => v & 0x07,
    };

    // Determine `mod` and `rm` from rm_field's source.
    match t.rm_field {
        RegOrOpcodeExt::Fixed(rm) => {
            // mod=00 rm=101 ⇒ [rip+disp32] on x64 / [disp32] absolute on x86.
            // Identical ModR/M bytes; the disp32 slot is recorded as a
            // RIP-relative (Rip) or absolute (Abs) fixup per the operand.
            let modrm = (t.mod_field & 0x03) << 6 | (reg & 0x07) << 3 | (rm & 0x07);
            let has_rip = row
                .operands
                .iter()
                .any(|k| matches!(k, super::table::OperandKind::MemRipRel));
            let has_abs = row
                .operands
                .iter()
                .any(|k| matches!(k, super::table::OperandKind::MemAbs));
            let slot = if has_rip {
                DispSlot::Rip
            } else if has_abs {
                DispSlot::Abs
            } else {
                DispSlot::None
            };
            Ok((modrm, None, None, slot))
        }
        RegOrOpcodeExt::FromOperand(i) => {
            let op = &operands[i as usize];
            match op {
                Operand::Reg(_, rid) => {
                    // mod=11 reg-reg.
                    let modrm = 0b11 << 6 | (reg & 0x07) << 3 | (rid.number() & 0x07);
                    Ok((modrm, None, None, DispSlot::None))
                }
                Operand::Mem {
                    base, disp, kind, ..
                } => {
                    let mod_bits = match kind {
                        DispKind::None => 0b00,
                        DispKind::Disp8 => 0b01,
                        DispKind::Disp32 => 0b10,
                    };
                    // Validate row consistency.
                    if mod_bits != (t.mod_field & 0x03) {
                        return Err(EncodeError::OperandOutOfRange(
                            "row mod_field disagrees with operand DispKind",
                        ));
                    }
                    let base_num = base.number();
                    let base_low = base_num & 0x07;
                    let needs_sib = base_low == 0b100; // RSP/R12
                    let rm = if needs_sib { 0b100 } else { base_low };
                    let modrm = (mod_bits & 0x03) << 6 | (reg & 0x07) << 3 | (rm & 0x07);
                    let sib = if needs_sib {
                        // scale=00 index=100 (none) base=base
                        Some((0b00 << 6) | (0b100 << 3) | (base_low & 0x07))
                    } else {
                        None
                    };
                    let disp_info = match kind {
                        DispKind::None => None,
                        d => Some((*d, *disp)),
                    };
                    Ok((modrm, sib, disp_info, DispSlot::None))
                }
                Operand::MemSib {
                    base,
                    index,
                    scale,
                    disp,
                    kind,
                    ..
                } => {
                    let mod_bits = match kind {
                        DispKind::None => 0b00,
                        DispKind::Disp8 => 0b01,
                        DispKind::Disp32 => 0b10,
                    };
                    if mod_bits != (t.mod_field & 0x03) {
                        return Err(EncodeError::OperandOutOfRange(
                            "row mod_field disagrees with SIB operand DispKind",
                        ));
                    }
                    let modrm = (mod_bits & 0x03) << 6 | (reg & 0x07) << 3 | 0b100;
                    let sib = (scale.bits() & 0x03) << 6
                        | ((index.number() & 0x07) << 3)
                        | (base.number() & 0x07);
                    let disp_info = match kind {
                        DispKind::None => None,
                        d => Some((*d, *disp)),
                    };
                    Ok((modrm, Some(sib), disp_info, DispSlot::None))
                }
                Operand::MemRipRel => {
                    // mod=00 rm=101 — RIP+disp32.
                    let modrm = (0b00 << 6) | (reg & 0x07) << 3 | 0b101;
                    Ok((modrm, None, None, DispSlot::Rip))
                }
                Operand::MemAbs => {
                    // mod=00 rm=101 — [disp32] absolute (x86).
                    let modrm = (0b00 << 6) | (reg & 0x07) << 3 | 0b101;
                    Ok((modrm, None, None, DispSlot::Abs))
                }
                other => {
                    let _ = other;
                    Err(EncodeError::OperandOutOfRange(
                        "rm_field source operand is not reg/mem",
                    ))
                }
            }
        }
    }
}

/// Pull a register out of an operand at index `i`.
fn operand_register(operands: &[Operand], i: usize) -> Result<RegId, EncodeError> {
    match operands.get(i) {
        Some(Operand::Reg(_, rid)) => Ok(*rid),
        _ => Err(EncodeError::OperandOutOfRange(
            "expected a register operand at this position",
        )),
    }
}

/// Same as above but tolerant of memory-source operands (just returns
/// `None` rather than failing).
fn operand_to_reg(op: &Operand) -> Option<RegId> {
    match op {
        Operand::Reg(_, rid) => Some(*rid),
        _ => None,
    }
}

/// For REX.B accounting we want the base register of a Mem/MemSib, or
/// the register itself if the operand is a register.
fn operand_to_rm_register(op: &Operand) -> Option<RegId> {
    match op {
        Operand::Reg(_, rid) => Some(*rid),
        Operand::Mem { base, .. } => Some(*base),
        Operand::MemSib { base, .. } => Some(*base),
        _ => None,
    }
}

/// Scan operands for the immediate's payload value (sign-extended into i64).
fn find_imm(operands: &[Operand]) -> Option<i64> {
    operands.iter().find_map(|o| match o {
        Operand::Imm(_, v) => Some(*v),
        _ => None,
    })
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn dump_byte_string(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

// -- Internal helper used by patterns.rs's docs to avoid unused warnings --
pub(crate) const _ASSERT_OP_CHANNEL: Op = Op::Mov;
pub(crate) const _ASSERT_CLASS: RegClass = RegClass::Gpr64;
