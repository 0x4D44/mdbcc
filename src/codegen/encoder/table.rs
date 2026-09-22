//! Encoding-table schema (S2a). Per HLD §3.1 + §3.6.
//!
//! A [`Pattern`] is one row of the table: it pairs a logical operation
//! ([`Op`]) and a list of expected operand shapes ([`OperandKind`]) with
//! the bytes the encoder emits when that shape matches. The encoder
//! iterates [`crate::codegen::encoder::patterns::PATTERN_TABLE`] picking
//! the first row that matches the call's actual operands. Today every row
//! is `ArchSet::X64Only` or `ArchSet::Both`; S2b will add `ArchSet::X86Only`
//! rows for the Win32 path.
//!
//! ## Encoding model
//!
//! Each emitted instruction is up to five contiguous pieces:
//!
//! 1. Optional **legacy / SSE prefixes** — `F2`, `F3`, `66` — copied
//!    verbatim from `Pattern::opcode_prefix`.
//! 2. Optional **REX byte** — computed from [`RexPolicy`] + the operand
//!    register widths/extensions.
//! 3. **Opcode bytes** — `Pattern::opcode`. 1-3 bytes. May be `0F`-prefixed
//!    for the two-byte family.
//! 4. Optional **ModR/M + SIB** — assembled from [`ModRMTemplate`] +
//!    operand register numbers. SIB is only emitted when the base register
//!    encoding demands it (RSP/R12 base ⇒ SIB scale=1 index=4 base=base).
//! 5. **Displacement** + **Immediate** — disp8/disp16/disp32/disp64,
//!    imm8/imm16/imm32/imm64. The encoder owns layout but the values come
//!    from the [`Operand`] payloads.
//!
//! ## Byte-identity rule
//!
//! The encoder must emit byte-for-byte the same bytes that the
//! pre-encoder hand-rolled call sites emit. The 88-fixture O1 SipHash
//! stripe in `tests/o1_byte_identity.rs` is the regression lock.

use super::regs::RegId;

/// Operand-class hint used to pick narrower forms when a wider one also
/// matches (e.g. `mov reg32, imm32` vs `mov reg64, imm32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegClass {
    /// 8-bit GPR (AL/CL/DL/...). Encodings without a REX prefix encode the
    /// "low byte" registers (AL/CL/DL/BL/AH/CH/DH/BH). With a REX prefix
    /// they encode the SIL/DIL/BPL/SPL family. mdbcc only uses AL/CL/DL/DIL.
    Gpr8,
    /// 16-bit GPR (AX/CX/DX/...). Emit `66` prefix.
    Gpr16,
    /// 32-bit GPR (EAX/ECX/EDX/...). Default operand size; no REX.W.
    Gpr32,
    /// 64-bit GPR (RAX/RCX/RDX/...). Emit REX.W = 1.
    Gpr64,
    /// XMM register (XMM0..XMM15).
    Xmm,
}

/// One operand shape an instruction-table row matches.
#[derive(Debug, Clone, Copy)]
pub enum OperandKind {
    /// Any register of a given class — the encoder fills the ModR/M
    /// `reg`/`rm` field from the operand's [`RegId`].
    AnyReg(RegClass),
    /// Memory `[base + disp]` where the displacement width is determined
    /// by [`DispKind`]. Base is encoded; disp comes from the operand.
    Mem(RegClass, DispKind),
    /// Memory `[base + index*scale + disp]`. SIB form. Today used only
    /// for the `[rsp + disp32]` slot in Win64 outgoing-arg stores.
    MemSib(RegClass, RegClass, ScaleKind, DispKind),
    /// `[rip + disp32]` on x64 (mod=00 rm=101). Encoded as a fixup site
    /// the emitter records on the calling [`crate::codegen::Gen`].
    MemRipRel,
    /// `[disp32]` absolute on x86 (mod=00 rm=101) — S2b.4. Same ModR/M
    /// bytes as [`Self::MemRipRel`]; the wire difference is the relocation
    /// kind the object layer picks (`IMAGE_REL_I386_DIR32`, absolute VA)
    /// rather than `REL32`. The emitter records the disp32 slot offset in
    /// [`Encoded::abs_at`]. x86 has no RIP-relative addressing, so globals
    /// / string literals are reached by absolute address (PE32 ImageBase
    /// is fixed at 0x400000 ⇒ the absolute VA fits 32 bits).
    MemAbs,
    /// Immediate of given width.
    Imm(ImmKind),
    /// Relative-32 displacement (E8 call rel32 / E9 jmp rel32).
    Rel32,
}

/// Displacement kind in a memory operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispKind {
    /// No displacement (mod=00). Only legal for bases that do not have
    /// the special "disp32-only" decoding (RBP/R13 force mod=01 disp8=0).
    None,
    /// 8-bit signed displacement (mod=01).
    Disp8,
    /// 32-bit signed displacement (mod=10).
    Disp32,
}

/// Index-register scale factor in a SIB byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScaleKind {
    S1,
    S2,
    S4,
    S8,
}

impl ScaleKind {
    pub const fn bits(self) -> u8 {
        match self {
            ScaleKind::S1 => 0b00,
            ScaleKind::S2 => 0b01,
            ScaleKind::S4 => 0b10,
            ScaleKind::S8 => 0b11,
        }
    }
}

/// Immediate-operand width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmKind {
    Imm8,
    Imm16,
    Imm32,
    Imm64,
}

impl ImmKind {
    pub const fn bytes(self) -> u32 {
        match self {
            ImmKind::Imm8 => 1,
            ImmKind::Imm16 => 2,
            ImmKind::Imm32 => 4,
            ImmKind::Imm64 => 8,
        }
    }
}

/// Architecture filter for a [`Pattern`] row. S2a only emits `X64Only`
/// or `Both` rows; S2b adds `X86Only` and the encoder's `arch` argument
/// becomes meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchSet {
    /// Row encodes the same byte sequence on both x64 and x86 (modulo
    /// REX, which the encoder skips on x86 even when the row sets it).
    Both,
    /// Row is x64-only — uses REX, 64-bit registers, or RIP-relative.
    X64Only,
    /// Row is x86-only — placeholder for S2b. No rows in S2a yet.
    #[allow(dead_code)]
    X86Only,
}

impl ArchSet {
    pub const fn matches(self, target: ArchSet) -> bool {
        match (self, target) {
            (ArchSet::Both, _) | (_, ArchSet::Both) => true,
            (a, b) => a as u8 == b as u8,
        }
    }
}

/// REX-prefix policy for a [`Pattern`] row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RexPolicy {
    /// Never emit REX, even on x64. Used by 32-bit ops (`mov eax, imm32`),
    /// SSE ops (the SSE prefix sits before any REX would go), and 1-byte
    /// register-only ops (`push rbp` = `55`).
    None,
    /// Always emit REX.W = 1 (`0x48`) plus any required REX.[R|B|X] from
    /// operand register-extension bits. Used by every 64-bit GPR op
    /// (`mov rax, [rbp+disp32]`).
    W,
    /// REX byte if and only if one of the operands needs a REX bit
    /// (R8..R15 extension, SIL/DIL/BPL/SPL low-byte). REX.W stays 0.
    /// Used by 32-bit GPR ops that may reference an extended register
    /// (mov r9d, ... etc).
    Auto,
    /// Explicit REX byte built directly from operand register-extension
    /// bits — REX.W = 1 alongside Auto extensions. Used by ops where REX
    /// is mandatory even though it carries no extension bits (e.g.
    /// `cvtsi2sd xmm0, rax` is `F2 48 0F 2A C0`).
    WithW,
}

/// Logical mnemonic the encoder dispatches on. Closed set covering the
/// ~60 mnemonics mdbcc emits today (S2a census). New mnemonics get a new
/// variant + a row in `patterns.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    // -- Data movement (GPR) -------------------------------------------------
    Mov,
    Movsxd,
    Movsx8,
    Movsx16,
    Movzx8,
    Movzx16,
    Lea,
    Xchg,
    // -- Stack ---------------------------------------------------------------
    Push,
    Pop,
    // -- Arithmetic / logic --------------------------------------------------
    Add,
    Sub,
    AddImm,
    SubImm,
    Cmp,
    CmpImm,
    Test,
    And,
    Or,
    Xor,
    Neg,
    Not,
    Inc,
    Dec,
    Imul,
    ImulImm,
    Idiv,
    Div,
    Mul,
    Cdq,
    Cqo,
    Shl,
    Shr,
    Sar,
    Btr,
    // -- Control flow --------------------------------------------------------
    Call,
    CallReg,
    Ret,
    RetImm,
    Jmp,
    JmpReg,
    Jcc(u8),
    /// Short conditional jump (1-byte rel8 displacement). Used for the
    /// `jns +2 ; ud2` and `jnc +2 ; ud2` overflow guards. The byte is
    /// the conditional-opcode, e.g. `0x73` = JNC, `0x79` = JNS.
    JccShort(u8),
    Setcc(u8),
    Ud2,
    Leave,
    /// Bare `ret` follows the same `RET` opcode as the Win64 epilogue's
    /// `leave; ret` two-byte sequence — encoder splits them into two
    /// adjacent rows so the `leave; ret` pair stays one logical emit.
    LeaveRet,
    Int3,
    Nop,
    // -- SSE2 scalar double --------------------------------------------------
    Movsd,
    Movss,
    Addsd,
    Subsd,
    Mulsd,
    Divsd,
    Ucomisd,
    Xorpd,
    Cvtsi2sd,
    Cvttsd2si,
}

/// Source of a `reg` or `rm` field at emit time.
#[derive(Debug, Clone, Copy)]
pub enum RegOrOpcodeExt {
    /// Take the register from operand at the given index.
    FromOperand(u8),
    /// Hard-coded value (opcode-extension `/N`, or `rm=101` for RIP-rel).
    Fixed(u8),
}

/// ModR/M template for a [`Pattern`] row.
#[derive(Debug, Clone, Copy)]
pub struct ModRMTemplate {
    /// `mod` field (00 / 01 / 10 / 11). For mem operands this is set by
    /// the table row to match the [`DispKind`]; for reg-reg ops it's 11.
    /// When the operand carries an actual `Mem` with a [`DispKind`], the
    /// emitter trusts the row and the [`DispKind`]s must agree.
    pub mod_field: u8,
    pub reg_field: RegOrOpcodeExt,
    pub rm_field: RegOrOpcodeExt,
}

/// One row of the encoding table.
#[derive(Debug, Clone, Copy)]
pub struct Pattern {
    pub op: Op,
    /// Position-significant operand-kind tags.
    pub operands: &'static [OperandKind],
    pub arch: ArchSet,
    pub rex: RexPolicy,
    /// Optional pre-opcode bytes (legacy/SSE prefix: F2, F3, 66). These
    /// sit BEFORE any REX byte. May be empty.
    pub opcode_prefix: &'static [u8],
    /// Opcode bytes proper. Includes the `0F` escape byte for two-byte
    /// opcodes.
    pub opcode: &'static [u8],
    /// `Some(template)` when ModR/M is required; `None` for ops without
    /// (RET / PUSH r64 — the latter uses opcode-register encoding via
    /// [`Self::opcode_reg`]).
    pub modrm: Option<ModRMTemplate>,
    /// True when the opcode byte's low 3 bits encode an operand register
    /// (`50+r` for PUSH rN, `B8+r` for MOV rN, imm32). The encoder ORs
    /// the operand-0 register number into the last opcode byte.
    pub opcode_reg: bool,
    /// Width of the displacement that follows ModR/M+SIB, when the
    /// matched operand contains one. Used to validate the row's
    /// shape consistency.
    pub disp: DispKind,
    /// Width of the trailing immediate (or `None`).
    pub imm: Option<ImmKind>,
}

/// One concrete operand the caller supplies to [`super::encode`].
#[derive(Debug, Clone, Copy)]
pub enum Operand {
    /// Plain register.
    Reg(RegClass, RegId),
    /// `[base + disp]` memory operand.
    Mem {
        class: RegClass,
        base: RegId,
        disp: i32,
        kind: DispKind,
    },
    /// `[base + index*scale + disp]` memory.
    MemSib {
        class: RegClass,
        base: RegId,
        index: RegId,
        scale: ScaleKind,
        disp: i32,
        kind: DispKind,
    },
    /// `[rip + disp32]` — x64 only; the caller records the fixup site
    /// after [`super::encode`] returns (the [`Encoded::riprel_at`] field
    /// tells them the offset of the disp32 slot relative to start).
    MemRipRel,
    /// `[disp32]` absolute — x86 only (S2b.4). The caller records the
    /// disp32 slot offset from [`Encoded::abs_at`] as an absolute-address
    /// (`DIR32`) fixup.
    MemAbs,
    /// Immediate value.
    Imm(ImmKind, i64),
    /// `call rel32` / `jmp rel32` — encoded as 4 zero bytes; caller patches.
    Rel32,
}

impl Operand {
    /// Match a concrete operand against a table row's expected kind. The
    /// encoder uses this when scanning the table.
    pub fn matches(&self, kind: &OperandKind) -> bool {
        match (self, kind) {
            (Operand::Reg(rc, _), OperandKind::AnyReg(k)) => rc == k,
            (
                Operand::Mem {
                    class, kind: dk, ..
                },
                OperandKind::Mem(k, dispk),
            ) => class == k && dk == dispk,
            (
                Operand::MemSib {
                    class,
                    scale,
                    kind: dk,
                    ..
                },
                OperandKind::MemSib(k, _, sc, dispk),
            ) => class == k && scale == sc && dk == dispk,
            (Operand::MemRipRel, OperandKind::MemRipRel) => true,
            (Operand::MemAbs, OperandKind::MemAbs) => true,
            (Operand::Imm(w, _), OperandKind::Imm(ek)) => w == ek,
            (Operand::Rel32, OperandKind::Rel32) => true,
            _ => false,
        }
    }
}

/// What an emit returned to the calling [`crate::codegen::Gen`].
#[derive(Debug, Clone)]
pub struct Encoded {
    /// Bytes the caller appends to its code buffer.
    pub bytes: Vec<u8>,
    /// If the row consumed a [`Operand::MemRipRel`] or [`Operand::Rel32`],
    /// this is the byte offset (within `bytes`) of the 4-byte disp32 /
    /// rel32 slot the caller must patch / record as a fixup. `None` when
    /// the row has no rel/RIP slot.
    pub riprel_at: Option<usize>,
    /// If the row consumed an absolute memory operand with `disp == 0`,
    /// future S2b will use this for `IMAGE_REL_I386_DIR32` recording.
    /// Unused in S2a; kept for forward compatibility.
    pub abs_at: Option<usize>,
}

/// Encoder failure mode.
#[derive(Debug, Clone)]
pub enum EncodeError {
    /// No table row matched the given (op, operand-kinds) tuple. Most
    /// often caused by a row gap (missing pattern) or a caller using
    /// the wrong [`RegClass`]/`DispKind` for the row they expected.
    NoMatchingRow(Op, Vec<OperandKindSnapshot>),
    /// Row matched but the operand carried an out-of-range value
    /// (e.g. an i64 immediate that doesn't fit Imm32 sign-extension).
    OperandOutOfRange(&'static str),
    /// Row demanded an `Operand::Reg` of class X but the caller passed
    /// a register from a different class.
    BadRegClass { expected: RegClass, got: RegClass },
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::NoMatchingRow(op, ops) => {
                write!(f, "no encoder row for op {op:?} with operands {ops:?}")
            }
            EncodeError::OperandOutOfRange(s) => {
                write!(f, "operand out of range: {s}")
            }
            EncodeError::BadRegClass { expected, got } => {
                write!(f, "bad register class: expected {expected:?}, got {got:?}")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Lightweight snapshot of an operand for error reporting (the
/// concrete `Operand` carries values we don't want to clone into
/// the error type).
#[derive(Debug, Clone)]
pub enum OperandKindSnapshot {
    Reg(RegClass),
    Mem(RegClass, DispKind),
    MemSib(RegClass, RegClass, ScaleKind, DispKind),
    MemRipRel,
    MemAbs,
    Imm(ImmKind),
    Rel32,
}

impl From<&Operand> for OperandKindSnapshot {
    fn from(o: &Operand) -> Self {
        match o {
            Operand::Reg(rc, _) => OperandKindSnapshot::Reg(*rc),
            Operand::Mem { class, kind, .. } => OperandKindSnapshot::Mem(*class, *kind),
            Operand::MemSib {
                class, scale, kind, ..
            } => OperandKindSnapshot::MemSib(*class, *class, *scale, *kind),
            Operand::MemRipRel => OperandKindSnapshot::MemRipRel,
            Operand::MemAbs => OperandKindSnapshot::MemAbs,
            Operand::Imm(k, _) => OperandKindSnapshot::Imm(*k),
            Operand::Rel32 => OperandKindSnapshot::Rel32,
        }
    }
}
