//! The encoding table (S2a). Per HLD §3 + §3.5.
//!
//! Each entry binds a logical [`Op`] + [`OperandKind`] tuple to the bytes
//! the encoder emits. The table is iterated linearly by
//! [`super::encode`]; the **first matching row wins**, so order matters
//! where multiple rows could match (always put narrower forms first —
//! e.g. `Disp8` before `Disp32`).
//!
//! ## Census (S2a inventory)
//!
//! Per HLD §3.5, mdbcc's Win64 codegen emits ~60 distinct mnemonics with
//! ~250 rows across both architectures. S2a covers the x64 stripe today;
//! S2b/d add x86 rows. Inventory of unique byte literals observed in
//! `src/codegen.rs` (529 emit sites, 199 unique prefixes):
//!
//! | Mnemonic family | Variants in codegen.rs |
//! |-----------------|------------------------|
//! | mov reg/reg     | 0x48 0x89 mod=11 (8 distinct pairs)
//! | mov reg/[rbp+d] | 0x48 0x8B 0x85/0x8D/0x95 (Rax/Rcx/Rdx) / 0x44 0x8B 0x85 (r8d) / 0x4C 0x8B 0x85/0x8D/0x95 (r8/r9/r10)
//! | mov [rbp+d]/reg | 0x48 0x89 0x85/0x8D/0x95 / 0x4C 0x89 0x8D/0x9D (r9/r11)
//! | mov mem/imm32   | 0x48 0xC7 0x85 / 0xC7 0x85 / 0xC6 0x85
//! | mov rax,imm64   | 0x48 0xB8
//! | mov reg,imm32   | 0xB8/0xB9 + reg-encoding
//! | mov r9d,imm32   | 0x41 0xB8 imm32 (mov r8d,imm32) etc
//! | lea reg, [rbp+d]| 0x48 0x8D 0x85/0x8D / 0x4C 0x8D 0x9D
//! | lea reg, [rip+d]| 0x48 0x8D 0x05 (Rax)
//! | call rel32      | 0xE8 (+4-byte rel32)
//! | call reg        | 0xFF 0xD0 (call rax)
//! | ret             | 0xC3
//! | leave;ret       | 0xC9 0xC3
//! | jmp rel32       | 0xE9 (+4-byte rel32)
//! | jcc rel32       | 0x0F 0x8c (+4-byte rel32)
//! | jcc short       | 0x73 / 0x79 (+1-byte rel8)
//! | setcc al        | 0x0F 0x9X (sete/setne/setb/...)
//! | movzx eax,al    | 0x0F 0xB6 0xC0
//! | movsxd rax,eax  | 0x48 0x63 0xC0
//! | xor reg,reg     | 0x48 0x31 0xC0 (xor rax,rax) / 0x31 0xC0 (xor eax,eax) / 0x31 0xD2 etc
//! | test reg,reg    | 0x48 0x85 0xC0 (test rax,rax) / 0x85 0xC0 / 0x84 0xC0 / 0x85 0xC9
//! | add rax,imm8    | 0x48 0x83 0xC0 0x08 (add rax,8)
//! | add reg, [rbp+d]| 0x48 0x03 0x85
//! | add reg,reg     | 0x48 0x01 0xC8 / 0x01 0xC8
//! | sub reg,reg     | 0x48 0x29 0xC8 / 0x29 0xC8
//! | inc rax         | 0x48 0xFF 0xC0
//! | dec rax         | 0xFF 0xC8 / 0xFF 0xC9
//! | neg eax         | 0xF7 0xD8
//! | not eax         | 0xF7 0xD0
//! | imul eax,ecx    | 0x0F 0xAF 0xC1
//! | imul rax,imm32  | 0x48 0x69 0xC0 imm32
//! | imul eax,eax,10 | 0x6B 0xC0 0x0A
//! | idiv rcx        | 0x48 0xF7 0xF9
//! | div ecx         | 0xF7 0xF1
//! | mul rcx         | 0x48 0xF7 0xE1
//! | cdq             | 0x99
//! | cqo             | 0x48 0x99
//! | shl/shr/sar by cl | 0xD3 0xE0 / 0xE8 / 0xF8
//! | btr rax,63      | 0x48 0x0F 0xBA 0xF0 0x3F
//! | push rbp        | 0x55
//! | pop rbp         | 0x5D
//! | ud2             | 0x0F 0x0B
//! | SSE2 family     | F2/F3/66 prefix + 0F + variants
//! | cvtsi2sd xmm0,eax | F2 0F 2A C0
//! | cvtsi2sd xmm0,rax | F2 48 0F 2A C0
//! | cvttsd2si eax,xmm0 | F2 0F 2C C0
//! | cvttsd2si rax,xmm0 | F2 48 0F 2C C0
//!
//! For S2a the table covers the **subset migratable today** byte-identically;
//! a number of opcode-extension variants (e.g. add-immediate with /0, or
//! the `[rsp+disp32]` SIB shape used in outgoing-arg stores) appear in the
//! table; the more exotic byte-level tricks (compound `jns +2 ; ud2`
//! sequences, multi-instruction blobs in the io helpers) stay as raw
//! `emit(&[..])` calls and are flagged with a TODO comment at the call
//! site per the migration brief.

use super::regs::RegId;
use super::table::{
    ArchSet, DispKind, ImmKind, ModRMTemplate, Op, OperandKind, Pattern, RegClass, RegOrOpcodeExt,
    RexPolicy, ScaleKind,
};

const REG0_RM1: ModRMTemplate = ModRMTemplate {
    mod_field: 0b11,
    reg_field: RegOrOpcodeExt::FromOperand(0),
    rm_field: RegOrOpcodeExt::FromOperand(1),
};

const REG1_RM0: ModRMTemplate = ModRMTemplate {
    mod_field: 0b11,
    reg_field: RegOrOpcodeExt::FromOperand(1),
    rm_field: RegOrOpcodeExt::FromOperand(0),
};

const MEM0_RM1_DISP32: ModRMTemplate = ModRMTemplate {
    mod_field: 0b10,
    reg_field: RegOrOpcodeExt::FromOperand(0),
    rm_field: RegOrOpcodeExt::FromOperand(1),
};

const REG_MEM0_RM1_NONE: ModRMTemplate = ModRMTemplate {
    mod_field: 0b00,
    reg_field: RegOrOpcodeExt::FromOperand(0),
    rm_field: RegOrOpcodeExt::FromOperand(1),
};

const REG_MEM0_RM1_DISP8: ModRMTemplate = ModRMTemplate {
    mod_field: 0b01,
    reg_field: RegOrOpcodeExt::FromOperand(0),
    rm_field: RegOrOpcodeExt::FromOperand(1),
};

const RIPREL_REG0: ModRMTemplate = ModRMTemplate {
    mod_field: 0b00,
    reg_field: RegOrOpcodeExt::FromOperand(0),
    rm_field: RegOrOpcodeExt::Fixed(0b101),
};

/// `ret`-with-imm16: opcode `C2 nn nn`. Not in S2a's path today.
#[allow(dead_code)]
const FIXED_EXT0_REG: ModRMTemplate = ModRMTemplate {
    mod_field: 0b11,
    reg_field: RegOrOpcodeExt::Fixed(0),
    rm_field: RegOrOpcodeExt::FromOperand(0),
};

#[allow(dead_code)]
const FIXED_EXT_RAX: ModRMTemplate = ModRMTemplate {
    mod_field: 0b11,
    reg_field: RegOrOpcodeExt::Fixed(0),
    rm_field: RegOrOpcodeExt::FromOperand(0),
};

// S2b.4 — x86 store-to-memory templates: the source register is operand 1
// (`mov [base+disp], r32`), the memory base is operand 0. Mirror the x64
// store rows' inline templates, named for reuse across disp widths.
const STORE_REG1_MEM0_NONE: ModRMTemplate = ModRMTemplate {
    mod_field: 0b00,
    reg_field: RegOrOpcodeExt::FromOperand(1),
    rm_field: RegOrOpcodeExt::FromOperand(0),
};
const STORE_REG1_MEM0_DISP8: ModRMTemplate = ModRMTemplate {
    mod_field: 0b01,
    reg_field: RegOrOpcodeExt::FromOperand(1),
    rm_field: RegOrOpcodeExt::FromOperand(0),
};
const STORE_REG1_MEM0_DISP32: ModRMTemplate = ModRMTemplate {
    mod_field: 0b10,
    reg_field: RegOrOpcodeExt::FromOperand(1),
    rm_field: RegOrOpcodeExt::FromOperand(0),
};
// S2b.4 — x86 absolute `[disp32]` store: reg = source operand (1),
// rm = Fixed(0b101) (mod=00 rm=101 ⇒ `[disp32]` with no base on x86).
const ABS_STORE_REG1: ModRMTemplate = ModRMTemplate {
    mod_field: 0b00,
    reg_field: RegOrOpcodeExt::FromOperand(1),
    rm_field: RegOrOpcodeExt::Fixed(0b101),
};

pub static PATTERN_TABLE: &[Pattern] = &[
    // ====================================================================
    // mov reg, reg (same width)
    // ====================================================================
    // mov r64, r64 — REX.W 89 /r (canonical Borland/MSVC choice).
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::AnyReg(RegClass::Gpr64),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x89],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // mov r32, r32 — 89 /r.
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x89],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // mov reg, [base+disp32] / mov [base+disp32], reg
    // ====================================================================
    // mov r64, [base+disp32] — REX.W 8B /r [disp32].
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::Mem(RegClass::Gpr64, DispKind::Disp32),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x8B],
        modrm: Some(MEM0_RM1_DISP32),
        opcode_reg: false,
        disp: DispKind::Disp32,
        imm: None,
    },
    // mov [base+disp32], r64 — REX.W 89 /r [disp32].
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::Mem(RegClass::Gpr64, DispKind::Disp32),
            OperandKind::AnyReg(RegClass::Gpr64),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x89],
        modrm: Some(ModRMTemplate {
            mod_field: 0b10,
            reg_field: RegOrOpcodeExt::FromOperand(1),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::Disp32,
        imm: None,
    },
    // mov r32, [base+disp32] — 8B /r [disp32].
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::Mem(RegClass::Gpr64, DispKind::Disp32),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x8B],
        modrm: Some(MEM0_RM1_DISP32),
        opcode_reg: false,
        disp: DispKind::Disp32,
        imm: None,
    },
    // mov [base+disp32], r32 — 89 /r [disp32].
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::Mem(RegClass::Gpr64, DispKind::Disp32),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x89],
        modrm: Some(ModRMTemplate {
            mod_field: 0b10,
            reg_field: RegOrOpcodeExt::FromOperand(1),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::Disp32,
        imm: None,
    },
    // ====================================================================
    // mov reg, [base] — no displacement (mod=00). Used for *rax loads.
    // ====================================================================
    // mov r64, [base]
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::Mem(RegClass::Gpr64, DispKind::None),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x8B],
        modrm: Some(REG_MEM0_RM1_NONE),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // mov r32, [base]
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::Mem(RegClass::Gpr64, DispKind::None),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x8B],
        modrm: Some(REG_MEM0_RM1_NONE),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // mov [base], r64
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::Mem(RegClass::Gpr64, DispKind::None),
            OperandKind::AnyReg(RegClass::Gpr64),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x89],
        modrm: Some(ModRMTemplate {
            mod_field: 0b00,
            reg_field: RegOrOpcodeExt::FromOperand(1),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // mov [base], r32
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::Mem(RegClass::Gpr64, DispKind::None),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x89],
        modrm: Some(ModRMTemplate {
            mod_field: 0b00,
            reg_field: RegOrOpcodeExt::FromOperand(1),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // mov r64, imm64 — REX.W B8+r imm64. (mov rax, 0x...)
    // ====================================================================
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::Imm(ImmKind::Imm64),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0xB8],
        modrm: None,
        opcode_reg: true,
        disp: DispKind::None,
        imm: Some(ImmKind::Imm64),
    },
    // mov r32, imm32 — B8+r imm32. (mov eax, n)
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::Imm(ImmKind::Imm32),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0xB8],
        modrm: None,
        opcode_reg: true,
        disp: DispKind::None,
        imm: Some(ImmKind::Imm32),
    },
    // ====================================================================
    // mov reg, [rip+disp32] — RIP-relative load.
    // ====================================================================
    Pattern {
        op: Op::Mov,
        operands: &[OperandKind::AnyReg(RegClass::Gpr64), OperandKind::MemRipRel],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x8B],
        modrm: Some(RIPREL_REG0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // lea reg, [base+disp32] / lea reg, [rip+disp32]
    // ====================================================================
    Pattern {
        op: Op::Lea,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::Mem(RegClass::Gpr64, DispKind::Disp32),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x8D],
        modrm: Some(MEM0_RM1_DISP32),
        opcode_reg: false,
        disp: DispKind::Disp32,
        imm: None,
    },
    Pattern {
        op: Op::Lea,
        operands: &[OperandKind::AnyReg(RegClass::Gpr64), OperandKind::MemRipRel],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x8D],
        modrm: Some(RIPREL_REG0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // lea r64, [base+index*1] — used by io helpers (`lea r9, [rax+8]`).
    Pattern {
        op: Op::Lea,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::Mem(RegClass::Gpr64, DispKind::Disp8),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x8D],
        modrm: Some(REG_MEM0_RM1_DISP8),
        opcode_reg: false,
        disp: DispKind::Disp8,
        imm: None,
    },
    // ====================================================================
    // call / ret / jmp / jcc
    // ====================================================================
    // call rel32 — E8 rel32. Caller records the fixup at returned offset.
    Pattern {
        op: Op::Call,
        operands: &[OperandKind::Rel32],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0xE8],
        modrm: None,
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // call r64 — FF /2.
    Pattern {
        op: Op::CallReg,
        operands: &[OperandKind::AnyReg(RegClass::Gpr64)],
        arch: ArchSet::X64Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0xFF],
        modrm: Some(ModRMTemplate {
            mod_field: 0b11,
            reg_field: RegOrOpcodeExt::Fixed(2),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // call r32 — FF /2 (X86Only). Same bytes as `call r64` (no REX on x86),
    // but tagged Gpr32 so the Win32 indirect-call site (`call eax`) routing
    // a 32-bit register operand matches. `call eax` = FF D0.
    Pattern {
        op: Op::CallReg,
        operands: &[OperandKind::AnyReg(RegClass::Gpr32)],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0xFF],
        modrm: Some(ModRMTemplate {
            mod_field: 0b11,
            reg_field: RegOrOpcodeExt::Fixed(2),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // jmp rel32 — E9 rel32.
    Pattern {
        op: Op::Jmp,
        operands: &[OperandKind::Rel32],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0xE9],
        modrm: None,
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ret — C3.
    Pattern {
        op: Op::Ret,
        operands: &[],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0xC3],
        modrm: None,
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // leave; ret — C9 C3 (Win64 epilogue).
    Pattern {
        op: Op::LeaveRet,
        operands: &[],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0xC9, 0xC3],
        modrm: None,
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ud2 — 0F 0B.
    Pattern {
        op: Op::Ud2,
        operands: &[],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x0F, 0x0B],
        modrm: None,
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // push / pop
    // ====================================================================
    // push r64 — 50+r.
    Pattern {
        op: Op::Push,
        operands: &[OperandKind::AnyReg(RegClass::Gpr64)],
        arch: ArchSet::X64Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x50],
        modrm: None,
        opcode_reg: true,
        disp: DispKind::None,
        imm: None,
    },
    // pop r64 — 58+r.
    Pattern {
        op: Op::Pop,
        operands: &[OperandKind::AnyReg(RegClass::Gpr64)],
        arch: ArchSet::X64Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x58],
        modrm: None,
        opcode_reg: true,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // Test / Cmp / Xor reg-reg
    // ====================================================================
    // test r64, r64 — REX.W 85 /r.
    Pattern {
        op: Op::Test,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::AnyReg(RegClass::Gpr64),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x85],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // test r32, r32 — 85 /r.
    Pattern {
        op: Op::Test,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x85],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // test r8, r8 — 84 /r.
    Pattern {
        op: Op::Test,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr8),
            OperandKind::AnyReg(RegClass::Gpr8),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x84],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // cmp r64, r64 — REX.W 39 /r.
    Pattern {
        op: Op::Cmp,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::AnyReg(RegClass::Gpr64),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x39],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // cmp r32, r32 — 39 /r.
    Pattern {
        op: Op::Cmp,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x39],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // xor r64, r64 — REX.W 31 /r.
    Pattern {
        op: Op::Xor,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::AnyReg(RegClass::Gpr64),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x31],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // xor r32, r32 — 31 /r.
    Pattern {
        op: Op::Xor,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x31],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // add / sub reg-reg
    // ====================================================================
    // add r64, r64 — REX.W 01 /r.
    Pattern {
        op: Op::Add,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::AnyReg(RegClass::Gpr64),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x01],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // add r32, r32 — 01 /r.
    Pattern {
        op: Op::Add,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x01],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // sub r64, r64 — REX.W 29 /r.
    Pattern {
        op: Op::Sub,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::AnyReg(RegClass::Gpr64),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x29],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // sub r32, r32 — 29 /r.
    Pattern {
        op: Op::Sub,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x29],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // movsxd r64, r32 — REX.W 63 /r (canonical: movsxd rax,eax = 48 63 C0)
    // ====================================================================
    Pattern {
        op: Op::Movsxd,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x63],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // inc / dec / neg / not (FF /N or F7 /N family)
    // ====================================================================
    // inc r64 — REX.W FF /0.
    Pattern {
        op: Op::Inc,
        operands: &[OperandKind::AnyReg(RegClass::Gpr64)],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0xFF],
        modrm: Some(ModRMTemplate {
            mod_field: 0b11,
            reg_field: RegOrOpcodeExt::Fixed(0),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // inc r32 — FF /0.
    Pattern {
        op: Op::Inc,
        operands: &[OperandKind::AnyReg(RegClass::Gpr32)],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0xFF],
        modrm: Some(ModRMTemplate {
            mod_field: 0b11,
            reg_field: RegOrOpcodeExt::Fixed(0),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // dec r64 — REX.W FF /1.
    Pattern {
        op: Op::Dec,
        operands: &[OperandKind::AnyReg(RegClass::Gpr64)],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0xFF],
        modrm: Some(ModRMTemplate {
            mod_field: 0b11,
            reg_field: RegOrOpcodeExt::Fixed(1),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // dec r32 — FF /1.
    Pattern {
        op: Op::Dec,
        operands: &[OperandKind::AnyReg(RegClass::Gpr32)],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0xFF],
        modrm: Some(ModRMTemplate {
            mod_field: 0b11,
            reg_field: RegOrOpcodeExt::Fixed(1),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // neg r32 — F7 /3.
    Pattern {
        op: Op::Neg,
        operands: &[OperandKind::AnyReg(RegClass::Gpr32)],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0xF7],
        modrm: Some(ModRMTemplate {
            mod_field: 0b11,
            reg_field: RegOrOpcodeExt::Fixed(3),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // neg r64 — REX.W F7 /3.
    Pattern {
        op: Op::Neg,
        operands: &[OperandKind::AnyReg(RegClass::Gpr64)],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0xF7],
        modrm: Some(ModRMTemplate {
            mod_field: 0b11,
            reg_field: RegOrOpcodeExt::Fixed(3),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // not r32 — F7 /2.
    Pattern {
        op: Op::Not,
        operands: &[OperandKind::AnyReg(RegClass::Gpr32)],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0xF7],
        modrm: Some(ModRMTemplate {
            mod_field: 0b11,
            reg_field: RegOrOpcodeExt::Fixed(2),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // movzx / movsx
    // ====================================================================
    // movzx r32, r8 — 0F B6 /r.
    Pattern {
        op: Op::Movzx8,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::AnyReg(RegClass::Gpr8),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::Auto,
        opcode_prefix: &[],
        opcode: &[0x0F, 0xB6],
        modrm: Some(REG1_RM0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // setcc r8 — 0F 9X /0 (we only generate writes into AL today).
    // ====================================================================
    // setcc al — opcode is row.op's payload byte; encoder picks it up.
    // (For sete: 0F 94 C0; setne: 0F 95 C0; etc.) Encoded with Setcc(byte).
    // ====================================================================
    // SSE2 scalar
    // ====================================================================
    // movsd xmm, xmm — F2 0F 10 /r (or 11 /r; we use 10 = load form).
    Pattern {
        op: Op::Movsd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x10],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // movsd xmm, [base+disp32] — F2 0F 10 /r [disp32].
    Pattern {
        op: Op::Movsd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::Mem(RegClass::Gpr64, DispKind::Disp32),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x10],
        modrm: Some(MEM0_RM1_DISP32),
        opcode_reg: false,
        disp: DispKind::Disp32,
        imm: None,
    },
    // movsd [base+disp32], xmm — F2 0F 11 /r [disp32].
    Pattern {
        op: Op::Movsd,
        operands: &[
            OperandKind::Mem(RegClass::Gpr64, DispKind::Disp32),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x11],
        modrm: Some(ModRMTemplate {
            mod_field: 0b10,
            reg_field: RegOrOpcodeExt::FromOperand(1),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::Disp32,
        imm: None,
    },
    // movsd xmm, [base] — F2 0F 10 /r [mod=00].
    Pattern {
        op: Op::Movsd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::Mem(RegClass::Gpr64, DispKind::None),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x10],
        modrm: Some(REG_MEM0_RM1_NONE),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // movsd [base], xmm — F2 0F 11 /r [mod=00].
    Pattern {
        op: Op::Movsd,
        operands: &[
            OperandKind::Mem(RegClass::Gpr64, DispKind::None),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x11],
        modrm: Some(ModRMTemplate {
            mod_field: 0b00,
            reg_field: RegOrOpcodeExt::FromOperand(1),
            rm_field: RegOrOpcodeExt::FromOperand(0),
        }),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // movsd xmm, [rip+disp32] — F2 0F 10 /r [rip+disp32].
    Pattern {
        op: Op::Movsd,
        operands: &[OperandKind::AnyReg(RegClass::Xmm), OperandKind::MemRipRel],
        arch: ArchSet::X64Only,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x10],
        modrm: Some(RIPREL_REG0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // movsd xmm, [disp32 abs] — F2 0F 10 /r, mod=00 rm=101 (X86Only). On
    // i386 an FP literal in `.flit.*` is loaded absolutely (no RIP-relative
    // mode); the bytes are the x64 RIP form verbatim (the `F2 0F 10` prefix/
    // opcode carry no REX, and mod=00 rm=101 is `[disp32]` on x86 rather than
    // `[rip+disp32]`). The disp32 slot is reported via `abs_at`; the Gen emit
    // site records it as a `RipRef::Data` fixup, which `to_object` maps to a
    // DIR32/Addr32 reloc on Win32 (same path as the integer-global lea).
    Pattern {
        op: Op::Movsd,
        operands: &[OperandKind::AnyReg(RegClass::Xmm), OperandKind::MemAbs],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x10],
        modrm: Some(RIPREL_REG0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // addsd xmm, xmm — F2 0F 58 /r.
    Pattern {
        op: Op::Addsd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x58],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // subsd xmm, xmm — F2 0F 5C /r.
    Pattern {
        op: Op::Subsd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x5C],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // mulsd xmm, xmm — F2 0F 59 /r.
    Pattern {
        op: Op::Mulsd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x59],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // divsd xmm, xmm — F2 0F 5E /r.
    Pattern {
        op: Op::Divsd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x5E],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ucomisd xmm, xmm — 66 0F 2E /r.
    Pattern {
        op: Op::Ucomisd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0x66],
        opcode: &[0x0F, 0x2E],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // xorpd xmm, xmm — 66 0F 57 /r.
    Pattern {
        op: Op::Xorpd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0x66],
        opcode: &[0x0F, 0x57],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // cvtsi2sd xmm, r32 — F2 0F 2A /r.
    Pattern {
        op: Op::Cvtsi2sd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x2A],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // cvtsi2sd xmm, r64 — F2 REX.W 0F 2A /r.
    Pattern {
        op: Op::Cvtsi2sd,
        operands: &[
            OperandKind::AnyReg(RegClass::Xmm),
            OperandKind::AnyReg(RegClass::Gpr64),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x2A],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // cvttsd2si r32, xmm — F2 0F 2C /r.
    Pattern {
        op: Op::Cvttsd2si,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x2C],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // cvttsd2si r64, xmm — F2 REX.W 0F 2C /r.
    Pattern {
        op: Op::Cvttsd2si,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr64),
            OperandKind::AnyReg(RegClass::Xmm),
        ],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[0xF2],
        opcode: &[0x0F, 0x2C],
        modrm: Some(REG0_RM1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // Misc 1-byte
    // ====================================================================
    // cdq — 99. (Sign-extend eax into edx:eax.)
    Pattern {
        op: Op::Cdq,
        operands: &[],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x99],
        modrm: None,
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // cqo — 48 99. (Sign-extend rax into rdx:rax.)
    Pattern {
        op: Op::Cqo,
        operands: &[],
        arch: ArchSet::X64Only,
        rex: RexPolicy::W,
        opcode_prefix: &[],
        opcode: &[0x99],
        modrm: None,
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // int3 — CC.
    Pattern {
        op: Op::Int3,
        operands: &[],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0xCC],
        modrm: None,
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // nop — 90.
    Pattern {
        op: Op::Nop,
        operands: &[],
        arch: ArchSet::Both,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x90],
        modrm: None,
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // ====================================================================
    // S2b.4 — x86-only (Win32 / i386) rows
    // ====================================================================
    // These mirror their x64 counterparts but use a 32-bit base register
    // (`RegClass::Gpr32`) and carry no REX byte (`encode_x86` suppresses
    // it). The `mov r32, r32` / `mov r32, imm32` / `ret` / `leave;ret` /
    // `call rel32` / `jmp rel32` forms are already `Both` rows above and
    // need no x86 duplicate. Absolute `[disp32]` addressing replaces x64's
    // RIP-relative form for globals + string literals.
    //
    // -- mov r32, [base32 (+disp)] (load) — 8B /r ------------------------
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::Mem(RegClass::Gpr32, DispKind::None),
        ],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x8B],
        modrm: Some(REG_MEM0_RM1_NONE),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::Mem(RegClass::Gpr32, DispKind::Disp8),
        ],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x8B],
        modrm: Some(REG_MEM0_RM1_DISP8),
        opcode_reg: false,
        disp: DispKind::Disp8,
        imm: None,
    },
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::Mem(RegClass::Gpr32, DispKind::Disp32),
        ],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x8B],
        modrm: Some(MEM0_RM1_DISP32),
        opcode_reg: false,
        disp: DispKind::Disp32,
        imm: None,
    },
    // -- mov [base32 (+disp)], r32 (store) — 89 /r -----------------------
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::Mem(RegClass::Gpr32, DispKind::None),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x89],
        modrm: Some(STORE_REG1_MEM0_NONE),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::Mem(RegClass::Gpr32, DispKind::Disp8),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x89],
        modrm: Some(STORE_REG1_MEM0_DISP8),
        opcode_reg: false,
        disp: DispKind::Disp8,
        imm: None,
    },
    Pattern {
        op: Op::Mov,
        operands: &[
            OperandKind::Mem(RegClass::Gpr32, DispKind::Disp32),
            OperandKind::AnyReg(RegClass::Gpr32),
        ],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x89],
        modrm: Some(STORE_REG1_MEM0_DISP32),
        opcode_reg: false,
        disp: DispKind::Disp32,
        imm: None,
    },
    // -- lea r32, [base32 (+disp)] — 8D /r -------------------------------
    Pattern {
        op: Op::Lea,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::Mem(RegClass::Gpr32, DispKind::Disp8),
        ],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x8D],
        modrm: Some(REG_MEM0_RM1_DISP8),
        opcode_reg: false,
        disp: DispKind::Disp8,
        imm: None,
    },
    Pattern {
        op: Op::Lea,
        operands: &[
            OperandKind::AnyReg(RegClass::Gpr32),
            OperandKind::Mem(RegClass::Gpr32, DispKind::Disp32),
        ],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x8D],
        modrm: Some(MEM0_RM1_DISP32),
        opcode_reg: false,
        disp: DispKind::Disp32,
        imm: None,
    },
    // -- lea r32, [disp32 abs] — 8D mod=00 rm=101 (globals/strings) ------
    Pattern {
        op: Op::Lea,
        operands: &[OperandKind::AnyReg(RegClass::Gpr32), OperandKind::MemAbs],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x8D],
        modrm: Some(RIPREL_REG0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // -- mov r32, [disp32 abs] (load) — 8B mod=00 rm=101 -----------------
    Pattern {
        op: Op::Mov,
        operands: &[OperandKind::AnyReg(RegClass::Gpr32), OperandKind::MemAbs],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x8B],
        modrm: Some(RIPREL_REG0),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // -- mov [disp32 abs], r32 (store) — 89 mod=00 rm=101 ----------------
    Pattern {
        op: Op::Mov,
        operands: &[OperandKind::MemAbs, OperandKind::AnyReg(RegClass::Gpr32)],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x89],
        modrm: Some(ABS_STORE_REG1),
        opcode_reg: false,
        disp: DispKind::None,
        imm: None,
    },
    // -- push r32 / pop r32 — 50+r / 58+r --------------------------------
    Pattern {
        op: Op::Push,
        operands: &[OperandKind::AnyReg(RegClass::Gpr32)],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x50],
        modrm: None,
        opcode_reg: true,
        disp: DispKind::None,
        imm: None,
    },
    Pattern {
        op: Op::Pop,
        operands: &[OperandKind::AnyReg(RegClass::Gpr32)],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0x58],
        modrm: None,
        opcode_reg: true,
        disp: DispKind::None,
        imm: None,
    },
    // -- ret imm16 — C2 iw (stdcall/fastcall callee stack cleanup) -------
    Pattern {
        op: Op::RetImm,
        operands: &[OperandKind::Imm(ImmKind::Imm16)],
        arch: ArchSet::X86Only,
        rex: RexPolicy::None,
        opcode_prefix: &[],
        opcode: &[0xC2],
        modrm: None,
        opcode_reg: false,
        disp: DispKind::None,
        imm: Some(ImmKind::Imm16),
    },
];

// Catch unused warnings for placeholders we use selectively in different
// arch flavours; per-row referenced from emit.rs.
#[allow(dead_code)]
const _COVERAGE_HINT: (RegId, RegClass, ScaleKind) = (RegId::Rax, RegClass::Gpr64, ScaleKind::S1);
