//! Unit tests for the table-driven encoder (S2a). Each test pins one
//! row of `patterns::PATTERN_TABLE` against the bytes the historical
//! hand-rolled emit site produced. The five HLD §3.3 worked examples
//! are covered first, then a sweep across the rest of the table.

use super::builders::*;
use super::regs::RegId::*;
use super::*;

fn enc(op: Op, ops: &[Operand]) -> Vec<u8> {
    encode_x64(op, ops).expect("encode").bytes
}

/// HLD §3.3 Example 1 — mov rax, [rbp+0x10] = 48 8B 85 10 00 00 00.
#[test]
fn ex1_mov_r64_from_rbp_disp32() {
    let bytes = enc(Op::Mov, &[reg64(Rax), mem64(Rbp, 0x10, DispKind::Disp32)]);
    assert_eq!(bytes, vec![0x48, 0x8B, 0x85, 0x10, 0x00, 0x00, 0x00]);
}

/// HLD §3.3 Example 2 — mov ecx, 42 = B9 2A 00 00 00.
#[test]
fn ex2_mov_r32_imm32() {
    let bytes = enc(Op::Mov, &[reg32(Rcx), imm32(42)]);
    assert_eq!(bytes, vec![0xB9, 0x2A, 0x00, 0x00, 0x00]);
}

/// HLD §3.3 Example 3 — call rel32 = E8 00 00 00 00.
#[test]
fn ex3_call_rel32() {
    let bytes = enc(Op::Call, &[rel32()]);
    assert_eq!(bytes, vec![0xE8, 0x00, 0x00, 0x00, 0x00]);
}

/// HLD §3.3 Example 4 — lea rax, [rip+0] = 48 8D 05 00 00 00 00.
/// The disp32 slot is reported via `riprel_at`.
#[test]
fn ex4_lea_riprel() {
    let r = encode_x64(Op::Lea, &[reg64(Rax), riprel()]).unwrap();
    assert_eq!(r.bytes, vec![0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(r.riprel_at, Some(3));
}

/// HLD §3.3 Example 5 — ret = C3.
#[test]
fn ex5_ret() {
    let bytes = enc(Op::Ret, &[]);
    assert_eq!(bytes, vec![0xC3]);
}

/// mov [rbp+disp32], rax = 48 89 85 disp32.
#[test]
fn mov_mem_rbp_disp32_from_rax() {
    let bytes = enc(Op::Mov, &[mem64(Rbp, -8, DispKind::Disp32), reg64(Rax)]);
    assert_eq!(bytes, vec![0x48, 0x89, 0x85, 0xF8, 0xFF, 0xFF, 0xFF]);
}

/// mov rax, rcx = 48 89 C8 (R1_RM0: reg=Rcx rm=Rax).
#[test]
fn mov_r64_r64() {
    let bytes = enc(Op::Mov, &[reg64(Rax), reg64(Rcx)]);
    assert_eq!(bytes, vec![0x48, 0x89, 0xC8]);
}

/// xor rax, rax = 48 31 C0.
#[test]
fn xor_rax_rax() {
    let bytes = enc(Op::Xor, &[reg64(Rax), reg64(Rax)]);
    assert_eq!(bytes, vec![0x48, 0x31, 0xC0]);
}

/// xor eax, eax = 31 C0 (no REX needed).
#[test]
fn xor_eax_eax() {
    let bytes = enc(Op::Xor, &[reg32(Rax), reg32(Rax)]);
    assert_eq!(bytes, vec![0x31, 0xC0]);
}

/// xor edx, edx = 31 D2.
#[test]
fn xor_edx_edx() {
    let bytes = enc(Op::Xor, &[reg32(Rdx), reg32(Rdx)]);
    assert_eq!(bytes, vec![0x31, 0xD2]);
}

/// test rax, rax = 48 85 C0.
#[test]
fn test_rax_rax() {
    let bytes = enc(Op::Test, &[reg64(Rax), reg64(Rax)]);
    assert_eq!(bytes, vec![0x48, 0x85, 0xC0]);
}

/// test eax, eax = 85 C0.
#[test]
fn test_eax_eax() {
    let bytes = enc(Op::Test, &[reg32(Rax), reg32(Rax)]);
    assert_eq!(bytes, vec![0x85, 0xC0]);
}

/// mov rax, imm64 = 48 B8 imm64.
#[test]
fn mov_rax_imm64() {
    let bytes = enc(Op::Mov, &[reg64(Rax), imm64(0x0123456789ABCDEFi64)]);
    assert_eq!(
        bytes,
        vec![0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]
    );
}

/// push rbp = 55.
#[test]
fn push_rbp() {
    let bytes = enc(Op::Push, &[reg64(Rbp)]);
    assert_eq!(bytes, vec![0x55]);
}

/// pop rbp = 5D.
#[test]
fn pop_rbp() {
    let bytes = enc(Op::Pop, &[reg64(Rbp)]);
    assert_eq!(bytes, vec![0x5D]);
}

/// jmp rel32 = E9 00 00 00 00.
#[test]
fn jmp_rel32() {
    let bytes = enc(Op::Jmp, &[rel32()]);
    assert_eq!(bytes, vec![0xE9, 0x00, 0x00, 0x00, 0x00]);
}

/// call rax = FF D0.
#[test]
fn call_rax() {
    let bytes = enc(Op::CallReg, &[reg64(Rax)]);
    assert_eq!(bytes, vec![0xFF, 0xD0]);
}

/// leave; ret = C9 C3.
#[test]
fn leave_ret() {
    let bytes = enc(Op::LeaveRet, &[]);
    assert_eq!(bytes, vec![0xC9, 0xC3]);
}

/// movsxd rax, eax = 48 63 C0.
#[test]
fn movsxd_rax_eax() {
    let bytes = enc(Op::Movsxd, &[reg64(Rax), reg32(Rax)]);
    assert_eq!(bytes, vec![0x48, 0x63, 0xC0]);
}

/// movsd xmm0, [rbp+disp32] = F2 0F 10 85 disp32.
#[test]
fn movsd_xmm0_from_rbp() {
    let bytes = enc(Op::Movsd, &[xmm(Xmm0), mem64(Rbp, -8, DispKind::Disp32)]);
    assert_eq!(bytes, vec![0xF2, 0x0F, 0x10, 0x85, 0xF8, 0xFF, 0xFF, 0xFF]);
}

/// movsd xmm1, [rbp+disp32] = F2 0F 10 8D disp32.
#[test]
fn movsd_xmm1_from_rbp() {
    let bytes = enc(Op::Movsd, &[xmm(Xmm1), mem64(Rbp, -16, DispKind::Disp32)]);
    assert_eq!(bytes[..4], [0xF2, 0x0F, 0x10, 0x8D]);
}

/// movsd [rbp+disp32], xmm0 = F2 0F 11 85 disp32.
#[test]
fn movsd_rbp_from_xmm0() {
    let bytes = enc(Op::Movsd, &[mem64(Rbp, -24, DispKind::Disp32), xmm(Xmm0)]);
    assert_eq!(bytes[..4], [0xF2, 0x0F, 0x11, 0x85]);
}

/// addsd xmm0, xmm1 = F2 0F 58 C1.
#[test]
fn addsd_xmm0_xmm1() {
    let bytes = enc(Op::Addsd, &[xmm(Xmm0), xmm(Xmm1)]);
    assert_eq!(bytes, vec![0xF2, 0x0F, 0x58, 0xC1]);
}

/// subsd xmm0, xmm1 = F2 0F 5C C1.
#[test]
fn subsd_xmm0_xmm1() {
    let bytes = enc(Op::Subsd, &[xmm(Xmm0), xmm(Xmm1)]);
    assert_eq!(bytes, vec![0xF2, 0x0F, 0x5C, 0xC1]);
}

/// mulsd xmm0, xmm1 = F2 0F 59 C1.
#[test]
fn mulsd_xmm0_xmm1() {
    let bytes = enc(Op::Mulsd, &[xmm(Xmm0), xmm(Xmm1)]);
    assert_eq!(bytes, vec![0xF2, 0x0F, 0x59, 0xC1]);
}

/// divsd xmm0, xmm1 = F2 0F 5E C1.
#[test]
fn divsd_xmm0_xmm1() {
    let bytes = enc(Op::Divsd, &[xmm(Xmm0), xmm(Xmm1)]);
    assert_eq!(bytes, vec![0xF2, 0x0F, 0x5E, 0xC1]);
}

/// ucomisd xmm0, xmm1 = 66 0F 2E C1.
#[test]
fn ucomisd_xmm0_xmm1() {
    let bytes = enc(Op::Ucomisd, &[xmm(Xmm0), xmm(Xmm1)]);
    assert_eq!(bytes, vec![0x66, 0x0F, 0x2E, 0xC1]);
}

/// xorpd xmm0, xmm0 = 66 0F 57 C0.
#[test]
fn xorpd_xmm0_xmm0() {
    let bytes = enc(Op::Xorpd, &[xmm(Xmm0), xmm(Xmm0)]);
    assert_eq!(bytes, vec![0x66, 0x0F, 0x57, 0xC0]);
}

/// cvtsi2sd xmm0, eax = F2 0F 2A C0.
#[test]
fn cvtsi2sd_xmm0_eax() {
    let bytes = enc(Op::Cvtsi2sd, &[xmm(Xmm0), reg32(Rax)]);
    assert_eq!(bytes, vec![0xF2, 0x0F, 0x2A, 0xC0]);
}

/// cvtsi2sd xmm0, rax = F2 48 0F 2A C0.
#[test]
fn cvtsi2sd_xmm0_rax() {
    let bytes = enc(Op::Cvtsi2sd, &[xmm(Xmm0), reg64(Rax)]);
    assert_eq!(bytes, vec![0xF2, 0x48, 0x0F, 0x2A, 0xC0]);
}

/// cvttsd2si eax, xmm0 = F2 0F 2C C0.
#[test]
fn cvttsd2si_eax_xmm0() {
    let bytes = enc(Op::Cvttsd2si, &[reg32(Rax), xmm(Xmm0)]);
    assert_eq!(bytes, vec![0xF2, 0x0F, 0x2C, 0xC0]);
}

/// cvttsd2si rax, xmm0 = F2 48 0F 2C C0.
#[test]
fn cvttsd2si_rax_xmm0() {
    let bytes = enc(Op::Cvttsd2si, &[reg64(Rax), xmm(Xmm0)]);
    assert_eq!(bytes, vec![0xF2, 0x48, 0x0F, 0x2C, 0xC0]);
}

/// add rax, rcx = 48 01 C8.
#[test]
fn add_r64_r64() {
    let bytes = enc(Op::Add, &[reg64(Rax), reg64(Rcx)]);
    assert_eq!(bytes, vec![0x48, 0x01, 0xC8]);
}

/// add eax, ecx = 01 C8.
#[test]
fn add_r32_r32() {
    let bytes = enc(Op::Add, &[reg32(Rax), reg32(Rcx)]);
    assert_eq!(bytes, vec![0x01, 0xC8]);
}

/// sub rax, rcx = 48 29 C8.
#[test]
fn sub_r64_r64() {
    let bytes = enc(Op::Sub, &[reg64(Rax), reg64(Rcx)]);
    assert_eq!(bytes, vec![0x48, 0x29, 0xC8]);
}

/// sub eax, ecx = 29 C8.
#[test]
fn sub_r32_r32() {
    let bytes = enc(Op::Sub, &[reg32(Rax), reg32(Rcx)]);
    assert_eq!(bytes, vec![0x29, 0xC8]);
}

/// cmp eax, ecx = 39 C8.
#[test]
fn cmp_r32_r32() {
    let bytes = enc(Op::Cmp, &[reg32(Rax), reg32(Rcx)]);
    assert_eq!(bytes, vec![0x39, 0xC8]);
}

/// movzx eax, al = 0F B6 C0.
#[test]
fn movzx_eax_al() {
    let bytes = enc(Op::Movzx8, &[reg32(Rax), reg8(Rax)]);
    assert_eq!(bytes, vec![0x0F, 0xB6, 0xC0]);
}

/// lea rax, [rbp+disp32] = 48 8D 85 disp32.
#[test]
fn lea_rax_rbp_disp32() {
    let bytes = enc(Op::Lea, &[reg64(Rax), mem64(Rbp, -32, DispKind::Disp32)]);
    assert_eq!(bytes, vec![0x48, 0x8D, 0x85, 0xE0, 0xFF, 0xFF, 0xFF]);
}

/// lea rcx, [rbp+disp32] = 48 8D 8D disp32.
#[test]
fn lea_rcx_rbp_disp32() {
    let bytes = enc(Op::Lea, &[reg64(Rcx), mem64(Rbp, 16, DispKind::Disp32)]);
    assert_eq!(bytes, vec![0x48, 0x8D, 0x8D, 0x10, 0x00, 0x00, 0x00]);
}

/// lea r9, [rax+8] = 4C 8D 48 08 (disp8 form).
#[test]
fn lea_r9_rax_disp8() {
    let bytes = enc(Op::Lea, &[reg64(R9), mem64(Rax, 0x08, DispKind::Disp8)]);
    assert_eq!(bytes, vec![0x4C, 0x8D, 0x48, 0x08]);
}

/// mov rax, [rsp+disp32] requires a SIB byte. Verify the encoder
/// emits `mod=10 rm=100 SIB=24` for the RSP base.
#[test]
fn mov_rax_from_rsp_disp32_uses_sib() {
    let bytes = enc(Op::Mov, &[reg64(Rax), mem64(Rsp, 0x20, DispKind::Disp32)]);
    assert_eq!(bytes, vec![0x48, 0x8B, 0x84, 0x24, 0x20, 0x00, 0x00, 0x00]);
}

/// mov [rsp+disp32], rax = 48 89 84 24 disp32. SIB + REX.W.
#[test]
fn mov_rsp_from_rax_uses_sib() {
    let bytes = enc(Op::Mov, &[mem64(Rsp, 0x20, DispKind::Disp32), reg64(Rax)]);
    assert_eq!(bytes, vec![0x48, 0x89, 0x84, 0x24, 0x20, 0x00, 0x00, 0x00]);
}

/// mov r9, [rbp+disp32] = 4C 8B 8D disp32 (REX.R extension for r9).
#[test]
fn mov_r9_rbp_disp32() {
    let bytes = enc(Op::Mov, &[reg64(R9), mem64(Rbp, -64, DispKind::Disp32)]);
    assert_eq!(bytes, vec![0x4C, 0x8B, 0x8D, 0xC0, 0xFF, 0xFF, 0xFF]);
}

/// cdq = 99.
#[test]
fn cdq() {
    let bytes = enc(Op::Cdq, &[]);
    assert_eq!(bytes, vec![0x99]);
}

/// cqo = 48 99.
#[test]
fn cqo() {
    let bytes = enc(Op::Cqo, &[]);
    assert_eq!(bytes, vec![0x48, 0x99]);
}

/// ud2 = 0F 0B.
#[test]
fn ud2() {
    let bytes = enc(Op::Ud2, &[]);
    assert_eq!(bytes, vec![0x0F, 0x0B]);
}

/// nop = 90.
#[test]
fn nop_op() {
    let bytes = enc(Op::Nop, &[]);
    assert_eq!(bytes, vec![0x90]);
}

/// mov rcx, [rbp+disp32] = 48 8B 8D disp32.
#[test]
fn mov_rcx_rbp_disp32() {
    let bytes = enc(Op::Mov, &[reg64(Rcx), mem64(Rbp, 0, DispKind::Disp32)]);
    assert_eq!(bytes, vec![0x48, 0x8B, 0x8D, 0x00, 0x00, 0x00, 0x00]);
}

/// mov rdx, [rbp+disp32] = 48 8B 95 disp32.
#[test]
fn mov_rdx_rbp_disp32() {
    let bytes = enc(Op::Mov, &[reg64(Rdx), mem64(Rbp, 0, DispKind::Disp32)]);
    assert_eq!(bytes, vec![0x48, 0x8B, 0x95, 0x00, 0x00, 0x00, 0x00]);
}

/// mov [rbp+disp32], rcx = 48 89 8D disp32 (ARG_SPILL[0]).
#[test]
fn mov_rbp_disp32_from_rcx() {
    let bytes = enc(Op::Mov, &[mem64(Rbp, 0, DispKind::Disp32), reg64(Rcx)]);
    assert_eq!(bytes, vec![0x48, 0x89, 0x8D, 0x00, 0x00, 0x00, 0x00]);
}

/// mov [rbp+disp32], rdx = 48 89 95 disp32 (ARG_SPILL[1]).
#[test]
fn mov_rbp_disp32_from_rdx() {
    let bytes = enc(Op::Mov, &[mem64(Rbp, 0, DispKind::Disp32), reg64(Rdx)]);
    assert_eq!(bytes, vec![0x48, 0x89, 0x95, 0x00, 0x00, 0x00, 0x00]);
}

/// mov [rbp+disp32], r8 = 4C 89 85 disp32 (ARG_SPILL[2]; REX.R for r8).
#[test]
fn mov_rbp_disp32_from_r8() {
    let bytes = enc(Op::Mov, &[mem64(Rbp, 0, DispKind::Disp32), reg64(R8)]);
    assert_eq!(bytes, vec![0x4C, 0x89, 0x85, 0x00, 0x00, 0x00, 0x00]);
}

/// mov [rbp+disp32], r9 = 4C 89 8D disp32 (ARG_SPILL[3]).
#[test]
fn mov_rbp_disp32_from_r9() {
    let bytes = enc(Op::Mov, &[mem64(Rbp, 0, DispKind::Disp32), reg64(R9)]);
    assert_eq!(bytes, vec![0x4C, 0x89, 0x8D, 0x00, 0x00, 0x00, 0x00]);
}

/// mov rax, [rip+disp32] = 48 8B 05 (RipRel; disp32 zero, fixup slot at 3).
#[test]
fn mov_rax_riprel_disp32() {
    let r = encode_x64(Op::Mov, &[reg64(Rax), riprel()]).unwrap();
    assert_eq!(r.bytes, vec![0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(r.riprel_at, Some(3));
}

/// movsd xmm0, [rip+disp32] = F2 0F 10 05 disp32 — fixup at 4.
#[test]
fn movsd_xmm0_riprel() {
    let r = encode_x64(Op::Movsd, &[xmm(Xmm0), riprel()]).unwrap();
    assert_eq!(
        r.bytes,
        vec![0xF2, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(r.riprel_at, Some(4));
}

/// mov eax, 0 = B8 00 00 00 00.
#[test]
fn mov_eax_zero() {
    let bytes = enc(Op::Mov, &[reg32(Rax), imm32(0)]);
    assert_eq!(bytes, vec![0xB8, 0x00, 0x00, 0x00, 0x00]);
}

/// mov eax, 1 = B8 01 00 00 00.
#[test]
fn mov_eax_one() {
    let bytes = enc(Op::Mov, &[reg32(Rax), imm32(1)]);
    assert_eq!(bytes, vec![0xB8, 0x01, 0x00, 0x00, 0x00]);
}

/// int3 = CC.
#[test]
fn int3_op() {
    let bytes = enc(Op::Int3, &[]);
    assert_eq!(bytes, vec![0xCC]);
}

/// inc rax = 48 FF C0.
#[test]
fn inc_rax() {
    let bytes = enc(Op::Inc, &[reg64(Rax)]);
    assert_eq!(bytes, vec![0x48, 0xFF, 0xC0]);
}

/// dec eax = FF C8.
#[test]
fn dec_eax() {
    let bytes = enc(Op::Dec, &[reg32(Rax)]);
    assert_eq!(bytes, vec![0xFF, 0xC8]);
}

/// dec ecx = FF C9.
#[test]
fn dec_ecx() {
    let bytes = enc(Op::Dec, &[reg32(Rcx)]);
    assert_eq!(bytes, vec![0xFF, 0xC9]);
}

/// inc r9 = 49 FF C1 (REX.B for r9).
#[test]
fn inc_r9() {
    let bytes = enc(Op::Inc, &[reg64(R9)]);
    assert_eq!(bytes, vec![0x49, 0xFF, 0xC1]);
}

/// dec r9 = 49 FF C9.
#[test]
fn dec_r9() {
    let bytes = enc(Op::Dec, &[reg64(R9)]);
    assert_eq!(bytes, vec![0x49, 0xFF, 0xC9]);
}

/// neg eax = F7 D8.
#[test]
fn neg_eax() {
    let bytes = enc(Op::Neg, &[reg32(Rax)]);
    assert_eq!(bytes, vec![0xF7, 0xD8]);
}

/// not eax = F7 D0.
#[test]
fn not_eax() {
    let bytes = enc(Op::Not, &[reg32(Rax)]);
    assert_eq!(bytes, vec![0xF7, 0xD0]);
}

// =======================================================================
// S2b.4 — x86 (Win32 / i386) encoder rows. `encode_x86` filters to
// `Both` + `X86Only` rows and suppresses the REX byte. Every expected
// byte string is hand-verified against Intel's encoding.
// =======================================================================
mod x86 {
    use super::*;

    fn enc86(op: Op, ops: &[Operand]) -> Vec<u8> {
        encode_x86(op, ops).expect("encode_x86").bytes
    }

    /// A `Both` row reached via x86: `mov ecx, 42` = B9 2A 00 00 00 — the
    /// same bytes x64 emits (no REX for low registers). Proves shared rows
    /// work through the x86 entry point.
    #[test]
    fn both_row_mov_r32_imm32() {
        assert_eq!(
            enc86(Op::Mov, &[reg32(Rcx), imm32(42)]),
            vec![0xB9, 0x2A, 0x00, 0x00, 0x00]
        );
    }

    /// `mov eax, ecx` = 89 C8 (no REX on x86; identical to x64 for these
    /// low registers — the REX-suppression path is a no-op here but the
    /// arch filter + Both row still resolve).
    #[test]
    fn both_row_mov_r32_r32() {
        assert_eq!(enc86(Op::Mov, &[reg32(Rax), reg32(Rcx)]), vec![0x89, 0xC8]);
    }

    /// `mov eax, [ebp-8]` = 8B 45 F8 (mod=01 reg=000 rm=101, disp8 = -8).
    #[test]
    fn mov_r32_from_frame_disp8() {
        assert_eq!(
            enc86(Op::Mov, &[reg32(Rax), mem32(Rbp, -8, DispKind::Disp8)]),
            vec![0x8B, 0x45, 0xF8]
        );
    }

    /// `mov eax, [ebp-16]` = 8B 85 F0 FF FF FF (mod=10, disp32 = -16).
    #[test]
    fn mov_r32_from_frame_disp32() {
        assert_eq!(
            enc86(Op::Mov, &[reg32(Rax), mem32(Rbp, -16, DispKind::Disp32)]),
            vec![0x8B, 0x85, 0xF0, 0xFF, 0xFF, 0xFF]
        );
    }

    /// `mov [ebp-8], ecx` = 89 4D F8 (store: reg=op1=ecx=001, rm=ebp=101).
    #[test]
    fn mov_frame_disp8_from_r32() {
        assert_eq!(
            enc86(Op::Mov, &[mem32(Rbp, -8, DispKind::Disp8), reg32(Rcx)]),
            vec![0x89, 0x4D, 0xF8]
        );
    }

    /// `lea eax, [ebp-8]` = 8D 45 F8.
    #[test]
    fn lea_r32_frame_disp8() {
        assert_eq!(
            enc86(Op::Lea, &[reg32(Rax), mem32(Rbp, -8, DispKind::Disp8)]),
            vec![0x8D, 0x45, 0xF8]
        );
    }

    /// `lea eax, [disp32]` = 8D 05 00 00 00 00. The absolute slot is
    /// reported via `abs_at` (NOT `riprel_at`) — x86 has no RIP-relative.
    #[test]
    fn lea_r32_abs() {
        let r = encode_x86(Op::Lea, &[reg32(Rax), memabs()]).unwrap();
        assert_eq!(r.bytes, vec![0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(r.abs_at, Some(2));
        assert_eq!(r.riprel_at, None);
    }

    /// `mov eax, [disp32]` = 8B 05 00 00 00 00, abs_at = 2.
    #[test]
    fn mov_r32_from_abs() {
        let r = encode_x86(Op::Mov, &[reg32(Rax), memabs()]).unwrap();
        assert_eq!(r.bytes, vec![0x8B, 0x05, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(r.abs_at, Some(2));
    }

    /// `mov [disp32], eax` = 89 05 00 00 00 00, abs_at = 2.
    #[test]
    fn mov_abs_from_r32() {
        let r = encode_x86(Op::Mov, &[memabs(), reg32(Rax)]).unwrap();
        assert_eq!(r.bytes, vec![0x89, 0x05, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(r.abs_at, Some(2));
    }

    /// `movsd xmm1, [disp32]` = F2 0F 10 0D 00 00 00 00, abs_at = 4. The
    /// i386 form of an FP-literal load: the x64 RIP bytes verbatim (no REX
    /// on the `F2 0F 10` prefix/opcode), with mod=00 rm=101 meaning absolute
    /// `[disp32]` on x86. The disp32 fixup slot is reported via `abs_at`
    /// (NOT `riprel_at`) — the Gen emit site records it as a `RipRef::Data`
    /// (Addr32) reloc against the `.flit.*` global.
    #[test]
    fn movsd_xmm_from_abs() {
        let r = encode_x86(Op::Movsd, &[xmm(Xmm1), memabs()]).unwrap();
        assert_eq!(
            r.bytes,
            vec![0xF2, 0x0F, 0x10, 0x0D, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(r.abs_at, Some(4));
        assert_eq!(r.riprel_at, None);
    }

    /// `movsd xmm0, [disp32]` = F2 0F 10 05 … (reg=000 ⇒ ModR/M 05) — pins
    /// the xmm operand into the ModR/M reg field.
    #[test]
    fn movsd_xmm0_from_abs() {
        let r = encode_x86(Op::Movsd, &[xmm(Xmm0), memabs()]).unwrap();
        assert_eq!(
            r.bytes,
            vec![0xF2, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(r.abs_at, Some(4));
    }

    /// `push ebp` = 55, `pop ebp` = 5D (opcode-register, no REX).
    #[test]
    fn push_pop_r32() {
        assert_eq!(enc86(Op::Push, &[reg32(Rbp)]), vec![0x55]);
        assert_eq!(enc86(Op::Pop, &[reg32(Rbp)]), vec![0x5D]);
    }

    /// `ret 8` = C2 08 00 (stdcall callee cleanup).
    #[test]
    fn ret_imm16() {
        assert_eq!(
            enc86(Op::RetImm, &[Operand::Imm(ImmKind::Imm16, 8)]),
            vec![0xC2, 0x08, 0x00]
        );
    }

    /// `call eax` = FF D0 (FF /2, mod=11 reg=/2 rm=eax; no REX on x86) — the
    /// x86 indirect-call form. Same bytes as the x64 `call rax` row, reached
    /// through a Gpr32 operand via the X86Only row.
    #[test]
    fn call_eax() {
        assert_eq!(enc86(Op::CallReg, &[reg32(Rax)]), vec![0xFF, 0xD0]);
    }

    /// `call ecx` = FF D1 — pins the rm field to the operand register.
    #[test]
    fn call_ecx() {
        assert_eq!(enc86(Op::CallReg, &[reg32(Rcx)]), vec![0xFF, 0xD1]);
    }

    /// Arch filter: an x64-only shape (`mov r64, [rbp+disp32]`) has no
    /// matching row for the x86 target — `encode_x86` errors rather than
    /// silently emitting a 64-bit form.
    #[test]
    fn x64_only_row_not_reachable_from_x86() {
        let r = encode_x86(Op::Mov, &[reg64(Rax), mem64(Rbp, -8, DispKind::Disp32)]);
        assert!(matches!(r, Err(EncodeError::NoMatchingRow(..))));
    }
}
