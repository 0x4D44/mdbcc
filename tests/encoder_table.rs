//! S2a integration tests for the table-driven encoder.
//!
//! Lock the 5 HLD §3.3 worked examples and a sweep of additional
//! mnemonics. These tests run against the public `mdbcc::codegen::encoder`
//! API (made `pub(crate)` for now; promoted to `pub` if the encoder
//! becomes a library surface in S8 disassembler work).
//!
//! Note: the codegen module is `pub(crate)` so we cannot import the
//! encoder directly from outside the crate. Instead, this file lives
//! under `tests/` but exercises the encoder via a dedicated public
//! re-export added in `src/lib.rs` (`pub mod encoder_api`). If/when
//! the re-export shifts, this test file moves with it.
//!
//! The 88-fixture O1 SipHash stripe in `tests/o1_byte_identity.rs` is
//! the deeper regression gate — those bytes lock the encoder's behaviour
//! end-to-end through `compile_to_pe()`. This file is the unit-test
//! complement: each row stands alone, easy to debug.

use mdbcc::encoder_api as enc;

fn assert_bytes(op: enc::Op, ops: &[enc::Operand], expected: &[u8]) {
    let r = enc::encode_x64(op, ops).expect("encode");
    assert_eq!(
        r.bytes, expected,
        "op {op:?} ops {ops:?} produced {:02X?}, expected {:02X?}",
        r.bytes, expected
    );
}

/// HLD §3.3 #1 — mov rax, [rbp+0x10].
#[test]
fn hld_ex1_mov_r64_rbp_disp32() {
    assert_bytes(
        enc::Op::Mov,
        &[
            enc::builders::reg64(enc::RegId::Rax),
            enc::builders::mem64(enc::RegId::Rbp, 0x10, enc::DispKind::Disp32),
        ],
        &[0x48, 0x8B, 0x85, 0x10, 0x00, 0x00, 0x00],
    );
}

/// HLD §3.3 #2 — mov ecx, 42.
#[test]
fn hld_ex2_mov_r32_imm32() {
    assert_bytes(
        enc::Op::Mov,
        &[
            enc::builders::reg32(enc::RegId::Rcx),
            enc::builders::imm32(42),
        ],
        &[0xB9, 0x2A, 0x00, 0x00, 0x00],
    );
}

/// HLD §3.3 #3 — call rel32 (E8 + 4-byte rel32 slot).
#[test]
fn hld_ex3_call_rel32() {
    let r = enc::encode_x64(enc::Op::Call, &[enc::builders::rel32()]).unwrap();
    assert_eq!(r.bytes, vec![0xE8, 0, 0, 0, 0]);
    assert_eq!(r.riprel_at, Some(1));
}

/// HLD §3.3 #4 — lea rax, [rip+disp32].
#[test]
fn hld_ex4_lea_riprel() {
    let r = enc::encode_x64(
        enc::Op::Lea,
        &[
            enc::builders::reg64(enc::RegId::Rax),
            enc::builders::riprel(),
        ],
    )
    .unwrap();
    assert_eq!(r.bytes, vec![0x48, 0x8D, 0x05, 0, 0, 0, 0]);
    assert_eq!(r.riprel_at, Some(3));
}

/// HLD §3.3 #5 — ret.
#[test]
fn hld_ex5_ret() {
    assert_bytes(enc::Op::Ret, &[], &[0xC3]);
}

// Additional mnemonic coverage (10+ rows per the brief).

#[test]
fn mov_r64_to_mem_rbp_disp32() {
    assert_bytes(
        enc::Op::Mov,
        &[
            enc::builders::mem64(enc::RegId::Rbp, -8, enc::DispKind::Disp32),
            enc::builders::reg64(enc::RegId::Rax),
        ],
        &[0x48, 0x89, 0x85, 0xF8, 0xFF, 0xFF, 0xFF],
    );
}

#[test]
fn xor_rax_rax_zero_idiom() {
    assert_bytes(
        enc::Op::Xor,
        &[
            enc::builders::reg64(enc::RegId::Rax),
            enc::builders::reg64(enc::RegId::Rax),
        ],
        &[0x48, 0x31, 0xC0],
    );
}

#[test]
fn xor_edx_edx_clear_high_remainder() {
    assert_bytes(
        enc::Op::Xor,
        &[
            enc::builders::reg32(enc::RegId::Rdx),
            enc::builders::reg32(enc::RegId::Rdx),
        ],
        &[0x31, 0xD2],
    );
}

#[test]
fn test_rax_rax_zero_check() {
    assert_bytes(
        enc::Op::Test,
        &[
            enc::builders::reg64(enc::RegId::Rax),
            enc::builders::reg64(enc::RegId::Rax),
        ],
        &[0x48, 0x85, 0xC0],
    );
}

#[test]
fn movsxd_rax_eax_sign_extend() {
    assert_bytes(
        enc::Op::Movsxd,
        &[
            enc::builders::reg64(enc::RegId::Rax),
            enc::builders::reg32(enc::RegId::Rax),
        ],
        &[0x48, 0x63, 0xC0],
    );
}

#[test]
fn movsd_xmm0_from_rbp_disp32() {
    let r = enc::encode_x64(
        enc::Op::Movsd,
        &[
            enc::builders::xmm(enc::RegId::Xmm0),
            enc::builders::mem64(enc::RegId::Rbp, -8, enc::DispKind::Disp32),
        ],
    )
    .unwrap();
    assert_eq!(r.bytes[..4], [0xF2, 0x0F, 0x10, 0x85]);
}

#[test]
fn addsd_xmm0_xmm1_canonical() {
    assert_bytes(
        enc::Op::Addsd,
        &[
            enc::builders::xmm(enc::RegId::Xmm0),
            enc::builders::xmm(enc::RegId::Xmm1),
        ],
        &[0xF2, 0x0F, 0x58, 0xC1],
    );
}

#[test]
fn ucomisd_xmm0_xmm1_uses_66_prefix() {
    assert_bytes(
        enc::Op::Ucomisd,
        &[
            enc::builders::xmm(enc::RegId::Xmm0),
            enc::builders::xmm(enc::RegId::Xmm1),
        ],
        &[0x66, 0x0F, 0x2E, 0xC1],
    );
}

#[test]
fn xorpd_xmm0_xmm0_load_zero() {
    assert_bytes(
        enc::Op::Xorpd,
        &[
            enc::builders::xmm(enc::RegId::Xmm0),
            enc::builders::xmm(enc::RegId::Xmm0),
        ],
        &[0x66, 0x0F, 0x57, 0xC0],
    );
}

#[test]
fn cvtsi2sd_xmm0_rax_needs_rex_w() {
    assert_bytes(
        enc::Op::Cvtsi2sd,
        &[
            enc::builders::xmm(enc::RegId::Xmm0),
            enc::builders::reg64(enc::RegId::Rax),
        ],
        &[0xF2, 0x48, 0x0F, 0x2A, 0xC0],
    );
}

#[test]
fn push_rbp_prologue_first_byte() {
    assert_bytes(
        enc::Op::Push,
        &[enc::builders::reg64(enc::RegId::Rbp)],
        &[0x55],
    );
}

#[test]
fn pop_rbp_epilogue() {
    assert_bytes(
        enc::Op::Pop,
        &[enc::builders::reg64(enc::RegId::Rbp)],
        &[0x5D],
    );
}

#[test]
fn leave_ret_pair_canonical_epilogue() {
    assert_bytes(enc::Op::LeaveRet, &[], &[0xC9, 0xC3]);
}

#[test]
fn ud2_unreachable_trap() {
    assert_bytes(enc::Op::Ud2, &[], &[0x0F, 0x0B]);
}

#[test]
fn call_rax_indirect() {
    assert_bytes(
        enc::Op::CallReg,
        &[enc::builders::reg64(enc::RegId::Rax)],
        &[0xFF, 0xD0],
    );
}

#[test]
fn jmp_rel32_zero_slot() {
    let r = enc::encode_x64(enc::Op::Jmp, &[enc::builders::rel32()]).unwrap();
    assert_eq!(r.bytes, vec![0xE9, 0, 0, 0, 0]);
    assert_eq!(r.riprel_at, Some(1));
}

#[test]
fn lea_r9_rax_disp8_io_helper_shape() {
    assert_bytes(
        enc::Op::Lea,
        &[
            enc::builders::reg64(enc::RegId::R9),
            enc::builders::mem64(enc::RegId::Rax, 0x08, enc::DispKind::Disp8),
        ],
        &[0x4C, 0x8D, 0x48, 0x08],
    );
}

#[test]
fn mov_r9_uses_rex_r_extension() {
    let r = enc::encode_x64(
        enc::Op::Mov,
        &[
            enc::builders::reg64(enc::RegId::R9),
            enc::builders::mem64(enc::RegId::Rbp, -8, enc::DispKind::Disp32),
        ],
    )
    .unwrap();
    assert_eq!(r.bytes[..3], [0x4C, 0x8B, 0x8D]);
}

#[test]
fn mov_rax_from_rsp_emits_sib() {
    assert_bytes(
        enc::Op::Mov,
        &[
            enc::builders::reg64(enc::RegId::Rax),
            enc::builders::mem64(enc::RegId::Rsp, 0x20, enc::DispKind::Disp32),
        ],
        &[0x48, 0x8B, 0x84, 0x24, 0x20, 0x00, 0x00, 0x00],
    );
}
