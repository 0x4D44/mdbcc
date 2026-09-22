//! Golden regression lock for the **console import path** (Phase C / C1a).
//!
//! C1a introduces `WIN32_IMPORTS` (a single source-of-truth symbol->DLL
//! table), a deterministic used-set scan of the module's `RipRef::Import`s,
//! and widens `RipRef::Import` from `&'static str` to `String`. The
//! non-negotiable contract is that this is a **pure refactor**: the emitted
//! `.idata` and entry stub for every existing (console, KERNEL32-only)
//! program are **byte-identical** to before the change.
//!
//! This test makes that contract *executable* (per the HLD: "locked by a
//! golden test, not just argued"). It pins the exact `.idata` section bytes
//! and the entry stub of two representative console programs against a
//! captured golden. Any future C1b/C2 change that perturbs the console path
//! — a different descriptor count, a reordered/extra/missing import, a
//! shifted IAT, a changed stub — fails here loudly *before* O1's behavioural
//! suite would even run, pinning the central Phase-C invariant.
//!
//! Structural, in-process, no external toolchain (mirrors `tests/pe_layout.rs`).

#![cfg(windows)]

use mdbcc::compile_to_pe;

const PE_OFF: usize = 0x80;
const SIZEOF_OPT: usize = 0xF0;
const SECT_HDR_LEN: usize = 40;

fn parse_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// `(raw_ptr, raw_size, vsize, va)` for the section named `name`, read from
/// the produced image's own section table (cannot be fooled by an optimizer).
fn section(pe: &[u8], name: &[u8]) -> (usize, usize, u32, u32) {
    let coff = PE_OFF + 4;
    let nsec = u16::from_le_bytes([pe[coff + 2], pe[coff + 3]]) as usize;
    let tbl = PE_OFF + 4 + 20 + SIZEOF_OPT;
    for i in 0..nsec {
        let h = tbl + i * SECT_HDR_LEN;
        let mut want = [0u8; 8];
        want[..name.len()].copy_from_slice(name);
        if pe[h..h + 8] == want {
            return (
                parse_u32(pe, h + 20) as usize, // PointerToRawData
                parse_u32(pe, h + 16) as usize, // SizeOfRawData
                parse_u32(pe, h + 8),           // VirtualSize
                parse_u32(pe, h + 12),          // VirtualAddress
            );
        }
    }
    panic!("section {:?} not found", String::from_utf8_lossy(name));
}

/// The raw `.idata` bytes (exactly `VirtualSize`, before file padding).
fn idata_bytes(pe: &[u8]) -> Vec<u8> {
    let (ptr, _raw, vsize, _va) = section(pe, b".idata");
    pe[ptr..ptr + vsize as usize].to_vec()
}

/// The entry stub: `STUB_LEN = 0x12` bytes at the start of `.text`. Its last
/// `call [rip+disp]` targets the `ExitProcess` IAT slot, so this also pins
/// that the stub still resolves through the (unchanged) KERNEL32 IAT.
fn entry_stub(pe: &[u8]) -> Vec<u8> {
    let (ptr, _raw, _vsize, _va) = section(pe, b".text");
    pe[ptr..ptr + 0x12].to_vec()
}

/// A representative console program exercising **both** import-bearing paths:
/// `printf` (GetStdHandle/WriteFile) and `new`/`delete`
/// (GetProcessHeap/HeapAlloc/HeapFree). Its `RipRef::Import` set is the full
/// historical KERNEL32 six; the C1a used-set scan must reproduce the exact
/// historical single-KERNEL32 `.idata`.
const PROG_FULL: &str = r#"
#include <stdio.h>
int main(void) {
    int *p = new int;
    *p = 7;
    printf("v=%d\n", *p);
    delete p;
    return 0;
}
"#;

/// The byte-identical *edge*: a program with **zero** `RipRef::Import`s. The
/// entry stub still calls `ExitProcess`, so KERNEL32 must still be emitted in
/// full — a naive "emit only used symbols" scan would shrink `.idata` here
/// and break every existing program. This case is the one the contract most
/// depends on.
const PROG_BARE: &str = "int main(void){ return 0; }";

// --- GOLDEN (re-blessed 2026-05-22 for Phase H4a) ---
//
// The full `.idata` of a KERNEL32-only console program: one
// IMAGE_IMPORT_DESCRIPTOR + null terminator, one ILT + one IAT of 9 (=8+1)
// by-name thunks (the historical six PLUS the Phase-H4a SEH pair
// `RaiseException` + `RtlUnwindEx`), eight hint/name entries, the
// `KERNEL32.dll\0` string. RVAs are absolute (fixed ImageBase, no relocs)
// and identical for any program whose `.text` fits the historical
// first-page budget (both programs here do — `idata_rva == 0x2000`), so a
// single golden pins both.
//
// Phase H4a added two KERNEL32 symbols (`RaiseException`, `RtlUnwindEx`)
// to `WIN32_IMPORTS`. The per-DLL grouping deliberately does NOT
// per-symbol prune (the documented dormancy-via-aggregation pattern every
// other Phase C/D/E/G import follows), so every KERNEL32-using program
// now imports all eight. The two SEH symbols sit dormant for any program
// that never throws / catches; only the descriptor count, the IAT/ILT
// length, and the two new hint/name entries grow.

#[rustfmt::skip]
const GOLDEN_IDATA: &[u8] = &[
    40, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 44, 33, 0, 0, 112, 32, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 184, 32, 0, 0, 0,
    0, 0, 0, 198, 32, 0, 0, 0, 0, 0, 0, 214, 32, 0, 0, 0, 0, 0, 0, 226, 32,
    0, 0, 0, 0, 0, 0, 244, 32, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0,
    12, 33, 0, 0, 0, 0, 0, 0, 30, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 184, 32, 0, 0, 0, 0, 0, 0, 198, 32, 0, 0, 0, 0, 0, 0, 214, 32, 0,
    0, 0, 0, 0, 0, 226, 32, 0, 0, 0, 0, 0, 0, 244, 32, 0, 0, 0, 0, 0, 0, 0,
    33, 0, 0, 0, 0, 0, 0, 12, 33, 0, 0, 0, 0, 0, 0, 30, 33, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 69, 120, 105, 116, 80, 114, 111, 99,
    101, 115, 115, 0, 0, 0, 71, 101, 116, 83, 116, 100, 72, 97, 110, 100,
    108, 101, 0, 0, 0, 0, 87, 114, 105, 116, 101, 70, 105, 108, 101, 0, 0,
    0, 71, 101, 116, 80, 114, 111, 99, 101, 115, 115, 72, 101, 97, 112, 0,
    0, 0, 0, 72, 101, 97, 112, 65, 108, 108, 111, 99, 0, 0, 0, 72, 101, 97,
    112, 70, 114, 101, 101, 0, 0, 0, 0, 82, 97, 105, 115, 101, 69, 120, 99,
    101, 112, 116, 105, 111, 110, 0, 0, 0, 0, 82, 116, 108, 85, 110, 119,
    105, 110, 100, 69, 120, 0, 75, 69, 82, 78, 69, 76, 51, 50, 46, 100, 108,
    108, 0,
];

/// The exact entry stub for a first-page program (`text_rva == 0x1000`,
/// `idata_rva == 0x2000`). Phase H4a added two KERNEL32 symbols so the IAT
/// block moved from `0x2060` to `0x2070` (16 bytes for two extra ILT
/// thunks). `ExitProcess`'s IAT slot is still the first IAT entry — now
/// at `0x2070` instead of `0x2060`. The stub's `call [rip+disp]`
/// displacement is therefore `0x2070 - 0x1011 = 0x105F` (was `0x104F`).
/// Every other byte of the stub is identical.
#[rustfmt::skip]
const GOLDEN_STUB: &[u8] = &[
    0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
    0xE8, 0x09, 0x00, 0x00, 0x00,       // call main (rel32 +9: main after stub)
    0x89, 0xC1,                         // mov ecx, eax
    0xFF, 0x15, 0x5F, 0x10, 0x00, 0x00, // call [rip+0x105F] -> 0x2070 ExitProc
    0xF4,                               // hlt
];

#[test]
fn console_idata_is_byte_identical_to_pre_phase_c_golden() {
    // The import-bearing program: the C1a used-set scan + table must
    // reproduce the historical single-KERNEL32 `.idata` exactly.
    let pe = compile_to_pe(PROG_FULL.as_bytes()).expect("compile PROG_FULL");
    let (_, _, _, idata_va) = section(&pe, b".idata");
    assert_eq!(
        idata_va, 0x2000,
        "golden assumes the first-page layout (idata_rva == 0x2000); the \
         representative program no longer fits it"
    );
    assert_eq!(
        idata_bytes(&pe),
        GOLDEN_IDATA,
        "console `.idata` diverged from the pre-Phase-C golden — the C1a \
         used-set scan / WIN32_IMPORTS table is NOT byte-identical for an \
         import-bearing console program (this is the central Phase-C \
         regression this lock exists to catch)"
    );
    assert_eq!(
        entry_stub(&pe),
        GOLDEN_STUB,
        "entry stub diverged from the pre-Phase-C golden (the stub's \
         ExitProcess IAT-slot displacement or length changed)"
    );
}

#[test]
fn bare_program_still_emits_full_kernel32_idata() {
    // ZERO `RipRef::Import`s, yet the stub calls `ExitProcess`: KERNEL32 must
    // still be emitted in full. A naive "only emit used symbols" scan would
    // shrink `.idata` here and silently break every existing program.
    let pe = compile_to_pe(PROG_BARE.as_bytes()).expect("compile PROG_BARE");
    let (_, _, _, idata_va) = section(&pe, b".idata");
    assert_eq!(idata_va, 0x2000, "bare program no longer first-page");
    assert_eq!(
        idata_bytes(&pe),
        GOLDEN_IDATA,
        "a zero-import console program no longer emits the full KERNEL32 \
         `.idata` — the used-set scan must keep KERNEL32 (the stub needs \
         ExitProcess); this is the byte-identical edge the contract most \
         depends on"
    );
    assert_eq!(entry_stub(&pe), GOLDEN_STUB, "bare-program stub diverged");
}

#[test]
fn idata_is_deterministic_across_compiles() {
    // Determinism guard: the used-set scan must never feed HashMap iteration
    // into emitted bytes. Recompiling the same source byte-for-byte twice
    // must yield identical `.idata`.
    let a = idata_bytes(&compile_to_pe(PROG_FULL.as_bytes()).unwrap());
    let b = idata_bytes(&compile_to_pe(PROG_FULL.as_bytes()).unwrap());
    assert_eq!(a, b, "`.idata` is not deterministic across compiles");
}
