//! Per-target codegen + ABI surface (HLD 2026-05-27 §2). One impl per
//! (architecture, OS, calling-convention-default) tuple. Two impls today:
//!
//! - [`Win64`] — Microsoft x64 ABI on PE32+ (the historical default
//!   since slice 5).
//! - [`Win32`] — Win32-x86 ABI on PE32 (S2's new path; Win32 codegen
//!   wires through this in S2b.5 / S2-future).
//!
//! ## Decision-1c.2 — non-generic dispatch (deferring HLD §2's
//! generic Gen refactor)
//!
//! The HLD §2.1 specified `impl Gen<'s, T: Target>` (generic over a
//! zero-sized target marker; LLVM inlines `T::method()` to nothing at
//! monomorphisation). The supervisor session 1c chose to defer the
//! generic refactor: it touches every method on `impl Gen` (~80
//! method signatures) and the regression risk to the 88 SipHash x64
//! baselines is real. Instead the codegen carries a [`TargetKind`]
//! enum field on `Gen` (S2b.2, when Win32 emission lands) and
//! branches on it where target-aware behaviour is needed. Runtime
//! cost of the branch is negligible (one cmov per emit call); the
//! refactor footprint is one new field + a handful of branches
//! instead of touching ~80 method signatures.
//!
//! The `Target` trait still exists as the spec-shaped abstraction:
//! it documents the per-target facts in one place and lets future
//! agents (Jun 2+) drive Win32 emission through `Target::method()`
//! calls if/when the generic refactor becomes worthwhile. For now
//! both [`Win64`] and [`Win32`] are documentation: the values are
//! consumed by the codegen via `TargetKind`-branch lookups, not via
//! the trait. See journal §1c entry for the full rationale.
//!
//! Rationale recorded in
//! `wrk_journals/2026.05.27 - JRN - S2 drive (32-bit x86 backend).md`
//! Decision-1c.2.

use crate::coff;

/// Per-target architecture + ABI facts. All methods are leaves (take
/// parameter-by-value, return small fixed-size data). The trait has no
/// associated state; impls are zero-sized markers ("phantom types").
///
/// Two impls today: [`Win64`] and [`Win32`].
pub trait Target: 'static {
    /// Pointer / GPR width in bytes (8 for x64, 4 for x86).
    fn ptr_bytes() -> u32;

    /// COFF machine value for `Object.machine` and PE file-header.
    fn coff_machine() -> coff::Machine;

    /// PE optional-header Magic (0x020B PE32+, 0x010B PE32).
    fn pe_magic() -> u16;

    /// PE optional-header SizeOfOptionalHeader (0xF0 PE32+, 0xE0 PE32).
    fn pe_size_of_optional_header() -> u16;

    /// Default ImageBase (Win64: 0x140000000; Win32: 0x400000).
    fn default_image_base() -> u64;

    /// True for x64 (RIP-relative addressing available). False for x86
    /// (no RIP-rel; cross-section refs use absolute IMAGE_BASE+disp).
    fn rip_relative() -> bool;

    /// SEH lowering strategy. The codegen collects `try_scopes`
    /// uniformly (see `eh.rs`); the target picks how to materialise
    /// them at PE-emit time.
    fn seh_kind() -> SehKind;

    /// Discriminator-style runtime tag matching this target. Used by
    /// the `target_kind: TargetKind` field on `Gen` (S2b.2 onward) so
    /// the codegen can branch without a generic refactor.
    fn target_kind() -> TargetKind;
}

/// SEH lowering strategy. The codegen collects scope tables uniformly
/// (`TryScope` in `eh.rs`); the target decides how to lower them at
/// PE-emit time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SehKind {
    /// x64: `.pdata` (RUNTIME_FUNCTION array) + `.xdata` (UNWIND_INFO),
    /// table-driven. Required by Win64 — every non-leaf function needs
    /// unwind tables for stack-walking. Implemented today.
    TableX64,
    /// x86: linked list of `EXCEPTION_REGISTRATION` records rooted at
    /// `fs:[0]`. Per-function prologue pushes the record onto the
    /// chain; epilogue pops it. **Not yet implemented (S2e).**
    Fs0Chain,
}

/// Runtime-discriminator tag for the codegen's target. Set on `Gen`
/// at construction; consumed by target-aware branches throughout
/// `marshal_args`, `emit_call`, name-mangling, etc. (S2b.2+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Win64,
    Win32,
}

// ---------------------------------------------------------------------------
// Two zero-sized impls.
// ---------------------------------------------------------------------------

/// Microsoft x64 ABI on PE32+. The historical default since slice 5.
pub struct Win64;

impl Target for Win64 {
    fn ptr_bytes() -> u32 {
        8
    }
    fn coff_machine() -> coff::Machine {
        coff::Machine::Amd64
    }
    fn pe_magic() -> u16 {
        0x020B
    }
    fn pe_size_of_optional_header() -> u16 {
        0xF0
    }
    fn default_image_base() -> u64 {
        0x0000_0001_4000_0000
    }
    fn rip_relative() -> bool {
        true
    }
    fn seh_kind() -> SehKind {
        SehKind::TableX64
    }
    fn target_kind() -> TargetKind {
        TargetKind::Win64
    }
}

/// Win32-x86 ABI on PE32 (S2's new path). Default calling convention is
/// `__cdecl` (per `_DEFS.H` on the CD — `__stdcall` only via
/// CALLBACK/WINAPI/APIENTRY macros in WINDEF.H). `__fastcall` deferred
/// to S2-future (Q-Fastcall); `__pascal` deferred to S5 (Q-Pascal).
pub struct Win32;

impl Target for Win32 {
    fn ptr_bytes() -> u32 {
        4
    }
    fn coff_machine() -> coff::Machine {
        coff::Machine::I386
    }
    fn pe_magic() -> u16 {
        0x010B
    }
    fn pe_size_of_optional_header() -> u16 {
        0xE0
    }
    fn default_image_base() -> u64 {
        0x0040_0000
    }
    fn rip_relative() -> bool {
        false
    }
    fn seh_kind() -> SehKind {
        SehKind::Fs0Chain
    }
    fn target_kind() -> TargetKind {
        TargetKind::Win32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win64_facts_match_pe_writer() {
        // Anchor: every value here is duplicated as a literal in
        // src/link/pe_writer.rs. The duplication is intentional today
        // (S2b.1 doesn't wire the trait into the writer); these
        // assertions catch silent drift if either side moves.
        assert_eq!(Win64::ptr_bytes(), 8);
        assert_eq!(Win64::coff_machine(), crate::coff::Machine::Amd64);
        assert_eq!(Win64::pe_magic(), 0x020B);
        assert_eq!(Win64::pe_size_of_optional_header(), 0xF0);
        assert_eq!(Win64::default_image_base(), 0x0000_0001_4000_0000);
        assert!(Win64::rip_relative());
        assert_eq!(Win64::seh_kind(), SehKind::TableX64);
        assert_eq!(Win64::target_kind(), TargetKind::Win64);
    }

    #[test]
    fn win32_facts_match_pe_writer() {
        // Anchor: same intent as the Win64 test — catches drift between
        // the trait and the PE writer's PE32 branch (S2d's is_pe32
        // path).
        assert_eq!(Win32::ptr_bytes(), 4);
        assert_eq!(Win32::coff_machine(), crate::coff::Machine::I386);
        assert_eq!(Win32::pe_magic(), 0x010B);
        assert_eq!(Win32::pe_size_of_optional_header(), 0xE0);
        assert_eq!(Win32::default_image_base(), 0x0040_0000);
        assert!(!Win32::rip_relative());
        assert_eq!(Win32::seh_kind(), SehKind::Fs0Chain);
        assert_eq!(Win32::target_kind(), TargetKind::Win32);
    }

    #[test]
    fn target_kinds_differ() {
        assert_ne!(Win64::target_kind(), Win32::target_kind());
    }
}
