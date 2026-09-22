# MDBCC-REQ-ANVIL-00044 — Cross-TU dedup uses defined `WeakExternal` symbols without Aux Format 3 instead of COMDAT

- **State:** Draft
- **Priority:** Should
- **Area:** Object format (COFF)
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Object emission SHOULD route cross-TU-foldable definitions into per-symbol COMDAT sections with `IMAGE_SCN_LNK_COMDAT` + a `SectionDef` aux `ComdatSelect`, OR the WeakExternal-without-aux convention MUST be documented as an mdlink-private extension and gated so it is never claimed to be standard COFF. At minimum the divergence MUST be captured as a sharpened parked gap recording the interop blast-radius (no non-mdlink linker can consume mdbcc objects' dedup). Given S8 is beyond the mission, prefer the documented-extension route over committing to COMDAT rework.

## Rationale
Foldable definitions (inline/template/vtable/typeinfo) are emitted as *defined* `WEAK_EXTERNAL` (class 105) symbols pointing at a real section + offset with empty `aux`, which standard COFF rejects — class-105 symbols must be undefined (SectionNumber 0) with one Aux Format 3 weak-external record. Cross-TU folding is by-name only and folded exclusively by mdlink, so no standard linker (link.exe, lld, dumpbin) can consume mdbcc objects' dedup.

- **Current:** A WEAK_EXTERNAL symbol is emitted as defined (section + value) with no auxiliary record; duplicate folding relies on name-equivalence folded only by mdlink. The divergence is described in code comments (`object.rs:545-577`, `663-669`, `696-699`) and the O13 oracle's COMDEF/COMDAT advisory (`oracle_o13_coff_parity.rs:308`), but there is no parked-ledger entry and no invariant test asserting the convention. There is no miscompile within the mdbcc+mdlink pairing — cross-TU fold works and S1c/S5/S7 use mdlink as the intended consumer.
- **Expected (BCC 4.52):** BCC4.52/MS COFF deduplicate inline functions, template instantiations, and vtables via COMDAT sections (`.text$xxx`/`.rdata$xxx` with `IMAGE_SCN_LNK_COMDAT` and a section-symbol Aux Format 5 carrying a `ComdatSelect`, typically Any/SameSize); the defining symbol is a normal External into its own COMDAT section and the linker keeps one copy. Any standard consumer treats class-105-without-aux as malformed.
- **Blocks:** Interop / S8-adjacent — consuming mdbcc objects with any non-mdlink linker; faithful COMDAT-parity vs bcc32 OMF COMDEF/COMDAT (O13 advisory at `oracle_o13_coff_parity.rs:308`).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OBJ-02** — severity medium, type spec-conformance, effort L, status sharpens-parked.

- **Evidence:** `C:\language\mdbcc\src\codegen\object.rs:568-575` (WeakExternal class on a `SectionRef::Section` + offset with `aux: Vec::new()`); same pattern for vtables (`object.rs:675-688`) and typeinfo (`object.rs:705-720`); linker special-case at `C:\language\mdbcc\src\link\mod.rs:644-651`; the implemented-but-unused COMDAT model at `C:\language\mdbcc\src\coff.rs:368-403` and `SectionName::TextComdat` (`coff.rs:279-285`).
- **Proposed acceptance oracle (set at Gate 1):** Either an emitted inline-function object round-trips through a standard COFF validator (or `dumpbin /symbols` shows COMDAT + Aux Format 5); or a documented invariant test asserts mdbcc deliberately emits the non-standard defined-weak form and lists mdlink as the only valid consumer.
