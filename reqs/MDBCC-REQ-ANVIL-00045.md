# MDBCC-REQ-ANVIL-00045 — COMDAT `SectionDef` checksum hard-coded to zero

- **State:** Draft
- **Priority:** Could
- **Area:** Object format (COFF)
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
IF/WHEN COMDAT sections are emitted (see OBJ-02), the `SectionDef` `CheckSum` MUST be the CRC-32 of the section data so SameSize/ExactMatch selections are sound; until then, mdbcc MUST document that it folds by name-Any-equivalence only and that `CheckSum` is intentionally zero.

## Rationale
Every section-definition aux record carries `CheckSum = 0`; no CRC-32-of-section-data is ever computed, so any COMDAT selection mode that depends on the checksum (SameSize/ExactMatch) cannot be honored correctly.

- **Current:** All `SectionDef` aux records carry `CheckSum=0`. mdlink's name-equivalence fold ignores it, so it is presently inert and harmless; codegen never constructs a `Comdat` with `selection: Some(...)`, so no SameSize/ExactMatch aux is ever emitted.
- **Expected (BCC 4.52):** MS/Borland COFF store a CRC-32 of the section's raw data in the COMDAT section-symbol `CheckSum`, which the linker uses to validate `IMAGE_COMDAT_SELECT_SAME_SIZE`/`EXACT_MATCH` folds (a mismatch is a hard error).
- **Blocks:** Faithful COMDAT SameSize/ExactMatch selection — subsumed by OBJ-02; no independent mission impact.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OBJ-03** — severity low, type incomplete, effort S, status new.

- **Evidence:** `C:\language\mdbcc\src\codegen\object.rs:521` (`checksum: 0`); also `C:\language\mdbcc\src\link\crt.rs:135,169,193`; the encoder writes it verbatim at `C:\language\mdbcc\src\coff.rs:1027`. No CRC-32 exists in the codebase.
- **Proposed acceptance oracle (set at Gate 1):** Either a CRC-32 is computed and a SameSize/ExactMatch round-trip test passes, or a documented note ties `checksum=0` to the name-fold-only convention (OBJ-02).
