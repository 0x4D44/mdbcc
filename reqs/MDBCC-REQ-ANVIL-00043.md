# MDBCC-REQ-ANVIL-00043 — Section relocation count truncated to `u16`, no `IMAGE_SCN_LNK_NRELOC_OVFL`

- **State:** Draft
- **Priority:** Must
- **Area:** Object format (COFF)
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Object emission MUST either (a) implement the `IMAGE_SCN_LNK_NRELOC_OVFL` extended-relocation form on both write and read when a section has ≥ 65535 relocations, or (b) fail with a clean typed `CodegenError`/`CoffError` naming the section and count. Silent truncation MUST NOT occur. The minimal correct fix is option (b): a typed error when `relocs.len() >= 0xFFFF`.

## Rationale
A section with more than 65535 relocations writes `(N mod 65536)` into `NumberOfRelocations` with no bound check, no overflow flag, and no diagnostic; the overflow relocations sit in the file but are never read back or applied, producing a silently miscompiled binary.

- **Current:** Both writer and aux mirror truncate via `as u16`; the reader has no extended-count path. mdbcc emits one monolithic `.text` per TU, so every call/data ref in a TU accumulates into a single section's reloc `Vec`, making >65535-in-one-section reachable on a large OWL/RTL TU.
- **Expected (BCC 4.52):** Per PE/COFF, when a section has ≥ 0xFFFF relocations the emitter sets `IMAGE_SCN_LNK_NRELOC_OVFL` in the section `Characteristics`, writes 0xFFFF in `NumberOfRelocations`, and stores the true 32-bit count in the `VirtualAddress` field of the first (synthetic) relocation record; MS/Borland toolchains and lld all honor this.
- **Blocks:** S5/S6 — building large OWL/RTL TUs where a single section may exceed 65535 relocations; any future link.exe/lld interop on such objects.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OBJ-01** — severity high, type bug, effort M, status new.

- **Evidence:** `C:\language\mdbcc\src\coff.rs:921` (`write_u16(&mut out, sec.relocs.len() as u16)`); aux mirror truncates identically at `C:\language\mdbcc\src\codegen\object.rs:1178` (`*num_relocs = sec.relocs.len() as u16`); the reader takes the bare `u16` at `C:\language\mdbcc\src\coff.rs:1108` and loops `for r in 0..num_relocs` at `C:\language\mdbcc\src\coff.rs:1120` with no overflow awareness. No test exercises >65535 relocs.
- **Proposed acceptance oracle (set at Gate 1):** A unit test builds a `Section` with 70000 relocations and round-trips it through `Object::write`/`Object::read`, recovering all 70000 relocs (NRELOC_OVFL path) OR `Object::write` returns a typed error; assert the `u16` slot is 0xFFFF and the first reloc's `VirtualAddress` holds the true count.
