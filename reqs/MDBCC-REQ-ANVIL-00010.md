# MDBCC-REQ-ANVIL-00010 — Bit-fields carry no width: every named bit-field becomes a full-width member

- **State:** Draft
- **Priority:** Must
- **Area:** Parser — C language
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Represent bit-fields in the AST (add bit-width + bit-offset to `Field`, or a dedicated bit-field member kind) and implement bcc32-compatible packing in `layout()`: allocate within the base storage unit, start a new unit on `:0` or on unit overflow, and account unnamed `:w` fields as padding.

## Rationale
`Field` has no bit-width representation, so each named bit-field is laid out as an ordinary full-width member and anonymous/`:0`/padding bit-fields are dropped entirely; `sizeof` and every offset after a bit-field are wrong.

- **Current:** Each `T name : w` becomes a full-width `T` member at its own slot; anonymous bit-fields (`:0` alignment markers, unnamed `:w` padding) are dropped. `_LDT_ENTRY`-style structs are ~8x oversized and post-bit-field offsets are wrong.
- **Expected (BCC 4.52):** bcc32 packs bit-fields into the base type's storage units, honours `unsigned x:0` as "align to next unit", and counts unnamed `:w` as consumed-but-unnamed padding; `sizeof` and offsets must match bcc32 exactly.
- **Blocks:** Byte-accurate Win32 SDK / WINNT struct ABI (S3/S6); any RTL or OWL struct using bit-fields across the Win32 ABI; struct byte-identity oracles.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PSC-01** — severity high, type abi, effort L, status sharpens-parked.

- **Evidence:** `src/ast.rs:232` (`struct Field { name, ty, offset }` — no bit-width); `src/parser.rs:2567-2582` (width bound to `_width` and discarded; anonymous bit-field pushes no field); in-repo test `src/parser.rs:10200-10214`; oracle `wrk_oracle/bc452/BC45/INCLUDE/WINNT.H:1369-1376` (`_LDT_ENTRY`).
- **Proposed acceptance oracle (set at Gate 1):** A test compiles `struct B { unsigned a:3; unsigned :2; unsigned b:1; int :0; unsigned c:1; };` and asserts `sizeof` and the bit/byte offsets of `a`, `b`, `c` match the bcc32 reference; `sizeof(_LDT_ENTRY) == 8`.
