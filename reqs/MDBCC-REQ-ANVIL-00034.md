# MDBCC-REQ-ANVIL-00034 — Struct-return classification uses the Win64 size rule on i386 (target-agnostic `effective_struct_abi`)

- **State:** Draft
- **Priority:** Must
- **Area:** Calling conventions & ABI
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Make struct-return/by-value classification target-aware (add an i386 classifier or a `TargetKind` parameter to `effective_struct_abi`) whose size partition — including a deliberate decision on the size-8 case (adopt bcc32's hidden-pointer rule or document EDX:EAX as an intentional internal ABI) — and register placement are validated against bcc32 EXAMPLES/oracle output, so future divergence (3-byte handling, copy-ctor rules) cannot silently track the Win64 rule.

## Rationale
`effective_struct_abi` calls `classify_struct_for_win64(ty.size())` (the Microsoft x64 1/2/4/8→InReg rule) with no `TargetKind` parameter and drives struct-return for both targets; the copy-ctor→HiddenPtr override is target-agnostic too. The existing i386 struct-return tests are self-consistent round-trips, not oracle-validated differential tests.

- **Current:** i386 struct return reuses the Win64 size partition (1/2/4/8 → register, else hidden sret). Critically this is **not** merely "accidentally correct": at size 8 the bcc32 oracle `DIV.ASM` returns `div_t`/`ldiv_t` via a hidden caller-allocated pointer, whereas mdbcc returns 8-byte structs in EDX:EAX — a silent ABI divergence at the mdbcc↔prebuilt-bcc32 boundary. When mdbcc rebuilds both sides from source it is self-consistent.
- **Expected (BCC 4.52):** bcc32 i386 returns POD structs of size 1/2 in AL/AX, 4 in EAX; the 8-byte case follows the bcc32 oracle (hidden pointer per `DIV.ASM`); everything else via a hidden caller-allocated pointer; classes with a non-trivial copy ctor always via hidden pointer. The rule must be expressed as the i386 rule and validated against the bcc32 oracle, not inherited from the Win64 classifier.
- **Blocks:** Confidence in i386 struct-return ABI parity and any mdbcc↔prebuilt-bcc32 interop that returns 8-byte structs (div/ldiv); clean separation needed before any i386 ABI tuning the Win64 rule would mask.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **ABI-03** — severity high, type incomplete, effort M, status new.

- **Evidence:** `src/codegen.rs:787`–`796`; `classify_struct_for_win64` at `src/codegen/abi.rs:133`–`138` (documented "Win64 ABI" at `abi.rs:1`,`:115`–`121`); use at `src/codegen.rs:3042`–`3048`; copy-ctor override at `src/codegen.rs:789`–`794`; 8-byte EDX:EAX return at `src/codegen.rs:9300`–`9305`.
- **Proposed acceptance oracle (set at Gate 1):** A differential test returns small/medium structs (sizes 1..16, with and without a copy ctor) from i386 functions and checks the bytes against a bcc32 reference (or an asserted oracle), independent of the Win64 classifier.
