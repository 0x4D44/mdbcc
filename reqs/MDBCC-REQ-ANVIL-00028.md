# MDBCC-REQ-ANVIL-00028 — i386 FP return convention is SSE (xmm0), not x87 (ST(0)) — not ABI-compatible with stock bcc32

- **State:** Draft
- **Priority:** Should
- **Area:** Code generation — i386
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Document and enforce the all-from-source invariant for the FP-return convention specifically: any i386 link that mixes an mdbcc object with a prebuilt-bcc32 FP-returning object must be diagnosed (or bridged ST(0)↔xmm0 at the extern boundary). Add a guard/test asserting the FP-return convention so a future mixed-link regression fails loudly.

## Rationale
i386 FP is lowered to SSE2 and `float`/`double` is returned in xmm0, whereas bcc32 returns in ST(0); linking an mdbcc object against an unrecompiled bcc32 FP-returning `.OBJ`/`.LIB` silently reads garbage. (FP arguments already match: they are stack-pushed, like bcc32 cdecl.)

- **Current:** A `double`-returning mdbcc function returns in xmm0; self-consistent when RTL/OWL are recompiled by mdbcc, but a mixed link against a stock-bcc32 FP-returning object yields garbage with no diagnostic.
- **Expected (BCC 4.52):** The i386 ABI returns `float`/`double` in ST(0); an mdbcc object linked with a bcc32 object must agree on the FP return convention.
- **Blocks:** Any i386 path that must link against unmodified bcc32 LIB/OBJ (boundary cases in S5/S6 if not everything is recompiled).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **C32-04** — severity medium, type abi, effort L, status sharpens-parked.

- **Evidence:** SSE lowering at `C:\language\mdbcc\src\codegen.rs:11949-11958` (load), `:12040-12046` (store), `:11476+` (arithmetic), `:5236-5239` (FP return in xmm0), `:12189-12217` (float↔int); FP args stack-pushed at `C:\language\mdbcc\src\codegen.rs:14639-14643`; the only x87 emitted is the `fldcw`/`fnstcw` control-word shim at `C:\language\mdbcc\src\codegen.rs:13589`; byte-identity stripe pins mdbcc's own output, not equality with bcc32 (`C:\language\mdbcc\tests\o1_x86_byte_identity.rs:30-31,196`).
- **Proposed acceptance oracle (set at Gate 1):** A documented invariant plus a test that detects an mdbcc i386 object declaring an extern FP-returning bcc32 symbol and either bridges ST(0)↔xmm0 or errors; no silent garbage-FP return path remains.
