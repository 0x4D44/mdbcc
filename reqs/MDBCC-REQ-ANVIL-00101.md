# MDBCC-REQ-ANVIL-00101 — codegen.rs is a 20.4k-LOC god-file; the S1a split stalled

- **State:** Draft
- **Priority:** Should
- **Area:** Maintainability / tech-debt
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Continue the S1a split: move cohesive subsystems out of codegen.rs into existing/new submodules behind the same `Codegen` impl (EH lowering, libc intrinsics, float formatting, new/delete) until no single file exceeds ~5k LOC, preserving byte-identity baselines at each step.

## Rationale
Almost the entire backend (expression/statement lowering, the per-function driver, EH, new/delete, libc intrinsics, float formatting, type re-derivation, struct ABI classification) lives in one 20,423-LOC / ~1MB file the S1a plan said should be split. The split produced only thin satellites; the core never moved.

- **Current:** A single editor/agent cannot hold the file in context; every codegen change re-reads or risks ~1MB of unrelated code.
- **Expected (BCC 4.52):** BCC 4.52 imposes no file layout; this is an internal requirement — the S1a plan called for codegen to be decomposed into cohesive modules (expr/stmt/eh/abi/intrinsics), each independently readable and testable.
- **Blocks:** none (a real velocity drag on S6/S7 backend work, but not blocking — recent features F-23..F-30 all landed inside the monolith); file as a parked tech-debt item.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DEBT-01** — severity medium, type tech-debt, effort XL, status sharpens-parked.

- **Evidence:** `src/codegen.rs` is 20,423 lines / 1,004,555 bytes with 274 `fn` definitions; one `impl<'s> Gen<'s>` block alone holds 247 of them across ~17.4k LOC (the `^impl ` count of 4 misses this block because `<` defeats the trailing-space regex). Satellites: `src/codegen/{abi.rs:169, decl.rs:258, expr.rs:181, stmt.rs:80, statics.rs:65, target.rs:204, cpp.rs:1006, object.rs:1606, template.rs:863}`.
- **Proposed acceptance oracle (set at Gate 1):** `src/codegen.rs` drops below ~8k LOC; the O1/O2 byte-identity and i386_run suites stay green after each extraction; no new `pub` surface leaks.
