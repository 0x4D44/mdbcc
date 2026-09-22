# MDBCC-REQ-ANVIL-00107 — Stale `#[allow(dead_code)]` on a live function, plus module-wide blanket allows

- **State:** Draft
- **Priority:** Could
- **Area:** Maintainability / tech-debt
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Remove the stale `#[allow(dead_code)]` on `encode_riprel`; for the module-wide `#![allow(dead_code)]` in coff.rs/link/*, add a one-line justification comment naming the reserved items or scope the allow to those items.

## Rationale
An `#[allow(dead_code)]` sits on `encode_riprel`, which is actually called 3 times — so the next reader wrongly assumes it is unused and may delete it; separately, module-wide `#![allow(dead_code)]` blankets suppress the compiler's real dead-code signal across thousands of lines.

- **Current:** Allow-attributes have drifted from reality: one is on a live function, and module-wide blankets hide genuinely unreachable code in coff/link (S1-era WIP parsers with deliberately reserved fields).
- **Expected (BCC 4.52):** Maintainability requirement: `dead_code` allows should be narrow and accurate, or removed so the compiler can flag truly-dead code.
- **Blocks:** none (obscures dead-code accumulation in the linker subsystem as it grows for S6/S7).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DEBT-07** — severity low, type tech-debt, effort S, status new.

- **Evidence:** `src/codegen.rs:4569` has `#[allow(dead_code)]` on `fn encode_riprel` (4570) whose doc-comment (4566) says it "replaces the historical `emit_riprel` pattern" — yet it is called at lines 4596, 18406, 18423. Module-wide blankets at `coff.rs:25`, `link/archive.rs:62`, `link/omf.rs:69`.
- **Proposed acceptance oracle (set at Gate 1):** Removing the `encode_riprel` attribute produces no `cargo build` warning (the fn is used); each remaining allow annotates a specific justified item or carries a comment naming why; no unexplained module-wide blanket.
