# MDBCC-REQ-ANVIL-00072 — Stateless virtual mixins laid out as duplicated plain bases diverge from bcc32 shared-vbase layout

- **State:** Draft
- **Priority:** Should
- **Area:** OWL runtime & 64-bit port
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Decide and document the conformance boundary — either lay all virtual bases (including stateless mixins) with shared-vbase semantics matching bcc32, or prove with a test that OWL never relies on cross-path mixin-pointer identity for `TEventHandler`/`TStreamableBase` so the divergence is provably benign.

## Rationale
A vptr-only virtual base with no data members (`TEventHandler`/`TStreamableBase`) is treated as non-data-bearing and laid out as one plain subobject per inheritance path, yielding duplicate dataless subobjects on re-inheritance instead of one shared copy. Object size, subobject offsets, and mixin-pointer identity then differ from bcc32; virtual dispatch still reaches the right override (Stage-2 secondary vtables), so the divergence only bites if OWL compares mixin pointers across paths (e.g. `(GENERIC*)this` casts in response tables) — which is unproven.

- **Current:** Stateless virtual mixins materialize as one plain subobject per path with distinct addresses where bcc32 shares one; pointer-equality and `(GENERIC*)this`-style casts in OWL response tables can observe a different subobject than bcc32 would.
- **Expected (BCC 4.52):** bcc32 gives a `virtual` base a single shared subobject regardless of data-bearing, with vbptr-based access and one canonical subobject address per most-derived object.
- **Blocks:** Interacts with OWL-01 (MFP this-adjustment depends on exact subobject layout); a candidate (unproven) contributor to dispatch/heap-corruption gaps. Blocks confident S7 ABI parity.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OWL-06** — severity medium, type spec-conformance, effort L, status new.

- **Evidence:** `src/parser.rs:1460-1479` (`vbase_is_data_bearing` treats vptr-only mixins as non-data-bearing), `:1871-1884` (laid as plain base; comment `:1878-1880` flags possible mixin-pointer identity divergence), routing at `:1830` vs layout gate at `:1888` (`subtree_has_data`) being two predicates; `(GENERIC*)this` casts in `EVENTHAN.H:138,148,159,171`; OWL reliance at `window.h:152-153`.
- **Proposed acceptance oracle (set at Gate 1):** A test comparing the address of the `TEventHandler`/`TStreamableBase` subobject reached via two inheritance paths of a `TWindow`-derived object against the bcc32 layout expectation (or an assertion that OWL's dispatch never compares them); `sizeof`/`offsetof` for a representative OWL window match the bcc32 oracle.
