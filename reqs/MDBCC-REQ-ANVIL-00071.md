# MDBCC-REQ-ANVIL-00071 — OWL library build silently drops translation units that fail to compile

- **State:** Draft
- **Priority:** Should
- **Area:** OWL runtime & 64-bit port
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
`build_bc45_libs` must record per-unit compile outcomes against an explicit expected-shippable set (at minimum the units the gated OWL samples need) and fail or clearly diagnose when a required unit is dropped, rather than silently emitting a partial `mdowl.lib`.

## Rationale
Every OWL build job is marked `required: false` and the main loop only prints an `ok=N skip=M` tally, never failing on skips. If a needed unit (GAUGE/SLIDER/COMBOBOX or a dependency such as CONTROL/COLOR/DC) fails to compile, its object is silently omitted from `mdowl.lib`, resurfacing later as an opaque linker unresolved-symbol error in the consuming app.

- **Current:** A failed OWL unit is dropped from `mdowl.lib` with the only signal a higher `skip=` count buried in build output; the failure resurfaces as a (clean but misleading) link-time unresolved-symbol error downstream.
- **Expected (BCC 4.52):** A from-source OWL build should know which units it intends to ship and fail loudly (or quarantine via an explicit allowlist) when a needed unit does not compile, so a compile regression is diagnosed at the library build rather than deferred to an app link.
- **Blocks:** Diagnosability of every OWL compile regression — directly the GAUGE/LISTBOX/COMBOBOX/SLIDER link-phase gaps. Blocks S5 generality and trustworthy S6 triage.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OWL-05** — severity medium, type incomplete, effort M, status new.

- **Evidence:** `src/bin/build_bc45_libs.rs:387-419` (OWL jobs `required: false`, `:417,:434`), `:322-330` (`ok/skip` print, no fail-on-skip), `:361-368` (only required units accumulate failures), `:332` (`archive()` runs unconditionally), comment `:384-386`; no test pins an OWL unit count; `tests/owl_examples_product.rs:140-183` records GAUGE/LISTBOX/COMBOBOX/SLIDER as Link-phase KnownGap; prior recurrence in F-30 (DIB.CPP).
- **Proposed acceptance oracle (set at Gate 1):** Building the Win64 libs with a deliberately-broken OWL unit fails the build (or emits a named, asserted-on diagnostic) instead of producing a lib that links with a downstream unresolved symbol; a test pins the set of OWL units expected to compile for the gated samples.
