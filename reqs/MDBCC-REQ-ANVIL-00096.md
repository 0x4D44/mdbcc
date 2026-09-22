# MDBCC-REQ-ANVIL-00096 — Linker archive-scan fixpoint full-rescan per pass

- **State:** Draft
- **Priority:** Could
- **Area:** Performance
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Replace the per-pass full rescan with an incremental worklist (compute initial defined/unresolved once, then update both by each pulled member's own symbols) and stop rebuilding the entire object slice each pass; the pulled-member set and order (first-archive-wins) must be identical.

## Rationale
The archive-scan fixpoint recomputes the all-objects unresolved/defined sets and rebuilds the object slice on every pass, giving worst-case O(M²) symbol work over a closure of M pulled members instead of an incremental worklist.

- **Current:** If each pass satisfies one member the loop runs ~M passes, each O(total symbols pulled so far) plus a full slice rebuild; invisible at RailC/two-sample scale — the linker analogue of the codegen O(n²) that G4 fixed.
- **Expected (BCC 4.52):** TLINK32 resolved large RTL/OWL/BIDS closures quickly; a scalable linker keeps an incrementally-updated unresolved worklist (seed once, then on pulling a member add its new undefined externals and drop names it defines) and an indexed defined-set, not a full all-objects rescan per pass.
- **Blocks:** Linking the full OWL/RTL/BIDS archive closure at scale (S5–S7); link-time component of G3 baselines once TU count grows.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PERF-02** — severity low, type perf, effort L, status sharpens-parked.

- **Evidence:** `src/link/mod.rs:408` (`loop {`) each iteration calls `src/link/mod.rs:409` (`build_object_slice`, rebuild at `src/link/mod.rs:529-554`) and `src/link/mod.rs:411` (`collect_unresolved_externals` double-scans every symbol into BTreeSets — `src/link/mod.rs:649-662,667-700`); loop terminates at `src/link/mod.rs:462`; inner pull per-name × per-archive at `src/link/mod.rs:417-418`; `src/link/mod.rs:548` concedes "fine for S1c-scale".
- **Proposed acceptance oracle (set at Gate 1):** A synthetic link with a large multi-member archive (hundreds of members in a deep dependency chain) links in roughly linear time; a trace shows each member's symbols processed O(1) times, not O(passes); `archive_trace` and pulled-member set match the current implementation byte-for-byte on existing link tests.
