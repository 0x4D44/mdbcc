# MDBCC-REQ-ANVIL-00098 — Dead-strip BFS rescans the whole section reloc list per unit

- **State:** Draft
- **Priority:** Could
- **Area:** Performance
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Pre-bucket each section's relocs by unit index (using the existing sorted `starts` table) once, so the BFS reads only a unit's own relocs; the reachable-unit set and dead-reloc set must be identical to today.

## Rationale
The dead-strip reachability walk re-iterates a section's entire reloc vector for every reachable code unit, filtering by the unit's offset window, giving O(U × R) per section instead of visiting each reloc O(1) times.

- **Current:** For a section holding U units (functions) and R relocs the walk is O(U × R); mdbcc archives are usually one-function-per-member so this is rarely hit today, but a section packing many functions (a concatenated/partial archive or a future bulk-emitted object) makes it quadratic.
- **Expected (BCC 4.52):** Dead-strip should visit each reloc O(1) times; relocs sorted by offset (or pre-bucketed per unit via the existing sorted `starts` partition) let each unit slice its relocs in O(log R + own-relocs).
- **Blocks:** Linking objects/archive members with many functions per section at scale (S5–S7).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PERF-04** — severity low, type perf, effort M, status sharpens-parked.

- **Evidence:** `src/link/pe_writer.rs:4336` (`while let Some((oi, si, ui)) = work.pop()`) then `src/link/pe_writer.rs:4339` (`for r in &objects[oi].sections[si].relocs { if r.offset < start || r.offset >= end { continue; }`); `unit_of` is correctly binary-search (`src/link/pe_writer.rs:4285-4289`) but the per-unit reloc sweep is not bucketed.
- **Proposed acceptance oracle (set at Gate 1):** A test object with one section containing many units and many relocs dead-strips in roughly linear time; the resulting `reachable`/`dead` sets and final PE bytes are byte-identical to the current implementation on all existing link tests.
