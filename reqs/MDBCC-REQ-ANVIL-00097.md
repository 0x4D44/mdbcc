# MDBCC-REQ-ANVIL-00097 — Archive member lookup is a double linear scan per symbol

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
Build a `HashMap<String, usize>` (symbol → member index, first-wins) once in `Archive::read` and make `find_member_for_symbol` an O(1) lookup, preserving first-match-wins for multiply-defined symbols within one archive.

## Rationale
`find_member_for_symbol` does two linear scans (symbol index, then member list) per unresolved name per pass, multiplying PERF-02's cost, instead of an O(1) hash lookup.

- **Current:** Each query is O(symbols + members); inside the O(passes × unresolved) loop this becomes O(passes × unresolved × symbols), compounding PERF-02.
- **Expected (BCC 4.52):** Real librarians/linkers index the archive symbol table into a hash map at load and look up members in O(1); for full OWL/RTL closures the linear sweep is a measurable multiplier.
- **Blocks:** Same closure-scale linking as PERF-02 (S5–S7).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PERF-03** — severity low, type perf, effort S, status sharpens-parked.

- **Evidence:** `src/link/archive.rs:401` (`symbol_index.iter().find_map(...)` — `src/link/archive.rs:402-405`) then `src/link/archive.rs:406` (`members.iter().position(|m| m.offset == target_offset)`); doc-comment `src/link/archive.rs:391-395` accepts the sweep as "acceptable for archives … (≤ a few thousand symbols)"; called once per unresolved name per pass from `src/link/mod.rs:419`.
- **Proposed acceptance oracle (set at Gate 1):** `find_member_for_symbol` is O(1) (a microbench or assertion shows lookup time independent of symbol-index size); existing archive/link tests, including the CRT-staging multiply-defined case at `src/link/archive.rs:397-400`, stay green with identical member selection.
