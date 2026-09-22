# MDBCC-REQ-ANVIL-00099 — Per-function string and FP-literal interners are linear scans

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
Back both interners with a hash index (`HashMap<Vec<u8>,usize>` for strings, `HashMap<u64,usize>` for FP bits) while keeping the `Vec` for ordered emission; emitted string-pool and `.flit.*` global order must be unchanged.

## Rationale
`intern_string` and `intern_fp_literal` linearly scan all prior literals on every occurrence, costing O(k²) (plus byte-compare length) within a function with k distinct literals, instead of O(1) amortised dedup.

- **Current:** A function with k distinct string/FP literals costs O(k²) to intern; most functions have small k, but a generated/table-building function (large static string array, big switch over many float constants) spikes. Dedup order feeds emitted bytes, so it must stay insertion-ordered.
- **Expected (BCC 4.52):** Interning should be O(1) amortised; a `HashMap<key, index>` alongside the insertion-ordered `Vec` gives O(1) dedup while preserving the deterministic insertion order the emit path depends on.
- **Blocks:** None.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PERF-05** — severity low, type perf, effort S, status new.

- **Evidence:** `src/codegen.rs:4628` (`intern_string` → `self.strings.iter().position(|s| *s == b)`); `src/codegen.rs:4641` (`intern_fp_literal` → `self.fp_literals.iter().position(|b| *b == bits)`); both per-`Gen` (reset per function); order contract documented at `src/codegen.rs:4637-4640`.
- **Proposed acceptance oracle (set at Gate 1):** A unit test compiling a function with thousands of distinct string/FP literals shows interning scaling linearly, not quadratically; the emitted object (string section + flit globals, in order) is byte-identical to current output for all existing codegen baselines.
