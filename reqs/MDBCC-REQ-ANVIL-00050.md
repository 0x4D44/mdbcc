# MDBCC-REQ-ANVIL-00050 — Dead-strip suppresses dead unresolved refs but still emits the dead bytes

- **State:** Draft
- **Priority:** Could
- **Area:** Linker / archives / CRT
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Extend the dead-strip to exclude unreachable units' bytes from section placement (not just their relocations), so the output image omits dead archive-member code/data; gate so all-explicit links (empty dead set) stay byte-identical.

## Rationale
The function-level GC is a pure resolution analysis: it lets a dead archive-member unit reference an undefined symbol without failing the link, but the dead unit's code/data is still placed into `.text`/`.rdata`. Image size and section contents diverge from a true tlink32 + fine-grained-library link.

- **Current:** Dead members' bytes still reach the EXE; no section-place culling keyed on reachability. Zero correctness impact — dead code never executes.
- **Expected (BCC 4.52):** tlink32 with a fine-grained library links only transitively-reachable members; dead code never reaches the EXE (the golden railc.exe contains none of the dead doc/view framework).
- **Blocks:** Byte/size parity with the bcc32 reference image; not a correctness blocker.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **LNK-04** — severity low, type incomplete, effort L, status new.

- **Evidence:** `src/link/pe_writer.rs:4255` (`compute_dead_relocs` returns only the set of dead relocations); `src/link/pe_writer.rs:4468-4473` uses `dead` solely to skip resolving a dead reference; the Pass-1 placement loop at `pe_writer.rs:3290` (`buf.extend_from_slice(&sec.data)`) copies all objects unconditionally; the doc at `pe_writer.rs:4237-4241` overstates parity (it reproduces tlink32's resolution effect, not its byte-pruning effect).
- **Proposed acceptance oracle (set at Gate 1):** Linking against a coarse archive where a pulled member has dead methods produces an EXE whose `.text` excludes those methods' bytes; image size matches/approaches the bcc32+OWLWF.LIB reference within tolerance; existing byte-identity goldens unaffected.
