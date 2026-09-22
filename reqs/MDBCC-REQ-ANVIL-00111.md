# MDBCC-REQ-ANVIL-00111 — `#pragma exit` (and other behavior-bearing Borland pragmas) silently ignored

- **State:** Draft
- **Priority:** Should
- **Area:** Cross-seam / completeness
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Implement `#pragma exit` registration on the same INIT/EXIT-record mechanism as `#pragma startup`, wired into the GAP-01 shutdown path. (Benign noop pragmas — `hdrstop`, `argsused`, `warn`, `option` — may stay ignored but should be acknowledged so they aren't mistaken for the same defect.)

## Rationale
Only `#pragma startup` is implemented; the symmetric `#pragma exit <fn> [prio]` — which the BC4.52 RTL uses to register shutdown handlers — is silently dropped. PP-01 covers only `#pragma pack`.

- **Current:** A TU relying on `#pragma exit` to run a shutdown routine gets no such routine; no diagnostic.
- **Expected (BCC 4.52):** `#pragma exit` registers an exit-time callback (the mirror of `#pragma startup`), run at program shutdown in priority order.
- **Blocks:** S5 — RTL/OWL shutdown sequencing built on `#pragma exit`.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **GAP-04** — severity medium, type missing-feature, effort S, status open.

- **Evidence:** `C:\language\mdbcc\src\pp.rs:1071-1099` handles `"startup"` and comments "Every other pragma stays ignored." A grep for `"exit"`/`"hdrstop"`/`"argsused"`/`"option"` in `pp.rs` finds no handler — `#pragma exit` is matched by neither branch.
- **Proposed acceptance oracle (set at Gate 1):** A TU with `#pragma exit cleanup` runs `cleanup` once at exit; ordering relative to other exit handlers matches the declared priority.
