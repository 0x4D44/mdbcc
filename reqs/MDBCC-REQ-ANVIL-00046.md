# MDBCC-REQ-ANVIL-00046 — No debug information emitted (CodeView and line numbers absent)

- **State:** Draft
- **Priority:** Could
- **Area:** Object format (COFF)
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Document that mdbcc emits NO debug information as a deliberate S8-deferred scope boundary (TimeDateStamp/line-numbers/CodeView all zero/absent across both `.obj` and linked PE), so a future S8 effort has a clear starting contract and downstream consumers do not assume debuggable output. No emission work is required for the S0–S7 mission.

## Rationale
mdbcc objects carry no debug info of any kind — no CodeView `.debug$S`/`.debug$T` subsections, no COFF line-number records, no File/FunctionDef aux symbols — so a produced PE has no source-level debuggability. This is a deliberate S8-deferred scope boundary, recorded only in scattered inline comments rather than a tracked invariant.

- **Current:** No CodeView symbol/type subsections, no COFF line-number records, no File/FunctionDef aux symbols, `TimeDateStamp`/`Characteristics` zeroed — across both the `.obj` and the linked PE. The `SectionRef::Debug` enum variant is only the `-2` special index used when parsing input objects; codegen never produces a Debug-classed symbol.
- **Expected (BCC 4.52):** BC++ 4.52 with `-v` emitted CodeView CV4 debug info (sstModule/sstSrcModule subsections, `$$SYMBOLS`/`$$TYPES`) consumable by Turbo Debugger; MS COFF uses `.debug$S`/`.debug$T`. The brief lists this as S8 — acknowledged future work, not a current-mission requirement.
- **Blocks:** S8 (source-level debugging); does not block the S0–S7 mission.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OBJ-04** — severity low, type missing-feature, effort S, status new.

- **Evidence:** No `debug$S`/`debug$T`/`CodeView` hits in codegen; `TimeDateStamp=0`/`Characteristics=0` at `C:\language\mdbcc\src\coff.rs:902,906`; `PointerToLinenumbers=0`/`NumberOfLinenumbers=0` at `C:\language\mdbcc\src\coff.rs:920,922` and again in the linked-PE headers at `C:\language\mdbcc\src\pe_writer.rs:3066,3068`; File/FunctionDef aux explicitly deferred at `C:\language\mdbcc\src\coff.rs:619-623`.
- **Proposed acceptance oracle (set at Gate 1):** A documented note/invariant (BUGS.md Parked or a scope marker) records that debug-info emission is S8-deferred and that `PointerToLinenumbers`/CodeView are intentionally absent in both the object and the linked PE; no behavioral test needed.
