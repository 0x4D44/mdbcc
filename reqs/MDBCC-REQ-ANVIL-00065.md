# MDBCC-REQ-ANVIL-00065 — Duplicate `__xcvt` — broken oracle XCVT.C not excluded as the shim claims

- **State:** Draft
- **Priority:** Should
- **Area:** RTL / CRT / iostreams
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Add an explicit per-file exclusion in `build_bc45_libs.rs` `rtl_jobs` for `MATH/COMMON32/XCVT.C` (and any other source the shim authoritatively replaces) so the shim definition is the sole provider, matching the documented contract.

## Rationale
The shim documents that XCVT.C is excluded and replaced by its correct reimplementation, but the library builder compiles `MATH/COMMON32/*.C` unconditionally with no XCVT exclusion. XCVT.C compiles cleanly under `-c` (its x87-asm helpers are merely unresolved externs), so its broken `__xcvt` and the shim's correct `__xcvt` both land in `mdcw32.lib`.

- **Current:** Both `__xcvt` definitions enter the archive. Because `archive()` sorts members by name, `MATH_COMMON32_XCVT.C.o` sorts before `rtlshim.o` and "first match wins" — so the linker deterministically pulls the **broken** oracle `__xcvt` (reads `fracw[4]` past the 8-byte folded-double local), a silent float→string formatting miscompile in the full-RTL build. (Scope: this bites the `build_bc45_libs` full-RTL path / Stone S5; the railc/OWL milestone slice already excludes XCVT.C via `source_slice.tsv`, so the currently-exercised path is unaffected.)
- **Expected (BCC 4.52):** Exactly one `__xcvt` — the shim's correct reimplementation — present in `mdcw32.lib`.
- **Blocks:** Determinism/correctness of float→string formatting (`printf %f`, gcvt, sprintf float) in the from-source full-RTL build.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RTL-05** — severity medium, type tech-debt, effort S, status new.

- **Evidence:** `wrk_rtlshim/rtlshim.c:284-289` (claims XCVT.C is excluded and replaced because the oracle copy reads past its 8-byte local under double-folded long double); `src/bin/build_bc45_libs.rs:456-476` (`rtl_jobs` pass-1 compiles `MATH/COMMON32/*.C` unconditionally — no per-file skip); `mdar.rs:49` (mdar does no duplicate-symbol detection, only basename disambiguation).
- **Proposed acceptance oracle (set at Gate 1):** After a libs build, `mdcw32.lib` contains exactly one `__xcvt` and it is `rtlshim.o`'s; a unit test asserts no archive member but `rtlshim` defines `__xcvt` (or that XCVT.C is not in the compiled RTL job set).
