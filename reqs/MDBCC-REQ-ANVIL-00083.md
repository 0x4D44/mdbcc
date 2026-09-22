# MDBCC-REQ-ANVIL-00083 — No `.cfg` config-file support and no `INCLUDE`/`LIB` environment variables

- **State:** Draft
- **Priority:** Should
- **Area:** Driver / CLI / project
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
bcc must auto-load `bcc32.cfg`/`turboc.cfg` (and honour `INCLUDE`) and mdlink a `tlink32.cfg` (and honour `LIB`), each contributing search paths/flags ahead of argv, gated so absence preserves today's behaviour.

## Rationale
`bcc` and `mdlink` read no `BCC32.CFG`/`TLINK32.CFG` and honour no `INCLUDE`/`LIB` env vars; all search paths must be passed explicitly via `-I` (bcc) or `mdbcc.toml` `include_dirs`.

- **Current:** Both tools ignore the shipped `*.CFG` entirely and require every search path on the command line or in the manifest.
- **Expected (BCC 4.52):** BCC32 reads `BCC32.CFG`/`TURBOC.CFG` from its own directory then the CWD, applying flags as if prepended to argv, and honours `INCLUDE` for `<...>` headers; TLINK32 reads `TLINK32.CFG` and honours `LIB` — how every install locates headers/libs without explicit `-I/-L`.
- **Blocks:** Out-of-the-box BC4.52 invocation that relies on the shipped `*.CFG` + `INCLUDE`/`LIB` env instead of explicit paths (off the native build path).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **CLI-03** — severity medium, type missing-feature, effort M, status new.

- **Evidence:** Oracle `BIN/BCC32.CFG` = `-ID:\BC45\INCLUDE -LD:\BC45\LIB`; `BIN/TLINK32.CFG` = `-LD:\BC45\LIB`; `EXAMPLES/MAKEFILE.GEN:830-842` generates a per-build `bcc32.cfg` that bcc32 auto-reads; `src/main.rs:55-104` has no cfg read; grep `env::var|"INCLUDE"|"LIB"|\.cfg` over `src/` finds only `MDBCC_*` vars (`project.rs:446`, `compile.rs:308`).
- **Proposed acceptance oracle (set at Gate 1):** With a cfg containing `-I<dir>` and no `-I` on the command line, bcc resolves a header found only in `<dir>`; mdlink resolves a `.lib` by bare name via `LIB`/`tlink32.cfg`.
