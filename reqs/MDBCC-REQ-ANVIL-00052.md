# MDBCC-REQ-ANVIL-00052 — Standalone entry stub passes NULL argv; synthesised-CRT argv path unreachable

- **State:** Draft
- **Priority:** Could
- **Area:** Linker / archives / CRT
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
For the standalone stub path, either marshal the real command line into argv/argc (`GetCommandLineA` + tokeniser) and `lpCmdLine` for GUI, OR document that argv-reading programs MUST link the source-built RTL C0 and gate accordingly; either way the NULL-argv limitation must be an explicit, tested boundary.

## Rationale
On the standalone stub path (in-process `compile_to_pe` / mdlink entry stub, not the source-built RTL C0), the program receives an empty command line and no argc/argv; the richer ctor-walking synthesised CRT exists but is never selected in production.

- **Current:** argv-reading standalone programs see empty input — no silent miscompile. The mission's OWL product builds via the source-built RTL C0, which marshals `GetCommandLineA` itself per STARTUP.C.
- **Expected (BCC 4.52):** C0 startup marshals the real command line (`GetCommandLineA`) into argc/argv/`_oscmd` and walks the global-ctor INIT chain.
- **Blocks:** Standalone (non-source-RTL) console/GUI programs that read the command line; not the source-built OWL product path.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **LNK-06** — severity low, type incomplete, effort M, status new.

- **Evidence:** `src/link/pe_writer.rs:1631` (GUI stub bakes `lpCmdLine = NULL`, "real argv is deferred per the HLD"); the console stub (`pe_writer.rs:1685-1697`) passes no argc/argv; `src/link/crt.rs:33-40` documents argc=0/argv=NULL/envp=NULL, and `synthesise_crt` is `false` at every call site (`src/compile.rs:174`, `src/link/mod.rs:83`) and never set by the driver, so `crt.rs`'s startup object is test-only.
- **Proposed acceptance oracle (set at Gate 1):** A standalone-linked console program that prints `argv[1]` receives the real argument (or a clear, tested diagnostic steers it to the RTL-C0 path); a regression covers command-line marshalling.
