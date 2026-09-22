# MDBCC-REQ-ANVIL-00055 — Built-in style table is a 14-entry subset

- **State:** Draft
- **Priority:** Must
- **Area:** Resource compiler
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Either resolve style identifiers through the preprocessor macro table (preferred, once a const-expression evaluator exists per RC-01) or substantially expand `style_symbol_value` to the full BC4.52 windows.h `WS_/ES_/BS_/SS_/LBS_/CBS_/DS_/SBS_` set, including an explicit-term `DS_SETFONT`.

## Rationale
`style_symbol_value` knows only 14 style names; any other `WS_`/`ES_`/`BS_`/`SS_`/`LBS_`/`CBS_`/`DS_` identifier is a fatal error, and an explicit-term `DS_SETFONT` is rejected even though the writer models `DS_SETFONT` as an auto-OR on FONT.

- **Current:** Any style identifier outside the 14 hardcoded names aborts the parse; `inputdia.rc` fails at the first unknown term (`WS_BORDER`) because it does not `#include <windows.h>`.
- **Expected (BCC 4.52):** BRC32 resolves all style names because windows.h/owl headers `#define` them; mdbcc's built-in table is documented to apply "even when no Windows header is included" (`parser.rs:1410`), so styles must resolve from `#define`'d macros or the built-in table must cover the full common vocabulary.
- **Blocks:** S6 OWL dialogs; essentially any real-world dialog using header style symbols.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RC-03** — severity high, type incomplete, effort M, status new.

- **Evidence:** `src/rc/parser.rs:1922-1939` (14-entry table), `src/rc/parser.rs:1428-1435` (fatal `unknown style symbol`); `src/rc/mod.rs:370` (DS_SETFONT auto-OR only); oracle `wrk_oracle/bc45/BC45/INCLUDE/owl/inputdia.rc:18` (`WS_BORDER`, `ES_AUTOHSCROLL`), `:15` (`DS_SETFONT`).
- **Proposed acceptance oracle (set at Gate 1):** A control with `WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL` parses to the correct OR'd style; `inputdia.rc`'s EDITTEXT round-trips to the brc32 style word.
