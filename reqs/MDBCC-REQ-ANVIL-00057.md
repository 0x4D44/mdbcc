# MDBCC-REQ-ANVIL-00057 — Missing shorthand dialog controls (CHECKBOX/LISTBOX/COMBOBOX/SCROLLBAR/…)

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
Add the missing shorthand control keywords and parse arms with brc32-correct default styles and class ordinals (text form vs no-text form as above).

## Rationale
The lexer and parser lack the standard shorthand controls CHECKBOX, RADIOBUTTON, AUTOCHECKBOX, AUTORADIOBUTTON, LISTBOX, COMBOBOX, SCROLLBAR, STATE3, and AUTO3STATE; only PUSHBUTTON/DEFPUSHBUTTON/LTEXT/RTEXT/CTEXT/EDITTEXT/GROUPBOX/ICON and the verbose generic CONTROL form work.

- **Current:** A DIALOG containing these keywords lexes them as bare Idents and fails with `expected dialog control (PUSHBUTTON, ...)`.
- **Expected (BCC 4.52):** BRC32 accepts these shorthand statements with their fixed class + default-style pairs, e.g. CHECKBOX → BUTTON + `BS_CHECKBOX|WS_TABSTOP`, AUTOCHECKBOX → `BS_AUTOCHECKBOX`, RADIOBUTTON → `BS_RADIOBUTTON`, STATE3 → `BS_3STATE`, AUTO3STATE → `BS_AUTO3STATE` (text form); LISTBOX/COMBOBOX/SCROLLBAR are the no-text form like EDITTEXT (LISTBOX adds `LBS_NOTIFY|WS_BORDER`).
- **Blocks:** S6 OWL sample dialogs (COMBOBOX/LISTBOX/EDIT/CHECKBOX-bearing dialogs in COLORDLG, EDIT, etc.).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RC-05** — severity high, type missing-feature, effort M, status new.

- **Evidence:** `src/rc/lexer.rs:625-677` (keyword_lookup has none of them), `src/rc/parser.rs:1168-1237` (dispatch), `src/rc/parser.rs:1229` (error arm); oracle counts over EXAMPLES/OWL: COMBOBOX ×26, CHECKBOX ×12, SCROLLBAR ×10, LISTBOX ×5; in-scope `LAYOUT.RC` uses shorthand `LISTBOX`/`COMBOBOX` statements mdbcc cannot parse.
- **Proposed acceptance oracle (set at Gate 1):** A dialog with `CHECKBOX "&On", ID, x,y,cx,cy`, `LISTBOX ID, x,y,cx,cy`, and `COMBOBOX ID, x,y,cx,cy` compiles to `.res` bytes matching brc32 for those control records.
