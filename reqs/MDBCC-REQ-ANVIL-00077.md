# MDBCC-REQ-ANVIL-00077 — No warning system: zero warnings, no W8xxx numbers, no `-w` flags

- **State:** Draft
- **Priority:** Could
- **Area:** Diagnostics
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Accept (parse and ignore, at minimum) bcc32 `-w`/`-w-name`/`-wname` flags so real BC4.52 build command lines don't fail; longer term, emit the highest-value default warnings with W8xxx numbers. (Note: the in-scope OWL makefiles do not pass `-w` flags, so the broader win is tolerating the full bcc32 flag vocabulary.)

## Rationale
mdbcc never emits a warning-severity diagnostic, has no W8xxx number table, and hard-rejects every bcc32 `-w...` flag as an unknown option. The flag-tolerance gap is real but narrow; warning emission is off the recompile critical path.

- **Current:** mdbcc emits only hard errors; it never warns about constructs bcc32 warns on (unused variable W8004, missing return value W8070, possibly-incorrect assignment W8060, condition-always-true W8008, etc.), and passing any bcc32 `-w...` flag is a hard failure.
- **Expected (BCC 4.52):** bcc32 has a default-on warning set with numbered W8xxx diagnostics and `-w`/`-w-`/`-wxxx` controls; a bcc32 command line containing warning flags must at least be accepted.
- **Blocks:** Accepting verbatim bcc32 IDE/makefile command lines; warning parity is otherwise not on the recompile critical path.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DIAG-03** — severity low, type missing-feature, effort L, status new.

- **Evidence:** No `warning:`/`Warning`/`warn(` diagnostic across `src/*.rs` + `src/codegen/*.rs`; no `-w*` handling and unknown `-` flags rejected at `src/main.rs:99-101` (`unknown option`); option parser at `src/main.rs:55-104` knows only `--dump-tokens`/`-E`/`-c`/`-m32`/`-m64`/`-o`/`-I`/`-D`; no E2xxx/W8xxx table.
- **Proposed acceptance oracle (set at Gate 1):** `bcc -w -wuse foo.cpp` no longer fails with `unknown option`; a follow-up test asserts at least one representative warning (e.g. missing return value) is emitted with a W-number on a known-triggering TU.
