# MDBCC-REQ-ANVIL-00086 — bcc lacks `-U` undefine and `-P` force-C++ (and single-file only)

- **State:** Draft
- **Priority:** Could
- **Area:** Driver / CLI / project
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
bcc should support `-U<name>` (undefine, threaded into the preprocessor define set, removed from `pp.macros`) and `-P` (force C++ dialect, overriding `is_cxx_source` in both preprocessor and parser); multi-file compile remains a documented S8 deferral with its existing rejection message.

## Rationale
bcc has no `-U<name>` (undefine) branch and no `-P` (force C++ dialect) branch — dialect is inferred solely from the file extension — and it rejects more than one input file.

- **Current:** `bcc a.cpp b.cpp` is rejected (with a workaround message); `-Uname` and `-Pcpp` are "unknown option" errors — you cannot undefine a macro or force a `.c` file to compile as C++.
- **Expected (BCC 4.52):** BCC32 compiles multiple TUs in one invocation, honours `-U<name>` to undefine a (predefined or earlier `-D`) macro, and `-P`/`-Pext`/`-p` to force C++ vs C compilation independent of extension.
- **Blocks:** Build scripts that pass `-U`/`-P`; the `bcc *.cpp` one-shot convenience (low — mdbcc.toml is the intended multi-file path).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **CLI-06** — severity low, type incomplete, effort M, status new.

- **Evidence:** `src/main.rs:111-120` (hard-errors when `inputs.len()>1`, multi-file deferred to S8 per HLD Q-Bcc); no `-U`/`-P` branch in the parse loop `main.rs:56-104`; dialect inferred via `is_cxx_source` at `main.rs:176`.
- **Proposed acceptance oracle (set at Gate 1):** `bcc -DFOO=1 -UFOO -c x.c` compiles with FOO undefined; `bcc -P -c plain.c` predefines `__cplusplus` and runs the parser in C++ mode.
