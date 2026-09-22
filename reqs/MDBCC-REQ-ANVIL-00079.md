# MDBCC-REQ-ANVIL-00079 — Linker unresolved-externals lists raw decorated symbol names

- **State:** Draft
- **Priority:** Could
- **Area:** Diagnostics
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Demangle (or additionally show the demangled form of) Borland-decorated names in the `UnresolvedExternals` diagnostic; mdbcc already owns the mangling scheme, so a reverse map is feasible.

## Rationale
The `UnresolvedExternals` diagnostic writes the mangled/decorated symbol name verbatim; there is no demangler anywhere in the codebase, so the operator sees decorated names instead of readable signatures.

- **Current:** mdlink reports `unresolved external function '@TGauge@q...'` (decorated), making it harder to identify which C++ entity/overload is missing.
- **Expected (BCC 4.52):** A readable demangled form, e.g. `Unresolved external 'TGauge::TGauge(TWindow*, int, ...)'`. (Note: real TLINK32 generally also reports decorated names — demangling lived in TDUMP/IMPDEF — so the justification is operator usability on the S6 OWL bring-up, not strict TLINK32 parity.)
- **Blocks:** Identifying the missing OWL/GDI symbols behind GAUGE/LISTBOX/COMBOBOX/SLIDER on the S6 path (nice-to-have; the underlying gaps are codegen/import-stub problems, not diagnostic ones).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DIAG-05** — severity low, type diagnostics, effort M, status new.

- **Evidence:** `src/link/mod.rs:135-166` (`LinkError::UnresolvedExternals` Display: `unresolved external function '{name}'` at `src/link/mod.rs:147,157,163`); decorated `name` pushed at `src/link/pe_writer.rs:3526,4486`; scratchpad notes GAUGE/LISTBOX/COMBOBOX/SLIDER linking with unresolved OWL/GDI helper symbols.
- **Proposed acceptance oracle (set at Gate 1):** A link failure on a missing OWL ctor reports the readable `Class::method(arg types)` form alongside or instead of the decorated name; a test asserts the demangled signature appears.
