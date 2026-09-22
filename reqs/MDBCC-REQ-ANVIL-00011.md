# MDBCC-REQ-ANVIL-00011 — No TU-wide C-linkage mode: defined C functions taking record-pointer params mis-mangle as C++

- **State:** Draft
- **Priority:** Should
- **Area:** Parser — C language
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Thread the source dialect into `Parser` so a C TU defaults `c_linkage = true` for top-level declarations, and route C-linkage defined functions through the C-symbol path rather than C++/overload mangling — without regressing the existing bare-name self-consistency for primitive-param functions.

## Rationale
The source dialect (`is_cxx_source`) is never threaded into the parser, so a `.c` TU does not default top-level declarations to C linkage; C linkage is honoured only inside an explicit `extern "C"` brace. Primitive-param free functions already link self-consistently via bare-name emission, but a C function taking a struct/record-pointer param wrongly receives C++ `@name$q...` mangling.

- **Current:** In a `.c` TU, top-level functions get C++ default symbols unless physically inside `extern "C"`. Primitive-param functions still emit a bare self-consistent name and link correctly; record-pointer-param functions and same-name collisions route through C++/overload mangling, which is wrong for a C TU.
- **Expected (BCC 4.52):** Compiling a `.c` file gives every top-level function C linkage; record-pointer-param C functions must not receive C++ overload mangling, and a `.c` definition must agree with an `extern "C"` declaration of the same function.
- **Blocks:** Compiling real BC4.52 RTL `.c` TUs that define record-pointer-param functions and linking them against C++ callers (S5 build-from-source).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **PSC-02** — severity medium, type spec-conformance, effort M, status sharpens-parked.

- **Evidence:** `src/parser.rs:250` / `src/parser.rs:421` (`c_linkage` defaults false); `src/parser.rs:6392-6393`; `src/compile.rs:161-162` (`is_cxx_source` passed only to the preprocessor, not the parser); `src/codegen.rs:447-449` (`Type::Ptr(Record)` ⇒ `type_needs_cxx`); `src/codegen/cpp.rs:453` (`borland_c_symbol`); `BUGS.md:64`.
- **Proposed acceptance oracle (set at Gate 1):** A `.c` TU defining a function with a record-pointer parameter emits a C-linkage symbol (no `@...$q...` suffix) that resolves against an `extern "C"` declaration of the same function across a multi-TU link, with no undefined or duplicate symbol; existing o13 bare-name parity is preserved.
