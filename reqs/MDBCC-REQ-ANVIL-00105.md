# MDBCC-REQ-ANVIL-00105 — parser.rs monolith with a 1529-LOC `record_specifier` function

- **State:** Draft
- **Priority:** Should
- **Area:** Maintainability / tech-debt
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Split `record_specifier` into cohesive sub-parsers (base clause, member declaration, access-specifier handling) so the bit-field/layout logic is isolated and testable.

## Rationale
Class/record parsing — the surface most stressed by S4 (C++ dialect parity) and S5 (OWL deep class hierarchies) — is one 1529-line function handling class/struct/union parsing, member layout, access control, base lists, and nested template instantiation in a single body.

- **Current:** Member-layout, bit-field, and base-class bugs must be diagnosed inside a single 1529-line function with no sub-parsers.
- **Expected (BCC 4.52):** Internal maintainability requirement: record parsing decomposed into base-list, member-declaration, access-control, and nested-type sub-parsers.
- **Blocks:** none (raises the cost/risk of remaining S4/S5 class-layout fidelity work that must edit this function; the team has edited it successfully many times).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **DEBT-05** — severity medium, type tech-debt, effort L, status new.

- **Evidence:** `src/parser.rs` is 10,446 LOC; `fn record_specifier` (line 1578) spans 1529 lines (1578–3106), the largest function in the parser; `primary` (8226) = 540, `external_declaration` (5952) = 422, `declarator` (4424) = 402, `unary` (7540) = 311, `decl_specifiers` (1180) = 280. The parked "bit-field struct layout not fully bcc32-accurate" gap (`BUGS.md:65`) lives inside this function.
- **Proposed acceptance oracle (set at Gate 1):** The extracted base-list/member-decl/access sub-parsers each gain direct unit coverage and the existing `cpp_*`/`oracle_s4_*` parser tests stay green, with `record_specifier` reduced to orchestration. (A flat "<~400 LOC" target is a softer secondary check.)
