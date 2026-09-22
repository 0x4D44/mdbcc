# MDBCC-REQ-ANVIL-00024 — Access control (private/protected/friend) is not enforced

- **State:** Draft
- **Priority:** Could
- **Area:** C++ semantics (overloads/templates/MI/RTTI)
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Provide member/base access checking (public/protected/private + friend grants) so ill-formed access is diagnosed; lowest priority because it only fails to REJECT ill-formed code (never miscompiles known-good BC4.52 source).

## Rationale
Access specifiers and base-class access are parsed but never recorded on members or checked at use sites; no `is_accessible`/access-check path exists, so ill-formed access to private/protected members is accepted silently.

- **Current:** References to private/protected members from non-member, non-friend contexts are accepted silently; ill-formed access is not diagnosed.
- **Expected (BCC 4.52):** Rejects access to private/protected members outside the class/friends with an error.
- **Blocks:** none (diagnostic-only; does not block compiling known-good source).

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **SEM-06** — severity low, type spec-conformance, effort L, status new.

- **Evidence:** member labels parsed at `C:\language\mdbcc\src\parser.rs:2213`, base specifiers at `C:\language\mdbcc\src\parser.rs:8988`, both discarded; self-documented gap at `C:\language\mdbcc\src\parser.rs:2227` ("mdbcc does not enforce access control"); `friend` plumbing at `C:\language\mdbcc\src\codegen.rs:1829`, `2355`, `10625`.
- **Proposed acceptance oracle (set at Gate 1):** Accessing a private member from a free function errors; a `friend` declaration grants access; compiling the BC45 OWL/RTL corpus shows no new rejections.
