# MDBCC-REQ-ANVIL-00073 — i386/Win32 SEH3 partial-construction unwind lacks ctor base/member and array-new cleanup pads

- **State:** Draft
- **Priority:** Should
- **Area:** OWL runtime & 64-bit port
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** heavy
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
The i386/Win32 SEH3 personality must emit and run partial-construction cleanup pads for ctor base/member subobjects and array-new elements (one shared root cause: the EH-integrated unwind path lacks i386 encoder rows), matching the already-implemented Win64 behaviour.

## Rationale
On the i386/-m32 (S6 32-bit) target, an exception thrown midway through constructing an object's bases/members, or midway through array-new element construction, does not run the cleanup pad for the already-constructed subobjects/elements — they leak, and the array-new storage block is not freed. The Win64 equivalent is fixed.

- **Current:** When a constructor throws during partial construction on i386, destructors for fully-constructed bases/members and array elements do not run and the array allocation is not freed.
- **Expected (BCC 4.52):** bcc32 SEH3 unwind runs destructors for fully-constructed bases/members and array elements in reverse order and frees the array allocation when a constructor throws during partial construction.
- **Blocks:** Exception-safety correctness of OWL apps built for the 32-bit S6 path (OWL throws `TXOwl`/`xalloc`/`xmsg` through these constructors). Win64 product path unaffected.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **OWL-07** — severity medium, type incomplete, effort L, status sharpens-parked.

- **Evidence:** `src/codegen.rs:4041` (`self.target != TargetKind::Win32` gates the member-dtor cleanup counter to Win64), `src/codegen.rs:16995-16999` (i386 array-new leaves partial-construction cleanup unwired); shared personality docs `src/eh.rs:742`; SEH3 handlers/cleanup-pad machinery `src/eh.rs:123-127,419,434,708,972,1128-1191`; documented Parked item `BUGS.md:37-40`. No i386 test asserts the acceptance criterion.
- **Proposed acceptance oracle (set at Gate 1):** An i386 test that throws from the Nth element's constructor in `new T[k]` (and from a base/member ctor) asserts the already-constructed elements'/subobjects' destructors run and the array storage is freed; differential against the Win64 path.
