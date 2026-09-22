# MDBCC-REQ-ANVIL-00062 — Iostreams slice omits all value insertion/extraction operators (`cout << n` unresolvable)

- **State:** Draft
- **Priority:** Must
- **Area:** RTL / CRT / iostreams
- **Raised:** 2026-06-21
- **Implemented-by:** —
- **Satisfied-by:** —
- **Violated-by:** —
- **Flow:** light
- **Claimed-by:** —
- **State history:** Draft (2026-06-21)

## Statement
Extend the iostreams slice to include the value insertion/extraction TUs (OSTINT, OSTFLOAT, OSTOUTST, OSTISCHR, OSTPTR, ISTEINT, ISTELNG, ISTEDBL/ISTEFLT) and the STDEC/STHEX/STOCT base manipulators so the common `cout<<`/`cin>>` surface resolves — or document iostreams value-formatting as explicitly unsupported. (OSTFLOAT depends on RTL-05's float-format core.)

## Rationale
The curated iostreams slice provides only stream/streambuf/filebuf/strstreambuf plumbing and a few manipulators; every integer/float/string/pointer insertion and extraction TU (OSTINT, OSTFLOAT, OSTOUTST, OSTISCHR, OSTPTR, ISTEINT, ISTELNG, ISTEDBL, ISTEFLT, OSTX, ISTX) and the dec/hex/oct base manipulators are absent.

- **Current:** `cout<<int` / `cout<<double` / `cout<<"str"` (OSTOUTST) / `cin>>int` resolve to operators absent from `mdstreams.lib` → unresolved external at link for any iostreams program beyond the narrow slice. (51 in-scope examples use `cout<<`.)
- **Expected (BCC 4.52):** The full operator`<<`/operator`>>` family from IOSTREAM.LIB is provided; `cout<<42<<' '<<3.14<<endl;` formats and prints.
- **Blocks:** Any in-scope C++ sample that prints via iostreams (much of TUTORIAL, OWLAPPS console diagnostics); the fstream-diamond work (F-29) is moot without value formatters.

## Source
From `wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md` item **RTL-02** — severity high, type incomplete, effort M, status new.

- **Evidence:** `src/bin/build_bc45_libs.rs:83-90` (`STREAM_NAMES` is 48 plumbing units; STDEC/STHEX/STOCT and every operator TU absent); the operator TUs exist in `wrk_oracle/.../IOSTREAM` (OSTINT.CPP, OSTFLOAT.CPP, OSTOUTST.CPP, OSTISCHR.CPP, OSTPTR.CPP, ISTEINT.CPP, ISTEDBL.CPP, ISTEFLT.CPP, ISTELNG.CPP, OSTX.CPP, ISTX.CPP) but none appears in `STREAM_NAMES`.
- **Proposed acceptance oracle (set at Gate 1):** A test linking `#include<iostream.h> cout<<123<<" "<<endl;` resolves and runs, emitting `123 `; `cin>>int` extraction round-trips.
