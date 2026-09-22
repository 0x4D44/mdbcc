# RailC track-diagram blank — 4-byte `float` global codegen

## Symptom
railc.exe (mdbcc-built) renders the full OWL window EXCEPT the central track
diagram: every track **section** and **platform indicator** polygon is missing.
Clock, toolbar, list panels, menus, and the left-hand selectors all render.

## Diagnosis (locked before fix)
Invisible elements draw their polygons from coordinates computed as:

    ThePoints[i].x = SetPoint[i].x * XScaleFactor;   // long = long * static float

where `XScaleFactor`/`YScaleFactor` are **`static float`** class globals
(SECTION.CPP:24-25, PLATDATA.CPP:24-25), set at runtime from
`float(rect.right)/850.0` via `Set*ScaleFactor(float)`.

Everything that DOES render avoids 4-byte float globals:
- DrawClock: `0.2 * lClientRect.right` — **double literal** path (tested, works).
- SizeSelectors: `float SCX, SCY` **locals** — "ride the 8-byte slot" (work).

`tests/floats.rs` header admits the gap: float (4-byte) "locals ride the 8-byte
slot ... refining `movss` is a tracked F-future polish." 4-byte float **global**
load/store (movss + cvtss2sd widen on read; cvtsd2ss narrow + movss store on
write) is the unfinished path → `XScaleFactor` reads back garbage/0 → every
section/platform polygon collapses to a degenerate point → invisible.

## Oracle
tests/floats.rs `exit_of(src)` = compile_to_pe + run + exit code. Minimal repro
mirrors railc:  `float k = 1.0;` (file scope) → assign at runtime → `(int)(N*k)`.
