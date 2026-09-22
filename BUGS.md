# mdbcc — known defects & gaps

Single source of truth for known bugs, gaps, and parked work. Supersedes the
ad-hoc `MDBCC-NN` list (carried from the daily journals) and the scattered
`G##` gap-fix log. Add an entry when a defect is found; move it to **Fixed**
(with the commit) when closed. Keep it honest — a documented gap is a feature;
a silent one is a liability.

Severity: **critical** (silent miscompile / corruption) · **high** (wrong
behaviour, in-scope path) · **medium** (wrong behaviour, narrow/rare path) ·
**low** (cosmetic / unlikely-in-target).

Status: **open** · **parked** (deliberately deferred) · **fixed** (+ commit).

The comprehensive gap inventory — all 107 verified requirements plus 6 cross-seam
additions, including the medium/low items — lives in
`wrk_docs/2026.06.21 - REQ - mdbcc compiler gap analysis and requirements.md`. The
**critical** and **high** items from that 2026-06-21 audit are promoted into the
Open tables below; their `PREFIX-NN` IDs cross-reference the REQ doc.

---

## Open — codegen / ABI

| ID | Sev | Title | Evidence / notes |
|----|-----|-------|------------------|
| ABI-01 | critical | `__fastcall`/`__pascal` parsed but silently emit cdecl | Wrong convention → stack-cleanup mismatch and arg misplacement. REQ 2026.06.21 ABI-01. |
| OWL-01 | critical | Member-function-pointer value carries no `this`-adjustment | OWL response-table dispatch on virtual / non-leftmost bases passes the wrong `this`. REQ OWL-01. |
| PP-01 | critical | `#pragma pack(push/N/pop)` silently dropped | Struct packing hardwired per target → layout diverges from the headers that set it. REQ PP-01. |
| ABI-02 | high | Calling convention absent from `Type::Func` | Indirect calls cannot honour a non-cdecl callee. REQ ABI-02. |
| ABI-03 | high | i386 struct-return uses the Win64 size rule | `effective_struct_abi` is target-agnostic → wrong sret on i386. REQ ABI-03. |
| ABI-04 | high | Member-function-pointer dispatch is single-inheritance-only | No this-delta for secondary-base methods. REQ ABI-04. |
| C32-01 | high | `long double` folded to 8-byte `double` | Miscompiles `%Lf`/`%Lg` and the long-double ABI; needs real 80-bit x87 storage. REQ C32-01. |
| C32-02 | high | i386 64-bit `/` and `%` emit a clean CodegenError | No software 64/64 divide. REQ C32-02. |
| OBJ-01 | high | Section reloc count truncated to u16, no overflow record | Missing `IMAGE_SCN_LNK_NRELOC_OVFL` → corruption past 65535 relocs. REQ OBJ-01. |
| PSC-01 | high | Bit-fields carry no width | Every named bit-field becomes a full-width member → silent layout miscompile. REQ PSC-01. |

## Open — C++ dialect / RTTI / EH

| ID | Sev | Title | Evidence / notes |
|----|-----|-------|------------------|
| SEM-01 | critical | `int` and `long` mangle to the same decorated symbol | Distinct overloads silently collide at link. REQ SEM-01. |
| SEM-02 | high | `arg_compat` cannot distinguish integral promotion from conversion | Overload ranking is wrong → best-match picked incorrectly. REQ SEM-02. |
| SEM-03 | high | `arg_compat` rejects all integer↔floating conversions | Valid overloaded/implicit-conversion calls rejected. REQ SEM-03. |
| EH-01 | high | Function-scope locals not destroyed on exception propagation | Both targets; dtors skipped / resources leaked when an exception unwinds a frame. REQ EH-01. |
| EH-02 | high | i386/Win32 has no partial-construction, array-new, or catch-side object destruction | Throws leak already-constructed subobjects/elements; sharpens the parked i386 partial-construction item. REQ EH-02. |

## Open — RTL / CRT / resources / toolchain

| ID | Sev | Title | Evidence / notes |
|----|-----|-------|------------------|
| RTL-01 | high | Core `math.h` functions unresolvable | asm-only RTL source, no intrinsic and no shim. REQ RTL-01. |
| RTL-02 | high | Iostreams slice omits all value insertion/extraction operators | `cout << n` is unresolvable. REQ RTL-02. |
| LNK-01 | high | Win32 imports resolved by hand-curated allowlist, not an import library | Blocks arbitrary Win32 API use. REQ LNK-01. |
| OWL-02 | high | OWL message crackers truncate 64-bit HWND/HANDLE to 32-bit uint | Win64 dispatch corruption. REQ OWL-02. |
| OWL-03 | high | `TApplication` default-startup / `TFrameWindow` run path crashes 0xC0000005 | Before any window appears (scratchpad HELLOAPP/POPUP). REQ OWL-03. |
| OWL-04 | high | OWL control-subclass ctor forwarding (GROUPBOX, EDIT) fails to reach clean codegen+link | Ctor overload resolution. REQ OWL-04. |
| PP-02 | high | Stringification (`#`) does not escape embedded quotes/backslashes | Loses source spacing → malformed string literal. REQ PP-02. |
| RTL-03 | medium | Win64 GUI exe linked with `mdcw32.lib` alone crashes 0xC0000005 at startup | `int PASCAL WinMain(...) { return 42; }` built by `mdbcc` with `libs = [".../win64/mdcw32.lib"]` and no OWL dies before exit; the same source with `libs = []` exits 42. RailC (OWL + RTL) is unaffected. Found 2026-09-22 building a sound probe. |
| RC-01 | high | RC preprocessor lacks `#if`/`#elif`/`defined()` | REQ RC-01. |
| RC-02 | high | RC has no INCLUDE search path; angle-bracket includes rejected | REQ RC-02. |
| RC-03 | high | RC built-in style table is a 14-entry subset | REQ RC-03. |
| RC-04 | high | RC style expressions support only the OR operator (no NOT / parentheses) | REQ RC-04. |
| RC-05 | high | Missing shorthand dialog controls (CHECKBOX/LISTBOX/COMBOBOX/SCROLLBAR/…) | REQ RC-05. |

## Parked (deferred until leverage)

- i386 `long long` division/modulo: non-div/mod pair operations are fixed in
  F-12; `/` and `%` now produce a clean `CodegenError` pending software 64/64
  divide support.
- i386 partial-construction EH cleanup: Win64 constructor base/member cleanup
  and array-new cleanup are fixed, but the Win32/i386 SEH3 path still lacks
  constructor/member and array-new cleanup pads; throws during those paths can
  leak already-constructed subobjects/elements.
- Bare `typeid(x)` full `typeinfo&` ABI: `.name()` and polymorphic `.tpp`
  are supported, but the bare result needs a real Borland `typeinfo` object
  layout (vptr + `tpp`) and member-function semantics, not the existing EH
  typeinfo descriptor table.
- Modern template forms outside the current Borland-targeted template subset:
  variable templates, alias templates, and deeper dependent-template syntax.
  Function templates, class-template instantiation, non-type class-template
  parameters, and dependent nested types are already covered by tests.
- `new` corner forms narrowed from B-16: multi-dimensional `new T[m][n]`
  remains a deliberate clean parser error pending nested array construction
  and delete/cookie semantics; scalar allocator placement-new `new(alloc) T`
  remains a clean codegen error pending class-specific
  `operator new(size, alloc)` resolution. Raw-buffer placement array-new and
  allocator placement array-new are already implemented and tested.
- B-19 RC row was stale against current main: named resource IDs,
  preprocessing/includes/conditionals, style expressions, ICON/BITMAP/RCDATA,
  VERSIONINFO, and the BC4.5 RailC `.res` oracle all pass existing tests.
  `DIALOGEX` remains intentionally rejected with a clear diagnostic pending
  real `DLGTEMPLATEEX` support.
- B-21 `_fuildq` precision above 2^53: the shim's return type is
  `long double`, but mdbcc currently folds `long double` to 8-byte `double`
  at the parser/AST boundary. A correct fix requires real 80-bit x87
  `long double` storage/ABI support, not a local `_fuildq` arithmetic tweak.
- Parser C-TU mode for principled `extern "C"` linkage (`!proto.c_linkage`).
- Bit-field struct layout not fully bcc32-accurate.
- Common-dialog "Set data file" select-success automation (oracle limitation).

---

## Fixed

| ID | Title | Commit |
|----|-------|--------|
| F-31 | **Win64 images carried subsystem version 6.0 instead of tlink32's 3.10**. Windows gives a 6.0 image the padded Vista frame and modern dialog base units, so RailC's fixed-pixel 300x192 Arrivals/Departures boards lost 10px of client and overflowed their frame border, and the About box shrank from 611 to 524px, clipping the bitmap blitted at x=450. The object linker now stamps OS 1.0 / subsystem 3.10 on PE32+ as it already did on PE32; guarded by `tests/pe_layout.rs::win64_images_carry_bc45_subsystem_version`, with an intentional 88-fixture `o1_byte_identity` re-bless (header bytes only). | `1cdaaf6` |
| SEM-04 | **Member function calling a same-named static overload failed "use of undeclared identifier 'this'"** (regression from `7730d8c`, which keyed static-ness by name). Knocked OWL `GDIBASE`/`BRUSH`/`WINDOW`/`COMPAT` out of the source-built libs, so RailC's Win64 link failed. The parser now decides static per overload signature, and a static body never gets an implicit `this->` call. Guarded by `tests/end_to_end.rs::mixed_static_and_instance_overloads_keep_this_per_signature` and `static_body_calls_static_overload_of_mixed_name`. | `789d05c` |
| F-30 | **BC45 lib producer skipped all of OWL `DIB.CPP` instead of compiling its useful sectioned slice**. `DIB.CPP` is Borland-sectioned; the full TU still exceeds current compiler stack limits in bitmap read/write sections, but `SECTION=1` provides `TDib::ToClipboard`, which RailC and OWL clipboard helpers need. `build_bc45_libs` now adds `SECTION=1` for `DIB.CPP`, keeping the source-built OWL library broader without pretending the full TU is solved. | `1379c8c` |
| F-29 | **Fstream-shaped truthiness missed conversion operators declared on extra/virtual bases**. Conversion-operator discovery walked only the primary `base` chain, so a `fstream : fstreambase, iostream` shape could miss `ios::operator void*` / `operator!` through the shared virtual base. The lookup now walks primary, extra, and virtual bases with cycle protection; guarded by `tests/end_to_end.rs::win64_fstream_shaped_vbase_truthiness`. | `1379c8c` |
| F-28 | **Cross-TU weak vtable folding could select an ABI-incompatible no-prefix vtable for `dynamic_cast`**. A TU without `dynamic_cast` could emit a weak `@Tag@3` vtable with no RTTI prefix; if that copy won the link fold, another TU's `dynamic_cast` read the word before the vtable as the complete-object adjustment/base link and produced a bogus pointer. Polymorphic vtables now always carry the two-word RTTI prefix while the vtable symbol still points at the slot array; guarded by `tests/two_file_link.rs::cross_tu_dynamic_cast_reads_folded_vtable_prefix` and an intentional `virtual.c` i386 byte-baseline re-bless. | `1379c8c` |
| F-27 | **Win64 dialog overlapping child controls lacked `WS_CLIPSIBLINGS`**, leaving sibling paint order undefined. An `SS_BLACKRECT` panel painted *over* the centred text it sits behind — RailC's "Start a new game" dialog lost 2 of its 3 text lines on Win64 (the "missing text in the dialog" report). Control z-order/styles/text/font were byte-identical to the working 32-bit build; the static-dispatcher OWL (dialog not subclassed) just happens to paint the filled panel last. `TDialog::SetupWindow` now walks the dialog's children and ORs in `WS_CLIPSIBLINGS` so overlapping controls render strictly by Z order. Verified: START shows all 3 lines; About/Config dialogs unchanged; Win64 source-slice link parity passes. | `4499655` |
| F-26 | **Win64 `outgoing` stack-arg reservation omitted the 0x20 callee shadow.** Stack args are stored at `[rsp+0x20 + 8*(i-4)]`, but `outgoing` reserved only `8*max_stack_args`; the `frame_fixed` +32 pad normally absorbs the overflow, but an H1 struct-by-value copy buffer / H2 result buffer is allocated *between* `frame_fixed` and the outgoing region, so a trailing stack-arg store corrupted the struct copy at offset 16. RailC's `new TToolbar(this, 12, ToolButtData /*4520-byte by value*/, ToolbarBitmaps)` overwrote `XPos[4]/[5]` of the copy with the trailing `HBITMAP`, so two toolbar buttons rendered at x=-32768/0 (the "toolbar buttons in the wrong order" report). Now reserves `0x20 + 8*max_stack_args` when a by-value/result buffer coexists with stack args; gated so non-byval/non-record functions stay byte-identical. Guarded by `tests/cpp_struct.rs::h1_byval_struct_*`. | `2912af0` |
| F-25 | **`EXCEPT.C` wrote Borland register pseudo-variables that mdbcc only modeled as `_EAX` reads**. `_EAX`/`_EDX` are now frame-backed pseudo-registers: assignments update their slots, Win32 direct calls materialize them into EAX/EDX immediately before `call rel32`, and the RTL build job gives `EXCEPT/COMMON32/EXCEPT.C` the required `WINVER=0x030A` header define; guarded by pseudo-register write/runtime and build-job regressions plus a direct compile of the real RTL TU. Was B-24. | `583e021` |
| F-24 | **`mdrc` relied on Cargo's `src/bin` auto-discovery instead of an explicit shipped-tool declaration**. `Cargo.toml` now declares `[[bin]] name = "mdrc"` at `src/bin/mdrc.rs`, the package/lock version is bumped to `0.7.1`, and a manifest regression test asserts every `src/bin/*.rs` tool has an explicit bin stanza. Was B-23. | `d441060` |
| F-23 | **`printf` rejected supported sign/alternate flags and capped `%f` precision at 15**. Explicit integer and float specs now prepend `+`, space, and alternate-form prefixes into the generated token, zero-pad after those prefixes, force the `%#.0f` decimal point, and size `%f` token/scratch buffers from the requested precision while extracting fractional digits one at a time; guarded by Win64/default and i386 printf regressions plus re-blessed i386 byte baselines for the affected printf fixtures. Was B-22. | `2daeb5d` |
| F-22 | **`_control87` updated only a software shadow control word**. The RTL shim now reads and writes the real x87 control word through private `fnstcw`/`fldcw` codegen intrinsics, preserving mask-merge semantics while keeping the fix scoped to the shim; guarded by an i386 test that observes real rounding-control bits changing and restoring. Was B-20. | `8ae3326` |
| F-21 | **Same-named block-scoped static locals in one function collided**. Static-local storage and runtime-init guards now use declaration-location-qualified symbols, and codegen binds static locals through a lexical scope stack parallel to automatic locals, so same-name sibling block statics remain distinct while normal shadowing still works; guarded by Win64 and i386 same-function block-static regressions. Was B-17. | `626d4f1` |
| F-20 | **Scalar `new T(value)` for non-class types was rejected after successful allocation**. `construct_in_place` now evaluates the single scalar initializer, converts it to the allocated type, and stores it through the existing target-aware scalar store path before returning the allocation pointer; guarded by Win64 and i386 `new int(42)` regressions. Was the live scalar portion of B-16. | `50b2b4c` |
| F-19 | **Win64 member-initializer constructor calls with arguments did not advance the partial-construction cleanup counter**. The cleanup recognizer now accepts the parser's `this->m.Tag(...)` shape instead of only zero-argument member ctor calls, so when a later member initializer throws, earlier fully constructed members are destroyed; guarded by `tests/cpp_exceptions.rs::t48b_throw_during_member_init_arg_ctor_chain`. Was B-13. | `471f644` |
| F-18 | **Variadic constructors were still parser-rejected while variadic free/member functions already worked**. Constructor declarations and definitions now preserve `Function::variadic`, so inline and out-of-line `C(int, ...)` ctors use the existing `this`-plus-varargs ABI path; guarded by integer and floating-vararg constructor regressions. Was B-12. | `4f8a965` |
| F-17 | **File-scope arrays of default-ctor class globals were never constructed**. The static-init queue now lowers init-less class arrays into per-element constructor calls, reuses the virtual-base setup path for each element lvalue, and keeps inline default ctors reachable through array element types; guarded by single-TU i386 and main-less two-file regressions. Was B-11. | `6c07167` |
| F-16 | **i386 nested `try` had only a flat active trylevel**. The i386 multi-try scope table now records each row's parent level, try fallthrough and catch pads restore the enclosing trylevel, and the SEH3 multi handler walks parent levels before continuing search outside the frame; guarded by nested i386 try fallthrough, catch-throw, and inner-nonmatch regressions. Was B-10. | `d66f562` |
| F-15 | **Secondary-base `dynamic_cast` had no complete-object RTTI metadata**. RTTI-enabled vtables now carry a source-subobject adjustment plus the existing base/owner link, secondary vtables link back to their owner primary vtable, and i386/Win64 `dynamic_cast` applies the adjustment on successful walks; guarded by `tests/oracle_s4_classlib.rs` secondary-base RTTI regression. Was B-09. | `a0b38c4` |
| F-14 | **Thrown class exception objects were raw-copied on Win64 and named catch references were never destroyed**. Win64 throw lowering now materializes `.mdbcc_eh_buffer` through the copy-constructor/memberwise-copy path shared with i386, and named Win64 `catch (T& name)` handlers register pointer-backed destructor cleanup for fallthrough and return; guarded by `tests/cpp_exceptions.rs` copy/dtor/rethrow regressions. Was B-08. | `324af61` |
| F-13 | **Call-argument evaluation order was left-to-right**. Direct, indirect, virtual, member-function-pointer, and inline libc call paths now evaluate explicit arguments right-to-left into source-position slots, preserving ABI delivery order; guarded by Win64/i386 direct, function-pointer, and `strcmp` side-effect regressions. Was B-07. | `de3b460` |
| F-12 | **i386 64-bit integer pair operations used EAX-only paths**. Win32 `long long` expressions now use EDX:EAX for literals, loads/stores, casts, unary/incdec, add/sub/mul, bitwise ops, shifts, comparisons, truthiness, scalar returns, and cdecl arguments; guarded by `tests/i386_run.rs` regressions. Division/modulo remain a documented clean-error gap. Was B-06. | `cde6eef` |
| F-11 | **i386 intrinsic `va_start`/`va_arg` used Win64 home-space and 64-bit pointer stores**. Intrinsic stdarg lowering now computes Win32 cdecl `&last + sizeof(last)`, advances `va_arg(ap, double)` over the 8-byte promoted slot, and stores `va_list` updates at target pointer width; guarded by `tests/i386_run.rs` intrinsic stdarg regressions. Was B-05. | `8ab1a26` |
| F-10 | **Win64 reference-argument binding passed unadjusted derived addresses**. Win64 direct, virtual, function-pointer, and member-function-pointer by-reference argument paths now upcast `Derived&` binds to the requested base subobject before spilling/loading call arguments; guarded by `tests/win64_ref_base_adjust.rs`. Was B-04. | `0299b1d` |
| F-09 | **`const_eval` unsigned right shifts folded arithmetically**. Constant folding now infers local unsigned operand width for `>>`, masks to that width, and folds unsigned shifts logically; guarded by `tests/i64_ops.rs` constant-context regressions. Was B-03. | `3f6a7a8` |
| F-08 | **`LL`-suffixed literals in `0x80000000..=0xFFFFFFFF` typed as 32-bit `int`**. Parser now keeps explicit `LL`/`ULL` suffixes as 64-bit through the u32 boundary, using an inner unsigned-32 tag to avoid sign-extending high-bit values; guarded by `tests/i64_ops.rs`. Was B-02. | `1cfd816` |
| F-07 | **Win64 pointer comparison was 32-bit** (`p == q` / relational pointer compares only compared the low dword). `gen_binary` now routes Win64 pointer-shaped comparisons through the existing 64-bit compare path; guarded by `tests/win64_pointer_compare.rs`. Was B-01. | `1e042a4` |
| F-01 | **64-bit integer arithmetic miscompile on Win64** (gen_intop 32-bit opcodes for all widths; `x>>32` wrapped mod 32; `cdq` not `cqo`; lost carry; literal/result mistyped as `int`; unary `neg`/`not` 32-bit). Was MDBCC-13. | `98115c4` |
| F-02 | Win64 startup heap corruption `0xC0000374` — array-new/`delete[]` cookie symmetry. Was MDBCC-01. | `6055544` |
| F-03 | Win64 wall-2 dispatch AV `0xC0000005` — `WPARAM`/`LPARAM`/`LRESULT` widened to pointer size. Was MDBCC-02. | `2b523de` |
| F-04 | 4-byte `float` global over-read (`movsd` instead of `movss`) — the blank-track-diagram bug. Was MDBCC-09. Guarded by 6 `tests/floats.rs` cases. | `f91163b` |
| F-05 | Win64 RTL printf integer varargs (BC45 `<stdarg.h>` register-passed garbage). | `756daaa`, `61ba06f` |
| F-06 | **`-m64` was test-scaffolding, not a real target** (B-18). `build_bc45_libs --target win64` now produces the Win64 OWL/streams/RTL/BIDS deps in `target/bc45-libs/win64/` (the `-m64` + `wrk_owl_win64` static-dispatcher OWL + `include64/` overlay recipe), so an OWL app builds Win64 straight from `mdbcc.toml` (the `overlay_dirs` half had landed earlier in `fa69d85`). Verified: RailC links a native Amd64/PE32+ GUI exe; import table passes the O1 gate (`*WindowLongPtrA` present; no `CTL3D32`/`VirtualAlloc`/`VirtualFree`). | `166249b` |
