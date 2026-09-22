# mdbcc — Borland C++ reimplementation: working notes

## Goal
Reimplement the Borland C++ compiler. Start with DOS-era Borland C/C++ dialect;
aim to also handle the Windows version. Purpose: rebuild old apps so they run on
modern Windows.

## Key architectural decision (2026-05-16)
"Rebuild old apps so they run on modern Windows" has a fork:
- Faithful Borland DOS  => 16-bit MZ/NE output => does NOT run on 64-bit Windows.
- Run on modern Windows => recompile Borland-dialect source to Win64 PE.

DECISION: Build a Borland-dialect C/C++ **front-end** + a clean back-end whose
**first target is Win64 PE, emitted directly** (no external assembler/linker —
none are installed; this also mirrors BCC+TLINK owning the whole pipeline).
Do NOT build a retargeting abstraction yet (premature). Keep backend factored so
a 16-bit DOS/OMF/MZ target can slot in later if bug-for-bug DOS fidelity is wanted.
Arthur can veto this direction.

## Environment
- rustc/cargo 1.95.0, Rust edition 2024.
- No clang/gcc/cl/ml64/MSVC link. Only Git's Unix `link` (irrelevant).
- => Emit PE executables directly from Rust. Zero external build tools.

## Roadmap (vertical slices, each must actually work + be tested)
1. [DONE] Scaffold: lib+bin crate, scratchpad.
2. [DONE] Lexer: C89 + core C++ + core Borland tokens. 19 tests.
3. [DONE] Parser + AST: funcs, return, integer-expr w/ precedence. 13 tests.
4. [DONE] Direct x86-64 machine-code generation for that subset.
5. [DONE] Minimal PE32+ writer + import table (kernel32!ExitProcess).
6. [DONE] End-to-end: bcc compiles .c -> runnable Win64 .exe; exit code
   verified by executing the binary on Windows. 5 e2e tests. (45 total.)
7. [DONE] Expand C: locals/assignment, multi-statement, if/else/while/for,
   all C operators, short-circuit &&/||. Oracle: exit-codes of computed
   programs (factorial=120, gcd=6, Σ1..100=5050, nested loops). 54 tests.
8. [DONE] Functions: params, calls, recursion, mutual recursion, nested-call
   args. Win64 int ABI (4 args). Module + linker resolves intra-unit calls by
   name (forward refs work w/o prototypes). 65 tests.
9. [DONE] Real I/O: string literals -> .rdata section, multi-import idata
   (ExitProcess/GetStdHandle/WriteFile), RIP-relative relocs, 5-arg Win64
   WriteFile path. Built-in printf/puts. "Hello, world!" runs. stdout
   verified byte-exact (escapes, concat, loops, return value). 71 tests.
10. [DONE] Function prototypes (parsed + discarded; linker resolves by name)
    and the C preprocessor: object/function/variadic macros, #/##, #include
    ("..." + stubbed <system>), #if/#ifdef/#ifndef/#elif/#else/#endif with a
    constant-expression evaluator + defined(), predefined __LINE__/__FILE__/
    __STDC__, #error, ignored #pragma/#line. lexer gained start_of_line.
    90 tests; CLI demo: includes+guards+macros+#if+prototype -> 89.
11. [DONE] Type system (Win64/LLP64): char/short/int/long/longlong +
    unsigned; multi-level pointers; arrays + subscript; &/*/[]; pointer
    arithmetic; sizeof; casts; ternary; ++/--; compound assignment;
    file-scope globals incl. `char *g="..."` (.data + abs-addr reloc);
    typed sized loads/stores w/ sign-zero ext; prototypes parsed. 94 tests
    (42 e2e: strlen, array sum, pointer write-through, casts, globals...).
12. [DONE] struct/union/enum/typedef: tagged + anonymous records, natural
    (MSVC) layout, self-referential/forward refs, `.`/`->`, nested structs,
    array-of-structs, whole-struct copy (assign & init), typedef aliases
    (scalar + anonymous-struct), enum constants fold to ints, sizeof.
    Struct-by-value params/returns rejected with a clear error (use a
    pointer) — deferred. 110 tests (52 e2e incl. linked list, union, ...).
13. [DONE] C++ v1: class/struct with data members + inline methods +
    implicit `this`; public/private/protected parsed&ignored; ctor (default
    & parameterized, auto-invoked at `T v;`/`T v(args);`); method calls
    `obj.m()`/`p->m()` + unqualified sibling calls/members; bare tag as type
    name; symbols mangled `Tag::name`. dtor parsed (manual-call only). 113
    tests. v2: references `T&` DONE (param-by-ref, local alias, ref-to-
    member; auto-addr at call, auto-deref on use). new/delete DONE:
    `new T`/`new T(args)` -> KERNEL32 GetProcessHeap+HeapAlloc then ctor;
    `delete p` -> dtor (if declared) then HeapFree; `delete[]` accepted.
    gen_call refactored to shared emit_call(callee,lead-this,args).
    RAII DONE: auto-dtor at scope exit, reverse construction order,
    function + lexical-block + early-`return` paths (return value saved
    across dtor calls); parser splices multi-declarators flat so they
    share the enclosing block scope. 122 tests (RAII order/return/inner-
    block all proven by exit code).
    out-of-line `T::m` DONE: class body accepts member/ctor/dtor
    prototypes; `Ret Tag::m(..){}`, `Tag::Tag(..){}`, `Tag::~Tag(){}`
    defined at file scope (qualified declarator in parser; `::` =
    Punct::ColonColon). Header-style classes compile/run. operator
    overloading DONE: member binary ops `+ - * / % == != < <= > >=`
    (inline or out-of-line; `operator@` via operator_name); `a@b`
    lowered to `Tag::operator@(&a,b)`, return type from its signature.
    single (public) inheritance DONE: `class D : [acc] B`, base
    subobject at offset 0 (flatten base fields → derived record;
    `this` reused as Base* with no adjustment), inherited data/
    methods (name union early so inline methods resolve; codegen
    method_target walks base chain), member-initializer lists
    `Ctor(p):Base(args),m(e){..}`, base ctor/dtor chained (injected
    in ctor_full_body/dtor_full_body or synthesized when derived
    declares none), Record gains `base`. default arguments DONE:
    `param_list` parses `=expr`; recorded per final/mangled name
    (`note_defaults`, this-prefixed for members) into
    TranslationUnit.defaults → Sigs; `emit_call` appends defaults for
    omitted trailing params (free fns, members, ctors incl. implicit
    `T v;`). free-function overloading DONE: overload sets detected
    in compile_module pass1 (names w/o `::`), symbol mangled by param
    types (type_code/overload_symbol), call sites resolved by arg-type
    scoring (arg_compat: exact/int-int/ptr-ptr/ref-binds), CompiledFn
    renamed to the mangled symbol in pass2; non-overloaded names &
    `main` stay unmangled. 136 tests. Slice 13 C++ subset COMPLETE.
    Deferred (future): virtual functions/vtables, multiple/virtual
    inheritance, member-function overloading, array-new `new T[n]`,
    scalar-init `new int(v)`, operator returning struct-by-value,
    lowering of `operator[]`/`operator()`/`operator=` (names parse,
    not lowered), unary/compound-assign operators, struct-by-value
    params/returns, float/double — all error or fall through clearly;
    no move semantics.
14. [DONE] Borland dialect (Win64 rebuild target).
    real format-string printf DONE: literal fmt parsed at compile time;
    runtime conversions `%d %i %u %o %x %X %c %s %p %%` via hand-emitted
    x86-64 itoa (div r10 loop, sign, hex digits) + strlen; flags/width/
    length modifiers skipped; returns total bytes; multi-arg + expr args
    (≤4 regs). 140 tests (printf byte-exact via stdout capture).
    near/far/huge + __cdecl/__pascal/__fastcall/__stdcall already
    parsed&ignored in decl_specifiers (correct for Win64 target);
    #pragma/#line ignored by pp. libc builtins DONE: strlen/strcmp/
    strcpy/strcat/memcpy/memset/abs/atoi as hand-emitted intrinsics
    (is_builtin guard: user definition overrides; libc_ret types them;
    <string.h>/<stdlib.h> etc. already stubbed by pp so includes are
    harmless). inline `asm`/`__asm` DONE: `asm{...}`, `asm(...)`,
    single-line `asm instr;`/newline-terminated all parsed & dropped
    (16/32-bit x86 can't run on Win64; surrounding code unaffected;
    skip_inline_asm uses Token.start_of_line). 146 tests. Slice 14
    COMPLETE for the Win64 rebuild goal — Borland-dialect source
    (calling-convention/memory-model keywords, #pragma, inline asm,
    stdio/string/stdlib via stubs+builtins, real printf) compiles to a
    runnable Win64 PE.
15. [OPTIONAL] Faithful 16-bit DOS target: real-mode codegen, OMF, MZ/NE,
    our TLINK. NOT pursued: the stated goal is "rebuild old apps so they
    run on modern Windows" — a 16-bit MZ does NOT run on 64-bit Windows,
    so this slice is explicitly optional/counter-goal. The Win64 path
    (slices 1–14) satisfies the goal. Revisit only if bug-for-bug DOS
    fidelity is later requested; backend is factored to allow it.

## Test oracles (2026-05-17) — v1 DONE

Design: `wrk_docs/2026.05.17 - HLD - Test Oracles.md` (V8). Spike +
acquisition: `notes/spike-oracles.md`. Journal:
`wrk_journals/2026.05.17 - JRN - Oracle v1 implementation.md`.

- **O1** (`tests/end_to_end.rs`) — unchanged, authoritative, 88 e2e green.
- **O2** — MSVC `cl` differential over `tests/corpus/portable/` (ACTIVE;
  vswhere→vcvars64 discovery + known-answer probe). 7/7.
- **O3** — genuine Borland **bcc32 5.5.1** (acquired, git-ignored
  `wrk_tools/BCC55/`): `bcc32 -c` acceptance (9/9) + Win32 behavioural
  (7/7). Three-way agreement: **mdbcc ≡ MSVC ≡ Borland** on portable C.
- Dialect parse-smoke tripwire + mdbcc determinism guard + a unit-tested
  §4.4 equivalence comparator (CRLF-normalised, crash/None-aware).
- §4.3 health guards: every breach halts the test process (oracle-health
  halt, not an mdbcc verdict); external oracles self-skip loudly.
- `tests/differential.rs` + `tests/support/mod.rs`; std-only, no new deps.
  bcc32 runs sandbox-off scoped to the O3 step (Arthur-authorised, V8 §9).
- Curated out (honest skips, mdbcc parse-smoke only): `inline_asm.c`
  (bcc32 5.5.1 free pkg has no tasm32.exe), `memory_model.c` (near/far
  are 16-bit-only — counter-goal). bcc64 (Win64) = v3 best-effort.

## printf format specifiers (2026-05-17) — DONE

`%`-spec width / `-` / `0` / string-precision / length-modifier-skip
implemented in codegen (compile-time `FmtSpec`, per-call-site emission;
fast path byte-identical via `int_token`). `+`/` `/`#`/int-precision/`*`
are explicit `CodegenError` (deferred, never silently wrong). Validated
three-way (O1 hand-expected + O2 MSVC + O3 Borland). 166 tests green.

## PE writer 4 KB-per-section limit — FIXED (2026-05-17)

(Was a blocker.) `src/pe.rs` now does dynamic section layout
(RVAs = `align_up(prev_end)` + correct `SizeOfImage`); programs with
arbitrarily large `.text`/`.data` build and load on Win11. Shipped in
36056b4/2010507/7cf7390 (on `main`); `tests/pe_layout.rs` locks it.

## Phase A: >4 args + function pointers (2026-05-18) — DONE

Win64 stack-arg ABI (args ≥5 at `[rsp+32+8*(i-4)]`; params ≥5 from
`[rbp+16+8*i]`; ≤4-arg/io functions byte-identical, regression-proven)
+ function pointers (`Type::Fn`, `Expr::CallPtr`, targeted fn-ptr
declarator, `RipRef::Func` decay, `call rax`). `Gen::named_fnptr` =
single source of truth for fn-ptr-var lowering + typing. Oracle
`tests/calling.rs` 10/10 + O2/O3 corpus `manyargs.c`/`funcptr.c`.
Commit 77d3872. 179 tests green; clippy clean. Code review
APPROVE-WITH-NITS (MINOR#1 fixed; MINOR#2 = release temp-overflow
silent corruption → tracked backlog, see `JRN - Roadmap to OWL`).
Next: Phase B (virtual functions/vtables).

## Phase C: Win32 runtime substrate (2026-05-18) — IN PROGRESS

HLD: `wrk_docs/2026.05.18 - HLD - Phase C (Win32 runtime substrate).md`.
- C1a [DONE]: `WIN32_IMPORTS` table + used-set scan + `RipRef::Import`
  → `String`; console `.idata`/stub byte-identical (`tests/pe_imports.rs`
  golden lock).
- C1b [DONE]: multi-descriptor `.idata` (one descriptor per used DLL);
  `tests/pe_imports.rs` multi-DLL structural test.
- C2 [DONE]: subsystem + entry selection. `codegen::Entry`
  {ConsoleMain, GuiWinMain} on `Module`; detected in `compile_module`
  (`main`→console, `WinMain`→GUI, BOTH→hard `CodegenError`, NEITHER→
  existing "no main" error). `pe.rs`: `GUI_STUB_LEN=0x28` + `stub_len()`
  selector used by the `.text` vsize pre-pass / `func_offsets` /
  `build_text`; GUI stub loads hInstance=IMAGE_BASE imm64 (no
  GetModuleHandleA import — `.idata` byte-identical for GUI too),
  hPrev=0, lpCmdLine=0, nCmdShow=1, `call WinMain`, `mov ecx,eax`,
  `call [ExitProcess]`; subsystem 2/3 by entry. Console path literally
  unchanged (byte-identical, `tests/pe_imports.rs` not re-blessed; e2e
  88 unchanged). `tests/winmain.rs` 4/4: WinMain→exit 7 on the real OS
  loader, both-entries error, subsystem==2 / ==3 structural.
- C3 [DONE]: intrinsic `<windows.h>` body + `gen_call` Win32 import path.
  `pe.rs`: one entry `("MessageBoxA","USER32.dll")` appended to
  `WIN32_IMPORTS` (KERNEL32 six unchanged) + `pub(crate) is_win32_import`
  (single source of truth shared with codegen). `pp.rs`: `WINDOWS_H`
  intrinsic body returned only for the literal `windows.h` —
  UINT/DWORD/BOOL/HANDLE/HWND/HINSTANCE/HMODULE/HMENU=void*,
  LPSTR=char*, LPCSTR=const char* (const is parser no-op),
  WPARAM=unsigned __int64, LPARAM/LRESULT=__int64 (Win64 8-byte),
  empty WINAPI/CALLBACK/WINAPIV, CONST, MB_OK/OKCANCEL/ICONERROR/
  ICONINFORMATION; no MSG/WNDCLASS (Phase D). `codegen.rs`: `emit_call`
  marshalling tail extracted into shared `marshal_args`; new
  `emit_win32_call` = marshal + `emit_riprel(FF 15,
  RipRef::Import(name))`; `is_win32_import` (delegates to pe, same
  override guard as `is_builtin`) routed in `gen_call` after fn-ptr,
  before default `emit_call`. Console byte-identical (USER32 dormant
  unless referenced; pe_imports 3 not re-blessed, e2e 88 unchanged).
  `tests/win32_msgbox.rs` 3/3: GUI MessageBoxA PE has subsystem 2 +
  KERNEL32+USER32 descriptors importing MessageBoxA; intrinsic header
  typedefs/MB_* parse; console = exactly one KERNEL32 descriptor, no
  USER32, MessageBoxA not imported.
- C5 [DONE] (backlog B-4 fold-in): harness C++ mode. `tests/support/
  mod.rs` gains `enum Lang { C, Cpp }` + pure `parse_lang` (sibling of
  `parse_skip`, same first-15-lines scan, orthogonal to it, unit-tested
  `lang_directive_parsing`). `msvc_build_run`/`bcc32_accept`/`bcc32_ref`
  take `Lang`: `Cpp` ⇒ temp written as `t.cpp` AND explicit mode flag
  (cl `/TP`, bcc32 `-P`); `C` branch (default) literally unchanged —
  `t.c`, no flag, byte-for-byte same invocation (probes pass `Lang::C`).
  `tests/differential.rs` reads `parse_lang(&src)` per file. Flipped
  `tests/corpus/portable/virtual.c`: `// oracle: skip` header replaced
  with `// oracle: lang cpp` (no skip text left in first 15 lines).
  virtual.c needed NO portability edit — bcc32 5.5.1 pre-standard ARM
  C++ accepted it as-is; NO cross-compiler divergence. Three-way restored
  & green: O2 18/18, O3-accept 20/20, O3-behave 18/18 (all +virtual,
  were 15/17/15). Full suite green (lib 61, e2e 88 unchanged, calling
  11, differential 16, gui 2, pe_imports 3, pe_layout 2, printf 5,
  virtual 11+1ign, win32_abi 1, win32_msgbox 3, winmain 4); clippy -D
  warnings clean. Phase C complete (C1–C5).

## Phase F: floating-point (2026-05-18) — IN PROGRESS

HLD: `wrk_docs/2026.05.18 - HLD - Phase F (floating point).md`.
- F-1 [DONE]: AST + lexer + parser + Type-arm sweep (compile-only;
  no FP codegen yet — F-2 lands the literal pool + arithmetic).
  AST: `Type::Float { bytes: u8 }` (bytes∈{4,8}, with `is_float()`
  accessor; size/align via `bytes as usize`), `Expr::Float { value:
  f64, bytes: u8 }` (literal value at f64 precision, bytes = declared
  type at the site — float=4 narrows on store via `cvtsd2ss` in F-2,
  double=8 stores as is). Eq/PartialEq decision: dropped `Eq` from
  `Type`/`Expr` (and the structs that contain them: `Record`, `Field`,
  `VtSlot`, `TranslationUnit`, `Item`, `Function`, `Stmt`). `f64` has
  `PartialEq` but no `Eq`; the codebase uses `Type`/`Expr` only as
  values (no `HashMap<Type,_>` / `HashSet<Type>` / etc., confirmed by
  rg), so `Eq` was unused. `UnOp`/`BinOp` keep `Eq` (no Float fields).
  Lexer: unchanged — `TokenKind::Float(String)` already emits the raw
  lexeme (`f`/`F`/`l`/`L` suffix and `[eE]±N` exponent). Parser:
  `decl_specifiers` accepts `Keyword::Float`/`Keyword::Double`/
  `Keyword::Bool` (B-6 fold-in: bool ⇒ 1-byte unsigned int); `long
  double` folds to `double` (F-1 backlog: 80-bit deferred). Hard
  error on illegal combos (`signed float`, `float int`, `long float`,
  `float double`). `primary` parses `TokenKind::Float` ⇒ strips
  suffix, `str::parse::<f64>()`, traps over-range `inf` explicitly
  (`is_finite()` check; never silently `inf`). `at_decl`/
  `peek_is_type_after_lparen` updated for the new keywords.
  Codegen Type-arm sweep — the Rust compiler enforced exhaustiveness
  at **3 sites**: `type_code` (mangling: `f`/`d`/reserved `e`),
  `gen_expr` (Expr::Float ⇒ explicit CodegenError), `expr_type`
  (Expr::Float ⇒ `Type::Float { bytes }` — typing only). Six
  additional defence-in-depth guards added at silently-degradable
  paths (size-keyed or shape-keyed, not Type-keyed): `load_rax` +
  `store_at_rcx` + `convert` (now all return `Result`), `Stmt::Decl`
  (FP local), `global_image` (FP global), `run` (FP param/return).
  All emit `"float not yet supported … (Phase F-…)"` per house style;
  F-2/F-3 progressively upgrade. New `tests/floats.rs`: 10/10 green
  (float/double/long double/global/param decl errors, signed-float
  parse error, bool-as-int8 compiles, float-literal lex shapes
  including `1.`/`.5`/`1e10`/`2.5E-3`/`1.5f`/`100.0L`). Full suite
  green (lib 61, e2e 88 unchanged, calling 11, differential 16, gui
  18, pe_imports 3, pe_layout 2, printf 5, virtual 11+1ign,
  win32_abi 1, win32_msgbox 3, win32_window_surface 2, winmain 4,
  **floats 10**); clippy -D warnings clean. Next: F-2 (FP arithmetic
  + literal storage + globals + return).
- F-2 [DONE]: SSE2 scalar codegen — the first XMM-register / SSE2-
  instruction surface in mdbcc. **Double-only**: every encoding is
  `F2`-prefixed scalar-double (movsd / addsd / subsd / mulsd / divsd
  / ucomisd / cvtsi2sd / cvttsd2si); 4-byte `float` rides the same
  8-byte slot + 8-byte movsd path (genuine `movss`/`cvtsd2ss`/
  `cvtss2sd` deferred to F-future — no v1 test needs single-
  precision-distinct storage). xmm0 is the FP expression-value
  register (mirrors RAX); xmm1 is the binary-op second-operand
  scratch. xmm regs ≥ 8 unused ⇒ every encoding REX-free.
  Encodings (all 4 bytes unless noted): `movsd xmm0/1,[rbp+disp32]`
  `F2 0F 10 85/8D`; `movsd [rbp+disp32],xmm0` `F2 0F 11 85`;
  `movsd xmm0,[rax]` `F2 0F 10 00`; `movsd [rcx],xmm0` `F2 0F 11 01`;
  `movsd xmm0,[rip+disp32]` `F2 0F 10 05`; `addsd/subsd/mulsd/divsd
  xmm0,xmm1` `F2 0F 58/5C/59/5E C1`; `ucomisd xmm0,xmm1` `66 0F 2E
  C1`; `xorpd xmm0,xmm0` `66 0F 57 C0`; `cvtsi2sd xmm0,eax` `F2 0F
  2A C0`; `cvttsd2si eax,xmm0` `F2 0F 2C C0`. FP literal pool: per-
  function intern by `u64 = value.to_bits()` (Vec'd, deterministic
  order, NaN-aware); `compile_module` promotes each fn's literals to
  module globals named `.flit.<fn>.<i>` (8-byte IEEE-754 image in
  `.data`). The `RipRef::Data(idx)` references emitted by gen_expr
  already carry the *module-global* index — Gen.new takes a
  `globals_base: usize` pinning the starting index, so no post-pass
  fixup of the riprefs is needed. **No new `RipRef` variant; no PE-
  writer change** beyond initialising the new `CompiledFn.fp_literals`
  field. Zero literal special-case: `+0.0` ⇒ `xorpd xmm0,xmm0` (no
  pool entry; the `-0.0` sign bit goes through the pool because it
  is observable via `1.0/-0.0`). Unary `-x` for double: in-memory
  sign-bit XOR (spill xmm0, `xor byte [rbp-t+7], 0x80`, reload) —
  smaller delta than a `.rdata` sign-mask, same byte count. FP
  global init in `global_image`: `Type::Float` ⇒ `value.to_le_bytes
  ()` (or `(value as f32).to_le_bytes()` for `bytes:4`), `None`
  init ⇒ 8-byte zero. `expr_type` for `Binary{Mul/Div/Add/Sub, …}`
  now reports `Type::Float{8}` when either operand is FP (the C
  usual-arithmetic-conversion rule); comparisons still report
  `Type::int()`. Stmt::Return spills xmm0 (not rax) across dtor
  calls when `ret.is_float()`. `run` lifted the F-1 ret-Float guard;
  FP params still error (F-3). New `tests/floats.rs`: **15 green**
  (10 F-2 arithmetic/literal/global/cast tests + 5 F-1 regressions
  preserved: signed-float-error, fp_param-error, bool keyword/value,
  literal-shape coverage). Full suite green (lib 61, e2e 88 byte-
  identical, calling 11, differential 16, gui 18, pe_imports 3,
  pe_layout 2, printf 5, virtual 11+1ign, win32_abi 1, win32_msgbox
  3, win32_window_surface 2, winmain 4, **floats 15**); clippy -D
  warnings clean. Next: F-3 (FP function args — XMM0..3 + stack;
  F-c slot-positional ABI).
- F-3 [DONE]: Win64 FP ABI — XMM0..3 by position + >4-arg stack via
  GPR shuttle. Slot-positional rule encoded in `marshal_args` /
  `emit_indirect_call` per-arg `is_fp` record; FP params spill via
  ARG_SPILL_XMM in the prologue. Detailed entry in goal-loop journal
  Tick 25; floats 20 green; e2e 88 byte-identical.
- F-4 [DONE]: printf %f via hand-emitted dtoa. parse_fmt accepts
  'f'; 'g'/'G'/'e'/'E' return explicit "Phase F-5 deferred" errors;
  precision capped at 15 (HLD-acceptable). New helpers:
  `gen_fp_arg_into_tmp` (rejects non-FP arg cleanly — no silent int
  reinterpret), `fmt_float_spec` (mirrors `fmt_int_spec`'s pad logic
  inline — duplicate is intentional, keeps int byte-stream untouched
  for the 88-byte-identical e2e guarantee), `float_token` (the dtoa).
  Algorithm (HLD §F-h approach A, integer-split): spill xmm0 to slot
  → `btr rax,63; setc cl` extracts sign + clears magnitude →
  `cmp rax, 0x7FF0_0000_0000_0000`; ja=NaN, je=Inf; finite path:
  reload `xmm0=|x|`, mulsd by `10^prec` (FP literal pool), addsd 0.5
  (round-half-up), `cvttsd2si r64,xmm0` (REX.W variant: F2 48 0F 2C C0)
  → split via `div r10` (r10=10^prec) into (quot=int-part, rem=
  frac-digits); build text r9..r11 backward with `.` injected at the
  prec boundary; prepend '-' from sign slot. NaN → "nan" (no sign);
  Inf → "inf" or "-inf". New X86-64 const: `MOVSD_XMM1_FROM_RIP`
  (F2 0F 10 0D). Sign-byte held in a stack tmp (r12-r15 are Win64
  callee-saved and `run`'s prologue doesn't push them). New O1 tests
  in `printf_format.rs` (printf_f_basic, _precision_0_to_10,
  _negative, _zero, _inf_nan, _width_padding, _combined — 7 new,
  total 12) + extended deferred-features (g/G/e/E + prec>15 + non-FP
  arg). New O2/O3 differential corpus `tests/corpus/portable/
  printf_float.c` (dyadic-rational inputs only — bcc32 prints
  `1.#INF`/`1.#NAN`, so inf/nan live in O1 only). All 12 dyadic-
  rational inputs three-way byte-exact. Full suite green: lib 61,
  e2e 88 byte-identical, calling 11, differential 16, floats 20,
  gui 18, pe_imports 3, pe_layout 2, printf_format 12 (was 5, +7),
  virtual 11+1ign, win32_abi 1, win32_msgbox 3, win32_window_surface
  2, winmain 4. clippy -D warnings clean. Next: F-5 (independent
  review + apply-feedback + phase closeout).

## Known limitations / deferred (revisit later)
- Lexer: mid-token backslash-newline splice only handled at whitespace/string level
  for now (full translation-phase-2 splice deferred). Float literals lex as raw
  lexeme (TokenKind::Float(String)); parser turns suffixed forms into
  `Expr::Float { value: f64, bytes }` (4/8). 80-bit `long double` deferred
  (Phase F backlog F-1) — currently folded to double.
- Type system done for scalars/pointers/arrays/globals/struct/union/enum/
  typedef. NOT yet: struct/union by value (param/return — errors clearly,
  use a pointer); function pointers; float/double; brace/aggregate
  initializers (`{...}`) for **file-scope globals** (J-9b deferred; the
  block-scope path landed in tick 57 — `int a[5] = {1,2,3,4,5};`,
  nested structs, deduced size, partial-init all work locally);
  designated init `{.x = 3}` / empty brace `T x = {};` / C++11 ctor
  brace-init `T x{a,b};` (all J-9c deferred); bitfields; >4 args;
  block-scope shadowing; variadic user functions. `printf` is still a string-literal-only builtin
  (no format args). Prototypes parsed but not signature-checked. Compound
  assignment re-evaluates its lvalue (fine for side-effect-free lvalues).
  Struct layout is natural/MSVC (no `#pragma pack` yet).
  All slated for slices 12+.
- Preprocessor: recursion bounded by a name guard rather than full per-token
  hide sets, so a few standards corner cases of re-expansion differ; system
  <headers> are stubbed empty (our libc subset is intrinsic); single include
  dir for "...". Adequate for real Borland-era source; revisit if needed.

## Risks
- Scope is very large. Mitigation: strict vertical slices, each runnable+tested.
- C++ pre-standard (ARM) + Borland quirks are under-documented; will need the
  win16-api / x86 / dos-internals skills and period docs when we reach them.

## Phase H1 — struct-by-value parameters (2026-05-22)

**Classifier**: `classify_struct_for_win64(size) -> InReg(1|2|4|8) | HiddenPtr`.
Sizes 1/2/4/8 → InReg; everything else (incl. 3/5/6/7 and >8) → HiddenPtr.
Pure function — unit-tested.

**Caller side** (marshal_args, emit_indirect_call, emit_virtual_call):
- InReg: gen_expr(struct_arg) → rax = address; load struct bits via
  movzx/mov sized to {1,2,4,8} into rax; spill to tmp; tmp later loads
  into the slot's GPR (or stack slot).
- HiddenPtr: gen_expr(struct_arg) → rax = source address; emit_struct_copy
  from [rax] to caller's hidden buffer in by_value region; spill the buffer
  address into tmp; tmp later loads as a pointer into the slot.

**Hidden-buffer region (Pattern A)**: lives within the persistent frame,
rbp-relative. New Gen field `by_value_bytes: i32` tracks max-call's hidden-
ptr-arg total; added to `frame_fixed` in `run`. Region top = `frame_fixed`
(just below the temp pool + 32B slack); slots grow downward. A function
that never passes a HiddenPtr struct keeps `by_value_bytes == 0` ⇒ frame
byte-identical to pre-H1 (O1 guarantee).

**Callee side** (Gen::new): for each HiddenPtr struct param, rewrite the
local's type from `Type::Record{..}` to `Type::Ref(Box<Record>)`. The slot
holds the buffer's address; `gen_addr(Var)` already dereferences refs
(line 1122-1126); `expr_type` already peels refs (line 3601-3603); member
accesses Just Work. For InReg struct params, no type rewrite needed — the
8-byte ARG_SPILL writes the GPR (which holds the struct bits + zero pad)
into the slot, and the slot IS the struct's storage.

**Four rejection sites** (HLD names 2 but per-call dupes exist):
- `Gen::new` ~line 633 — only reject ret-record (H2 will lift); param check lifted.
- `marshal_args` ~2555, `emit_indirect_call` ~2173, `emit_virtual_call` ~1291
  all become decision branches.

Limitation deferred: no copy-ctor on caller, no dtor on callee for by-value
struct params. mdbcc has no copy-ctor synthesis yet; this is consistent with
its current Phase-B model. Filed as H-future-MINOR if needed.

## Phase H2 — struct-by-value RETURN values (2026-05-22)

**Classifier reused from H1**: sizes 1/2/4/8 → InReg (packed in RAX);
all other sizes (3/5/6/7, >8) → HiddenPtr (caller allocates result buffer,
passes its address as a synthetic FIRST arg in RCX; callee writes through
that pointer and returns it in RAX, per Microsoft convention — NOT SysV's
RAX+RDX pair).

**Caller side**: at gen_expr's Call/CallPtr/MethodCall arm, dispatch on
return type. For HiddenPtr: prepare_record_return_call allocs a result
buffer + spills its address into a `lead` tmp slot; the existing
`marshal_args(lead=Some(...))` shifts user args by 1 (rcx = hidden ptr,
rdx/r8/r9/stack = user args 0..n). For InReg: post-call, complete_-
record_return_call stores RAX bytes into a result buffer and lea's the
buffer's address into RAX. In both cases gen_expr's contract for record-
typed expressions ("address in RAX") is preserved.

**Callee side** (Gen::new): when `f.ret` is HiddenPtr-classified, prepend
a synthetic hidden_result_off slot at RBP offset 8; user param/local
offsets begin at 16 (instead of 0). The prologue spills RCX into the
hidden slot, then shifts user-param spills by +1 register slot. Stmt::-
Return for record-typed return values dispatches on classifier: InReg →
pack n bytes from [rax] into rax; HiddenPtr → memcpy from [rax] (source)
through *[rbp-hr] (caller's buffer), then `mov rax, [rbp-hr]`.

**Frame layout extension (Pattern A)**: new region `result_buf_*` lives
above `by_value_*` in the frame. Stack-disciplined cursor: alloc_result_buf
bumps; explicit free at each consumer site (maybe_free_record_call_result).
Functions never returning records keep result_buf_max == 0 ⇒ frame is
byte-identical to pre-H2 (gates the O1 88 byte-identity contract — verified
empirically).

**Edge case — virtual record-returning methods**: explicit reject in
gen_expr's MethodCall arm. Chained `lead` (hidden_result + this) would
need a wider refactor of emit_virtual_call; H2 tests don't require it,
defer to a future increment.

**Edge case — record-returning Call's address taken via Member/Index**:
e.g. `bar(make().a)`. gen_addr now accepts Call/MethodCall when the
result is a record, but the Member/Index consumer doesn't free the
result_buf. This LEAKS one buffer per such call site; bounded; not a
correctness bug (just minor stack pressure). H2 tests avoid this pattern.

Mechanism summary for the slot shift in marshal_args/emit_indirect_call/
emit_virtual_call: `base = lead.is_some() as usize` already gave 1 for
methods that pass `this` via lead. H2 reuses this exactly: a HiddenPtr-
returning Call pre-allocates a result buffer, spills its address into a
tmp, passes that tmp as `lead`. The slot indices then naturally start at
1 (rdx) for user args, matching Microsoft's hidden-result-arg-first
convention.

## Phase H H3 — exception syntax (parse-only) [2026-05-22, tick 39]

Tiny contained increment per HLD §H3. Lexer ALREADY tokenises
`Keyword::Throw|Try|Catch` (lexer.rs:73-76,680-688) — confirmed. Parser
needs to consume them; codegen rejects cleanly with a Grep-able phrase
that next tick (H4a) replaces with SEH emission.

AST additions (src/ast.rs):
- `Stmt::Throw(Option<Expr>)` — `Some(expr)` is `throw expr;`,
  `None` is bare `throw;` (rethrow; runtime-check deferred to H4a).
- `Stmt::Try { body: Vec<Stmt>, catches: Vec<CatchClause> }`.
- `pub struct CatchClause { kind: CatchKind, body: Vec<Stmt> }`.
- `pub enum CatchKind { All, Typed { ty: Type, name: Option<String> } }`.

Parser additions (src/parser.rs):
- `statement()`: dispatch `Keyword::Throw` → `throw_statement()`;
  `Keyword::Try` → `try_statement()`.
- `throw_statement()`: bare `;` ⇒ rethrow; else expression then `;`.
- `try_statement()`: `try` `{` block `}` then 1..N catch clauses.
- `catch_clause()`: `catch` `(` ( `...` | decl-specs + opt declarator )
  `)` `{` block `}`. Reuses `decl_specifiers`/`declarator` for type.

Codegen rejection (src/codegen.rs):
- `Stmt::Throw` and `Stmt::Try` arms in `gen_stmt`: both return
  `CodegenError("exception runtime not yet supported (Phase H4); throw/try/catch parse but cannot compile yet")`.
- `collect_decls` and `uses_io`: extend to descend into Try body +
  catch bodies; Throw evaluated like other expression-bearing stmts.

Rejection phrase (EXACT — for H4a Grep):
  `exception runtime not yet supported (Phase H4); throw/try/catch parse but cannot compile yet`

Test plan (tests/cpp_exceptions.rs, NEW): 13 tests
  parser happy 1-8, parser-error 9-11, codegen-reject 12-13.
Tests drive `Parser::parse(&Lexer::tokenize(src)?)` for parse asserts
(no PE built); use `compile_to_pe` for the codegen-reject pair to
ensure the whole pipeline propagates the error.

## Phase H H4a — int-only SEH runtime [2026-05-22, tick 40]

The largest single H increment per HLD risk register. Lands the full
Win64 SEH unwind path for `throw <int-expr>;` + `try {…} catch (int e)
{…}`. All 17+ tests green on Windows 11; e2e 88 still green; no other
suite regresses.

**EXCEPTION_MDBCC_INT = `0xE0000001`** (Sev=ERROR, C=customer, Code=1).

**Throw lowering** (gen_throw_int, codegen.rs:1304-1359): evaluates
int expr → spills to stack tmp → calls `RaiseException(0xE0000001, 0,
1, &tmp)` via the standard `emit_riprel` IAT path → `ud2` after for
defence-in-depth. The OS records the slot's VALUE (not address) into
`ExceptionInformation[0]` because RaiseException copies `*lpArguments`
by value into the EXCEPTION_RECORD (the docs are explicit; this is the
ONE bug that took the longest to debug).

**Try lowering** (gen_try, codegen.rs:1380-1450): records
(try_begin, try_end, handler) function-relative code offsets in a
new `CompiledFn.try_scopes: Vec<TryScope>`. Catch parameter slot is
allocated up-front by `collect_decls` (new path that descends into
`Stmt::Try.catches`). Body emits a `jmp` past the catch on normal
completion; catch landing pad's FIRST insn is `mov [rbp-slot], eax`
(the personality function transfers control here with rax = thrown int
via RtlUnwindEx's ReturnValue).

**`.pdata` / `.xdata` plumbing** (pe.rs:build_pdata + build_xdata,
write_pe_with_rsrc wire-up): two new sections, conditional on
`module.funcs.any(!try_scopes.is_empty())`. RUNTIME_FUNCTION array
covers EVERY function in the module (sorted by RVA via module order).
UNWIND_INFO uses the standard mdbcc prologue opcodes (PUSH_NONVOL rbp
@ offset 1 + ALLOC_SMALL/LARGE @ offset 0xB — sub_rsp imm decoded
from the function's emitted bytes by `read_prolog_alloc`). Try-bearing
funcs get UNW_FLAG_EHANDLER + scope table (4 B count + N × 16 B
entries). FrameRegister = 0 (rsp-relative unwind, NOT SET_FPREG —
mdbcc's `mov rbp,rsp` comes BEFORE `sub rsp`, which violates the
Microsoft ordering rule; rsp-relative works without SET_FPREG).

**Synthetic personality function** (build_personality_function,
codegen.rs:457-606): hand-emitted ~165 bytes of x86-64 with standard
mdbcc prologue (so .xdata describes it like any other function — no
special-case needed). Body:
  - Save rcx/rdx/r8/r9 to locals.
  - If `er->ExceptionCode != 0xE0000001` → return ContinueSearch.
  - If `er->ExceptionFlags & EH_UNWINDING (=2)` → ContinueSearch
    (phase-1 search only; phase-2 unwind walks back through us
    transparently).
  - Walk scope table at `dc->HandlerData`. For each scope, compare
    `dc->ControlPc` against `[ImageBase + try_begin, ImageBase +
    try_end]` (NOTE: inclusive upper bound — software exceptions
    raised by a call at the tail of a try body have ControlPc =
    address-AFTER-call = exactly try_end; strict-`<` boundary missed
    the cross-frame throw case, t19).
  - On match: extract thrown int from `ExceptionInformation[0]`
    (DIRECTLY — the int is IN the field, not behind another `*`),
    call `RtlUnwindEx(frame, handler_abs, er, thrown_int, ctx, NULL)`.
    RtlUnwindEx places ReturnValue in RAX before transferring to
    TargetIp, so the catch landing pad's `mov [rbp-slot], eax` gets
    the int directly.

**Frame size 0x60** (96): 32 shadow + 16 stack-arg slots ([rsp+32],
[rsp+40] for RtlUnwindEx's args 5+6) + 48 locals (5 saved-arg slots +
1 handler_abs scratch). FIRST attempt used 0x50 (80) — the [rsp+40]
write overlapped local [rbp-40] (handler_abs), corrupting the
TargetIp to 0 and crashing RtlUnwindEx with STATUS_ACCESS_VIOLATION.

**WIN32_IMPORTS** (pe.rs:182-200): appended `RaiseException` +
`RtlUnwindEx` (both KERNEL32). Per the dormancy-via-aggregation
pattern every Phase-C/D/E/G import follows, every KERNEL32-using
program now imports all eight (`pe_imports` golden re-blessed in
lockstep; the ONE consequence for non-throwing programs is a 16-byte
shift in the ExitProcess IAT slot — disp 0x104F → 0x105F). The
e2e 88 corpus stays green (no behavioural regression; the IAT
location changed but the dispatch is still through `call [rip+disp]`).

**Tests** (cpp_exceptions.rs 13 → 20):
  - 1-8 parser happy (unchanged from H3)
  - 9-11 parser errors (unchanged from H3)
  - 12-14 codegen rejection of H4b shapes: class catches, `catch(…)`,
    bare `throw;` (rethrow)
  - 15-16 structural (Windows-only): non-throwing TU has no `.pdata`
    / `.xdata` / DataDir[3]; try-bearing TU has all three with valid
    layout
  - 17-20 runtime (Windows-only): throw-catch-int (exit 5),
    nested try (exit 8), throw-across-frame (exit 42), try-without-
    throw fall-through (exit 11) — ALL GREEN on Win11

**Bugs hit + fixed**:
  1. Frame-size overlap (write to [rsp+40] clobbered [rbp-40]
     handler scratch) — `STATUS_ACCESS_VIOLATION`. Fix: frame
     0x50 → 0x60.
  2. `ExceptionInformation[0]` interpretation — initial code did
     `*(int*)EI[0]` thinking EI was an array of addresses; in fact
     RaiseException copies `*lpArguments` so EI[0] = the value
     itself. Fix: removed one dereference.
  3. Inclusive-vs-exclusive try_end — strict `<` missed cross-frame
     throws (`call boom()` as last try-body stmt → ControlPc = try_end
     exactly). Fix: `jae` → `ja` in personality scope test.
