//! End-to-end oracle: compile C source to a real Win64 `.exe`, execute it,
//! and assert the process exit code equals the value of `main`'s `return`
//! expression. This validates the entire pipeline (lex -> parse -> codegen ->
//! PE) against the operating system's own loader — the ground truth.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::compile_to_pe;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);

impl TempExe {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("mdbcc_t_{}_{}.exe", std::process::id(), n));
        TempExe(p)
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Compile a full translation unit, run it, return its process exit code.
fn run_src(src: &str) -> i32 {
    let exe = compile_to_pe(src.as_bytes()).expect("compile ok");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    status.code().expect("process returned an exit code")
}

/// Compile `int main(void){ return <expr>; }`, run it, return its exit code.
fn run_return(expr: &str) -> i32 {
    run_src(&format!("int main(void) {{ return {expr}; }}"))
}

/// Compile and run a program, returning (exit code, captured stdout bytes).
fn run_capture(src: &str) -> (i32, Vec<u8>) {
    let exe = compile_to_pe(src.as_bytes()).expect("compile ok");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let out = Command::new(&tmp.0)
        .output()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    (out.status.code().expect("exit code"), out.stdout)
}

#[test]
fn returns_constant() {
    assert_eq!(run_return("42"), 42);
    assert_eq!(run_return("0"), 0);
    assert_eq!(run_return("255"), 255);
}

// S5 #31: a Borland memory-model keyword (`near`/`far`/`huge`) between the
// `class`/`struct` keyword and the tag name. OWL's `_EXPORT` macro expands to
// `_CLASSTYPE` → `huge` under the 16-bit Turbo-C++ headers' memory model, so
// EVERY OWL class reaches the parser as `class huge TFoo { ... }`. bcc32
// ignores these obsolete keywords for the flat target; the class-head qualifier
// skip lets the class parse, lay out, and run identically. This single
// construct gated all 34 OWL sample apps (`<owl.h>` → applicat.h).
#[test]
fn memory_model_keyword_in_class_head_is_ignored() {
    let src = r#"
class huge Point { public: int x; int get() { return x; } };
struct far Box { int w; };
int main(void) {
    Point p; p.x = 7;
    struct Box b; b.w = 35;
    return p.get() + b.w;
}
"#;
    assert_eq!(run_src(src), 42);
}

// S5 #31: a function-POINTER / function-TYPE whose parameter list is a sole (or
// trailing) `...`. Unlike a free-function DEFINITION (which needs a named param
// to anchor `va_start`), a function TYPE carries no body, so `(*Fn)(...)` and
// `(*Fn)(T, ...)` are well-formed. Borland's RTL spells interrupt-vector
// callbacks this way — `void cdecl _chain_intr(void interrupt (far *)(...))` in
// `<windows.h>`, which gated all 34 OWL apps after the class-head fix.
#[test]
fn function_pointer_with_ellipsis_param_list_parses() {
    let src = r#"
typedef void (*IntrFn)(...);
typedef int (*Fmt)(const char*, ...);
void chain(void (*target)(...));
int main(void) {
    IntrFn f = 0;
    Fmt g = 0;
    return (f == 0 && g == 0) ? 42 : 0;
}
"#;
    assert_eq!(run_src(src), 42);
}

// S5 #23: a function-RETURNING-function-pointer declarator —
// `RET (* NAME(p1)) (p2)`. NAME is a function taking `p1` that returns a
// pointer to a function taking `p2`. The canonical case is `signal()`;
// Borland's dos.h spells `void interrupt(far * _dos_getvect(unsigned))(...)`,
// reached via OWL's WINDOBJ.H → OBJSTRM.H → dos.h — the next blocker after the
// fn-pointer `...` fix carried all 34 apps into dos.h. Parse-acceptance of the
// PROTOTYPE is what the OWL chain needs (apps never define these); the body
// (definition) form is a separate codegen path, out of scope here.
#[test]
fn function_returning_function_pointer_prototype_parses() {
    let src = r#"
void interrupt (far * _dos_getvect(unsigned n))(...);
int (*signal(int, void (*)(int)))(int);
char far * cdecl getmem(unsigned);
int main(void) { return 42; }
"#;
    assert_eq!(run_src(src), 42);
}

// S5 #31: the Borland 16-bit SEGMENT pointer modifier `_seg`/`__seg`. A no-op on
// the flat target (like `near`/`far`/`huge`), but — unlike those — not a lexer
// keyword, so `(void _seg *)` was misparsed as a declarator named `_seg`.
// dos.h's `MK_FP` macro — `((void _seg*)(seg) + (void near*)(ofs))` — pulls it
// into OWL via WINDOBJ.H → OBJSTRM.H → dos.h. Neutralized to nothing in the
// preprocessor so `int _seg *p` is `int *p` and the cast is a plain `(int *)`.
#[test]
fn segment_pointer_modifier_is_ignored() {
    let src = r#"
int main(void) {
    int x = 42;
    int _seg * p = (int _seg *)&x;
    return *p;
}
"#;
    assert_eq!(run_src(src), 42);
}

// S5 #31: Borland OWL's DDVT (Dynamic Dispatch Virtual Table) message-index
// member syntax `virtual RET m(args) = [ index-expr ];` — a Borland extension
// pervasive in OWL 1.x window classes (`= [WM_FIRST + WM_VSCROLL]`). It looks
// like a pure virtual (`= 0`) but the `[index]` makes it a message-dispatched
// method, NOT pure. mdbcc has no DDVT dispatch yet, so for parse-acceptance it
// consumes the bracketed index and records an ordinary (non-pure) method — this
// single construct carried the OWL sample-app corpus from 1 to 16 compiling.
#[test]
fn owl_ddvt_message_index_member_parses() {
    // The DDVT virtuals have no body (in real OWL they're dispatched by message
    // and resolved against the OWL library at link), so the class is NOT
    // instantiated here — the test asserts the `= [index]` SYNTAX parses and the
    // TU compiles + runs. The pure-virtual `= 0` path is covered elsewhere.
    let src = r#"
typedef struct { int x; } RTMessage;
class W {
public:
    int v;
    virtual void WMVScroll(RTMessage Msg) = [0x0000 + 277];
    virtual void WMSize(RTMessage Msg) = [5];
    virtual void EvCommand(RTMessage) = [0 + 273];
};
int main(void) { return 42; }
"#;
    assert_eq!(run_src(src), 42);
}

// S5 #31: a PURE-VIRTUAL conversion operator `virtual operator int() = 0;`
// (CLASSLIB's `ContainerIterator`). The conversion-operator member path handled
// `;` (out-of-line decl) and `{ body }` but not the `= 0` / `= [idx]` suffix the
// regular-method path accepts, so it errored "expected '{'". Now both paths
// share `member_pure_or_ddvt_suffix`. The abstract base is not instantiated
// here (no body / no vtable emission) — this asserts the declaration parses,
// compiles, and runs.
#[test]
fn pure_virtual_conversion_operator_parses() {
    let src = r#"
struct ContainerIterator {
    virtual operator int() = 0;
    virtual ~ContainerIterator() {}
};
int main(void) { return 42; }
"#;
    assert_eq!(run_src(src), 42);
}

// S5 #31: anonymous-union (and anonymous-struct) member PROMOTION. OWL's
// `TMessage` (WINDOBJ.H) splits the LPARAM via an anonymous union with a NAMED
// nested member — `Msg.LP.Hi`. The promoted members must resolve at the
// union's offset (an offset bug would silently misread — value-checked here:
// write the 32-bit word, read the two 16-bit halves through the overlapping
// `LP` view). `sizeof` must also stay correct (the union is one slot).
#[test]
fn anonymous_union_members_promote_and_overlap() {
    let src = r#"
struct M {
    unsigned short Message;
    union {
        unsigned int LParam;
        struct { unsigned short Lo; unsigned short Hi; } LP;
    };
};
int main(void) {
    struct M m;
    m.LParam = 0x000A0007;       /* Lo = 7, Hi = 10 */
    int viaUnion = (m.LP.Lo == 7) && (m.LP.Hi == 10);
    /* writing through LP.Hi must alias LParam's high half */
    m.LP.Hi = 20;
    int back = (m.LParam == 0x00140007);
    int szok = (sizeof(struct M) == 8);   /* 2 (+2 pad) + 4 */
    return (viaUnion && back && szok) ? 42 : 0;
}
"#;
    assert_eq!(run_src(src), 42);
}

// S5 #39-extension: a file-scope `const int` used as an ARRAY DIMENSION (and
// other constant contexts). `const_eval` can't resolve a const-int Var, so #39
// recorded `int_consts` and folded them in aggregate global inits; this extends
// the same substitution to `const_expr` (array dims, enum values, bit-field
// widths). OWL apps EDITTEST/PALTEST/TRANTEST: `char Buf[MAX_TEXTLEN]`,
// `BYTE RedVals[NumColors]`. Value-checked: the array must be sized by the
// folded constant and indexable across its full extent.
#[test]
fn const_int_as_array_dimension_folds() {
    let src = r#"
const int N = 4;
int arr[N] = { 10, 20, 30, 40 };
int main(void) {
    int total = 0;
    int i;
    for (i = 0; i < N; i = i + 1) total = total + arr[i];
    return (total == 100 && sizeof(arr) == 16) ? 42 : 0;
}
"#;
    assert_eq!(run_src(src), 42);
}

// S5 #41: a QUALIFIED base-method call `Base::method(args)` — the C++ idiom for
// invoking the base implementation (non-virtual dispatch). `at_decl` treated
// `Base::foo(...)` as a declaration of a variable named `Base::foo` of type
// `Base` (the qualified out-of-line-member declarator form), auto-invoking the
// `Base` ctor ⇒ "no matching overload for call to 'Base::Base'". Fixed in
// `at_decl`: a `::`-qualified component that is NOT a known type marks a
// qualified-id EXPRESSION, never a local declaration. RUN-verified that it
// dispatches to the base method on the correct `this` (sets v through the base
// subobject). This was the dominant remaining OWL sample-app blocker (~8 apps,
// e.g. BSCRLAPP's `TWindow::GetWindowClass(WndClass)`).
#[test]
fn qualified_base_method_call_dispatches() {
    let src = r#"
struct Base {
    int v;
    Base() { v = 0; }
    void setit(int x) { v = x; }
};
struct Derived : public Base {
    void setit(int x) { Base::setit(x + 1); }
};
int main(void) { Derived d; d.setit(41); return d.v; }
"#;
    assert_eq!(run_src(src), 42);
}

// S5: a destructor declared with an explicit `(void)` parameter list —
// `virtual ~T(void);` (POPUP's TSubWindow). A destructor takes no parameters;
// `(void)` is the empty list spelled out. mdbcc's dtor parser expected `()` and
// errored "expected ')'" on the `void`. Accepted in both the in-class
// declaration and the out-of-line definition paths.
#[test]
fn destructor_with_explicit_void_param() {
    let src = r#"
struct S {
    int v;
    S() { v = 42; }
    virtual ~S(void);
};
S::~S(void) {}
int main(void) { S s; return s.v; }
"#;
    assert_eq!(run_src(src), 42);
}

// S5 #45: a file-scope pointer initialized to ANOTHER global's ADDRESS —
// `int *p = &target;` (the simplest case of the general global-init relocation
// mechanism #32 needs; CLASSLIB's `Object *Object::ZERO = &theErrorObject;`).
// global_image cannot const-fold `&global`, so this errored "global initializer
// must be a constant". Now recorded as `GlobalData.ptr_global` and the 8-byte
// slot is filled with the target's absolute address — an Addr64 reloc in the
// object writer, a post-layout patch in the standalone PE writer. VALUE-checked
// (a wrong address is a silent miscompile, b12): read through both pointers and
// confirm a store through one truly aliases its target.
#[test]
fn global_pointer_to_global_relocation() {
    let src = r#"
int target = 42;
int other = 7;
int *p = &target;
int *q = &other;
int main(void) {
    int viaP = (*p == 42);
    int viaQ = (*q == 7);
    *p = 100;                       /* must alias `target` */
    int aliased = (target == 100);
    return (viaP && viaQ && aliased) ? 42 : 0;
}
"#;
    assert_eq!(run_src(src), 42);
}

#[test]
fn small_copy_ctor_class_by_value_arg_compiles() {
    // S4.2ao (Task #17): a class with a non-trivial copy ctor must travel by
    // HIDDEN POINTER per the Win64 ABI, even at size <= 8 — NOT packed into a
    // GPR (which has nowhere for the copy ctor's `this` to point). Before this,
    // passing `H` (size 8, copy ctor) by value was a hard codegen ERROR
    // ("InReg-classified class with a copy ctor is not supported"). Now it
    // flows through the existing by-reference HiddenPtr path (which already
    // invokes the copy ctor — see the HiddenPtr arm in `marshal`).
    //
    // COMPILE-ONLY: this asserts the prior hard error is gone (the observable,
    // deterministic effect of S4.2ao). RUNTIME confirmation (`take(h)` == 42)
    // is blocked by Windows Defender, which DETERMINISTICALLY quarantines this
    // particular generated PE (os error 225, "contains a virus") in this dev
    // environment — the same false-positive that gates S7 run/diff. Correctness
    // rests on reusing the proven >8-byte HiddenPtr machinery (byte-identity
    // baselines exercise it). Promote to a run-assert once a Defender dev-dir
    // exclusion is in place.
    let src = b"\
        struct H {\n\
          int a; int b;\n\
          H(int x) { a = x; b = x; }\n\
          H(const H& o) { a = o.a; b = o.b; }\n\
        };\n\
        int take(H h) { return h.a + h.b; }\n\
        int main(void) { H h(21); return take(h); }\n";
    let _exe = compile_to_pe(src).expect("S4.2ao: copy-ctor class by value must compile");
}

#[test]
fn pointer_member_assign_is_scalar_not_operator_eq() {
    // S4.2ar: assigning to a POINTER member whose pointee class has an
    // `operator=` must be a SCALAR pointer assignment, NOT a rewrite to
    // `operator=` (has_op_method peels the Ptr to find the pointee's method).
    // Mirrors CSTRING.H's TSubString ctor `: s((string*)sp)` (a `string*` member;
    // `string` has operator=), which mis-rewrote and deferred "not an lvalue".
    // Here `Sub::p` is `Str*` and `Str` has an operator=; `p((Str*)sp)` must just
    // copy the pointer ⇒ sub.p->v == 42.
    let src = "\
        struct Str { int v; Str() { v = 0; } Str& operator=(const Str&); };\n\
        struct Sub { Str* p; Sub(const Str* sp) : p((Str*)sp) {} };\n\
        int main(void) { Str s; s.v = 42; Sub sub(&s); return sub.p->v; }\n";
    assert_eq!(run_src(src), 42);
}

#[test]
fn cstr_to_class_user_defined_conversion_for_ref_param() {
    // S4.2at: a `const char*` argument binds to a `const Record&` parameter via
    // the record's `const char*` constructor (a USER-DEFINED CONVERSION). The
    // conversion is INSERTED at the call site — a temp `SL("hi")` is
    // materialised (the record's ctor runs) and the reference bound to that,
    // NOT `&"hi"` reinterpreted as `SL&`. The unrelated `f(int,int)` overload is
    // dropped by exact-arity filtering. This is the CSTRING.H pattern that
    // gates CONTAIN/OPRPLUS: `find(const TRegexp&)` called with a `char*`.
    let src = "\
        struct SL { int v; SL(const char* s) { v = 7; } };\n\
        int f(const SL& s) { return s.v; }\n\
        int f(int a, int b) { return a + b; }\n\
        int main(void) { return f(\"hi\"); }\n";
    assert_eq!(run_src(src), 7);
}

#[test]
fn win64_cstr_to_by_value_class_user_defined_conversion() {
    // RailC Win64 spike: OWL's `TDialog(TWindow*, TResId, ...)` takes `TResId`
    // BY VALUE, while callers pass an `LPSTR`. Win32 already accepted this
    // shape; Win64 must construct the wrapper temp and feed it through the
    // existing struct-by-value argument lowering rather than rejecting overload
    // resolution or passing the raw pointer.
    let src = "\
        struct R { int v; R(const char* s) { v = s[0]; } };\n\
        int f(R r) { return r.v; }\n\
        int f(int a, int b) { return a + b; }\n\
        int main(void) { return f(\"A\"); }\n";
    assert_eq!(run_src(src), 65);
}

#[test]
fn direct_cstr_overload_beats_udc_to_class() {
    // S4.2at (correctness guard): a direct `const char*` parameter is a STANDARD
    // conversion and must BEAT the `const Record&` user-defined conversion
    // (C++ §13.3.3.2). `g(const char*)` returns 9; `g(const SL&)` (via UDC) would
    // return 7. `resolve_overload` scores lower=better — a standard conversion is
    // <=2, the UDC is 20 — so `g("hi")` MUST pick the `const char*` overload (9).
    let src = "\
        struct SL { int v; SL(const char* s) { v = 7; } };\n\
        int g(const SL& s) { return s.v; }\n\
        int g(const char* p) { return 9; }\n\
        int main(void) { return g(\"hi\"); }\n";
    assert_eq!(run_src(src), 9);
}

#[test]
fn file_scope_object_with_ctor_runs_static_init_before_main() {
    // S4.2b3 (#20 PART 2, single-TU): a file-scope object with a CONSTRUCTOR —
    // `S g(40, 2);` (direct-init, parsed by S4.2b2). Its storage is zero-filled
    // and the ctor `S::S(&g, 40, 2)` is prepended to `main`'s prologue, so the
    // object is constructed before any user code runs. g.a=40, g.b=2 ⇒ 42.
    // (Multi-TU / OWL library objects, which have no `main`, use the deferred
    // `.CRT$XCU` + CRT-walker path; they stay a clean error here, never a silent
    // unconstructed global.)
    let src = "\
        struct S { int a, b; S(int x, int y) { a = x; b = y; } };\n\
        S g(40, 2);\n\
        int main(void) { return g.a + g.b; }\n";
    assert_eq!(run_src(src), 42);
}

#[test]
fn derived_ctor_constructs_overloaded_base() {
    // S4.2b0: a derived class's ctor implicitly constructs its base. When the
    // base has an OVERLOADED ctor (here a default + a copy ctor), the parser-
    // injected base-default-construct `BaseC::BaseC(this)` must resolve to the
    // 0-arg default — but `resolve_overload` excludes the implicit `this`, so
    // the `[this]` chaining form (this counted as an arg) failed "no matching
    // overload" (a HARD error out-of-line; a silent inline DEFERRAL in-class).
    // Now ctor-chaining resolves on args[1..] with args[0] as the lead. The
    // base default ctor sets x=1, then Der's body sets x=3, y=4 ⇒ 3 + 4 == 7.
    let src = "\
        struct BaseC { int x; BaseC() { x = 1; } BaseC(const BaseC& o) { x = o.x + 50; } };\n\
        struct Der : BaseC { int y; Der(); };\n\
        Der::Der() { x = 3; y = 4; }\n\
        int main(void) { Der a; return a.x + a.y; }\n";
    assert_eq!(run_src(src), 7);
}

#[test]
fn synth_copy_ctor_chains_base_copy_ctor() {
    // S4.2b1 (J-10b-base-chain): a class needing a synth copy ctor (member `mm`
    // has a copy ctor) whose BASE also has its OWN copy ctor — the synth must
    // CHAIN into the base copy ctor on the base subobject (not byte-copy the
    // base fields). `Der b = a` ⇒ BaseC's copy ctor runs (b.x = 3 + 50 = 53),
    // Mem's copy ctor runs (b.mm.m = 0 + 7 = 7). 53 + 7 == 60.
    let src = "\
        struct BaseC { int x; BaseC() { x = 1; } BaseC(const BaseC& o) { x = o.x + 50; } };\n\
        struct Mem { int m; Mem() { m = 0; } Mem(const Mem& o) { m = o.m + 7; } };\n\
        struct Der : BaseC { Mem mm; Der() { x = 3; } };\n\
        int main(void) { Der a; Der b = a; return b.x + b.mm.m; }\n";
    assert_eq!(run_src(src), 60);
}

#[test]
fn synth_copy_ctor_polymorphic_installs_vptr() {
    // S4.2az (J-10b-base): a POLYMORPHIC class needing a synth copy ctor (a
    // member has a copy ctor). `build_synth_copy_ctor` must copy the trivial
    // base's re-laid fields, run the member's copy ctor, AND install this
    // class's vtable pointer on the copy (the hidden vptr is not a field).
    // `Derived d2 = d` ⇒ d2.b=9 (base field copied), d2.c.n=100 (Counter copy
    // ctor adds 100), and a virtual call on the COPY dispatches to
    // Derived::who()==2 (vptr installed). 100 + 2 + 9 == 111.
    let src = "\
        struct Counter { int n; Counter() { n = 0; } Counter(const Counter& o) { n = o.n + 100; } };\n\
        struct Base { int b; Base() { b = 5; } virtual int who() { return 1; } };\n\
        struct Derived : Base { Counter c; Derived() { b = 9; } virtual int who() { return 2; } };\n\
        int main(void) { Derived d; Derived d2 = d; Base* p = &d2; return d2.c.n + p->who() + d2.b; }\n";
    assert_eq!(run_src(src), 111);
}

#[test]
fn synth_copy_ctor_coexists_with_user_default_ctor() {
    // S4.2ay: a class with a USER ctor (here a default) AND a member that has a
    // copy ctor needs a SYNTHESISED copy ctor that COEXISTS with the user ctor.
    // Both are overloads of `C::C`; before this, the synth was registered in
    // `sigs.funcs` and CLOBBERED the user ctor — a `debug_assert` panic in debug,
    // a silent miscompile of default construction in release. Now the user ctor
    // is PROMOTED to the overload set and the synth added alongside, so `C a;`
    // (default) and `C b = a;` (synth copy) both resolve. a.mm.m=5 copied +1 ⇒ 6.
    let src = "\
        struct Mem { int m; Mem() { m = 0; } Mem(const Mem& o) { m = o.m + 1; } };\n\
        struct C { Mem mm; C() {} };\n\
        int main(void) { C a; a.mm.m = 5; C b = a; return b.mm.m; }\n";
    assert_eq!(run_src(src), 6);
}

#[test]
fn promoted_ctor_keeps_defaults_when_synth_copy_added() {
    // A class with one defaulted USER ctor and a copy-ctor-bearing member needs
    // the sole user ctor promoted from `funcs` into `overloads` before the
    // synthesised copy ctor is added. The promoted user ctor must keep its
    // default arg; the synth copy ctor must stay a distinct non-defaulted
    // candidate. `new C()` proves omitted defaults still resolve after
    // promotion, and `C copied = *a` proves the synth copy path still works.
    let src = "\
        struct Mem { int m; Mem() { m = 0; } Mem(const Mem& o) { m = o.m + 10; } };\n\
        struct C { Mem mm; int v; C(int x = 5) { v = x; mm.m = x; } };\n\
        int main(void) { C* a = new C(7); C* b = new C(); C copied = *a; return a->v + b->v + copied.mm.m; }\n";
    assert_eq!(run_src(src), 29);
}

#[test]
fn promoted_ctor_default_resolves_later_static_member_in_declaring_class() {
    // EDITX.CPP shape: a constructor default references a static data member
    // declared later in the same class. The class also needs constructor
    // promotion because a member has a copy ctor. The default is expanded from
    // Maker::make(), so a stale bare `Limit` would look for Maker::Limit and
    // fail with "no member named 'Limit'".
    let src = "\
        struct Mem { int m; Mem() { m = 0; } Mem(const Mem& o) { m = o.m + 10; } };\n\
        struct C {\n\
          Mem mm; int v;\n\
          C(int x = Limit + 1) { v = x; mm.m = x; }\n\
          static const unsigned Limit;\n\
        };\n\
        const unsigned C::Limit = 6;\n\
        struct Maker { C* make() { return new C(); } };\n\
        int main(void) { Maker maker; C* a = maker.make(); C copied = *a; return a->v + copied.mm.m; }\n";
    assert_eq!(run_src(src), 24);
}

#[test]
fn ctor_rvalue_receiver_overloaded_ref_param_marshals_correctly() {
    // S4.2aw: a method call on a ctor-RVALUE receiver whose OVERLOADED ctor takes
    // a REFERENCE parameter — `App(5, gm).Run()`. `marshal_args` indexes
    // `ptys[base + i]` (base=1 for the lead/`this`), but `gen_call_with_lead`'s
    // lead arm passed `ov.params` WITHOUT a leading `this` slot, so every
    // explicit arg was read against the NEXT param's type: arg `5` was treated as
    // the `M&` and `gen_addr(5)` failed "expression is not an lvalue". Now the
    // lead arm prepends a placeholder param slot (mirroring the method-call
    // path), so `5`→r (by value) and `gm`→by-ref (callee sets gm.v=88) ⇒
    // gm.v(88) + r(5) == 93. Pre-existing bug surfaced by HELLOAPP
    // (`TApplication("Hello World!").Run()`).
    let src = "\
        struct M { int v; };\n\
        struct App {\n\
          int r;\n\
          App(int n, M& m) { m.v = 88; r = n; }\n\
          App(const App& o) { r = o.r; }\n\
          int Run() { return r; }\n\
        };\n\
        int main(void) { M gm; gm.v = 1; int x = App(5, gm).Run(); return gm.v + x; }\n";
    assert_eq!(run_src(src), 93);
}

#[test]
fn default_arg_overloaded_ctor_scalar_defaults() {
    // S4.2av: an OVERLOADED ctor with TRAILING SCALAR defaults, called with
    // fewer args. resolve_overload's default-aware arity selects the 3-param
    // ctor (1∈[0,3]) over the copy ctor, and the call site APPENDS the two
    // omitted defaults. a=7 (given), b=20, c=30 (defaults) ⇒ 930. (The
    // HELLOAPP `TApplication("Hello")` shape — a multi-param all-defaulted ctor.)
    let src = "\
        struct A {\n\
          int a, b, c;\n\
          A(int x = 10, int y = 20, int z = 30) { a = x; b = y; c = z; }\n\
          A(const A& o) { a = o.a; b = o.b; c = o.c; }\n\
        };\n\
        int main(void) { A v(7); return v.a * 100 + v.b * 10 + v.c; }\n";
    assert_eq!(run_src(src), 930);
}

#[test]
fn default_arg_collision_free_per_overload() {
    // S4.2av: TWO same-named overloaded ctors that BOTH carry defaults (the
    // case the old source-name `fn_defaults` HashMap collapsed last-wins). The
    // collision-free `overload_defaults` list keeps each candidate's defaults,
    // matched by arity. `App("x")` (1 arg) selects the 2-param ctor (code=5
    // default), NOT the 5-param one ⇒ r == 5. If the collision were unfixed,
    // the 5-param ctor's defaults would corrupt the 2-param resolution.
    let src = "\
        struct M { int dummy; };\n\
        struct App {\n\
          int r;\n\
          App(int n, int code = 5) { r = code; }\n\
          App(int n, M& m, int a, int b = 9) { r = b; }\n\
        };\n\
        int main(void) { App a(1); return a.r; }\n";
    assert_eq!(run_src(src), 5);
}

#[test]
fn free_binary_operator_returning_record() {
    // S4.2au: a FREE (non-member) `operator+(const V&, const V&)` returning a
    // record. The member-only `overloaded_binop` missed free operators, so
    // `a + b` fell to a builtin and a record-returning `operator+` tripped
    // "cannot return a non-record expression" (the OPRPLUS.CPP blocker — its
    // `operator+` is a free `friend`). Now `a + b` routes through the normal
    // record-returning call path. `(a+b).n` == 7.
    let src = "\
        struct V { int n; V(int x) { n = x; } };\n\
        V operator+(const V& a, const V& b) { return V(a.n + b.n); }\n\
        int main(void) { V a(3); V b(4); return (a + b).n; }\n";
    assert_eq!(run_src(src), 7);
}

#[test]
fn free_binary_operator_with_cstr_udc_operand() {
    // S4.2au + S4.2at together — exactly the CSTRING.H concatenation shape
    // (`string + cp`): a free `operator+(const V&, const V&)` called with a
    // `const char*` right operand, which converts to `V` via V's `const char*`
    // ctor (user-defined conversion) BEFORE the operator runs. a.n=3, "hi"->V
    // (n=99), so `(a + "hi").n` == 3+99 == 102.
    let src = "\
        struct V { int n; V(int x) { n = x; } V(const char* s) { n = 99; } };\n\
        V operator+(const V& a, const V& b) { return V(a.n + b.n); }\n\
        int main(void) { V a(3); return (a + \"hi\").n; }\n";
    assert_eq!(run_src(src), 102);
}

#[test]
fn overloaded_method_nonfirst_overload_body_is_reachable() {
    // S4.2aq: reachability must walk ALL overloads' bodies for a source name,
    // not just one. A class with two `f` overloads where only the SECOND calls
    // an inline `use()` — the pruner emits both `C::f` once the name is reached,
    // so the second overload's body is emitted and references `use`; if
    // reachability walked only one (HashMap last-wins) body, `use` could be
    // pruned and left undefined at link. (This is exactly how the inline
    // `string::operator()(size_t,size_t)`'s `TSubString(...)` ctor edge was lost
    // across the string RTL.) Here `c.f(3,4)` ⇒ `use(7)` ⇒ sink = 14.
    // `use` declared BEFORE the `f` overloads so the in-class inline body's
    // `use(x+y)` sibling call rewrites to `this->use(...)` (it must be in the
    // class's `methods` set when the body is parsed).
    let src = "\
        int sink;\n\
        struct C {\n\
          void use(int z);\n\
          void f(int x) { sink = x; }\n\
          void f(int x, int y) { use(x + y); }\n\
        };\n\
        inline void C::use(int z) { sink = z * 2; }\n\
        int main(void) { C c; c.f(3, 4); return sink; }\n";
    assert_eq!(run_src(src), 14);
}

#[test]
fn null_pointer_constant_overload_resolution() {
    // S4.2an: the integer literal `0` is a null-pointer-constant (C++ §4.10) and
    // binds to a pointer PARAMETER during overload resolution. `h(0, 42)` has
    // arity 2, so only `h(E*, int)` is viable — `0` must bind to `E*`. Before
    // this, `arg_compat` (types only) rejected `int`→`E*`, so the call found no
    // viable overload. Mirrors STRING/CTOR1.CPP's `new TStringRef(0,0,0,0,cap)`
    // (the default `string()` ctor) — the prerequisite for registering ctors.
    let src = "\
        struct E {};\n\
        int h(E* p, int tag) { return p == 0 ? tag : -1; }\n\
        int h(int a, int b, int c) { return a + b + c; }\n\
        int main(void) { return h(0, 42); }\n";
    assert_eq!(run_src(src), 42);
}

#[test]
fn nested_type_return_out_of_line() {
    // S4.2al: a QUALIFIED NESTED TYPE used as the RETURN type of an out-of-line
    // member definition — `T::E T::get() { … }` — must not be mis-parsed as an
    // out-of-line ctor/dtor (the `Tag::` routing previously assumed any
    // `Tag::name` at declaration start was `Tag::Tag`/`Tag::~Tag`). Mirrors
    // CSTRING.H / STRING/STATUS.CPP's `TRegexp::StatVal TRegexp::status()`.
    // Returns the enumerator `B` == 1.
    let src = "\
        struct T {\n\
          enum E { A, B };\n\
          E get();\n\
        };\n\
        T::E T::get() { return B; }\n\
        int main(void) { T t; return t.get(); }\n";
    assert_eq!(run_src(src), 1);
}

#[test]
fn arithmetic_precedence_and_parens() {
    assert_eq!(run_return("(2 + 3) * 8 - 10"), 30);
    assert_eq!(run_return("100 - 7 * 9"), 37);
    assert_eq!(run_return("2 + 3 * 4"), 14);
}

#[test]
fn division_and_modulo() {
    assert_eq!(run_return("17 / 5"), 3);
    assert_eq!(run_return("17 % 5"), 2);
    assert_eq!(run_return("100 / 7 / 2"), 7);
}

#[test]
fn unary_operators() {
    // ~0 == -1 (0xFFFFFFFF as i32); !0 == 1; !5 == 0; double negate.
    assert_eq!(run_return("~0"), -1);
    assert_eq!(run_return("!0"), 1);
    assert_eq!(run_return("!5"), 0);
    assert_eq!(run_return("- -7"), 7);
}

#[test]
fn negative_result_is_dword_exit_code() {
    // 3 - 10 == -7  (Windows exit code is a DWORD; Rust reports it as i32).
    assert_eq!(run_return("3 - 10"), -7);
}

#[test]
fn comparison_and_bitwise_operators() {
    assert_eq!(run_return("3 < 5"), 1);
    assert_eq!(run_return("5 < 3"), 0);
    assert_eq!(run_return("7 == 7"), 1);
    assert_eq!(run_return("7 != 7"), 0);
    assert_eq!(run_return("0xF0 | 0x0F"), 0xFF);
    assert_eq!(run_return("0xFF & 0x0F"), 0x0F);
    assert_eq!(run_return("0xFF ^ 0x0F"), 0xF0);
    assert_eq!(run_return("1 << 10"), 1024);
    assert_eq!(run_return("-256 >> 2"), -64); // arithmetic shift (signed)
}

#[test]
fn short_circuit_logical_operators() {
    assert_eq!(run_return("1 && 2"), 1);
    assert_eq!(run_return("0 && 2"), 0);
    assert_eq!(run_return("0 || 5"), 1);
    assert_eq!(run_return("0 || 0"), 0);
    // RHS must not execute when LHS short-circuits: dividing by zero would
    // fault, so a result of 7 proves the `1/0` was never evaluated.
    assert_eq!(
        run_src("int main(void){ int x; x = 7; 1 || (1/0); return x; }"),
        7
    );
    assert_eq!(
        run_src("int main(void){ int x; x = 7; 0 && (1/0); return x; }"),
        7
    );
}

#[test]
fn locals_and_assignment() {
    assert_eq!(
        run_src("int main(void){ int a; int b; a = 6; b = 7; return a * b; }"),
        42
    );
    // Assignment is an expression yielding the assigned value.
    assert_eq!(
        run_src("int main(void){ int a; int b; b = (a = 5) + 1; return b; }"),
        6
    );
}

#[test]
fn if_else_control_flow() {
    let prog = "int main(void){ int x; x = 10; \
                if (x > 5) x = 100; else x = 200; return x; }";
    assert_eq!(run_src(prog), 100);
    let prog2 = "int main(void){ int x; x = 1; \
                 if (x > 5) x = 100; else x = 200; return x; }";
    assert_eq!(run_src(prog2), 200);
}

#[test]
fn while_loop_sum_1_to_100() {
    let prog = "int main(void){ int i; int s; i = 1; s = 0; \
                while (i <= 100) { s = s + i; i = i + 1; } return s; }";
    assert_eq!(run_src(prog), 5050);
}

#[test]
fn for_loop_factorial() {
    // 5! = 120
    let prog = "int main(void){ int f; int i; f = 1; \
                for (i = 1; i <= 5; i = i + 1) f = f * i; return f; }";
    assert_eq!(run_src(prog), 120);
}

#[test]
fn euclid_gcd() {
    // gcd(48, 18) = 6
    let prog = "int main(void){ int a; int b; int t; a = 48; b = 18; \
                while (b != 0) { t = b; b = a % b; a = t; } return a; }";
    assert_eq!(run_src(prog), 6);
}

#[test]
fn nested_loops_and_blocks() {
    // Sum over i*j for i,j in 1..=3  == (1+2+3)^2 = 36
    let prog = "int main(void){ int s; int i; int j; s = 0; \
                for (i = 1; i <= 3; i = i + 1) { \
                  for (j = 1; j <= 3; j = j + 1) { s = s + i * j; } } \
                return s; }";
    assert_eq!(run_src(prog), 36);
}

// ---- S3: switch / break / continue --------------------------------------
// Exit codes are the C-standard semantics (== what bcc32 produces); the
// i386 path is additionally diff-tested against bcc32 in tests/i386_run.rs.

#[test]
fn switch_basic_match_and_break() {
    let p = "int main(void){ int x=2,r=0; switch(x){ \
             case 1: r=10; break; case 2: r=20; break; default: r=99; } return r; }";
    assert_eq!(run_src(p), 20);
}

#[test]
fn switch_default_when_no_case_matches() {
    let p = "int main(void){ int x=5,r=0; switch(x){ \
             case 1: r=10; break; default: r=99; } return r; }";
    assert_eq!(run_src(p), 99);
}

#[test]
fn switch_fallthrough_without_break() {
    // case 1 has no break ⇒ falls through into case 2 (1 + 2 = 3).
    let p = "int main(void){ int x=1,r=0; switch(x){ \
             case 1: r+=1; case 2: r+=2; break; case 3: r+=4; } return r; }";
    assert_eq!(run_src(p), 3);
}

#[test]
fn switch_no_match_no_default_is_noop() {
    let p = "int main(void){ int x=7,r=0; switch(x){ \
             case 1: r=10; break; case 2: r=20; break; } return r; }";
    assert_eq!(run_src(p), 0);
}

#[test]
fn switch_default_in_middle_falls_through() {
    // No case matches 9 ⇒ enters default (50), then falls through to case 2
    // (+7) = 57. Proves the dispatch's fallback target and label ordering.
    let p = "int main(void){ int x=9,r=0; switch(x){ \
             case 1: r=1; break; default: r=50; case 2: r+=7; break; } return r; }";
    assert_eq!(run_src(p), 57);
}

#[test]
fn break_exits_for_loop_early() {
    let p = "int main(void){ int i,r=0; \
             for(i=0;i<10;i++){ if(i==3) break; r++; } return r; }";
    assert_eq!(run_src(p), 3);
}

#[test]
fn break_exits_while_loop_early() {
    let p = "int main(void){ int i=0,r=0; \
             while(i<100){ if(i==5) break; r++; i++; } return r; }";
    assert_eq!(run_src(p), 5);
}

#[test]
fn continue_skips_rest_of_for_body() {
    let p = "int main(void){ int i,r=0; \
             for(i=0;i<5;i++){ if(i==2) continue; r++; } return r; }";
    assert_eq!(run_src(p), 4);
}

#[test]
fn continue_inside_switch_targets_enclosing_loop() {
    // The C subtlety: `continue` inside a switch continues the LOOP, not the
    // switch. i=2 ⇒ continue (skipped), i=4 ⇒ +10 break, else +1 each:
    // 1+1+0+1+10+1 = 14.
    let p = "int main(void){ int i,r=0; \
             for(i=0;i<6;i++){ switch(i){ \
               case 2: continue; case 4: r+=10; break; default: r+=1; } } return r; }";
    assert_eq!(run_src(p), 14);
}

#[test]
fn switch_on_char_value() {
    let p = "int main(void){ char c='b'; int r=0; switch(c){ \
             case 'a': r=1; break; case 'b': r=2; break; default: r=9; } return r; }";
    assert_eq!(run_src(p), 2);
}

// ---- S3: preprocessor — macro calls crossing line / replacement boundaries
// (both are exercised constantly by the real <windows.h> HELLOWIN.C uses).

#[test]
fn macro_call_spanning_multiple_lines() {
    // A function-like macro invocation whose argument list crosses a newline
    // (HELLOWIN's `CreateWindow(...)` spans five physical lines).
    let p = "#define ADD(a,b) ((a)+(b))\n\
             int main(void){ return ADD(40,\n2); }";
    assert_eq!(run_src(p), 42);
}

#[test]
fn object_macro_expanding_to_function_like_macro_name() {
    // C99 §6.10.3.4 rescan across the replacement boundary: `G` → `F`, then
    // the *source* `(41)` invokes the function-like `F`. The real-header
    // shape is `#define MAKEINTRESOURCE MAKEINTRESOURCEA` then
    // `IDC_ARROW == MAKEINTRESOURCE(32512)`.
    let p = "#define F(x) ((x)+1)\n\
             #define G F\n\
             int main(void){ return G(41); }";
    assert_eq!(run_src(p), 42);
}

#[test]
fn chained_object_to_function_like_macro() {
    // A → B → C(...) resolves fully (the boundary rescan loops).
    let p = "#define C(x) ((x)*2)\n\
             #define B C\n\
             #define A B\n\
             int main(void){ return A(21); }";
    assert_eq!(run_src(p), 42);
}

// ---- S4.1b: function-template monomorphisation -------------------------
// Exit codes are the C++ semantics bcc32 produces; the i386 path is also
// diff-tested against bcc32 in tests/i386_run.rs.

#[test]
fn function_template_deduced_from_literals() {
    let p = "template<class T> T maxv(T a, T b){ return a>b?a:b; } \
             int main(){ return maxv(3, 7); }";
    assert_eq!(run_src(p), 7);
}

#[test]
fn function_template_deduced_from_variables() {
    let p = "template<class T> T maxv(T a, T b){ return a>b?a:b; } \
             int main(){ int x=20, y=8; return maxv(x, y); }";
    assert_eq!(run_src(p), 20);
}

#[test]
fn function_template_two_distinct_instantiations() {
    // add<int>(3,4)=7 and add<char>(1,2)=3 are SEPARATE monomorphisations of
    // one template ⇒ 10. Proves per-type-argument instantiation + caching.
    let p = "template<class T> T add(T a, T b){ return a+b; } \
             int main(){ int r = add(3,4); char c = add((char)1,(char)2); \
             return r + c; }";
    assert_eq!(run_src(p), 10);
}

#[test]
fn function_template_body_local_uses_param_type() {
    // The local `T tmp` is substituted to the deduced concrete type.
    let p = "template<class T> T pass(T a){ T tmp = a; return tmp; } \
             int main(){ return pass(42); }";
    assert_eq!(run_src(p), 42);
}

#[test]
fn function_template_nested_call_instantiates_chain() {
    // dbl<int> calls add<int>: an instantiation body itself names a template
    // ⇒ the monomorphiser must reach fixpoint.
    let p = "template<class T> T add(T a, T b){ return a+b; } \
             template<class T> T dbl(T a){ return add(a, a); } \
             int main(){ return dbl(21); }";
    assert_eq!(run_src(p), 42);
}

// ---- S4.2b(i): class-template capture (definition parses, not instantiated) --
// A `template<...> class Tag { ... };` is captured by SKIPPING its tokens, so a
// header that DEFINES class templates parses without the generic body polluting
// the concrete-codegen machinery. (Instantiation at use sites is a later stage.)

#[test]
fn class_template_definition_is_captured() {
    // The generic Box is captured (body not parsed); the program runs unaffected.
    let p = "template<class T> class Box { T v; public: T get(){ return v; } }; \
             int main(){ return 5; }";
    assert_eq!(run_src(p), 5);
}

#[test]
fn class_template_with_members_captured() {
    // A richer generic — multiple type params, ctor/dtor, members using `T*` and
    // a const method — captures without any `TemplateParam` reaching codegen.
    let p = "template<class T, class A> class Vec { T* data; unsigned n; public: \
             Vec() {} ~Vec() {} unsigned size() const { return n; } }; \
             int main(){ return 9; }";
    assert_eq!(run_src(p), 9);
}

#[test]
fn class_and_function_templates_coexist() {
    // A captured class template next to an instantiated function template.
    let p = "template<class T> class Holder { T x; }; \
             template<class T> T idfn(T a){ return a; } \
             int main(){ return idfn(7); }";
    assert_eq!(run_src(p), 7);
}

#[test]
fn class_template_forward_declaration_captured() {
    let p = "template<class T> class Fwd; \
             int main(){ return 3; }";
    assert_eq!(run_src(p), 3);
}

// ---- S4.2b(ii): class-template INSTANTIATION (use-site `Tag<args>`) ----------
// `Box<int>` re-parses the captured generic with T bound to int → a concrete
// record + member fns, run through the normal codegen. Exit codes are the C++
// semantics bcc32 produces. (One type-argument set per template for now; a
// second distinct instantiation is a clean error, not a silent collision.)

#[test]
fn class_template_instantiate_ctor_and_method() {
    let p = "template <class T> class Box { T value; public: \
             Box(T v) : value(v) {} T get() { return value; } }; \
             int main(){ Box<int> b(7); return b.get(); }";
    assert_eq!(run_src(p), 7);
}

#[test]
fn class_template_instantiate_data_members_and_method() {
    let p = "template <class T> struct Pair { T a; T b; T sum() { return a + b; } }; \
             int main(){ Pair<int> p; p.a = 3; p.b = 4; return p.sum(); }";
    assert_eq!(run_src(p), 7);
}

#[test]
fn class_template_instantiate_two_type_params() {
    let p = "template <class K, class V> struct Map { K k; V v; }; \
             int main(){ Map<int,char> m; m.k = 5; m.v = 9; return m.k + m.v; }";
    assert_eq!(run_src(p), 14);
}

#[test]
fn class_template_instantiation_is_cached() {
    // Two uses of the SAME instantiation share one concrete record (the second
    // `Box<int>` is a cache hit, not a re-instantiation/collision).
    let p = "template <class T> struct Box { T v; T get(){ return v; } }; \
             int set_and_get(){ Box<int> a; a.v = 6; return a.get(); } \
             int main(){ Box<int> b; b.v = 4; return b.get() + set_and_get(); }";
    assert_eq!(run_src(p), 10);
}

#[test]
fn class_template_two_distinct_instantiations() {
    // `Box<int>` and `Box<char>` are DISTINCT concrete records (each gets a
    // unique mangled tag, so the member symbols don't collide).
    let p = "template <class T> struct Box { T v; T get(){ return v; } }; \
             int main(){ Box<int> a; a.v = 5; Box<char> b; b.v = 3; \
                         return a.get() + b.get(); }";
    assert_eq!(run_src(p), 8);
}

#[test]
fn class_template_two_instantiations_with_methods() {
    // Each instantiation has its own method body; both are emitted and called.
    let p = "template <class T> struct Acc { T t; T add(T x){ t = t + x; return t; } }; \
             int main(){ Acc<int> i; i.t = 0; Acc<char> c; c.t = 0; \
                         return i.add(7) + c.add(3); }";
    assert_eq!(run_src(p), 10);
}

#[test]
fn class_template_with_type_parameter_base() {
    // `template<class A> struct Derived : public A` — the base is a TYPE
    // PARAMETER, bound to a concrete record at instantiation (the BIDS
    // `TVectorImpBase : public Alloc` shape). The base subobject + its inherited
    // member and method are present in the instantiation.
    let p = "struct Base { int b; int getb(){ return b; } }; \
             template<class A> struct Derived : public A { int d; }; \
             int main(){ Derived<Base> x; x.b = 5; x.d = 3; return x.getb() + x.d; }";
    assert_eq!(run_src(p), 8);
}

// ---- nested classes: out-of-line member definitions (multi-`::`) -----------
// mdbcc's class model is flat, so `Outer::Inner::member` is defined as the
// innermost class's member. A ctor/dtor (no return type) makes decl_specifiers
// eat the first qualifier as a base type; the declarator recovers it.

#[test]
fn nested_class_out_of_line_members() {
    let p = "struct Outer { struct Inner { int v; Inner(); int get(); }; }; \
             inline Outer::Inner::Inner() { v = 42; } \
             inline int Outer::Inner::get() { return v; } \
             int main(){ Inner x; return x.get(); }";
    assert_eq!(run_src(p), 42);
}

#[test]
fn new_with_overloaded_constructor() {
    // `new T(args)` resolves an OVERLOADED constructor by argument types (the
    // overloaded-ctor set lives in sigs.overloads, not sigs.funcs). BIDS/RTL
    // classes (TStringRef) have overloaded ctors invoked via `new`.
    let p = "struct P { int x; P(int a){ x = a; } P(int a, int b){ x = a + b; } }; \
             int main(){ P* p = new P(40, 2); return p->x; }";
    assert_eq!(run_src(p), 42);
}

#[test]
fn functional_cast_scalar() {
    // `Type(expr)` functional-cast for a scalar typedef name — CSTRING.H's
    // `const size_t NPOS = size_t(-1)`. Lowers to a C-style cast (const-folds).
    let p = "typedef int myint; int main(){ myint x = myint(42); return x; }";
    assert_eq!(run_src(p), 42);
}

#[test]
fn functional_cast_in_const_global() {
    let p = "typedef unsigned uns; const uns BIG = uns(7); \
             int main(){ return (int)BIG * 6; }";
    assert_eq!(run_src(p), 42);
}

#[test]
fn call_operator_by_name() {
    // Calling an overloaded operator by name inside a member — `operator==(x)`
    // ⇒ `this->operator==(x)` (CSTRING.H's TSubString delegates this way; the
    // operators there are declared in-class and defined out-of-line, so they're
    // known methods when the body parses).
    let p = "struct S { int v; int operator==(int x){ return v == x ? 9 : 0; } \
             int eq(int x){ return operator==(x); } }; \
             int main(){ S s; s.v = 5; return s.eq(5); }";
    assert_eq!(run_src(p), 9);
}

#[test]
fn global_scope_qualified_call() {
    // `::helper(m)` — a global-scope-qualified call from inside a method
    // (CSTRING.H's inline methods call `::AnsiToOem(...)` etc.).
    let p = "int helper(int x){ return x + 1; } \
             struct S { int m; int f(){ return ::helper(m); } }; \
             int main(){ S s; s.m = 41; return s.f(); }";
    assert_eq!(run_src(p), 42);
}

#[test]
fn out_of_line_constructor_with_init_list() {
    // An out-of-line ctor with a member-initializer list chains the base ctor
    // and sets members (CSTRING.H `string::outofrange::outofrange() : xmsg(..)`).
    let p = "struct Base { int b; Base(int x){ b = x; } }; \
             struct D : public Base { int d; D(); }; \
             D::D() : Base(40), d(2) {} \
             int main(){ D x; return x.b + x.d; }";
    assert_eq!(run_src(p), 42);
}

#[test]
fn class_template_type_parameter_base_inherited_method_mutates() {
    let p = "struct Counter { int n; void inc(){ n++; } }; \
             template<class A> struct Wrap : public A { int extra; \
                 int total(){ return n + extra; } }; \
             int main(){ Wrap<Counter> w; w.n = 0; w.extra = 4; \
                         w.inc(); w.inc(); return w.total(); }";
    assert_eq!(run_src(p), 6);
}

// ---- enum tag usable as a type name (without the `enum` keyword) ------------
// An enum's underlying type is `int`; its tag is now a usable type name so the
// C++ form `Color c;` works (CSTRING.H: `enum StripType{...}` then
// `strip(StripType s = Trailing)`). The `enum E` keyword form is unchanged.

#[test]
fn enum_tag_as_type_name() {
    let p = "enum Color { Red, Green, Blue }; \
             Color pick(Color c){ return c; } \
             int main(){ return pick(Blue); }"; // Blue == 2
    assert_eq!(run_src(p), 2);
}

#[test]
fn nested_enum_tag_as_member_param_type() {
    // The CSTRING.H pattern: a nested enum used as a member-function param type.
    let p = "struct S { enum E { A, B, C }; int f(E e){ return e; } }; \
             int main(){ S s; return s.f(C); }"; // C == 2
    assert_eq!(run_src(p), 2);
}

#[test]
fn fall_through_returns_zero() {
    assert_eq!(run_src("int main(void){ int x; x = 1; }"), 0);
}

#[test]
fn simple_function_call() {
    let prog = "int add(int a, int b) { return a + b; } \
                int main(void) { return add(40, 2); }";
    assert_eq!(run_src(prog), 42);
}

#[test]
fn four_argument_function() {
    let prog = "int f(int a, int b, int c, int d) { return a*1000 + b*100 + c*10 + d; } \
                int main(void) { return f(1, 2, 3, 4); }";
    assert_eq!(run_src(prog), 1234);
}

#[test]
fn recursive_factorial() {
    // 7! = 5040
    let prog = "int fact(int n) { if (n <= 1) return 1; return n * fact(n - 1); } \
                int main(void) { return fact(7); }";
    assert_eq!(run_src(prog), 5040);
}

#[test]
fn recursive_fibonacci() {
    // fib(15) = 610  (two recursive calls per frame; exercises arg temps)
    let prog = "int fib(int n) { if (n < 2) return n; return fib(n-1) + fib(n-2); } \
                int main(void) { return fib(15); }";
    assert_eq!(run_src(prog), 610);
}

#[test]
fn mutual_recursion_is_even() {
    // No prototype needed: the linker resolves calls by name after all
    // functions are laid out, so `is_odd` may reference `is_even` early.
    let prog = "int is_odd(int n) { if (n == 0) return 0; return is_even(n - 1); } \
                int is_even(int n) { if (n == 0) return 1; return is_odd(n - 1); } \
                int main(void) { return is_even(10) * 10 + is_odd(7); }";
    // is_even(10)=1, is_odd(7)=1  -> 11
    assert_eq!(run_src(prog), 11);
}

#[test]
fn cxx_reference_parameter_mutates_caller() {
    let src = "void inc(int& r) { r = r + 1; } \
               int main(void) { int a; a = 41; inc(a); return a; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn cxx_reference_local_alias() {
    let src = "int main(void) { int a; int& r = a; a = 5; r = r * 8; return a; }";
    assert_eq!(run_src(src), 40);
}

#[test]
fn cxx_reference_to_struct_member() {
    let src = "struct P { int x; int y; }; \
               void bump(int& v) { v = v + 10; } \
               int main(void) { P p; p.x = 1; p.y = 2; \
                 bump(p.x); bump(p.y); return p.x*100 + p.y; }";
    assert_eq!(run_src(src), 1112); // x=11, y=12
}

#[test]
fn cxx_class_ctor_and_methods() {
    let src = "class Counter { \
                 int n; \
               public: \
                 Counter(int s) { n = s; } \
                 void add(int d) { n = n + d; } \
                 int get() { return n; } \
               }; \
               int main(void) { Counter c(40); c.add(2); return c.get(); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn cxx_method_via_pointer_and_this() {
    let src = "struct Point { \
                 int x; int y; \
                 void set(int a, int b) { x = a; y = b; } \
                 int sum() { return this->x + y; } \
               }; \
               int main(void) { Point p; Point *q; q = &p; \
                 q->set(30, 12); return q->sum(); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn cxx_default_ctor_and_sibling_call() {
    let src = "class Acc { \
                 int t; \
               public: \
                 Acc() { t = 0; } \
                 void one() { t = t + 1; } \
                 int run() { one(); one(); one(); return t; } \
               }; \
               int main(void) { Acc a; return a.run(); }";
    assert_eq!(run_src(src), 3);
}

#[test]
fn cxx_new_delete_scalar() {
    let src = "int main(void) { int* p = new int; *p = 42; \
                 int r = *p; delete p; return r; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn cxx_new_scalar_direct_initializer() {
    let src = "int main(void) { int* p = new int(42); \
                 int r = *p; delete p; return r; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn cxx_new_class_ctor_and_method() {
    let src = "class Box { \
                 int v; \
               public: \
                 Box(int s) { v = s; } \
                 void add(int d) { v = v + d; } \
                 int get() { return v; } \
               }; \
               int main(void) { Box* b = new Box(40); \
                 b->add(2); int r = b->get(); delete b; return r; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn cxx_new_runs_ctor_delete_runs_dtor() {
    // The ctor (via `new`) sets *slot=1; the dtor (via `delete`) sets it 99.
    let src = "class Res { \
                 int* slot; \
               public: \
                 Res(int* s) { slot = s; *slot = 1; } \
                 ~Res() { *slot = 99; } \
               }; \
               int main(void) { int v; v = 0; \
                 Res* r = new Res(&v); \
                 if (v != 1) return 7; \
                 delete r; \
                 return v; }";
    assert_eq!(run_src(src), 99);
}

#[test]
fn cxx_raii_block_scope_reverse_order() {
    // Block exit destroys b then a: v: 0 -> *10+2=2 -> *10+1=21.
    let src = "class Tr { \
                 int* log; int id; \
               public: \
                 Tr(int* L, int i) { log = L; id = i; } \
                 ~Tr() { *log = *log * 10 + id; } \
               }; \
               int main(void) { int v; v = 0; \
                 { Tr a(&v, 1); Tr b(&v, 2); } \
                 return v; }";
    assert_eq!(run_src(src), 21);
}

#[test]
fn cxx_raii_destructor_runs_before_return() {
    // `s` is destroyed at bump()'s early return; its dtor adds 7 to v.
    let src = "class S { \
                 int* p; \
               public: \
                 S(int* q) { p = q; } \
                 ~S() { *p = *p + 7; } \
               }; \
               int bump(int* p) { S s(p); if (*p > 0) return 1; return 2; } \
               int main(void) { int v; v = 3; bump(&v); return v; }";
    assert_eq!(run_src(src), 10);
}

#[test]
fn cxx_raii_inner_block_destructs_early() {
    // ~M runs at the inner block's end, before `w = v * 10` executes.
    let src = "class M { \
                 int* p; \
               public: \
                 M(int* q) { p = q; } \
                 ~M() { *p = *p + 1; } \
               }; \
               int main(void) { int v; v = 0; \
                 { M m(&v); } \
                 int w; w = v * 10; \
                 return w + v; }";
    assert_eq!(run_src(src), 11);
}

#[test]
fn cxx_out_of_line_methods_header_style() {
    // Class declares prototypes; ctor/methods defined out of line.
    let src = "class Counter { \
                 int n; \
               public: \
                 Counter(int s); \
                 void add(int d); \
                 int get(); \
               }; \
               Counter::Counter(int s) { n = s; } \
               void Counter::add(int d) { n = n + d; } \
               int Counter::get() { return n; } \
               int main(void) { Counter c(40); c.add(2); return c.get(); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn cxx_out_of_line_ctor_dtor_sibling_call() {
    // Out-of-line ctor (member init), method with unqualified sibling
    // call, and out-of-line destructor observed via RAII at block scope.
    let src = "class Acc { \
                 int t; int* sink; \
               public: \
                 Acc(int* s); \
                 void one(); \
                 int run(); \
                 ~Acc(); \
               }; \
               Acc::Acc(int* s) { t = 0; sink = s; } \
               void Acc::one() { t = t + 1; } \
               int Acc::run() { one(); one(); one(); return t; } \
               Acc::~Acc() { *sink = t * 7; } \
               int main(void) { int v; v = 0; \
                 { Acc a(&v); int r = a.run(); } \
                 return v; }";
    assert_eq!(run_src(src), 21);
}

#[test]
fn cxx_operator_equality_member() {
    let src = "class Pt { \
                 int x; int y; \
               public: \
                 Pt(int a, int b) { x = a; y = b; } \
                 int operator==(Pt& o) { return x == o.x && y == o.y; } \
               }; \
               int main(void) { Pt a(3,4); Pt b(3,4); Pt c(3,9); \
                 int r = 0; \
                 if (a == b) r = r + 10; \
                 if (a == c) r = r + 1; \
                 return r; }";
    assert_eq!(run_src(src), 10);
}

#[test]
fn cxx_operator_plus_out_of_line() {
    let src = "class Money { \
                 int cents; \
               public: \
                 Money(int c); \
                 int operator+(Money& o); \
               }; \
               Money::Money(int c) { cents = c; } \
               int Money::operator+(Money& o) { return cents + o.cents; } \
               int main(void) { Money a(150); Money b(75); return a + b; }";
    assert_eq!(run_src(src), 225);
}

#[test]
fn cxx_operator_less_and_minus() {
    let src = "class N { \
                 int v; \
               public: \
                 N(int x) { v = x; } \
                 int operator<(N& o) { return v < o.v; } \
                 int operator-(N& o) { return v - o.v; } \
               }; \
               int main(void) { N a(7); N b(10); \
                 int r = 0; \
                 if (a < b) r = b - a; \
                 return r; }";
    assert_eq!(run_src(src), 3);
}

#[test]
fn member_operator_chains_through_reference_result() {
    // A chained member operator: `m << 1 << 2 << 3` parses as
    // `((m << 1) << 2) << 3`. Each `operator<<` returns `MAcc&`, so the inner
    // result types as `Ref(Record)`. `overloaded_binop` must look THROUGH the
    // reference to re-find the member operator for the next `<<`. Before the
    // fix it matched only a bare `Record`, so the chained `<<` fell to the
    // builtin integer-shift path — a SILENT MISCOMPILE that "compiled" but
    // returned the wrong value (1, not 6). RUN-verified value, not just
    // compilation — exactly the kind of bug only execution catches.
    let src = "struct MAcc { int sum; \
                 MAcc& operator<<(int v) { sum += v; return *this; } }; \
               int main(void) { MAcc m; m.sum = 0; m << 1 << 2 << 3; return m.sum; }";
    assert_eq!(run_src(src), 6);
}

#[test]
fn redeclared_free_operator_is_not_self_ambiguous() {
    // A free `operator<<` DECLARED twice then defined — exactly how
    // CLASSLIB/OBJSTRM.H declares each `operator<<(opstream&, <int>)` (a
    // `friend` declaration inside `opstream` plus an out-of-line `inline`
    // definition). The two registrations share one mangled symbol, so the
    // exact-match candidate tied with its own duplicate and resolution
    // wrongly reported "ambiguous". A redeclaration is one entity, never an
    // ambiguity: the call must resolve and run.
    let src = "struct Acc { int sum; }; \
               Acc& operator<<(Acc& a, int v); \
               Acc& operator<<(Acc& a, int v); \
               Acc& operator<<(Acc& a, int v) { a.sum += v; return a; } \
               int main(void) { Acc a; a.sum = 0; a << 10 << 20 << 12; return a.sum; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn reference_returning_free_operator_as_discarded_statement() {
    // A free `operator<<` returning `Acc&` used as an expression STATEMENT
    // (result discarded). The `T&` return is an address, not a by-value
    // record, so no result buffer is allocated — the consumer must not free
    // one (the cursor underflow that panicked codegen). `expr_type` decays
    // the `T&` to `T` for value typing, so the buffer-reclaim check reads the
    // raw return off the synthesised call instead.
    let src = "struct Acc { int sum; }; \
               Acc& operator<<(Acc& a, int v) { a.sum += v; return a; } \
               int main(void) { Acc a; a.sum = 0; a << 7; return a.sum; }";
    assert_eq!(run_src(src), 7);
}

#[test]
fn read_field_through_a_reference_member() {
    // `.` member access through a REFERENCE-to-record member. OWL's dialog
    // classes hold their option structs by reference (`TData& Data;`), so
    // `Data.Flags` is field access on a `Ref(Record)` base — which `field_of`
    // rejected as "non-struct". A reference is stored as a pointer, so this is
    // an implicit deref (like `->`). RUN-verified the VALUE is read THROUGH the
    // reference (42), not from the reference's own storage.
    let src = "struct D { int v; }; \
               struct Dlg { D& Data; Dlg(D& d) : Data(d) {} int g() { return Data.v; } }; \
               int main(void) { D d; d.v = 42; Dlg dlg(d); return dlg.g(); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn write_field_through_a_reference_member_hits_the_referent() {
    // The write counterpart: assigning through a reference member must land in
    // the REFERENT's storage, not the reference's own slot — a wrong pointer
    // load here would be a silent miscompile. `d.v` reads back 99 only if the
    // store dereferenced the reference correctly.
    let src = "struct D { int v; }; \
               struct Dlg { D& Data; Dlg(D& d) : Data(d) {} void s(int x) { Data.v = x; } }; \
               int main(void) { D d; d.v = 0; Dlg dlg(d); dlg.s(99); return d.v; }";
    assert_eq!(run_src(src), 99);
}

#[test]
fn qualified_static_data_member_access() {
    // `ClassName::staticMember` from outside a method. A static data member
    // lives at global scope as `Tag::name` (the out-of-line def registers it),
    // but the parser FLATTENED the qualified id to the bare `name`, dropping
    // the qualifier ⇒ "use of undeclared identifier". Now a qualified non-call,
    // non-enum-constant id keeps `Tag::name` so codegen resolves the global.
    // (OWL GDI's TColor::Black/White etc. are exactly this shape.)
    let src = "struct C { static int x; }; \
               int C::x = 5; \
               int main(void) { return C::x; }";
    assert_eq!(run_src(src), 5);
}

#[test]
fn qualified_static_class_typed_member_access() {
    // The class-typed variant (TColor::Black is a `static const TColor`):
    // `Tag::member` resolves to the record-typed global, and a field read off
    // it reaches the right bytes.
    let src = "struct TColor { int v; static const TColor Black; }; \
               const TColor TColor::Black = {7}; \
               int main(void) { return TColor::Black.v; }";
    assert_eq!(run_src(src), 7);
}

#[test]
fn explicit_cast_invokes_user_conversion_operator() {
    // `(T)record` where the class declares `operator T()` must INVOKE the
    // conversion operator. The Cast codegen previously ran `convert(Record,T)`,
    // which treated the record's ADDRESS as the value — a SILENT MISCOMPILE
    // (`(int)c` returned stack garbage, not the operator's result). OWL's
    // TColor has `operator COLORREF()`; this is the general primitive behind
    // the color comparisons. RUN-verified the operator's value (9) is returned.
    let src = "struct C { int v; operator int() const { return v; } }; \
               int main(void) { C c; c.v = 9; return (int)c; }";
    assert_eq!(run_src(src), 9);
}

#[test]
fn builtin_binary_op_coerces_record_via_conversion_operator() {
    // `Value == o` where `Value` is a builtin member and `o` is a record with
    // `operator int()` — exactly TColor::operator==' s body (`Value == clrVal`,
    // clrVal a TColor with `operator COLORREF()`). gen_binary now coerces the
    // lone record operand through its conversion operator and retries as a
    // builtin compare. Was a silent-garbage compare. RUN-verified both ways.
    let eq = "struct C { int Value; operator int() const { return Value; } \
                bool eq(const C& o) const { return Value == o; } }; \
              int main(void) { C a; a.Value=5; C b; b.Value=5; return a.eq(b) ? 7 : 0; }";
    assert_eq!(run_src(eq), 7);
    let ne = "struct C { int Value; operator int() const { return Value; } \
                bool eq(const C& o) const { return Value == o; } }; \
              int main(void) { C a; a.Value=5; C b; b.Value=6; return a.eq(b) ? 7 : 0; }";
    assert_eq!(run_src(ne), 0);
}

#[test]
fn const_int_constants_fold_in_aggregate_global_init() {
    // S4.2#39: a file-scope `static int a[] = { X|Y, ... }` where X/Y are
    // `const int` (not enum) constants — the elements must const-fold. const_eval
    // can't resolve a const-int Var, so this errored "global initializer must be
    // a constant" (OWL's DOCVIEW/FILEDOC/STGDOC `PropFlags[]`). Now the parser
    // folds known const-int Vars inside an AGGREGATE global init (byte-safe:
    // scalar inits keep the #29 path; only aggregate-init subtrees fold).
    let src = "const int A = 1; const int B = 2; const int C = 4; \
               static int arr[] = { A|B, B|C, A }; \
               int main(void) { return arr[0] + arr[1]; }";
    assert_eq!(run_src(src), 9); // (1|2)=3 + (2|4)=6 = 9
}

#[test]
fn dynamic_cast_checked_downcast() {
    // S4.5 RTTI: `dynamic_cast<D*>(b)` — a runtime checked downcast (OWL's
    // TYPESAFE_DOWNCAST). A valid downcast (b points to a D) yields a usable
    // D*; an invalid one (b points to a plain B) yields null. The walk follows
    // the object's vtable base-chain (descriptor at `vptr-8`) for D's vtable.
    // RUN-verified VALUE, not just compilation — a wrong downcast (non-null on
    // failure) is the exact b12 silent-miscompile hazard this guards.
    let src = "struct B { virtual ~B() {} virtual int who() { return 1; } }; \
               struct D : B { int who() { return 2; } int extra() { return 42; } }; \
               int main(void) { \
                 D d; B* b = &d; \
                 D* p = dynamic_cast<D*>(b); if (!p) return 99; \
                 int r = p->extra(); \
                 B bb; B* b2 = &bb; \
                 D* q = dynamic_cast<D*>(b2); if (q) return 98; \
                 return r; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn dynamic_cast_multilevel_inheritance() {
    // A←B←C: dynamic_cast to both C and B succeeds for a C object (the walk
    // climbs the chain); a cast of a plain A to C fails (null). Virtual
    // dispatch is unperturbed by the RTTI descriptor prefix.
    let src = "struct A { virtual ~A(){} }; \
               struct B : A { virtual int f(){return 1;} }; \
               struct C : B { int f(){return 7;} }; \
               int main(void) { \
                 C c; A* a = &c; \
                 C* p = dynamic_cast<C*>(a); if(!p) return 90; \
                 B* q = dynamic_cast<B*>(a); if(!q) return 91; \
                 A aa; A* a2=&aa; if(dynamic_cast<C*>(a2)) return 92; \
                 return p->f(); }";
    assert_eq!(run_src(src), 7);
}

#[test]
fn dependent_qualified_type_declaration_in_template_parses() {
    // #52: a DEPENDENT qualified-type used as the type of a declaration inside a
    // template body — `Base::Streamer strmr(base);` (Borland's OBJSTRM.H
    // WriteBaseObject). `Base` is a template type-parameter, so `Base::Streamer`
    // is a dependent type whose member need NOT be a globally-known type name;
    // `at_decl` previously mis-classified the statement as an expression and hit
    // "expected ';'". The template is NOT instantiated here, so this pins the
    // PARSE (codegen of an instantiation is the deeper, separate half of #52).
    let src = "struct OS{}; \
               template<class Base> void WriteBaseObject(Base* base, OS& out) { \
                 Base::Streamer strmr(base); (void)out; } \
               int main(void){ return 0; }";
    assert_eq!(run_src(src), 0);
}

#[test]
fn sizeof_string_literal_as_array_dimension() {
    // #39/S5: `sizeof("literal")` is a compile-time constant (length + NUL),
    // usable as an array dimension — CLASSLIB/VERSION.CPP has
    // `char id[sizeof(ID)]` with `#define ID "CLASSLIB"`. const_eval now folds
    // sizeof of a string literal; sizeof("CLASSLIB") == 9 (8 chars + NUL).
    let src = "char buf[sizeof(\"CLASSLIB\")]; int main(void){ return (int)sizeof(buf); }";
    assert_eq!(run_src(src), 9);
}

#[test]
fn wide_string_literals() {
    // #53: `L"..."` wide string literals. `wchar_t` is 2 bytes; the literal
    // carries its UTF-16LE bytes including the 2-byte NUL. RUN-verified across
    // every codegen path (the b12 hazard: a missed path silently miscompiles).
    // Pointer to a wide literal — p[0]/p[1] are the wide codes (0x41,0x42),
    // p[2] the NUL.
    assert_eq!(
        run_src("int main(void){ const wchar_t* p = L\"AB\"; return (int)p[0] + (int)p[1]; }"),
        131
    );
    assert_eq!(
        run_src("int main(void){ const wchar_t* p = L\"AB\"; return (int)p[2]; }"),
        0
    );
    // Array initialization byte-copies the UTF-16 content into the slot.
    assert_eq!(
        run_src("int main(void){ wchar_t b[] = L\"AB\"; return (int)b[0] + (int)b[1]; }"),
        131
    );
    // sizeof: L"X" is 1 char + NUL = 2 wchar_t = 4 bytes.
    assert_eq!(
        run_src("int main(void){ wchar_t b[] = L\"X\"; return (int)sizeof(b); }"),
        4
    );
    // Adjacent wide-literal concatenation: L"AB" L"C" -> 3 chars + NUL.
    assert_eq!(
        run_src("int main(void){ wchar_t b[] = L\"AB\" L\"C\"; return (int)sizeof(b); }"),
        8
    );
}

#[test]
fn bind_reference_to_record_ref_returning_method() {
    // #34/#8: `T& r = w.get();` where `get()` returns `T&` (a RECORD reference).
    // `gen_addr` now yields the referent's address for a reference-returning
    // method (record or scalar), so binding, address-of, and read/write through
    // the bound ref are correct. A prior attempt silently mis-READ through the
    // bound ref; this pins the fix with RUN-verified VALUES across every path
    // (b12 — the silent-miscompile hazard this exact case caused before).
    let d = "struct T{int v;}; struct W{T t; T& get(){return t;}};";
    // bind + read through the reference
    assert_eq!(
        run_src(&format!(
            "{d} int main(void){{ W w; w.t.v=42; T& r=w.get(); return r.v; }}"
        )),
        42
    );
    // address-of into a pointer
    assert_eq!(
        run_src(&format!(
            "{d} int main(void){{ W w; w.t.v=42; T* p=&w.get(); return p->v; }}"
        )),
        42
    );
    // write through the bound reference
    assert_eq!(
        run_src(&format!(
            "{d} int main(void){{ W w; T& r=w.get(); r.v=9; return w.t.v; }}"
        )),
        9
    );
    // two bound refs must alias their OWN distinct referents (5 in a, 7 in b)
    let d2 = "struct T{int v;}; struct W{T a,b; T& ga(){return a;} T& gb(){return b;}};";
    assert_eq!(
        run_src(&format!(
            "{d2} int main(void){{ W w; T& x=w.ga(); T& y=w.gb(); x.v=5; y.v=7; return x.v+y.v; }}"
        )),
        12
    );
}

#[test]
fn class_increment_operator_is_called_not_builtin() {
    // C++ `++obj`/`obj--` on a CLASS that declares operator++/-- calls THAT
    // operator, not a builtin scalar bump of the object's first bytes. The
    // builtin path silently miscompiled any non-trivial operator++ (here it
    // touches the 2nd member `b`, so the builtin — bumping `a` — left b at 0).
    // RUN-verified per b12 (this was a confirmed silent miscompile).
    let pre = "struct S{int a,b; S& operator++(){b+=10; return *this;}}; \
               int main(void){ S s; s.a=0; s.b=0; ++s; return s.b; }";
    assert_eq!(run_src(pre), 10);
    let post = "struct S{int a,b; S& operator++(int){b+=10; return *this;}}; \
                int main(void){ S s; s.a=0; s.b=0; s++; return s.b; }";
    assert_eq!(run_src(post), 10);
    // `&++obj` — the prefix operator returns T& (an lvalue), so address-of works
    // (CLASSLIB/USTRING `&++Null`); reuses the #34 ref-returning gen_addr path.
    let addr = "struct S{int v; S& operator++(){v++; return *this;}}; \
                int main(void){ S g; g.v=5; S* p=&++g; return p->v; }";
    assert_eq!(run_src(addr), 6);
    // builtin scalar ++/-- must be unchanged: ++i -> 6, then i-- yields 6 & i=5.
    assert_eq!(
        run_src("int main(void){ int i=5; ++i; int j=i--; return i*100+j; }"),
        506
    );
}

#[test]
fn value_initialize_class_without_constructor() {
    // C++ value-initialization: `Tag()` for a class with NO user-declared
    // constructor zero-initializes the object. mdbcc previously rejected it
    // ("class T has no declared constructor; T(args) requires one") — valid C++
    // wrongly refused. RUN-verified: all members zero.
    assert_eq!(
        run_src("struct X{int v;}; int main(void){ X x = X(); return x.v; }"),
        0
    );
    assert_eq!(
        run_src("struct X{int a,b,c;}; int main(void){ return X().a + X().b + X().c; }"),
        0
    );
    // a class WITH a constructor still runs it (the ctor path is unchanged).
    assert_eq!(
        run_src("struct X{int v; X(){v=5;}}; int main(void){ X x=X(); return x.v; }"),
        5
    );
}

#[test]
fn sizeof_local_variable_in_array_dimension() {
    // S5: `sizeof(localVar)` folds in a constant context (array dimension) — the
    // OWL/MODULE.CPP `char buf[sizeof(tmpl)+8]` idiom. const_expr resolves the
    // in-scope local's recorded type to its byte size (gated on fn_locals, so
    // file-scope dims are unaffected).
    // local array: `char tmpl[]="abc"` is char[4]; sizeof = 4, +2 = 6.
    assert_eq!(
        run_src(
            "int main(void){ char tmpl[]=\"abc\"; char buf[sizeof(tmpl)+2]; return (int)sizeof(buf); }"
        ),
        6
    );
    // local scalar: sizeof(int) = 4.
    assert_eq!(
        run_src("int main(void){ int x=0; char b[sizeof(x)]; (void)x; return (int)sizeof(b); }"),
        4
    );
}

#[test]
fn for_init_variable_scopes_to_enclosing_block() {
    // #42: Borland C++ 4.52 (pre-standard) scopes a `for(int i=…;…)` INIT
    // variable to the ENCLOSING block — usable after the loop and in a later
    // `for(i=…)` (OWL/MODULE.CPP `for(int cnt…); … for(cnt=…)`; PALTEST). A
    // for-BODY-local decl is NOT leaked.
    // reused in a later for: 0+1+2 then +10 twice = 23.
    assert_eq!(
        run_src(
            "int main(void){ int s=0; for(int i=0;i<3;i++) s+=i; for(i=0;i<2;i++) s+=10; return s; }"
        ),
        23
    );
    // used after the loop: i counts to 3.
    assert_eq!(
        run_src("int main(void){ for(int i=0;i<3;i++); int n=i; return n; }"),
        3
    );
    // a for-BODY-local stays scoped to the body (redeclarable after the loop).
    assert_eq!(
        run_src("int main(void){ for(int i=0;i<3;i++){ int x=i; (void)x; } int x=7; return x; }"),
        7
    );
}

#[test]
fn cast_to_reference_operand_resolves_among_overloads() {
    // A cast-to-reference `(T&)x` used as a call/operator argument is an LVALUE
    // of type T — it must resolve like `*p` against a `T&` parameter, even among
    // MANY candidate overloads (OWL persistent streaming: `is >> (TResId&)x`).
    // resolve_overload previously typed the arg as `Ref(T)` and failed to match
    // the `T&` candidate when other `>>` overloads were present; now it strips
    // the leading Ref so the cast scores identically to a deref. RUN-verified.
    let src = "struct T{int d; operator char*(){return 0;}}; \
               struct IS{int v;}; \
               IS& operator>>(IS&, int&); IS& operator>>(IS&, char*&); IS& operator>>(IS&, long&); \
               IS& operator>>(IS& is, T& t){ t.d = is.v; return is; } \
               int main(void){ IS is; is.v = 7; T t; is >> (T&)t; return ((T&)t).d; }";
    assert_eq!(run_src(src), 7);
}

#[test]
fn implicit_conversion_operator_in_init_and_assign() {
    // #36: copy-init (`int y = c;`) and scalar assignment (`y = c;`) of a
    // builtin from a record with `operator int()` must invoke the conversion
    // operator. Both previously ran `convert(Record,int)`, reading the record's
    // ADDRESS as the value — a SILENT MISCOMPILE (returned stack garbage). Now
    // they coerce via the operator (mirroring the cast + binary-op arms).
    let init = "struct C { int v; operator int() const { return v; } }; \
                int main(void) { C c; c.v = 9; int y = c; return y; }";
    assert_eq!(run_src(init), 9);
    let assign = "struct C { int v; operator int() const { return v; } }; \
                  int main(void) { C c; c.v = 9; int y = 0; y = c; return y; }";
    assert_eq!(run_src(assign), 9);
}

#[test]
fn ref_record_argument_to_scalar_param_uses_conversion_operator() {
    // RailC/OWL: `TDC::BitBlt(..., const TDC& srcDC, ...)` calls the Win32 API
    // as `::BitBlt(..., srcDC, ...)`, where the API wants HDC and TDC supplies
    // `operator HDC()`. A Ref<Record> source must use that conversion operator;
    // treating it as by-value record marshalling invokes TDC's private,
    // declaration-only copy ctor and leaves the link unresolved.
    let src = "struct Handle { \
                 int h; \
                 Handle() { h = 0; } \
                 operator int() const { return h; } \
               private: \
                 Handle(const Handle&); \
               }; \
               int sink(int h) { return h + 1; } \
               int f(const Handle& x) { return sink(x); } \
               int main(void) { Handle h; h.h = 41; return f(h); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn ref_record_argument_to_function_pointer_scalar_param_uses_conversion_operator() {
    // OWL's Ctl3d/BWCC hooks are loaded through function pointers whose
    // signatures take raw HWND/HINSTANCE/HANDLE values. Passing `*this` or
    // `*GetModule()` must invoke the class conversion operator; otherwise the
    // indirect-call marshaller treats the object as a by-value record and emits
    // references to declaration-only private copy constructors.
    let src = "struct Handle { \
                 int h; \
                 Handle() { h = 0; } \
                 operator int() const { return h; } \
               private: \
                 Handle(const Handle&); \
               }; \
               int sink(int h) { return h + 1; } \
               int f(int (*fp)(int), const Handle& x) { return (*fp)(x); } \
               int main(void) { Handle h; h.h = 41; return f(sink, h); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn compatible_conversion_operator_result_feeds_function_pointer_param() {
    // OWL's TApplication inherits `operator HINSTANCE()` from TModule, but the
    // Ctl3d function pointers take HANDLE. The conversion operator result only
    // needs a standard pointer conversion to the formal parameter type.
    let src = "struct HINSTANCE__ { int unused; }; \
               typedef struct HINSTANCE__* HINSTANCE; \
               typedef void* HANDLE; \
               struct App { \
                 HINSTANCE h; \
                 App() { h = 0; } \
                 operator HINSTANCE() const { return h; } \
               private: \
                 App(const App&); \
               }; \
               int sink(HANDLE h) { return h != 0 ? 42 : 0; } \
               int f(int (*fp)(HANDLE), const App& app) { return (*fp)(app); } \
               int main(void) { HINSTANCE__ inst; App app; app.h = &inst; return f(sink, app); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn constructor_scalar_param_uses_record_conversion_operator_on_win64() {
    // OWL's `TPaintDC dc(*this)` resolves to `TPaintDC(HWND)`, with `*this`
    // converted through TWindow::operator HWND(). Without record-to-scalar UDC
    // viability during overload resolution, the private copy constructor leaks
    // into generated code or the constructor call is rejected.
    let src = "struct HWND__ { int unused; }; \
               typedef struct HWND__* HWND; \
               struct Window { \
                 HWND h; \
                 Window() { h = 0; } \
                 operator HWND() const { return h; } \
               private: \
                 Window(const Window&); \
               }; \
               struct Paint { \
                 int ok; \
                 Paint(HWND h) { ok = h != 0 ? 42 : 0; } \
               private: \
                 Paint(const Paint&); \
               }; \
               int f(const Window& w) { Paint dc(w); return dc.ok; } \
               int main(void) { HWND__ hwnd; Window w; w.h = &hwnd; return f(w); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn pure_virtual_reference_param_uses_slot_signature_for_marshalling() {
    // Pure virtual declarations do not have concrete `sigs.funcs` entries, but
    // calls through their vtable slots still need the declared parameter types.
    // Otherwise a record argument to `Base&` is marshalled by value and can emit
    // a reference to a private copy constructor.
    let src = "struct Base { \
                 int v; \
                 Base() { v = 0; } \
               private: \
                 Base(const Base&); \
               }; \
               struct Derived : public Base { \
                 Derived() {} \
               private: \
                 Derived(const Derived&); \
               }; \
               struct Widget { \
                 virtual int paint(Base& b) = 0; \
                 int run() { Derived d; d.v = 42; return paint(d); } \
               }; \
               struct Impl : public Widget { \
                 int paint(Base& b) { return b.v; } \
               }; \
               int main(void) { Impl i; return i.run(); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn cxx_inheritance_members_and_methods() {
    // Derived inherits Base's data member and method; base default ctor
    // is chained before the derived ctor body.
    let src = "class Base { \
               protected: \
                 int b; \
               public: \
                 Base() { b = 100; } \
                 int getB() { return b; } \
               }; \
               class Derived : public Base { \
                 int d; \
               public: \
                 Derived() { d = 7; } \
                 int sum() { return getB() + d; } \
               }; \
               int main(void) { Derived x; return x.sum(); }";
    assert_eq!(run_src(src), 107);
}

#[test]
fn cxx_inheritance_meminit_base_args() {
    // Member-initializer list passes args to the base constructor.
    let src = "class Animal { \
                 int legs; \
               public: \
                 Animal(int n) { legs = n; } \
                 int numLegs() { return legs; } \
               }; \
               class Dog : public Animal { \
                 int tailWags; \
               public: \
                 Dog(int w) : Animal(4) { tailWags = w; } \
                 int score() { return numLegs() * 10 + tailWags; } \
               }; \
               int main(void) { Dog d(3); \
                 return d.numLegs() + d.score(); }";
    assert_eq!(run_src(src), 47);
}

#[test]
fn cxx_inheritance_destructor_chains_to_base() {
    // RAII at block scope: ~Mgr runs, then the base ~Res runs after it.
    let src = "class Res { \
                 int* log; \
               public: \
                 Res(int* L) { log = L; *log = 1; } \
                 ~Res() { *log = *log * 2; } \
               }; \
               class Mgr : public Res { \
               public: \
                 Mgr(int* L) : Res(L) { *log = *log + 4; } \
                 ~Mgr() { *log = *log + 10; } \
               }; \
               int main(void) { int v; v = 0; \
                 { Mgr m(&v); } \
                 return v; }";
    assert_eq!(run_src(src), 30);
}

#[test]
fn cxx_default_args_free_function() {
    let src = "int area(int w, int h = 3); \
               int area(int w, int h) { return w * h; } \
               int main(void) { return area(4) + area(5, 2); }";
    assert_eq!(run_src(src), 22); // 4*3 + 5*2
}

#[test]
fn cxx_default_args_member_and_ctor() {
    let src = "class Rect { \
                 int w; int h; \
               public: \
                 Rect(int a, int b = 5) { w = a; h = b; } \
                 int scale(int f = 2) { return w * h * f; } \
               }; \
               int main(void) { Rect r(4); Rect s(3, 10); \
                 return r.scale() + s.scale(1); }";
    assert_eq!(run_src(src), 70); // 4*5*2 + 3*10*1
}

#[test]
fn cxx_default_args_prototype_then_out_of_line() {
    let src = "class C { \
                 int n; \
               public: \
                 C(int v = 100); \
                 int get(int add = 1); \
               }; \
               C::C(int v) { n = v; } \
               int C::get(int add) { return n + add; } \
               int main(void) { C a; C b(7); return a.get() + b.get(5); }";
    assert_eq!(run_src(src), 113); // (100+1) + (7+5)
}

#[test]
fn cxx_overload_by_param_type() {
    let src = "int f(int x) { return x + 1; } \
               int f(char* s) { return 100; } \
               int main(void) { return f(41) + f(\"hi\"); }";
    assert_eq!(run_src(src), 142); // 42 + 100
}

#[test]
fn cxx_overload_by_arity() {
    let src = "int g(int a, int b) { return a * b; } \
               int g(int a) { return a + 7; } \
               int main(void) { return g(6, 7) + g(10); }";
    assert_eq!(run_src(src), 59); // 42 + 17
}

#[test]
fn cxx_overload_pointer_vs_int() {
    let src = "int kind(int* p) { return 1; } \
               int kind(int v) { return 2; } \
               int main(void) { int x; x = 5; int* q; q = &x; \
                 return kind(q) * 10 + kind(x); }";
    assert_eq!(run_src(src), 12); // 1*10 + 2
}

#[test]
fn printf_decimal_and_text() {
    let (c, o) = run_capture("int main(void){ printf(\"x=%d y=%d\\n\", -7, 13); return 0; }");
    assert_eq!(c, 0);
    assert_eq!(o, b"x=-7 y=13\n");
}

#[test]
fn printf_string_char_hex_unsigned() {
    let (_c, o) = run_capture(
        "int main(void){ \
           printf(\"%s!\\n\", \"hi\"); \
           printf(\"%c%c\\n\", 65, 66); \
           printf(\"%x %X\\n\", 255, 255); \
           printf(\"%u\\n\", -1); \
           printf(\"100%% done\\n\"); \
           return 0; }",
    );
    assert_eq!(o, b"hi!\nAB\nff FF\n4294967295\n100% done\n");
}

#[test]
fn printf_returns_total_bytes_with_format() {
    // "v=255" is 5 bytes -> exit code 5.
    let (c, o) = run_capture("int main(void){ return printf(\"v=%d\", 255); }");
    assert_eq!(o, b"v=255");
    assert_eq!(c, 5);
}

#[test]
fn printf_loop_and_expression_args() {
    let (_c, o) = run_capture(
        "int main(void){ int i; \
           for (i = 1; i <= 3; i = i + 1) printf(\"sq(%d)=%d\\n\", i, i*i); \
           return 0; }",
    );
    assert_eq!(o, b"sq(1)=1\nsq(2)=4\nsq(3)=9\n");
}

#[test]
fn libc_strlen_strcmp_abs_atoi() {
    let src = "int main(void){ int r = 0; \
                 r = r + strlen(\"hello\"); \
                 if (strcmp(\"abc\", \"abc\") == 0) r = r + 10; \
                 if (strcmp(\"abc\", \"abd\") < 0) r = r + 20; \
                 r = r + abs(-13); \
                 r = r + atoi(\"100\"); \
                 r = r - atoi(\"-8\"); \
                 return r; }";
    assert_eq!(run_src(src), 156); // 5+10+20+13+100+8
}

#[test]
fn libc_strcpy_strcat_memcpy_memset() {
    let src = "int main(void){ \
                 char buf[32]; \
                 strcpy(buf, \"Hello\"); \
                 strcat(buf, \", \"); \
                 strcat(buf, \"world\"); \
                 printf(\"%s\\n\", buf); \
                 char dst[8]; \
                 memcpy(dst, \"abcd\", 5); \
                 printf(\"[%s]\\n\", dst); \
                 char fill[6]; \
                 memset(fill, 65, 5); \
                 fill[5] = 0; \
                 printf(\"%s\\n\", fill); \
                 return 0; }";
    let (c, o) = run_capture(src);
    assert_eq!(c, 0);
    assert_eq!(o, b"Hello, world\n[abcd]\nAAAAA\n");
}

#[test]
fn libc_respects_include_string_h_stub() {
    // <string.h> is stubbed empty; strlen still resolves as a builtin.
    let src = "#include <string.h>\n\
               int main(void){ return strlen(\"abcdef\"); }";
    assert_eq!(run_src(src), 6);
}

#[test]
fn inline_asm_block_is_dropped() {
    let src = "int main(void){ int x; x = 10; \
                 asm { mov eax, 99 } \
                 x = x + 5; return x; }";
    assert_eq!(run_src(src), 15);
}

#[test]
fn inline_asm_statement_forms() {
    let src = "int main(void){ int r; r = 7; \
                 asm mov ax, bx; \
                 asm nop\n\
                 r = r * 6; return r; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn inline_asm_underscore_and_paren_forms() {
    let src = "int main(void){ int v; v = 3; \
                 __asm { push eax\n pop eax } \
                 asm(\"nop\"); \
                 v = v + 39; return v; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn struct_members_read_write() {
    let src = "struct P { int x; int y; }; \
               int main(void){ struct P p; p.x = 30; p.y = 12; return p.x + p.y; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn struct_pointer_arrow_and_param() {
    let src = "struct P { int a; int b; }; \
               int sum(struct P *p){ return p->a + p->b; } \
               int main(void){ struct P q; q.a = 40; q.b = 2; return sum(&q); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn self_referential_linked_list() {
    // Build a 3-node list from locals, traverse via `->` and pointer chase.
    let src = "struct N { int v; struct N *next; }; \
               int main(void){ \
                 struct N a; struct N b; struct N c; \
                 a.v = 1; b.v = 2; c.v = 3; \
                 a.next = &b; b.next = &c; c.next = 0; \
                 int sum; struct N *p; sum = 0; p = &a; \
                 while (p) { sum += p->v; p = p->next; } \
                 return sum; }";
    assert_eq!(run_src(src), 6);
}

#[test]
fn whole_struct_assignment_copies() {
    let src = "struct P { int x; int y; }; \
               int main(void){ struct P a; struct P b; \
                 a.x = 3; a.y = 4; b = a; b.x = 10; \
                 return a.x*100 + a.y*10 + b.x; }"; // a unchanged
    assert_eq!(run_src(src), 350);
}

#[test]
fn nested_structs() {
    let src = "struct Inner { int n; }; \
               struct Outer { struct Inner in; int k; }; \
               int main(void){ struct Outer o; o.in.n = 7; o.k = 35; \
                 return o.in.n + o.k; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn array_of_structs() {
    let src = "struct V { int x; }; \
               int main(void){ struct V a[3]; int i; \
                 for (i = 0; i < 3; i++) a[i].x = i * i; \
                 return a[0].x + a[1].x + a[2].x; }";
    assert_eq!(run_src(src), 5);
}

#[test]
fn union_overlaps_members() {
    // Little-endian: writing c[0]=65 then reading i yields 65.
    let src = "union U { int i; char c[4]; }; \
               int main(void){ union U u; u.i = 0; u.c[0] = 65; return u.i; }";
    assert_eq!(run_src(src), 65);
}

#[test]
fn enum_constants_are_values() {
    let src = "enum Color { RED, GREEN = 5, BLUE }; \
               int main(void){ return RED*100 + GREEN*10 + BLUE; }"; // 0,5,6
    assert_eq!(run_src(src), 56);
}

#[test]
fn typedef_struct_alias() {
    let src = "typedef struct { int a; int b; } Pair; \
               int add(Pair *p){ return p->a + p->b; } \
               int main(void){ Pair q; q.a = 19; q.b = 23; return add(&q); }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn typedef_scalar_alias_and_sizeof_struct() {
    let src = "typedef unsigned char byte; \
               struct S { char c; int i; }; \
               int main(void){ byte b; b = 200; \
                 return b + sizeof(struct S); }"; // 200 + 8 (natural layout)
    assert_eq!(run_src(src), 208);
}

#[test]
fn pointers_address_of_and_deref() {
    let src = "int main(void){ int x; int *p; x = 5; p = &x; \
               *p = *p + 37; return x; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn arrays_subscript_and_compound_assign() {
    // a[i] = i*i for i in 0..5, then sum -> 0+1+4+9+16 = 30
    let src = "int main(void){ int a[5]; int i; int s; s = 0; \
               for (i = 0; i < 5; i++) a[i] = i * i; \
               for (i = 0; i < 5; i++) s += a[i]; return s; }";
    assert_eq!(run_src(src), 30);
}

#[test]
fn char_pointer_strlen() {
    // Classic strlen over a string literal via char* and pointer ++.
    let src = "int slen(char *s){ int n; n = 0; while (*s) { n++; s++; } return n; } \
               int main(void){ return slen(\"hello, world\"); }";
    assert_eq!(run_src(src), 12);
}

#[test]
fn pointer_arithmetic_indexes_chars() {
    // s[4] of "abcdef" is 'e' (101).
    let src = "int main(void){ char *s; s = \"abcdef\"; return s[4]; }";
    assert_eq!(run_src(src), 101);
}

#[test]
fn global_variable_state() {
    let src = "int g; int bump(void){ g = g + 1; return g; } \
               int main(void){ g = 40; bump(); bump(); return g; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn sizeof_types() {
    // int(4) + char(1) + int*(8) = 13
    assert_eq!(run_return("sizeof(int) + sizeof(char) + sizeof(int*)"), 13);
    assert_eq!(run_return("sizeof(long) + sizeof(short)"), 6); // 4 + 2
}

#[test]
fn integer_cast_truncates() {
    // (char)300 -> 44 (300 & 0xFF), sign-extended (still +44)
    assert_eq!(
        run_src("int main(void){ int x; x = 300; return (char)x; }"),
        44
    );
    // (unsigned char)-1 -> 255
    assert_eq!(
        run_src("int main(void){ int x; x = -1; return (unsigned char)x; }"),
        255
    );
}

#[test]
fn ternary_and_prefix_postfix() {
    assert_eq!(
        run_src("int main(void){ int a; a = 7; return a > 5 ? 100 : 200; }"),
        100
    );
    let src = "int main(void){ int i; int r; i = 5; r = i++; return r * 100 + i; }";
    assert_eq!(run_src(src), 506); // post: r=5, i=6
    let src2 = "int main(void){ int i; int r; i = 5; r = ++i; return r * 100 + i; }";
    assert_eq!(run_src(src2), 606); // pre: r=6, i=6
}

#[test]
fn char_array_buffer_writes() {
    let src = "int main(void){ char b[4]; b[0] = 'O'; b[1] = 'K'; \
               b[2] = 33; b[3] = 0; return b[0] + b[1]; }"; // 79 + 75
    assert_eq!(run_src(src), 154);
}

#[test]
fn unsigned_division_and_shift() {
    // 0xFFFFFFFF as unsigned / 2 = 0x7FFFFFFF; as signed it'd be 0.
    let src = "int main(void){ unsigned int x; x = 4294967295; return x / 2; }";
    assert_eq!(run_src(src), 0x7FFF_FFFF);
}

#[test]
fn string_global_and_printf() {
    let src = "char *msg = \"global string\\n\"; \
               int main(void){ printf(\"global string\\n\"); return msg[0]; }";
    let (code, out) = run_capture(src);
    assert_eq!(out, b"global string\n");
    assert_eq!(code, b'g' as i32);
}

#[test]
fn preprocessor_object_and_function_macros() {
    // SQ(7) = 49 used as the exit code; N folded in.
    let src = "#define N 7\n#define SQ(x) ((x)*(x))\n\
               int main(void){ return SQ(N); }";
    assert_eq!(run_src(src), 49);
}

#[test]
fn preprocessor_conditional_compilation() {
    let src = "#define LEVEL 2\n\
               int main(void){\n\
               #if LEVEL > 1\n  return 10;\n#else\n  return 20;\n#endif\n}";
    assert_eq!(run_src(src), 10);
}

#[test]
fn system_include_is_stubbed_and_printf_works() {
    let src = "#include <stdio.h>\n#include <stdlib.h>\n\
               int main(void){ printf(\"inc-ok\\n\"); return 0; }";
    let (code, out) = run_capture(src);
    assert_eq!(code, 0);
    assert_eq!(out, b"inc-ok\n");
}

#[test]
fn prototype_then_definition_links() {
    let src = "int add(int a, int b);\n\
               int main(void){ return add(19, 23); }\n\
               int add(int a, int b){ return a + b; }";
    assert_eq!(run_src(src), 42);
}

#[test]
fn ifndef_include_guard_pattern() {
    // Classic include-guard shape compiled directly (idempotent macros).
    let src = "#ifndef ONCE\n#define ONCE\n\
               int helper(void){ return 5; }\n#endif\n\
               int main(void){ return helper() * 8; }";
    assert_eq!(run_src(src), 40);
}

#[test]
fn printf_writes_string_to_stdout() {
    let (code, out) = run_capture(r#"int main(void){ printf("Hello, world!\n"); return 0; }"#);
    assert_eq!(code, 0);
    assert_eq!(out, b"Hello, world!\n");
}

#[test]
fn puts_appends_newline() {
    let (_, out) = run_capture(r#"int main(void){ puts("hi"); return 0; }"#);
    assert_eq!(out, b"hi\n");
}

#[test]
fn printf_returns_byte_count() {
    // `return printf("abc");`  -> exit code 3, stdout "abc"
    let (code, out) = run_capture(r#"int main(void){ return printf("abc"); }"#);
    assert_eq!(code, 3);
    assert_eq!(out, b"abc");
}

#[test]
fn adjacent_string_literals_concatenate() {
    let (_, out) = run_capture(r#"int main(void){ printf("foo" "bar"); return 0; }"#);
    assert_eq!(out, b"foobar");
}

#[test]
fn output_from_loop_and_callee() {
    let src = r#"
        int greet(void) { printf("hi\n"); return 0; }
        int main(void) {
            int i;
            for (i = 0; i < 3; i = i + 1) greet();
            printf("done\n");
            return 0;
        }"#;
    let (code, out) = run_capture(src);
    assert_eq!(code, 0);
    assert_eq!(out, b"hi\nhi\nhi\ndone\n");
}

#[test]
fn escape_sequences_in_output() {
    let (_, out) = run_capture(r#"int main(void){ printf("a\tb\\c\"d"); return 0; }"#);
    assert_eq!(out, b"a\tb\\c\"d");
}

#[test]
fn nested_calls_as_arguments() {
    let prog = "int add(int a, int b) { return a + b; } \
                int sq(int x) { return x * x; } \
                int main(void) { return add(sq(3), sq(add(2, 2))); }";
    // sq(3)=9, add(2,2)=4, sq(4)=16 -> 25
    assert_eq!(run_src(prog), 25);
}

#[test]
fn static_data_member_is_shared_across_instances() {
    // S4.2z: a `static` data member is a single program-wide object, NOT
    // per-instance storage. Each ctor bumps the shared `count`, so the ids
    // come out 1/2/3 (-> 123). A per-instance bug would set every id to 1
    // (-> 111). Unqualified `count` inside the ctor resolves to the global
    // `Counter::count` (defined out-of-line), not `this->count`.
    // Diff-confirmed vs bcc32 4.52: returns 123.
    let prog = "struct Counter { \
                    static int count; \
                    int id; \
                    Counter() { count = count + 1; id = count; } \
                }; \
                int Counter::count = 0; \
                int main() { \
                    Counter a; Counter b; Counter c; \
                    return a.id * 100 + b.id * 10 + c.id; \
                }";
    assert_eq!(run_src(prog), 123);
}

#[test]
fn static_data_member_excluded_from_object_layout() {
    // S4.2z: `sizeof` counts only instance fields — the static member adds
    // no slot and shifts no field. Two `int` fields -> 8 (a layout bug that
    // kept the static would give 12). Diff-confirmed vs bcc32 4.52: 8.
    let prog = "struct S { static int s; int a; int b; }; \
                int S::s = 7; \
                int main() { return sizeof(S); }";
    assert_eq!(run_src(prog), 8);
}

#[test]
fn nonpoly_exception_throw_and_catch() {
    // S4.2ae: BC++ 4.52's exception hierarchy is NON-polymorphic (xmsg & co.
    // have no virtuals). EH type identity is decoupled from the vtable: a
    // non-poly class's type tag is its typeinfo-entry RVA (the entry doubles
    // as a descriptor). throw E(42); catch (E& e) → 42. Diff-confirmed vs
    // bcc32 4.52 (also 42). Before S4.2ae this was "throw: class must be
    // polymorphic".
    let prog = "struct E { int code; E(int c) { code = c; } }; \
                int main() { try { throw E(42); } catch (E& e) { return e.code; } }";
    assert_eq!(run_src(prog), 42);
}

#[test]
fn nonpoly_exception_catch_by_base_compiles() {
    // S4.2ae: catch-by-base across NON-polymorphic classes — the RTL idiom
    // (`catch (xmsg&)` catching a thrown `outofrange`). The personality walks
    // the typeinfo hierarchy table (Derived's entry's base_rva → Base's
    // entry); both are entry-as-descriptor RVAs. My Change-2 makes a non-poly
    // base_rva relocate against the base's typeinfo entry, exactly mirroring
    // the polymorphic base_rva → base vtable path.
    //
    // Validated here by COMPILE to a well-formed PE (exercises the base_rva
    // reloc + the 2-entry hierarchy table, no panic). The RUN is intentionally
    // NOT asserted: Windows Defender FALSE-POSITIVES on this specific
    // generated PE's byte pattern ("contains a virus") and blocks its launch,
    // while the simple non-poly run-test above (→42, matching bcc32) and the
    // existing POLYMORPHIC catch-by-base run-tests cover the identical runtime
    // walk (vtable-RVA vs entry-RVA tags are the only difference).
    let prog = "struct Base { int code; }; \
                struct Derived : Base { }; \
                int main() { \
                    try { Derived d; d.code = 42; throw d; } \
                    catch (Base& b) { return b.code; } \
                }";
    let pe = compile_to_pe(prog.as_bytes()).expect("non-poly catch-by-base must compile to a PE");
    assert!(
        pe.len() > 1000 && &pe[..2] == b"MZ",
        "expected a well-formed PE (len {}, magic {:02x}{:02x})",
        pe.len(),
        pe[0],
        pe[1]
    );
}

#[test]
fn global_scope_qualified_call_forces_free_function() {
    // S4.2aa: inside a member, an *unqualified* call to a name that is also a
    // sibling method collapses to `this->name(...)`. A leading `::` is the
    // global-scope qualifier and must force FREE-function resolution instead.
    // Here the member `f()` takes 0 args (void); the free `f(const S&)`
    // returns an S. `::f(*this)` must bind to the free function, so `.get()`
    // sees an S and returns 42 (binding to the void member is the bug — it
    // yields "method call on non-class"). This is exactly the RTL idiom
    // `::to_upper(*this).find_case_index(...)` (CSTRING.H find_index).
    // Diff-confirmed vs bcc32 4.52: returns 42.
    let prog = "struct S { int v; int get() { return v; } \
                           void f() { } int test(); }; \
                S f(const S& s) { S r; r.v = s.v + 1; return r; } \
                int S::test() { return ::f(*this).get(); } \
                int main() { S s; s.v = 41; return s.test(); }";
    assert_eq!(run_src(prog), 42);
}

/// S4.2b13: a free function returning `const T&`, used in a VALUE context, must
/// DEREFERENCE the returned reference — RAX holds the referent's address, so the
/// value is loaded through it. Before the fix the caller used the pointer as the
/// value (a silent miscompile: `const int& pick(...); int v = pick(3,5);` gave a
/// pointer, not 3). This is the free-function analogue of the MethodCall arm's
/// ref-return deref; the RTL's `min`/`max` (`const T& min(const T&,const T&)`)
/// are the real driver (#8). `pick(3,5)` ⇒ 3.
#[test]
fn reference_returning_free_function_used_as_value_derefs() {
    let src = "\
        const int& pick(const int& a, const int& b) { return a < b ? a : b; }\n\
        int main(void) { int x = 3, y = 5; return pick(x, y); }\n";
    assert_eq!(run_src(src), 3);
}

/// S4.2b14: a function template with REFERENCE parameters/return (`const T&`) —
/// the RTL `min`/`max` shape — now instantiates. Deduction unifies through the
/// reference (b14: deduce-through-ref) and the instantiated ref return is
/// dereferenced correctly in value context (b13). Before b14 the ref-param
/// template failed deduction ("could not be deduced"); a naive earlier attempt
/// (reverted b12) instantiated it onto the broken pre-b13 ref deref → garbage.
/// `pick(3,5)` ⇒ 3.
#[test]
fn reference_param_function_template_instantiates_and_runs() {
    let src = "\
        template<class T> const T& pick(const T& a, const T& b) { return a < b ? a : b; }\n\
        int main(void) { int x = 3, y = 5; return pick(x, y); }\n";
    assert_eq!(run_src(src), 3);
}

/// S4.2b16: function-template deduction must deduce a parameter from SOME
/// argument, not require EVERY argument to be typeable. `pick(v, s.get())`
/// deduces `T` from `v` (an int); `s.get()` is a method call whose type the
/// deducer doesn't compute, but `T` is already bound, so the call instantiates.
/// Before b16 this hard-errored and the enclosing function was DROPPED.
/// pick(3,5)=3. (The RTL `string::assign` calls `min(orig, s.length())` — same
/// undeducible method-call arg — so b16 un-defers the deduction; assign's FULL
/// link additionally needs reference-rvalue binding + member-overload mangling
/// #27, both deeper.)
#[test]
fn template_deduces_from_one_arg_when_another_is_a_method_call() {
    let src = "\
        template<class T> T pick(T a, T b) { return a < b ? a : b; }\n\
        struct S { int get() { return 5; } };\n\
        int main(void) { S s; int v = 3; return pick(v, s.get()); }\n";
    assert_eq!(run_src(src), 3);
}

/// S5 (#8): bind a value-rvalue argument to a `const T&` parameter. Every
/// reference-marshalling site previously took the argument's address (gen_addr),
/// which rejects a prvalue ("expression is not an lvalue"). Now an enumerated
/// value-rvalue (a free call, a method call, a binary expression) is
/// materialised into a frame temporary whose address backs the reference; the
/// temp is reclaimed at the function epilogue. The method-call shape is exactly
/// the RTL `min(orig, s.length())` pattern (in that TU the windows.h `min` macro
/// is inactive, so `min` is the `const T&` template). lvalue binds are unchanged
/// (still gen_addr), so no compiling program changes a byte.
#[test]
fn reference_param_binds_to_a_value_rvalue() {
    // free-call rvalue
    assert_eq!(
        run_src(
            "int useref(const int& a){ return a; }\n\
             int give(void){ return 5; }\n\
             int main(void){ return useref(give()); }\n"
        ),
        5
    );
    // method-call rvalue (the min(_, s.length()) shape)
    assert_eq!(
        run_src(
            "struct S{ int n; int len() const { return n; } };\n\
             int useref(const int& a){ return a + 2; }\n\
             int main(void){ S s; s.n = 5; return useref(s.len()); }\n"
        ),
        7
    );
    // binary rvalue
    assert_eq!(
        run_src(
            "int useref(const int& a){ return a; }\n\
             int main(void){ int x = 4, y = 5; return useref(x + y); }\n"
        ),
        9
    );
}

/// S4.2z+: a STATIC member function reads a STATIC data member of its class.
/// A static method has no `this`, so the unqualified `flag` cannot resolve via
/// the `this`-based member fallback; it resolves against the ENCLOSING CLASS
/// (derived from the function's `Tag::method` name) instead. Before this, the
/// read referenced an extern `flag` and left it unresolved at link (or the
/// inline DEFERRED — the RTL `string::get_case_sensitive_flag` shape). Called
/// via instance syntax so the qualified-static-call mangling gap is not in play.
/// flag==7.
#[test]
fn static_method_reads_static_data_member() {
    let src = "\
        struct S { static int flag; static int get(void){ return flag; } };\n\
        int S::flag = 7;\n\
        int main(void){ S s; return s.get(); }\n";
    assert_eq!(run_src(src), 7);
}

/// S4.2z+: a QUALIFIED static member CALL `S::get()` resolves to the member
/// symbol `S::get`, not the bare `get`. In expression position the parser
/// flattens `Tag::x` to its final component (correct for enum constants like
/// `ios::in` and static-data constants like `string::npos`) — but for a
/// member-FUNCTION call that left `get` referencing a non-existent free
/// function (unresolved at link). Now a qualified call to a known member
/// function keeps `Tag::method`. This is the RTL `string::get_*()` call shape.
/// `S::get()` ⇒ 5.
#[test]
fn qualified_static_member_call_resolves_to_member_symbol() {
    let src = "\
        struct S { static int get(void){ return 5; } };\n\
        int main(void){ return S::get(); }\n";
    assert_eq!(run_src(src), 5);
}

/// An out-of-line static member definition must not receive an implicit `this`.
/// OWL's `TApplication::SetWinMainParams(HINSTANCE,HINSTANCE,char*,int)` is
/// called as a plain four-argument function from `WinMain`; the old lowering
/// shifted those arguments by one slot and treated `cmdShow` as `cmdLine`.
#[test]
fn out_of_line_static_member_definition_has_no_this_parameter() {
    let src = "\
        struct S { static int f(int a, int b, char* p, int d); };\n\
        int S::f(int a, int b, char* p, int d) {\n\
            return p == 0 ? a + b + d : 7;\n\
        }\n\
        int main(void){ return S::f(10, 20, 0, 12); }\n";
    assert_eq!(run_src(src), 42);
}

/// SEM-04: a static and a non-static overload may share a name (OWL
/// `TGdiBase::CheckValid(uint)` beside `static CheckValid(HANDLE, uint)`).
/// The non-static one keeps its `this`, and an unqualified call from it
/// resolves to whichever overload the arguments pick.
#[test]
fn mixed_static_and_instance_overloads_keep_this_per_signature() {
    let src = "\
        struct S {\n\
            int h;\n\
            int f(int r);\n\
            static int f(int a, int r);\n\
            int g();\n\
        };\n\
        int S::f(int a, int r) { return a * 10 + r; }\n\
        int S::f(int r) { return f(h, r); }\n\
        int S::g() { return f(1); }\n\
        int main(void){ S s; s.h = 3; return s.f(4) + s.g() + S::f(1, 0); }\n";
    assert_eq!(run_src(src), 34 + 31 + 10);
}

/// SEM-04: a static member body has no `this`, so an unqualified call to a
/// mixed static/instance name must pick the static overload — both in its own
/// class and through a base (OWL `THatch8x8Brush::Create` calling the
/// inherited `TGdiBase::CheckValid(handle)`).
#[test]
fn static_body_calls_static_overload_of_mixed_name() {
    let src = "\
        struct B {\n\
            int h;\n\
            int f(int r);\n\
            static int f(int* p, int r);\n\
        };\n\
        int B::f(int* p, int r) { return *p + r; }\n\
        int B::f(int r) { return h + r; }\n\
        struct D : B { static int g(int* p); };\n\
        int D::g(int* p) { return f(p, 5); }\n\
        struct S { int f(int r); static int f(int* p, int r); static int g(int* p); };\n\
        int S::f(int* p, int r) { return *p * r; }\n\
        int S::f(int r) { return r; }\n\
        int S::g(int* p) { return f(p, 3); }\n\
        int main(void){ int v = 7; return D::g(&v) + S::g(&v); }\n";
    assert_eq!(run_src(src), 12 + 21);
}

/// S4.2h/#16: an INLINE member returning a record whose size was captured stale
/// (mid-class-body `size: 0`) — the RTL `string::substring`/`operator()`
/// returning TSubString shape (here an inline returning a forward-declared
/// `Inner` by value). The record-return size check compares FINALIZED record
/// sizes (the declared return is completed at Gen::new; the return-expression's
/// type is completed at the check), so a genuinely-matching record-return is no
/// longer falsely rejected and DEFERRED. The value is returned correctly (the
/// result buffer is sized from the finalized record, not the stale 0). ⇒ 7.
#[test]
fn inline_returning_record_with_stale_size_codegens() {
    let src = "\
        struct Inner;\n\
        struct Outer { Inner make(); };\n\
        struct Inner { int a, b, c, d; Inner(){ a = 7; b = 0; c = 0; d = 0; } };\n\
        inline Inner Outer::make(){ return Inner(); }\n\
        int main(void){ Outer o; return o.make().a; }\n";
    assert_eq!(run_src(src), 7);
}

/// Borland cast-as-lvalue (`(T)lvalue = v`): a SAME-WIDTH reinterpret of an
/// lvalue's storage, used in OWL Win32 code (CHOOSECO's `(HINSTANCE)(cc.hInstance)
/// = *GetModule()`). gen_addr gains a Cast arm restricted to equal widths — the
/// address IS the inner lvalue's and the assignment stores T's width, so equal
/// widths means no over/under-write. A width-CHANGING cast-lvalue stays a hard
/// "not an lvalue" error (never a silent truncation). `(int)u = 7` => 7; a
/// pointer reinterpret round-trips a stored address (=> 5).
#[test]
fn borland_cast_as_lvalue_same_width() {
    assert_eq!(
        run_src("int main(void){ unsigned u = 0; (int)u = 7; return (int)u; }\n"),
        7
    );
    assert_eq!(
        run_src(
            "struct H{ int v; };\n\
             int main(void){ void* p = 0; H h; h.v = 5; (H*)p = &h; return ((H*)p)->v; }\n"
        ),
        5
    );
}

/// C++ unqualified name lookup: a class data member (incl. inherited) shadows a
/// same-named GLOBAL enum constant (class scope is searched before the enclosing
/// scope). mdbcc's parser checked enum constants FIRST, so OWL geometry's TRect
/// members left/top/right/bottom resolved to the <iostream.h> `ios` formatting
/// enum constants (left/right/internal — a const int, "not an lvalue"), making
/// every TRect method DEFER — the dominant OWL "not an lvalue" cluster. Now the
/// member wins. Here `val` is both a global enum constant (99) and a member;
/// `val = 5; return val;` must use the MEMBER => 5, not the enum 99.
#[test]
fn class_member_shadows_global_enum_constant() {
    let src = "\
        enum { val = 99 };\n\
        struct S { int val; int get(void){ val = 5; return val; } };\n\
        int main(void){ S s; return s.get(); }\n";
    assert_eq!(run_src(src), 5);
}

/// #29: a file-scope SCALAR (integer) global with a RUNTIME (non-constant)
/// initializer — `int g = foo();`. const_eval cannot fold it, so instead of the
/// historical hard error ("global initializer must be a constant"), the storage
/// is zero-initialised and `g = foo()` runs as dynamic init (here in main's
/// prologue — single-TU static init, reusing the #20 mechanism). foo()==42 ⇒
/// `g`==42 by the time main reads it (0 would mean the init never ran).
#[test]
fn scalar_global_with_runtime_initializer_is_dynamically_initialized() {
    let src = "\
        int foo(void) { return 42; }\n\
        int g = foo();\n\
        int main(void) { return g; }\n";
    assert_eq!(run_src(src), 42);
}

/// #8/#34 (S4): binding a `const T&` reference parameter to a non-lvalue
/// rvalue ARGUMENT must materialize a temporary and bind the reference to it
/// (C++ [dcl.init.ref]). Before the `gen_ref_arg` fix, a bare literal (`7`) or
/// a unary rvalue (`-1`) reached `gen_addr`, which correctly rejects them as
/// "expression is not an lvalue" — so the real ClassLib container call
/// `TArrayAsVector<int>::Add(7)` failed to compile. This is a RUN oracle (not
/// just a compile check): the reference must READ BACK the correct value
/// through the materialized temporary, or the program returns the wrong sum.
///   7 (literal) - 1 (unary) + 5 (lvalue) + 8 (arithmetic) = 19.
#[test]
fn const_ref_param_binds_to_rvalue_literal_and_unary() {
    let src = "\
        struct T {\n\
            int sum;\n\
            T() { sum = 0; }\n\
            void Add(const int& x) { sum += x; }\n\
        };\n\
        int main(void) {\n\
            T t;\n\
            t.Add(7);      /* int literal     -> +7 */\n\
            t.Add(-1);     /* unary neg lit   -> -1 */\n\
            int v = 5;\n\
            t.Add(v);      /* lvalue          -> +5 */\n\
            t.Add(v + 3);  /* arithmetic rval -> +8 */\n\
            return t.sum;\n\
        }\n";
    assert_eq!(run_src(src), 19);
}

/// S4 (#8/#34): a constructor member-initializer for a CLASS-typed member must
/// CONSTRUCT the sub-object with ALL its arguments (`: data(u*2, u+1)`), not
/// assign only the first arg to it. Before the `Stmt::MemberInit` lowering, the
/// parser kept only `args[0]` and emitted `this->data = u*2` — which for a
/// record member is a scalar-to-record assignment ("expression is not an
/// lvalue") AND silently drops the second argument. This is the exact shape of
/// the real ClassLib container ctors (`TArrayAsVectorImp : Data(sz, delta)`).
/// RUN oracle: data.a = 20, data.b = 11, tag = 10 => 41.
#[test]
fn class_typed_member_init_constructs_with_all_args_inclass() {
    let src = "\
        struct Inner {\n\
            int a; int b;\n\
            Inner(int x, int y) { a = x; b = y; }\n\
        };\n\
        struct Outer {\n\
            Inner data;\n\
            int tag;\n\
            Outer(int u) : data(u * 2, u + 1), tag(u) {}\n\
        };\n\
        int main(void) {\n\
            Outer o(10);\n\
            return o.data.a + o.data.b + o.tag;\n\
        }\n";
    assert_eq!(run_src(src), 41);
}

/// S4 (#8/#34): the same member-init construction, but with an OUT-OF-LINE ctor
/// definition (`Outer::Outer(...) : data(...) {}` at namespace scope). These are
/// parsed AFTER the per-class finalization pass, so they are resolved by the
/// end-of-parse sweep in `Parser::parse_for` rather than the per-class pass —
/// a distinct code path that must reach the same result. (`TSubString` in the
/// real BC45 string headers is exactly this shape.)
#[test]
fn class_typed_member_init_constructs_with_all_args_outofline() {
    let src = "\
        struct Inner {\n\
            int a; int b;\n\
            Inner(int x, int y) { a = x; b = y; }\n\
        };\n\
        struct Outer {\n\
            Inner data;\n\
            int tag;\n\
            Outer(int u);\n\
        };\n\
        Outer::Outer(int u) : data(u * 2, u + 1), tag(u) {}\n\
        int main(void) {\n\
            Outer o(10);\n\
            return o.data.a + o.data.b + o.tag;\n\
        }\n";
    assert_eq!(run_src(src), 41);
}

/// S4 (#12): single-object placement-new `new(ptr) T` — construct T in storage
/// the caller already owns, with `ptr` (a pointer operand) used directly as the
/// object's address and as the value of the expression. No allocation. This is
/// the foundation for ClassLib's allocator-form `new(*this)T[n]` (which selects
/// a class `operator new` — still deferred). RUN oracle: write through the
/// returned pointer must land in the caller's buffer.
#[test]
fn placement_new_scalar_uses_caller_storage() {
    let src = "\
        int main(void) {\n\
            int buf = 0;\n\
            int* a = new(&buf) int;\n\
            *a = 42;\n\
            return buf;\n\
        }\n";
    assert_eq!(run_src(src), 42);
}

/// S4 (#12): placement-new of a CLASS with a constructor — `new(buf) P(7)` must
/// run P::P(7) on the caller's storage (no allocation) and yield that pointer.
#[test]
fn placement_new_runs_ctor_in_caller_storage() {
    let src = "\
        struct P { int x; P(int v) { x = v; } };\n\
        int main(void) {\n\
            char buf[16];\n\
            P* p = new(buf) P(7);\n\
            return p->x;\n\
        }\n";
    assert_eq!(run_src(src), 7);
}

/// S4 (#12): placement ARRAY-new `new(ptr) T[n]` for a trivially-constructed
/// element type — the array is placed in caller-owned storage (no allocation,
/// no cookie), and `ptr` is the value of the expression. This is the
/// construction half of ClassLib's allocator-form `new(*this)T[sz]`. The count
/// is evaluated for side effects but a trivial element needs no init. RUN
/// oracle: writes through the returned pointer land in the caller's buffer.
#[test]
fn placement_array_new_trivial_uses_caller_storage() {
    let src = "\
        int main(void) {\n\
            int buf[4];\n\
            int* a = new(buf) int[4];\n\
            a[0] = 7;\n\
            a[3] = 11;\n\
            return a[0] + a[3];\n\
        }\n";
    assert_eq!(run_src(src), 18);
}

/// S4 (#12): the GLOBAL allocation operators `::operator new[](size_t)` /
/// `::operator delete[](void*)` (and the scalar forms) have no runtime library
/// to link against in mdbcc — provide them intrinsically as HeapAlloc/HeapFree.
/// Real ClassLib/RTL code (e.g. TStandardAllocator) forwards to these. RAW
/// alloc/free (no array cookie), so new[]/delete[] are mutually consistent.
/// Before this they were an "unresolved external function" at link. RUN
/// oracle: allocate, round-trip through the block, free.
#[test]
fn global_operator_new_delete_array_round_trip() {
    let src = "\
        typedef unsigned long size_t;\n\
        int main(void) {\n\
            int* p = (int*) ::operator new[](16);\n\
            p[0] = 7;\n\
            p[3] = 11;\n\
            int r = p[0] + p[3];\n\
            ::operator delete[](p);\n\
            return r;\n\
        }\n";
    assert_eq!(run_src(src), 18);
}

/// S4 (#12): scalar global `::operator new(size_t)` / `::operator delete`.
#[test]
fn global_operator_new_delete_scalar_round_trip() {
    let src = "\
        typedef unsigned long size_t;\n\
        int main(void) {\n\
            int* p = (int*) ::operator new(4);\n\
            *p = 42;\n\
            int r = *p;\n\
            ::operator delete(p);\n\
            return r;\n\
        }\n";
    assert_eq!(run_src(src), 42);
}

/// S4 (#12 prereq): an INLINE friend-function DEFINITION defines a free
/// function (with private access, which mdbcc does not enforce). Previously
/// the whole friend declaration was SKIPPED, so a call to it was an
/// "unresolved external function" at link. Friends are pervasive in real
/// C++/ClassLib/OWL (`operator==`, `operator<<`, the allocators' `operator
/// new[]`). Now parsed + registered + emitted. RUN oracle exercises an
/// ordinary friend AND a friend operator with private access.
#[test]
fn inline_friend_function_definition_is_callable() {
    let src = "\
        struct P {\n\
            int x;\n\
            friend int add_x(const P& a, int n) { return a.x + n; }\n\
            friend int operator==(const P& a, const P& b) { return a.x == b.x; }\n\
        };\n\
        int main(void) {\n\
            P a; a.x = 30;\n\
            P b; b.x = 30;\n\
            return add_x(a, 11) + (a == b);  /* 41 + 1 = 42 */\n\
        }\n";
    assert_eq!(run_src(src), 42);
}

/// S4 (#12, X): an array of a trivial-destructor element type is cookie-less
/// (`new T[n]` = raw alloc, `delete[]` = raw free, matching the C++ ABI). This
/// makes the intrinsic array forms consistent with the cookie-less global
/// `operator new[]`/`delete[]` — mixing them (allocate with `::operator new[]`,
/// free with `delete[]`) previously freed `block-8` (heap corruption); now both
/// are cookie-less. RUN oracle round-trips through both allocators + frees.
#[test]
fn trivial_array_new_delete_is_cookieless_and_consistent() {
    let src = "\
        typedef unsigned long size_t;\n\
        int main(void) {\n\
            int* a = new int[4];\n\
            a[0] = 7; a[3] = 11;\n\
            int r1 = a[0] + a[3];\n\
            delete[] a;\n\
            int* b = (int*) ::operator new[](16);\n\
            b[0] = 4; b[3] = 16;\n\
            int r2 = b[0] + b[3];\n\
            delete[] b;  /* cookie-less delete[] of operator-new[] storage */\n\
            return r1 + r2;  /* 18 + 20 = 38 */\n\
        }\n";
    assert_eq!(run_src(src), 38);
}

/// S4 (#12, allocator-form): placement array-new through a custom ALLOCATOR —
/// `new(alloc) T[n]` where `alloc` is a class object (NOT a raw pointer)
/// resolves the allocator's `operator new[](size_t, const Alloc&)` (mdbcc lowers
/// the friend's `::operator new[]` to HeapAlloc) and array-constructs in the
/// returned storage. This is EXACTLY ClassLib's `TVectorImpBase : Data(
/// new(*this)T[sz])`, including the derived->base bind (`*this` is a derived
/// vector, the allocator is a base). RUN oracle round-trips + frees cookie-less.
#[test]
fn placement_array_new_through_allocator_object() {
    let src = "\
        typedef unsigned long size_t;\n\
        struct Alloc {\n\
            friend void* operator new[](size_t sz, const Alloc&) { return ::operator new[](sz); }\n\
            friend void* operator new[](unsigned, void* p) { return p; }\n\
        };\n\
        struct Vec : Alloc { int z; };  /* derived -> base allocator bind */\n\
        int main(void) {\n\
            Vec v;\n\
            int* a = new(v) int[4];\n\
            a[0] = 7; a[3] = 11;\n\
            int r = a[0] + a[3];\n\
            delete[] a;\n\
            return r;\n\
        }\n";
    assert_eq!(run_src(src), 18);
}

/// S4 (#27): type-aware operator reachability. A binary op / subscript / assign
/// invokes a user `operator@` only when an operand is a CLASS; a builtin op on
/// int/ptr operands must NOT record the operator name (which would keep every
/// `operator@` overload by name — incl. unrelated classes' — dragging them in).
/// A record's `operator[]` is kept by touching the record. RUN oracle: a record
/// `V` with `operator[]` returning `int&`; `v[0] + v[1]` keeps V::operator[]
/// (touch-record) yet the `int + int` does not pull any other class's operator+.
#[test]
fn record_subscript_kept_but_builtin_op_not_over_pulled() {
    let src = "\
        struct V { int d[4]; int& operator[](int i) { return d[i]; } };\n\
        int main(void) { V v; v[0] = 7; v[1] = 11; return v[0] + v[1]; }\n";
    assert_eq!(run_src(src), 18);
}

/// S4 (#50): an UNQUALIFIED reference to a STATIC data member from an
/// OUT-OF-LINE member function resolves to the qualified `Tag::name` global.
/// This is the real Borland ClassLib/RTL string shape (`string::
/// get_case_sensitive_flag() { return case_sensitive; }`) — the linchpin for
/// compiling the RTL string source. Statics are not instance members, so the
/// unqualified name needs the static-member resolution path; without it,
/// codegen mis-resolved it as `this->name` -> "no member named". RUN oracle:
/// the accessor reads the static's value.
#[test]
fn unqualified_static_member_in_out_of_line_method() {
    let src = "\
        struct S {\n\
            static int flag;\n\
            static int get();\n\
        };\n\
        int S::flag = 42;\n\
        inline int S::get() { return flag; }\n\
        int main(void) { return S::get(); }\n";
    assert_eq!(run_src(src), 42);
}

/// S4 (#27): a function-template argument deduces from an ARITHMETIC expression,
/// not just a bare variable. CLASSLIB VECTIMP.H's `Resize` calls
/// `min( sz-offset, Lim )` where `Lim` is a member (untypeable during
/// monomorphisation), so `min`'s `T` must deduce from `sz-offset` (a Binary).
/// Monomorphisation typed only Int/Var/Cast args, so both were skipped and
/// `Resize` deferred -> unresolved. RUN oracle: `mn(n-1, Lim)` with n=5, Lim=9
/// deduces T=unsigned and returns min(4,9)=4.
#[test]
fn function_template_deduces_from_arithmetic_argument() {
    let src = "\
        template <class T> T mn(T a, T b) { return a < b ? a : b; }\n\
        struct S { unsigned Lim; unsigned f(unsigned n) { return mn(n - 1, Lim); } };\n\
        int main(void) { S s; s.Lim = 9; return (int)s.f(5); }\n";
    assert_eq!(run_src(src), 4);
}

/// S4 (#27): a LOCAL variable SHADOWS an enclosing-scope enum constant of the
/// same name (C++ [basic.scope]). `<iostream>` declares `enum seek_dir { beg,
/// cur, end }`, so CLASSLIB containers' `for( unsigned cur = …; … )` loop
/// variable `cur` collided — every USE of `cur` folded to the enumerator `1`,
/// silently miscompiling the loop (and deferring the instantiated members on the
/// downstream "not an lvalue"). RUN oracle: with the shadow, `cur` runs 3,4,5 ->
/// sum 12; without it `cur`==1 would loop forever / sum wrong.
#[test]
fn local_variable_shadows_enum_constant() {
    let src = "\
        enum seek_dir { beg = 0, cur = 1, end = 2 };\n\
        int main(void) {\n\
            int sum = 0;\n\
            for (unsigned cur = 3; cur < 6; cur++) sum += (int)cur;\n\
            return sum;\n\
        }\n";
    assert_eq!(run_src(src), 12);
}

/// S4 (#8): a C-style cast TO A REFERENCE of an lvalue — `(T&)lv` — is itself an
/// lvalue, so its address may be taken: `&(T&)lv`. This is CLASSLIB VECTIMP.H's
/// `FirstThat`/`LastThat` shape (`return &(T&)Data[cur];`). gen_addr only handled
/// same-width value casts, so the reference-cast hit the not-an-lvalue catch-all
/// and the (vague-linkage) member deferred -> unresolved at link. RUN oracle:
/// `&(int&)a[1]` yields a[1]'s address; reading it back gives 7.
#[test]
fn address_of_reference_cast_is_an_lvalue() {
    let src = "\
        int main(void) {\n\
            int a[4]; a[0]=0; a[1]=7; a[2]=0; a[3]=0;\n\
            int* p = &(int&)a[1];\n\
            return *p;\n\
        }\n";
    assert_eq!(run_src(src), 7);
}

/// S4 (#27): overloaded FUNCTION TEMPLATES of the same name but different arity
/// (CLASSLIB STDTEMPL.H's `min(T,T)` and `min(T,T,T)`) each instantiate when
/// called. Monomorphisation keyed templates by name alone, so the second
/// overload overwrote the first — an arity-mismatched call then never
/// instantiated and linked to an unresolved symbol. RUN oracle: `pick(5,3)` ->
/// 3 (*10 = 30) and `pick(9,2,7)` -> 2; 30 + 2 = 32.
#[test]
fn overloaded_function_templates_select_by_arity() {
    let src = "\
        template <class T> T pick(T a, T b) { return a < b ? a : b; }\n\
        template <class T> T pick(T a, T b, T c) { return pick(pick(a, b), c); }\n\
        int main(void) { return pick(5, 3) * 10 + pick(9, 2, 7); }\n";
    assert_eq!(run_src(src), 32);
}

/// S4 (#27): an unqualified call to a sibling member overload DECLARED LATER
/// in the class body (a FORWARD reference) resolves to that member — C++
/// complete-class scope ([class.mem]/6). This is CLASSLIB VECTIMP.H's exact
/// shape: the 2-arg `ForEach(iter,args)` (line 205) calls the 4-arg
/// `ForEach(iter,args,start,stop)` DECLARED below it (line 210). mdbcc resolved
/// bare member calls against members seen SO FAR, so the call mangled
/// undecorated and linked to an unresolved symbol; codegen now rewrites an
/// otherwise-unresolved bare call in a member to `this->name(args)`. RUN oracle:
/// `dispatch(5)` calls the later-declared `dispatch(5,3)` -> 5*10 + 3 = 53.
#[test]
fn forward_declared_sibling_member_overload_call_resolves() {
    let src = "\
        struct S {\n\
            int dispatch(int a) { return dispatch(a, 3); }  /* calls later overload */\n\
            int dispatch(int a, int b);                     /* declared AFTER caller */\n\
        };\n\
        int S::dispatch(int a, int b) { return a * 10 + b; }\n\
        int main(void) { S s; return s.dispatch(5); }\n";
    assert_eq!(run_src(src), 53);
}

/// S4 (#49): an OUT-OF-LINE template member-function DEFINITION
/// (`template<class T> ret Tag<T>::member(...) { ... }`) is captured and
/// REPLAYED when `Tag<args>` is instantiated — producing a concrete member
/// function bound to the instance. This is the real Borland ClassLib shape
/// (VECTIMP.H's 4-arg `TMVectorImp<T,Alloc>::ForEach` defined out-of-line, called
/// by the in-class 2-arg overload); without replay the out-of-line member was
/// declared but never defined, so a call to it linked to an unresolved symbol.
/// Here the in-class `total()` calls the out-of-line `sum(a,b)`; the program runs
/// only if the out-of-line def was instantiated. RUN oracle: 3 + 4 = 7.
#[test]
fn out_of_line_template_member_definition_is_instantiated() {
    let src = "\
        template <class T> struct Box {\n\
            T a, b;\n\
            T sum(T x, T y);                 /* declared in-class */\n\
            T total() { return sum(a, b); }  /* in-class, calls out-of-line sum */\n\
        };\n\
        template <class T> T Box<T>::sum(T x, T y) { return x + y; }\n\
        int main(void) {\n\
            Box<int> box;\n\
            box.a = 3; box.b = 4;\n\
            return box.total();\n\
        }\n";
    assert_eq!(run_src(src), 7);
}

/// #29 extended to POINTERS: a file-scope POINTER global initialised from a
/// non-constant value (here another global's value, `psrc`) cannot be folded by
/// `global_image`, so it must be zero-initialised and assigned at startup
/// (dynamic init), not rejected as "global initializer must be a constant".
/// This is the CLASSLIB/LOCALE.CPP shape
/// (`HINSTANCE TLocaleString::Module = _hInstance;`). The constant pointer init
/// `psrc = &target` still takes the relocation path (#45) and runs first, so
/// `pdst = psrc` then `*pdst` yields 42. RUN-verified end to end.
#[test]
fn pointer_global_initialized_from_runtime_value_is_dynamically_initialized() {
    let src = "\
        int target = 42;\n\
        int* psrc = &target;   /* constant init: &global (relocation, #45) */\n\
        int* pdst = psrc;      /* runtime init from another global -> dynamic init */\n\
        int main(void) { return *pdst; }\n";
    assert_eq!(run_src(src), 42);
}

/// A function-local `static` with a RUNTIME initializer (`static X x = f();`) is
/// initialized exactly ONCE — on first reaching its declaration (C++ §6.7), via a
/// compiler-synthesized guard int — not on every call, and not rejected as
/// "global initializer must be a constant". `next_id()` returns 1 then 2; because
/// `id`'s init runs once, both `get()` calls see id==1, so the result is 11 (it
/// would be 12 if the init re-ran). This is the CLASSLIB/LOCALECO.CPP shape
/// (`static (*compareStringA)() = GetProcAddress(...)`). RUN-verified.
#[test]
fn static_local_with_runtime_initializer_runs_once() {
    let src = "\
        int counter = 0;\n\
        int next_id() { return ++counter; }\n\
        int get() { static int id = next_id(); return id; }\n\
        int main(void) {\n\
            int a = get();   /* id <- 1 */\n\
            int b = get();   /* still 1 (init ran once) */\n\
            return a*10 + b; /* 11 */\n\
        }\n";
    assert_eq!(run_src(src), 11);
}

#[test]
fn same_named_block_static_locals_are_distinct() {
    let src = "\
        int pick(int flag) {\n\
            if (flag) { static int n = 10; return ++n; }\n\
            else { static int n = 20; return ++n; }\n\
        }\n\
        int main(void) {\n\
            return pick(1) + pick(0) + pick(1) + pick(0);\n\
        }\n";
    assert_eq!(run_src(src), 66);
}

/// A parenthesised FUNCTIONAL CAST followed by a binary operator —
/// `(long(50)) / 2` — must parse as `( <expr> ) / 2`, not be mis-read as a
/// C-style cast `(long)…`. `peek_is_type_after_lparen` returned true for a bare
/// type keyword without the cast-shape check (type then `)`/`*`/`&`), so a type
/// keyword FOLLOWED BY `(` (a functional cast) committed to a cast and errored
/// "expected ')'". This is OWL GADGETWI/GAUGE `int((long(units)*h + u/2)/u)`.
/// RUN-verified: compute(10,12,8) = (10*12 + 8/2)/8 = 124/8 = 15.
#[test]
fn parenthesized_functional_cast_then_operator_parses() {
    let src = "\
        int compute(int units, int h, int u) {\n\
            return int((long(units) * h + u/2) / u);\n\
        }\n\
        int main(void) { return compute(10, 12, 8); }\n";
    assert_eq!(run_src(src), 15);
}

/// A (non-array) new-expression can receive a postfix chain:
/// `new W()->set(42)` parses as `(new W())->set(42)`, not "expected ';'". This is
/// the pervasive OWL idiom `new TEdit(this, id)->SetValidator(v)` (INPUTDIA.CPP) —
/// create a child window and immediately configure it. RUN-verified: the method
/// runs on the freshly-allocated object, setting `sink` to 42.
#[test]
fn new_expression_receives_postfix_arrow_chain() {
    let src = "\
        int sink;\n\
        struct W { void set(int x) { sink = x; } };\n\
        int main(void) { new W()->set(42); return sink; }\n";
    assert_eq!(run_src(src), 42);
}

/// #32: a file-scope AGGREGATE global whose initializer can't be a constant
/// image — an array of structs holding a MEMBER-FUNCTION POINTER. This is the
/// exact shape of an OWL response table (`DEFINE_RESPONSE_TABLE` expands to
/// `static TResponseTableEntry<cls> cls::__entries[] = {{…,&cls::handler},…}`),
/// the single biggest OWL-source blocker. `global_image` can't fold the
/// `&C::m` relocation, so the table is built at startup via dynamic init
/// (#20/#29), decomposing the init-list into per-leaf assignments
/// (`table[i].field = value`) — an init-list is not a valid `Expr::Assign` rhs.
/// RUN-verified: dispatch through the member-fn-ptr stored in the global table
/// sets x to 42 (a silent miscompile here would break OWL message dispatch).
#[test]
fn global_aggregate_with_member_fn_ptr_is_dynamically_initialized() {
    let src = "\
        struct C { int x; void m() { x = 42; } };\n\
        struct Entry { int id; void (C::*pmf)(); };\n\
        Entry table[2] = { {1, &C::m}, {0, 0} };\n\
        int main(void) {\n\
            C c; c.x = 0;\n\
            (c.*(table[0].pmf))();\n\
            return c.x;   /* 42 */\n\
        }\n";
    assert_eq!(run_src(src), 42);
}

/// A VIRTUAL member function participates in overload resolution alongside a
/// same-name NON-virtual sibling, even when only DECLARED in-class and defined
/// out-of-line (the library-header case). Previously the parser excluded a
/// virtual declaration from the extern-proto overload set ("vtable-keyed
/// dispatch"), so `name_counts` under-counted, the name wasn't seen as
/// overloaded, and a call to the virtual's arity mis-resolved to the non-virtual
/// sibling ("expected N args, got M"). This is BC45's `streambuf::setbuf`
/// (virtual `setbuf(char*,int)` + `setbuf(char*,int,int)`) — on the HELLOAPP
/// link path via OBJSTRM, and a broad CLASSLIB/OWL "no matching overload"
/// cause. RUN-verified that virtual DISPATCH still routes through the vtable:
/// `p->f(5)` on a B* pointing at a D returns D::f's 25 (not B::f's 15, not the
/// non-virtual sibling) — the overload-set fix must not turn a virtual call
/// into a static one.
#[test]
fn virtual_member_joins_overload_set_and_still_dispatches() {
    let src = "\
        struct B { int x; virtual int f(int a); int f(int a, int b); };\n\
        struct D : B { virtual int f(int a); };\n\
        int B::f(int a) { return 10 + a; }\n\
        int B::f(int a, int b) { return a + b; }\n\
        int D::f(int a) { return 20 + a; }\n\
        int main() { B* p = new D(); return p->f(5); }\n";
    assert_eq!(run_src(src), 25);
}

/// S6: Win64 uses register `this`, so secondary-base vtables need an x64
/// this-adjusting thunk (`sub rcx, off; jmp target`). Without it the parser
/// poisoned any polymorphic non-primary base on x64, which rejected OWL shapes
/// such as `TWindow : virtual TEventHandler, virtual TStreamableBase` at
/// heap-allocation sites.
#[test]
fn win64_mi_polymorphic_second_base_new_and_virtual_dispatch() {
    let src = "\
        struct B1 { int a; B1(){ a = 5; } virtual int f(){ return 1; } };\n\
        struct B2 { int b; B2(){ b = 6; } virtual int g(){ return 2; } };\n\
        struct D : B1, B2 { \
          int c; \
          D(){ c = 7; } \
          int f(){ return a + 10; } \
          int g(){ return b + 20; } };\n\
        int main(void){ \
          D* d = new D(); \
          B2* p2 = d; \
          B1* p1 = d; \
          return p1->f() + p2->g() + d->c - 6; }\n";
    assert_eq!(run_src(src), 42);
}

#[test]
fn win64_mi_secondary_thunk_with_eh_metadata() {
    let src = "\
        struct B1 { int a; B1(){ a = 5; } virtual int f(){ return 1; } };\n\
        struct B2 { int b; B2(){ b = 6; } virtual int g(){ return 2; } };\n\
        struct D : B1, B2 { \
          int c; \
          D(){ c = 7; } \
          int f(){ return a + 10; } \
          int g(){ return b + 20; } };\n\
        int main(void){ \
          try { \
            D* d = new D(); \
            B2* p2 = d; \
            B1* p1 = d; \
            return p1->f() + p2->g() + d->c - 6; \
          } catch(...) { return 1; } }\n";
    assert_eq!(run_src(src), 42);
}

#[test]
fn win64_fstream_shaped_data_bearing_virtual_base_diamond() {
    let src = "\
        struct ios { \
          int state; \
          ios(){ state = 7; } \
          int val(){ return state; } \
          void set(int x){ state = x; } \
          virtual ~ios(){} \
        };\n\
        struct fstreambase : virtual public ios { \
          int fb; \
          fstreambase(){ fb = 3; } \
          virtual ~fstreambase(){} \
        };\n\
        struct istream : virtual public ios { \
          int input; \
          istream(){ input = 5; } \
          virtual ~istream(){} \
        };\n\
        struct ostream : virtual public ios { \
          int output; \
          ostream(){ output = 11; } \
          virtual ~ostream(){} \
        };\n\
        struct iostream : public istream, public ostream { \
          int both; \
          iostream(){ both = 13; } \
          virtual ~iostream(){} \
        };\n\
        struct fstream : public fstreambase, public iostream { \
          int file; \
          fstream(){ file = 17; } \
          virtual ~fstream(){} \
        };\n\
        int main(void){ \
          fstream f; \
          f.set(19); \
          fstreambase* fb = &f; \
          istream* in = &f; \
          ostream* out = &f; \
          ios* a = (ios*)fb; \
          ios* b = (ios*)in; \
          ios* c = (ios*)out; \
          return (f.val() == 19 && a->val() == 19 && b->val() == 19 && c->val() == 19 && \
                  f.fb == 3 && f.input == 5 && f.output == 11 && f.both == 13 && f.file == 17) \
                 ? 42 : 0; \
        }\n";
    assert_eq!(run_src(src), 42);
}

#[test]
fn win64_fstream_shaped_vbase_truthiness() {
    let src = "\
        struct ios { \
          int state; \
          ios(){ state = 0; } \
          int fail(){ return state & 6; } \
          operator void*(){ return fail() ? (void*)0 : this; } \
          int operator!(){ return fail(); } \
          void set(int x){ state = x; } \
          virtual ~ios(){} \
        };\n\
        struct fstreambase : virtual public ios { \
          int fb; \
          fstreambase(){ fb = 3; } \
          virtual ~fstreambase(){} \
        };\n\
        struct istream : virtual public ios { \
          int input; \
          istream(){ input = 5; } \
          virtual ~istream(){} \
        };\n\
        struct ostream : virtual public ios { \
          int output; \
          ostream(){ output = 11; } \
          virtual ~ostream(){} \
        };\n\
        struct iostream : public istream, public ostream { \
          int both; \
          iostream(){ both = 13; } \
          virtual ~iostream(){} \
        };\n\
        struct fstream : public fstreambase, public iostream { \
          int file; \
          fstream(){ file = 17; } \
          virtual ~fstream(){} \
        };\n\
        int main(void){ \
          fstream f; \
          int r = 0; \
          if (f) r = r + 7; else r = r + 100; \
          if (!f) r = r + 1000; else r = r + 5; \
          f.set(6); \
          if (f) r = r + 2000; else r = r + 11; \
          if (!f) r = r + 19; else r = r + 3000; \
          return r; \
        }\n";
    assert_eq!(run_src(src), 42);
}

/// S6 minimal RTTI: `typeid(X).name()` lowers to a string of X's STATIC type
/// name — the only way typeid is used in the BC45 corpus (the real
/// TApplication::Run's `catch(Bad_cast&){…typeid(x).name()…}` handlers +
/// IMPLEMENT_STREAMABLE's `typeid(cls).name()` registry key). A class's name is
/// its tag, so `typeid(w).name()[0]` is 'W' for `Widget`. RUN-verified. (The
/// full typeinfo/tpid ABI — dynamic typeid via the vtable — is the separate #38
/// stone; this minimal static form unblocks the real OWL runtime's compile,
/// where typeid only ever feeds `.name()`.)
#[test]
fn typeid_name_yields_static_type_name_string() {
    let src = "\
        struct Widget { int x; };\n\
        int main() { Widget w; const char* n = typeid(w).name(); return (int)n[0]; }\n";
    assert_eq!(run_src(src), 'W' as i32);
}

/// S6: `catch (...)` (catch-all) — the personality adds a kind=4 branch that
/// matches ANY in-range exception with no type check and terminates the search.
/// RUN-verified semantics: it CATCHES a throw (→42); does NOT fire on normal
/// completion (→99); and a TYPED handler is tried before it (→5). This is the
/// real OWL TApplication::Run's outer-handler shape (the rethrow sub-case is a
/// separate increment). The personality byte change is byte-safe — no
/// byte-identity baseline uses EH, so none emits the personality function.
#[test]
fn catch_all_handler_catches_any_throw() {
    assert_eq!(
        run_src("int main(){int r=0; try{throw 5; r=99;}catch(...){r=42;} return r;}"),
        42,
    );
    assert_eq!(
        run_src("int main(){int r=0; try{r=99;}catch(...){r=42;} return r;}"),
        99,
    );
    assert_eq!(
        run_src("int main(){int r=0; try{throw 5;}catch(int x){r=x;}catch(...){r=1;} return r;}"),
        5,
    );
}

/// S6: `throw;` (rethrow) inside a `catch (...)` body re-raises the ORIGINAL
/// exception verbatim to an outer handler. This is the exact APPLICAT.CPP
/// pattern (OSL/EXCEPT.H's exception-cloning inline does `catch(...){…throw;}`).
/// The personality's catch-all branch stamps the caught ExceptionRecord into
/// `.mdbcc_eh_save`; the rethrow re-raises from there, so the outer typed
/// handler observes the unchanged exception.
///
/// RUN-verified two ways:
/// * int: inner catch-all adds 1, rethrows 42, outer `catch(int)` adds 42 ⇒ 43
///   (a lost/garbled rethrow would yield 1 or a crash).
/// * class: inner catch-all adds 2, rethrows a polymorphic E{v=40}, outer
///   `catch(E&)` reads ex.v=40 ⇒ 42 (verifies the re-raise preserves BOTH the
///   vtable (args[0]) and the buffer ptr (args[1]), since a wrong vtable would
///   miss the outer match and a wrong buffer would read garbage for ex.v).
#[test]
fn catch_all_rethrow_reraises_original_to_outer_handler() {
    // int payload re-raised through catch-all
    assert_eq!(
        run_src(
            "int main(){int r=0; \
               try { try { throw 42; } catch(...) { r+=1; throw; } } \
               catch(int x) { r+=x; } \
             return r;}"
        ),
        43,
    );
    // polymorphic-class payload re-raised through catch-all (the APPLICAT case)
    assert_eq!(
        run_src(
            "struct E { int v; virtual ~E(){} }; \
             int main(){int r=0; \
               try { try { E e; e.v=40; throw e; } catch(...) { r+=2; throw; } } \
               catch(E& ex) { r+=ex.v; } \
             return r;}"
        ),
        42,
    );
}

/// S6: address-of a member of a NESTED class — `&Outer::Inner::f`. mdbcc's class
/// model is FLAT (nested `Outer::Inner` collapses to innermost tag `Inner`), and
/// every other path already flattens (out-of-line members `A::B::m`→`B::m`,
/// bases `TCriticalSection::Lock`→`Lock`, nested TYPE refs by last component).
/// The member-address path was the lone hold-out keeping the full qualified
/// "Outer::Inner", so `&TApplication::Streamer::Build` (OWL IMPLEMENT_STREAMABLE,
/// APPLICAT.CPP:880) failed with "no class named 'TApplication::Streamer'".
/// Flattening the qualifier to its innermost component fixes it; APPLICAT.CPP
/// now compiles past the Streamer registration.
///
/// RUN-verified via an inline `.*` call (non-static member to avoid the separate
/// pre-existing static-member-`this` gap): `(o.*&Outer::Inner::f)(41)` invokes
/// `Inner::f`, which returns x+1 ⇒ 42. A mis-resolved nested class would error
/// at compile time; a wrong target would return a wrong value.
#[test]
fn address_of_nested_class_member_flattens_qualifier() {
    let src = "\
        struct Outer { struct Inner { int f(int x){ return x + 1; } }; };\n\
        int main(){ Outer::Inner o; return (o.*&Outer::Inner::f)(41); }\n";
    assert_eq!(run_src(src), 42);
}

/// S6: a class that is THROWN but never instantiated in the TU must still be
/// force-lived so its EH type tag (vtable for a polymorphic class, typeinfo
/// entry otherwise) exists. The reachability walker force-lived CAUGHT types
/// (`catch (T)`) but not THROWN types — so `throw *p` / `throw *this` of a
/// dormant class left its `RipRef::Vtable` dangling (codegen panic) and its EH
/// buffer unsized ("class size N exceeds the shared exception buffer size 0").
/// This is the OWL exception idiom `void Throw(){ throw *this; }` (window.h:161
/// TXWindow, a nested polymorphic exception never `new`'d in APPLICAT.CPP) — the
/// last gate before APPLICAT.CPP compiles end-to-end.
///
/// RUN-verified: `trigger` throws `*p` (a polymorphic E never instantiated
/// anywhere), guarded by a runtime-false flag so the throw doesn't execute — the
/// point is that the TU now COMPILES (pre-fix: codegen panic) and the function
/// runs, returning 7. The deref `*p` exercises the new `rg_expr_type` deref arm.
#[test]
fn thrown_but_uninstantiated_class_is_force_lived() {
    let src = "\
        struct E { int v; virtual int k(){ return 1; } };\n\
        int trigger(E* p, int go){ if (go) throw *p; return 7; }\n\
        int main(){ return trigger(0, 0); }\n";
    assert_eq!(run_src(src), 7);
}

/// S6: a block-scope FUNCTION DECLARATION — a local forward-declaration of a
/// file-scope function, `int helper(uint32 id);` inside a function body. This is
/// the OWL/WINDOW.CPP:273 pattern (`void CacheFlush(uint32 id);` declared before
/// the call at :274, defined at :756) that blocked TWindow's destructor from
/// parsing. The statement parser read `int helper` as a variable decl and choked
/// on `(`. Now a paren-list that STARTS WITH A TYPE (distinguishing it from the
/// scalar direct-init `int x(5)`, whose paren holds an expression) is parsed as a
/// prototype and discarded — the call resolves via the file-scope definition.
///
/// RUN-verified: the locally-declared `helper` (defined above main) is called and
/// returns id+1 = 42. (A scalar direct-init `int x(5)` must still NOT be eaten by
/// this path — covered by the existing init tests.)
#[test]
fn block_scope_function_declaration_parses() {
    let src = "\
        typedef unsigned uint32;\n\
        int helper(uint32 id){ return (int)id + 1; }\n\
        int main(){ int helper(uint32 id); return helper(41); }\n";
    assert_eq!(run_src(src), 42);
}

/// S6: assigning a SCALAR to a record-typed lvalue that has a converting ctor and
/// NO user `operator=` — `Attr.Menu = 0` where `TResId Menu;` has `TResId(int)`
/// (OWL/WINDOW.CPP:196, TWindow::Init). The record-copy assignment path took the
/// RHS's address for a member-wise copy, but a bare scalar `0` is not addressable
/// → "expression is not an lvalue". Now `lv = x` rewrites to `lv = T(x)` (the
/// converting-ctor rvalue, which IS addressable) and the member-wise copy runs.
///
/// RUN-verified: `m.Menu = 7` stores via `R(7)` (Id = (char*)7), and reading
/// `m.Menu.Id` back yields 7. (`R(0)` then `R(7)` exercises the converting ctor,
/// not the default.)
#[test]
fn record_lvalue_assigned_scalar_uses_converting_ctor() {
    let src = "\
        struct R { const char* Id; R():Id(0){} R(int n):Id((const char*)(long)n){} };\n\
        struct A { R Menu; };\n\
        int main(){ A m; m.Menu = 7; return (int)(long)m.Menu.Id; }\n";
    assert_eq!(run_src(src), 7);
}

/// S6: an UNRELATED free `operator@` must not hijack a comparison whose real
/// resolution is a conversion-operator coercion. `p != w` is HND vs Win (Win has
/// `operator HND()`) and must coerce `w`→HND then compare via the builtin — NOT
/// call the free `operator!=(const S&, const S&)` that merely EXISTS in the TU.
/// Before the viability gate, `free_binop_call` selected that free op and (with a
/// lone candidate) reinterpreted the operands → returned 100, a SILENT
/// MISCOMPILE; with the RTL's `operator!=(const string&,…)` candidates it instead
/// errored "no matching overload for call to 'operator!='" (OWL/WINDOW.CPP:658,
/// `hCmdTarget != *this`, HWND vs TWindow). Now a free operator fires only when a
/// candidate's record param matches a record operand.
///
/// RUN-verified two ways: (1) the hijack case coerces → 0 (was 100); (2) the free
/// op STILL fires when both operands actually match it → 7.
#[test]
fn unrelated_free_operator_does_not_hijack_conversion_comparison() {
    let hijack = "\
        struct S { int v; };\n\
        int operator!=(const S& a, const S& b){ return 100; }\n\
        struct HND__; typedef HND__* HND;\n\
        struct Win { HND h; operator HND() const { return h; } };\n\
        int main(){ Win w; w.h=(HND)0; HND p=(HND)0; return (p != w); }\n";
    assert_eq!(run_src(hijack), 0);
    let matches = "\
        struct S { int v; };\n\
        int operator!=(const S& a, const S& b){ return a.v != b.v ? 7 : 3; }\n\
        int main(){ S x; x.v=1; S y; y.v=2; return (x != y); }\n";
    assert_eq!(run_src(matches), 7);
}

/// S6 (#61): `typeid(EXPR).tpp` for a polymorphic object yields a unique DYNAMIC
/// type-identity. This is OWL's `TYPE_UNIQUE_UINT32` (window.h:31,
/// `reinterpret_cast<uint32>(typeid(t).tpp)`), the `OWL_RTTI_MSGCACHE` key set in
/// WINDOW.CPP:817 `UniqueId = TYPE_UNIQUE_UINT32(*this)`. #38 handled only
/// `.name()`. mdbcc lowers `typeid(EXPR).tpp` (polymorphic lvalue) to the object's
/// VPTR (`[&EXPR+0]`) — unique per dynamic type and stable, the exact identity
/// property the cache needs; the value differs from bcc32's real `tpp` address but
/// `UniqueId` is an internal key, never observed, so behaviour matches.
///
/// RUN-verified (the genuine oracle): two B's share a dynamic type ⇒ equal ids;
/// a D differs ⇒ unequal id ⇒ 42. A static (non-vptr) lowering would give all
/// three the same id (B's static type) and return 1 — caught here.
#[test]
fn typeid_tpp_yields_dynamic_type_identity_via_vptr() {
    let src = "\
        struct B { virtual ~B(){} };\n\
        struct D : B {};\n\
        unsigned id(B& b){ return (unsigned)(unsigned long)typeid(b).tpp; }\n\
        int main(){ B b1, b2; D d1; return (id(b1)==id(b2) && id(b1)!=id(d1)) ? 42 : 1; }\n";
    assert_eq!(run_src(src), 42);
}

/// S6 (#63, part A): a user-defined conversion (a converting CTOR) applied to a
/// call ARGUMENT to match a `const Record&` parameter. `f(21)` picks
/// `f(const C&)` by converting the `int` via `C(int)` and binding the reference
/// to the temp. This generalizes the existing `const char*`→class UDC (S4.2at) to
/// ANY scalar→record converting ctor — e.g. `COLORREF → TColor` for an OWL
/// `f(const TColor&)`. Gated to BY-REFERENCE params (the marshal path builds the
/// temp + binds the ref); by-value record params are deferred (their 7 marshal
/// sites lack a UDC branch — accepting them would silently pass the raw scalar).
///
/// RUN-verified: `f(21)` → `C(21)` (v=42) → `f(const C&)` returns 42. The `char*`
/// overload is non-viable for an int arg, so the resolver's UDC scoring runs.
#[test]
fn byref_param_scalar_arg_uses_converting_ctor_udc() {
    let src = "\
        struct C { int v; C(int x):v(x*2){} };\n\
        int f(const C& c){ return c.v; }\n\
        int f(char* s){ return s ? 1 : 0; }\n\
        int main(){ return f(21); }\n";
    assert_eq!(run_src(src), 42);
}

/// S6 (#22): NON-TYPE (value) template parameters. A class template
/// `template<int N> struct A` / `template<E v> struct B` instantiated with a VALUE
/// argument (`A<7>`, `B<e2>`) — the value binds at instantiation (as a scoped
/// enum-constant) so the body's uses of the param fold to it, and distinct values
/// produce distinct instantiations. This is the OWL layout cluster's
/// `TEdgeOrSizeConstraint<lmWidth>` / `<lmHeight>` (layoutco.h:130/174, ~7 files);
/// mdbcc previously errored "expected a type, found Ident(lmWidth)".
///
/// RUN-verified: `A<7>::f()` → 7 (int param); `B<e2>`/`B<e3>` are DISTINCT
/// instantiations whose `g()` returns 2 and 3 → 23 (enum param + per-value
/// instantiation, not a single shared/collided record).
/// S6 (#63 A', rvalue form): a ctor-rvalue `Tag(scalar)` whose viable 1-arg ctor
/// takes a BY-VALUE record `R` constructible from the scalar — the scalar is
/// converted via `R`'s converting ctor (`Tag(R(scalar))`). This is the OWL
/// `TBrush(GetSysColor(...))` pattern (GADGET.CPP:190 — COLORREF → TColor →
/// TBrush(TColor)), a by-value analogue of the by-ref UDC. Applied centrally in
/// gen_call_with_lead so it covers the rvalue/temporary form (the `Tag v(args)`
/// DECL form goes through a different path, still pending).
///
/// RUN-verified: `use(Brush(7))` → `Brush(R(7))` (R::v = 21) → 21. The overloaded
/// `Brush(int*)` ctor is non-viable for an int, so the converting-ctor path is the
/// only match.
#[test]
fn ctor_rvalue_byvalue_record_param_uses_converting_ctor_udc() {
    let src = "\
        struct R { int v; R(int x):v(x*3){} };\n\
        struct Brush { int b; Brush(R r):b(r.v){} Brush(int* p):b(0){} };\n\
        int use(Brush br){ return br.b; }\n\
        int main(){ return use(Brush(7)); }\n";
    assert_eq!(run_src(src), 21);
}

/// S6 (#63 A', decl form): the `Tag v(scalar)` DECL form of the by-value ctor UDC
/// — `Brush hi(7)` (vs the rvalue `Brush(7)`). The decl ctor-args auto-invoke
/// routes through the gen + expr_type MethodCall arms (recv.Tag(args)), which
/// resolve the ctor BEFORE gen_call_with_lead; both now rebuild the call with the
/// scalar converted via the by-value record param's ctor. This is the OWL
/// `TBrush highlight(GetSysColor(...))` pattern (GADGET.CPP:195) — landing it
/// FLIPPED GADGET.CPP to PASS.
///
/// RUN-verified: `Brush hi(7)` → `hi.Brush(R(7))` (b = 21).
#[test]
fn ctor_decl_byvalue_record_param_uses_converting_ctor_udc() {
    let src = "\
        struct R { int v; R(int x):v(x*3){} };\n\
        struct Brush { int b; Brush(R r):b(r.v){} Brush(int* p):b(0){} };\n\
        int main(){ Brush hi(7); return hi.b; }\n";
    assert_eq!(run_src(src), 21);
}

/// S6: a VIRTUAL method returning a struct/class BY VALUE (win64). The hidden
/// result pointer is the first integer arg (RCX), shifting `this` to RDX; the
/// vtable slot is loaded from `this` (RDX). Previously rejected ("virtual method
/// returning a struct/class by value is not yet supported") — the OWL TDC/TColor
/// accessors (TColor TDC::GetBkColor(), etc.) and GAUGE/HSLIDER/GADGETWI hit this.
///
/// RUN-verified through a BASE POINTER (true virtual dispatch): `p->make(5)` calls
/// `Der::make` via the vtable, returning `R{5,10}` by value ⇒ 15. A wrong vtable
/// dispatch or a clobbered `this`/result-ptr would give a wrong value.
#[test]
fn virtual_method_returning_record_by_value() {
    let src = "\
        struct R { int a, b; };\n\
        struct Base { virtual R make(int x){ R r; r.a=x; r.b=0; return r; } virtual ~Base(){} };\n\
        struct Der : Base { R make(int x){ R r; r.a=x; r.b=x*2; return r; } };\n\
        int main(){ Der d; Base* p = &d; R r = p->make(5); return r.a + r.b; }\n";
    assert_eq!(run_src(src), 15);
}

/// S6: `return <scalar>;` from a record-returning function — the return value is
/// constructed from the scalar via the record's converting ctor. This is the
/// return-statement analogue of the by-value ctor UDC, and is pervasive in OWL's
/// `TDC`/`TColor` accessors (`TColor TDC::GetBkColor(){ return ::GetBkColor(h); }`
/// — COLORREF → TColor); previously "cannot return a non-record expression from a
/// record-returning function".
///
/// RUN-verified: `make(5)` returns an int that constructs `C(5)` (v = 105).
#[test]
fn return_scalar_from_record_returning_fn_uses_converting_ctor() {
    let src = "\
        struct C { int v; C(int x):v(x+100){} };\n\
        C make(int n){ return n; }\n\
        int main(){ C c = make(5); return c.v; }\n";
    assert_eq!(run_src(src), 105);
}

/// S6 (#63 B): a RECORD ctor argument converted to a SCALAR param via the record's
/// CONVERSION OPERATOR — `TClipboard(*this)` where `*this` is a window with
/// `operator HWND()` (EDIT.CPP:334, `TClipboard clipboard(*this)`); the ctor takes
/// `HWND`. The complement of the converting-ctor direction. Guarded against
/// copy/slice (a record-param ctor the arg IS-A wins).
///
/// RUN-verified for BOTH the decl form `Clip c(w)` and the rvalue form `Clip(w)`:
/// `w` (a W with `operator HND()`) converts to HND, the ctor stores it ⇒ 42.
#[test]
fn record_ctor_arg_converts_to_scalar_param_via_operator() {
    let src = "\
        struct H__; typedef H__* HND;\n\
        struct W { HND h; operator HND() const { return h; } };\n\
        struct Clip { long k; Clip(HND x):k((long)x){} Clip():k(0){} };\n\
        int main(){ W w; w.h=(HND)0; Clip c(w); Clip d = Clip(w); return (c.k==0 && d.k==0) ? 42 : 1; }\n";
    assert_eq!(run_src(src), 42);
}

/// S6: a derived class's copy ctor SLICES its base via `Base(src)` where `Base`
/// has 2+ user ctors (⇒ registered in `overloads`) but NO user/synth copy ctor —
/// a TRIVIAL (bitwise) base-subobject copy. `resolve_overload` carries no
/// implicit-copy-ctor candidate, so before the gen-site `emit_struct_copy`
/// fallback this hard-errored ("no matching overload for call to 'X::X'").
/// Non-trivial bases with their own base/member copy needs are handled by the
/// synthesized copy-ctor path; this fallback is only for genuinely trivial
/// base slices. A single-ctor (`funcs`) base keeps its existing path, so this is
/// purely additive.
///
/// RUN-verified: `D d2(d1)` bitwise-slices d1's X subobject (v = 7+9 = 16) into
/// d2; the explicit member w is d1.w+5 (= 8). returns 16 + 8 = 24.
#[test]
fn derived_copy_ctor_slices_base_with_two_ctors_no_copy_ctor() {
    let src = "\
        struct X { int v; X(int a,int b):v(a+b){} X(const char* s):v(99){} };\n\
        struct D : X { int w; D():X(7,9),w(3){} D(const D& s):X(s),w(s.w+5){} };\n\
        int main(){ D d1; D d2(d1); return d2.v + d2.w; }\n";
    assert_eq!(run_src(src), 24);
}

#[test]
fn non_type_template_parameters_bind_values() {
    let int_param = "\
        template<int N> struct A { int f(){ return N; } };\n\
        int main(){ A<7> a; return a.f(); }\n";
    assert_eq!(run_src(int_param), 7);
    let enum_param = "\
        enum E { e0, e1, e2, e3 };\n\
        template<E v> struct B { int g(){ return (int)v; } };\n\
        int main(){ B<e2> b2; B<e3> b3; return b2.g()*10 + b3.g(); }\n";
    assert_eq!(run_src(enum_param), 23);
}

/// #57: a class-template instantiation made from a FORWARD declaration and frozen
/// into a typedef BEFORE the body is defined must still pick up the members once
/// the body appears. This is the OWL EVENTHAN.H `TResponseTableEntry` /
/// `TGenericTableEntry` pattern (forward at :55, typedef-instantiate at :56, body
/// at :97) that underlies the response-table (__entries) and `no member named`
/// clusters (~30 OWL files). RUN-verified: the completed layout is correct, so
/// `e->Msg + e->Id` reads back 5+7 = 12 (a wrong layout would yield a wrong value).
#[test]
fn forward_declared_template_instantiation_completes_members() {
    let src = "\
        template <class T> struct E;            /* forward declaration */\n\
        typedef E<int> EI;                      /* instantiate from INCOMPLETE */\n\
        template <class T> struct E { int Msg; int Id; };  /* body (later) */\n\
        int f(EI* e) { return e->Msg + e->Id; }\n\
        int main(void) { EI e; e.Msg = 5; e.Id = 7; return f(&e); }\n";
    assert_eq!(run_src(src), 12);
}

/// OUT-OF-LINE definition of a static member function pointer:
/// `int (*C::fp)(int) = setter;` — OWL DOCTPL.CPP:99-100
/// (`bool (*TDocTemplate::SelectSave_)(...) = SelectSaveX;`). The grouped fn-ptr
/// declarator parsed only a SIMPLE name, so the qualified `C::fp` errored
/// "expected ')'". Now it accepts `Class::member` and emits the static member's
/// global with the function-address initializer. RUN-verified: `C::fp == setter`
/// and `(C::fp)(42)` sets `got` to 42 — the definition stores the right address.
/// (A bare unparenthesised `C::fp(42)` call is a separate codegen gap, #58, that
/// NO real source file uses — across all CLASSLIB+OWL only DOCTPL defines this,
/// and it never bare-calls — so the parse fix is safe.)
#[test]
fn out_of_line_static_member_function_pointer_definition() {
    let src = "\
        int got;\n\
        int setter(int x) { got = x; return x + 1; }\n\
        struct C { static int (*fp)(int); };\n\
        int (*C::fp)(int) = setter;\n\
        int main(void) { (C::fp)(42); return got + (C::fp == setter ? 0 : 100); }\n";
    assert_eq!(run_src(src), 42);
}

/// C++ boolean literals `true` / `false`. mdbcc models `bool` as u8, so these are
/// the integer constants 1 / 0. They were unsupported (lexed as undeclared
/// identifiers), which blocked any header using them — e.g. OWL/applicat.h's
/// `bool enable = true` default args, on the real HELLOAPP path. RUN-verified.
#[test]
fn boolean_literals_true_and_false() {
    let src = "int main(void) { bool b = true; bool c = false; return (b && !c) ? 7 : 0; }\n";
    assert_eq!(run_src(src), 7);
}

/// A C-style cast whose type is `const` + a TYPEDEF/TAG name — `(const Foo)x` —
/// must be recognised as a cast, not mis-read as a parenthesised expression.
/// `peek_is_type_after_lparen` put a leading `const` in the built-in-keyword arm,
/// so the following typedef name went unconsumed and the cast was rejected
/// ("expected an expression" at `const`) — a regression that broke real-header
/// parsing (OWL/applicat.h -> HELLOAPP). Pre-consuming leading cv-quals fixes it.
/// RUN-verified: `(const Foo)x` casts cleanly. (`(const int)`, `(Foo)`, the
/// functional-cast `(long(5))/2`, and `(Flags & mask)` all still behave.)
#[test]
fn cast_const_typedef_is_recognized() {
    let src = "\
        typedef int Foo;\n\
        int main(void) { Foo x = 35; return (const Foo)x + (const int)7; }\n";
    assert_eq!(run_src(src), 42);
}
