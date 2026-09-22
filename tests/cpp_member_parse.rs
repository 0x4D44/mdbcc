//! S4.2: member/declarator parse-completeness surfaced by the BC++ 4.52
//! RTL/classlib closure (CSTRING.H, REF.H, EXCEPT.H, ...). Each construct below
//! came from a real header that blocked the `<owl/applicat.h>` closure:
//!
//!  * function exception-specifications — `void raise() throw(xmsg);`
//!  * a calling convention after a reference `&` — `string & __cdecl why()`
//!  * compound-assignment / bitwise / shift operator names — `operator +=`
//!  * `friend` declarations inside a class
//!  * a bare nested type definition — `enum StripType { ... };`
//!  * a stray top-level `;` (empty declaration) after a definition
//!
//! Where a value can be observed the test compiles + runs (Win64) and asserts
//! the exit code; the rest are compile-acceptance (the program builds without a
//! parse/codegen error).

#![cfg(windows)]

mod support;

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::compile_to_pe;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);
impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Compile + run, returning the exit code.
fn code(src: &str) -> i32 {
    let exe = compile_to_pe(src.as_bytes()).expect("mdbcc compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_memparse_{}_{}.exe", std::process::id(), n));
    let t = TempExe(p);
    std::fs::write(&t.0, &exe).expect("write exe");
    Command::new(&t.0)
        .status()
        .expect("launch")
        .code()
        .expect("exit code")
}

/// Compile-acceptance only: the source builds without error.
fn compiles(src: &str) {
    assert!(
        compile_to_pe(src.as_bytes()).is_ok(),
        "expected a clean compile"
    );
}

/// A member function with an exception-specification AND a body runs normally
/// (the spec is parsed and discarded).
#[test]
fn member_with_exception_spec_runs() {
    let src = "struct S { int f() throw(int) { return 5; } };\n\
               int main(){ S s; return s.f(); }";
    assert_eq!(code(src), 5);
}

/// A nested `enum` defined inside a class, used by an inline method.
#[test]
fn nested_enum_member() {
    let src = "struct S { enum E { A, B, C }; int pick() { return C; } };\n\
               int main(){ S s; return s.pick(); }";
    assert_eq!(code(src), 2);
}

/// A `friend` declaration inside a class is accepted (and skipped); the
/// befriended free function is defined at namespace scope and callable.
#[test]
fn friend_declaration_then_free_function() {
    let src = "struct S { friend int helper(S s); int x; };\n\
               int helper(S s){ return s.x; }\n\
               int main(){ S s; s.x = 9; return helper(s); }";
    assert_eq!(code(src), 9);
}

/// A reference-returning member with a calling convention after the `&`
/// (`int & __cdecl r()`) — the RTL spelling `string & _RTLENTRY why()`. The
/// convention is dropped (identical codegen to the conv-free form). Reading
/// through the returned reference yields the member's value.
#[test]
fn calling_conv_after_reference() {
    let src = "struct S { int v; int & __cdecl r() { return v; } };\n\
               int main(){ S s; s.v = 8; return s.r(); }";
    assert_eq!(code(src), 8);
}

/// Reading through a reference-returning method (value context) loads the
/// referent's VALUE, not its address. RTL/classlib accessors return references
/// pervasively (`string& why()`); previously this returned a stack address.
#[test]
fn reference_returning_method_read() {
    // Direct read, and a ref result used inside an arithmetic expression.
    assert_eq!(
        code(
            "struct S { int v; int& r() { return v; } };\n\
                     int main(){ S s; s.v = 6; return s.r(); }"
        ),
        6
    );
    assert_eq!(
        code(
            "struct S { int v; int& r() { return v; }\n\
                     int twice() { return r() + r(); } };\n\
                     int main(){ S s; s.v = 5; return s.twice(); }"
        ),
        10
    );
}

/// A stray top-level `;` after a function definition (empty declaration).
#[test]
fn stray_top_level_semicolon() {
    let src = "int f(){ return 4; };\n\
               int main(){ return f(); };";
    assert_eq!(code(src), 4);
}

/// `static_cast<T>(e)` lowers to a C-style cast (osl/defs.h's `ToBool`
/// template: `static_cast<bool>(t)`). A narrowing long→int value cast.
#[test]
fn static_cast_value() {
    let src = "int main(){ long x = 7; return static_cast<int>(x); }";
    assert_eq!(code(src), 7);
}

/// `const_cast<T*>` strips const so the pointee is writable through the result.
#[test]
fn const_cast_pointer() {
    let src = "int main(){ const int x = 4; int* p = const_cast<int*>(&x); return *p; }";
    assert_eq!(code(src), 4);
}

/// `reinterpret_cast<char*>` reads the low byte of an int (little-endian).
#[test]
fn reinterpret_cast_pointer() {
    let src = "int main(){ int x = 9; char* p = reinterpret_cast<char*>(&x); return *p; }";
    assert_eq!(code(src), 9);
}

/// Compound-assignment + other operator names parse as member declarations
/// (CSTRING.H declares `operator +=`, `operator <<`, etc.). Compile-acceptance.
#[test]
fn compound_and_bitwise_operator_names_parse() {
    compiles(
        "struct S {\n\
         \x20 int v;\n\
         \x20 S& operator+=(int n) { v += n; return *this; }\n\
         \x20 S& operator<<=(int n) { v <<= n; return *this; }\n\
         \x20 int operator!() { return v == 0; }\n\
         };\n\
         int main(){ return 0; }",
    );
}

/// S4.2e: a functional cast to a BUILT-IN type — `long(expr)` (CLASSLIB's
/// `return long(Width() * Height())`). mdbcc handled the `Ident(expr)` form; this
/// adds the scalar-keyword form.
#[test]
fn builtin_functional_cast() {
    assert_eq!(
        code("int main(){ int w = 6; int h = 7; return long(w * h); }"),
        42
    );
}

/// S4.2e: the most-vexing-parse — a functional-cast temporary with a member call
/// at statement scope (`Acc(2).val();`) is an EXPRESSION, not a declaration
/// (CLASSLIB's `Base::Streamer(base).Read(in,version)`). `at_decl` now treats an
/// Ident type-name immediately followed by `(…)` then `.`/`->`/`[` as an
/// expression. A direct-init variable (`Acc r(40)`) stays a declaration.
#[test]
fn functional_cast_temporary_statement() {
    let src = "struct Acc { int n; Acc(int x){ n = x; } int val(){ return n; } };\n\
               int main(){ int r = Acc(40).val(); Acc(2).val(); return r; }";
    assert_eq!(code(src), 40);
}

/// S4.2e: a DEPENDENT qualified type `T::Nested` (a nested type of a template
/// parameter) parses in a function-template body (CLASSLIB's `WriteBaseObject`:
/// `Base::Streamer strmr;`). It stays dependent (a `TemplateParam`) so codegen
/// errors cleanly at any instantiation rather than mis-resolving. A CONCRETE
/// `Outer::Inner` out-of-line member name is unaffected (left to the declarator).
#[test]
fn dependent_qualified_nested_type_parses() {
    compiles(
        "struct Outer { struct Inner { int v; }; };\n\
         template<class T> void f(T* p) { T::Inner x; }\n\
         int main(){ return 0; }",
    );
}

/// S4.2e: the RTTI `typeid` operator PARSES (so real OWL source gets past it —
/// `typeid(*this).name()` in the streaming classes) and reaches codegen as a
/// CLEAN error (RTTI semantics are the S4.5 stone), NOT a parse error and NOT a
/// silent wrong-type result.
#[test]
fn typeid_parses_then_clean_codegen_error() {
    let err = compile_to_pe(b"int main(){ typeid(0); return 0; }")
        .expect_err("typeid codegen is deferred (S4.5)");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("typeid") || msg.to_lowercase().contains("rtti"),
        "expected a typeid/RTTI codegen error (proving it PARSED), got: {msg}"
    );
}

/// S4.2f: an explicit FULL specialization of a class template, Borland's
/// `template<>`-less form (`struct Box<char> { … };`, OSL/GEOMETRY.H's
/// `class TPointer<char>`). The specialization is parsed as a concrete record;
/// the PRIMARY still instantiates for other arguments.
#[test]
fn class_template_specialization_primary_still_works() {
    // `Box<char>` is specialized; `Box<int>` uses the primary.
    let src = "template<class T> struct Box { T v; };\n\
               struct Box<char> { int special; };\n\
               int main(){ Box<int> b; b.v = 3; return b.v; }";
    assert_eq!(code(src), 3);
}

/// S4.2f: instantiating EXACTLY the specialized arguments uses the specialized
/// body, not the primary template's fields.
#[test]
fn class_template_specialization_body_is_used() {
    let src = "template<class T> struct Box { T v; };\n\
               struct Box<char> { int special; };\n\
               int main(){ Box<char> b; b.special = 42; return b.special; }";
    assert_eq!(code(src), 42);
}

/// S4.2f: a function template whose declarator returns/takes a POINTER-TO-MEMBER
/// (OWL/SIGNATUR.H's `bool(T::*B_Sig(bool(T::*pmf)()))()` message-handler
/// signatures) is parsed-and-skipped so the header advances; an unrelated `main`
/// still compiles and runs.
#[test]
fn function_template_pointer_to_member_skipped() {
    let src = "template <class T> inline int(T::*B_Sig(int(T::*pmf)()))() \
               { return pmf; }\n\
               int main(){ return 7; }";
    assert_eq!(code(src), 7);
}

/// S4.2f: a typedef of a class-template INSTANTIATION, used as a type. This
/// exercises the `is_typedef` preservation fix — `instantiate_class_template`
/// re-enters `decl_specifiers` (for the `<…>` args), which reset the typedef
/// intent, so `typedef Box<int> BI;` previously registered a VARIABLE, not an
/// alias, and `BI b;` failed with "expected a type".
#[test]
fn typedef_of_template_instantiation_used_as_type() {
    let src = "template<class T> struct Box { T v; };\n\
               typedef Box<int> BI;\n\
               int main(){ BI b; b.v = 5; return b.v; }";
    assert_eq!(code(src), 5);
}

/// S4.2f: a FORWARD-declared class template (`template<class T> class TRE;`) is
/// registered so a use site recognises it — OWL/EVENTHAN.H writes
/// `typedef TResponseTableEntry<GENERIC> TGenericTableEntry;` then uses
/// `TGenericTableEntry*` as a member BEFORE the template body appears. The
/// instantiation is an opaque incomplete record; using it as a pointer is fine.
#[test]
fn forward_declared_class_template_typedef_pointer() {
    let src = "class GENERIC;\n\
               template<class T> class TRE;\n\
               typedef TRE<GENERIC> TG;\n\
               struct S { TG* entry; };\n\
               int main(){ S s; s.entry = 0; return 0; }";
    assert_eq!(code(src), 0);
}

/// S4.2f: a call instantiates a function template only when its ARITY matches.
/// CLASSLIB declares a 2-parameter placement allocator
/// `template<class Alloc> void* operator new(size_t, const Alloc&)`; a plain
/// `new X` lowers to a 1-arg `operator new(size)` and must resolve to the ordinary
/// global operator new, NOT mis-instantiate the 2-param template (which left
/// `Alloc` undeducible). Modelled here with a template/non-template overload pair.
#[test]
fn function_template_only_instantiated_on_arity_match() {
    let src = "template<class A> int pick(int s, const A& a){ return s + 1; }\n\
               int pick(int s){ return s; }\n\
               int main(){ return pick(42); }";
    assert_eq!(code(src), 42);
}

/// S4.2f: a QUALIFIED base-class name — `struct D : public Outer::Inner` (a class
/// deriving from a nested class, as OWL/window.h's
/// `class Lock : private TCriticalSection::Lock`). mdbcc's flat class model keeps
/// the innermost component; the base subobject (and its data) resolves correctly.
#[test]
fn qualified_base_class_name() {
    let src = "struct Outer { struct Inner { int x; }; };\n\
               struct D : public Outer::Inner { int y; };\n\
               int main(){ D d; d.x = 40; d.y = 2; return d.x + d.y; }";
    assert_eq!(code(src), 42);
}

/// S4.2f: a QUALIFIED base name in a ctor-init-list — `D(int x) :
/// Outer::Inner(x)` (OWL/window.h's out-of-line nested-class ctor
/// `TSync::Lock::Lock(...) : TCriticalSection::Lock(...)`). The base ctor is
/// chained correctly (the base subobject is initialised through the qualified
/// name).
#[test]
fn qualified_base_in_ctor_init_list() {
    let src = "struct Outer { struct Inner { int b; Inner(int v){ b = v; } }; };\n\
               struct D : public Outer::Inner { int d; \
               D(int x) : Outer::Inner(x) { d = x + 1; } };\n\
               int main(){ D o(41); return o.b + (o.d - 41); }";
    assert_eq!(code(src), 42);
}

/// S4.2f: a QUALIFIED nested type as a return type — `inline TThread::Status
/// TThread::GetStatus(...)` (OWL/window.h). `decl_specifiers` (via `qualify_nested`)
/// consumes `TThread::Status` as the return type and resolves it to the flat
/// nested type, leaving `TThread::GetStatus` for the declarator. The look-ahead
/// keeps an out-of-line member definition (`A::B::member()`) untouched.
#[test]
fn qualified_nested_type_as_return_type() {
    let src = "struct TThread { enum Status { Created, Running }; Status GetStatus(); };\n\
               inline TThread::Status TThread::GetStatus(){ return Running; }\n\
               int main(){ TThread t; return t.GetStatus(); }";
    assert_eq!(code(src), 1);
}

/// S4.2f: a MULTI-level qualified nested type as a return type —
/// `inline A::B::E A::B::get()` (OWL/window.h's
/// `TThread::ThreadError::ErrorType TThread::ThreadError::…`). `qualify_nested`
/// scans the whole `::` chain and resolves the final component.
#[test]
fn multilevel_qualified_nested_type_as_return_type() {
    let src = "struct A { struct B { enum E { X, Y, Z }; E get(); }; };\n\
               inline A::B::E A::B::get(){ return Z; }\n\
               int main(){ A::B b; return b.get(); }";
    assert_eq!(code(src), 2);
}

/// S4.2f: an explicit (pseudo-)destructor call through a qualified name —
/// `t.T::~T()` (OWL/window.h's `reinterpret_cast<TMutex*>(Mutex)->TMutex::~TMutex()`).
/// The member parser handles the `~` and the `::`-qualified member name; the
/// explicit call runs (here a no-op empty dtor, leaving the object intact).
#[test]
fn explicit_destructor_call_qualified() {
    let src = "struct T { int x; ~T(){} };\n\
               int main(){ T t; t.x = 42; t.T::~T(); return t.x; }";
    assert_eq!(code(src), 42);
}

/// S4.2f: a QUALIFIED type name in a `new` expression — `new Outer::Lock(42)`
/// (OWL/window.h's `new (AppLock) TMutex::Lock(...)`). In `new` context `A::B` is
/// unambiguously a type, so `new_type_prefix` consumes the `::` chain regardless
/// of the following `(`. (The placement form parses too; its codegen is the
/// separate deferred S4.2b item.)
#[test]
fn new_expression_with_qualified_type() {
    let src = "struct Outer { struct Lock { int v; Lock(int x){ v = x; } }; };\n\
               int main(){ Outer::Lock* p = new Outer::Lock(42); return p->v; }";
    assert_eq!(code(src), 42);
}

/// S4.2f: a member variable that SHADOWS a global type, used in a member body —
/// `W::set` does `F |= u32(m);` where a global `struct Flags`-style type exists.
/// In mdbcc's flat resolver `F`'s name could resolve to a global type, so the
/// statement looked like a declaration; `at_decl` now treats a binary/assignment
/// operator right after a "type-name" as proof it is a VALUE (an expression).
/// This is the shape of OWL/window.h's `Flags |= uint32(mask)` (CHECKS.H declares
/// a global `struct Flags`).
#[test]
fn member_shadowing_global_type_compound_assign() {
    let src = "struct Flags { int dummy; };\n\
               typedef unsigned u32;\n\
               struct W { void set(int m) { F |= u32(m); } u32 F; };\n\
               int main(){ W w; w.F = 0; w.set(10); return w.F; }";
    assert_eq!(code(src), 10);
}

/// S4.2f: `(member & value)` where `member` shadows a global type is a bit-and
/// EXPRESSION, not a `(Type&)` cast — OWL/window.h's `IsFlagSet` does
/// `return (Flags & mask) ? 1 : 0;` with a global `struct Flags` in scope.
/// `peek_is_type_after_lparen` now requires a full cast SHAPE (type + cv/`*`/`&`
/// then `)`); a value token after `&` means an expression.
#[test]
fn paren_member_bitand_not_a_ref_cast() {
    let src = "struct Flags { int d; };\n\
               struct W { unsigned F; int test(unsigned m){ return (F & m) ? 7 : 0; } };\n\
               int main(){ W w; w.F = 6; return w.test(2); }";
    assert_eq!(code(src), 7);
}

/// S4.2f: a POINTER-TO-MEMBER typedef inside a class template that is
/// INSTANTIATED — `template<class T> struct Entry { typedef void (T::*PMF)(); …}`
/// then `Entry<G>` (OWL/EVENTHAN.H's `TResponseTableEntry<cls>`, surfaced when the
/// captured body is replayed at instantiation). mdbcc parses `(T::*PMF)()` as a
/// function pointer (the `T::` is consumed/ignored), so the instantiation
/// succeeds and the record's other members stay usable.
#[test]
fn pointer_to_member_typedef_in_instantiated_template() {
    let src = "struct GENERIC { int x; };\n\
               template<class T> struct Entry { typedef void (T::*PMF)(); int id; PMF pmf; };\n\
               typedef Entry<GENERIC> GE;\n\
               int main(){ GE e; e.id = 42; return e.id; }";
    assert_eq!(code(src), 42);
}

/// S4.2f: a nested type of a class-template INSTANTIATION in a typedef —
/// `typedef Entry<G>::PMF MyPMF;` (OWL/window.h's DECLARE_RESPONSE_TABLE
/// `typedef TResponseTableEntry<cls>::PMF TMyPMF;`). Instantiation registers the
/// member type flat, so `decl_specifiers` routes the instantiation result through
/// `qualify_nested` to resolve the `::PMF` suffix.
#[test]
fn nested_type_of_class_template_instantiation() {
    let src = "struct G { int x; };\n\
               template<class T> struct Entry { typedef void (T::*PMF)(); int id; };\n\
               typedef Entry<G> GE;\n\
               typedef Entry<G>::PMF MyPMF;\n\
               int main(){ GE e; e.id = 9; return e.id; }";
    assert_eq!(code(src), 9);
}

/// S4.2g: a function whose body has a not-yet-instantiable template call is
/// DEFERRED (dropped with a diagnostic) instead of failing the whole TU — the
/// interim step toward inline-on-demand. Here `unused_helper` calls `tt(const T&)`
/// with a comparison arg the S4.1b deducer can't type, so it is deferred; `main`
/// (which never references it) compiles and runs. Mirrors OWL's unreachable inline
/// bodies that call `ToBool<T>`.
#[test]
fn undeducible_template_call_in_unused_fn_is_deferred() {
    let src = "template<class T> int tt(const T& t){ return 0; }\n\
               int unused_helper(){ return tt(1 == 1); }\n\
               int main(){ return 42; }";
    assert_eq!(code(src), 42);
}

/// S4.2h: an INLINE member function whose body needs a construct mdbcc can't
/// codegen yet is DEFERRED (dropped with a diagnostic), not a hard TU error — the
/// interim toward inline-on-demand. Here `S::make` does `new NoCtor(5)` (a class
/// with no matching ctor); it is inline and unreached by `main`, so it is deferred
/// and `main` compiles + runs. Mirrors OWL's unreachable inline bodies (e.g.
/// `inline string::string(char) { new TStringRef(...) }`).
#[test]
fn inline_member_failing_codegen_is_deferred() {
    let src = "struct NoCtor { int x; };\n\
               struct S { void make() { NoCtor* p = new NoCtor(5); (void)p; } };\n\
               int main(){ return 7; }";
    assert_eq!(code(src), 7);
}

/// S4.2h: a FREE function declared `inline` is also droppable on demand — its
/// `inline` is captured before the declarator/param-list clears the flag. Here a
/// free `inline make()` hits an unhandled construct and is deferred (not a hard
/// error), so `main` (which never calls it) compiles + runs. This is the shape of
/// OWL's header `inline bool operator==(TPoint, TPoint)`.
#[test]
fn free_inline_function_failing_codegen_is_deferred() {
    let src = "struct NoCtor { int x; };\n\
               inline void make() { NoCtor* p = new NoCtor(5); (void)p; }\n\
               int main(){ return 8; }";
    assert_eq!(code(src), 8);
}

/// S4.2e: a named cast is a postfix-expression — its result chains
/// (`static_cast<B*>(p)->get()`), as OWL's streaming classes write
/// (`static_cast<TStreamable*>(GetObjectA())->streamableName()`).
#[test]
fn named_cast_result_chains_postfix() {
    let src = "struct B { int v; int get(){ return v; } };\n\
               int main(){ B b; b.v = 9; void* p = &b; \
               return static_cast<B*>(p)->get(); }";
    assert_eq!(code(src), 9);
}

/// S4.2e: a stray `;` after an inline member body (`S(int x) : B(x) {} ;`) is
/// skipped, not parsed as a member (OWL's streaming classes write it). The
/// derived ctor's base-init still runs.
#[test]
fn stray_semicolon_after_inline_member_body() {
    let src = "struct B { int b; B(int x){ b = x; } };\n\
               struct S : public B { S(int x) : B(x) {} ; int y; };\n\
               int main(){ S s(7); return s.b; }";
    assert_eq!(code(src), 7);
}

/// S4.2e: a class-member TYPEDEF is registered as a type (mdbcc's flat model),
/// so it resolves at its use site — both a simple `typedef int Int;` (used as a
/// field type AND a return type) and a function-pointer `typedef void
/// (*Fn)(int&, void*);` (CLASSLIB/BIDS `typedef void (*IterFunc)(T&, void*)`).
/// Previously the member-typedef name was (wrongly) treated as a data member.
#[test]
fn member_typedef_registers_as_type() {
    let src = "struct S { typedef int Int; typedef void (*Fn)(int&, void*); \
               Int v; Int get(){ return v; } };\n\
               int main(){ S s; s.v = 8; return s.get(); }";
    assert_eq!(code(src), 8);
}

/// S4.2e: a SELF-REFERENTIAL class template — `Node<T>` with a `Node<T>* next`
/// member. Instantiating `Node<int>` re-parses the body, which references
/// `Node<int>` again; the instantiation cache is now PRE-REGISTERED before the
/// re-parse, so the self-reference resolves to the in-progress record instead of
/// recursing without bound (the omanip2 / BIDS `TVectorImpBase` pattern).
#[test]
fn self_referential_template_instantiation() {
    let src = "template<class T> class Node { public: T val; Node<T>* next; };\n\
               int main(){ Node<int> n; n.val = 5; n.next = 0; \
               return n.val + (n.next == 0 ? 2 : 0); }";
    assert_eq!(code(src), 7);
}

/// S4.2e: a DEPENDENT class-template instantiation — `Box<T>` where `T` is still
/// a generic parameter (in a function template's signature) — is DEFERRED, not
/// eagerly instantiated. Instantiating with a generic arg would re-parse the
/// body with the param unresolved (CLASSLIB's `template<class Alloc> class X :
/// public Alloc` ⇒ "unknown base class Alloc"). The dependent form returns an
/// opaque incomplete record; the real instantiation happens when the enclosing
/// template gets a concrete argument.
#[test]
fn dependent_template_instantiation_is_deferred() {
    compiles(
        "template<class T> class Box : public T {};\n\
         template<class T> Box<T>* mk() { return 0; }\n\
         int main(){ return 0; }",
    );
}

/// S4.2e: a Borland IMPLICIT-INT member function — `get(){...}` with no return
/// type returns `int` (CLASSLIB/MEMMGR.H's `AllocBlock( size_t );`). In a class
/// body `name(` where `name` is not a type is unambiguously such a method.
#[test]
fn implicit_int_member_function() {
    let src = "struct S { int n; S(int x){ n = x; } get(){ return n; } \
               twice(){ return n + n; } };\n\
               int main(){ S s(5); return s.get() + s.twice(); }";
    assert_eq!(code(src), 5 + 10);
}

/// S4.2e: a ctor whose init-list initializes a TEMPLATE-ID BASE
/// (`IntBox(int n) : Holder<int>(n) {}`). The init-list reader now skips the
/// `<...>` after the base name and routes the args to the base ctor — so the
/// base subobject is constructed with them. CLASSLIB's BIDS does this
/// (`TBlockList(blk) : TMBlockList<TStandardAllocator>(blk)`).
#[test]
fn ctor_initializes_template_id_base() {
    let src = "template<class T> class Holder { public: T v; Holder(T x){ v = x; } };\n\
               struct IntBox : public Holder<int> { IntBox(int n) : Holder<int>(n) {} };\n\
               int main(){ IntBox b(9); return b.v; }";
    assert_eq!(code(src), 9);
}

/// S4.2e: a class deriving from a class-template INSTANTIATION
/// (`struct IntBox : public Holder<int>`). The template is instantiated and the
/// concrete record becomes the base subobject, so inherited members/methods
/// resolve. CLASSLIB's BIDS containers derive from `TMBlockList<Alloc>` this way.
#[test]
fn derive_from_template_instantiation_base() {
    let src = "template<class T> class Holder { public: T v; T get() const { return v; } };\n\
               struct IntBox : public Holder<int> { void set(int x){ v = x; } };\n\
               int main(){ IntBox b; b.set(7); return b.get(); }";
    assert_eq!(code(src), 7);
}

/// S4.2e: an OUT-OF-LINE template-member definition (`template<class T>
/// Box<T>::Box(T) : v(x) {}` and `template<class T> T Box<T>::get() {...}`) is
/// accepted — the function-template path can't model the `Box<T>::` qualifier or
/// the ctor init-list, so these (the template's implementation) are skipped.
/// CLASSLIB's BIDS containers (TMBlockList, ...) define members this way.
#[test]
fn out_of_line_template_member_definitions_parse() {
    compiles(
        "template<class T> class Box { T v; public: Box(T x); T get() const; };\n\
         template<class T> Box<T>::Box(T x) : v(x) {}\n\
         template<class T> T Box<T>::get() const { return v; }\n\
         int main(){ return 0; }",
    );
}

/// Allocation-operator names parse as member declarations: `operator new`,
/// `operator new[]`, `operator delete`, `operator delete[]` (the keyword forms).
/// CLASSLIB/ALLOCTR.H's `TStandardAllocator` declares all four. Compile-
/// acceptance (the prototype form; the inline bodies' `::operator delete(p)`
/// global-call is a separate, deeper feature).
#[test]
fn allocation_operator_names_parse() {
    compiles(
        "struct A {\n\
         \x20 void* operator new(unsigned n);\n\
         \x20 void* operator new[](unsigned n);\n\
         \x20 void operator delete(void* p);\n\
         \x20 void operator delete[](void* p);\n\
         };\n\
         int main(){ return 0; }",
    );
}

/// S4.2c: a user-defined CONVERSION operator `operator int()` parses, is emitted
/// with the correct return type, and is callable in explicit form
/// `obj.operator int()`. (The RTL idiom `ios::operator void*` is the out-of-line
/// pointer form; this exercises the in-class definition + explicit call.)
#[test]
fn conversion_operator_explicit_call() {
    let src = "struct C { int v; operator int() { return v; } };\n\
               int main(){ C c; c.v = 42; return c.operator int(); }";
    assert_eq!(code(src), 42);
}

/// S4.2c: a conversion operator to a POINTER type (`operator void*`) parses both
/// the in-class declaration and an out-of-line `Tag::operator void*()` definition
/// (the IOSTREAM.H `ios::operator void _FAR *` shape). Compile-acceptance — the
/// declarator path now recognises the conversion name instead of erroring.
#[test]
fn conversion_operator_to_pointer_out_of_line() {
    compiles(
        "struct S {\n\
         \x20 int v;\n\
         \x20 operator void*();\n\
         };\n\
         void* S::operator void*() { return v ? this : 0; }\n\
         int main(){ return 0; }",
    );
}

/// S4.2c: a qualified-id naming a (nested) enum constant resolves in expression
/// position — `Flags::in | Flags::out | Flags::ate`. This is exactly IOSTREAM.H's
/// default argument `(ios::in | ios::out)`, and the parenthesised form must NOT
/// be mistaken for a C-style cast `(Flags::...)`.
#[test]
fn qualified_enum_constants_in_expression() {
    let src = "struct Flags { enum { in = 1, out = 2, ate = 4 }; };\n\
               int main(){ return (Flags::in | Flags::out | Flags::ate); }";
    assert_eq!(code(src), 7);
}

/// S4.2c: SHIFT and BITWISE binary operators are overloadable. The stream
/// classes spell extraction/insertion as `operator>>`/`operator<<`; here we
/// exercise the value-context form (`binop_spelling` + `overloaded_binop` now
/// cover `<< >> & | ^`, including OVERLOADED sets in `sigs.overloads`). An
/// integer `a >> b` is unaffected (only a RECORD left operand routes here).
#[test]
fn shift_and_bitwise_operator_overloads_run() {
    // Shift overloads used as values.
    assert_eq!(
        code(
            "struct S { int v;\n\
              int operator<<(int n){ return v << n; }\n\
              int operator>>(int n){ return v >> n; } };\n\
              int main(){ S s; s.v = 8; return (s << 1) + (s >> 2); }"
        ),
        18,
    );
    // Bitwise overloads, AND an overloaded set (two `operator&`) resolved by
    // argument type — the int overload is selected here.
    assert_eq!(
        code(
            "struct B { int v;\n\
              int operator&(int n){ return v & n; }\n\
              int operator&(B o){ return v & o.v; }\n\
              int operator|(int n){ return v | n; } };\n\
              int main(){ B b; b.v = 6; return (b & 4) + (b | 1); }"
        ),
        4 + 7,
    );
}

/// S4.2c regression guard: the new cast-vs-parenthesised-expr disambiguation
/// (which only changes the `(Tag :: …)` lookahead) must NOT disturb an ordinary
/// non-qualified type cast — `(myint)x` is still a C-style cast, not a
/// parenthesised expression.
#[test]
fn plain_typedef_cast_still_works() {
    let src = "typedef int myint;\n\
               int main(){ long x = 9; return (myint)x; }";
    assert_eq!(code(src), 9);
}

/// S4.2f: while replaying a class-template body, a C-style cast may name the
/// current template-id type: `((TPointerBase<T>*)p)->P = 0` in OSL/GEOMETRY.H.
/// The cast lookahead must recognize `Box<T>*` as a type-id so the expression
/// is not parsed as a parenthesized value.
#[test]
fn c_style_cast_to_template_id_pointer_type() {
    compiles(
        "template<class T> struct Box { \
           T* P; \
           void zap(void* p) { ((Box<T>*)p)->P = 0; } \
         }; \
         int main(){ Box<char> b; return 0; }",
    );
}

/// S4.2d: a polymorphic class deriving from a NON-polymorphic base that carries
/// data members. The vptr sits at offset 0 and the base subobject is pushed to
/// `ptr_bytes`, so `Derived*→Base*` and a base-method `this` are adjusted by that
/// offset (the Microsoft object model). Exercises: virtual dispatch (vptr@0),
/// a base method via the derived (`this` += base_offset), an upcast, and base
/// field/method access via the base pointer. (Base has no ctor/dtor — the
/// ctor/dtor-chaining adjustment is a separate increment.)
#[test]
fn polymorphic_derived_from_nonpoly_base_with_data() {
    let src = "struct Base { int x; int getx() { return x; } };\n\
               struct Derived : public Base { int y; virtual int t() { return x + y; } };\n\
               int main(){\n\
               \x20 Derived d; d.x = 5; d.y = 6;\n\
               \x20 Derived* dp = &d;\n\
               \x20 Base* bp = &d;\n\
               \x20 return dp->t() + dp->getx() + bp->x + bp->getx();\n\
               }";
    assert_eq!(code(src), 5 + 6 + 5 + 5 + 5); // t()=11, getx()=5, bp->x=5, bp->getx()=5
}

/// S4.2d: the same shape but the base has a CONSTRUCTOR and DESTRUCTOR (the
/// `xmsg` idiom that gates the OWL exception hierarchy). The derived ctor's
/// `: Base(a)` chain runs `Base::Base` on the SHIFTED base subobject
/// (`this + base_offset`), so `x` is initialised at the right place. Exercises
/// the ctor/dtor-chaining `this` adjustment (`base_ctor_call_adjust`).
#[test]
fn ctor_chaining_to_shifted_base() {
    let src = "struct Base { int x; Base(int v){ x = v; } ~Base(){} \
               int getx(){ return x; } };\n\
               struct Derived : public Base { int y; \
               Derived(int a, int b) : Base(a) { y = b; } \
               virtual int t(){ return x + y; } };\n\
               int main(){ Derived d(5, 6); Derived* dp = &d; Base* bp = &d; \
               return dp->t() + dp->getx() + bp->x + bp->getx(); }";
    assert_eq!(code(src), 11 + 5 + 5 + 5);
}

/// S4.2d: a base method that READS through `this` after the adjustment returns
/// the right field (guards the `this += base_offset` wrap in isolation), and a
/// two-data-member base so the base subobject is wider than one slot.
#[test]
fn nonpoly_base_method_reads_adjusted_this() {
    let src = "struct B { int a; int b; int sum() { return a + b; } };\n\
               struct D : public B { int c; virtual int f() { return c; } };\n\
               int main(){ D d; d.a = 2; d.b = 3; d.c = 9; return d.sum() + d.f(); }";
    assert_eq!(code(src), 2 + 3 + 9);
}

/// S4.2c: a base-clause may write `virtual` BEFORE the access-specifier
/// (`class istream : virtual public ios`), not only after. For a single base the
/// layout is identical to a non-virtual base, so member access through the
/// derived object is exact. (The shared-vbase diamond join is a deeper MI item.)
#[test]
fn virtual_before_access_base_clause() {
    let src = "struct Base { int x; };\n\
               struct Derived : virtual public Base { int y; };\n\
               int main(){ Derived d; d.x = 3; d.y = 4; return d.x + d.y; }";
    assert_eq!(code(src), 7);
}
