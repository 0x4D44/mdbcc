//! O1-style hand-expected oracle for Phase B: C++ virtual functions,
//! vtables and virtual destructors. Fast, in-process, no external
//! toolchain (broad three-way coverage lives in the differential corpus
//! `tests/corpus/portable/virtual.c`).
//!
//! Expected values are hand-computed against C++ semantics. Weighted
//! sums make the *dispatched-to* implementation observable: a vtable
//! slot-order bug or a wrong-override binding changes the result, so a
//! dispatch bug cannot pass silently. Data-member values are read back
//! through the object to prove the vptr-at-0 / data-member +8 shift is
//! applied consistently (layout regression guard).

#![cfg(windows)]

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

fn build(src: &str) -> TempExe {
    let exe = compile_to_pe(src.as_bytes()).expect("compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_virt_{}_{}.exe", std::process::id(), n));
    let t = TempExe(p);
    std::fs::write(&t.0, &exe).expect("write exe");
    t
}

/// Exit code of `int main(){...}` in `src`.
fn code(src: &str) -> i32 {
    let t = build(src);
    Command::new(&t.0)
        .status()
        .expect("launch")
        .code()
        .expect("exit code")
}

/// stdout of `src`.
fn out(src: &str) -> String {
    let t = build(src);
    let o = Command::new(&t.0).output().expect("launch");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

// ---- B1: polymorphic dispatch through a base pointer ------------------

#[test]
fn virtual_dispatch_through_base_pointer() {
    // p->area() must call the dynamic type's override, not Shape::area.
    // Sq(3)=9, Rect(4,5)=20  ->  9*100 + 20 = 920.
    let r = code(
        "class Shape { public: virtual int area() { return 0; } };\n\
         class Sq : public Shape { int s; public: Sq(int x){s=x;}\n\
           virtual int area(){ return s*s; } };\n\
         class Rect : public Shape { int w; int h;\n\
           public: Rect(int a,int b){w=a;h=b;}\n\
           virtual int area(){ return w*h; } };\n\
         int main(void){ Sq sq(3); Rect rc(4,5); Shape* p;\n\
           p=&sq; int t; t=p->area();\n\
           p=&rc; t=t*100+p->area(); return t; }\n",
    );
    assert_eq!(r, 920);
}

// ---- B2: override bound through a base reference -----------------------

#[test]
fn virtual_dispatch_through_base_reference() {
    let r = code(
        "class B { public: virtual int f(){ return 1; } };\n\
         class D : public B { public: virtual int f(){ return 2; } };\n\
         int callit(B& b){ return b.f(); }\n\
         int main(void){ D d; return callit(d); }\n",
    );
    assert_eq!(r, 2);
}

// ---- B3: array of base pointers, mixed dynamic types ------------------

#[test]
fn array_of_base_pointers_dispatch() {
    // 10 + 20 + 30 = 60. Slot-order / wrong-binding bug changes this.
    let r = code(
        "class A { public: virtual int v(){ return 10; } };\n\
         class A2 : public A { public: virtual int v(){ return 20; } };\n\
         class A3 : public A { public: virtual int v(){ return 30; } };\n\
         int main(void){ A a; A2 b; A3 c; A* arr[3];\n\
           arr[0]=&a; arr[1]=&b; arr[2]=&c;\n\
           int s; s=0; int i;\n\
           for(i=0;i<3;i=i+1){ s=s+arr[i]->v(); }\n\
           return s; }\n",
    );
    assert_eq!(r, 60);
}

// ---- B4: virtual destructor ordering via delete (Base*) --------------

#[test]
fn virtual_destructor_runs_derived_then_base() {
    // delete through Base* with a virtual dtor must run Der::~Der first
    // then chain to Base::~Base. Order is the oracle.
    let s = out("#include <stdio.h>\n\
         class Base { public: virtual ~Base(){ printf(\"~Base\\n\"); } };\n\
         class Der : public Base { public: ~Der(){ printf(\"~Der\\n\"); } };\n\
         int main(void){ Base* p; p = new Der(); delete p; return 0; }\n");
    assert_eq!(s, "~Der\n~Base\n");
}

// ---- B5: non-virtual dtor through Base* does NOT reach Der -----------

#[test]
fn nonvirtual_destructor_through_base_is_static() {
    // Contrast with B4: no `virtual` on the dtor => delete (Base*)
    // statically calls Base::~Base only (standard, if technically UB to
    // rely on; we encode the deterministic static-dispatch behaviour).
    let s = out("#include <stdio.h>\n\
         class Base { public: ~Base(){ printf(\"~Base\\n\"); } };\n\
         class Der : public Base { public: ~Der(){ printf(\"~Der\\n\"); } };\n\
         int main(void){ Base* p; p = new Der(); delete p; return 0; }\n");
    assert_eq!(s, "~Base\n");
}

// ---- B6: vptr-at-0 must not corrupt data members ---------------------

#[test]
fn polymorphic_object_data_members_are_intact() {
    // a,b,c are read back through a virtual method: proves the +8
    // data-member shift (vptr at offset 0) is applied consistently to
    // every field access. 1 + 2*10 + 3*100 = 321.
    let r = code(
        "class V { int a; int b; int c;\n\
           public: V(){ a=1; b=2; c=3; }\n\
           virtual int sum(){ return a + b*10 + c*100; } };\n\
         int main(void){ V v; return v.sum(); }\n",
    );
    assert_eq!(r, 321);
}

// ---- B7: inherited (non-overridden) virtual slot ---------------------

#[test]
fn inherited_virtual_slot_is_kept() {
    // D overrides g but not h; p->h() must still reach B::h via the
    // inherited slot. 50*100 + 6 = 5006.
    let r = code(
        "class B { public: virtual int g(){ return 5; }\n\
           virtual int h(){ return 6; } };\n\
         class D : public B { public: virtual int g(){ return 50; } };\n\
         int main(void){ D d; B* p; p=&d;\n\
           return p->g()*100 + p->h(); }\n",
    );
    assert_eq!(r, 5006);
}

// ---- B8: non-virtual method on a polymorphic class calls a virtual ---

#[test]
fn nonvirtual_method_calls_virtual_on_this() {
    // plain() is non-virtual (direct call) but internally calls the
    // virtual v() through this->vptr; the override must win. x=7,
    // D::v()=9  ->  7 + 9 = 16.
    let r = code(
        "class P { int x;\n\
           public: P(){ x=7; }\n\
           virtual int v(){ return 1; }\n\
           int plain(){ return x + v(); } };\n\
         class Q : public P { public: virtual int v(){ return 9; } };\n\
         int main(void){ Q q; return q.plain(); }\n",
    );
    assert_eq!(r, 16);
}

// ---- B9: abstract class (pure virtual) cannot be instantiated --------

#[test]
fn abstract_class_instantiation_is_a_clean_error() {
    // `= 0` makes f pure => Abstract is abstract; `Abstract a;` must be
    // a clean CodegenError, never silently wrong.
    let src = "class Abstract { public: virtual int f() = 0; };\n\
               int main(void){ Abstract a; return 0; }\n";
    let r = compile_to_pe(src.as_bytes());
    assert!(
        r.is_err(),
        "instantiating an abstract class must be a CodegenError, got Ok"
    );
    let msg = format!("{:?}", r.err().unwrap());
    assert!(
        msg.to_lowercase().contains("abstract") || msg.to_lowercase().contains("pure virtual"),
        "error should mention abstract/pure virtual, got: {msg}"
    );
}

// ---- B10: BLOCKER-1 regression — vptr installed on ALL ctor paths ----

#[test]
fn early_return_constructor_still_installs_vptr() {
    // Phase B code-review BLOCKER-1: the ctor's vtable install must run
    // even when the constructor `return`s early. Pre-fix (fall-through-
    // only store) this dispatched through an uninitialised vptr →
    // crash / wrong answer. who()=2 (D::who) and t=5  ->  205.
    let r = code(
        "class B { public: virtual int who(){ return 1; } };\n\
         class D : public B { int t;\n\
           public: D(int x){ t = x; if (x > 0) return; t = 999; }\n\
           virtual int who(){ return 2; } };\n\
         int main(void){ D d(5); B* p; p=&d;\n\
           return p->who()*100 + d.t; }\n",
    );
    assert_eq!(r, 205);
}

#[test]
fn virtual_call_inside_base_constructor_resolves_to_base() {
    // In-ctor virtual dispatch: while B::B runs (even as a subobject of
    // D), the vptr is B's, so id() resolves to B::id (standard C++).
    // Proves SetVptr is installed before the ctor body, not after it.
    let s = out("#include <stdio.h>\n\
         class B { public: virtual int id(){ return 10; }\n\
           B(){ printf(\"%d\\n\", id()); } };\n\
         class D : public B { public: virtual int id(){ return 20; } };\n\
         int main(void){ D d; return 0; }\n");
    assert_eq!(s, "10\n");
}

// ---- B11: tracked pre-existing defect (NOT Phase-B-introduced) -------

#[test]
#[ignore = "backlog B-5: early `return` in a (v)dtor body skips the \
            parser-appended base-dtor chain call — pre-existing control-\
            flow defect (the non-virtual dtor has it too), tracked in \
            JRN - Roadmap to OWL; needs dtor base-chain as an all-paths \
            finalizer, out of Phase B's minimal scope"]
fn early_return_destructor_still_chains_base() {
    let s = out("#include <stdio.h>\n\
         class Base { public: virtual ~Base(){ printf(\"~Base\\n\"); } };\n\
         class Der : public Base { int n;\n\
           public: Der(){ n = 0; }\n\
           ~Der(){ printf(\"~Der\\n\"); if (n == 0) return; }\n\
         };\n\
         int main(void){ Base* p; p = new Der(); delete p; return 0; }\n");
    assert_eq!(s, "~Der\n~Base\n");
}
