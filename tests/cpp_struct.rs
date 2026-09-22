//! Phase H1: struct/class by-value parameter passing (Win64 ABI).
//!
//! Exhaustive coverage of the silent-miscompile trap from HLD §H1 risk
//! register: Win64 classifies aggregates by **byte size alone** (NOT
//! field count, NOT SysV-style eightbyte). Sizes 1/2/4/8 ⇒ packed into
//! the positional integer register; sizes 3/5/6/7 and every size > 8 ⇒
//! passed by hidden pointer to a caller-allocated copy. Padding 3/5/6/7
//! up to 4/8 and passing in-register is the silent miscompile this
//! suite guards against.
//!
//! Where MSVC `cl` is available the suite also runs a behavioural
//! differential (exit code + stdout) for at least 3 representative
//! tests — the HLD §H1 differential entry. cl absence ⇒ behavioural
//! assertion against mdbcc-built only (graceful self-skip).

#![cfg(windows)]

mod support;

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::compile_to_pe;
use support::{Lang, msvc_ref, normalize_newlines, o2_active};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);
impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn build(src: &str) -> TempExe {
    let exe = compile_to_pe(src.as_bytes()).expect("mdbcc compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_cppstruct_{}_{}.exe", std::process::id(), n));
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

/// Behavioural differential against `cl /MT`: compile the same C source
/// with MSVC, run it, assert mdbcc's stdout (after `\r\n` → `\n`
/// normalisation) and exit code match. cl absent ⇒ silent skip (the
/// mdbcc-side assertion still ran in the caller). Returns true if cl
/// actually ran a comparison, false on self-skip.
fn differential_against_cl(src: &str, mdbcc_stdout: &str, mdbcc_exit: i32) -> bool {
    if !o2_active() {
        return false;
    }
    let r = msvc_ref(src, Lang::C);
    if !r.launched {
        return false; // toolchain absent or build failed — caller already validated mdbcc
    }
    let cl_stdout = String::from_utf8_lossy(&normalize_newlines(&r.stdout)).into_owned();
    assert_eq!(
        cl_stdout, mdbcc_stdout,
        "cl differential FAIL (stdout): cl={cl_stdout:?} mdbcc={mdbcc_stdout:?}"
    );
    assert_eq!(
        r.exit,
        Some(mdbcc_exit),
        "cl differential FAIL (exit): cl={:?} mdbcc={mdbcc_exit}",
        r.exit
    );
    true
}

// ---- InReg classification (sizes 1/2/4/8 — packed into the positional GPR)

#[test]
fn inreg_size_1_one_char_field() {
    // sizeof(B) == 1 ⇒ classifier returns InReg(1). Callee reads b.x ⇒ 7.
    let src = "\
        struct B { char x; };\n\
        int f(struct B b) { return b.x; }\n\
        int main(void) { struct B v; v.x = 7; return f(v); }\n";
    assert_eq!(code(src), 7);
}

#[test]
fn inreg_size_2_pair_of_chars() {
    // sizeof(B) == 2 ⇒ InReg(2). Caller MUST emit movzx eax,word [src]
    // (NOT a 4-byte mov, NOT a 1-byte mov). Asserts the field SUM so
    // both bytes are observable in the test.
    let src = "\
        struct B { char a; char b; };\n\
        int f(struct B s) { return s.a + s.b; }\n\
        int main(void) { struct B v; v.a = 3; v.b = 4; return f(v); }\n";
    assert_eq!(code(src), 7);
}

#[test]
fn inreg_size_4_int_wrapper() {
    // sizeof(B) == 4 ⇒ InReg(4). mov eax,[src] (32-bit; zero-extends to rax).
    let src = "\
        struct B { int x; };\n\
        int f(struct B b) { return b.x; }\n\
        int main(void) { struct B v; v.x = 12345; return f(v); }\n";
    assert_eq!(code(src), 12345);
}

#[test]
fn inreg_size_8_long_long_wrapper() {
    // sizeof(B) == 8 ⇒ InReg(8). mov rax,[src] (full 64-bit load).
    // Stdout-based to observe the full 64-bit value (exit codes truncate).
    let src = "\
        #include <stdio.h>\n\
        struct B { long long x; };\n\
        int f(struct B b) { printf(\"%lld\\n\", b.x); return 0; }\n\
        int main(void) { struct B v; v.x = 1234567890LL; return f(v); }\n";
    let s = out(src);
    assert_eq!(s, "1234567890\n");
    // Differential #1: an InReg-size-8 program against cl.
    differential_against_cl(src, &s, 0);
}

#[test]
fn inreg_size_8_single_double_uses_gpr_not_xmm() {
    // Phase H code-review MINOR-8 pin: Win64 ABI classifies aggregates by
    // SIZE alone, NOT by field type. A `struct { double x; }` is size 8,
    // so it goes via the positional GPR (rcx) — UNLIKE SysV which would
    // route it through xmm0 because the single eightbyte is FP.
    //
    // `classify_struct_for_win64` is type-blind today (correct), but a
    // future "optimisation" that special-cased single-FP-field structs
    // would silently break Win64 differentials. This test locks the
    // invariant via a behavioural differential against cl /MT. We round
    // to int so the exit code is a stable integer witness.
    let src = "\
        #include <stdio.h>\n\
        struct B { double x; };\n\
        int f(struct B b) { return (int)(b.x * 1000.0); }\n\
        int main(void) { struct B v; v.x = 3.141; return f(v); }\n";
    assert_eq!(code(src), 3141);
    // The differential is the actual Win64 ABI lock — if mdbcc and cl
    // route the struct differently (one GPR, one XMM), this fails.
    let s = out(src);
    differential_against_cl(src, &s, 3141);
}

// ---- HiddenPtr classification (the 3/5/6/7 trap quartet, plus > 8)

#[test]
fn hiddenptr_size_3_three_chars() {
    // sizeof(B) == 3 ⇒ HiddenPtr (NOT padded to 4!). The trap: pad-to-4
    // and pass in-reg silently miscompiles. Sum=1+2+3=6.
    let src = "\
        struct B { char a; char b; char c; };\n\
        int f(struct B s) { return s.a + s.b + s.c; }\n\
        int main(void) { struct B v; v.a = 1; v.b = 2; v.c = 3; return f(v); }\n";
    assert_eq!(code(src), 6);
}

#[test]
fn hiddenptr_size_5_five_chars() {
    // sizeof(B) == 5 ⇒ HiddenPtr (NOT padded to 8). Sum=1..5=15.
    let src = "\
        struct B { char a; char b; char c; char d; char e; };\n\
        int f(struct B s) { return s.a + s.b + s.c + s.d + s.e; }\n\
        int main(void) {\n\
          struct B v; v.a = 1; v.b = 2; v.c = 3; v.d = 4; v.e = 5;\n\
          return f(v);\n\
        }\n";
    assert_eq!(code(src), 15);
}

#[test]
fn hiddenptr_size_6_six_chars() {
    // sizeof(B) == 6 ⇒ HiddenPtr (NOT padded to 8). Sum=1..6=21.
    let src = "\
        struct B { char a; char b; char c; char d; char e; char f; };\n\
        int g(struct B s) {\n\
          return s.a + s.b + s.c + s.d + s.e + s.f;\n\
        }\n\
        int main(void) {\n\
          struct B v;\n\
          v.a = 1; v.b = 2; v.c = 3; v.d = 4; v.e = 5; v.f = 6;\n\
          return g(v);\n\
        }\n";
    assert_eq!(code(src), 21);
}

#[test]
fn hiddenptr_size_7_seven_chars() {
    // sizeof(B) == 7 ⇒ HiddenPtr (NOT padded to 8). Sum=1..7=28.
    let src = "\
        struct B { char a; char b; char c; char d; char e; char f; char g; };\n\
        int h(struct B s) {\n\
          return s.a + s.b + s.c + s.d + s.e + s.f + s.g;\n\
        }\n\
        int main(void) {\n\
          struct B v;\n\
          v.a = 1; v.b = 2; v.c = 3; v.d = 4; v.e = 5; v.f = 6; v.g = 7;\n\
          return h(v);\n\
        }\n";
    assert_eq!(code(src), 28);
}

#[test]
fn hiddenptr_size_16_two_ints() {
    // sizeof(B) == 16 (two ints + 8 bytes alignment) — well above 8 ⇒
    // HiddenPtr. Sum=11+22+33+44... use two ints: 100 + 23 = 123.
    let src = "\
        struct B { int a; int b; int c; int d; };\n\
        int f(struct B s) { return s.a + s.b + s.c + s.d; }\n\
        int main(void) {\n\
          struct B v; v.a = 10; v.b = 20; v.c = 30; v.d = 40;\n\
          return f(v);\n\
        }\n";
    assert_eq!(code(src), 100);
    let src_io = "\
        #include <stdio.h>\n\
        struct B { int a; int b; int c; int d; };\n\
        int f(struct B s) { return s.a + s.b + s.c + s.d; }\n\
        int main(void) {\n\
          struct B v; v.a = 10; v.b = 20; v.c = 30; v.d = 40;\n\
          printf(\"%d\\n\", f(v)); return 0;\n\
        }\n";
    let s = out(src_io);
    assert_eq!(s, "100\n");
    // Differential #2: a HiddenPtr-size-16 program against cl.
    differential_against_cl(src_io, &s, 0);
}

#[test]
fn hiddenptr_size_24_three_long_longs() {
    // sizeof(B) == 24 ⇒ HiddenPtr. Three 8-byte fields.
    let src = "\
        struct B { long long a; long long b; long long c; };\n\
        int f(struct B s) { return (int)(s.a + s.b + s.c); }\n\
        int main(void) {\n\
          struct B v; v.a = 100; v.b = 200; v.c = 300;\n\
          return f(v);\n\
        }\n";
    assert_eq!(code(src), 600);
}

#[test]
fn hiddenptr_size_64_array_style_aggregate() {
    // sizeof(B) == 64 (16 ints) ⇒ HiddenPtr. Sum 1..16 = 136.
    let src = "\
        #include <stdio.h>\n\
        struct B { int v[16]; };\n\
        int f(struct B s) {\n\
          int i; int t = 0;\n\
          for (i = 0; i < 16; ++i) t += s.v[i];\n\
          return t;\n\
        }\n\
        int main(void) {\n\
          struct B v;\n\
          int i;\n\
          for (i = 0; i < 16; ++i) v.v[i] = i + 1;\n\
          printf(\"%d\\n\", f(v)); return 0;\n\
        }\n";
    let s = out(src);
    assert_eq!(s, "136\n");
    // Differential #3: a HiddenPtr-size-64 program against cl.
    differential_against_cl(src, &s, 0);
}

// ---- Stack-slot (>4-arg) coverage

#[test]
fn stack_slot_5plus_by_value_struct() {
    // Five by-value structs ⇒ slot 5 is on the caller's stack. Even with
    // a HiddenPtr struct, the 5th slot must receive the BUFFER POINTER in
    // an 8-byte stack write at [rsp + 0x20 + 8*(5-4)] = [rsp+0x28]. A
    // bug confusing register vs stack for the 5th slot would silently
    // wrong-answer here.
    let src = "\
        #include <stdio.h>\n\
        struct S16 { int a; int b; int c; int d; };\n\
        int f(struct S16 s1, struct S16 s2, struct S16 s3, struct S16 s4, struct S16 s5) {\n\
          return s1.a + s2.b + s3.c + s4.d + s5.a + s5.b + s5.c + s5.d;\n\
        }\n\
        int main(void) {\n\
          struct S16 a; a.a = 1; a.b = 2; a.c = 3; a.d = 4;\n\
          struct S16 b; b.a = 10; b.b = 20; b.c = 30; b.d = 40;\n\
          struct S16 c; c.a = 100; c.b = 200; c.c = 300; c.d = 400;\n\
          struct S16 d; d.a = 1000; d.b = 2000; d.c = 3000; d.d = 4000;\n\
          struct S16 e; e.a = 5; e.b = 6; e.c = 7; e.d = 8;\n\
          printf(\"%d\\n\", f(a, b, c, d, e)); return 0;\n\
        }\n";
    // 1 + 20 + 300 + 4000 + (5+6+7+8) = 1 + 20 + 300 + 4000 + 26 = 4347.
    let s = out(src);
    assert_eq!(s, "4347\n");
}

// ---- Semantic gates: by-value really IS by-value

#[test]
fn callee_mutation_does_not_affect_caller_original_hiddenptr() {
    // Real by-value semantics: the callee's HiddenPtr param IS the caller's
    // hidden BUFFER (not the original). Mutations to the param must NOT
    // propagate back. Failure mode would be writing through the original
    // (e.g. passing the source addr instead of copying into a buffer).
    let src = "\
        #include <stdio.h>\n\
        struct S16 { int a; int b; int c; int d; };\n\
        int sink(struct S16 s) { s.a = -999; s.b = -999; return s.a; }\n\
        int main(void) {\n\
          struct S16 v; v.a = 11; v.b = 22; v.c = 33; v.d = 44;\n\
          sink(v);\n\
          printf(\"%d %d %d %d\\n\", v.a, v.b, v.c, v.d);\n\
          return 0;\n\
        }\n";
    let s = out(src);
    assert_eq!(
        s, "11 22 33 44\n",
        "caller's struct was modified by callee — by-value semantics broken"
    );
}

#[test]
fn callee_mutation_does_not_affect_caller_original_inreg() {
    // Same semantic for an InReg-classified (size 4) struct: the callee's
    // local slot is its private copy of the struct bits; writes must not
    // touch the caller's original. (An InReg arg passes the VALUE in a
    // register, so this is structurally easier — but worth pinning.)
    let src = "\
        #include <stdio.h>\n\
        struct S4 { int x; };\n\
        int sink(struct S4 s) { s.x = -1; return s.x; }\n\
        int main(void) {\n\
          struct S4 v; v.x = 42;\n\
          sink(v);\n\
          printf(\"%d\\n\", v.x); return 0;\n\
        }\n";
    let s = out(src);
    assert_eq!(s, "42\n");
}

// ---- Mixed param lists: positional slot accounting must NOT break

#[test]
fn mixed_int_struct_int_struct_int_positional_slots() {
    // Pinned-pinning the HLD risk-register concern: a by-value struct
    // consumes a positional integer slot (rcx/rdx/r8/r9 if 1-4), just
    // like an int. Sequence: int (rcx), struct8 (rdx), int (r8),
    // struct16 (r9 as HiddenPtr — buffer addr), int (stack slot 5).
    // Each value distinctly contributes to the result so any
    // slot-shuffling bug shows up immediately.
    let src = "\
        #include <stdio.h>\n\
        struct S8 { long long x; };\n\
        struct S16 { int a; int b; int c; int d; };\n\
        int f(int p0, struct S8 p1, int p2, struct S16 p3, int p4) {\n\
          return p0 + (int)p1.x * 10 + p2 * 100 + p3.a * 1000 + p4 * 10000;\n\
        }\n\
        int main(void) {\n\
          struct S8 s8; s8.x = 2;\n\
          struct S16 s16; s16.a = 3; s16.b = 0; s16.c = 0; s16.d = 0;\n\
          printf(\"%d\\n\", f(1, s8, 4, s16, 5));\n\
          return 0;\n\
        }\n";
    // 1 + 2*10 + 4*100 + 3*1000 + 5*10000 = 1 + 20 + 400 + 3000 + 50000 = 53421.
    let s = out(src);
    assert_eq!(s, "53421\n");
}

// ---- Two more bonus pins: nested member access + reading at offset

#[test]
fn hiddenptr_callee_reads_all_fields_at_all_offsets() {
    // A 32-byte struct with fields at offsets 0/8/16/24 — verifies the
    // ARG_SPILL → local-slot path (param rewritten to Ref) correctly
    // dereferences the buffer pointer at non-zero field offsets. A bug
    // that confused "address of buffer" with "buffer value" would read
    // garbage at offsets > 0.
    let src = "\
        #include <stdio.h>\n\
        struct B32 { long long a; long long b; long long c; long long d; };\n\
        int f(struct B32 s) {\n\
          return (int)(s.a + s.b * 2 + s.c * 3 + s.d * 4);\n\
        }\n\
        int main(void) {\n\
          struct B32 v; v.a = 1; v.b = 2; v.c = 3; v.d = 4;\n\
          printf(\"%d\\n\", f(v)); return 0;\n\
        }\n";
    // 1 + 4 + 9 + 16 = 30.
    let s = out(src);
    assert_eq!(s, "30\n");
}

// ===========================================================================
// Phase H2: struct/class by-value RETURN values (Win64 ABI).
//
// Same classifier as H1 — sizes 1/2/4/8 ⇒ returned packed in RAX; all other
// sizes (3, 5, 6, 7, and everything > 8) ⇒ caller allocates a result buffer
// and passes its address as a synthetic FIRST argument in RCX (shifting all
// real args by one positional slot). The callee writes through that pointer
// and also returns it in RAX (Microsoft convention; NOT SysV's rax+rdx pair).
// ===========================================================================

// ---- InReg-return (sizes 1/2/4/8): RAX-packed return

#[test]
fn h2_inreg_ret_size_1() {
    // sizeof(B) == 1 ⇒ InReg(1) return. Callee packs b.x into AL; main
    // unpacks via member access. Exit code = 7.
    let src = "\
        struct B { char x; };\n\
        struct B make(void) { struct B b; b.x = 7; return b; }\n\
        int main(void) { struct B v = make(); return v.x; }\n";
    assert_eq!(code(src), 7);
}

#[test]
fn h2_inreg_ret_size_2() {
    // sizeof(B) == 2 ⇒ InReg(2). MOVZX into RAX (not 4-byte mov; not
    // 1-byte). Caller reads both bytes. Sum=10+3=13.
    let src = "\
        struct B { char a; char b; };\n\
        struct B make(void) { struct B b; b.a = 10; b.b = 3; return b; }\n\
        int main(void) { struct B v = make(); return v.a + v.b; }\n";
    assert_eq!(code(src), 13);
}

#[test]
fn h2_inreg_ret_size_4() {
    // sizeof(B) == 4 ⇒ InReg(4). `mov eax, [src]` (32-bit zero-extends in
    // x86-64). Caller reads back the int.
    let src = "\
        struct B { int x; };\n\
        struct B make(void) { struct B b; b.x = 12345; return b; }\n\
        int main(void) { struct B v = make(); return v.x; }\n";
    assert_eq!(code(src), 12345);
}

#[test]
fn h2_inreg_ret_size_8() {
    // sizeof(B) == 8 ⇒ InReg(8). Full-width `mov rax, [src]`. Stdout
    // observes the full 64-bit value; also runs cl differential. Value
    // chosen within int32 range to avoid the pre-existing mdbcc
    // limitation of always treating integer literals as `int` (loses
    // upper 32 bits during the int→long-long widen `movsxd rax,eax`).
    let src = "\
        #include <stdio.h>\n\
        struct B { long long x; };\n\
        struct B make(void) { struct B b; b.x = 1234567890; return b; }\n\
        int main(void) {\n\
          struct B v = make();\n\
          printf(\"%lld\\n\", v.x); return 0;\n\
        }\n";
    let s = out(src);
    assert_eq!(s, "1234567890\n");
    // Differential #1: InReg-size-8 record return against cl.
    differential_against_cl(src, &s, 0);
}

// ---- HiddenPtr-return (sizes 3, 5, 6, 7, > 8): hidden-first-arg return

#[test]
fn h2_hiddenptr_ret_size_3() {
    // sizeof(B) == 3 ⇒ HiddenPtr. Caller allocates a 3-byte (round-to-8)
    // result buffer; passes its address in RCX; callee memcpy's its return
    // expression into [RCX], returns RCX in RAX. Sum=1+2+3=6.
    let src = "\
        struct B { char a; char b; char c; };\n\
        struct B make(void) { struct B b; b.a = 1; b.b = 2; b.c = 3; return b; }\n\
        int main(void) { struct B v = make(); return v.a + v.b + v.c; }\n";
    assert_eq!(code(src), 6);
}

#[test]
fn h2_hiddenptr_ret_size_5() {
    // sizeof(B) == 5 ⇒ HiddenPtr. Five bytes copied through hidden ptr.
    let src = "\
        struct B { char a; char b; char c; char d; char e; };\n\
        struct B make(void) {\n\
          struct B b;\n\
          b.a = 1; b.b = 2; b.c = 3; b.d = 4; b.e = 5;\n\
          return b;\n\
        }\n\
        int main(void) {\n\
          struct B v = make();\n\
          return v.a + v.b + v.c + v.d + v.e;\n\
        }\n";
    assert_eq!(code(src), 15);
}

#[test]
fn h2_hiddenptr_ret_size_16() {
    // sizeof(B) == 16 ⇒ HiddenPtr. Two-int struct. Includes a cl
    // differential (the size HLD §H2 says is the smallest "big enough
    // that the rax+rdx-pair-vs-hidden-arg distinction matters").
    let src = "\
        #include <stdio.h>\n\
        struct B { int a; int b; int c; int d; };\n\
        struct B make(void) {\n\
          struct B b; b.a = 10; b.b = 20; b.c = 30; b.d = 40;\n\
          return b;\n\
        }\n\
        int main(void) {\n\
          struct B v = make();\n\
          printf(\"%d %d %d %d\\n\", v.a, v.b, v.c, v.d);\n\
          return 0;\n\
        }\n";
    let s = out(src);
    assert_eq!(s, "10 20 30 40\n");
    // Differential #2: HiddenPtr-size-16 against cl.
    differential_against_cl(src, &s, 0);
}

#[test]
fn h2_hiddenptr_ret_size_24() {
    // sizeof(B) == 24 ⇒ HiddenPtr. Three-int struct (with alignment
    // padding to 8). Includes cl differential.
    let src = "\
        #include <stdio.h>\n\
        struct B { long long a; long long b; long long c; };\n\
        struct B make(void) {\n\
          struct B b; b.a = 100; b.b = 200; b.c = 300;\n\
          return b;\n\
        }\n\
        int main(void) {\n\
          struct B v = make();\n\
          printf(\"%lld\\n\", v.a + v.b + v.c);\n\
          return 0;\n\
        }\n";
    let s = out(src);
    assert_eq!(s, "600\n");
    // Differential #3: HiddenPtr-size-24 against cl.
    differential_against_cl(src, &s, 0);
}

#[test]
fn h2_hiddenptr_ret_size_64() {
    // sizeof(B) == 64 ⇒ HiddenPtr. Large struct; exercises the memcpy
    // loop's full unroll length for the hidden-pointer-return path.
    let src = "\
        #include <stdio.h>\n\
        struct B { int v[16]; };\n\
        struct B make(void) {\n\
          struct B b; int i;\n\
          for (i = 0; i < 16; ++i) b.v[i] = i + 1;\n\
          return b;\n\
        }\n\
        int main(void) {\n\
          struct B v = make();\n\
          int i; int t = 0;\n\
          for (i = 0; i < 16; ++i) t += v.v[i];\n\
          printf(\"%d\\n\", t); return 0;\n\
        }\n";
    let s = out(src);
    assert_eq!(s, "136\n");
    // Differential #4: HiddenPtr-size-64 against cl.
    differential_against_cl(src, &s, 0);
}

// ---- HiddenPtr-return with explicit args (slot-shift pin)

#[test]
fn h2_hiddenptr_ret_with_two_int_args() {
    // foo(int a, int b) returns a 16-byte struct ⇒ caller's call site is
    // `rcx = result_buf; rdx = a; r8 = b`. A bug forgetting to shift `a`
    // off rcx into rdx would silently miscompile (a would be the buffer
    // address, b would land in rdx, etc.). Asserts both args round-trip
    // through the struct fields back to the caller.
    let src = "\
        #include <stdio.h>\n\
        struct S { int a; int b; int c; int d; };\n\
        struct S foo(int a, int b) {\n\
          struct S s; s.a = a; s.b = b; s.c = a + b; s.d = a * b;\n\
          return s;\n\
        }\n\
        int main(void) {\n\
          struct S v = foo(10, 20);\n\
          printf(\"%d %d %d %d\\n\", v.a, v.b, v.c, v.d);\n\
          return 0;\n\
        }\n";
    let s = out(src);
    assert_eq!(s, "10 20 30 200\n");
}

// ---- Interleaved struct-by-value param + struct-by-value return

#[test]
fn h2_hiddenptr_arg_and_ret_interleave() {
    // HiddenPtr-arg AND HiddenPtr-return ⇒ slot 0 = hidden RETURN ptr
    // (rcx), slot 1 = hidden ARG ptr (rdx, the struct-by-value's buffer
    // address). If the implementation confuses the two pointers, the
    // callee would either trash the caller's input struct or trash its
    // own return buffer. Asserts both directions round-trip cleanly.
    let src = "\
        #include <stdio.h>\n\
        struct S { int a; int b; int c; int d; };\n\
        struct S transform(struct S in) {\n\
          struct S out;\n\
          out.a = in.a * 2;\n\
          out.b = in.b * 2;\n\
          out.c = in.c * 2;\n\
          out.d = in.d * 2;\n\
          return out;\n\
        }\n\
        int main(void) {\n\
          struct S x; x.a = 1; x.b = 2; x.c = 3; x.d = 4;\n\
          struct S y = transform(x);\n\
          printf(\"%d %d %d %d -> %d %d %d %d\\n\",\n\
            x.a, x.b, x.c, x.d, y.a, y.b, y.c, y.d);\n\
          return 0;\n\
        }\n";
    let s = out(src);
    // Input unchanged (by-value semantics); output is 2x each field.
    assert_eq!(s, "1 2 3 4 -> 2 4 6 8\n");
}

// ---- Pass-through chain: struct from foo() into bar() as by-value arg

#[test]
fn h2_chain_struct_through_two_calls_no_aliasing() {
    // `bar(foo())` where foo returns HiddenPtr struct and bar takes one
    // HiddenPtr param. The caller must:
    //   (a) allocate a result buffer for foo, call foo (rcx = &foo_buf),
    //   (b) memcpy from foo_buf to bar's by-value param region (separate
    //       region — foo's result buf and bar's arg buf MUST NOT alias),
    //   (c) call bar with rcx = &bar_arg_buf.
    // A bug aliasing the two regions would cause bar to see clobbered
    // input (or trash its own arg buffer mid-memcpy).
    let src = "\
        #include <stdio.h>\n\
        struct S { int a; int b; int c; int d; };\n\
        struct S foo(void) {\n\
          struct S s; s.a = 100; s.b = 200; s.c = 300; s.d = 400;\n\
          return s;\n\
        }\n\
        int bar(struct S s) { return s.a + s.b + s.c + s.d; }\n\
        int main(void) {\n\
          printf(\"%d\\n\", bar(foo())); return 0;\n\
        }\n";
    let s = out(src);
    assert_eq!(s, "1000\n");
}

// ---- InReg-return through a chain of calls (no aliasing)

#[test]
fn h2_chain_inreg_ret_through_two_calls() {
    // Same chain pattern but with InReg-class return (size 4) — the call
    // returns bytes in rax; the caller spills to a result buffer and uses
    // the buffer address as a by-value-arg source for the next call.
    // (size 4 instead of 8 because mdbcc's int-literal-to-long-long
    // widening loses upper 32 bits — pre-existing limitation, unrelated
    // to H2; size 4 sidesteps it cleanly.)
    let src = "\
        #include <stdio.h>\n\
        struct S { int x; };\n\
        struct S foo(void) {\n\
          struct S s; s.x = 1234567; return s;\n\
        }\n\
        int bar(struct S s) { return s.x * 2; }\n\
        int main(void) {\n\
          printf(\"%d\\n\", bar(foo())); return 0;\n\
        }\n";
    let s = out(src);
    assert_eq!(s, "2469134\n");
}

#[test]
fn h1_byval_struct_then_trailing_stack_arg_not_corrupted() {
    // Regression (RailC toolbar "wrong order"): a HiddenPtr struct-by-value arg
    // copied into the caller's hidden buffer, followed by a trailing argument
    // that lands in the OUTGOING stack-arg area. The Win64 stack arg is stored
    // at [rsp+0x20 + 8*(i-4)], but `outgoing` reserved only `8*max_stack_args`
    // (not the 0x20 callee-shadow below the args). With an H1 by-value buffer
    // placed between `frame_fixed` and the outgoing region, the trailing arg's
    // store overwrote the struct copy (≈ offset 16 ⇒ `a[4]`). Verify the WHOLE
    // struct AND the trailing arg survive (robust to io_out shifting the offset).
    let src = "\
        struct Big { int a[20]; };\n\
        int check(int p0, int p1, int p2, struct Big b, int trailing) {\n\
          int i, ok = 1;\n\
          for (i = 0; i < 20; i++) if (b.a[i] != (i + 1) * 3) ok = 0;\n\
          if (trailing != 0x1234) ok = 0;\n\
          if (p0 + p1 + p2 != 21) ok = 0;\n\
          return ok;\n\
        }\n\
        int main(void) {\n\
          struct Big b; int i;\n\
          for (i = 0; i < 20; i++) b.a[i] = (i + 1) * 3;\n\
          return check(7, 7, 7, b, 0x1234) ? 42 : 7;\n\
        }\n";
    assert_eq!(code(src), 42);
}

#[test]
fn h1_byval_struct_two_trailing_stack_args_not_corrupted() {
    // Same class, two trailing stack args (max_stack_args == 2) and a pointer
    // trailing arg (the RailC shape: TToolbar(this, n, ButtonData, HBITMAP)).
    // The struct must occupy the 4th register slot (r9) so the trailing args
    // spill to the stack: check(p0,p1,p2, struct b /*r9 ptr*/, t1, t2 /*stack*/).
    let src = "\
        struct Big { int a[40]; };\n\
        int check(int p0, int p1, int p2, struct Big b, int t1, void* t2) {\n\
          int i, ok = 1;\n\
          for (i = 0; i < 40; i++) if (b.a[i] != i + 100) ok = 0;\n\
          if (t1 != 0x5678) ok = 0;\n\
          if (t2 != (void*)0) ok = 0;\n\
          if (p0 + p1 + p2 != 27) ok = 0;\n\
          return ok;\n\
        }\n\
        int main(void) {\n\
          struct Big b; int i;\n\
          for (i = 0; i < 40; i++) b.a[i] = i + 100;\n\
          return check(9, 9, 9, b, 0x5678, (void*)0) ? 42 : 7;\n\
        }\n";
    assert_eq!(code(src), 42);
}
