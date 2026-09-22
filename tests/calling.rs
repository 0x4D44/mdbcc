//! O1-style hand-expected oracle for Phase A: the Win64 calling path —
//! more than four arguments (the stack-arg ABI) and function pointers.
//! Fast, in-process, no external toolchain (broad three-way coverage
//! lives in `tests/corpus/portable/{manyargs,funcptr}.c`).
//!
//! Weighted sums make every argument *position* observable: a single
//! mis-slotted arg changes the result, so a stack-ABI bug cannot pass.

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
    p.push(format!("mdbcc_call_{}_{}.exe", std::process::id(), n));
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

// ---- A1: more than 4 arguments (Win64 stack-arg ABI) -------------------

#[test]
fn five_args_weighted_sum() {
    // First stack slot exercised (arg5). 2+6+12+20+30 = 70.
    let r = code(
        "int f(int a,int b,int c,int d,int e){return a+b*2+c*3+d*4+e*5;}\n\
         int main(void){return f(2,3,4,5,6);}\n",
    );
    assert_eq!(r, 70);
}

#[test]
fn eight_args_weighted_sum_exit_code() {
    // 1+4+9+16+25+36+49+64 = 204. Any mis-slotted arg changes this.
    let r = code(
        "int f(int a,int b,int c,int d,int e,int f,int g,int h){\n\
         return a+b*2+c*3+d*4+e*5+f*6+g*7+h*8;}\n\
         int main(void){return f(1,2,3,4,5,6,7,8);}\n",
    );
    assert_eq!(r, 204);
}

#[test]
fn eight_args_via_stdout() {
    // 10+40+90+160+250+360+490+640 = 2040.
    let s = out("#include <stdio.h>\n\
         int f(int a,int b,int c,int d,int e,int f,int g,int h){\n\
         return a+b*2+c*3+d*4+e*5+f*6+g*7+h*8;}\n\
         int main(void){ printf(\"%d\\n\", f(10,20,30,40,50,60,70,80)); return 0; }\n");
    assert_eq!(s, "2040\n");
}

#[test]
fn many_args_and_printf_in_same_function() {
    // The fn both makes a >4-arg call AND uses printf (the io 'outgoing'
    // path): the frame must reserve the MAX of both, not either alone.
    let s = out("#include <stdio.h>\n\
         int add6(int a,int b,int c,int d,int e,int f){return a+b+c+d+e+f;}\n\
         int main(void){\n\
           int s; s = add6(1,2,3,4,5,6);\n\
           printf(\"sum=%d\\n\", s);\n\
           return 0; }\n");
    assert_eq!(s, "sum=21\n");
}

#[test]
fn nested_call_passes_more_than_four_args() {
    // g forwards into f; both >4 args; frame correct across the call.
    let r = code(
        "int f(int a,int b,int c,int d,int e,int g){return a+b*2+c*3+d*4+e*5+g*6;}\n\
         int g(int x){return f(x,x+1,x+2,x+3,x+4,x+5);}\n\
         int main(void){return g(1);}\n",
    );
    // f(1,2,3,4,5,6) = 1+4+9+16+25+36 = 91
    assert_eq!(r, 91);
}

#[test]
fn call_args_evaluate_right_to_left() {
    let r = code(
        "int s;\n\
         int a(void){ s = s * 10 + 1; return s; }\n\
         int b(void){ s = s * 10 + 2; return s; }\n\
         int pack(int x, int y){ return x * 10 + y; }\n\
         int main(void){ return pack(a(), b()) == 212 ? 42 : 7; }\n",
    );
    assert_eq!(r, 42);
}

// ---- A2: function pointers --------------------------------------------

#[test]
fn call_through_function_pointer_variable() {
    let r = code(
        "int dbl(int x){return x*2;}\n\
         int main(void){ int (*fp)(int); fp = dbl; return fp(21); }\n",
    );
    assert_eq!(r, 42);
}

#[test]
fn function_pointer_args_evaluate_right_to_left() {
    let r = code(
        "int s;\n\
         int a(void){ s = s * 10 + 1; return s; }\n\
         int b(void){ s = s * 10 + 2; return s; }\n\
         int pack(int x, int y){ return x * 10 + y; }\n\
         int main(void){ int (*fp)(int,int); fp = pack; return fp(a(), b()) == 212 ? 42 : 7; }\n",
    );
    assert_eq!(r, 42);
}

#[test]
fn function_pointer_as_callback_parameter() {
    // Higher-order: apply() invokes the passed callback (qsort-shaped).
    let r = code(
        "int inc(int x){return x+1;}\n\
         int apply(int (*f)(int), int v){ return f(v); }\n\
         int main(void){ return apply(inc, 100); }\n",
    );
    assert_eq!(r, 101);
}

#[test]
fn array_of_function_pointers_dispatch() {
    let s = out("#include <stdio.h>\n\
         int add(int a,int b){return a+b;}\n\
         int sub(int a,int b){return a-b;}\n\
         int mul(int a,int b){return a*b;}\n\
         int main(void){\n\
           int (*ops[3])(int,int);\n\
           ops[0]=add; ops[1]=sub; ops[2]=mul;\n\
           printf(\"%d %d %d\\n\", ops[0](6,4), ops[1](6,4), ops[2](6,4));\n\
           return 0; }\n");
    assert_eq!(s, "10 2 24\n");
}

#[test]
fn function_pointer_variable_returning_pointer_is_typed() {
    // Regression for the review's MINOR #1: `fp(...)` where fp is a
    // function-pointer *variable* must take the pointee's return type
    // (here `int*`), not a hard-coded `int`. If mis-typed as int, the
    // surrounding `*fp()` fails to compile ("cannot dereference").
    let r = code(
        "int gv = 77;\n\
         int *get(void){ return &gv; }\n\
         int main(void){ int *(*fp)(void); fp = get; return *fp(); }\n",
    );
    assert_eq!(r, 77);
}

#[test]
fn function_pointer_with_more_than_four_args() {
    // A2 reuses the A1 stack-arg marshalling through an indirect call.
    let r = code(
        "int f(int a,int b,int c,int d,int e,int g){return a+b*2+c*3+d*4+e*5+g*6;}\n\
         int main(void){ int (*p)(int,int,int,int,int,int); p=f;\n\
           return p(1,2,3,4,5,6); }\n",
    );
    assert_eq!(r, 91);
}

#[test]
fn libc_intrinsic_args_evaluate_right_to_left() {
    let r = code(
        "int strcmp(char*, char*);\n\
         int s;\n\
         char* a(void){ s = s * 10 + 1; return s == 21 ? \"same\" : \"wrong\"; }\n\
         char* b(void){ s = s * 10 + 2; return \"same\"; }\n\
         int main(void){ return strcmp(a(), b()) == 0 ? 42 : 7; }\n",
    );
    assert_eq!(r, 42);
}

// ---- B-1: temp-budget overflow is a clean error, not corruption -------

#[test]
fn excessive_call_arity_is_a_clean_error_not_corruption() {
    // Backlog B-1 / Phase A review MINOR #2: a call that needs more
    // expression-temporaries than the per-function budget must fail with
    // a CodegenError — NOT panic (debug) and NOT silently corrupt the
    // frame (release). emit_call holds one temp per argument across the
    // load loop, so a >16-arg call overflows the 16-slot budget.
    let src = "int f(int a0,int a1,int a2,int a3,int a4,int a5,int a6,\
                     int a7,int a8,int a9,int a10,int a11,int a12,int a13,\
                     int a14,int a15,int a16,int a17,int a18,int a19){\
                 return a0+a19;}\n\
               int main(void){ return f(0,1,2,3,4,5,6,7,8,9,10,11,12,\
                 13,14,15,16,17,18,19); }\n";
    let r = compile_to_pe(src.as_bytes());
    assert!(
        r.is_err(),
        "expected a clean CodegenError on temp-budget overflow, got Ok"
    );
    let msg = format!("{:?}", r.err().unwrap());
    assert!(
        msg.contains("temporary budget") || msg.contains("too many arguments"),
        "error should explain the temp-budget limit, got: {msg}"
    );
}
