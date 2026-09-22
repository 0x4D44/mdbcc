//! S1b.8 — CLI-path OBJ byte-identity stripe (HLD §4.4).
//!
//! For each of the 88 e2e fixtures (same source list as
//! `tests/o1_byte_identity.rs` and `tests/o1_module_to_object_roundtrip.rs`),
//! compile the source via the `bcc -c` **subprocess** path twice and assert
//! the produced `.obj` bytes hash to the same SHA-256.
//!
//! ## Why this stripe (vs S1b.4's in-process determinism)
//!
//! S1b.4 (`tests/o1_module_to_object_roundtrip.rs::s1b4_object_byte_determinism_all_88_fixtures`)
//! already proves the in-process `compile_to_object` → `Object::write` path
//! is deterministic. The new signal here is the **CLI binary path**: a
//! subprocess invocation of `bcc.exe -c` adds an env-vars / working-dir /
//! process-startup layer that, in principle, could introduce non-determinism
//! (e.g. anything in main.rs that leaks `SystemTime`, PID, env-driven flags,
//! locale-dependent path normalisation). If those bytes ever shift between
//! two consecutive subprocess runs, content-addressable caching at the build
//! layer (S1d / S5 OWL progress tracking) collapses. This stripe is the
//! one-shot belt-and-braces check.
//!
//! ## Hash: SHA-256, std-only
//!
//! Per the S1b HLD's "no new dependencies" charter, we inline a small
//! SHA-256 implementation (FIPS 180-4). The bcc_oracle.rs module already
//! does this for the build cache (see `sha256_hex` there); we duplicate the
//! few lines here to keep the test file self-contained — the test-suite
//! rule forbids touching `tests/support/mod.rs`. A self-test
//! (`sha256_known_answer`) pins the algorithm against the FIPS test
//! vectors so an implementation bug surfaces as a single visible failure,
//! not 88 mysterious mismatches.
//!
//! ## Fixture-list duplication (acknowledged J-20b)
//!
//! The `FIXTURES` const below is the third copy of the 88-source list
//! (after `tests/o1_byte_identity.rs` and `tests/o1_module_to_object_roundtrip.rs`).
//! J-20b proposed extracting the list to a shared module; with three
//! consumers the case firms up further, but extraction still doesn't
//! belong in this tick — keeping S1b.8 atomic and avoiding touches to
//! the o1_byte_identity baseline is the priority. Filed for follow-up.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Test-harness helpers (mirrors `tests/cli_dash_c.rs` — duplicated rather
// than imported because tests/support/ may not host CLI helpers per the
// S1b.8 constraint, and the helpers are only ~50 LoC of mechanical glue).
// ---------------------------------------------------------------------------

/// Path to the `bcc` binary built by Cargo for this crate. The
/// `CARGO_BIN_EXE_bcc` env var is injected automatically by `cargo test`
/// for every `[[bin]]` defined in `Cargo.toml`.
fn bcc_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bcc"))
}

/// Allocate a fresh per-fixture temp dir. One directory per fixture keeps
/// parallel test runs from clobbering each other's `.obj` files and lets
/// us clean up with a single `remove_dir_all` after the assertion.
fn fresh_temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mdbcc_obj_id_cli_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        tag
    ));
    std::fs::create_dir_all(&p).expect("mkdir temp");
    p
}

/// Run `cmd` to completion under a wall-clock timeout, capturing stdout
/// and stderr through reader threads (avoid pipe-buffer deadlock). Mirrors
/// `tests/cli_dash_c.rs::run_with_timeout`.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (None, Vec::new(), format!("spawn failed: {e}").into_bytes()),
    };
    let mut so = child.stdout.take().expect("piped stdout");
    let mut se = child.stderr.take().expect("piped stderr");
    let h_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = std::io::Read::read_to_end(&mut so, &mut v);
        v
    });
    let h_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = std::io::Read::read_to_end(&mut se, &mut v);
        v
    });
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break None,
        }
    };
    let stdout = h_out.join().unwrap_or_default();
    let stderr = h_err.join().unwrap_or_default();
    let exit = status.and_then(|s| s.code());
    (exit, stdout, stderr)
}

/// Invoke `bcc <args>` with `cwd = work_dir`. Returns (exit, stdout, stderr).
fn run_bcc(work_dir: &Path, args: &[&str]) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let mut cmd = Command::new(bcc_exe());
    cmd.current_dir(work_dir).args(args);
    run_with_timeout(&mut cmd, Duration::from_secs(30))
}

/// Compile `src` through the `bcc -c` CLI subprocess and return the
/// produced `.obj` bytes plus a SHA-256 hex digest. Panics on any CLI
/// failure (compile error, missing output) with a fixture-tagged message
/// so the test report is self-explanatory.
fn compile_via_cli(fixture: &str, src: &str, is_cpp: bool) -> (Vec<u8>, String) {
    let dir = fresh_temp_dir(fixture);
    let src_name = if is_cpp { "t.cpp" } else { "t.c" };
    let src_path = dir.join(src_name);
    std::fs::write(&src_path, src).unwrap_or_else(|e| panic!("{fixture}: write source: {e}"));

    let (exit, _stdout, stderr) = run_bcc(&dir, &["-c", src_name, "-o", "t.obj"]);
    if exit != Some(0) {
        let _ = std::fs::remove_dir_all(&dir);
        panic!(
            "{fixture}: bcc -c failed: exit={exit:?} stderr={}",
            String::from_utf8_lossy(&stderr)
        );
    }

    let obj_path = dir.join("t.obj");
    let bytes = std::fs::read(&obj_path).unwrap_or_else(|e| {
        let _ = std::fs::remove_dir_all(&dir);
        panic!("{fixture}: read t.obj: {e}");
    });
    let hex = sha256_hex(&bytes);

    let _ = std::fs::remove_dir_all(&dir);
    (bytes, hex)
}

// ---------------------------------------------------------------------------
// FIXTURES: 88 e2e fixtures, mirroring tests/o1_byte_identity.rs.
//
// `is_cpp` flag drives the temp-file extension (.c vs .cpp). The mdbcc
// parser today treats both identically, but the CLI infers some behaviour
// from the extension (see cli_dash_c.rs::bcc_dash_c_cpp_source) so we
// preserve the distinction. Fixtures using C++-only syntax (`class`,
// references, `new`/`delete`, member-init lists, operator overloads,
// default args, function overloading) are flagged `is_cpp=true`. Plain
// C-99 fixtures stay `is_cpp=false`.
// ---------------------------------------------------------------------------

#[rustfmt::skip]
const FIXTURES: &[(&str, &str, bool)] = &[
    ("returns_constant",
        "int main(void) { return 42; }", false),
    ("arithmetic_precedence_and_parens",
        "int main(void) { return (2 + 3) * 8 - 10; }", false),
    ("division_and_modulo",
        "int main(void) { return 17 / 5; }", false),
    ("unary_operators",
        "int main(void) { return ~0; }", false),
    ("negative_result_is_dword_exit_code",
        "int main(void) { return 3 - 10; }", false),
    ("comparison_and_bitwise_operators",
        "int main(void) { return 3 < 5; }", false),
    ("short_circuit_logical_operators",
        "int main(void) { return 1 && 2; }", false),
    ("locals_and_assignment",
        "int main(void){ int a; int b; a = 6; b = 7; return a * b; }", false),
    ("if_else_control_flow",
        "int main(void){ int x; x = 10; \
                if (x > 5) x = 100; else x = 200; return x; }", false),
    ("while_loop_sum_1_to_100",
        "int main(void){ int i; int s; i = 1; s = 0; \
                while (i <= 100) { s = s + i; i = i + 1; } return s; }", false),
    ("for_loop_factorial",
        "int main(void){ int f; int i; f = 1; \
                for (i = 1; i <= 5; i = i + 1) f = f * i; return f; }", false),
    ("euclid_gcd",
        "int main(void){ int a; int b; int t; a = 48; b = 18; \
                while (b != 0) { t = b; b = a % b; a = t; } return a; }", false),
    ("nested_loops_and_blocks",
        "int main(void){ int s; int i; int j; s = 0; \
                for (i = 1; i <= 3; i = i + 1) { \
                  for (j = 1; j <= 3; j = j + 1) { s = s + i * j; } } \
                return s; }", false),
    ("fall_through_returns_zero",
        "int main(void){ int x; x = 1; }", false),
    ("simple_function_call",
        "int add(int a, int b) { return a + b; } \
                int main(void) { return add(40, 2); }", false),
    ("four_argument_function",
        "int f(int a, int b, int c, int d) { return a*1000 + b*100 + c*10 + d; } \
                int main(void) { return f(1, 2, 3, 4); }", false),
    ("recursive_factorial",
        "int fact(int n) { if (n <= 1) return 1; return n * fact(n - 1); } \
                int main(void) { return fact(7); }", false),
    ("recursive_fibonacci",
        "int fib(int n) { if (n < 2) return n; return fib(n-1) + fib(n-2); } \
                int main(void) { return fib(15); }", false),
    ("mutual_recursion_is_even",
        "int is_odd(int n) { if (n == 0) return 0; return is_even(n - 1); } \
                int is_even(int n) { if (n == 0) return 1; return is_odd(n - 1); } \
                int main(void) { return is_even(10) * 10 + is_odd(7); }", false),
    ("cxx_reference_parameter_mutates_caller",
        "void inc(int& r) { r = r + 1; } \
               int main(void) { int a; a = 41; inc(a); return a; }", true),
    ("cxx_reference_local_alias",
        "int main(void) { int a; int& r = a; a = 5; r = r * 8; return a; }", true),
    ("cxx_reference_to_struct_member",
        "struct P { int x; int y; }; \
               void bump(int& v) { v = v + 10; } \
               int main(void) { P p; p.x = 1; p.y = 2; \
                 bump(p.x); bump(p.y); return p.x*100 + p.y; }", true),
    ("cxx_class_ctor_and_methods",
        "class Counter { \
                 int n; \
               public: \
                 Counter(int s) { n = s; } \
                 void add(int d) { n = n + d; } \
                 int get() { return n; } \
               }; \
               int main(void) { Counter c(40); c.add(2); return c.get(); }", true),
    ("cxx_method_via_pointer_and_this",
        "struct Point { \
                 int x; int y; \
                 void set(int a, int b) { x = a; y = b; } \
                 int sum() { return this->x + y; } \
               }; \
               int main(void) { Point p; Point *q; q = &p; \
                 q->set(30, 12); return q->sum(); }", true),
    ("cxx_default_ctor_and_sibling_call",
        "class Acc { \
                 int t; \
               public: \
                 Acc() { t = 0; } \
                 void one() { t = t + 1; } \
                 int run() { one(); one(); one(); return t; } \
               }; \
               int main(void) { Acc a; return a.run(); }", true),
    ("cxx_new_delete_scalar",
        "int main(void) { int* p = new int; *p = 42; \
                 int r = *p; delete p; return r; }", true),
    ("cxx_new_class_ctor_and_method",
        "class Box { \
                 int v; \
               public: \
                 Box(int s) { v = s; } \
                 void add(int d) { v = v + d; } \
                 int get() { return v; } \
               }; \
               int main(void) { Box* b = new Box(40); \
                 b->add(2); int r = b->get(); delete b; return r; }", true),
    ("cxx_new_runs_ctor_delete_runs_dtor",
        "class Res { \
                 int* slot; \
               public: \
                 Res(int* s) { slot = s; *slot = 1; } \
                 ~Res() { *slot = 99; } \
               }; \
               int main(void) { int v; v = 0; \
                 Res* r = new Res(&v); \
                 if (v != 1) return 7; \
                 delete r; \
                 return v; }", true),
    ("cxx_raii_block_scope_reverse_order",
        "class Tr { \
                 int* log; int id; \
               public: \
                 Tr(int* L, int i) { log = L; id = i; } \
                 ~Tr() { *log = *log * 10 + id; } \
               }; \
               int main(void) { int v; v = 0; \
                 { Tr a(&v, 1); Tr b(&v, 2); } \
                 return v; }", true),
    ("cxx_raii_destructor_runs_before_return",
        "class S { \
                 int* p; \
               public: \
                 S(int* q) { p = q; } \
                 ~S() { *p = *p + 7; } \
               }; \
               int bump(int* p) { S s(p); if (*p > 0) return 1; return 2; } \
               int main(void) { int v; v = 3; bump(&v); return v; }", true),
    ("cxx_raii_inner_block_destructs_early",
        "class M { \
                 int* p; \
               public: \
                 M(int* q) { p = q; } \
                 ~M() { *p = *p + 1; } \
               }; \
               int main(void) { int v; v = 0; \
                 { M m(&v); } \
                 int w; w = v * 10; \
                 return w + v; }", true),
    ("cxx_out_of_line_methods_header_style",
        "class Counter { \
                 int n; \
               public: \
                 Counter(int s); \
                 void add(int d); \
                 int get(); \
               }; \
               Counter::Counter(int s) { n = s; } \
               void Counter::add(int d) { n = n + d; } \
               int Counter::get() { return n; } \
               int main(void) { Counter c(40); c.add(2); return c.get(); }", true),
    ("cxx_out_of_line_ctor_dtor_sibling_call",
        "class Acc { \
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
                 return v; }", true),
    ("cxx_operator_equality_member",
        "class Pt { \
                 int x; int y; \
               public: \
                 Pt(int a, int b) { x = a; y = b; } \
                 int operator==(Pt& o) { return x == o.x && y == o.y; } \
               }; \
               int main(void) { Pt a(3,4); Pt b(3,4); Pt c(3,9); \
                 int r = 0; \
                 if (a == b) r = r + 10; \
                 if (a == c) r = r + 1; \
                 return r; }", true),
    ("cxx_operator_plus_out_of_line",
        "class Money { \
                 int cents; \
               public: \
                 Money(int c); \
                 int operator+(Money& o); \
               }; \
               Money::Money(int c) { cents = c; } \
               int Money::operator+(Money& o) { return cents + o.cents; } \
               int main(void) { Money a(150); Money b(75); return a + b; }", true),
    ("cxx_operator_less_and_minus",
        "class N { \
                 int v; \
               public: \
                 N(int x) { v = x; } \
                 int operator<(N& o) { return v < o.v; } \
                 int operator-(N& o) { return v - o.v; } \
               }; \
               int main(void) { N a(7); N b(10); \
                 int r = 0; \
                 if (a < b) r = b - a; \
                 return r; }", true),
    ("cxx_inheritance_members_and_methods",
        "class Base { \
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
               int main(void) { Derived x; return x.sum(); }", true),
    ("cxx_inheritance_meminit_base_args",
        "class Animal { \
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
                 return d.numLegs() + d.score(); }", true),
    ("cxx_inheritance_destructor_chains_to_base",
        "class Res { \
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
                 return v; }", true),
    ("cxx_default_args_free_function",
        "int area(int w, int h = 3); \
               int area(int w, int h) { return w * h; } \
               int main(void) { return area(4) + area(5, 2); }", true),
    ("cxx_default_args_member_and_ctor",
        "class Rect { \
                 int w; int h; \
               public: \
                 Rect(int a, int b = 5) { w = a; h = b; } \
                 int scale(int f = 2) { return w * h * f; } \
               }; \
               int main(void) { Rect r(4); Rect s(3, 10); \
                 return r.scale() + s.scale(1); }", true),
    ("cxx_default_args_prototype_then_out_of_line",
        "class C { \
                 int n; \
               public: \
                 C(int v = 100); \
                 int get(int add = 1); \
               }; \
               C::C(int v) { n = v; } \
               int C::get(int add) { return n + add; } \
               int main(void) { C a; C b(7); return a.get() + b.get(5); }", true),
    ("cxx_overload_by_param_type",
        "int f(int x) { return x + 1; } \
               int f(char* s) { return 100; } \
               int main(void) { return f(41) + f(\"hi\"); }", true),
    ("cxx_overload_by_arity",
        "int g(int a, int b) { return a * b; } \
               int g(int a) { return a + 7; } \
               int main(void) { return g(6, 7) + g(10); }", true),
    ("cxx_overload_pointer_vs_int",
        "int kind(int* p) { return 1; } \
               int kind(int v) { return 2; } \
               int main(void) { int x; x = 5; int* q; q = &x; \
                 return kind(q) * 10 + kind(x); }", true),
    ("printf_decimal_and_text",
        "int main(void){ printf(\"x=%d y=%d\\n\", -7, 13); return 0; }", false),
    ("printf_string_char_hex_unsigned",
        "int main(void){ \
           printf(\"%s!\\n\", \"hi\"); \
           printf(\"%c%c\\n\", 65, 66); \
           printf(\"%x %X\\n\", 255, 255); \
           printf(\"%u\\n\", -1); \
           printf(\"100%% done\\n\"); \
           return 0; }", false),
    ("printf_returns_total_bytes_with_format",
        "int main(void){ return printf(\"v=%d\", 255); }", false),
    ("printf_loop_and_expression_args",
        "int main(void){ int i; \
           for (i = 1; i <= 3; i = i + 1) printf(\"sq(%d)=%d\\n\", i, i*i); \
           return 0; }", false),
    ("libc_strlen_strcmp_abs_atoi",
        "int main(void){ int r = 0; \
                 r = r + strlen(\"hello\"); \
                 if (strcmp(\"abc\", \"abc\") == 0) r = r + 10; \
                 if (strcmp(\"abc\", \"abd\") < 0) r = r + 20; \
                 r = r + abs(-13); \
                 r = r + atoi(\"100\"); \
                 r = r - atoi(\"-8\"); \
                 return r; }", false),
    ("libc_strcpy_strcat_memcpy_memset",
        "int main(void){ \
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
                 return 0; }", false),
    ("libc_respects_include_string_h_stub",
        "#include <string.h>\n\
               int main(void){ return strlen(\"abcdef\"); }", false),
    ("inline_asm_block_is_dropped",
        "int main(void){ int x; x = 10; \
                 asm { mov eax, 99 } \
                 x = x + 5; return x; }", false),
    ("inline_asm_statement_forms",
        "int main(void){ int r; r = 7; \
                 asm mov ax, bx; \
                 asm nop\n\
                 r = r * 6; return r; }", false),
    ("inline_asm_underscore_and_paren_forms",
        "int main(void){ int v; v = 3; \
                 __asm { push eax\n pop eax } \
                 asm(\"nop\"); \
                 v = v + 39; return v; }", false),
    ("struct_members_read_write",
        "struct P { int x; int y; }; \
               int main(void){ struct P p; p.x = 30; p.y = 12; return p.x + p.y; }", false),
    ("struct_pointer_arrow_and_param",
        "struct P { int a; int b; }; \
               int sum(struct P *p){ return p->a + p->b; } \
               int main(void){ struct P q; q.a = 40; q.b = 2; return sum(&q); }", false),
    ("self_referential_linked_list",
        "struct N { int v; struct N *next; }; \
               int main(void){ \
                 struct N a; struct N b; struct N c; \
                 a.v = 1; b.v = 2; c.v = 3; \
                 a.next = &b; b.next = &c; c.next = 0; \
                 int sum; struct N *p; sum = 0; p = &a; \
                 while (p) { sum += p->v; p = p->next; } \
                 return sum; }", false),
    ("whole_struct_assignment_copies",
        "struct P { int x; int y; }; \
               int main(void){ struct P a; struct P b; \
                 a.x = 3; a.y = 4; b = a; b.x = 10; \
                 return a.x*100 + a.y*10 + b.x; }", false),
    ("nested_structs",
        "struct Inner { int n; }; \
               struct Outer { struct Inner in; int k; }; \
               int main(void){ struct Outer o; o.in.n = 7; o.k = 35; \
                 return o.in.n + o.k; }", false),
    ("array_of_structs",
        "struct V { int x; }; \
               int main(void){ struct V a[3]; int i; \
                 for (i = 0; i < 3; i++) a[i].x = i * i; \
                 return a[0].x + a[1].x + a[2].x; }", false),
    ("union_overlaps_members",
        "union U { int i; char c[4]; }; \
               int main(void){ union U u; u.i = 0; u.c[0] = 65; return u.i; }", false),
    ("enum_constants_are_values",
        "enum Color { RED, GREEN = 5, BLUE }; \
               int main(void){ return RED*100 + GREEN*10 + BLUE; }", false),
    ("typedef_struct_alias",
        "typedef struct { int a; int b; } Pair; \
               int add(Pair *p){ return p->a + p->b; } \
               int main(void){ Pair q; q.a = 19; q.b = 23; return add(&q); }", false),
    ("typedef_scalar_alias_and_sizeof_struct",
        "typedef unsigned char byte; \
               struct S { char c; int i; }; \
               int main(void){ byte b; b = 200; \
                 return b + sizeof(struct S); }", false),
    ("pointers_address_of_and_deref",
        "int main(void){ int x; int *p; x = 5; p = &x; \
               *p = *p + 37; return x; }", false),
    ("arrays_subscript_and_compound_assign",
        "int main(void){ int a[5]; int i; int s; s = 0; \
               for (i = 0; i < 5; i++) a[i] = i * i; \
               for (i = 0; i < 5; i++) s += a[i]; return s; }", false),
    ("char_pointer_strlen",
        "int slen(char *s){ int n; n = 0; while (*s) { n++; s++; } return n; } \
               int main(void){ return slen(\"hello, world\"); }", false),
    ("pointer_arithmetic_indexes_chars",
        "int main(void){ char *s; s = \"abcdef\"; return s[4]; }", false),
    ("global_variable_state",
        "int g; int bump(void){ g = g + 1; return g; } \
               int main(void){ g = 40; bump(); bump(); return g; }", false),
    ("sizeof_types",
        "int main(void) { return sizeof(int) + sizeof(char) + sizeof(int*); }", false),
    ("integer_cast_truncates",
        "int main(void){ int x; x = 300; return (char)x; }", false),
    ("ternary_and_prefix_postfix",
        "int main(void){ int a; a = 7; return a > 5 ? 100 : 200; }", false),
    ("char_array_buffer_writes",
        "int main(void){ char b[4]; b[0] = 'O'; b[1] = 'K'; \
               b[2] = 33; b[3] = 0; return b[0] + b[1]; }", false),
    ("unsigned_division_and_shift",
        "int main(void){ unsigned int x; x = 4294967295; return x / 2; }", false),
    ("string_global_and_printf",
        "char *msg = \"global string\\n\"; \
               int main(void){ printf(\"global string\\n\"); return msg[0]; }", false),
    ("preprocessor_object_and_function_macros",
        "#define N 7\n#define SQ(x) ((x)*(x))\n\
               int main(void){ return SQ(N); }", false),
    ("preprocessor_conditional_compilation",
        "#define LEVEL 2\n\
               int main(void){\n\
               #if LEVEL > 1\n  return 10;\n#else\n  return 20;\n#endif\n}", false),
    ("system_include_is_stubbed_and_printf_works",
        "#include <stdio.h>\n#include <stdlib.h>\n\
               int main(void){ printf(\"inc-ok\\n\"); return 0; }", false),
    ("prototype_then_definition_links",
        "int add(int a, int b);\n\
               int main(void){ return add(19, 23); }\n\
               int add(int a, int b){ return a + b; }", false),
    ("ifndef_include_guard_pattern",
        "#ifndef ONCE\n#define ONCE\n\
               int helper(void){ return 5; }\n#endif\n\
               int main(void){ return helper() * 8; }", false),
    ("printf_writes_string_to_stdout",
        r#"int main(void){ printf("Hello, world!\n"); return 0; }"#, false),
    ("puts_appends_newline",
        r#"int main(void){ puts("hi"); return 0; }"#, false),
    ("printf_returns_byte_count",
        r#"int main(void){ return printf("abc"); }"#, false),
    ("adjacent_string_literals_concatenate",
        r#"int main(void){ printf("foo" "bar"); return 0; }"#, false),
    ("output_from_loop_and_callee",
        r#"
        int greet(void) { printf("hi\n"); return 0; }
        int main(void) {
            int i;
            for (i = 0; i < 3; i = i + 1) greet();
            printf("done\n");
            return 0;
        }"#, false),
    ("escape_sequences_in_output",
        r#"int main(void){ printf("a\tb\\c\"d"); return 0; }"#, false),
    ("nested_calls_as_arguments",
        "int add(int a, int b) { return a + b; } \
                int sq(int x) { return x * x; } \
                int main(void) { return add(sq(3), sq(add(2, 2))); }", false),
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn s1b8_fixture_count_matches_e2e_suite() {
    // Sanity: the fixture list must stay locked to the 88-program contract.
    // Drift here means either a new e2e fixture was added without an entry
    // in this stripe, or an e2e fixture was removed and the stale entry
    // here was missed. Mirrors the equivalent guard in o1_byte_identity.rs.
    assert_eq!(
        FIXTURES.len(),
        88,
        "FIXTURES drifted from the 88-program O1 contract; reconcile \
         with tests/end_to_end.rs (88 #[test] functions)."
    );
    let mut seen = std::collections::HashSet::new();
    for (name, _, _) in FIXTURES {
        assert!(
            seen.insert(*name),
            "duplicate fixture name {name:?} — names must be unique."
        );
    }
}

/// Headline sweep: every fixture compiles twice via `bcc -c` and the two
/// `.obj` files must hash to the same SHA-256. Failures across multiple
/// fixtures are batched into one report so a single re-run shows the whole
/// story.
#[test]
fn s1b8_obj_byte_identity_cli_all_88_fixtures() {
    let mut failures: Vec<String> = Vec::new();
    for (name, src, is_cpp) in FIXTURES {
        let (bytes_a, hash_a) = compile_via_cli(name, src, *is_cpp);
        let (bytes_b, hash_b) = compile_via_cli(name, src, *is_cpp);
        if hash_a != hash_b {
            // Surface the first-byte divergence offset so a regression
            // points directly at the leaking field (TimeDateStamp at
            // offset 4? a HashMap-ordered string table? etc.).
            let first_diff = bytes_a
                .iter()
                .zip(&bytes_b)
                .position(|(a, b)| a != b)
                .map(|i| {
                    format!(
                        "first diff at offset {i} (a=0x{:02x}, b=0x{:02x})",
                        bytes_a[i], bytes_b[i]
                    )
                })
                .unwrap_or_else(|| "lengths differ".to_string());
            failures.push(format!(
                "{name}: non-deterministic CLI .obj bytes \
                 (len_a={}, len_b={}, sha_a={hash_a}, sha_b={hash_b}, {first_diff})",
                bytes_a.len(),
                bytes_b.len()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "S1b.8 CLI-path determinism failures ({} fixture(s)):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Tighter stripe on a single fixture: compile 5 times consecutively and
/// assert every hash matches. This is the higher-confidence determinism
/// probe — if the CLI path leaks any per-run state (PID, time, env diff),
/// a single twin-run might miss it, but 5 runs almost certainly will not.
#[test]
fn s1b8_obj_byte_identity_cli_five_runs() {
    let (name, src, is_cpp) = FIXTURES[0]; // returns_constant — smallest, fastest
    let mut hashes: Vec<String> = Vec::with_capacity(5);
    for _ in 0..5 {
        let (_, h) = compile_via_cli(name, src, is_cpp);
        hashes.push(h);
    }
    let first = &hashes[0];
    for (i, h) in hashes.iter().enumerate() {
        assert_eq!(
            h, first,
            "S1b.8 CLI-path determinism: run #{} hash {} differs from run #0 {} \
             (fixture {name})",
            i, h, first,
        );
    }
}

/// SHA-256 algorithm self-test using FIPS 180-2 appendix-B vectors. If
/// this fails, the inline implementation has a bug; treat it as the
/// canonical "stop the whole tick" failure rather than chasing 88
/// downstream mismatches.
#[test]
fn sha256_known_answer() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
}

// ---------------------------------------------------------------------------
// SHA-256 — std-only inline implementation (FIPS 180-4). Mirrors the
// implementation in tests/support/bcc_oracle.rs::sha256_hex — duplicated
// here to keep this test file self-contained per the S1b.8 constraint
// that forbids touching tests/support/mod.rs to expose new helpers.
// ---------------------------------------------------------------------------

fn sha256_hex(input: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut h = Sha256::new();
    h.update(input);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            buf_len: 0,
            total: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        let mut i = 0;
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            i += take;
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while i + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[i..i + 64]);
            self.compress(&block);
            i += 64;
        }
        if i < data.len() {
            let rem = data.len() - i;
            self.buf[..rem].copy_from_slice(&data[i..]);
            self.buf_len = rem;
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total.wrapping_mul(8);
        // append 0x80, zero-pad until length ≡ 56 (mod 64), then 8-byte
        // big-endian bit length.
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        let len_be = bit_len.to_be_bytes();
        self.update(&len_be);
        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}
