//! S1b.4 — Module → Object → COFF → Object round-trip lock.
//!
//! For each of the 88 e2e fixtures (same source list as
//! `tests/o1_byte_identity.rs`), this suite:
//! 1. Invokes the new [`mdbcc::compile_to_object`] entry point to
//!    produce an in-memory [`mdbcc::coff::Object`].
//! 2. Serialises that Object via [`mdbcc::coff::Object::write`].
//! 3. Decodes the bytes back via [`mdbcc::coff::Object::read`].
//! 4. Asserts the decoded Object is **structurally equivalent** to the
//!    original (sections, symbols-resolved-by-name, relocations).
//!
//! Plus a determinism stripe: each fixture is compiled twice and the
//! produced bytes must be byte-identical. This is the S1b.4 precursor
//! to the full S1b.8 OBJ byte-identity stripe (which adds the SHA-256
//! baselines).
//!
//! The two assertions together exercise the major contracts of the
//! converter:
//! - **Round-trip parity**: the encoder + decoder pair preserves every
//!   IR field the converter populates. A drift here points either at
//!   an encoder bug or at the converter producing a field the decoder
//!   doesn't yet handle (both are S1b.2 / S1b.4 regressions).
//! - **Determinism (R16)**: two runs of the converter on identical
//!   input produce identical bytes. A drift here is the canonical
//!   "HashMap iteration leaked into emitted bytes" symptom.
//!
//! ## Fixture list duplication (acknowledged J-20b)
//!
//! The FIXTURES const below is intentionally duplicated from
//! `tests/o1_byte_identity.rs`. J-20b proposed extracting the list to
//! a shared module; the subagent's J-20b note (May-26 session 2)
//! deferred this for now (single consumer, simpler diff). With S1b.4
//! adding the second consumer, the case for extraction firms up but
//! is still a follow-up — keeping the in-test duplication keeps S1b.4
//! atomic and avoids touching the o1_byte_identity baseline.

use mdbcc::coff::{Object, SymName, Symbol};
use mdbcc::compile_to_object;

/// Resolve a `Symbol`'s name back to a `String` regardless of whether
/// the encoding chose the inline 8-byte slot or the strtab indirection.
/// This is the canonical comparison key — the round-trip is structural,
/// not byte-equal — so `Short` vs `Long` is invisible to the assertion.
fn resolve_name(sym: &Symbol, obj: &Object) -> String {
    match &sym.name {
        SymName::Short(a) => {
            let end = a.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&a[..end]).into_owned()
        }
        SymName::Long(off) => obj
            .strtab
            .get_str(*off)
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                panic!(
                    "S1b.4 round-trip: symbol Long({off}) does not resolve \
                     in strtab — encoder/decoder out of sync"
                )
            }),
    }
}

/// Assert structural equivalence between two Objects. Used after a
/// write+read round trip — the decoded Object should match the
/// original in every field the on-disk format preserves.
fn assert_structurally_equivalent(orig: &Object, back: &Object, fixture: &str) {
    assert_eq!(orig.machine, back.machine, "{fixture}: machine");
    assert_eq!(orig.directives, back.directives, "{fixture}: directives");
    assert_eq!(
        orig.sections.len(),
        back.sections.len(),
        "{fixture}: section count"
    );
    for (i, (a, b)) in orig.sections.iter().zip(&back.sections).enumerate() {
        assert_eq!(
            a.name.render(),
            b.name.render(),
            "{fixture}: section[{i}] name"
        );
        assert_eq!(
            a.characteristics, b.characteristics,
            "{fixture}: section[{i}] characteristics"
        );
        assert_eq!(a.data, b.data, "{fixture}: section[{i}] data");
        assert_eq!(a.bss_size, b.bss_size, "{fixture}: section[{i}] bss_size");
        assert_eq!(
            a.relocs.len(),
            b.relocs.len(),
            "{fixture}: section[{i}] reloc count"
        );
        // Relocs compare by (offset, resolved-symbol-name, kind). The
        // raw `symbol` index can shift across a round-trip if the
        // decoder remaps disk-indices to user-indices, but the
        // referenced name MUST match.
        for (j, (ra, rb)) in a.relocs.iter().zip(&b.relocs).enumerate() {
            assert_eq!(
                ra.offset, rb.offset,
                "{fixture}: section[{i}] reloc[{j}] offset"
            );
            assert_eq!(ra.kind, rb.kind, "{fixture}: section[{i}] reloc[{j}] kind");
            let name_a = resolve_name(&orig.symbols[ra.symbol as usize], orig);
            let name_b = resolve_name(&back.symbols[rb.symbol as usize], back);
            assert_eq!(
                name_a, name_b,
                "{fixture}: section[{i}] reloc[{j}] target name"
            );
        }
        assert_eq!(a.comdat, b.comdat, "{fixture}: section[{i}] comdat");
    }
    assert_eq!(
        orig.symbols.len(),
        back.symbols.len(),
        "{fixture}: symbol count"
    );
    for (i, (a, b)) in orig.symbols.iter().zip(&back.symbols).enumerate() {
        let name_a = resolve_name(a, orig);
        let name_b = resolve_name(b, back);
        assert_eq!(name_a, name_b, "{fixture}: symbol[{i}] name");
        assert_eq!(a.value, b.value, "{fixture}: symbol[{i}] value");
        assert_eq!(a.section, b.section, "{fixture}: symbol[{i}] section");
        assert_eq!(a.kind, b.kind, "{fixture}: symbol[{i}] kind");
        assert_eq!(a.storage, b.storage, "{fixture}: symbol[{i}] storage");
        assert_eq!(a.aux, b.aux, "{fixture}: symbol[{i}] aux");
    }
}

// ---------------------------------------------------------------------------
// FIXTURES: 88 e2e fixtures, mirroring tests/o1_byte_identity.rs.
// ---------------------------------------------------------------------------

#[rustfmt::skip]
const FIXTURES: &[(&str, &str)] = &[
    ("returns_constant",
        "int main(void) { return 42; }"),
    ("arithmetic_precedence_and_parens",
        "int main(void) { return (2 + 3) * 8 - 10; }"),
    ("division_and_modulo",
        "int main(void) { return 17 / 5; }"),
    ("unary_operators",
        "int main(void) { return ~0; }"),
    ("negative_result_is_dword_exit_code",
        "int main(void) { return 3 - 10; }"),
    ("comparison_and_bitwise_operators",
        "int main(void) { return 3 < 5; }"),
    ("short_circuit_logical_operators",
        "int main(void) { return 1 && 2; }"),
    ("locals_and_assignment",
        "int main(void){ int a; int b; a = 6; b = 7; return a * b; }"),
    ("if_else_control_flow",
        "int main(void){ int x; x = 10; \
                if (x > 5) x = 100; else x = 200; return x; }"),
    ("while_loop_sum_1_to_100",
        "int main(void){ int i; int s; i = 1; s = 0; \
                while (i <= 100) { s = s + i; i = i + 1; } return s; }"),
    ("for_loop_factorial",
        "int main(void){ int f; int i; f = 1; \
                for (i = 1; i <= 5; i = i + 1) f = f * i; return f; }"),
    ("euclid_gcd",
        "int main(void){ int a; int b; int t; a = 48; b = 18; \
                while (b != 0) { t = b; b = a % b; a = t; } return a; }"),
    ("nested_loops_and_blocks",
        "int main(void){ int s; int i; int j; s = 0; \
                for (i = 1; i <= 3; i = i + 1) { \
                  for (j = 1; j <= 3; j = j + 1) { s = s + i * j; } } \
                return s; }"),
    ("fall_through_returns_zero",
        "int main(void){ int x; x = 1; }"),
    ("simple_function_call",
        "int add(int a, int b) { return a + b; } \
                int main(void) { return add(40, 2); }"),
    ("four_argument_function",
        "int f(int a, int b, int c, int d) { return a*1000 + b*100 + c*10 + d; } \
                int main(void) { return f(1, 2, 3, 4); }"),
    ("recursive_factorial",
        "int fact(int n) { if (n <= 1) return 1; return n * fact(n - 1); } \
                int main(void) { return fact(7); }"),
    ("recursive_fibonacci",
        "int fib(int n) { if (n < 2) return n; return fib(n-1) + fib(n-2); } \
                int main(void) { return fib(15); }"),
    ("mutual_recursion_is_even",
        "int is_odd(int n) { if (n == 0) return 0; return is_even(n - 1); } \
                int is_even(int n) { if (n == 0) return 1; return is_odd(n - 1); } \
                int main(void) { return is_even(10) * 10 + is_odd(7); }"),
    ("cxx_reference_parameter_mutates_caller",
        "void inc(int& r) { r = r + 1; } \
               int main(void) { int a; a = 41; inc(a); return a; }"),
    ("cxx_reference_local_alias",
        "int main(void) { int a; int& r = a; a = 5; r = r * 8; return a; }"),
    ("cxx_reference_to_struct_member",
        "struct P { int x; int y; }; \
               void bump(int& v) { v = v + 10; } \
               int main(void) { P p; p.x = 1; p.y = 2; \
                 bump(p.x); bump(p.y); return p.x*100 + p.y; }"),
    ("cxx_class_ctor_and_methods",
        "class Counter { \
                 int n; \
               public: \
                 Counter(int s) { n = s; } \
                 void add(int d) { n = n + d; } \
                 int get() { return n; } \
               }; \
               int main(void) { Counter c(40); c.add(2); return c.get(); }"),
    ("cxx_method_via_pointer_and_this",
        "struct Point { \
                 int x; int y; \
                 void set(int a, int b) { x = a; y = b; } \
                 int sum() { return this->x + y; } \
               }; \
               int main(void) { Point p; Point *q; q = &p; \
                 q->set(30, 12); return q->sum(); }"),
    ("cxx_default_ctor_and_sibling_call",
        "class Acc { \
                 int t; \
               public: \
                 Acc() { t = 0; } \
                 void one() { t = t + 1; } \
                 int run() { one(); one(); one(); return t; } \
               }; \
               int main(void) { Acc a; return a.run(); }"),
    ("cxx_new_delete_scalar",
        "int main(void) { int* p = new int; *p = 42; \
                 int r = *p; delete p; return r; }"),
    ("cxx_new_class_ctor_and_method",
        "class Box { \
                 int v; \
               public: \
                 Box(int s) { v = s; } \
                 void add(int d) { v = v + d; } \
                 int get() { return v; } \
               }; \
               int main(void) { Box* b = new Box(40); \
                 b->add(2); int r = b->get(); delete b; return r; }"),
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
                 return v; }"),
    ("cxx_raii_block_scope_reverse_order",
        "class Tr { \
                 int* log; int id; \
               public: \
                 Tr(int* L, int i) { log = L; id = i; } \
                 ~Tr() { *log = *log * 10 + id; } \
               }; \
               int main(void) { int v; v = 0; \
                 { Tr a(&v, 1); Tr b(&v, 2); } \
                 return v; }"),
    ("cxx_raii_destructor_runs_before_return",
        "class S { \
                 int* p; \
               public: \
                 S(int* q) { p = q; } \
                 ~S() { *p = *p + 7; } \
               }; \
               int bump(int* p) { S s(p); if (*p > 0) return 1; return 2; } \
               int main(void) { int v; v = 3; bump(&v); return v; }"),
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
                 return w + v; }"),
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
               int main(void) { Counter c(40); c.add(2); return c.get(); }"),
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
                 return v; }"),
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
                 return r; }"),
    ("cxx_operator_plus_out_of_line",
        "class Money { \
                 int cents; \
               public: \
                 Money(int c); \
                 int operator+(Money& o); \
               }; \
               Money::Money(int c) { cents = c; } \
               int Money::operator+(Money& o) { return cents + o.cents; } \
               int main(void) { Money a(150); Money b(75); return a + b; }"),
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
                 return r; }"),
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
               int main(void) { Derived x; return x.sum(); }"),
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
                 return d.numLegs() + d.score(); }"),
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
                 return v; }"),
    ("cxx_default_args_free_function",
        "int area(int w, int h = 3); \
               int area(int w, int h) { return w * h; } \
               int main(void) { return area(4) + area(5, 2); }"),
    ("cxx_default_args_member_and_ctor",
        "class Rect { \
                 int w; int h; \
               public: \
                 Rect(int a, int b = 5) { w = a; h = b; } \
                 int scale(int f = 2) { return w * h * f; } \
               }; \
               int main(void) { Rect r(4); Rect s(3, 10); \
                 return r.scale() + s.scale(1); }"),
    ("cxx_default_args_prototype_then_out_of_line",
        "class C { \
                 int n; \
               public: \
                 C(int v = 100); \
                 int get(int add = 1); \
               }; \
               C::C(int v) { n = v; } \
               int C::get(int add) { return n + add; } \
               int main(void) { C a; C b(7); return a.get() + b.get(5); }"),
    ("cxx_overload_by_param_type",
        "int f(int x) { return x + 1; } \
               int f(char* s) { return 100; } \
               int main(void) { return f(41) + f(\"hi\"); }"),
    ("cxx_overload_by_arity",
        "int g(int a, int b) { return a * b; } \
               int g(int a) { return a + 7; } \
               int main(void) { return g(6, 7) + g(10); }"),
    ("cxx_overload_pointer_vs_int",
        "int kind(int* p) { return 1; } \
               int kind(int v) { return 2; } \
               int main(void) { int x; x = 5; int* q; q = &x; \
                 return kind(q) * 10 + kind(x); }"),
    ("printf_decimal_and_text",
        "int main(void){ printf(\"x=%d y=%d\\n\", -7, 13); return 0; }"),
    ("printf_string_char_hex_unsigned",
        "int main(void){ \
           printf(\"%s!\\n\", \"hi\"); \
           printf(\"%c%c\\n\", 65, 66); \
           printf(\"%x %X\\n\", 255, 255); \
           printf(\"%u\\n\", -1); \
           printf(\"100%% done\\n\"); \
           return 0; }"),
    ("printf_returns_total_bytes_with_format",
        "int main(void){ return printf(\"v=%d\", 255); }"),
    ("printf_loop_and_expression_args",
        "int main(void){ int i; \
           for (i = 1; i <= 3; i = i + 1) printf(\"sq(%d)=%d\\n\", i, i*i); \
           return 0; }"),
    ("libc_strlen_strcmp_abs_atoi",
        "int main(void){ int r = 0; \
                 r = r + strlen(\"hello\"); \
                 if (strcmp(\"abc\", \"abc\") == 0) r = r + 10; \
                 if (strcmp(\"abc\", \"abd\") < 0) r = r + 20; \
                 r = r + abs(-13); \
                 r = r + atoi(\"100\"); \
                 r = r - atoi(\"-8\"); \
                 return r; }"),
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
                 return 0; }"),
    ("libc_respects_include_string_h_stub",
        "#include <string.h>\n\
               int main(void){ return strlen(\"abcdef\"); }"),
    ("inline_asm_block_is_dropped",
        "int main(void){ int x; x = 10; \
                 asm { mov eax, 99 } \
                 x = x + 5; return x; }"),
    ("inline_asm_statement_forms",
        "int main(void){ int r; r = 7; \
                 asm mov ax, bx; \
                 asm nop\n\
                 r = r * 6; return r; }"),
    ("inline_asm_underscore_and_paren_forms",
        "int main(void){ int v; v = 3; \
                 __asm { push eax\n pop eax } \
                 asm(\"nop\"); \
                 v = v + 39; return v; }"),
    ("struct_members_read_write",
        "struct P { int x; int y; }; \
               int main(void){ struct P p; p.x = 30; p.y = 12; return p.x + p.y; }"),
    ("struct_pointer_arrow_and_param",
        "struct P { int a; int b; }; \
               int sum(struct P *p){ return p->a + p->b; } \
               int main(void){ struct P q; q.a = 40; q.b = 2; return sum(&q); }"),
    ("self_referential_linked_list",
        "struct N { int v; struct N *next; }; \
               int main(void){ \
                 struct N a; struct N b; struct N c; \
                 a.v = 1; b.v = 2; c.v = 3; \
                 a.next = &b; b.next = &c; c.next = 0; \
                 int sum; struct N *p; sum = 0; p = &a; \
                 while (p) { sum += p->v; p = p->next; } \
                 return sum; }"),
    ("whole_struct_assignment_copies",
        "struct P { int x; int y; }; \
               int main(void){ struct P a; struct P b; \
                 a.x = 3; a.y = 4; b = a; b.x = 10; \
                 return a.x*100 + a.y*10 + b.x; }"),
    ("nested_structs",
        "struct Inner { int n; }; \
               struct Outer { struct Inner in; int k; }; \
               int main(void){ struct Outer o; o.in.n = 7; o.k = 35; \
                 return o.in.n + o.k; }"),
    ("array_of_structs",
        "struct V { int x; }; \
               int main(void){ struct V a[3]; int i; \
                 for (i = 0; i < 3; i++) a[i].x = i * i; \
                 return a[0].x + a[1].x + a[2].x; }"),
    ("union_overlaps_members",
        "union U { int i; char c[4]; }; \
               int main(void){ union U u; u.i = 0; u.c[0] = 65; return u.i; }"),
    ("enum_constants_are_values",
        "enum Color { RED, GREEN = 5, BLUE }; \
               int main(void){ return RED*100 + GREEN*10 + BLUE; }"),
    ("typedef_struct_alias",
        "typedef struct { int a; int b; } Pair; \
               int add(Pair *p){ return p->a + p->b; } \
               int main(void){ Pair q; q.a = 19; q.b = 23; return add(&q); }"),
    ("typedef_scalar_alias_and_sizeof_struct",
        "typedef unsigned char byte; \
               struct S { char c; int i; }; \
               int main(void){ byte b; b = 200; \
                 return b + sizeof(struct S); }"),
    ("pointers_address_of_and_deref",
        "int main(void){ int x; int *p; x = 5; p = &x; \
               *p = *p + 37; return x; }"),
    ("arrays_subscript_and_compound_assign",
        "int main(void){ int a[5]; int i; int s; s = 0; \
               for (i = 0; i < 5; i++) a[i] = i * i; \
               for (i = 0; i < 5; i++) s += a[i]; return s; }"),
    ("char_pointer_strlen",
        "int slen(char *s){ int n; n = 0; while (*s) { n++; s++; } return n; } \
               int main(void){ return slen(\"hello, world\"); }"),
    ("pointer_arithmetic_indexes_chars",
        "int main(void){ char *s; s = \"abcdef\"; return s[4]; }"),
    ("global_variable_state",
        "int g; int bump(void){ g = g + 1; return g; } \
               int main(void){ g = 40; bump(); bump(); return g; }"),
    ("sizeof_types",
        "int main(void) { return sizeof(int) + sizeof(char) + sizeof(int*); }"),
    ("integer_cast_truncates",
        "int main(void){ int x; x = 300; return (char)x; }"),
    ("ternary_and_prefix_postfix",
        "int main(void){ int a; a = 7; return a > 5 ? 100 : 200; }"),
    ("char_array_buffer_writes",
        "int main(void){ char b[4]; b[0] = 'O'; b[1] = 'K'; \
               b[2] = 33; b[3] = 0; return b[0] + b[1]; }"),
    ("unsigned_division_and_shift",
        "int main(void){ unsigned int x; x = 4294967295; return x / 2; }"),
    ("string_global_and_printf",
        "char *msg = \"global string\\n\"; \
               int main(void){ printf(\"global string\\n\"); return msg[0]; }"),
    ("preprocessor_object_and_function_macros",
        "#define N 7\n#define SQ(x) ((x)*(x))\n\
               int main(void){ return SQ(N); }"),
    ("preprocessor_conditional_compilation",
        "#define LEVEL 2\n\
               int main(void){\n\
               #if LEVEL > 1\n  return 10;\n#else\n  return 20;\n#endif\n}"),
    ("system_include_is_stubbed_and_printf_works",
        "#include <stdio.h>\n#include <stdlib.h>\n\
               int main(void){ printf(\"inc-ok\\n\"); return 0; }"),
    ("prototype_then_definition_links",
        "int add(int a, int b);\n\
               int main(void){ return add(19, 23); }\n\
               int add(int a, int b){ return a + b; }"),
    ("ifndef_include_guard_pattern",
        "#ifndef ONCE\n#define ONCE\n\
               int helper(void){ return 5; }\n#endif\n\
               int main(void){ return helper() * 8; }"),
    ("printf_writes_string_to_stdout",
        r#"int main(void){ printf("Hello, world!\n"); return 0; }"#),
    ("puts_appends_newline",
        r#"int main(void){ puts("hi"); return 0; }"#),
    ("printf_returns_byte_count",
        r#"int main(void){ return printf("abc"); }"#),
    ("adjacent_string_literals_concatenate",
        r#"int main(void){ printf("foo" "bar"); return 0; }"#),
    ("output_from_loop_and_callee",
        r#"
        int greet(void) { printf("hi\n"); return 0; }
        int main(void) {
            int i;
            for (i = 0; i < 3; i = i + 1) greet();
            printf("done\n");
            return 0;
        }"#),
    ("escape_sequences_in_output",
        r#"int main(void){ printf("a\tb\\c\"d"); return 0; }"#),
    ("nested_calls_as_arguments",
        "int add(int a, int b) { return a + b; } \
                int sq(int x) { return x * x; } \
                int main(void) { return add(sq(3), sq(add(2, 2))); }"),
];

#[test]
fn s1b4_fixture_count_matches_e2e_suite() {
    assert_eq!(
        FIXTURES.len(),
        88,
        "FIXTURES drifted from the 88-program O1 contract; reconcile \
         with tests/end_to_end.rs (88 #[test] functions)."
    );
    let mut seen = std::collections::HashSet::new();
    for (name, _) in FIXTURES {
        assert!(
            seen.insert(*name),
            "duplicate fixture name {name:?} — names must be unique."
        );
    }
}

#[test]
fn s1b4_module_to_object_roundtrip_all_88_fixtures() {
    let mut failures: Vec<String> = Vec::new();
    for (name, src) in FIXTURES {
        match compile_to_object(src.as_bytes()) {
            Err(e) => {
                failures.push(format!("{name}: compile_to_object failed: {e}"));
                continue;
            }
            Ok(obj) => {
                let bytes = obj.write();
                let decoded = match Object::read(&bytes) {
                    Ok(d) => d,
                    Err(e) => {
                        failures.push(format!("{name}: decode failed: {e}"));
                        continue;
                    }
                };
                // The assertion macros panic on first failure; we wrap
                // in a closure so the loop can continue and report all
                // broken fixtures in one run.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    assert_structurally_equivalent(&obj, &decoded, name)
                }));
                if let Err(panic_payload) = result {
                    let msg = panic_payload
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| {
                            panic_payload
                                .downcast_ref::<&'static str>()
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_else(|| "<unknown panic>".to_string());
                    failures.push(format!("{name}: round-trip mismatch: {msg}"));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "S1b.4 round-trip failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn s1b4_object_byte_determinism_all_88_fixtures() {
    let mut failures: Vec<String> = Vec::new();
    for (name, src) in FIXTURES {
        let bytes_a = match compile_to_object(src.as_bytes()) {
            Ok(o) => o.write(),
            Err(e) => {
                failures.push(format!("{name}: compile #1 failed: {e}"));
                continue;
            }
        };
        let bytes_b = match compile_to_object(src.as_bytes()) {
            Ok(o) => o.write(),
            Err(e) => {
                failures.push(format!("{name}: compile #2 failed: {e}"));
                continue;
            }
        };
        if bytes_a != bytes_b {
            // Surface the size + first-diff offset so a regression is
            // diagnosable without rerunning under a debugger.
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
                "{name}: non-deterministic OBJ bytes \
                 (len_a={}, len_b={}, {first_diff})",
                bytes_a.len(),
                bytes_b.len()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "S1b.4 determinism failures (R16 violation):\n{}",
        failures.join("\n")
    );
}
