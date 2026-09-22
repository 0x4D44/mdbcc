//! S1c.4 — Two-file program linking.
//!
//! The S1c.4 gate test (HLD §8.4): merge two independent COFF Objects
//! into a single PE executable. The `foo` Object is produced by
//! `mdbcc::compile_to_object` from a normal `.cpp` source that calls an
//! extern function; the `bar` Object is hand-constructed (a minimal
//! `int bar(int x)` machine-code blob plus the `_bar` symbol) because
//! mdbcc's codegen currently requires every translation unit to define
//! `main` (the HLD §10 Q-Mangling-Reach issue — closing the C-linkage
//! definitions side is deferred to S3/S4). Hand-rolling the Object lets
//! S1c.4 verify the linker's multi-Object machinery without depending on
//! a codegen change that's out of phase scope.
//!
//! Additional coverage:
//! - Duplicate strong external definitions across two inputs are detected
//!   and reported via [`mdbcc::link::LinkError::DuplicateSymbol`].
//! - Truly unresolved externals (caller present in one input; callee
//!   absent from every input) are reported via
//!   [`mdbcc::link::LinkError::UnresolvedExternals`] with the missing
//!   name listed.
//! - Single-input `link(&[Input::Object(obj)], opts)` produces a
//!   byte-identical PE to `link_single(obj, opts)` (R19 byte-identity
//!   invariant; closes the 88 SipHash baseline stripe — if this test
//!   fails, the multi-Object pipeline has diverged from single-Object).

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::coff::{
    self, AuxRecord, Object, Section, SectionRef, StorageClass, SymKind, SymName, Symbol,
};
use mdbcc::compile::compile_to_object_with;
use mdbcc::link::{self, Input, LinkOpts, Subsystem};
use mdbcc::pp;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);

impl TempExe {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("mdbcc_two_file_{}_{}.exe", std::process::id(), n));
        TempExe(p)
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn default_resolver() -> pp::DefaultResolver {
    pp::DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    }
}

fn link_opts() -> LinkOpts {
    LinkOpts {
        subsystem: Subsystem::Console,
        ..LinkOpts::default()
    }
}

fn object_has_ctor_thunk(obj: &Object) -> bool {
    obj.symbols.iter().any(|s| {
        let n = match &s.name {
            mdbcc::coff::SymName::Short(a) => {
                let end = a.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&a[..end]).into_owned()
            }
            mdbcc::coff::SymName::Long(off) => obj.strtab.get_str(*off).unwrap_or("").to_string(),
        };
        n.starts_with(".mdbcc_ctor.")
    })
}

/// Hand-craft a coff::Object that defines `_bar` as
/// `int bar(int x) { return x + 1; }`. The implementation is a tiny
/// position-independent x64 function: `mov eax, ecx; inc eax; ret`
/// (Win64 ABI: first integer arg in ECX/RCX; return in EAX/RAX).
///
/// Why hand-crafted and not `compile_to_object`: mdbcc's codegen requires
/// every translation unit to define `main` (or `WinMain`); a TU defining
/// only `bar` errors out at codegen with "no 'main' function defined".
/// That limitation is the HLD §10 Q-Mangling-Reach issue (closing the
/// C-linkage definitions side is deferred past S1c). For S1c.4's gate
/// we want the linker's multi-Object machinery exercised end-to-end;
/// the source-of-the-second-Object isn't part of the test scope.
fn build_bar_object() -> Object {
    // bar's machine code:
    //   89 C8             mov eax, ecx      ; eax = x
    //   FF C0             inc eax           ; eax = x + 1
    //   C3                ret
    // 5 bytes total. Section is padded to 16 (FN_ALIGN in codegen/object.rs)
    // for COMDAT compatibility, but a single-function .text section without
    // padding is structurally fine for the linker; we keep it minimal.
    let bar_code: Vec<u8> = vec![0x89, 0xC8, 0xFF, 0xC0, 0xC3];

    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };

    // .text section carrying just `_bar`'s body.
    let text_section = Section {
        data: bar_code.clone(),
        ..Section::text()
    };
    obj.sections.push(text_section);

    // Symbols:
    //   [0] .text — STATIC section symbol with SectionDef aux.
    //   [1] _bar  — EXTERNAL function, defined in .text at offset 0.
    //
    // The encoder requires the SectionDef aux for STATIC section symbols
    // (it carries the section's length / reloc count / checksum).
    let mut section_name_arr = [0u8; 8];
    section_name_arr[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(section_name_arr),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: bar_code.len() as u32,
            num_relocs: 0,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    // `_bar` symbol — name fits in 8 bytes (Short form).
    let mut bar_name_arr = [0u8; 8];
    bar_name_arr[..4].copy_from_slice(b"_bar");
    obj.symbols.push(Symbol {
        name: SymName::Short(bar_name_arr),
        value: 0, // offset within .text
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    obj.symbol_source_locs = vec![None; obj.symbols.len()];
    obj
}

/// Hand-craft a coff::Object that defines `_bar` with a different
/// implementation (`return x + 99`) — used by the duplicate-symbol test
/// to clash against another `_bar` definition.
fn build_bar_object_other() -> Object {
    let mut obj = build_bar_object();
    // Replace the body bytes (5-byte `mov eax, ecx; inc eax; ret` becomes
    // an obviously-different `mov eax, ecx; add eax, 99; ret` — we don't
    // execute the merged image so the exact bytes don't matter).
    obj.sections[0].data = vec![0x89, 0xC8, 0x83, 0xC0, 0x63, 0xC3]; // add eax, 99
    obj.sections[0].relocs.clear();
    if let Some(AuxRecord::SectionDef { length, .. }) = obj.symbols[0].aux.first_mut() {
        *length = obj.sections[0].data.len() as u32;
    }
    obj
}

/// Hand-craft a coff::Object defining `@C@$bcall$qui` — the Borland-mangled
/// `char& C::operator()(unsigned i)` for the S4.2aj test's class `C` (whose
/// first member is `char* buf`). Returns `&buf[i]`:
///   48 8B 01   mov rax, [rcx]   ; rax = this->buf   (Win64: `this` in RCX)
///   48 01 D0   add rax, rdx     ; rax = buf + i     (`i` in EDX, zero-extended)
///   C3         ret              ; return char& == the address in RAX
/// Hand-rolled (not compiled) for the same reason as `build_bar_object`: a TU
/// defining only this operator — no `main` — fails mdbcc codegen.
fn build_c_operator_call_object() -> Object {
    let code: Vec<u8> = vec![0x48, 0x8B, 0x01, 0x48, 0x01, 0xD0, 0xC3];
    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };
    let text_section = Section {
        data: code.clone(),
        ..Section::text()
    };
    obj.sections.push(text_section);
    let mut section_name_arr = [0u8; 8];
    section_name_arr[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(section_name_arr),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: code.len() as u32,
            num_relocs: 0,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    // `@C@$bcall$qui` is 13 bytes (> 8) ⇒ Long form, interned in the strtab.
    let opname = SymName::from_str("@C@$bcall$qui", &mut obj.strtab);
    obj.symbols.push(Symbol {
        name: opname,
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    obj.symbol_source_locs = vec![None; obj.symbols.len()];
    obj
}

/// Hand-craft a coff::Object defining `@C@fold$qr1Ci` — the Borland-mangled
/// `int C::fold(const C& o, int k)` for the S4.2ak test's class `C` (first
/// member `int v`). Returns `this->v + o.v + k`:
///   8B 01      mov eax, [rcx]   ; eax = this->v   (Win64: `this` in RCX)
///   03 02      add eax, [rdx]   ; eax += o->v     (`const C&` o passed as ptr in RDX)
///   41 03 C0   add eax, r8d     ; eax += k        (3rd int arg in R8D)
///   C3         ret
/// Hand-rolled (a TU defining only this overload — no `main` — fails codegen).
fn build_c_fold_object() -> Object {
    let code: Vec<u8> = vec![0x8B, 0x01, 0x03, 0x02, 0x41, 0x03, 0xC0, 0xC3];
    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };
    let text_section = Section {
        data: code.clone(),
        ..Section::text()
    };
    obj.sections.push(text_section);
    let mut section_name_arr = [0u8; 8];
    section_name_arr[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(section_name_arr),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: code.len() as u32,
            num_relocs: 0,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    let foldname = SymName::from_str("@C@fold$qr1Ci", &mut obj.strtab);
    obj.symbols.push(Symbol {
        name: foldname,
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    obj.symbol_source_locs = vec![None; obj.symbols.len()];
    obj
}

#[test]
fn extern_extra_arg_overload_links_and_runs() {
    // S4.2ak: a member with ONE in-TU definition but an ADDITIONAL extern-only
    // overload (declared in-class, defined in another TU / the RTL .lib) — the
    // shape of `string::append`/`assign`/`replace`/`find`, where the short form
    // is inline and delegates to the extra-arg form in the .lib. Without S4.2ak
    // the extern overload is invisible (the set is built from in-TU defs only):
    // the inline delegator's call "expects 0..=1 args, got N" and DEFERS,
    // dropping the symbol. S4.2ak promotes the member to the overload set by
    // counting the DISTINCT extern proto, TYPE-COMPLETES its self-referential
    // `const C&` param (captured `size:0` mid-class-body) so `arg_compat` matches,
    // and mangles via the records table so the call + the cross-TU definition
    // agree on the stable TAG form (`@C@fold$qr1Ci`, not a per-TU id placeholder).
    //
    // `fold(const C&)` is defined out-of-line (the RTL idiom — so the sibling-
    // call rewrite sees a complete `methods` set) and delegates to the extern
    // `fold(const C&, int)`. Linking against the hand-crafted `@C@fold$qr1Ci`
    // (returns `this->v + o.v + k`) and running `a.fold(b)` with a.v=40, b.v=2
    // ⇒ fold(b,1) ⇒ 40 + 2 + 1 = 43.
    let main_src = b"\
        struct C {\n\
          int v;\n\
          int fold(const C& o);\n\
          int fold(const C& o, int k);\n\
        };\n\
        inline int C::fold(const C& o) { return fold(o, 1); }\n\
        int main(void) {\n\
          C a; a.v = 40;\n\
          C b; b.v = 2;\n\
          return a.fold(b);\n\
        }\n";
    let resolver = default_resolver();
    let main_obj =
        compile_to_object_with(main_src, "fmain.cpp", &resolver).expect("compile fmain.cpp");
    let ext_obj = build_c_fold_object();

    let exe = link::link(
        &[Input::Object(&main_obj), Input::Object(&ext_obj)],
        &link_opts(),
    )
    .expect(
        "link fmain + @C@fold$qr1Ci — the inline `fold(const C&)` delegator must \
         resolve+emit (not defer) and call the extern overload under the stable \
         tag-mangled symbol (S4.2ak)",
    );

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    let code = status.code().expect("process returned an exit code");
    assert_eq!(
        code, 43,
        "expected exit 43 (a.fold(b) => fold(b,1) => 40+2+1) via extra-arg extern overload"
    );
}

#[test]
fn extern_ref_returning_operator_links_and_runs() {
    // S4.2aj — a member operator DECLARED in-class but defined OUT-OF-LINE
    // (extern, in another TU / the RTL .lib). The overload SET is built only
    // from in-TU definitions, so without S4.2aj the extern-only ref-returning
    // primitive `char& C::operator()(unsigned)` is invisible to the resolver:
    // the inline `operator[]`'s `return (*this)(i);` mis-resolves to a
    // by-value `operator()` sibling, the ref-return lvalue path fails, and
    // `operator[]` is DEFERRED — dropping `@C@$bsubs$qui` and leaving an
    // UNRESOLVED external at link. This mirrors CSTRING.H exactly:
    // `string::operator[]` delegates to the RTL-lib primitive
    // `string::operator()(size_t)->char&` (no inline body in the header).
    //
    // With S4.2aj the primitive resolves, `operator[]` is emitted, and linking
    // it against the hand-crafted `@C@$bcall$qui` (returns `&buf[i]`) then
    // running `c[2] = 42; return c[2];` yields exit 42. Two inline `operator()`
    // siblings put the name into the overload set (the precondition for the
    // S4.2aj `overloads.contains_key` branch).
    let main_src = b"\
        struct C {\n\
          char* buf;\n\
          int   operator()(int a, int b) { return a + b; }\n\
          int   operator()(int a) { return a; }\n\
          char& operator()(unsigned i);\n\
          char& operator[](unsigned i) { return (*this)(i); }\n\
        };\n\
        int main(void) {\n\
          char data[4];\n\
          C c; c.buf = data;\n\
          c[2] = 42;\n\
          return c[2];\n\
        }\n";
    let resolver = default_resolver();
    let main_obj =
        compile_to_object_with(main_src, "cmain.cpp", &resolver).expect("compile cmain.cpp");
    let prim_obj = build_c_operator_call_object();

    let exe = link::link(
        &[Input::Object(&main_obj), Input::Object(&prim_obj)],
        &link_opts(),
    )
    .expect(
        "link cmain + @C@$bcall$qui — operator[] must be EMITTED (not deferred) \
         for the reference to resolve (S4.2aj)",
    );

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    let code = status.code().expect("process returned an exit code");
    assert_eq!(
        code, 42,
        "expected exit 42 (c[2] = 42; return c[2]) via operator[] -> extern operator()"
    );
}

#[test]
fn two_objects_link_and_run() {
    // foo.cpp — defines main, declares bar (extern in another TU).
    //   main computes 1 + bar(10) + bar(20) = 1 + 11 + 21 = 33
    let foo_src = b"\
        int bar(int x);\n\
        int main(void) {\n\
            int v;\n\
            v = 1;\n\
            v = v + bar(10);\n\
            v = v + bar(20);\n\
            return v;\n\
        }\n";

    // S4.2b8: compile the `bar` definer with mdbcc TOO (was a hand-crafted
    // `_bar` blob). This now exercises real mdbcc→mdbcc free-function linking:
    // the caller references the primitive-param extern `bar` by its PLAIN name,
    // matching the definer's plain `bar` symbol. Before the fix the caller
    // emitted `_bar` (C-linkage heuristic) and left it unresolved against the
    // definer's `bar`.
    let bar_src = b"int bar(int x) { return x + 1; }\n";
    let resolver = default_resolver();
    let foo_obj = compile_to_object_with(foo_src, "foo.cpp", &resolver).expect("compile foo.cpp");
    let bar_obj = compile_to_object_with(bar_src, "bar.cpp", &resolver).expect("compile bar.cpp");

    let exe = link::link(
        &[Input::Object(&foo_obj), Input::Object(&bar_obj)],
        &link_opts(),
    )
    .expect("link foo + bar (mdbcc→mdbcc, plain `bar` both sides)");

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    let code = status.code().expect("process returned an exit code");
    assert_eq!(
        code, 33,
        "two-file link expected exit 33 (1 + bar(10) + bar(20))"
    );
}

#[test]
fn cross_tu_dynamic_cast_reads_folded_vtable_prefix() {
    // G56: vtable symbols are weak-folded across TUs, so the selected vtable
    // layout must not depend on whether that particular TU uses dynamic_cast.
    // Link the no-dynamic_cast factory first so, before the fix, its no-prefix
    // `@Derived@3` vtable won the fold. The caller's dynamic_cast then read the
    // word before the vtable as a bogus this-adjustment.
    let common = "\
        struct Base { \
          int b; \
          Base(){ b = 1; } \
          virtual int tag(){ return 1; } \
          virtual ~Base(){} \
        };\n\
        struct Derived : public Base { \
          int d; \
          Derived(){ d = 41; } \
          virtual int tag(){ return 2; } \
          virtual ~Derived(){} \
        };\n";
    let factory_src = format!(
        "{common}\
        static Derived g;\n\
        Base* make() {{ return &g; }}\n"
    );
    let app_src = format!(
        "{common}\
        static Derived anchor;\n\
        Base* make();\n\
        int main(void) {{ \
          Base* b = make(); \
          Derived* d = dynamic_cast<Derived*>(b); \
          if (!d) return 10; \
          return d->d + 1; \
        }}\n"
    );
    let resolver = default_resolver();
    let factory_obj = compile_to_object_with(factory_src.as_bytes(), "dc_factory.cpp", &resolver)
        .expect("compile dynamic_cast factory TU");
    let app_obj = compile_to_object_with(app_src.as_bytes(), "dc_app.cpp", &resolver)
        .expect("compile dynamic_cast app TU");
    let exe = link::link(
        &[Input::Object(&factory_obj), Input::Object(&app_obj)],
        &link_opts(),
    )
    .expect("link dynamic_cast app with folded vtable");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    assert_eq!(
        status.code().expect("exit code"),
        42,
        "dynamic_cast must recover the object pointer through a folded vtable"
    );
}

/// S4 (#48): a no-initializer data declaration INSIDE an `extern "C"` linkage
/// spec is an external DECLARATION (C++ [dcl.link]/7), NOT a definition — so
/// multiple TUs that include the same `EXTERN_C const IID name;` (the OLE GUID
/// headers' `DEFINE_GUID` without `INITGUID`) do not collide. Before the fix
/// the no-init `extern "C" const` was emitted as a DEFINITION in every TU ->
/// "duplicate symbol 'IID_IAdviseSink'" at a multi-TU link (the first blocker
/// linking the real RTL string objects). Here TU1 references an
/// `extern "C" const int X;` (declaration) and TU2 defines it; they link
/// cleanly and X resolves to 5 (a definition WITH an initializer stays a def).
#[test]
fn extern_c_const_no_init_is_a_declaration_not_a_definition() {
    let ref_src = b"extern \"C\" const int X;\nint main() { return X; }\n";
    let def_src = b"extern \"C\" const int X = 5;\n";
    let resolver = default_resolver();
    let ref_obj = compile_to_object_with(ref_src, "refx.cpp", &resolver).expect("compile refx.cpp");
    let def_obj = compile_to_object_with(def_src, "defx.cpp", &resolver).expect("compile defx.cpp");
    let exe = link::link(
        &[Input::Object(&ref_obj), Input::Object(&def_obj)],
        &link_opts(),
    )
    .expect("link refx + defx (extern \"C\" const decl must not duplicate the def)");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    assert_eq!(
        status.code().expect("exit code"),
        5,
        "X must resolve to the definer's 5"
    );
}

#[test]
fn file_scope_const_with_initializer_has_internal_linkage() {
    // The NPOS case: a namespace-scope `const` WITH an initializer (as from a
    // shared header like cstring.h's `const size_t NPOS = size_t(-1);`) has
    // INTERNAL linkage in C++. Each TU that includes the header emits its own
    // private copy, so linking two such TUs must NOT report a duplicate symbol.
    let a_src = b"const int K = 5; int a() { return K; }\n";
    let b_src = b"const int K = 5; extern int a(); int main() { return a() + K - 3; }\n";
    let resolver = default_resolver();
    let a_obj = compile_to_object_with(a_src, "ka.cpp", &resolver).expect("compile ka.cpp");
    let b_obj = compile_to_object_with(b_src, "kb.cpp", &resolver).expect("compile kb.cpp");
    let exe = link::link(
        &[Input::Object(&a_obj), Input::Object(&b_obj)],
        &link_opts(),
    )
    .expect("link ka + kb (const-with-init must be internal linkage, not a duplicate def)");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    assert_eq!(
        status.code().expect("exit code"),
        7,
        "each TU's K=5: 5 + 5 - 3 = 7"
    );
}

#[test]
fn duplicate_symbol_reports_error() {
    // Both Objects define `_bar` as an EXTERNAL function. The linker
    // must reject the merged input with DuplicateSymbol.
    let a = build_bar_object();
    let b = build_bar_object_other();

    let err = link::link(&[Input::Object(&a), Input::Object(&b)], &link_opts())
        .expect_err("expected DuplicateSymbol");

    match err {
        link::LinkError::DuplicateSymbol { name } => {
            assert_eq!(name, "_bar", "expected duplicate name '_bar', got '{name}'");
        }
        other => panic!("expected DuplicateSymbol, got {other:?}"),
    }
}

#[test]
fn unresolved_symbol_after_link_reports_error() {
    // main calls bar but only foo.obj is given (bar is undefined).
    let foo_src = b"\
        int bar(int x);\n\
        int main(void) {\n\
            return bar(40);\n\
        }\n";

    let resolver = default_resolver();
    let foo_obj = compile_to_object_with(foo_src, "foo.cpp", &resolver).expect("compile foo.cpp");

    let err = link::link(&[Input::Object(&foo_obj)], &link_opts())
        .expect_err("expected UnresolvedExternals");

    match err {
        link::LinkError::UnresolvedExternals(items) => {
            let names: Vec<&str> = items.iter().map(|(n, _)| n.as_str()).collect();
            assert!(
                names.iter().any(|n| *n == "_bar" || *n == "bar"),
                "expected unresolved '_bar' (or 'bar') in {names:?}"
            );
        }
        other => panic!("expected UnresolvedExternals, got {other:?}"),
    }
}

#[test]
fn single_object_through_link_matches_link_single() {
    // R19 byte-identity: link(&[Input::Object(obj)], opts) MUST produce
    // the same bytes as link_single(obj, opts) for any single-Object
    // input. If this fails, the 88 SipHash baselines in
    // tests/o1_byte_identity.rs would shift in lockstep — investigate
    // the multi-Object pipeline divergence before re-blessing.
    let src = b"int main(void) { return 42; }\n";
    let resolver = default_resolver();
    let obj = compile_to_object_with(src, "input.cpp", &resolver).expect("compile input.cpp");
    let opts = link_opts();
    let pe_single = link::link_single(&obj, &opts).expect("link_single");
    let pe_multi = link::link(&[Input::Object(&obj)], &opts).expect("link slice");
    assert_eq!(
        pe_single.len(),
        pe_multi.len(),
        "single-Object byte length differs between link_single and link"
    );
    if pe_single != pe_multi {
        // Locate the first diverging byte to make the failure
        // actionable (helpful for hunting structural drift).
        let n = pe_single.len().min(pe_multi.len());
        for (i, (a, b)) in pe_single
            .iter()
            .take(n)
            .zip(pe_multi.iter().take(n))
            .enumerate()
        {
            if a != b {
                panic!(
                    "single-Object byte-identity broken at offset 0x{i:x}: \
                     link_single=0x{a:02x}, link=0x{b:02x} \
                     (this is the R19 invariant — multi-Object pipeline \
                     must collapse to single-Object output)"
                );
            }
        }
    }
    assert_eq!(
        pe_single, pe_multi,
        "single-Object byte-identity invariant broken"
    );
}

/// #20 PART 2b: a constructor-initialised file-scope object in a main-LESS TU
/// (an OWL/RTL library `.obj` — e.g. OWL COLOR.CPP's `TColor` instances) is
/// constructed before user code by a CRT static-init pass. bcc emits a
/// parameterless `.mdbcc_ctor.<g>` thunk that runs the ctor; mdlink collects
/// every such thunk and CALLS each, in order, from the entry stub immediately
/// before `main`. Previously such a TU was a hard compile error ("global
/// initializer must be a constant").
///
/// This links a main-LESS ctor-global TU with a separate `main` TU and RUNS
/// the image, asserting `main`'s return is intact (7) — i.e. the synthesised
/// ctor thunk executes before `main` and returns control cleanly, without
/// corrupting the stack or the entry path. (Observing the ctor's cross-TU side
/// effect additionally needs cross-TU global unification, tracked separately;
/// here the contract is "the static-init mechanism links + runs cleanly".)
#[test]
fn main_less_ctor_global_links_and_runs_static_init_thunk() {
    let lib_src = b"struct S { int v; S(int x) { v = x; } };\nS g(42);\n";
    let main_src = b"int main(void) { return 7; }\n";
    let resolver = default_resolver();
    let lib_obj = compile_to_object_with(lib_src, "ctorlib.cpp", &resolver)
        .expect("main-less ctor-global TU must COMPILE (#20 PART 2b)");
    let main_obj =
        compile_to_object_with(main_src, "ctormain.cpp", &resolver).expect("compile main TU");
    // The lib object must carry the synthesised constructor thunk.
    assert!(
        object_has_ctor_thunk(&lib_obj),
        "bcc must emit a .mdbcc_ctor.* thunk for the ctor-global"
    );

    let exe = link::link(
        &[Input::Object(&lib_obj), Input::Object(&main_obj)],
        &link_opts(),
    )
    .expect("link ctor-global lib + main (mdlink collects the thunk + calls it pre-main)");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let code = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"))
        .code()
        .expect("process returned an exit code");
    assert_eq!(
        code, 7,
        "the CRT static-init thunk must run before main and return cleanly \
         (main's return value 7 intact)"
    );
}

/// B-11: the main-less static-init thunk path must also default-construct every
/// element of an INIT-LESS file-scope class array. The single-TU `main` path and
/// scalar globals already had coverage; this catches the library-object route.
#[test]
fn main_less_default_ctor_global_array_observed_in_main() {
    let lib_src = b"static int seq = 0;\n\
                    struct G { int v; G() { seq = seq + 1; v = seq; } };\n\
                    static G gs[3];\n\
                    int sum_gs(void) { return seq * 10 + gs[0].v + gs[1].v + gs[2].v + 6; }\n";
    let app_src = b"int sum_gs(void);\n\
                    int main(void) { return sum_gs(); }\n";
    let resolver = default_resolver();
    let lib_obj = compile_to_object_with(lib_src, "ctor_array_lib.cpp", &resolver)
        .expect("compile main-less default-ctor global array lib");
    assert!(
        object_has_ctor_thunk(&lib_obj),
        "bcc must emit a .mdbcc_ctor.* thunk for the default-ctor global array"
    );
    let app_obj =
        compile_to_object_with(app_src, "ctor_array_app.cpp", &resolver).expect("compile app");
    let exe = link::link(
        &[Input::Object(&lib_obj), Input::Object(&app_obj)],
        &link_opts(),
    )
    .expect("link default-ctor global array lib + app");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let code = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"))
        .code()
        .expect("process returned an exit code");
    assert_eq!(
        code, 42,
        "the CRT static-init thunk must construct all array elements before main"
    );
}

/// S4.2b8 (with #20 PART 2b): the strongest end-to-end slice. A main-LESS
/// library TU has a file-scope object whose constructor calls a cross-TU free
/// function; the app TU defines that function (recording into a global) and
/// `main`. Linking + RUNNING the two mdbcc objects proves three things at once:
///   (a) the CRT static-init thunk runs the ctor BEFORE main (#20 PART 2b);
///   (b) the ctor's call to `record` — a primitive-param free function defined
///       in the OTHER TU — RESOLVES (mdbcc→mdbcc free-function linking; before
///       S4.2b8 the caller referenced `_record` and the definer emitted
///       `record`, leaving it unresolved);
///   (c) the observable side effect (`slot == 42`) is seen by `main`.
#[test]
fn static_init_ctor_calls_cross_tu_function_observed_in_main() {
    let lib_src = b"void record(int);\n\
                    struct S { S(int x) { record(x); } };\n\
                    S g(42);\n";
    let app_src = b"int slot;\n\
                    void record(int x) { slot = x; }\n\
                    int main(void) { return slot; }\n";
    let resolver = default_resolver();
    let lib_obj = compile_to_object_with(lib_src, "ctorlib2.cpp", &resolver)
        .expect("compile main-less ctor-global lib");
    let app_obj = compile_to_object_with(app_src, "ctorapp2.cpp", &resolver).expect("compile app");
    let exe = link::link(
        &[Input::Object(&lib_obj), Input::Object(&app_obj)],
        &link_opts(),
    )
    .expect("link lib + app (cross-TU ctor → record, static-init thunk)");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let code = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"))
        .code()
        .expect("process returned an exit code");
    assert_eq!(
        code, 42,
        "ctor ran before main (static init) AND its cross-TU record(42) \
         resolved + was observed in main"
    );
}

/// #29: a main-LESS library TU with a file-scope SCALAR global whose initializer
/// is a RUNTIME expression (`int g = compute();`). bcc zero-initialises `g` and
/// emits a `.mdbcc_ctor.g` thunk that runs `g = compute()` before main (reusing
/// the #20 PART 2b mechanism — assignment body instead of a ctor call); mdlink
/// collects + calls it. The app reads `g` through a cross-TU accessor (`getg`)
/// to avoid relying on cross-TU data unification (#24). compute()==42, so the
/// thunk must run before main for getg() to observe 42. Before #29 this lib TU
/// was a hard error ("global initializer must be a constant").
#[test]
fn main_less_scalar_dynamic_init_thunk_observed_in_main() {
    let lib_src = b"int compute(void) { return 42; }\n\
                    int g = compute();\n\
                    int getg(void) { return g; }\n";
    let app_src = b"int getg(void);\n\
                    int main(void) { return getg(); }\n";
    let resolver = default_resolver();
    let lib_obj = compile_to_object_with(lib_src, "dynlib.cpp", &resolver)
        .expect("compile main-less dynamic-init scalar lib (#29)");
    let app_obj = compile_to_object_with(app_src, "dynapp.cpp", &resolver).expect("compile app");
    let has_thunk = lib_obj.symbols.iter().any(|s| {
        let n = match &s.name {
            mdbcc::coff::SymName::Short(a) => {
                let end = a.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&a[..end]).into_owned()
            }
            mdbcc::coff::SymName::Long(off) => {
                lib_obj.strtab.get_str(*off).unwrap_or("").to_string()
            }
        };
        n.starts_with(".mdbcc_ctor.")
    });
    assert!(
        has_thunk,
        "bcc must emit a .mdbcc_ctor.* thunk for the dynamic-init scalar global"
    );
    let exe = link::link(
        &[Input::Object(&lib_obj), Input::Object(&app_obj)],
        &link_opts(),
    )
    .expect("link dynamic-init scalar lib + app (#29 thunk runs pre-main)");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let code = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"))
        .code()
        .expect("process returned an exit code");
    assert_eq!(
        code, 42,
        "the #29 init thunk runs `g = compute()` before main; getg() observes 42"
    );
}

/// #24: cross-TU extern DATA. TU1 declares `extern int g;` and reads it; TU2
/// defines `int g = 42;`. Before #24, `extern int g;` emitted a LOCAL zero
/// definition and the read used the TU's own slot — a SILENT MISCOMPILE (main
/// returned 0). Now the extern declaration emits an UNDEFINED external symbol
/// and the defining global has EXTERNAL linkage, so mdlink resolves the read
/// cross-TU. Also verifies a cross-TU WRITE (`g = 9` in TU1, observed via TU1's
/// own read after the defining TU set 0). reader ⇒ 42; writer ⇒ 9.
#[test]
fn cross_tu_extern_data_reads_and_writes() {
    let resolver = default_resolver();
    let run = |objs: &[&mdbcc::coff::Object]| -> i32 {
        let inputs: Vec<Input> = objs.iter().map(|o| Input::Object(o)).collect();
        let exe = link::link(&inputs, &link_opts()).expect("link cross-TU extern data");
        let tmp = TempExe::new();
        std::fs::write(&tmp.0, &exe).expect("write exe");
        Command::new(&tmp.0)
            .status()
            .unwrap_or_else(|e| panic!("launch: {e}"))
            .code()
            .expect("exit code")
    };
    // READ: extern int g; return g;  +  int g = 42;  => 42
    let rd = compile_to_object_with(
        b"extern int g;\nint main(void){ return g; }\n",
        "rd.cpp",
        &resolver,
    )
    .expect("compile extern-read TU");
    let def =
        compile_to_object_with(b"int g = 42;\n", "def.cpp", &resolver).expect("compile def TU");
    assert_eq!(
        run(&[&rd, &def]),
        42,
        "#24: cross-TU extern data read resolves (was a silent 0)"
    );
    // WRITE: extern int g; set g=9 then read it  +  int g = 0;  => 9
    let wr = compile_to_object_with(
        b"extern int g;\nint main(void){ g = 9; return g; }\n",
        "wr.cpp",
        &resolver,
    )
    .expect("compile extern-write TU");
    let def0 =
        compile_to_object_with(b"int g = 0;\n", "def0.cpp", &resolver).expect("compile def0 TU");
    assert_eq!(
        run(&[&wr, &def0]),
        9,
        "#24: cross-TU extern data write resolves"
    );
}

/// S4.2#35: cross-TU STATIC DATA MEMBER. TU2 references `C::x` (kept qualified,
/// not flattened to a bare `x`); being declared-but-undefined there it emits an
/// extern global, resolved by mdlink against TU1's out-of-line `int C::x = 42;`.
/// Also covers a RECORD-typed static member (the OWL `TColor::Black` shape) —
/// a silent-0 risk if the cross-TU read used the wrong slot/size. Both ⇒ 42.
/// (Unblocked OWL PEN.CPP — corpus 27→28.)
#[test]
fn cross_tu_static_data_member_reads() {
    let resolver = default_resolver();
    let run = |objs: &[&mdbcc::coff::Object]| -> i32 {
        let inputs: Vec<Input> = objs.iter().map(|o| Input::Object(o)).collect();
        let exe = link::link(&inputs, &link_opts()).expect("link cross-TU static member");
        let tmp = TempExe::new();
        std::fs::write(&tmp.0, &exe).expect("write exe");
        Command::new(&tmp.0)
            .status()
            .unwrap_or_else(|e| panic!("launch: {e}"))
            .code()
            .expect("exit code")
    };
    // Scalar static member: `int C::x = 42;` (def TU) + `return C::x;` (ref TU).
    let sdef = compile_to_object_with(
        b"struct C { static int x; };\nint C::x = 42;\n",
        "sdef.cpp",
        &resolver,
    )
    .expect("compile scalar-def TU");
    let srd = compile_to_object_with(
        b"struct C { static int x; };\nint main(void){ return C::x; }\n",
        "srd.cpp",
        &resolver,
    )
    .expect("compile scalar-ref TU");
    assert_eq!(
        run(&[&srd, &sdef]),
        42,
        "#35: cross-TU scalar static-member read"
    );
    // Record-typed static member (TColor::Black shape): 11 + 31 = 42.
    let rdef = compile_to_object_with(
        b"struct K { int a, b; static K g; };\nK K::g = {11, 31};\n",
        "rdef.cpp",
        &resolver,
    )
    .expect("compile record-def TU");
    let rrd = compile_to_object_with(
        b"struct K { int a, b; static K g; };\nint main(void){ return K::g.a + K::g.b; }\n",
        "rrd.cpp",
        &resolver,
    )
    .expect("compile record-ref TU");
    assert_eq!(
        run(&[&rrd, &rdef]),
        42,
        "#35: cross-TU RECORD static-member read (no silent 0)"
    );
}

/// S4.2b9: an OVERLOADED free function called across a TU boundary. The caller
/// sees two `add` extern protos ⇒ the name is overloaded ⇒ each call mangles
/// `@add$q<params>` (matching the definer's overload symbols), where before it
/// emitted the non-overloaded form and left `add` unresolved. `add(40, 2)`
/// resolves to `@add$qii` ⇒ 42. (Covers RTL operators / overloaded helpers.)
#[test]
fn overloaded_free_function_links_across_tu() {
    let caller_src = b"int add(int a, int b);\n\
                       int add(int a);\n\
                       int main(void) { return add(40, 2); }\n";
    let definer_src = b"int add(int a, int b) { return a + b; }\n\
                        int add(int a) { return a; }\n";
    let resolver = default_resolver();
    let caller =
        compile_to_object_with(caller_src, "ovl_caller.cpp", &resolver).expect("compile caller");
    let definer =
        compile_to_object_with(definer_src, "ovl_definer.cpp", &resolver).expect("compile definer");
    let exe = link::link(
        &[Input::Object(&caller), Input::Object(&definer)],
        &link_opts(),
    )
    .expect("link overloaded free function across TUs (@add$qii both sides)");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let code = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"))
        .code()
        .expect("process returned an exit code");
    assert_eq!(code, 42, "add(40,2) via the 2-arg overload (@add$qii) ⇒ 42");
}

/// S4.2b10: an IDENTICAL extern re-declaration is NOT an overload. Real Win32
/// headers re-declare an API along multiple include paths; counting raw protos
/// (b9) mis-tallied such a name as overloaded ⇒ the call mangled `@name$q…`
/// instead of the plain (b8) form, breaking the cross-TU link. Deduping by
/// signature restores the plain reference. Here `bar` is declared twice
/// identically in the caller; it must still link against the plain `bar` definer.
#[test]
fn identical_extern_redeclaration_is_not_an_overload() {
    let caller_src = b"int bar(int x);\n\
                       int bar(int x);\n\
                       int main(void) { return bar(41) + 1; }\n";
    let definer_src = b"int bar(int x) { return x; }\n";
    let resolver = default_resolver();
    let caller =
        compile_to_object_with(caller_src, "dup_caller.cpp", &resolver).expect("compile caller");
    let definer =
        compile_to_object_with(definer_src, "dup_definer.cpp", &resolver).expect("compile definer");
    let exe = link::link(
        &[Input::Object(&caller), Input::Object(&definer)],
        &link_opts(),
    )
    .expect("link: identical redeclaration must reference plain `bar`, not `@bar$qi`");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let code = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"))
        .code()
        .expect("process returned an exit code");
    assert_eq!(
        code, 42,
        "bar(41)+1 ⇒ 42 (identical redecl linked as plain `bar`)"
    );
}

/// S4.2b11: a C-linkage (`extern "C"`) primitive-param free function is
/// referenced by its PLAIN name, NOT `@name$q…` (C++ overload mangling). Before
/// the fix the `!proto.c_linkage` guard routed c_linkage protos to the C++
/// branch, so e.g. a Win32 API in windows.h's `extern "C"` block (`CharToOemA`)
/// mangled `@CharToOemA$qpcpc` instead of the plain import name. Here a caller
/// references `extern "C" int twice(int)` and links against a plain `twice`
/// definer ⇒ 42. (A C-linkage function gets no C++ mangling.)
#[test]
fn extern_c_primitive_function_links_plain_across_tu() {
    let caller_src = b"extern \"C\" { int twice(int x); }\n\
                       int main(void) { return twice(21); }\n";
    let definer_src = b"extern \"C\" int twice(int x) { return x + x; }\n";
    let resolver = default_resolver();
    let caller =
        compile_to_object_with(caller_src, "extc_caller.cpp", &resolver).expect("compile caller");
    let definer = compile_to_object_with(definer_src, "extc_definer.cpp", &resolver)
        .expect("compile definer");
    let exe = link::link(
        &[Input::Object(&caller), Input::Object(&definer)],
        &link_opts(),
    )
    .expect("link extern \"C\" function across TUs (plain `twice` both sides)");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let code = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"))
        .code()
        .expect("process returned an exit code");
    assert_eq!(
        code, 42,
        "twice(21) ⇒ 42 (extern \"C\" linked as plain `twice`)"
    );
}
