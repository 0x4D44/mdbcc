//! S1c.7 — Static library (`.lib`) archive ingestion + iterative pull.
//!
//! Verifies the HLD §4 algorithm:
//! 1. An archive whose member defines `_bar` satisfies a `main` that calls
//!    `bar(...)` — link succeeds, exit code matches the C-level expectation.
//! 2. Iterative resolution: archive member `B` calls `c()`; pulling `B` in
//!    surfaces `c` as a new unresolved external; the loop continues until
//!    `C` is also pulled (or the link fails loud).
//! 3. Hand-rolled archives produced by [`mdbcc::link::archive::build_archive_bytes`]
//!    round-trip through [`mdbcc::link::archive::Archive::read`] and are
//!    consumable by the live link pipeline.
//! 4. An archive member that depends on a symbol no input defines (and
//!    that no other archive member defines) is reported via
//!    [`mdbcc::link::LinkError::UnresolvedExternals`] with the surviving
//!    name listed — the iterative pull doesn't silently swallow the
//!    failure.
//!
//! Test members are hand-crafted [`mdbcc::coff::Object`] instances
//! (same pattern as `tests/two_file_link.rs`'s `build_bar_object`) because
//! mdbcc's codegen requires every TU to define `main`, which makes
//! `compile_to_object` an awkward fit for producing "just a helper"
//! library member. The hand-crafted Objects are written to COFF bytes via
//! [`mdbcc::coff::Object::write`] and bundled into archives via
//! [`mdbcc::link::archive::build_archive_bytes`].

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::coff::{
    self, AuxRecord, Object, Reloc, RelocKind, Section, SectionRef, StorageClass, SymKind, SymName,
    Symbol,
};
use mdbcc::compile::compile_to_object_with;
use mdbcc::link::{self, Input, LinkOpts, Subsystem, archive};
use mdbcc::pp;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);

impl TempExe {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("mdbcc_archive_{}_{}.exe", std::process::id(), n));
        TempExe(p)
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("{prefix}_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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

/// Hand-craft a COFF Object that defines a leaf function `_<name>` whose
/// body is `mov eax, ecx; <op>; ret`, returning the input plus the supplied
/// constant. Win64 ABI: first integer arg in ECX, return in EAX.
fn build_leaf_fn(name: &str, plus: u8) -> Object {
    build_leaf_fn_with_storage(name, plus, StorageClass::External)
}

fn build_leaf_fn_with_storage(name: &str, plus: u8, storage: StorageClass) -> Object {
    // mov eax, ecx     ; 89 C8
    // add eax, plus    ; 83 C0 <plus>
    // ret              ; C3
    let code: Vec<u8> = vec![0x89, 0xC8, 0x83, 0xC0, plus, 0xC3];

    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };
    let text_section = Section {
        data: code.clone(),
        ..Section::text()
    };
    obj.sections.push(text_section);

    let mut sec_name = [0u8; 8];
    sec_name[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(sec_name),
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

    // Defined external for the leaf function.
    let mut sym = leaf_name_symbol(name, &mut obj.strtab);
    sym.storage = storage;
    obj.symbols.push(sym);
    obj.symbol_source_locs = vec![None; obj.symbols.len()];
    obj
}

/// Hand-craft a COFF Object that defines a zero-argument leaf function
/// returning a fixed integer. Useful for entry-point tests where the startup
/// stub owns the calling convention and the callee ignores all arguments.
fn build_const_fn(name: &str, value: u32) -> Object {
    // mov eax, imm32  ; B8 <imm32>
    // ret             ; C3
    let mut code: Vec<u8> = Vec::with_capacity(6);
    code.push(0xB8);
    code.extend_from_slice(&value.to_le_bytes());
    code.push(0xC3);

    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };
    obj.sections.push(Section {
        data: code.clone(),
        ..Section::text()
    });

    let mut sec_name = [0u8; 8];
    sec_name[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(sec_name),
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
    obj.symbols.push(leaf_name_symbol(name, &mut obj.strtab));
    obj.symbol_source_locs = vec![None; obj.symbols.len()];
    obj
}

/// Hand-craft a COFF Object that defines `_<name>` whose body is
/// `<prologue>; call <callee>; <epilogue>; return <call_result> + plus_const`.
/// The relocation against `_<callee>` is recorded as an
/// [`RelocKind::Rel32`] AMD64 PC-relative — the linker patches it during
/// Pass 4 of `write_pe_from_objects`.
///
/// Body (17 bytes):
/// ```text
///   48 83 EC 28                sub rsp, 0x28           ; shadow + 16-align
///   E8 ?? ?? ?? ??             call rel32 callee       ; reloc here (offset 5)
///   83 C0 <plus>               add eax, plus           ; eax += plus_const
///   48 83 C4 28                add rsp, 0x28
///   C3                         ret
/// ```
fn build_caller_fn(name: &str, callee: &str, plus: u8) -> Object {
    let mut code: Vec<u8> = Vec::with_capacity(17);
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
    code.push(0xE8); // call rel32
    code.extend_from_slice(&[0, 0, 0, 0]); // patched by linker
    code.extend_from_slice(&[0x83, 0xC0, plus]); // add eax, plus
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
    code.push(0xC3); // ret
    assert_eq!(code.len(), 17);

    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };

    // Build the symbol table BEFORE the section so we can record the reloc
    // by symbol index. Order:
    //   [0] .text section symbol (Static)
    //   [1] _<name> (External, defined)
    //   [2] _<callee> (External, undefined — reloc target)
    let mut sec_name = [0u8; 8];
    sec_name[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(sec_name),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: code.len() as u32,
            num_relocs: 1,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    obj.symbols.push(leaf_name_symbol(name, &mut obj.strtab));
    let callee_sym = Symbol {
        name: SymName::from_str(callee, &mut obj.strtab), // S4.2b8: plain name
        value: 0,
        section: SectionRef::Undefined,
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    };
    let callee_sym_ix = obj.symbols.len();
    obj.symbols.push(callee_sym);

    // Now the .text section with one reloc at offset 5 (the rel32 imm
    // following the 0xE8 opcode). RelocKind::Rel32 = AMD64 PC-relative.
    let text_section = Section {
        data: code,
        relocs: vec![Reloc {
            offset: 5,
            symbol: callee_sym_ix as u32,
            kind: RelocKind::Rel32,
        }],
        ..Section::text()
    };
    obj.sections.push(text_section);
    obj.symbol_source_locs = vec![None; obj.symbols.len()];
    obj
}

/// Build a Symbol carrying the underscore-prefixed name of a leaf function.
/// Names ≤ 7 chars (so `_<name>` ≤ 8) use the Short form; longer names
/// intern into the string table.
fn leaf_name_symbol(name: &str, strtab: &mut coff::StringTable) -> Symbol {
    // S4.2b8: plain source name (was `_<name>`). mdbcc references a
    // primitive-param free function by its PLAIN name now, matching the
    // definer; the hand-crafted archive members follow suit so a compiled
    // `main` calling `a(…)` resolves against the member defining `a`.
    Symbol {
        name: SymName::from_str(name, strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    }
}

/// Convenience: COFF-encode a hand-crafted Object so it can be embedded as
/// a `.lib` member.
fn obj_bytes(obj: &Object) -> Vec<u8> {
    obj.write()
}

/// W5: a leaf object defining TWO strong externals over the same `mov eax,ecx;
/// add eax,plus; ret` body — a UNIQUE name (forces the member to be pulled)
/// and a SHARED name (the duplicate). Models Borland shipping the same strong
/// symbol (e.g. `TRect::Inflate`) out-of-line in both owl.lib and bids.lib.
fn build_dup_member(uniq: &str, shared: &str, plus: u8) -> Object {
    build_dup_member_with_shared_storage(uniq, shared, plus, StorageClass::External)
}

fn build_dup_member_with_shared_storage(
    uniq: &str,
    shared: &str,
    plus: u8,
    shared_storage: StorageClass,
) -> Object {
    let code: Vec<u8> = vec![0x89, 0xC8, 0x83, 0xC0, plus, 0xC3];
    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };
    obj.sections.push(Section {
        data: code.clone(),
        ..Section::text()
    });
    let mut sec_name = [0u8; 8];
    sec_name[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(sec_name),
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
    obj.symbols.push(leaf_name_symbol(uniq, &mut obj.strtab));
    let mut shared_sym = leaf_name_symbol(shared, &mut obj.strtab);
    shared_sym.storage = shared_storage;
    obj.symbols.push(shared_sym);
    obj.symbol_source_locs = vec![None; obj.symbols.len()];
    obj
}

/// W5 dead-strip: one archive member object holding TWO functions —
/// `live_name` (`mov eax,ecx; add eax,plus; ret`, offset 0) and `dead_name`
/// (`sub rsp; call <missing>; add rsp; ret`, offset 6) that references the
/// UNDEFINED external `missing`. When an explicit object calls only `live_name`,
/// the member is pulled but `dead_name` is unreachable — linker GC must drop its
/// `missing` reference so the link succeeds. Models OWL `APPLICAT.o`'s live
/// `TApplication` ctor co-located with dead doc-manager methods that reference
/// the never-compiled `TDocManager`.
fn build_live_and_dead_member(live_name: &str, dead_name: &str, missing: &str, plus: u8) -> Object {
    let mut code: Vec<u8> = Vec::new();
    // live @0: mov eax,ecx; add eax,plus; ret  (6 bytes)
    code.extend_from_slice(&[0x89, 0xC8, 0x83, 0xC0, plus, 0xC3]);
    // dead @6: sub rsp,0x28; call rel32 missing; add rsp,0x28; ret
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // 6..10
    code.push(0xE8); // 10
    code.extend_from_slice(&[0, 0, 0, 0]); // 11..15  (reloc site)
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // 15..19
    code.push(0xC3); // 19
    let code_len = code.len() as u32;

    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };
    let mut sec_name = [0u8; 8];
    sec_name[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(sec_name),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: code_len,
            num_relocs: 1,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    // [1] live_name @0, [2] dead_name @6 (both defined External).
    obj.symbols
        .push(leaf_name_symbol(live_name, &mut obj.strtab));
    let mut dead_sym = leaf_name_symbol(dead_name, &mut obj.strtab);
    dead_sym.value = 6;
    obj.symbols.push(dead_sym);
    // [3] missing — undefined external, referenced ONLY by dead_name.
    let missing_ix = obj.symbols.len();
    obj.symbols.push(Symbol {
        name: SymName::from_str(missing, &mut obj.strtab),
        value: 0,
        section: SectionRef::Undefined,
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    obj.sections.push(Section {
        data: code,
        relocs: vec![Reloc {
            offset: 11,
            symbol: missing_ix as u32,
            kind: RelocKind::Rel32,
        }],
        ..Section::text()
    });
    obj.symbol_source_locs = vec![None; obj.symbols.len()];
    obj
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 1. Raw archive read on a valid hand-crafted MS-format archive. Verifies
///    the [`archive::Archive::read`] reader accepts the bytes produced by
///    [`archive::build_archive_bytes`] and surfaces the expected member
///    names and symbol index.
#[test]
fn archive_read_msvc_format() {
    let helper = build_leaf_fn("helper", 5);
    let helper_bytes = obj_bytes(&helper);
    let other = build_leaf_fn("other", 9);
    let other_bytes = obj_bytes(&other);

    let members = vec![
        ("helper.obj".to_string(), helper_bytes.clone()),
        ("other.obj".to_string(), other_bytes.clone()),
    ];
    let syms = vec![vec!["_helper".to_string()], vec!["_other".to_string()]];
    let ar_bytes = archive::build_archive_bytes(&members, &syms);

    let ar = archive::Archive::read(&ar_bytes).expect("Archive::read");
    assert_eq!(ar.member_count(), 2);
    assert_eq!(ar.member_name(0), "helper.obj");
    assert_eq!(ar.member_name(1), "other.obj");
    assert_eq!(ar.find_member_for_symbol("_helper"), Some(0));
    assert_eq!(ar.find_member_for_symbol("_other"), Some(1));
    assert_eq!(ar.find_member_for_symbol("_missing"), None);
    // The embedded bytes are bit-exact COFF Objects.
    assert_eq!(ar.member_bytes(0), helper_bytes.as_slice());
    assert_eq!(ar.member_bytes(1), other_bytes.as_slice());
    assert_eq!(ar.detect_member_format(0), archive::MemberFormat::CoffAmd64);
    assert_eq!(ar.detect_member_format(1), archive::MemberFormat::CoffAmd64);
}

/// W6 (railc self-host): mdar must not let an earlier weak inline wrapper
/// hide a later strong out-of-line RTL body in the archive index. Weak-only
/// symbols still need indexing, but weak->strong collisions promote to the
/// strong member.
#[test]
fn mdar_archive_index_prefers_strong_over_earlier_weak() {
    let tmp = TempDir::new("mdbcc_mdar_weak_strong");
    let weak_path = tmp.0.join("weak.obj");
    let strong_path = tmp.0.join("strong.obj");
    let lib_path = tmp.0.join("out.lib");

    let weak = build_leaf_fn_with_storage("shared", 1, StorageClass::WeakExternal);
    let strong = build_leaf_fn_with_storage("shared", 42, StorageClass::External);
    std::fs::write(&weak_path, obj_bytes(&weak)).expect("write weak obj");
    std::fs::write(&strong_path, obj_bytes(&strong)).expect("write strong obj");

    let status = Command::new(env!("CARGO_BIN_EXE_mdar"))
        .arg("-o")
        .arg(&lib_path)
        .arg(&weak_path)
        .arg(&strong_path)
        .status()
        .unwrap_or_else(|e| panic!("launch mdar: {e}"));
    assert!(status.success(), "mdar failed with status {status}");

    let bytes = std::fs::read(&lib_path).expect("read mdar output");
    let ar = archive::Archive::read(&bytes).expect("Archive::read");
    assert_eq!(ar.member_count(), 2);
    assert_eq!(
        ar.find_member_for_symbol("shared"),
        Some(1),
        "archive index must point at strong.obj, not the earlier weak.obj"
    );
}

/// The linker-emitted GUI startup stub calls `WinMain`, but that reference is
/// synthesized after archive scanning. An OWL `OwlMain` program relies on
/// `mdowl.lib(WINMAIN.o)` supplying `WinMain`, so the archive scan must treat
/// the eventual PE entry symbol as a root even when no input object has an
/// explicit undefined `WinMain` symbol.
#[test]
fn gui_entry_symbol_can_be_satisfied_by_archive_member() {
    let winmain_obj = build_const_fn("WinMain", 23);
    let ar_bytes = archive::build_archive_bytes(
        &[("WINMAIN.o".to_string(), obj_bytes(&winmain_obj))],
        &[vec!["WinMain".to_string()]],
    );

    let opts = LinkOpts {
        subsystem: Subsystem::Gui,
        ..LinkOpts::default()
    };
    let exe = link::link(
        &[Input::Archive {
            name: "mdowl.lib".to_string(),
            bytes: ar_bytes,
        }],
        &opts,
    )
    .expect("GUI entry WinMain should be pulled from archive");

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated GUI exe: {e}"));
    let code = status.code().expect("process returned an exit code");
    assert_eq!(code, 23);
}

/// 2. Main calls a helper that lives in an archive — link pulls the
///    defining member and the program runs to the expected exit code.
#[test]
fn archive_pull_satisfies_unresolved() {
    // main.cpp: declare bar, return bar(10).
    //   _bar(x) = x + 7  ⇒  main returns 17.
    let main_src = b"\
        int bar(int x);\n\
        int main(void) {\n\
            return bar(10);\n\
        }\n";

    let resolver = default_resolver();
    let main_obj =
        compile_to_object_with(main_src, "main.cpp", &resolver).expect("compile main.cpp");

    let bar_obj = build_leaf_fn("bar", 7);
    let bar_bytes = obj_bytes(&bar_obj);
    let ar_bytes = archive::build_archive_bytes(
        &[("bar.obj".to_string(), bar_bytes)],
        &[vec!["bar".to_string()]],
    );

    let exe = link::link(
        &[
            Input::Object(&main_obj),
            Input::Archive {
                name: "test.lib".to_string(),
                bytes: ar_bytes,
            },
        ],
        &link_opts(),
    )
    .expect("link main + archive(bar)");

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    let code = status.code().expect("process returned an exit code");
    assert_eq!(code, 17, "expected bar(10) + 7 = 17, got {code}");
}

/// W5 dead-strip (linker GC): a pulled archive member carries a LIVE function
/// (`live_helper`, reached from `main`) co-located with a DEAD function
/// (`dead_helper`) that references the undefined external `nonexistent_extern`.
/// Linker garbage-collection must recognise `dead_helper` as unreachable and
/// drop its undefined reference, so the link SUCCEEDS and the exe runs. This is
/// the unit-scale model of the railc closure root cause: pulling `APPLICAT.o`
/// for the live `TApplication` ctor must NOT demand `TDocManager` (referenced
/// only by TApplication's dead, never-called doc-manager methods). Without GC
/// the link fails on `nonexistent_extern`; with GC `live_helper(10)+7 = 17`.
#[test]
fn archive_dead_member_function_is_gc_stripped() {
    let main_src = b"\
        int live_helper(int x);\n\
        int main(void) {\n\
            return live_helper(10);\n\
        }\n";
    let resolver = default_resolver();
    let main_obj =
        compile_to_object_with(main_src, "main.cpp", &resolver).expect("compile main.cpp");

    let member = build_live_and_dead_member("live_helper", "dead_helper", "nonexistent_extern", 7);
    let member_bytes = obj_bytes(&member);
    let ar_bytes = archive::build_archive_bytes(
        &[("helpers.obj".to_string(), member_bytes)],
        &[vec!["live_helper".to_string(), "dead_helper".to_string()]],
    );

    let exe = link::link(
        &[
            Input::Object(&main_obj),
            Input::Archive {
                name: "helpers.lib".to_string(),
                bytes: ar_bytes,
            },
        ],
        &link_opts(),
    )
    .expect("link must SUCCEED — dead_helper's undefined ref is GC-stripped");

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    let code = status.code().expect("process returned an exit code");
    assert_eq!(code, 17, "expected live_helper(10) + 7 = 17, got {code}");
}

/// 3. Iterative pull: main calls A; A is an in-archive member that calls B;
///    B is an in-archive member that calls C; C is also in the archive. The
///    link must pull A, then B, then C as each member surfaces a new
///    unresolved external.
#[test]
fn archive_iterative_pull() {
    // main calls a(0); _a(x) calls _b(x); _b(x) calls _c(x); _c(x) = x + 42.
    // Each caller adds 1 to the callee's return, so:
    //   c(0) = 42
    //   b(0) = c(0) + 1 = 43
    //   a(0) = b(0) + 2 = 45
    //   main → return a(0) = 45
    //
    // Why "+2" for `a` and "+1" for `b`: we use the `plus_const` parameter
    // of `build_caller_fn` to distinguish each level's contribution so a
    // miscompile (e.g. pulling C before B is decoded) would surface as a
    // wrong exit code, not just "the program crashed".
    let main_src = b"\
        int a(int x);\n\
        int main(void) {\n\
            return a(0);\n\
        }\n";
    let resolver = default_resolver();
    let main_obj =
        compile_to_object_with(main_src, "main.cpp", &resolver).expect("compile main.cpp");

    let a_obj = build_caller_fn("a", "b", 2);
    let b_obj = build_caller_fn("b", "c", 1);
    let c_obj = build_leaf_fn("c", 42);

    let members = vec![
        ("a.obj".to_string(), obj_bytes(&a_obj)),
        ("b.obj".to_string(), obj_bytes(&b_obj)),
        ("c.obj".to_string(), obj_bytes(&c_obj)),
    ];
    let syms = vec![
        vec!["a".to_string()],
        vec!["b".to_string()],
        vec!["c".to_string()],
    ];
    let ar_bytes = archive::build_archive_bytes(&members, &syms);

    let exe = link::link(
        &[
            Input::Object(&main_obj),
            Input::Archive {
                name: "chain.lib".to_string(),
                bytes: ar_bytes,
            },
        ],
        &link_opts(),
    )
    .expect("link main + archive(a→b→c)");

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    let code = status.code().expect("process returned an exit code");
    assert_eq!(
        code, 45,
        "iterative pull expected exit 45 (c(0)=42 + 1 (b) + 2 (a)), got {code}"
    );
}

/// Milestone-2 discovery aid: when requested, the linker writes the archive
/// member that satisfied each unresolved symbol. This lets the RailC harness
/// derive the OWL/ClassLib source slice from actual link behavior instead of
/// guessing from a symbol map.
#[test]
fn archive_trace_records_each_pulled_member() {
    let main_src = b"int a(int x); int main(void) { return a(0); }\n";
    let resolver = default_resolver();
    let main_obj =
        compile_to_object_with(main_src, "main.cpp", &resolver).expect("compile main.cpp");

    let a_obj = build_caller_fn("a", "b", 2);
    let b_obj = build_caller_fn("b", "c", 1);
    let c_obj = build_leaf_fn("c", 42);
    let members = vec![
        ("a.obj".to_string(), obj_bytes(&a_obj)),
        ("b.obj".to_string(), obj_bytes(&b_obj)),
        ("c.obj".to_string(), obj_bytes(&c_obj)),
    ];
    let syms = vec![
        vec!["a".to_string()],
        vec!["b".to_string()],
        vec!["c".to_string()],
    ];
    let ar_bytes = archive::build_archive_bytes(&members, &syms);
    let tmp = TempDir::new("mdbcc_archive_trace");
    let trace_path = tmp.0.join("archive_trace.tsv");
    let mut opts = link_opts();
    opts.archive_trace = Some(trace_path.clone());

    let _exe = link::link(
        &[
            Input::Object(&main_obj),
            Input::Archive {
                name: "chain.lib".to_string(),
                bytes: ar_bytes,
            },
        ],
        &opts,
    )
    .expect("link with archive trace");

    let trace = std::fs::read_to_string(&trace_path).expect("read archive trace");
    let lines: Vec<&str> = trace.lines().collect();
    assert_eq!(lines[0], "symbol\tarchive\tmember");
    assert_eq!(lines[1], "a\tchain.lib\ta.obj");
    assert_eq!(lines[2], "b\tchain.lib\tb.obj");
    assert_eq!(lines[3], "c\tchain.lib\tc.obj");
    assert_eq!(lines.len(), 4, "unexpected trace:\n{trace}");
}

/// 4. Unused members are not required for a successful link. An archive with
///    `_b`, `_c`, `_d`; main only references `_b`; the link succeeds. We
///    don't assert that `_c`/`_d` bytes are dropped from the PE (that's an
///    S8-territory refinement) — just that the unused-member case doesn't
///    fail the link.
#[test]
fn archive_unused_members_dropped() {
    let main_src = b"\
        int b(int x);\n\
        int main(void) {\n\
            return b(5);\n\
        }\n";
    let resolver = default_resolver();
    let main_obj =
        compile_to_object_with(main_src, "main.cpp", &resolver).expect("compile main.cpp");

    let b_obj = build_leaf_fn("b", 11);
    let c_obj = build_leaf_fn("c", 22);
    let d_obj = build_leaf_fn("d", 33);
    let members = vec![
        ("b.obj".to_string(), obj_bytes(&b_obj)),
        ("c.obj".to_string(), obj_bytes(&c_obj)),
        ("d.obj".to_string(), obj_bytes(&d_obj)),
    ];
    let syms = vec![
        vec!["b".to_string()],
        vec!["c".to_string()],
        vec!["d".to_string()],
    ];
    let ar_bytes = archive::build_archive_bytes(&members, &syms);

    let exe = link::link(
        &[
            Input::Object(&main_obj),
            Input::Archive {
                name: "many.lib".to_string(),
                bytes: ar_bytes,
            },
        ],
        &link_opts(),
    )
    .expect("link main + archive(b,c,d) where only b is referenced");

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    let code = status.code().expect("process returned an exit code");
    assert_eq!(code, 16, "expected b(5) = 5 + 11 = 16, got {code}");
}

/// 5. Archive member's own unresolved external surfaces in the final error.
///    `_b` (in the archive) calls `_unresolved_external` which is in nothing.
///    Pulling `_b` introduces `_unresolved_external` as a new unresolved
///    name; the loop terminates with `_unresolved_external` in the
///    [`LinkError::UnresolvedExternals`] list.
#[test]
fn archive_unresolved_after_pull_reports_error() {
    let main_src = b"\
        int b(int x);\n\
        int main(void) {\n\
            return b(1);\n\
        }\n";
    let resolver = default_resolver();
    let main_obj =
        compile_to_object_with(main_src, "main.cpp", &resolver).expect("compile main.cpp");

    // _b calls _unresolved_external (which is in NEITHER the archive nor
    // the explicit inputs).
    let b_obj = build_caller_fn("b", "unresolved_external", 3);
    let members = vec![("b.obj".to_string(), obj_bytes(&b_obj))];
    let syms = vec![vec!["b".to_string()]]; // S4.2b8: plain name (main calls `b`)
    let ar_bytes = archive::build_archive_bytes(&members, &syms);

    let err = link::link(
        &[
            Input::Object(&main_obj),
            Input::Archive {
                name: "broken.lib".to_string(),
                bytes: ar_bytes,
            },
        ],
        &link_opts(),
    )
    .expect_err("expected UnresolvedExternals after b is pulled");

    match err {
        link::LinkError::UnresolvedExternals(items) => {
            let names: Vec<&str> = items.iter().map(|(n, _)| n.as_str()).collect();
            assert!(
                names.iter().any(|n| n.contains("unresolved_external")),
                "expected '_unresolved_external' in {names:?}"
            );
        }
        other => panic!("expected UnresolvedExternals, got {other:?}"),
    }
}

/// 6. S5: ALL reloc-referenced unresolved externals are reported in ONE batch
///    — not just the first. apply_relocs_multi previously bailed at the first
///    failing reloc (`apply_one_reloc`'s `?`), masking the true closure (the
///    railc bisection oracle saw "1 unresolved" when ~430 were missing). This
///    builds an object whose body calls TWO distinct undefined externals and
///    asserts BOTH surface.
#[test]
fn unresolved_externals_reported_in_one_batch() {
    // sub rsp,0x28 ; call missing_one ; call missing_two ; add rsp,0x28 ; ret
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // 0: sub rsp,0x28
    code.push(0xE8); // 4: call rel32 -> reloc imm @ 5
    code.extend_from_slice(&[0, 0, 0, 0]);
    code.push(0xE8); // 9: call rel32 -> reloc imm @ 10
    code.extend_from_slice(&[0, 0, 0, 0]);
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // 14: add rsp,0x28
    code.push(0xC3); // 18: ret

    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };
    let mut sec_name = [0u8; 8];
    sec_name[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(sec_name),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: code.len() as u32,
            num_relocs: 2,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    obj.symbols
        .push(leaf_name_symbol("twocaller", &mut obj.strtab));
    let one_ix = obj.symbols.len();
    obj.symbols.push(Symbol {
        name: SymName::from_str("missing_one", &mut obj.strtab),
        value: 0,
        section: SectionRef::Undefined,
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    let two_ix = obj.symbols.len();
    obj.symbols.push(Symbol {
        name: SymName::from_str("missing_two", &mut obj.strtab),
        value: 0,
        section: SectionRef::Undefined,
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    obj.sections.push(Section {
        data: code,
        relocs: vec![
            Reloc {
                offset: 5,
                symbol: one_ix as u32,
                kind: RelocKind::Rel32,
            },
            Reloc {
                offset: 10,
                symbol: two_ix as u32,
                kind: RelocKind::Rel32,
            },
        ],
        ..Section::text()
    });
    obj.symbol_source_locs = vec![None; obj.symbols.len()];

    let err = link::link(&[Input::Object(&obj)], &link_opts())
        .expect_err("expected UnresolvedExternals for both missing callees");
    match err {
        link::LinkError::UnresolvedExternals(items) => {
            let names: Vec<&str> = items.iter().map(|(n, _)| n.as_str()).collect();
            assert!(
                names.iter().any(|n| n.contains("missing_one"))
                    && names.iter().any(|n| n.contains("missing_two")),
                "both unresolved externals must be reported in one batch; got {names:?}"
            );
        }
        other => panic!("expected UnresolvedExternals, got {other:?}"),
    }
}

/// W5 (library-member duplicate folding): two archives (modeling owl.lib +
/// bids.lib) each ship a member that defines the SAME strong symbol `shared`
/// out-of-line (Borland's `TRect::Inflate`), alongside a unique symbol. A
/// `main` that calls BOTH unique symbols pulls BOTH members; the strong
/// `shared` duplicate must FOLD (first archive wins, library order) rather
/// than raise DuplicateSymbol — tlink/link.exe semantics.
#[test]
fn library_member_strong_duplicate_folds() {
    // main calls uniqa(10) + uniqb(0); uniqa=x+30 ⇒ 40, uniqb=x+2 ⇒ 2 ⇒ 42.
    let main_src = b"\
        int uniqa(int x);\n\
        int uniqb(int x);\n\
        int main(void) { return uniqa(10) + uniqb(0); }\n";
    let resolver = default_resolver();
    let main_obj = compile_to_object_with(main_src, "main.cpp", &resolver).expect("compile main");

    let owl = build_dup_member("uniqa", "shared", 30);
    let bids = build_dup_member("uniqb", "shared", 2);
    let owl_lib = archive::build_archive_bytes(
        &[("owlmem.obj".to_string(), obj_bytes(&owl))],
        &[vec!["uniqa".to_string(), "shared".to_string()]],
    );
    let bids_lib = archive::build_archive_bytes(
        &[("bidsmem.obj".to_string(), obj_bytes(&bids))],
        &[vec!["uniqb".to_string(), "shared".to_string()]],
    );

    let exe = link::link(
        &[
            Input::Object(&main_obj),
            Input::Archive {
                name: "owl.lib".to_string(),
                bytes: owl_lib,
            },
            Input::Archive {
                name: "bids.lib".to_string(),
                bytes: bids_lib,
            },
        ],
        &link_opts(),
    )
    .expect("strong duplicate from two library members must FOLD, not error");

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let code = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("launch: {e}"))
        .code()
        .expect("exit code");
    assert_eq!(code, 42, "uniqa(10)=40 + uniqb(0)=2 = 42, got {code}");
}

/// W6 (railc self-host): if an archive member is pulled for one symbol and
/// also carries a weak duplicate, a later pulled strong definition of that
/// duplicate must replace it. This is the link-scale pair to the mdar index
/// promotion test above.
#[test]
fn archive_pulled_strong_definition_overrides_earlier_weak_duplicate() {
    let main_src = b"\
        int a_anchor(int x);\n\
        int zshared(int x);\n\
        int main(void) { return a_anchor(0) + zshared(0); }\n";
    let resolver = default_resolver();
    let main_obj = compile_to_object_with(main_src, "main.cpp", &resolver).expect("compile main");

    let weak =
        build_dup_member_with_shared_storage("a_anchor", "zshared", 1, StorageClass::WeakExternal);
    let strong = build_leaf_fn("zshared", 41);
    let lib = archive::build_archive_bytes(
        &[
            ("weakmem.obj".to_string(), obj_bytes(&weak)),
            ("strongmem.obj".to_string(), obj_bytes(&strong)),
        ],
        &[vec!["a_anchor".to_string()], vec!["zshared".to_string()]],
    );

    let exe = link::link(
        &[
            Input::Object(&main_obj),
            Input::Archive {
                name: "weak_then_strong.lib".to_string(),
                bytes: lib,
            },
        ],
        &link_opts(),
    )
    .expect("strong archive definition must override earlier weak duplicate");

    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let code = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("launch: {e}"))
        .code()
        .expect("exit code");
    assert_eq!(
        code, 42,
        "a_anchor(0)=1 plus strong zshared(0)=41; weak zshared would return 2"
    );
}

/// W5 (#26): the archive symbol index must advertise WEAK section-defined
/// symbols, not only plain `External` ones. mdbcc emits every vague-linkage
/// definition (out-of-line member methods, vtables, template instantiations)
/// as a WEAK section-defined symbol so cross-TU duplicates COMDAT-fold. A
/// member whose definitions are ALL weak — OWL's `EVENTHAN.o`, where
/// `TEventHandler::Find`/`Dispatch`/`SearchEntries` are weak — was left
/// UNINDEXED, so the linker (which pulls members only via the index) never
/// pulled it and the whole response-table base went unresolved. Regression
/// lock for [`archive::member_pubdefs`]: index External + WeakExternal that
/// live in a real section; exclude undefined refs (section 0) and locals.
#[test]
fn member_pubdefs_indexes_weak_section_defs_excludes_undef_and_local() {
    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };
    obj.sections.push(Section {
        data: vec![0xC3],
        ..Section::text()
    });
    let mut sec_name = [0u8; 8];
    sec_name[..5].copy_from_slice(b".text");
    // [0] .text section symbol — Static local, in-section: EXCLUDED.
    obj.symbols.push(Symbol {
        name: SymName::Short(sec_name),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: Vec::new(),
    });
    let mk = |obj: &mut Object, n: &str, sec: SectionRef, sc: StorageClass| {
        let name = SymName::from_str(n, &mut obj.strtab);
        obj.symbols.push(Symbol {
            name,
            value: 0,
            section: sec,
            kind: SymKind::Function,
            storage: sc,
            aux: Vec::new(),
        });
    };
    mk(
        &mut obj,
        "strong_def",
        SectionRef::Section(1),
        StorageClass::External,
    ); // INDEX
    mk(
        &mut obj,
        "weak_def",
        SectionRef::Section(1),
        StorageClass::WeakExternal,
    ); // INDEX (the EVENTHAN.o case)
    mk(
        &mut obj,
        "weak_undef",
        SectionRef::Undefined,
        StorageClass::WeakExternal,
    ); // exclude (a ref)
    mk(
        &mut obj,
        "strong_undef",
        SectionRef::Undefined,
        StorageClass::External,
    ); // exclude (a ref)
    obj.symbol_source_locs = vec![None; obj.symbols.len()];

    let pubdefs = archive::member_pubdefs(&obj);
    assert!(
        pubdefs.contains(&"strong_def".to_string()),
        "strong section-def must index"
    );
    assert!(
        pubdefs.contains(&"weak_def".to_string()),
        "WEAK section-def must index (the EVENTHAN.o response-table-base case)"
    );
    assert!(
        !pubdefs.contains(&"weak_undef".to_string()),
        "weak undefined ref must NOT index"
    );
    assert!(
        !pubdefs.contains(&"strong_undef".to_string()),
        "strong undefined ref must NOT index"
    );
    assert!(
        !pubdefs.iter().any(|s| s == ".text"),
        "local section symbol must NOT index"
    );
    assert_eq!(
        pubdefs.len(),
        2,
        "exactly the two section-defined externals"
    );
}

/// W5 (#26): a member function whose parameter is a function-pointer that
/// carries a record type INCOMPLETE at the in-class declaration but COMPLETE at
/// the out-of-line definition must mangle to the SAME symbol in its defining TU
/// and in every referencing TU — else the all-mdbcc link mismatches.
///
/// This is the reduced model of OWL's response-table cluster: `Find(TEventInfo&,
/// bool(*)(TResponseTableEntry<GENERIC>&, TEventInfo&) = 0)`. The decl (in the
/// class body) captured the func-ptr's inner record as `size: 0`; the
/// out-of-line def captured it `size: 16`. `complete_record_sizes` only
/// completed TOP-LEVEL records, so the redeclaration dedup saw a "second
/// overload", tallied `> 1`, and mangled the DEFINITION (`@C@find$q…`) while
/// every referencing TU (one proto ⇒ tally 1) emitted the bare `C::find` —
/// leaving the cluster unresolved. The fix recurses `complete_record_sizes`
/// into `Type::Func`/`Type::MemFn`; both sides then agree (bare `C::find`).
#[test]
fn cross_tu_member_funcptr_record_param_mangles_consistently() {
    // Fwd is FORWARD-declared (incomplete) where `find` is declared in-class,
    // then COMPLETED before the out-of-line definition — the size-mismatch trap.
    let def_src = b"\
        struct Fwd;\n\
        struct C { int find(int x, bool (*op)(Fwd&) = 0); };\n\
        struct Fwd { int a, b, c, d; };\n\
        int C::find(int x, bool (*op)(Fwd&)) { return x + 1; }\n\
        int use_it(C& c) { return c.find(5); }\n";
    let ref_src = b"\
        struct Fwd;\n\
        struct C { int find(int x, bool (*op)(Fwd&) = 0); };\n\
        int call_it(C& c) { return c.find(9); }\n";

    let resolver = default_resolver();
    let def_obj = compile_to_object_with(def_src, "def.cpp", &resolver).expect("compile def TU");
    let ref_obj = compile_to_object_with(ref_src, "ref.cpp", &resolver).expect("compile ref TU");

    let sym_named = |obj: &Object, needle: &str| -> Option<(String, bool)> {
        for s in &obj.symbols {
            let n = match &s.name {
                SymName::Short(a) => {
                    let e = a.iter().position(|&b| b == 0).unwrap_or(8);
                    String::from_utf8_lossy(&a[..e]).into_owned()
                }
                SymName::Long(off) => obj
                    .strtab
                    .get_str(*off)
                    .map(str::to_string)
                    .unwrap_or_default(),
            };
            if n.contains(needle) {
                return Some((n, matches!(s.section, SectionRef::Section(_))));
            }
        }
        None
    };

    let (def_name, def_is_def) = sym_named(&def_obj, "find").expect("def TU defines C::find");
    let (ref_name, ref_is_def) = sym_named(&ref_obj, "find").expect("ref TU references C::find");
    assert!(def_is_def, "def TU must DEFINE the symbol (in-section)");
    assert!(!ref_is_def, "ref TU must reference it (undefined)");
    assert_eq!(
        def_name, ref_name,
        "C::find must mangle identically across TUs ({def_name} != {ref_name})"
    );
    assert_eq!(
        def_name, "C::find",
        "non-overloaded member ⇒ bare source-form symbol"
    );
}

/// W5: the fold is LIBRARY-ONLY — two EXPLICIT object files defining the same
/// strong symbol still raise DuplicateSymbol (an ODR violation in the user's
/// own inputs is a real error, unchanged).
#[test]
fn explicit_object_strong_duplicate_still_errors() {
    let a = build_dup_member("ua", "clash", 1);
    let b = build_dup_member("ub", "clash", 2);
    let err = link::link(&[Input::Object(&a), Input::Object(&b)], &link_opts())
        .expect_err("two explicit objects defining 'clash' strong must conflict");
    match err {
        link::LinkError::DuplicateSymbol { name } => assert_eq!(name, "clash"),
        other => panic!("expected DuplicateSymbol, got {other:?}"),
    }
}
