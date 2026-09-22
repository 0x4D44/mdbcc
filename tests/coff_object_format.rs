//! S1b.2 — round-trip and format-conformance tests for `mdbcc::coff`.
//!
//! Per the HLD §4.3 plan: a hand-rolled decoder is part of the public
//! crate (mdlink will consume it in S1c), so the round-trip checks are
//! structural — encode an `Object`, decode it back, compare. We do NOT
//! diff raw bytes between two `Object`s (the encoder is allowed to
//! invent strtab interning, etc.); we diff the decoded IR.
//!
//! The final test (`validate_with_lld_link`) is the format-conformance
//! gate (HLD §4.2 "Half B"): it self-skips when `lld-link` is absent,
//! so the suite stays green on stripped-down environments. When
//! present, it byte-emits a tiny `main` returning 42, hands the bytes
//! to lld-link, runs the resulting exe, and asserts exit 42.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff::{
    AuxRecord, Comdat, ComdatSelect, Machine, Object, Reloc, RelocKind, Section, SectionName,
    SectionRef, StorageClass, StringTable, SymKind, SymName, Symbol,
};
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::pp::DefaultResolver;

// ---------------------------------------------------------------------------
// Round-trip helper
// ---------------------------------------------------------------------------

/// Encode, decode, and assert structural equality on the round-trip.
/// We compare every IR field that the on-disk format preserves; the
/// strtab body is asserted equal modulo set membership (the order in
/// which names land inside the body depends on encode-time interning).
fn assert_roundtrip(obj: &Object) -> Object {
    let bytes = obj.write();
    let back = Object::read(&bytes).expect("decode succeeds");
    assert_eq!(back.machine, obj.machine, "machine");
    assert_eq!(back.directives, obj.directives, "directives");
    assert_eq!(back.sections.len(), obj.sections.len(), "section count");
    for (i, (a, b)) in obj.sections.iter().zip(&back.sections).enumerate() {
        assert_eq!(a.name.render(), b.name.render(), "section[{i}] name");
        assert_eq!(a.data, b.data, "section[{i}] data");
        assert_eq!(a.bss_size, b.bss_size, "section[{i}] bss_size");
        assert_eq!(
            a.characteristics, b.characteristics,
            "section[{i}] characteristics"
        );
        assert_eq!(a.relocs, b.relocs, "section[{i}] relocs");
        assert_eq!(a.comdat, b.comdat, "section[{i}] comdat");
    }
    assert_eq!(back.symbols.len(), obj.symbols.len(), "symbol count");
    for (i, (a, b)) in obj.symbols.iter().zip(&back.symbols).enumerate() {
        // Symbol name: compare the resolved string (Short vs Long
        // distinction is internal — the round-trip's contract is that
        // the *name* survives, not its encoding choice).
        let a_name = resolve_name(&a.name, &obj.strtab);
        let b_name = resolve_name(&b.name, &back.strtab);
        assert_eq!(a_name, b_name, "symbol[{i}] name");
        assert_eq!(a.value, b.value, "symbol[{i}] value");
        assert_eq!(a.section, b.section, "symbol[{i}] section");
        assert_eq!(a.kind, b.kind, "symbol[{i}] kind");
        assert_eq!(a.storage, b.storage, "symbol[{i}] storage");
        assert_eq!(a.aux, b.aux, "symbol[{i}] aux");
    }
    back
}

fn resolve_name(n: &SymName, st: &StringTable) -> String {
    match n {
        SymName::Short(a) => {
            let end = a.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&a[..end]).into_owned()
        }
        SymName::Long(off) => st.get_str(*off).unwrap_or("").to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests 1–8 — round-trip / encoding-invariant
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_empty_object() {
    let obj = Object::default();
    let back = assert_roundtrip(&obj);
    assert_eq!(back.sections.len(), 0);
    assert_eq!(back.symbols.len(), 0);
}

#[test]
fn roundtrip_single_function() {
    let mut obj = Object::default();
    let mut text = Section::text();
    // ret + 3 nops (4 bytes — keeps the section small and easy to eyeball).
    text.data.extend_from_slice(&[0xC3, 0x90, 0x90, 0x90]);
    obj.sections.push(text);

    // STATIC section symbol for .text (1 aux record). Section number 1.
    obj.symbols.push(Symbol {
        name: SymName::from_str(".text", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: 4,
            num_relocs: 0,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    // EXTERNAL function symbol at offset 0.
    obj.symbols.push(Symbol {
        name: SymName::from_str("_main", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });

    assert_roundtrip(&obj);
}

#[test]
fn roundtrip_function_with_call() {
    let mut obj = Object::default();
    let mut text = Section::text();
    // 16 bytes: two tiny "functions":
    //   foo: 90 C3 90 90 90 90 90 90    (offsets 0..8 — nop+ret+padding)
    //   bar: E8 ?? ?? ?? ?? C3 90 90    (offsets 8..16 — call foo + ret)
    text.data.extend_from_slice(&[
        0x90, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90,
        0x90,
    ]);
    // REL32 reloc at offset 9 (the disp32 inside the E8 call instruction
    // at byte offset 8). Points to symbol index 2 ("_foo"), so the
    // linker will fill in the rel32 to the start of foo (offset 0).
    text.relocs.push(Reloc {
        offset: 9,
        symbol: 2,
        kind: RelocKind::Rel32,
    });
    obj.sections.push(text);

    obj.symbols.push(Symbol {
        name: SymName::from_str(".text", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: 16,
            num_relocs: 1,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    obj.symbols.push(Symbol {
        name: SymName::from_str("_bar", &mut obj.strtab),
        value: 8,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    obj.symbols.push(Symbol {
        name: SymName::from_str("_foo", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });

    let back = assert_roundtrip(&obj);
    // Explicitly verify the reloc survived in user-index form.
    let reloc = &back.sections[0].relocs[0];
    assert_eq!(reloc.offset, 9);
    assert_eq!(reloc.symbol, 2);
    assert_eq!(reloc.kind, RelocKind::Rel32);
}

#[test]
fn roundtrip_data_with_pointer() {
    let mut obj = Object::default();
    let mut data = Section::data();
    // 8 bytes of u64 zero — the reloc patches in the absolute VA at
    // load time.
    data.data.extend_from_slice(&[0u8; 8]);
    // ADDR64 reloc at offset 0 against symbol 2 (the external).
    data.relocs.push(Reloc {
        offset: 0,
        symbol: 2,
        kind: RelocKind::Addr64,
    });
    obj.sections.push(data);

    obj.symbols.push(Symbol {
        name: SymName::from_str(".data", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: 8,
            num_relocs: 1,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    obj.symbols.push(Symbol {
        name: SymName::from_str("_ptr", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    obj.symbols.push(Symbol {
        name: SymName::from_str("_target", &mut obj.strtab),
        value: 0,
        section: SectionRef::Undefined,
        kind: SymKind::Notype,
        storage: StorageClass::External,
        aux: Vec::new(),
    });

    let back = assert_roundtrip(&obj);
    let reloc = &back.sections[0].relocs[0];
    assert_eq!(reloc.kind, RelocKind::Addr64);
    assert_eq!(reloc.symbol, 2);
}

#[test]
fn roundtrip_comdat_function() {
    let mut obj = Object::default();
    // COMDAT .text$Foo section, Selection::Any. Two bytes of code.
    // Per the COFF spec, a COMDAT section MUST have IMAGE_SCN_LNK_COMDAT
    // set; the encoder ORs it on whenever `comdat` is Some, so we set
    // it here too to keep the round-trip strictly equal.
    const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
    let mut comdat_sec = Section::text();
    comdat_sec.name = SectionName::TextComdat("Foo".to_string());
    comdat_sec.data.extend_from_slice(&[0xC3, 0x90]);
    comdat_sec.characteristics |= IMAGE_SCN_LNK_COMDAT;
    comdat_sec.comdat = Some(Comdat {
        selection: ComdatSelect::Any,
        associated_section: 0,
    });
    obj.sections.push(comdat_sec);

    // Leader STATIC section symbol carrying the selection in aux.
    obj.symbols.push(Symbol {
        name: SymName::from_str(".text$Foo", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: 2,
            num_relocs: 0,
            checksum: 0,
            number: 0,
            selection: Some(ComdatSelect::Any),
        }],
    });
    // EXTERNAL "real" symbol at offset 0.
    obj.symbols.push(Symbol {
        name: SymName::from_str("_Foo_method", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });

    let back = assert_roundtrip(&obj);
    let comdat = back.sections[0].comdat.as_ref().expect("comdat preserved");
    assert_eq!(comdat.selection, ComdatSelect::Any);
}

#[test]
fn roundtrip_long_symbol_name() {
    // 30 chars — well past the 8-byte inline slot.
    let long_name = "A_30_character_mangled_sym_abc";
    assert_eq!(long_name.len(), 30);

    let mut obj = Object::default();
    obj.sections.push(Section::text());
    obj.symbols.push(Symbol {
        name: SymName::from_str(".text", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: 0,
            num_relocs: 0,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    let sym_name = SymName::from_str(long_name, &mut obj.strtab);
    assert!(matches!(sym_name, SymName::Long(_)));
    obj.symbols.push(Symbol {
        name: sym_name,
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });

    let back = assert_roundtrip(&obj);
    let resolved = resolve_name(&back.symbols[1].name, &back.strtab);
    assert_eq!(resolved, long_name);
}

#[test]
fn symbol_dedup_via_strtab() {
    // Three names — two identical. intern returns the same offset for
    // the duplicate; encoded bytes contain the unique name only once.
    let mut st = StringTable::new();
    let a = st.intern("really_long_name_one");
    let b = st.intern("really_long_name_two");
    let c = st.intern("really_long_name_one");
    assert_eq!(a, c, "duplicate intern must return same offset");
    assert_ne!(a, b);

    let body = &st.finalize()[4..]; // skip the size prefix
    // Count occurrences of the unique-1 needle — must be exactly one.
    let count_one = body
        .windows(b"really_long_name_one".len())
        .filter(|w| *w == b"really_long_name_one")
        .count();
    let count_two = body
        .windows(b"really_long_name_two".len())
        .filter(|w| *w == b"really_long_name_two")
        .count();
    assert_eq!(count_one, 1, "deduped name appears once");
    assert_eq!(count_two, 1, "unique name appears once");
}

#[test]
fn section_alignment_characteristics() {
    // The Section::text / ::data / ::pdata convenience constructors
    // must each set the documented ALIGN_* bits.
    let text = Section::text();
    let data = Section::data();
    let rdata = Section::rdata();
    let pdata = Section::pdata();
    let xdata = Section::xdata();
    let bss = Section::bss(64);
    // ALIGN_* mask from PE/COFF spec: bits 20–23 carry the alignment
    // code; 0x0050_0000 = ALIGN_16, 0x0040_0000 = ALIGN_8, etc.
    const ALIGN_MASK: u32 = 0x00F0_0000;
    const ALIGN_16: u32 = 0x0050_0000;
    const ALIGN_8: u32 = 0x0040_0000;
    const ALIGN_4: u32 = 0x0030_0000;
    assert_eq!(text.characteristics & ALIGN_MASK, ALIGN_16, ".text 16-byte");
    assert_eq!(data.characteristics & ALIGN_MASK, ALIGN_8, ".data 8-byte");
    assert_eq!(rdata.characteristics & ALIGN_MASK, ALIGN_8, ".rdata 8-byte");
    assert_eq!(pdata.characteristics & ALIGN_MASK, ALIGN_4, ".pdata 4-byte");
    assert_eq!(xdata.characteristics & ALIGN_MASK, ALIGN_4, ".xdata 4-byte");
    assert_eq!(bss.characteristics & ALIGN_MASK, ALIGN_8, ".bss 8-byte");
}

#[test]
fn amd64_object_omits_unwind_rows_for_secondary_vtable_thunks() {
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
            return p2->g(); \
          } catch(...) { return 1; } }\n";
    let resolver = DefaultResolver {
        base_dir: PathBuf::from("."),
    };
    let obj =
        compile_to_object_with_target(src.as_bytes(), "main.cpp", &resolver, TargetKind::Win64)
            .expect("compile AMD64 object");
    assert_eq!(obj.machine, Machine::Amd64);
    let thunk_count = obj
        .symbols
        .iter()
        .filter(|s| resolve_name(&s.name, &obj.strtab).starts_with("$thunk$"))
        .count();
    assert!(
        thunk_count > 0,
        "test must exercise secondary-vtable thunks"
    );
    let defined_fn_count = obj
        .symbols
        .iter()
        .filter(|s| s.kind == SymKind::Function && matches!(s.section, SectionRef::Section(_)))
        .count();
    let pdata = obj
        .sections
        .iter()
        .find(|s| s.name.render() == ".pdata")
        .expect("try block should emit .pdata");
    assert!(
        pdata.data.len() < defined_fn_count * 12,
        "leaf thunk functions should not get RUNTIME_FUNCTION rows"
    );
    Object::read(&obj.write()).expect("encoded object decodes");
}

#[test]
fn amd64_eax_pseudovar_compiles_as_entry_rax() {
    let src = "\
        struct TWindow { \
          int value; \
          int ReceiveMessage(unsigned msg, unsigned long wParam, long lParam) { \
            return value + (int)msg + (int)wParam + (int)lParam; \
          } \
        };\n\
        int StdWndProc(void* hwnd, unsigned msg, unsigned long wParam, long lParam) { \
          return ((TWindow*)_EAX)->ReceiveMessage(msg, wParam, lParam); \
        }\n";
    let resolver = DefaultResolver {
        base_dir: PathBuf::from("."),
    };
    let obj =
        compile_to_object_with_target(src.as_bytes(), "main.cpp", &resolver, TargetKind::Win64)
            .expect("compile AMD64 object with _EAX pseudo-variable");
    assert_eq!(obj.machine, Machine::Amd64);
    let text = obj
        .sections
        .iter()
        .find(|s| s.name.render() == ".text")
        .expect("object should have .text");
    assert!(
        text.data.windows(3).any(|w| w == [0x48, 0x89, 0x85]),
        "_EAX should spill entry RAX with a word-width store"
    );
    Object::read(&obj.write()).expect("encoded object decodes");
}

#[test]
fn amd64_ctl3d_uses_source_built_symbol_not_legacy_import_slot() {
    let src = r#"
        extern "C" int Ctl3dRegister(void*);
        int main(void) { return Ctl3dRegister(0); }
    "#;
    let resolver = DefaultResolver {
        base_dir: PathBuf::from("."),
    };
    let obj =
        compile_to_object_with_target(src.as_bytes(), "main.cpp", &resolver, TargetKind::Win64)
            .expect("compile AMD64 object with CTL3D compatibility call");
    assert_eq!(obj.machine, Machine::Amd64);
    let undefined: Vec<String> = obj
        .symbols
        .iter()
        .filter(|s| {
            s.storage == StorageClass::External && matches!(s.section, SectionRef::Undefined)
        })
        .map(|s| resolve_name(&s.name, &obj.strtab))
        .collect();
    assert!(
        undefined.iter().any(|s| s == "Ctl3dRegister"),
        "Win64 CTL3D calls should be satisfied by source-built shims, got {undefined:?}"
    );
    assert!(
        !undefined.iter().any(|s| s == "__imp_Ctl3dRegister"),
        "Win64 CTL3D calls must not create a CTL3D32.dll import slot, got {undefined:?}"
    );
    Object::read(&obj.write()).expect("encoded object decodes");
}

// ---------------------------------------------------------------------------
// Test 9 — determinism (R16)
// ---------------------------------------------------------------------------

#[test]
fn determinism() {
    // Build a non-trivial object and serialise it 10 times. Every run
    // must produce byte-identical output, even if HashMap iteration
    // order varies (which it does, run-to-run, by design in Rust).
    let mut obj = Object::default();
    let mut text = Section::text();
    text.data.extend_from_slice(&[0xC3, 0x90, 0x90, 0x90]);
    text.relocs.push(Reloc {
        offset: 0,
        symbol: 1,
        kind: RelocKind::Rel32,
    });
    obj.sections.push(text);
    let mut data = Section::data();
    data.data.extend_from_slice(&[0u8; 16]);
    data.relocs.push(Reloc {
        offset: 0,
        symbol: 2,
        kind: RelocKind::Addr64,
    });
    obj.sections.push(data);

    obj.symbols.push(Symbol {
        name: SymName::from_str(".text", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: 4,
            num_relocs: 1,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    // Many long names exercise the strtab interning path — the prime
    // candidate for HashMap-iteration nondeterminism.
    for i in 0..16 {
        obj.symbols.push(Symbol {
            name: SymName::from_str(&format!("_symbol_with_a_long_name_{i}"), &mut obj.strtab),
            value: 0,
            section: SectionRef::Undefined,
            kind: SymKind::Notype,
            storage: StorageClass::External,
            aux: Vec::new(),
        });
    }

    let baseline = obj.write();
    for run in 0..10 {
        let again = obj.write();
        assert_eq!(again, baseline, "run {run} differs from baseline");
    }
}

// ---------------------------------------------------------------------------
// Test 10 — format-conformance gate (lld-link)
// ---------------------------------------------------------------------------

/// Self-skip helper. Returns `None` if lld-link is unavailable; the
/// caller prints a "skipped:" line and returns early.
fn discover_lld_link() -> Option<PathBuf> {
    for cand in [
        PathBuf::from("lld-link.exe"),
        PathBuf::from("lld-link"),
        PathBuf::from(r"C:\Program Files\LLVM\bin\lld-link.exe"),
        PathBuf::from(r"C:\Program Files (x86)\LLVM\bin\lld-link.exe"),
    ] {
        let mut probe = Command::new(&cand);
        probe.arg("--version");
        probe
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Ok(mut child) = probe.spawn() {
            let _ = child.wait();
            return Some(cand);
        }
    }
    None
}

fn discover_kernel32_lib() -> Option<PathBuf> {
    // Probe the Windows 10/11 SDK's standard install root, walking
    // sorted descending so newer SDKs win. The SDK is not strictly
    // required to demonstrate "lld-link accepts our .obj" — but our
    // tiny main calls ExitProcess so it returns the right exit code,
    // which needs kernel32.Lib. If absent, the test self-skips.
    let lib_root = PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\Lib");
    if !lib_root.exists() {
        return None;
    }
    let mut versions: Vec<PathBuf> = match std::fs::read_dir(&lib_root) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(_) => return None,
    };
    versions.sort();
    versions.reverse();
    for v in versions {
        let candidate = v.join("um").join("x64").join("kernel32.Lib");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn temp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mdbcc_coff_test_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        name
    ));
    p
}

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

#[test]
fn validate_with_lld_link() {
    let lld = match discover_lld_link() {
        Some(p) => p,
        None => {
            eprintln!("[coff_object_format] skipped: lld-link not on PATH or LLVM install");
            return;
        }
    };
    let kernel32 = match discover_kernel32_lib() {
        Some(p) => p,
        None => {
            eprintln!("[coff_object_format] skipped: kernel32.Lib not found in Win10 SDK");
            return;
        }
    };

    // The simplest x64 program that exits with a specific code via
    // ExitProcess (the loader does not propagate `ret` from `main`
    // when we bypass the CRT). Codegen:
    //
    //   sub    rsp, 0x28       ; 48 83 EC 28  (32-byte shadow + 8 align)
    //   mov    ecx, 42         ; B9 2A 00 00 00
    //   call   [rip+0]         ; FF 15 ?? ?? ?? ??   (rel32 patched by linker)
    //   int3                   ; CC  (safety: never reached)
    //
    // The `sub rsp, 0x28` is mandatory: Win64 ABI requires RSP be
    // 16-byte aligned at the *call* instruction (i.e. ABI guarantees
    // 16-byte alignment of RSP+8 inside the callee). The loader gives
    // us RSP%16==0 on entry, so after the implicit return address push
    // it would be 16-misaligned — `sub rsp, 0x28` (40 bytes) realigns
    // and reserves the 32-byte shadow space callees can spill into.
    //
    // The call goes through the IAT slot for ExitProcess. lld-link
    // resolves an `__imp_ExitProcess` UNDEFINED EXTERNAL to that IAT
    // slot automatically (`__imp_<sym>` is the documented convention).
    let mut obj = Object::default();
    let mut text = Section::text();
    text.data.extend_from_slice(&[
        0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
        0xB9, 0x2A, 0x00, 0x00, 0x00, // mov ecx, 42
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call [rip+0]
        0xCC, // int3
    ]);
    // REL32 reloc on the disp32 inside the `call [rip+disp32]`.
    // The disp32 sits at offset 11 (after sub-rsp[4] + mov-ecx[5] +
    // FF 15 [2]).
    text.relocs.push(Reloc {
        offset: 11,
        symbol: 2, // __imp_ExitProcess (added below at index 2)
        kind: RelocKind::Rel32,
    });
    obj.sections.push(text);

    // Symbol 0 — STATIC .text section symbol.
    obj.symbols.push(Symbol {
        name: SymName::from_str(".text", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: 16,
            num_relocs: 1,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    // Symbol 1 — EXTERNAL "main" at offset 0.
    obj.symbols.push(Symbol {
        name: SymName::from_str("main", &mut obj.strtab),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    // Symbol 2 — UNDEFINED EXTERNAL __imp_ExitProcess.
    obj.symbols.push(Symbol {
        name: SymName::from_str("__imp_ExitProcess", &mut obj.strtab),
        value: 0,
        section: SectionRef::Undefined,
        kind: SymKind::Notype,
        storage: StorageClass::External,
        aux: Vec::new(),
    });

    let obj_bytes = obj.write();
    let obj_path = temp_path("main.obj");
    let exe_path = temp_path("main.exe");
    if std::fs::write(&obj_path, &obj_bytes).is_err() {
        eprintln!("[coff_object_format] skipped: could not write temp .obj");
        return;
    }

    let mut cmd = Command::new(&lld);
    cmd.arg("/subsystem:console")
        .arg("/entry:main")
        .arg(format!("/out:{}", exe_path.display()))
        .arg(&obj_path)
        .arg(&kernel32);
    let (exit, stdout, stderr) = run_with_timeout(&mut cmd, Duration::from_secs(30));
    if exit != Some(0) {
        // Don't panic in a CI-skip-friendly way: print the failure
        // details and let the developer debug. The diagnostic is the
        // important part — a panic on link failure is the right
        // behaviour because it indicates a real COFF bug in our
        // encoder.
        let _ = std::fs::remove_file(&obj_path);
        let _ = std::fs::remove_file(&exe_path);
        panic!(
            "lld-link failed: exit={exit:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
    }

    // Run the produced exe. Skip if exec fails for environment reasons
    // (e.g. Windows Defender quarantine of a temp .exe — rare but real).
    let mut run = Command::new(&exe_path);
    let (run_exit, _, _) = run_with_timeout(&mut run, Duration::from_secs(5));
    let _ = std::fs::remove_file(&obj_path);
    let _ = std::fs::remove_file(&exe_path);
    match run_exit {
        Some(42) => { /* success */ }
        Some(other) => panic!("exe ran but exit code = {other} (expected 42)"),
        None => panic!("exe did not produce an exit code (env issue or crash)"),
    }
}
