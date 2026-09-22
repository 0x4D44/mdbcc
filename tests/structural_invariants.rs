//! Q6 structural invariants for compiler-emitted COFF objects.
//!
//! These checks catch corrupt objects before a runnable executable happens to
//! expose the bug: relocation targets and offsets must be in range, section
//! symbols must describe their sections, strong external definitions must be
//! unique, section alignment flags must match the section family, vtable/typeinfo
//! symbols must point at ABI-shaped `.rdata`, stack/call-frame bookkeeping must
//! stay aligned and bounded, and Win64 unwind bookkeeping must stay structurally
//! coherent.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff::{
    AuxRecord, Machine, Object, RelocKind, SectionRef, StorageClass, SymName, Symbol,
};
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::pp::DefaultResolver;

const ALIGN_MASK: u32 = 0x00F0_0000;
const ALIGN_4: u32 = 0x0030_0000;
const ALIGN_8: u32 = 0x0040_0000;
const ALIGN_16: u32 = 0x0050_0000;

struct StructuralCase {
    name: &'static str,
    target: TargetKind,
    ptr_width: usize,
    source: &'static str,
}

const WIN64_STRUCTURAL_SRC: &str = r#"
    struct Big { int a; int b; int c; int d; };
    Big make(int a, int b) {
      Big s;
      s.a = a;
      s.b = b;
      s.c = a + b;
      s.d = a * b;
      return s;
    }

    class Base {
      public:
        virtual int f(int x) { return x + 1; }
        virtual ~Base() {}
    };

    class Derived : public Base {
      public:
        virtual int f(int x) { return x + 2; }
        virtual ~Derived() {}
    };

    struct E {
      int code;
      E(int c) : code(c) {}
      virtual ~E() {}
    };

    int consume(Big b, int tail) {
      return b.a + b.b + b.c + b.d + tail;
    }

    int stackmix(int a, int b, int c, int d, int e, int f) {
      return a + b + c + d + e + f;
    }

    int main(void) {
      Derived d;
      Base* p = &d;
      try {
        throw E(40);
      } catch (E& e) {
        Big b = make(3, 5);
        return p->f(e.code) + consume(b, -41) + stackmix(1, 2, 3, 4, 5, 6) - 21;
      }
      return 7;
    }
"#;

const I386_STRUCTURAL_SRC: &str = r#"
    struct M { int v; M(int k) : v(k) {} };
    struct D : M {
      D(void) : M(40) {}
      virtual int f(void) { return v + 2; }
      virtual ~D() {}
    };

    struct P { int x; int y; };
    P make(int a) {
      P p;
      p.x = a;
      p.y = a * 2;
      return p;
    }

    int take(M& m, P p, int tail) {
      return m.v + p.x + p.y + tail;
    }

    int main(void) {
      D d;
      P p = make(3);
      return take(d, p, -7);
    }
"#;

fn structural_cases() -> Vec<StructuralCase> {
    vec![
        StructuralCase {
            name: "win64_virtual_eh_sret",
            target: TargetKind::Win64,
            ptr_width: 8,
            source: WIN64_STRUCTURAL_SRC,
        },
        StructuralCase {
            name: "i386_virtual_ref_record",
            target: TargetKind::Win32,
            ptr_width: 4,
            source: I386_STRUCTURAL_SRC,
        },
    ]
}

fn resolver() -> DefaultResolver {
    DefaultResolver {
        base_dir: PathBuf::from("."),
    }
}

fn compile_case(case: &StructuralCase) -> Object {
    compile_to_object_with_target(
        case.source.as_bytes(),
        "structural_invariants.cpp",
        &resolver(),
        case.target,
    )
    .unwrap_or_else(|err| panic!("{} compile failed: {err}", case.name))
}

fn symbol_name(obj: &Object, sym: &Symbol) -> String {
    match &sym.name {
        SymName::Short(bytes) => {
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        }
        SymName::Long(off) => obj.strtab.get_str(*off).unwrap_or("").to_string(),
    }
}

fn reloc_width(kind: RelocKind) -> usize {
    match kind {
        RelocKind::Addr64 => 8,
        RelocKind::Addr32 | RelocKind::Addr32nb | RelocKind::Rel32 | RelocKind::SecRel32 => 4,
        RelocKind::SectionIx => 2,
    }
}

fn section_index(section: SectionRef) -> Option<usize> {
    match section {
        SectionRef::Section(n) if n > 0 => Some(n as usize - 1),
        _ => None,
    }
}

fn assert_common_invariants(case: &StructuralCase, obj: &Object) {
    assert!(
        !obj.sections.is_empty(),
        "{} should emit at least one section",
        case.name
    );
    assert!(
        !obj.symbols.is_empty(),
        "{} should emit at least one symbol",
        case.name
    );

    let bytes = obj.write();
    let roundtrip = Object::read(&bytes).unwrap_or_else(|err| {
        panic!(
            "{} object must decode after write; byte len {}: {err}",
            case.name,
            bytes.len()
        )
    });
    assert_eq!(
        roundtrip.machine, obj.machine,
        "{} machine roundtrip",
        case.name
    );

    for (sym_ix, sym) in obj.symbols.iter().enumerate() {
        if let Some(sec_ix) = section_index(sym.section) {
            assert!(
                sec_ix < obj.sections.len(),
                "{} symbol[{sym_ix}] {} points at missing section {}",
                case.name,
                symbol_name(obj, sym),
                sec_ix + 1
            );
        }
    }

    for (sec_ix, sec) in obj.sections.iter().enumerate() {
        let sec_name = sec.name.render();
        for reloc in &sec.relocs {
            assert!(
                (reloc.symbol as usize) < obj.symbols.len(),
                "{} {sec_name} reloc at {} points at missing symbol {}",
                case.name,
                reloc.offset,
                reloc.symbol
            );
            let width = reloc_width(reloc.kind);
            assert!(
                reloc.offset as usize + width <= sec.data.len(),
                "{} {sec_name} reloc {:?} at {} width {} exceeds section data len {}",
                case.name,
                reloc.kind,
                reloc.offset,
                width,
                sec.data.len()
            );
            if obj.machine == Machine::I386 {
                assert_ne!(
                    reloc.kind,
                    RelocKind::Addr64,
                    "{} i386 object must not carry Addr64 relocs",
                    case.name
                );
            }
        }
        assert_section_alignment(case.name, &sec_name, sec.characteristics);
        assert_section_aux_matches(case.name, obj, sec_ix);
    }

    let mut strong_defs = BTreeMap::<String, usize>::new();
    for sym in obj.symbols.iter().filter(|sym| {
        sym.storage == StorageClass::External && matches!(sym.section, SectionRef::Section(_))
    }) {
        let name = symbol_name(obj, sym);
        let count = strong_defs.entry(name.clone()).or_insert(0);
        *count += 1;
        assert_eq!(
            *count, 1,
            "{} duplicate strong external definition: {name}",
            case.name
        );
    }
}

fn assert_section_alignment(case_name: &str, section_name: &str, characteristics: u32) {
    let expected = if section_name.starts_with(".text") {
        Some(ALIGN_16)
    } else if section_name.starts_with(".data")
        || section_name.starts_with(".bss")
        || section_name.starts_with(".rdata")
    {
        Some(ALIGN_8)
    } else if section_name.starts_with(".pdata") || section_name.starts_with(".xdata") {
        Some(ALIGN_4)
    } else {
        None
    };
    if let Some(expected) = expected {
        assert_eq!(
            characteristics & ALIGN_MASK,
            expected,
            "{case_name} {section_name} alignment flags"
        );
    }
}

fn assert_section_aux_matches(case_name: &str, obj: &Object, sec_ix: usize) {
    let sec = &obj.sections[sec_ix];
    let sec_name = sec.name.render();
    let section_number = SectionRef::Section(sec_ix as u16 + 1);
    let mut matches = obj.symbols.iter().filter(|sym| {
        sym.storage == StorageClass::Static
            && sym.section == section_number
            && symbol_name(obj, sym) == sec_name
    });
    let Some(section_sym) = matches.next() else {
        panic!("{case_name} {sec_name} missing static section symbol");
    };
    assert!(
        matches.next().is_none(),
        "{case_name} {sec_name} has duplicate static section symbols"
    );
    let Some(AuxRecord::SectionDef {
        length, num_relocs, ..
    }) = section_sym.aux.first()
    else {
        panic!("{case_name} {sec_name} section symbol missing SectionDef aux");
    };
    assert_eq!(
        *length,
        sec.data.len() as u32 + sec.bss_size,
        "{case_name} {sec_name} SectionDef length"
    );
    assert_eq!(
        *num_relocs as usize,
        sec.relocs.len(),
        "{case_name} {sec_name} SectionDef reloc count"
    );
}

fn assert_vtable_and_typeinfo_invariants(case: &StructuralCase, obj: &Object) {
    let mut vtables = Vec::new();
    let mut typeinfos = Vec::new();
    for sym in &obj.symbols {
        let name = symbol_name(obj, sym);
        if name.starts_with(".Lvtbl.") || (name.starts_with('@') && name.ends_with("@3")) {
            vtables.push((name, sym));
        } else if name.starts_with(".Lxt.") || name.starts_with("@$xt$") {
            typeinfos.push((name, sym));
        }
    }
    assert!(
        !vtables.is_empty(),
        "{} should emit vtable symbols for the structural fixture",
        case.name
    );

    for (name, sym) in vtables {
        let sec_ix = section_index(sym.section)
            .unwrap_or_else(|| panic!("{} vtable {name} is not section-defined", case.name));
        let sec = &obj.sections[sec_ix];
        assert_eq!(
            sec.name.render(),
            ".rdata",
            "{} vtable {name} should live in .rdata",
            case.name
        );
        let value = sym.value as usize;
        assert_eq!(
            value % case.ptr_width,
            0,
            "{} vtable {name} should be pointer-aligned",
            case.name
        );
        assert!(
            value >= case.ptr_width * 2,
            "{} vtable {name} should leave a two-word RTTI prefix",
            case.name
        );
        assert!(
            value + case.ptr_width <= sec.data.len(),
            "{} vtable {name} should point at at least one slot",
            case.name
        );
        assert!(
            sec.relocs
                .iter()
                .all(|reloc| reloc.offset as usize != value - case.ptr_width * 2),
            "{} vtable {name} first RTTI prefix word should be an inline this-adjust value",
            case.name
        );
    }

    for (name, sym) in typeinfos {
        let sec_ix = section_index(sym.section)
            .unwrap_or_else(|| panic!("{} typeinfo {name} is not section-defined", case.name));
        let sec = &obj.sections[sec_ix];
        assert_eq!(
            sec.name.render(),
            ".rdata",
            "{} typeinfo {name} should live in .rdata",
            case.name
        );
        let value = sym.value as usize;
        assert_eq!(value % 4, 0, "{} typeinfo {name} alignment", case.name);
        assert!(
            value + 8 <= sec.data.len(),
            "{} typeinfo {name} should cover two u32 RVA fields",
            case.name
        );
    }
}

fn assert_win64_unwind_invariants(case: &StructuralCase, obj: &Object) {
    if obj.machine != Machine::Amd64 {
        return;
    }
    let mut names = BTreeSet::new();
    for section in &obj.sections {
        names.insert(section.name.render());
    }
    assert!(
        names.contains(".pdata"),
        "{} Win64 object should emit .pdata unwind records",
        case.name
    );
    assert!(
        names.contains(".xdata"),
        "{} Win64 object should emit .xdata unwind records",
        case.name
    );
    let pdata = obj
        .sections
        .iter()
        .find(|section| section.name.render() == ".pdata")
        .expect(".pdata present");
    assert_eq!(
        pdata.data.len() % 12,
        0,
        "{} .pdata must be an array of 12-byte runtime-function records",
        case.name
    );
    assert_eq!(
        pdata.relocs.len(),
        (pdata.data.len() / 12) * 3,
        "{} each .pdata record should have begin/end/unwind-info relocs",
        case.name
    );
    let xdata = obj
        .sections
        .iter()
        .find(|section| section.name.render() == ".xdata")
        .expect(".xdata present");
    assert!(
        !xdata.data.is_empty(),
        "{} .xdata should carry unwind bytes",
        case.name
    );
}

fn text_bytes<'a>(case: &StructuralCase, obj: &'a Object) -> &'a [u8] {
    obj.sections
        .iter()
        .find(|section| section.name.render() == ".text")
        .map(|section| section.data.as_slice())
        .unwrap_or_else(|| panic!("{} missing .text section", case.name))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(slice.try_into().unwrap()))
}

fn win64_frame_allocations(text: &[u8]) -> Vec<u32> {
    let mut frames = Vec::new();
    let mut ix = 0usize;
    while ix + 11 <= text.len() {
        if text[ix..].starts_with(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC]) {
            if let Some(frame) = read_u32_le(text, ix + 7) {
                frames.push(frame);
            }
            ix += 11;
        } else {
            ix += 1;
        }
    }
    frames
}

fn win64_rsp_store_displacements(text: &[u8]) -> Vec<u32> {
    let mut disps = Vec::new();
    let mut ix = 0usize;
    while ix + 8 <= text.len() {
        if text[ix..].starts_with(&[0x48, 0x89, 0x84, 0x24]) {
            if let Some(disp) = read_u32_le(text, ix + 4) {
                disps.push(disp);
            }
            ix += 8;
        } else {
            ix += 1;
        }
    }
    disps
}

fn i386_caller_cleanups(text: &[u8]) -> Vec<u32> {
    let mut cleanups = Vec::new();
    let mut ix = 0usize;
    while ix < text.len() {
        if ix + 3 <= text.len() && text[ix..].starts_with(&[0x83, 0xC4]) {
            cleanups.push(text[ix + 2] as u32);
            ix += 3;
        } else if ix + 6 <= text.len() && text[ix..].starts_with(&[0x81, 0xC4]) {
            if let Some(bytes) = read_u32_le(text, ix + 2) {
                cleanups.push(bytes);
            }
            ix += 6;
        } else {
            ix += 1;
        }
    }
    cleanups
}

fn assert_call_frame_invariants(case: &StructuralCase, obj: &Object) {
    let text = text_bytes(case, obj);
    match obj.machine {
        Machine::Amd64 => {
            let frames = win64_frame_allocations(text);
            assert!(
                !frames.is_empty(),
                "{} Win64 object should have frame-allocation prologues",
                case.name
            );
            for frame in &frames {
                assert_eq!(
                    frame % 16,
                    0,
                    "{} Win64 frame allocation {frame} should preserve 16-byte call alignment",
                    case.name
                );
                assert!(
                    *frame >= 32,
                    "{} Win64 frame allocation {frame} should reserve caller shadow space",
                    case.name
                );
            }

            let stack_arg_disps: Vec<u32> = win64_rsp_store_displacements(text)
                .into_iter()
                .filter(|disp| *disp >= 0x20)
                .collect();
            assert!(
                stack_arg_disps.len() >= 2,
                "{} Win64 fixture should exercise at least two outgoing stack-argument stores",
                case.name
            );
            let max_frame = frames.into_iter().max().unwrap_or(0);
            for disp in stack_arg_disps {
                assert_eq!(
                    disp % 8,
                    0,
                    "{} Win64 outgoing stack slot {disp:#x} should be 8-byte aligned",
                    case.name
                );
                assert!(
                    disp + 8 <= max_frame,
                    "{} Win64 outgoing stack slot {disp:#x} exceeds max frame allocation {max_frame:#x}",
                    case.name
                );
            }
        }
        Machine::I386 => {
            let cleanups = i386_caller_cleanups(text);
            assert!(
                cleanups.iter().any(|bytes| *bytes >= 4),
                "{} i386 fixture should exercise caller stack cleanup",
                case.name
            );
            for bytes in cleanups {
                assert_eq!(
                    bytes % 4,
                    0,
                    "{} i386 caller cleanup {bytes} should be slot-aligned",
                    case.name
                );
            }
        }
    }
}

#[test]
fn generated_structural_invariants_hold_for_high_risk_objects() {
    for case in structural_cases() {
        let obj = compile_case(&case);
        assert_common_invariants(&case, &obj);
        assert_vtable_and_typeinfo_invariants(&case, &obj);
        assert_call_frame_invariants(&case, &obj);
        assert_win64_unwind_invariants(&case, &obj);
    }
}
