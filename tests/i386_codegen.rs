//! S2b.2 — real codegen emits i386 machine code for the Win32 target.
//!
//! These are object-level. They prove that
//! `compile_to_object_with_target(.., Win32)` tags the COFF object
//! `IMAGE_FILE_MACHINE_I386` and emits an x86-shaped `.text` (no REX prefix,
//! x86 prologue / epilogue), while the default Win64 path stays byte-for-byte
//! on its historical x64 shape (the divergence test below pins both).

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff::Machine;
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::pp::DefaultResolver;

fn resolver() -> DefaultResolver {
    DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    }
}

fn text_of(obj: &mdbcc::coff::Object) -> Vec<u8> {
    obj.sections
        .iter()
        .find(|s| s.name.as_str() == ".text")
        .expect(".text section present")
        .data
        .clone()
}

/// `int main(void){ return 42; }` compiled for Win32 → an i386 object whose
/// `.text` is x86-shaped (push ebp / mov ebp,esp / sub esp,imm — no REX) and
/// carries the `mov eax, 42` return and `leave; ret` epilogue.
#[test]
fn i386_main_returns_constant_is_x86_shaped() {
    let src = b"int main(void){ return 42; }";
    let obj = compile_to_object_with_target(src, "main.c", &resolver(), TargetKind::Win32)
        .expect("compile i386 object");

    assert_eq!(obj.machine, Machine::I386, "COFF machine must be i386");

    let text = text_of(&obj);
    // x86 prologue: push ebp (55); mov ebp,esp (89 E5); sub esp,imm32 (81 EC ..).
    assert_eq!(
        &text[..5],
        &[0x55, 0x89, 0xE5, 0x81, 0xEC],
        "expected x86 prologue, got {text:02x?}"
    );
    // No x64 prologue (push rbp / mov rbp,rsp with REX.W = 48 89 E5).
    assert!(
        !contains(&text, &[0x48, 0x89, 0xE5]),
        "i386 .text must not contain the REX.W x64 prologue"
    );
    // The return value: mov eax, 42 = B8 2A 00 00 00.
    assert!(
        contains(&text, &[0xB8, 0x2A, 0x00, 0x00, 0x00]),
        "expected `mov eax, 42`, got {text:02x?}"
    );
    // Epilogue: leave; ret = C9 C3.
    assert!(
        contains(&text, &[0xC9, 0xC3]),
        "expected `leave; ret`, got {text:02x?}"
    );

    // The function symbol is still the bare `main` (Borland C decoration
    // `_main` is S2b.6; mdlink's CRT stub references `main` today).
    let want = {
        let mut a = [0u8; 8];
        a[..4].copy_from_slice(b"main");
        a
    };
    assert!(
        obj.symbols
            .iter()
            .any(|s| matches!(s.name, mdbcc::coff::SymName::Short(b) if b == want)),
        "expected a `main` symbol"
    );
}

/// The same source compiled for Win64 keeps its historical x64 shape:
/// machine AMD64, prologue `push rbp; mov rbp,rsp` = 55 48 89 E5. This pins
/// that the Win32 path is a genuine divergence, not a global behaviour change.
#[test]
fn win64_path_unchanged_for_same_source() {
    let src = b"int main(void){ return 42; }";
    let obj = compile_to_object_with_target(src, "main.c", &resolver(), TargetKind::Win64)
        .expect("compile x64 object");

    assert_eq!(obj.machine, Machine::Amd64);
    let text = text_of(&obj);
    assert_eq!(
        &text[..4],
        &[0x55, 0x48, 0x89, 0xE5],
        "expected x64 prologue push rbp; mov rbp,rsp"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
