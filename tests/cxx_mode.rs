//! S4.2-pre: dialect selection by source extension. A `.cpp`/`.cc`/`.cxx`/`.C`
//! translation unit preprocesses with `__cplusplus` defined (so the C++-only
//! Borland headers — which guard with `#error Must use C++ for …` — compile);
//! a `.c` source, and the extension-less `"<input>"` name used by every
//! byte-identity fixture, stays C mode. Verified as a COMPILE differential
//! (no run needed): the same `#error`-guarded TU compiles as `.cpp` and is
//! rejected as `.c`.

use mdbcc::codegen::target::TargetKind;
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::pp::DefaultResolver;
use std::path::PathBuf;

fn resolver() -> DefaultResolver {
    DefaultResolver {
        base_dir: PathBuf::from("."),
    }
}

/// A TU that compiles ONLY in C++ mode (it `#error`s when `__cplusplus` is
/// undefined — exactly how CSTRING.H / the OWL headers gate themselves).
const NEEDS_CXX: &str = "#ifndef __cplusplus\n#error needs C++\n#endif\nint main(){ return 0; }";

#[test]
fn cpp_extension_enables_cplusplus_mode() {
    let r = resolver();
    // `.cpp` ⇒ C++ mode ⇒ `__cplusplus` defined ⇒ the #error does not fire.
    assert!(
        compile_to_object_with_target(NEEDS_CXX.as_bytes(), "t.cpp", &r, TargetKind::Win64).is_ok(),
        "a .cpp TU must compile in C++ mode (__cplusplus defined)"
    );
    // `.C` (uppercase) is also C++ to Borland.
    assert!(
        compile_to_object_with_target(NEEDS_CXX.as_bytes(), "T.C", &r, TargetKind::Win64).is_ok(),
        "a .C (uppercase) TU must compile in C++ mode"
    );
}

#[test]
fn c_extension_stays_c_mode() {
    let r = resolver();
    // `.c` ⇒ C mode ⇒ `__cplusplus` undefined ⇒ the #error fires (rejected).
    assert!(
        compile_to_object_with_target(NEEDS_CXX.as_bytes(), "t.c", &r, TargetKind::Win64).is_err(),
        "a .c TU must stay C mode (__cplusplus undefined) — the #error must fire"
    );
}

#[test]
fn extensionless_input_stays_c_mode() {
    // The in-process byte-identity fixtures compile under `"<input>"`; that
    // name MUST remain C mode so the 88 x64 SipHash baselines are unchanged.
    let r = resolver();
    assert!(
        compile_to_object_with_target(NEEDS_CXX.as_bytes(), "<input>", &r, TargetKind::Win64)
            .is_err(),
        "the extension-less '<input>' name must stay C mode (byte-identity)"
    );
}

#[test]
fn cxx_mode_is_classified_by_extension() {
    use mdbcc::compile::is_cxx_source;
    assert!(is_cxx_source("a.cpp"));
    assert!(is_cxx_source("a.cc"));
    assert!(is_cxx_source("a.cxx"));
    assert!(is_cxx_source("DIR\\Mixed.Cpp")); // case-insensitive for the lower set
    assert!(is_cxx_source("a.C")); // uppercase .C is C++
    assert!(!is_cxx_source("a.c"));
    assert!(!is_cxx_source("a.h"));
    assert!(!is_cxx_source("<input>"));
    assert!(!is_cxx_source("main"));
}
