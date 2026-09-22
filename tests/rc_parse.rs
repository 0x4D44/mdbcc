//! G1 — `.rc` lexer/parser scaffolding tests. STRINGTABLE-only.
//!
//! In-process unit tests over [`mdbcc::rc::parse`]. No PE / .res output
//! (those are G2/G3); these tests pin down the AST shape that the
//! writer will read.

use mdbcc::rc::{Language, RcUnit, Resource, parse};

/// Extract a borrow of the (single, expected) StringTable from an
/// [`RcUnit`]. Panics with a clear message if the unit doesn't carry
/// exactly one and only one StringTable — invariant for the
/// single-block tests.
fn only_stringtable(unit: &RcUnit) -> &mdbcc::rc::StringTable {
    assert_eq!(
        unit.resources.len(),
        1,
        "expected exactly one resource, got {}",
        unit.resources.len()
    );
    match &unit.resources[0] {
        Resource::StringTable(st) => st,
        other => panic!("expected StringTable, got {:?}", other),
    }
}

#[test]
fn empty_stringtable_produces_zero_entries() {
    let unit = parse("STRINGTABLE BEGIN END").expect("parse ok");
    let st = only_stringtable(&unit);
    assert!(st.entries.is_empty());
    assert_eq!(st.language, None);
    assert_eq!(st.flags, mdbcc::rc::MemoryFlags::default());
}

#[test]
fn single_entry_with_decimal_id() {
    let unit = parse(r#"STRINGTABLE BEGIN 1 "hello" END"#).expect("parse ok");
    let st = only_stringtable(&unit);
    assert_eq!(st.entries.len(), 1);
    assert_eq!(st.entries[0].id, 1);
    assert_eq!(st.entries[0].value, "hello");
}

#[test]
fn multiple_entries_with_and_without_commas() {
    // First three entries use comma between id and value; last three
    // omit it. brc32 accepts both — so must we.
    let src = r#"
        STRINGTABLE
        BEGIN
            10, "ten"
            20, "twenty"
            30, "thirty"
            40 "forty"
            50 "fifty"
            60 "sixty"
        END
    "#;
    let unit = parse(src).expect("parse ok");
    let st = only_stringtable(&unit);
    assert_eq!(st.entries.len(), 6);
    let ids: Vec<u16> = st.entries.iter().map(|e| e.id).collect();
    assert_eq!(ids, vec![10, 20, 30, 40, 50, 60]);
    let vals: Vec<&str> = st.entries.iter().map(|e| e.value.as_str()).collect();
    assert_eq!(
        vals,
        vec!["ten", "twenty", "thirty", "forty", "fifty", "sixty"]
    );
}

#[test]
fn hex_ids_parsed() {
    let src = r#"STRINGTABLE BEGIN 0x100 "abc" 0X1FF "def" END"#;
    let unit = parse(src).expect("parse ok");
    let st = only_stringtable(&unit);
    assert_eq!(st.entries[0].id, 0x100);
    assert_eq!(st.entries[1].id, 0x1FF);
}

#[test]
fn string_escapes_decoded() {
    // \n \t \r \" \\ — each produces the canonical byte.
    let src = r#"
        STRINGTABLE BEGIN
            1 "n=\n,t=\t,r=\r,q=\",bs=\\"
        END
    "#;
    let unit = parse(src).expect("parse ok");
    let st = only_stringtable(&unit);
    assert_eq!(st.entries[0].value, "n=\n,t=\t,r=\r,q=\",bs=\\");
}

#[test]
fn hex_escape_produces_byte() {
    // \x41 = 'A'; \x48\x69 = "Hi".
    let unit = parse(r#"STRINGTABLE BEGIN 1 "\x41" 2 "\x48\x69" END"#).expect("parse ok");
    let st = only_stringtable(&unit);
    assert_eq!(st.entries[0].value, "A");
    assert_eq!(st.entries[1].value, "Hi");
}

#[test]
fn discardable_flag_recognised() {
    let unit = parse(r#"STRINGTABLE DISCARDABLE BEGIN 1 "x" END"#).expect("parse ok");
    let st = only_stringtable(&unit);
    assert!(st.flags.discardable);
    assert!(!st.flags.preload);
    assert!(!st.flags.moveable);
    assert_eq!(st.entries.len(), 1);
}

#[test]
fn multiple_flags_any_order() {
    let unit = parse(r#"STRINGTABLE PRELOAD MOVEABLE BEGIN 1 "x" END"#).expect("parse ok");
    let st = only_stringtable(&unit);
    assert!(st.flags.preload);
    assert!(st.flags.moveable);
    assert!(!st.flags.discardable);
    assert!(!st.flags.loadoncall);
    assert!(!st.flags.fixed);
}

#[test]
fn per_block_language_recorded() {
    // LANGUAGE 0x09, 0x01 → en-US, attached to the STRINGTABLE itself
    // (not file-level — it appears between STRINGTABLE and BEGIN).
    let src = r#"
        STRINGTABLE
        LANGUAGE 0x09, 0x01
        BEGIN
            1 "hi"
        END
    "#;
    let unit = parse(src).expect("parse ok");
    let st = only_stringtable(&unit);
    assert_eq!(
        st.language,
        Some(Language {
            primary: 0x09,
            sub: 0x01
        })
    );
    // File-level LANGUAGE should remain unset.
    assert_eq!(unit.language, None);
}

#[test]
fn file_level_language_recorded() {
    let src = r#"
        LANGUAGE 0x09, 0x01
        STRINGTABLE BEGIN 1 "hi" END
    "#;
    let unit = parse(src).expect("parse ok");
    assert_eq!(
        unit.language,
        Some(Language {
            primary: 0x09,
            sub: 0x01
        })
    );
    let st = only_stringtable(&unit);
    assert_eq!(st.language, None);
    assert_eq!(st.entries.len(), 1);
}

#[test]
fn case_insensitive_keywords() {
    let unit = parse(r#"stringtable begin 1 "x" end"#).expect("parse ok");
    let st = only_stringtable(&unit);
    assert_eq!(st.entries.len(), 1);
    assert_eq!(st.entries[0].value, "x");

    // Mixed case + lowercase flag.
    let unit2 = parse(r#"StringTable Discardable Begin 7 "y" End"#).expect("parse ok");
    let st2 = only_stringtable(&unit2);
    assert!(st2.flags.discardable);
    assert_eq!(st2.entries[0].id, 7);
}

#[test]
fn comments_skipped() {
    let src = r#"
        // a line comment
        /* a block
           comment */
        STRINGTABLE BEGIN
            // entry comment
            1 "a" /* trailing */
            2 /* inline */ "b"
        END
        // tail
    "#;
    let unit = parse(src).expect("parse ok");
    let st = only_stringtable(&unit);
    assert_eq!(st.entries.len(), 2);
    assert_eq!(st.entries[0].value, "a");
    assert_eq!(st.entries[1].value, "b");
}

#[test]
fn multiple_stringtable_blocks_concatenate() {
    let src = r#"
        STRINGTABLE BEGIN
            1 "first"
            2 "second"
        END
        STRINGTABLE BEGIN
            17 "bundle-2-first"
            18 "bundle-2-second"
        END
    "#;
    let unit = parse(src).expect("parse ok");
    // Two distinct Resource::StringTable entries — the writer (G2)
    // bundles them by id>>4. The parser collects them faithfully.
    assert_eq!(unit.resources.len(), 2);
    let counts: Vec<usize> = unit
        .resources
        .iter()
        .map(|r| match r {
            Resource::StringTable(st) => st.entries.len(),
            _ => 0,
        })
        .collect();
    assert_eq!(counts, vec![2, 2]);
    let ids: Vec<u16> = unit
        .resources
        .iter()
        .flat_map(|r| match r {
            Resource::StringTable(st) => st.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .collect();
    assert_eq!(ids, vec![1, 2, 17, 18]);
}

#[test]
fn missing_end_is_an_error() {
    // EOF reached inside the BEGIN…END block.
    let err = parse(r#"STRINGTABLE BEGIN 1 "no-end""#).expect_err("must fail");
    assert!(
        err.message.to_lowercase().contains("end"),
        "error should mention END; got: {}",
        err.message
    );
}

#[test]
fn entry_missing_id_is_an_error() {
    // First entry has a string where an id should be.
    let err = parse(r#"STRINGTABLE BEGIN "no-id" "x" END"#).expect_err("must fail");
    assert!(
        err.message.to_lowercase().contains("integer") || err.message.to_lowercase().contains("id"),
        "error should mention integer/id; got: {}",
        err.message
    );
}

#[test]
fn entry_missing_string_is_an_error() {
    // Two ids, no string between them.
    let err = parse(r#"STRINGTABLE BEGIN 1 2 "two" END"#).expect_err("must fail");
    assert!(
        err.message.to_lowercase().contains("string"),
        "error should mention string literal; got: {}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// G4 — MENU + ACCELERATORS parser tests
// ---------------------------------------------------------------------------

fn only_menu(unit: &RcUnit) -> &mdbcc::rc::MenuResource {
    assert_eq!(unit.resources.len(), 1);
    match &unit.resources[0] {
        Resource::Menu(m) => m,
        other => panic!("expected MENU, got {:?}", other),
    }
}

fn only_accel(unit: &RcUnit) -> &mdbcc::rc::AcceleratorTable {
    assert_eq!(unit.resources.len(), 1);
    match &unit.resources[0] {
        Resource::Accelerators(a) => a,
        other => panic!("expected ACCELERATORS, got {:?}", other),
    }
}

/// G4-P1: Simple MENU with 2 POPUPs and 3 MENUITEMs total.
#[test]
fn g4_parse_menu_two_popups_three_items() {
    use mdbcc::rc::MenuItem;
    let src = r#"
        100 MENU
        BEGIN
          POPUP "File"
          BEGIN
            MENUITEM "Open", 200
            MENUITEM "Exit", 201
          END
          POPUP "Help"
          BEGIN
            MENUITEM "About", 300
          END
        END
    "#;
    let unit = parse(src).expect("parse ok");
    let m = only_menu(&unit);
    assert_eq!(m.id, 100);
    assert_eq!(m.items.len(), 2, "two top-level POPUPs");
    match &m.items[0] {
        MenuItem::Popup { text, items, .. } => {
            assert_eq!(text, "File");
            assert_eq!(items.len(), 2);
            // First item: Open / 200
            match &items[0] {
                MenuItem::Item { text, id, .. } => {
                    assert_eq!(text, "Open");
                    assert_eq!(*id, 200);
                }
                other => panic!("expected MENUITEM Open, got {:?}", other),
            }
        }
        other => panic!("expected POPUP File, got {:?}", other),
    }
    match &m.items[1] {
        MenuItem::Popup { text, items, .. } => {
            assert_eq!(text, "Help");
            assert_eq!(items.len(), 1);
        }
        other => panic!("expected POPUP Help, got {:?}", other),
    }
}

/// G4-P2: MENU with SEPARATOR.
#[test]
fn g4_parse_menu_with_separator() {
    use mdbcc::rc::MenuItem;
    let src = r#"
        100 MENU
        BEGIN
          POPUP "File"
          BEGIN
            MENUITEM "Open", 200
            MENUITEM SEPARATOR
            MENUITEM "Exit", 201
          END
        END
    "#;
    let unit = parse(src).expect("parse ok");
    let m = only_menu(&unit);
    match &m.items[0] {
        MenuItem::Popup { items, .. } => {
            assert_eq!(items.len(), 3, "Open + SEPARATOR + Exit");
            assert!(matches!(items[1], MenuItem::Separator));
        }
        other => panic!("expected POPUP, got {:?}", other),
    }
}

/// G4-P3: ACCELERATORS with `"^O"` (Ctrl-O cooked at parse time to 0x0F).
#[test]
fn g4_parse_accel_ctrl_ascii() {
    let src = r#"
        100 ACCELERATORS
        BEGIN
          "^O", 200
        END
    "#;
    let unit = parse(src).expect("parse ok");
    let a = only_accel(&unit);
    assert_eq!(a.id, 100);
    assert_eq!(a.entries.len(), 1);
    assert_eq!(a.entries[0].key, 0x0F, "Ctrl-O cooks to 0x0F");
    assert_eq!(a.entries[0].cmd, 200);
    assert_eq!(a.entries[0].flags, 0, "no CONTROL/VIRTKEY bit for ^X form");
}

/// G4-P4: ACCELERATORS with `VIRTKEY` flag and a numeric VK code.
#[test]
fn g4_parse_accel_virtkey_numeric() {
    let src = r#"
        100 ACCELERATORS
        BEGIN
          0x70, 300, VIRTKEY
        END
    "#;
    let unit = parse(src).expect("parse ok");
    let a = only_accel(&unit);
    assert_eq!(a.entries.len(), 1);
    assert_eq!(a.entries[0].key, 0x70, "VK_F1");
    assert_eq!(a.entries[0].cmd, 300);
    assert_eq!(a.entries[0].flags, 0x01, "FACCEL_VIRTKEY");
}

/// G4-P5: ACCELERATORS with multiple flags VIRTKEY + CONTROL + SHIFT.
#[test]
fn g4_parse_accel_multiple_flags() {
    let src = r#"
        100 ACCELERATORS
        BEGIN
          "Z", 201, VIRTKEY, CONTROL, SHIFT
        END
    "#;
    let unit = parse(src).expect("parse ok");
    let a = only_accel(&unit);
    assert_eq!(a.entries.len(), 1);
    assert_eq!(a.entries[0].key, 0x5A, "'Z' upcased under VIRTKEY");
    assert_eq!(
        a.entries[0].flags,
        0x01 | 0x08 | 0x04,
        "VIRTKEY | CONTROL | SHIFT"
    );
}

/// G4-P6 (error path): MENU without END is a parse error.
#[test]
fn g4_parse_menu_missing_end_is_error() {
    let src = r#"100 MENU BEGIN POPUP "File" BEGIN MENUITEM "Exit", 200 END"#;
    let err = parse(src).expect_err("must fail (missing outer END)");
    assert!(
        err.message.to_lowercase().contains("end")
            || err.message.to_lowercase().contains("expected"),
        "error should mention END or expected; got: {}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// G5a — DIALOG parser tests
// ---------------------------------------------------------------------------

fn only_dialog(unit: &RcUnit) -> &mdbcc::rc::DialogResource {
    assert_eq!(unit.resources.len(), 1);
    match &unit.resources[0] {
        Resource::Dialog(d) => d,
        other => panic!("expected DIALOG, got {:?}", other),
    }
}

/// G5a-P1: An empty DIALOG (no controls, no statements). Verifies the
/// default style — brc32 5.40 emits 0x80880000 when no STYLE statement
/// is present.
#[test]
fn g5a_parse_dialog_empty() {
    let src = "100 DIALOG 0, 0, 100, 50\nBEGIN\nEND\n";
    let unit = parse(src).expect("parse ok");
    let d = only_dialog(&unit);
    assert_eq!(d.id, 100);
    assert_eq!((d.x, d.y, d.cx, d.cy), (0, 0, 100, 50));
    assert_eq!(d.style, mdbcc::rc::DIALOG_DEFAULT_STYLE);
    assert_eq!(d.ex_style, 0);
    assert!(d.caption.is_none());
    assert!(d.font.is_none());
    assert!(d.controls.is_empty());
}

/// G5a-P2: DIALOG with STYLE + CAPTION. Verifies that CAPTION OR's in
/// WS_CAPTION on top of the explicit STYLE.
#[test]
fn g5a_parse_dialog_style_caption() {
    let src = "\
100 DIALOG 0, 0, 100, 50
STYLE 0x80000000
CAPTION \"Test\"
BEGIN
END
";
    let unit = parse(src).expect("parse ok");
    let d = only_dialog(&unit);
    // explicit STYLE 0x80000000 | WS_CAPTION 0x00C00000 = 0x80C00000.
    assert_eq!(d.style, 0x80C0_0000);
    assert_eq!(d.caption.as_deref(), Some("Test"));
}

/// G5a-P3: DIALOG with FONT — DS_SETFONT bit set in style.
#[test]
fn g5a_parse_dialog_font() {
    let src = "\
100 DIALOG 0, 0, 100, 50
FONT 8, \"MS Sans Serif\"
BEGIN
END
";
    let unit = parse(src).expect("parse ok");
    let d = only_dialog(&unit);
    // Default style | DS_SETFONT = 0x80880040.
    assert_eq!(
        d.style,
        mdbcc::rc::DIALOG_DEFAULT_STYLE | mdbcc::rc::DS_SETFONT
    );
    assert_eq!(d.font, Some((8, "MS Sans Serif".to_string())));
}

/// G5a-P4: DIALOG with PUSHBUTTON + LTEXT controls. Verifies shorthand
/// expansion to the brc32 default style + class ordinal.
#[test]
fn g5a_parse_dialog_pushbutton_ltext() {
    use mdbcc::rc::{CC_BUTTON, CC_STATIC, ControlClass, ResRef};
    let src = "\
100 DIALOG 0, 0, 100, 50
BEGIN
  PUSHBUTTON \"OK\", 1, 10, 20, 30, 14
  LTEXT \"Hi\", 65535, 5, 5, 20, 10
END
";
    let unit = parse(src).expect("parse ok");
    let d = only_dialog(&unit);
    assert_eq!(d.controls.len(), 2);
    let pb = &d.controls[0];
    assert_eq!(pb.style, mdbcc::rc::STYLE_PUSHBUTTON);
    assert_eq!(pb.class, ControlClass::Predefined(CC_BUTTON));
    assert_eq!(pb.id, 1);
    assert_eq!(pb.text, ResRef::Name("OK".to_string()));
    assert_eq!((pb.x, pb.y, pb.cx, pb.cy), (10, 20, 30, 14));

    let lt = &d.controls[1];
    assert_eq!(lt.style, mdbcc::rc::STYLE_LTEXT);
    assert_eq!(lt.class, ControlClass::Predefined(CC_STATIC));
    assert_eq!(lt.id as u16, 0xFFFF);
    assert_eq!(lt.text, ResRef::Name("Hi".to_string()));
}

/// G5a-P5: DIALOG with the generic CONTROL form — predefined class name
/// "BUTTON" should be normalised to the ordinal at parse time.
#[test]
fn g5a_parse_dialog_generic_control() {
    use mdbcc::rc::{CC_BUTTON, ControlClass};
    let src = "\
100 DIALOG 0, 0, 100, 50
BEGIN
  CONTROL \"OK\", 1, \"BUTTON\", 0x50010000, 10, 20, 30, 14
END
";
    let unit = parse(src).expect("parse ok");
    let d = only_dialog(&unit);
    assert_eq!(d.controls.len(), 1);
    let c = &d.controls[0];
    assert_eq!(c.class, ControlClass::Predefined(CC_BUTTON));
    assert_eq!(c.style, 0x5001_0000);
}

/// G5a-P5b: CONTROL with a user-defined class — string preserved.
#[test]
fn g5a_parse_dialog_generic_user_class() {
    use mdbcc::rc::ControlClass;
    let src = "\
100 DIALOG 0, 0, 100, 50
BEGIN
  CONTROL \"OK\", 1, \"MyCustom\", 0x50010000, 10, 20, 30, 14
END
";
    let unit = parse(src).expect("parse ok");
    let d = only_dialog(&unit);
    let c = &d.controls[0];
    assert_eq!(c.class, ControlClass::UserClass("MyCustom".to_string()));
}

/// G5a-P6: DIALOG missing END is a parse error.
#[test]
fn g5a_parse_dialog_missing_end_is_error() {
    let src = "100 DIALOG 0, 0, 100, 50\nBEGIN\n  PUSHBUTTON \"OK\", 1, 0, 0, 10, 10\n";
    let err = parse(src).expect_err("must fail (missing END)");
    assert!(
        err.message.to_lowercase().contains("end")
            || err.message.to_lowercase().contains("expected"),
        "error should mention END or expected; got: {}",
        err.message
    );
}

/// G5a-P7 (G-fix-2 / MAJOR-2): DIALOGEX is REJECTED at parse time with a
/// clear diagnostic. Previously the parser accepted it and the writer
/// silently emitted classic DLGTEMPLATE bytes — see Phase G review
/// MAJOR-2. The new error message must reference "DIALOGEX" and identify
/// it as unsupported so the user knows to fall back to `DIALOG`.
#[test]
fn g5a_dialogex_is_rejected_with_clear_diagnostic() {
    let src = "100 DIALOGEX 0, 0, 100, 50\nBEGIN\nEND\n";
    let err = parse(src).expect_err("DIALOGEX must be rejected");
    assert!(
        err.message.contains("DIALOGEX is not supported"),
        "diagnostic should pinpoint DIALOGEX; got: {}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// W5 rc gap 5 — named resource IDs, style expressions, ICON shorthand
// ---------------------------------------------------------------------------

#[test]
fn g5_named_menu_and_dialog_resource_ids_parse() {
    use mdbcc::rc::ResId;

    let src = "\
MAIN_MENU MENU
BEGIN
END

ABOUTBOX DIALOG 0, 0, 100, 50
BEGIN
END
";
    let unit = parse(src).expect("parse ok");
    assert_eq!(unit.resources.len(), 2);
    match &unit.resources[0] {
        Resource::Menu(m) => assert_eq!(m.id, ResId::Name("MAIN_MENU".to_string())),
        other => panic!("expected named MENU, got {:?}", other),
    }
    match &unit.resources[1] {
        Resource::Dialog(d) => assert_eq!(d.id, ResId::Name("ABOUTBOX".to_string())),
        other => panic!("expected named DIALOG, got {:?}", other),
    }
}

#[test]
fn g5_style_exprs_and_icon_shorthand_parse() {
    use mdbcc::rc::{CC_BUTTON, CC_STATIC, ControlClass, ResRef};

    let src = "\
ABOUTBOX DIALOG 0, 0, 100, 50
STYLE DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU
BEGIN
  LTEXT \"Hi\", -1, 5, 5, 20, 10, WS_CHILD | WS_VISIBLE | WS_GROUP
  DEFPUSHBUTTON \"OK\", 1, 10, 20, 30, 14, WS_CHILD | WS_VISIBLE | WS_TABSTOP
  ICON \"AMAIN\", 2, 103, 14, 18, 20
  ICON \"md\", 3, 126, 14, 18, 20, WS_CHILD | WS_VISIBLE
  CONTROL \"Auto\", 4, \"BUTTON\", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, 0, 40, 10
END
";
    let unit = parse(src).expect("parse ok");
    let d = only_dialog(&unit);
    assert_eq!(d.style, 0x80C8_0080);
    assert_eq!(d.id, mdbcc::rc::ResId::Name("ABOUTBOX".to_string()));
    assert_eq!(d.controls.len(), 5);

    let lt = &d.controls[0];
    assert_eq!(lt.id, -1);
    assert_eq!(
        lt.style, 0x5002_0000,
        "explicit LTEXT style must not force WS_TABSTOP"
    );
    assert_eq!(lt.class, ControlClass::Predefined(CC_STATIC));

    let def = &d.controls[1];
    assert_eq!(
        def.style, 0x5001_0001,
        "explicit DEFPUSHBUTTON keeps BS_DEFPUSHBUTTON"
    );
    assert_eq!(def.class, ControlClass::Predefined(CC_BUTTON));

    let icon_default = &d.controls[2];
    assert_eq!(icon_default.text, ResRef::Name("AMAIN".to_string()));
    assert_eq!(icon_default.class, ControlClass::Predefined(CC_STATIC));
    assert_eq!(icon_default.style, 0x5000_0003);
    assert_eq!(
        (
            icon_default.x,
            icon_default.y,
            icon_default.cx,
            icon_default.cy
        ),
        (103, 14, 18, 20)
    );

    let icon_explicit = &d.controls[3];
    assert_eq!(icon_explicit.text, ResRef::Name("md".to_string()));
    assert_eq!(
        icon_explicit.style, 0x5000_0003,
        "explicit ICON style keeps SS_ICON only"
    );

    let generic = &d.controls[4];
    assert_eq!(generic.class, ControlClass::Predefined(CC_BUTTON));
    assert_eq!(generic.style, 0x5000_0003);
}

#[test]
fn g7_parse_inline_icon_bitmap_and_rcdata_resources() {
    use mdbcc::rc::ResId;

    let src = "\
APPICON ICON
BEGIN
  '00 00 01 00 01 00 20 20 10 00 00 00 00 00 10 00 00 00 16 00 00 00'
  '28 00 00 00 00 00 00 00 00 00 00 00 01 00 04 00'
END
SPLASH BITMAP
BEGIN
  '42 4D 3A 00 00 00 00 00 00 00 36 00 00 00'
  '28 00 00 00 01 00 00 00 01 00 00 00 01 00 20 00 00 00 00 00 00 00 00 00'
  '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF 00 00 00'
END
BEEP RCDATA
BEGIN
  '52 49 46 46'
END
";
    let unit = parse(src).expect("parse ok");
    assert_eq!(unit.resources.len(), 3);
    match &unit.resources[0] {
        Resource::Icon(i) => {
            assert_eq!(i.id, ResId::Name("APPICON".to_string()));
            assert_eq!(i.ordinal, 1);
            assert_eq!(i.image_data.len(), 16);
            assert_eq!(i.group_data.len(), 20);
            assert_eq!(&i.group_data[0..6], &[0, 0, 1, 0, 1, 0]);
            assert_eq!(&i.group_data[18..20], &1u16.to_le_bytes());
        }
        other => panic!("expected ICON, got {:?}", other),
    }
    match &unit.resources[1] {
        Resource::Bitmap(b) => {
            assert_eq!(b.id, ResId::Name("SPLASH".to_string()));
            assert_eq!(b.data.len(), 44, "BITMAPFILEHEADER must be stripped");
            assert_eq!(&b.data[0..4], &[0x28, 0, 0, 0]);
            assert_eq!(
                &b.data[20..24],
                &4u32.to_le_bytes(),
                "BI_RGB biSizeImage=0 must be patched to computed pixel bytes"
            );
        }
        other => panic!("expected BITMAP, got {:?}", other),
    }
    match &unit.resources[2] {
        Resource::RcData(r) => {
            assert_eq!(r.id, ResId::Name("BEEP".to_string()));
            assert_eq!(r.data, b"RIFF");
        }
        other => panic!("expected RCDATA, got {:?}", other),
    }
}

#[test]
fn g8_parse_versioninfo_resource() {
    use mdbcc::rc::{ResId, VersionNode};

    let src = r#"
1 VERSIONINFO
 FILEVERSION 2,3,0,0
 PRODUCTVERSION 2,3,0,0
 FILEFLAGSMASK 0x20L
 FILEFLAGS 0x0L
 FILEOS 0x1L
 FILETYPE 0x1L
 FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904E4"
    BEGIN
      VALUE "CompanyName", "MD Soft\0", "\0"
      VALUE "FileVersion", "2.3\0"
    END
  END
END
"#;
    let unit = parse(src).expect("parse ok");
    assert_eq!(unit.resources.len(), 1);
    let Resource::VersionInfo(v) = &unit.resources[0] else {
        panic!("expected VERSIONINFO, got {:?}", unit.resources[0]);
    };
    assert_eq!(v.id, ResId::Ord(1));
    assert_eq!(v.fixed.file_version, [2, 3, 0, 0]);
    assert_eq!(v.fixed.product_version, [2, 3, 0, 0]);
    assert_eq!(v.fixed.file_flags_mask, 0x20);
    assert_eq!(v.fixed.file_flags, 0);
    assert_eq!(v.fixed.file_os, 1);
    assert_eq!(v.fixed.file_type, 1);
    assert_eq!(v.fixed.file_subtype, 0);

    let [
        VersionNode::Block {
            key: string_file_info,
            children: tables,
        },
    ] = v.children.as_slice()
    else {
        panic!("expected one StringFileInfo block");
    };
    assert_eq!(string_file_info, "StringFileInfo");
    let [
        VersionNode::Block {
            key: table_key,
            children: values,
        },
    ] = tables.as_slice()
    else {
        panic!("expected one string table block");
    };
    assert_eq!(table_key, "040904E4");
    assert_eq!(values.len(), 2);
    match &values[0] {
        VersionNode::Value { key, value } => {
            assert_eq!(key, "CompanyName");
            assert_eq!(value, "MD Soft\0\0");
        }
        other => panic!("expected CompanyName value, got {:?}", other),
    }
    match &values[1] {
        VersionNode::Value { key, value } => {
            assert_eq!(key, "FileVersion");
            assert_eq!(value, "2.3\0");
        }
        other => panic!("expected FileVersion value, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// G-fix-1 / MAJOR-1: MENUITEM trailing MF_* flag identifiers
// ---------------------------------------------------------------------------

/// G-fix-1 (MAJOR-1): A single `MENUITEM "X", id, GRAYED` records flags
/// = MF_GRAYED (0x0001) on the AST. Previously the parser silently
/// dropped the flag and the writer emitted just MF_END (0x0080), which
/// diverged byte-for-byte from brc32 5.40 (0x0081). Pins the AST so
/// the writer's byte-level OR'ing is now exercised end-to-end.
#[test]
fn g_fix_1_menuitem_grayed_captures_flag_bit() {
    use mdbcc::rc::MenuItem;
    let src = r#"
        100 MENU
        BEGIN
          MENUITEM "X", 200, GRAYED
        END
    "#;
    let unit = parse(src).expect("parse ok");
    let m = match &unit.resources[0] {
        Resource::Menu(m) => m,
        other => panic!("expected MENU, got {:?}", other),
    };
    match &m.items[0] {
        MenuItem::Item { flags, .. } => {
            assert_eq!(*flags, 0x0001, "MF_GRAYED bit must be captured");
        }
        other => panic!("expected MENUITEM, got {:?}", other),
    }
}

/// G-fix-1 (MAJOR-1): two flags OR'd with `|` (brc32 accepts both `,`
/// and `|` as flag separators). `GRAYED | INACTIVE` ⇒ flags = 0x0003.
#[test]
fn g_fix_1_menuitem_grayed_pipe_inactive_ors_both_bits() {
    use mdbcc::rc::MenuItem;
    let src = r#"
        100 MENU
        BEGIN
          MENUITEM "X", 200, GRAYED | INACTIVE
        END
    "#;
    let unit = parse(src).expect("parse ok");
    let m = match &unit.resources[0] {
        Resource::Menu(m) => m,
        other => panic!("expected MENU, got {:?}", other),
    };
    match &m.items[0] {
        MenuItem::Item { flags, .. } => {
            assert_eq!(*flags, 0x0003, "GRAYED|INACTIVE = 0x01|0x02 = 0x03");
        }
        other => panic!("expected MENUITEM, got {:?}", other),
    }
}

/// G-fix-1 (MAJOR-1): all six recognised flags map to the documented
/// MF_* bits (GRAYED=0x0001, INACTIVE=0x0002, CHECKED=0x0008,
/// MENUBARBREAK=0x0020, MENUBREAK=0x0040, HELP=0x4000) — verified
/// empirically against brc32 5.40 on the menu_flags.rc differential
/// fixture.
#[test]
fn g_fix_1_all_six_flag_keywords_map_to_correct_bits() {
    use mdbcc::rc::MenuItem;
    let cases: &[(&str, u16)] = &[
        ("GRAYED", 0x0001),
        ("INACTIVE", 0x0002),
        ("CHECKED", 0x0008),
        ("MENUBARBREAK", 0x0020),
        ("MENUBREAK", 0x0040),
        ("HELP", 0x4000),
    ];
    for &(name, expected) in cases {
        let src = format!("100 MENU\nBEGIN\n  MENUITEM \"X\", 200, {name}\nEND\n");
        let unit = parse(&src).unwrap_or_else(|e| panic!("parse {name} ok: {e}"));
        let m = match &unit.resources[0] {
            Resource::Menu(m) => m,
            other => panic!("expected MENU, got {:?}", other),
        };
        match &m.items[0] {
            MenuItem::Item { flags, .. } => {
                assert_eq!(*flags, expected, "flag {name} should be 0x{expected:04X}");
            }
            other => panic!("expected MENUITEM, got {:?}", other),
        }
    }
}

/// G-fix-1 (MAJOR-1): unknown identifiers in the trailing-flag position
/// must reject loudly — the "never silently wrong" central discipline.
/// Previously the parser ate any `Ident(_)`, dropping the bits silently.
#[test]
fn g_fix_1_unknown_menuitem_flag_is_rejected() {
    let src = r#"
        100 MENU
        BEGIN
          MENUITEM "X", 200, BOGUS
        END
    "#;
    let err = parse(src).expect_err("unknown flag must reject");
    assert!(
        err.message.contains("BOGUS") && err.message.to_lowercase().contains("flag"),
        "diagnostic should mention BOGUS and `flag`; got: {}",
        err.message
    );
}
