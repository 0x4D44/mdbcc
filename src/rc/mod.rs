//! Resource-compiler front end (`.rc` lexer + parser).
//!
//! Phase G1 — STRINGTABLE-only scaffolding. The `.rc` grammar is disjoint
//! from C/C++ (different keywords, different lexical structure: there are
//! no `;` statement terminators, blocks use `BEGIN`/`END`, identifiers
//! are case-insensitive). So this module is self-contained: its own
//! [`Lexer`](lexer::Lexer), its own [`Parser`](parser::Parser), its own
//! token enum. Nothing leaks into the C lexer's namespace.
//!
//! Subsequent increments (G2 .res writer, G3 `.rsrc` PE emission, G4
//! MENU/ACCELERATORS, G5 DIALOG) extend the [`Resource`] enum below —
//! the AST shape is the stable contract between the front end and the
//! resource writer.

pub mod lexer;
pub mod parser;
pub mod pp;
pub mod res;

pub use res::{write_res, write_res_bc45};

/// Parsed resource file: a flat list of resource definitions in source
/// order.
///
/// Per Win32: multiple `STRINGTABLE` blocks in one `.rc` file are
/// independent at parse time; the writer (G2) groups all string entries
/// into 16-entry "bundles" indexed by `id >> 4`. The parser just
/// collects them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RcUnit {
    /// Resource definitions in source order.
    pub resources: Vec<Resource>,
    /// File-level `LANGUAGE` statement (most recent one wins for any
    /// resource that doesn't carry its own). v1 corpus uses the default
    /// (en-US = 0x0409) but the AST records what was written. `None`
    /// means "no file-level LANGUAGE was given".
    pub language: Option<Language>,
}

/// A single resource definition. The enum grows per increment: G1 added
/// STRINGTABLE; G4 added MENU + ACCELERATORS; G5a adds DIALOG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    /// `STRINGTABLE [flags] [LANGUAGE …] BEGIN <entries> END`. Each
    /// entry is `(id, value)` with the value stored as UTF-8 (the writer
    /// transcodes to UTF-16LE per Win32 .res format — G2's concern).
    StringTable(StringTable),
    /// `<id> MENU [flags] BEGIN <items> END` — Phase G / G4.
    Menu(MenuResource),
    /// `<id> ACCELERATORS [flags] BEGIN <entries> END` — Phase G / G4.
    Accelerators(AcceleratorTable),
    /// `<id> DIALOG <x>,<y>,<cx>,<cy> [stmts…] BEGIN <controls> END` —
    /// Phase G / G5a. Classic `DLGTEMPLATE` only; source-level
    /// `DIALOGEX` is rejected at parse time (G-fix-2 / MAJOR-2) — the
    /// `DLGTEMPLATEEX` form is G-future-4.
    Dialog(DialogResource),
    /// `<id> ICON <file-or-inline-ico>` — cooked into RT_ICON image bytes
    /// plus RT_GROUP_ICON metadata by the parser.
    Icon(IconResource),
    /// `<id> BITMAP <file-or-inline-bmp>` — cooked to RT_BITMAP bytes by
    /// the parser (the BITMAPFILEHEADER is stripped).
    Bitmap(BitmapResource),
    /// `<id> RCDATA <file-or-inline-bytes>` — opaque bytes.
    RcData(RcDataResource),
    /// `<id> VERSIONINFO ... BEGIN ... END` — fixed file metadata plus a
    /// nested VS_VERSION_INFO string tree.
    VersionInfo(VersionInfoResource),
}

/// A `STRINGTABLE` block — flags, optional per-block LANGUAGE, entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StringTable {
    /// Memory/loader flags written before `BEGIN`. Order on input is
    /// not preserved (set semantics — duplicates are silently merged).
    pub flags: MemoryFlags,
    /// Per-block `LANGUAGE primary, sub` (overrides any file-level
    /// LANGUAGE for this block's entries).
    pub language: Option<Language>,
    /// `(id, value)` pairs in source order. v1: ids are bare numeric
    /// literals; symbolic-constant resolution (`#define IDS_FOO 7`)
    /// is G3.
    pub entries: Vec<StringTableEntry>,
}

/// One string-table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringTableEntry {
    /// Resource ID (Win32 string-table IDs are u16-ranged).
    pub id: u16,
    /// String value as UTF-8 (transcoded to UTF-16LE by the writer).
    pub value: String,
    /// 1-based source position of the entry's ID (for diagnostics).
    pub line: u32,
    pub col: u32,
}

/// Resource name/id used by top-level resources. Win32 resources can be
/// addressed either by ordinal (`MAKEINTRESOURCE`) or by a string name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResId {
    Ord(u16),
    Name(String),
}

impl ResId {
    pub fn as_ord(&self) -> Option<u16> {
        match self {
            ResId::Ord(v) => Some(*v),
            ResId::Name(_) => None,
        }
    }
}

impl From<u16> for ResId {
    fn from(value: u16) -> Self {
        ResId::Ord(value)
    }
}

impl PartialEq<u16> for ResId {
    fn eq(&self, other: &u16) -> bool {
        matches!(self, ResId::Ord(v) if v == other)
    }
}

/// `<id> MENU [flags] BEGIN <items> END` — Phase G / G4. The items form a
/// tree: a top-level item is either a
/// `MENUITEM "text", id` leaf or a `POPUP "text" BEGIN <nested items>
/// END` subtree. Nesting depth in v1 is bounded at 2 (top → popups →
/// items); deeper nesting is parsable but documented as G-future.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuResource {
    /// Resource id (the menu's name in `LoadMenuA(NULL, MAKEINTRESOURCE(id))`).
    pub id: ResId,
    /// Memory/loader flags (currently a single set; v1 supports the same
    /// shared `MemoryFlags` vocabulary as STRINGTABLE).
    pub flags: MemoryFlags,
    /// Optional per-resource LANGUAGE override; otherwise the file-level
    /// LANGUAGE (or brc32's compiled-in default) applies.
    pub language: Option<Language>,
    /// Item list in source order. The last item gets MF_END set by the
    /// writer; the parser records source structure only.
    pub items: Vec<MenuItem>,
}

/// One menu item — either a leaf [`MenuItem::Item`], a separator
/// [`MenuItem::Separator`] (a MENUITEM with no text and id 0), or a
/// popup [`MenuItem::Popup`] carrying nested items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuItem {
    /// `MENUITEM "text", id [, flags…]` — leaf item with a command id.
    Item {
        text: String,
        id: u16,
        /// MF_* style bits OR'd from the optional trailing flag
        /// identifiers (GRAYED, INACTIVE, CHECKED, MENUBARBREAK,
        /// MENUBREAK, HELP). MF_END (0x0080) is added by the writer
        /// for the last sibling; MF_POPUP (0x0010) is reserved for
        /// POPUP entries — neither belongs here.
        flags: u16,
    },
    /// `MENUITEM SEPARATOR` — a horizontal divider; encoded as an item
    /// with empty text and id 0 in the .res payload.
    Separator,
    /// `POPUP "text" [, flags] BEGIN <nested items> END` — a submenu.
    Popup {
        text: String,
        /// MF_* style bits OR'd from the optional trailing flag
        /// identifiers (same set as [`MenuItem::Item::flags`]). The
        /// writer OR's MF_POPUP and MF_END on top per position.
        flags: u16,
        items: Vec<MenuItem>,
    },
}

/// `<id> ACCELERATORS [flags] BEGIN <entries> END` — Phase G / G4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceleratorTable {
    /// Resource id (the table's name in
    /// `LoadAcceleratorsA(NULL, MAKEINTRESOURCE(id))`).
    pub id: ResId,
    /// Memory/loader flags (shared `MemoryFlags` vocabulary).
    pub flags: MemoryFlags,
    /// Optional per-resource LANGUAGE override.
    pub language: Option<Language>,
    /// Entries in source order. The last entry gets FACCEL_LAST set by
    /// the writer; the parser records source structure only.
    pub entries: Vec<AcceleratorEntry>,
}

/// One accelerator entry. v1 carries the cooked key + cmd + flag bits;
/// `"^X"` strings are converted to their Ctrl-X byte (X - 0x40) at parse
/// time (matching brc32 — verified against the differential corpus).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceleratorEntry {
    /// Virtual-key code or cooked ASCII character (per `flags`).
    pub key: u16,
    /// `WM_COMMAND` id sent when the accelerator fires.
    pub cmd: u16,
    /// `FACCEL_*` bits (FACCEL_LAST is added by the writer for the last
    /// entry — not stored on individual entries).
    pub flags: u8,
}

// ---- G5a: DIALOG ----------------------------------------------------------

/// `<id> DIALOG <x>,<y>,<cx>,<cy> [stmts…] BEGIN <controls> END` — Phase
/// G / G5a. Classic `DLGTEMPLATE` only; source-level `DIALOGEX` is
/// rejected at parse time (G-fix-2 / MAJOR-2). DLGTEMPLATEEX is tracked
/// as G-future-4.
///
/// Field layout mirrors the binary `DLGTEMPLATE` header so the writer is
/// a thin serializer over the AST. `style`/`ex_style` are the resolved
/// 32-bit values (post merging of `STYLE`/`CAPTION`/`FONT` per the
/// brc32-observed model — see `src/rc/parser.rs::parse_dialog`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogResource {
    pub id: ResId,
    pub flags: MemoryFlags,
    pub language: Option<Language>,
    pub x: i16,
    pub y: i16,
    pub cx: i16,
    pub cy: i16,
    /// `style` already includes any bits OR'd in by CAPTION (WS_CAPTION =
    /// 0x00C00000) and FONT (DS_SETFONT = 0x40); the writer just emits
    /// it verbatim.
    pub style: u32,
    pub ex_style: u32,
    pub caption: Option<String>,
    /// `(point_size, typeface)` from `FONT pt, "name"`. When present, the
    /// writer emits the 2-byte point size + UTF-16LE typeface NUL string
    /// after the title, and the resolved `style` has DS_SETFONT set.
    pub font: Option<(u16, String)>,
    pub menu: Option<ResRef>,
    pub class: Option<ResRef>,
    pub controls: Vec<DialogControl>,
}

/// One control inside a DIALOG's `BEGIN…END` block.
///
/// The shorthand forms (`PUSHBUTTON`/`LTEXT`/`EDITTEXT`/…) and the
/// generic `CONTROL` form both produce this struct; the parser
/// pre-resolves the shorthand to its (class, default-style) pair so the
/// writer is shorthand-agnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogControl {
    /// Title — either a UTF-8 string (becomes UTF-16LE + NUL) or a u16
    /// resource ordinal (becomes `0xFFFF u16, ordinal u16`, used by ICON).
    pub text: ResRef,
    /// Control id. brc32 emits this as a u16 even when source wrote
    /// `-1` (it becomes `0xFFFF`); we store as `i16` and the writer
    /// reinterprets via `as u16`.
    pub id: i16,
    pub class: ControlClass,
    pub style: u32,
    pub ex_style: u32,
    pub x: i16,
    pub y: i16,
    pub cx: i16,
    pub cy: i16,
}

/// Top-level ICON resource. `ordinal` is the global RT_ICON id assigned in
/// source order; `group_data` is the RT_GROUP_ICON payload whose final `nID`
/// points at that ordinal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconResource {
    pub id: ResId,
    pub flags: MemoryFlags,
    pub language: Option<Language>,
    pub ordinal: u16,
    pub image_data: Vec<u8>,
    pub group_data: Vec<u8>,
}

/// Top-level BITMAP resource. `data` is the Win32 RT_BITMAP payload, not the
/// complete `.bmp` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapResource {
    pub id: ResId,
    pub flags: MemoryFlags,
    pub language: Option<Language>,
    pub data: Vec<u8>,
}

/// Top-level RCDATA resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcDataResource {
    pub id: ResId,
    pub flags: MemoryFlags,
    pub language: Option<Language>,
    pub data: Vec<u8>,
}

/// Top-level VERSIONINFO resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfoResource {
    pub id: ResId,
    pub flags: MemoryFlags,
    pub language: Option<Language>,
    pub fixed: VersionFixedInfo,
    pub children: Vec<VersionNode>,
}

/// Fields encoded in the 52-byte `VS_FIXEDFILEINFO` payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionFixedInfo {
    pub file_version: [u16; 4],
    pub product_version: [u16; 4],
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
}

/// Nested VERSIONINFO tree node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionNode {
    Block {
        key: String,
        children: Vec<VersionNode>,
    },
    Value {
        key: String,
        value: String,
    },
}

/// A DIALOG control's window-class. Predefined classes (BUTTON, EDIT,
/// STATIC, …) emit the brc32 ordinal form (`0xFFFF u16, ordinal u16`);
/// user classes emit a UTF-16LE NUL string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlClass {
    /// Predefined class — emit `0xFFFF, ordinal`. brc32 normalises the
    /// case-insensitive class strings BUTTON/EDIT/STATIC/LISTBOX/
    /// SCROLLBAR/COMBOBOX into the ordinal form even when written via
    /// `CONTROL "Text", id, "BUTTON", style, x, y, cx, cy`.
    Predefined(u16),
    /// User-defined class — emit UTF-16LE string + u16 NUL.
    UserClass(String),
}

/// A resource reference — either a numeric ordinal or a name string. Used
/// for DIALOG's MENU/CLASS statements and for the title field of
/// numeric-ordinal controls (e.g. ICON).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResRef {
    /// `0xFFFF u16, ordinal u16` in the binary.
    Numeric(u16),
    /// UTF-16LE NUL-terminated string in the binary.
    Name(String),
}

/// Default DIALOG style when no `STYLE` statement is present —
/// `WS_POPUP | WS_BORDER | WS_SYSMENU`. brc32-observed empirically (5.40).
/// Folklore-busting: some references list this as just `WS_POPUP |
/// WS_CAPTION | WS_SYSMENU` (`0x80c80000`), but brc32 5.40 uses
/// `WS_BORDER` (0x00800000), not `WS_CAPTION` (0x00c00000) — `WS_CAPTION`
/// is OR'd in *only* when a `CAPTION` statement is present.
pub const DIALOG_DEFAULT_STYLE: u32 = 0x8088_0000;

/// `WS_CAPTION` — OR'd into the dialog style when a `CAPTION` statement
/// is present in source (per brc32 5.40).
pub const WS_CAPTION: u32 = 0x00C0_0000;

/// `DS_SETFONT` — OR'd into the dialog style when a `FONT` statement is
/// present in source (per brc32 5.40).
pub const DS_SETFONT: u32 = 0x0000_0040;

/// Predefined control-class ordinals brc32 emits in the `0xFFFF, ord`
/// form. Used by both the shorthand expansion (PUSHBUTTON→BUTTON etc.)
/// and the generic CONTROL form's case-insensitive string→ordinal
/// normalisation.
pub const CC_BUTTON: u16 = 0x0080;
pub const CC_EDIT: u16 = 0x0081;
pub const CC_STATIC: u16 = 0x0082;
pub const CC_LISTBOX: u16 = 0x0083;
pub const CC_SCROLLBAR: u16 = 0x0084;
pub const CC_COMBOBOX: u16 = 0x0085;

// Default style values for the shorthand control statements. Verified
// against brc32 5.40 — see `tests/rc_res.rs` G5a tests.
pub const STYLE_PUSHBUTTON: u32 = 0x5001_0000;
pub const STYLE_DEFPUSHBUTTON: u32 = 0x5001_0001;
pub const STYLE_LTEXT: u32 = 0x5002_0000;
pub const STYLE_RTEXT: u32 = 0x5002_0002;
pub const STYLE_CTEXT: u32 = 0x5002_0001;
pub const STYLE_EDITTEXT: u32 = 0x5081_0000;
pub const STYLE_GROUPBOX: u32 = 0x5000_0007;
pub const STYLE_ICON: u32 = 0x5000_0003;

/// `LANGUAGE primary, sub` — Win32 language identifier components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Language {
    /// `LANG_*` primary language id (e.g. 0x09 = LANG_ENGLISH).
    pub primary: u16,
    /// `SUBLANG_*` sublanguage id (e.g. 0x01 = SUBLANG_ENGLISH_US).
    pub sub: u16,
}

/// Resource memory/loader flags from `STRINGTABLE [DISCARDABLE | PRELOAD
/// | LOADONCALL | MOVEABLE | FIXED] …`. v1 carries them on the AST but
/// the writer (G2) emits them as the `IMAGE_RESOURCE_DATA_ENTRY`
/// memory-flags word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemoryFlags {
    pub discardable: bool,
    pub preload: bool,
    pub loadoncall: bool,
    pub moveable: bool,
    pub fixed: bool,
}

/// Parse error for the `.rc` front end. Kept disjoint from
/// [`crate::lexer::LexError`] / [`crate::parser::ParseError`] because the
/// `.rc` grammar is disjoint from C — there is no upstream code that
/// wants to handle both error types uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcError {
    pub message: String,
    pub line: u32,
    pub col: u32,
}

impl std::fmt::Display for RcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: error: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for RcError {}

/// Parse a `.rc` source string into an [`RcUnit`]. Convenience wrapper
/// over [`lexer::Lexer::tokenize`] + [`parser::Parser::parse_unit`].
pub fn parse(src: &str) -> Result<RcUnit, RcError> {
    let toks = lexer::Lexer::tokenize(src.as_bytes())?;
    parser::Parser::new(&toks).parse_unit()
}

/// W5 (rc gap 2): the BYTE-clean front door. A 1990s `.rc` is LATIN-1 —
/// RAILC.RC's raw 0xA9 `©` makes `fs::read_to_string` fail before the lexer
/// even runs. Latin-1 is the identity prefix of Unicode, so transcoding
/// byte→same-numbered-code-point then running the UTF-8 lexer yields the
/// same UTF-16 unit brc32 emits (golden: `a9 00`). [`parse`] keeps its
/// historical &str/UTF-8 semantics (pinned by `utf16_string_encoding_of_
/// latin1` in tests/rc_res.rs).
pub fn parse_bytes(src: &[u8]) -> Result<RcUnit, RcError> {
    let text: String = src.iter().map(|&b| b as char).collect();
    parse(&text)
}

/// W5 (rc gap 4): the FILE front door — load `path` as raw bytes (Latin-1
/// clean), run the `.rc` preprocessor (`#define`/`#include` relative to the
/// file's own directory/`#ifdef`), then lex + parse. `defines` seeds the
/// macro table (empty = the railc golden profile, `_DEBUG` undefined).
pub fn compile_file(
    path: &std::path::Path,
    defines: &std::collections::HashMap<String, String>,
) -> Result<RcUnit, RcError> {
    let bytes = std::fs::read(path).map_err(|e| RcError {
        message: format!("{}: {e}", path.display()),
        line: 0,
        col: 0,
    })?;
    let dir = path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();
    let mut macros = defines.clone();
    let expanded = pp::preprocess(&bytes, &dir, &mut macros)?;
    let text: String = expanded.iter().map(|&b| b as char).collect();
    let toks = lexer::Lexer::tokenize(text.as_bytes())?;
    parser::Parser::with_base_dir(&toks, dir).parse_unit()
}
