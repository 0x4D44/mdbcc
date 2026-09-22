//! Parser for `.rc` (Win32 resource compiler) syntax — G1 + G4 subset.
//!
//! Recursive-descent over the token stream from [`super::lexer`]. The
//! resource forms recognised are:
//!
//! - file-level `LANGUAGE primary, sub`
//! - `STRINGTABLE [flags] [LANGUAGE …] BEGIN <entries> END`
//! - `<id> MENU [flags] [LANGUAGE …] BEGIN <menu items> END` (G4)
//! - `<id> ACCELERATORS [flags] [LANGUAGE …] BEGIN <entries> END` (G4)
//!
//! Future increments will add `DIALOG`.
//!
//! Error type is [`super::RcError`] (one error → fail-fast; the C
//! parser uses the same style — see `src/parser.rs:31`).

use super::lexer::{Keyword, Token, TokenKind};
use super::{
    AcceleratorEntry, AcceleratorTable, BitmapResource, CC_BUTTON, CC_COMBOBOX, CC_EDIT,
    CC_LISTBOX, CC_SCROLLBAR, CC_STATIC, ControlClass, DIALOG_DEFAULT_STYLE, DS_SETFONT,
    DialogControl, DialogResource, IconResource, Language, MemoryFlags, MenuItem, MenuResource,
    RcDataResource, RcError, RcUnit, ResId, ResRef, Resource, STYLE_CTEXT, STYLE_DEFPUSHBUTTON,
    STYLE_EDITTEXT, STYLE_GROUPBOX, STYLE_ICON, STYLE_LTEXT, STYLE_PUSHBUTTON, STYLE_RTEXT,
    StringTable, StringTableEntry, VersionFixedInfo, VersionInfoResource, VersionNode, WS_CAPTION,
};
use std::path::PathBuf;

type PResult<T> = Result<T, RcError>;

pub struct Parser<'t> {
    toks: &'t [Token],
    pos: usize,
    base_dir: Option<PathBuf>,
    next_icon_ordinal: u16,
}

struct BinaryPayload {
    flags: MemoryFlags,
    language: Option<Language>,
    data: Vec<u8>,
    line: u32,
    col: u32,
}

impl<'t> Parser<'t> {
    pub fn new(toks: &'t [Token]) -> Self {
        Parser {
            toks,
            pos: 0,
            base_dir: None,
            next_icon_ordinal: 1,
        }
    }

    pub fn with_base_dir(toks: &'t [Token], base_dir: PathBuf) -> Self {
        Parser {
            toks,
            pos: 0,
            base_dir: Some(base_dir),
            next_icon_ordinal: 1,
        }
    }

    /// Parse a whole `.rc` translation unit. Top-level statements are
    /// `LANGUAGE …` (sets file-level default), `STRINGTABLE …`, or
    /// `<id> MENU/ACCELERATORS …` (G4). Multiple `STRINGTABLE`s are
    /// concatenated — the writer bundles their entries together.
    pub fn parse_unit(&mut self) -> PResult<RcUnit> {
        let mut unit = RcUnit::default();
        loop {
            match self.peek_kind() {
                TokenKind::Eof => return Ok(unit),
                TokenKind::Keyword(Keyword::Language) => {
                    let lang = self.parse_language_stmt()?;
                    unit.language = Some(lang);
                }
                TokenKind::Keyword(Keyword::StringTable) => {
                    let st = self.parse_stringtable()?;
                    unit.resources.push(Resource::StringTable(st));
                }
                // `<id> MENU …` / `<id> ACCELERATORS …` / `<id> DIALOG[EX] …`
                // — G4/G5a. Gap 5 extends the resource id from ordinal-only
                // to ordinal-or-name; we still peek the next token to
                // disambiguate from a stray literal/identifier.
                TokenKind::Int(_) | TokenKind::Ident(_) => match self.peek_kind_n(1) {
                    Some(TokenKind::Keyword(Keyword::Menu)) => {
                        let m = self.parse_menu()?;
                        unit.resources.push(Resource::Menu(m));
                    }
                    Some(TokenKind::Keyword(Keyword::Accelerators)) => {
                        let a = self.parse_accelerators()?;
                        unit.resources.push(Resource::Accelerators(a));
                    }
                    Some(TokenKind::Keyword(Keyword::Dialog))
                    | Some(TokenKind::Keyword(Keyword::DialogEx)) => {
                        let d = self.parse_dialog()?;
                        unit.resources.push(Resource::Dialog(d));
                    }
                    Some(TokenKind::Keyword(Keyword::Icon)) => {
                        let i = self.parse_icon_resource()?;
                        unit.resources.push(Resource::Icon(i));
                    }
                    Some(TokenKind::Keyword(Keyword::Bitmap)) => {
                        let b = self.parse_bitmap_resource()?;
                        unit.resources.push(Resource::Bitmap(b));
                    }
                    Some(TokenKind::Keyword(Keyword::RcData)) => {
                        let r = self.parse_rcdata_resource()?;
                        unit.resources.push(Resource::RcData(r));
                    }
                    Some(TokenKind::Keyword(Keyword::VersionInfo)) => {
                        let v = self.parse_versioninfo_resource()?;
                        unit.resources.push(Resource::VersionInfo(v));
                    }
                    _ => {
                        let t = self.peek();
                        return self.err_at(
                            format!(
                                "expected MENU, ACCELERATORS, DIALOG[EX], ICON, BITMAP, RCDATA, or VERSIONINFO after id at top level, found {}",
                                self.peek_n(1)
                                    .map(|t| describe_kind(&t.kind))
                                    .unwrap_or_else(|| "end of file".into())
                            ),
                            t.line,
                            t.col,
                        );
                    }
                },
                _ => {
                    let t = self.peek();
                    return self.err_at(
                        format!(
                            "expected STRINGTABLE, LANGUAGE, or `<id> MENU/ACCELERATORS/DIALOG/ICON/BITMAP/RCDATA/VERSIONINFO`, found {}",
                            describe_kind(&t.kind)
                        ),
                        t.line,
                        t.col,
                    );
                }
            }
        }
    }

    // ---- token plumbing --------------------------------------------------

    fn peek(&self) -> &Token {
        // The lexer guarantees a trailing Eof, so this is always valid.
        &self.toks[self.pos]
    }

    fn peek_kind(&self) -> &TokenKind {
        &self.peek().kind
    }

    /// Lookahead by `n` positions. `None` when past Eof.
    fn peek_n(&self, n: usize) -> Option<&Token> {
        self.toks.get(self.pos + n)
    }

    /// Lookahead kind by `n` positions; `None` past Eof.
    fn peek_kind_n(&self, n: usize) -> Option<&TokenKind> {
        self.peek_n(n).map(|t| &t.kind)
    }

    fn advance(&mut self) -> &Token {
        let tok = &self.toks[self.pos];
        if !matches!(tok.kind, TokenKind::Eof) {
            self.pos += 1;
        }
        tok
    }

    fn err_at<T>(&self, msg: impl Into<String>, line: u32, col: u32) -> PResult<T> {
        Err(RcError {
            message: msg.into(),
            line,
            col,
        })
    }

    /// Consume the next token if its kind matches `expected` exactly
    /// (using `==`); otherwise produce a diagnostic referring to the
    /// human-readable name `what`.
    fn expect_keyword(&mut self, kw: Keyword, what: &str) -> PResult<()> {
        let tok = self.peek();
        if let TokenKind::Keyword(k) = tok.kind
            && k == kw
        {
            self.advance();
            return Ok(());
        }
        let (line, col) = (tok.line, tok.col);
        let found = describe_kind(&tok.kind);
        self.err_at(format!("expected {what}, found {found}"), line, col)
    }

    /// Consume an optional comma (silently — no error if absent).
    fn eat_optional_comma(&mut self) {
        if matches!(self.peek_kind(), TokenKind::Comma) {
            self.advance();
        }
    }

    // ---- statements ------------------------------------------------------

    /// `LANGUAGE primary, sub` — both numeric.
    fn parse_language_stmt(&mut self) -> PResult<Language> {
        self.expect_keyword(Keyword::Language, "LANGUAGE")?;
        let primary = self.parse_u16_with_label("LANGUAGE primary id")?;
        // Per rc.exe the comma is required, but we accept it as optional
        // for forgiveness — brc32 also tolerates whitespace separation.
        self.eat_optional_comma();
        let sub = self.parse_u16_with_label("LANGUAGE sublanguage id")?;
        Ok(Language { primary, sub })
    }

    /// `STRINGTABLE [flags…] [LANGUAGE …] BEGIN entry* END`.
    fn parse_stringtable(&mut self) -> PResult<StringTable> {
        self.expect_keyword(Keyword::StringTable, "STRINGTABLE")?;

        let mut st = StringTable::default();

        // Memory/loader flags and an optional per-block LANGUAGE in any
        // order, until BEGIN.
        loop {
            match self.peek_kind() {
                TokenKind::Keyword(Keyword::Discardable) => {
                    st.flags.discardable = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Preload) => {
                    st.flags.preload = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Loadoncall) => {
                    st.flags.loadoncall = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Moveable) => {
                    st.flags.moveable = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Fixed) => {
                    st.flags.fixed = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Language) => {
                    let lang = self.parse_language_stmt()?;
                    st.language = Some(lang);
                }
                TokenKind::Keyword(Keyword::Begin) => break,
                _ => {
                    let t = self.peek();
                    return self.err_at(
                        format!(
                            "expected STRINGTABLE flag, LANGUAGE, or BEGIN, found {}",
                            describe_kind(&t.kind)
                        ),
                        t.line,
                        t.col,
                    );
                }
            }
        }

        self.expect_keyword(Keyword::Begin, "BEGIN")?;

        // Entries: `<id> [,] "<string>"`.
        loop {
            match self.peek_kind() {
                TokenKind::Keyword(Keyword::End) => {
                    self.advance();
                    return Ok(st);
                }
                TokenKind::Eof => {
                    let t = self.peek();
                    return self.err_at(
                        "unexpected end of file in STRINGTABLE; expected END".to_string(),
                        t.line,
                        t.col,
                    );
                }
                _ => {
                    let entry = self.parse_stringtable_entry()?;
                    st.entries.push(entry);
                }
            }
        }
    }

    /// One STRINGTABLE entry: `<id-int> [,] "<string-literal>"`. The
    /// comma between id and value is optional (brc32 accepts both).
    /// `<id>` is a numeric literal here; symbolic-constant resolution
    /// (`#define IDS_FOO 7`) is deferred to G3.
    fn parse_stringtable_entry(&mut self) -> PResult<StringTableEntry> {
        let t = self.peek().clone();
        let id = self.parse_u16_with_label("STRINGTABLE entry id")?;
        self.eat_optional_comma();
        let val_tok = self.peek().clone();
        let value = match val_tok.kind {
            TokenKind::Str(s) => {
                self.advance();
                s
            }
            other => {
                return self.err_at(
                    format!(
                        "expected string literal after STRINGTABLE entry id, found {}",
                        describe_kind(&other)
                    ),
                    val_tok.line,
                    val_tok.col,
                );
            }
        };
        Ok(StringTableEntry {
            id,
            value,
            line: t.line,
            col: t.col,
        })
    }

    // ---- G4: MENU --------------------------------------------------------

    /// `<id> MENU [flags…] [LANGUAGE …] BEGIN <items> END`.
    fn parse_menu(&mut self) -> PResult<MenuResource> {
        let id = self.parse_resid_with_label("MENU resource id")?;
        self.expect_keyword(Keyword::Menu, "MENU")?;

        let mut flags = MemoryFlags::default();
        let mut language: Option<Language> = None;
        self.parse_optional_flags_and_language(&mut flags, &mut language, "MENU")?;

        self.expect_keyword(Keyword::Begin, "BEGIN")?;
        let items = self.parse_menu_items()?;
        self.expect_keyword(Keyword::End, "END")?;

        Ok(MenuResource {
            id,
            flags,
            language,
            items,
        })
    }

    /// Sequence of menu items between BEGIN/END (or POPUP BEGIN/END).
    /// The structure is recursive: POPUPs nest item sequences inside.
    fn parse_menu_items(&mut self) -> PResult<Vec<MenuItem>> {
        let mut items = Vec::new();
        loop {
            match self.peek_kind() {
                TokenKind::Keyword(Keyword::End) | TokenKind::Eof => return Ok(items),
                TokenKind::Keyword(Keyword::MenuItem) => {
                    items.push(self.parse_menuitem()?);
                }
                TokenKind::Keyword(Keyword::Popup) => {
                    items.push(self.parse_popup()?);
                }
                _ => {
                    let t = self.peek();
                    return self.err_at(
                        format!(
                            "expected MENUITEM, POPUP, or END in MENU body, found {}",
                            describe_kind(&t.kind)
                        ),
                        t.line,
                        t.col,
                    );
                }
            }
        }
    }

    /// `MENUITEM "text", id [, flags…]` or `MENUITEM SEPARATOR`.
    fn parse_menuitem(&mut self) -> PResult<MenuItem> {
        self.expect_keyword(Keyword::MenuItem, "MENUITEM")?;
        if matches!(self.peek_kind(), TokenKind::Keyword(Keyword::Separator)) {
            self.advance();
            return Ok(MenuItem::Separator);
        }
        let text_tok = self.peek().clone();
        let text = match text_tok.kind {
            TokenKind::Str(s) => {
                self.advance();
                s
            }
            other => {
                return self.err_at(
                    format!(
                        "expected string literal after MENUITEM, found {}",
                        describe_kind(&other)
                    ),
                    text_tok.line,
                    text_tok.col,
                );
            }
        };
        self.eat_optional_comma();
        let id = self.parse_u16_with_label("MENUITEM id")?;
        // Optional trailing MF_* flag tokens. v1 records them as 0; the
        // writer does not consume them yet (kept here so flag-tolerant
        // sources parse cleanly; differential-equivalent to brc32's
        // ignore-and-warn behaviour for flags it doesn't model).
        let flags = self.parse_optional_menuitem_flags()?;
        Ok(MenuItem::Item { text, id, flags })
    }

    /// `POPUP "text" [, flags…] BEGIN <nested items> END`.
    fn parse_popup(&mut self) -> PResult<MenuItem> {
        self.expect_keyword(Keyword::Popup, "POPUP")?;
        let text_tok = self.peek().clone();
        let text = match text_tok.kind {
            TokenKind::Str(s) => {
                self.advance();
                s
            }
            other => {
                return self.err_at(
                    format!(
                        "expected string literal after POPUP, found {}",
                        describe_kind(&other)
                    ),
                    text_tok.line,
                    text_tok.col,
                );
            }
        };
        let flags = self.parse_optional_menuitem_flags()?;
        self.expect_keyword(Keyword::Begin, "BEGIN")?;
        let items = self.parse_menu_items()?;
        self.expect_keyword(Keyword::End, "END")?;
        Ok(MenuItem::Popup { text, flags, items })
    }

    /// Consume any trailing MF_* style flag identifiers after a
    /// MENUITEM/POPUP and return the OR'd value. Separators are `,` or
    /// `|` (brc32 accepts both interchangeably). Recognised flags:
    /// GRAYED (0x0001), INACTIVE (0x0002), CHECKED (0x0008),
    /// MENUBARBREAK (0x0020), MENUBREAK (0x0040), HELP (0x4000).
    ///
    /// **Unknown identifiers reject loudly** — the "never silently wrong"
    /// central discipline that Phase G's MAJOR-1 review caught the parser
    /// violating. Previously this routine consumed any `Ident(_)` and
    /// dropped the bits; that produced byte-different output from brc32
    /// without any diagnostic. Now we recognise the documented set and
    /// fail on anything else.
    fn parse_optional_menuitem_flags(&mut self) -> PResult<u16> {
        let mut bits: u16 = 0;
        loop {
            match self.peek_kind() {
                TokenKind::Comma | TokenKind::Pipe => {
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Grayed) => {
                    self.advance();
                    bits |= 0x0001;
                }
                TokenKind::Keyword(Keyword::Inactive) => {
                    self.advance();
                    bits |= 0x0002;
                }
                TokenKind::Keyword(Keyword::Checked) => {
                    self.advance();
                    bits |= 0x0008;
                }
                TokenKind::Keyword(Keyword::MenuBarBreak) => {
                    self.advance();
                    bits |= 0x0020;
                }
                TokenKind::Keyword(Keyword::MenuBreak) => {
                    self.advance();
                    bits |= 0x0040;
                }
                TokenKind::Keyword(Keyword::Help) => {
                    self.advance();
                    bits |= 0x4000;
                }
                TokenKind::Ident(name) => {
                    let name = name.clone();
                    let t = self.peek().clone();
                    return self.err_at(
                        format!(
                            "unsupported MENUITEM/POPUP flag `{name}`; expected one of \
                             GRAYED, INACTIVE, CHECKED, MENUBARBREAK, MENUBREAK, HELP"
                        ),
                        t.line,
                        t.col,
                    );
                }
                _ => return Ok(bits),
            }
        }
    }

    // ---- G4: ACCELERATORS -----------------------------------------------

    /// `<id> ACCELERATORS [flags…] [LANGUAGE …] BEGIN <entries> END`.
    fn parse_accelerators(&mut self) -> PResult<AcceleratorTable> {
        let id = self.parse_resid_with_label("ACCELERATORS resource id")?;
        self.expect_keyword(Keyword::Accelerators, "ACCELERATORS")?;

        let mut flags = MemoryFlags::default();
        let mut language: Option<Language> = None;
        self.parse_optional_flags_and_language(&mut flags, &mut language, "ACCELERATORS")?;

        self.expect_keyword(Keyword::Begin, "BEGIN")?;
        let mut entries = Vec::new();
        loop {
            match self.peek_kind() {
                TokenKind::Keyword(Keyword::End) => {
                    self.advance();
                    return Ok(AcceleratorTable {
                        id,
                        flags,
                        language,
                        entries,
                    });
                }
                TokenKind::Eof => {
                    let t = self.peek();
                    return self.err_at(
                        "unexpected end of file in ACCELERATORS; expected END".to_string(),
                        t.line,
                        t.col,
                    );
                }
                _ => {
                    entries.push(self.parse_accelerator_entry()?);
                }
            }
        }
    }

    /// One accelerator entry: `<key> , <cmd-id> [, <flag>…]` where
    /// `<key>` is either a string literal (with optional `^X` Ctrl prefix)
    /// or an integer (typically a VK_* code). Flags: VIRTKEY, ASCII,
    /// CONTROL, SHIFT, ALT, NOINVERT.
    fn parse_accelerator_entry(&mut self) -> PResult<AcceleratorEntry> {
        let tok = self.peek().clone();
        let key = match tok.kind {
            TokenKind::Str(ref s) => {
                self.advance();
                // brc32 cooks `"^X"` to (X - 0x40) and stores the resulting
                // byte; no FACCEL_CONTROL bit is set.
                let bytes = s.as_bytes();
                if bytes.len() >= 2 && bytes[0] == b'^' {
                    let c = bytes[1].to_ascii_uppercase();
                    if !c.is_ascii_uppercase() {
                        return self.err_at(
                            format!(
                                "`^` accelerator key must be a letter, got {:?}",
                                bytes[1] as char
                            ),
                            tok.line,
                            tok.col,
                        );
                    }
                    u16::from(c - b'@')
                } else if bytes.len() == 1 {
                    // Plain ASCII char (no Ctrl). brc32 uppercases this when
                    // VIRTKEY is set; for ASCII (default) it leaves the byte
                    // alone. We carry the literal here and uppercase below
                    // once we know whether VIRTKEY is in effect.
                    u16::from(bytes[0])
                } else {
                    return self.err_at(
                        format!(
                            "ACCELERATORS key string must be one character (or `^X`), got {s:?}"
                        ),
                        tok.line,
                        tok.col,
                    );
                }
            }
            TokenKind::Int(v) => {
                self.advance();
                u16::try_from(v).map_err(|_| RcError {
                    message: format!("ACCELERATORS key {v} out of range for u16"),
                    line: tok.line,
                    col: tok.col,
                })?
            }
            other => {
                return self.err_at(
                    format!(
                        "expected ACCELERATORS entry key (string or integer), found {}",
                        describe_kind(&other)
                    ),
                    tok.line,
                    tok.col,
                );
            }
        };
        self.eat_optional_comma();
        let cmd = self.parse_u16_with_label("ACCELERATORS entry cmd id")?;
        // Trailing flags. brc32 accepts them in any order after the cmd id.
        let (mut flag_bits, key_was_string) = (0u8, matches!(tok.kind, TokenKind::Str(_)));
        let mut saw_virtkey = false;
        loop {
            match self.peek_kind() {
                TokenKind::Comma => {
                    self.advance();
                }
                TokenKind::Keyword(Keyword::VirtKey) => {
                    self.advance();
                    flag_bits |= 0x01; // FACCEL_VIRTKEY
                    saw_virtkey = true;
                }
                TokenKind::Keyword(Keyword::Ascii) => {
                    // FACCEL_VIRTKEY clear is ASCII; explicit ASCII is a no-op.
                    self.advance();
                }
                TokenKind::Keyword(Keyword::NoInvert) => {
                    self.advance();
                    flag_bits |= 0x02; // FACCEL_NOINVERT
                }
                TokenKind::Keyword(Keyword::Shift) => {
                    self.advance();
                    flag_bits |= 0x04; // FACCEL_SHIFT
                }
                TokenKind::Keyword(Keyword::Control) => {
                    self.advance();
                    flag_bits |= 0x08; // FACCEL_CONTROL
                }
                TokenKind::Keyword(Keyword::Alt) => {
                    self.advance();
                    flag_bits |= 0x10; // FACCEL_ALT
                }
                _ => break,
            }
        }
        // brc32 uppercases a single-character VIRTKEY key written as a string.
        // (Verified empirically: `"S", id, VIRTKEY` and `"s", id, VIRTKEY`
        // both encode key = 0x53.)
        let key = if saw_virtkey && key_was_string && key < 0x80 {
            (key as u8).to_ascii_uppercase() as u16
        } else {
            key
        };
        Ok(AcceleratorEntry {
            key,
            cmd,
            flags: flag_bits,
        })
    }

    // ---- W5 rc gap 7: ICON / BITMAP / RCDATA ----------------------------

    fn parse_icon_resource(&mut self) -> PResult<IconResource> {
        let id = self.parse_resid_with_label("ICON resource id")?;
        self.expect_keyword(Keyword::Icon, "ICON")?;
        let payload = self.parse_binary_payload("ICON")?;
        let ordinal = self.next_icon_ordinal;
        self.next_icon_ordinal = self
            .next_icon_ordinal
            .checked_add(1)
            .ok_or_else(|| RcError {
                message: "too many ICON resources (ordinal overflow)".to_string(),
                line: payload.line,
                col: payload.col,
            })?;
        let (image_data, group_data) =
            cook_ico_payload(&payload.data, ordinal, payload.line, payload.col)?;
        Ok(IconResource {
            id,
            flags: payload.flags,
            language: payload.language,
            ordinal,
            image_data,
            group_data,
        })
    }

    fn parse_bitmap_resource(&mut self) -> PResult<BitmapResource> {
        let id = self.parse_resid_with_label("BITMAP resource id")?;
        self.expect_keyword(Keyword::Bitmap, "BITMAP")?;
        let payload = self.parse_binary_payload("BITMAP")?;
        let data = cook_bmp_payload(&payload.data, payload.line, payload.col)?;
        Ok(BitmapResource {
            id,
            flags: payload.flags,
            language: payload.language,
            data,
        })
    }

    fn parse_rcdata_resource(&mut self) -> PResult<RcDataResource> {
        let id = self.parse_resid_with_label("RCDATA resource id")?;
        self.expect_keyword(Keyword::RcData, "RCDATA")?;
        let payload = self.parse_binary_payload("RCDATA")?;
        Ok(RcDataResource {
            id,
            flags: payload.flags,
            language: payload.language,
            data: payload.data,
        })
    }

    // ---- W5 rc gap 8: VERSIONINFO ---------------------------------------

    fn parse_versioninfo_resource(&mut self) -> PResult<VersionInfoResource> {
        let id = self.parse_resid_with_label("VERSIONINFO resource id")?;
        self.expect_keyword(Keyword::VersionInfo, "VERSIONINFO")?;

        let mut flags = MemoryFlags::default();
        let mut language: Option<Language> = None;
        let mut fixed = VersionFixedInfo::default();
        loop {
            match self.peek_kind() {
                TokenKind::Keyword(Keyword::Discardable) => {
                    flags.discardable = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Preload) => {
                    flags.preload = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Loadoncall) => {
                    flags.loadoncall = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Moveable) => {
                    flags.moveable = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Fixed) => {
                    flags.fixed = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Language) => {
                    language = Some(self.parse_language_stmt()?);
                }
                TokenKind::Keyword(Keyword::Begin) => break,
                TokenKind::Ident(name) if ident_eq(name, "FILEVERSION") => {
                    self.advance();
                    fixed.file_version = self.parse_version_quad("FILEVERSION")?;
                }
                TokenKind::Ident(name) if ident_eq(name, "PRODUCTVERSION") => {
                    self.advance();
                    fixed.product_version = self.parse_version_quad("PRODUCTVERSION")?;
                }
                TokenKind::Ident(name) if ident_eq(name, "FILEFLAGSMASK") => {
                    self.advance();
                    fixed.file_flags_mask = self.parse_u32_with_label("FILEFLAGSMASK")?;
                }
                TokenKind::Ident(name) if ident_eq(name, "FILEFLAGS") => {
                    self.advance();
                    fixed.file_flags = self.parse_u32_with_label("FILEFLAGS")?;
                }
                TokenKind::Ident(name) if ident_eq(name, "FILEOS") => {
                    self.advance();
                    fixed.file_os = self.parse_u32_with_label("FILEOS")?;
                }
                TokenKind::Ident(name) if ident_eq(name, "FILETYPE") => {
                    self.advance();
                    fixed.file_type = self.parse_u32_with_label("FILETYPE")?;
                }
                TokenKind::Ident(name) if ident_eq(name, "FILESUBTYPE") => {
                    self.advance();
                    fixed.file_subtype = self.parse_u32_with_label("FILESUBTYPE")?;
                }
                _ => {
                    let t = self.peek();
                    return self.err_at(
                        format!(
                            "expected VERSIONINFO fixed field, flag, LANGUAGE, or BEGIN, found {}",
                            describe_kind(&t.kind)
                        ),
                        t.line,
                        t.col,
                    );
                }
            }
        }

        self.expect_keyword(Keyword::Begin, "BEGIN")?;
        let children = self.parse_versioninfo_children("VERSIONINFO")?;
        Ok(VersionInfoResource {
            id,
            flags,
            language,
            fixed,
            children,
        })
    }

    fn parse_version_quad(&mut self, what: &str) -> PResult<[u16; 4]> {
        let mut quad = [0u16; 4];
        for (i, slot) in quad.iter_mut().enumerate() {
            if i != 0 {
                self.eat_optional_comma();
            }
            *slot = self.parse_u16_with_label(what)?;
        }
        Ok(quad)
    }

    fn parse_versioninfo_children(&mut self, what: &str) -> PResult<Vec<VersionNode>> {
        let mut children = Vec::new();
        loop {
            let tok = self.peek().clone();
            match tok.kind {
                TokenKind::Keyword(Keyword::End) => {
                    self.advance();
                    return Ok(children);
                }
                TokenKind::Ident(ref name) if ident_eq(name, "BLOCK") => {
                    children.push(self.parse_versioninfo_block()?);
                }
                TokenKind::Ident(ref name) if ident_eq(name, "VALUE") => {
                    children.push(self.parse_versioninfo_value()?);
                }
                TokenKind::Eof => {
                    return self.err_at(
                        format!("unexpected end of file in {what}; expected END"),
                        tok.line,
                        tok.col,
                    );
                }
                other => {
                    return self.err_at(
                        format!(
                            "expected BLOCK, VALUE, or END in {what}, found {}",
                            describe_kind(&other)
                        ),
                        tok.line,
                        tok.col,
                    );
                }
            }
        }
    }

    fn parse_versioninfo_block(&mut self) -> PResult<VersionNode> {
        self.expect_ident_ci("BLOCK", "BLOCK")?;
        let key = self.expect_string_with_label("VERSIONINFO BLOCK key")?;
        self.expect_keyword(Keyword::Begin, "BEGIN")?;
        let children = self.parse_versioninfo_children("VERSIONINFO BLOCK")?;
        Ok(VersionNode::Block { key, children })
    }

    fn parse_versioninfo_value(&mut self) -> PResult<VersionNode> {
        self.expect_ident_ci("VALUE", "VALUE")?;
        let key = self.expect_string_with_label("VERSIONINFO VALUE key")?;
        self.eat_optional_comma();

        let mut value = self.expect_string_with_label("VERSIONINFO VALUE string")?;
        while matches!(self.peek_kind(), TokenKind::Comma) {
            self.advance();
            match self.peek_kind() {
                TokenKind::Str(_) => {
                    value.push_str(&self.expect_string_with_label("VERSIONINFO VALUE string")?);
                }
                other => {
                    let t = self.peek();
                    return self.err_at(
                        format!(
                            "expected string literal after comma in VERSIONINFO VALUE, found {}",
                            describe_kind(other)
                        ),
                        t.line,
                        t.col,
                    );
                }
            }
        }

        Ok(VersionNode::Value { key, value })
    }

    fn parse_binary_payload(&mut self, what: &str) -> PResult<BinaryPayload> {
        let mut flags = MemoryFlags::default();
        let mut language: Option<Language> = None;
        loop {
            match self.peek_kind() {
                TokenKind::Keyword(Keyword::Discardable) => {
                    flags.discardable = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Preload) => {
                    flags.preload = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Loadoncall) => {
                    flags.loadoncall = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Moveable) => {
                    flags.moveable = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Fixed) => {
                    flags.fixed = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Language) => {
                    language = Some(self.parse_language_stmt()?);
                }
                _ => break,
            }
        }

        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Str(path) => {
                self.advance();
                let bytes = self.read_resource_file(&path, tok.line, tok.col)?;
                Ok(BinaryPayload {
                    flags,
                    language,
                    data: bytes,
                    line: tok.line,
                    col: tok.col,
                })
            }
            TokenKind::Keyword(Keyword::Begin) => {
                let line = tok.line;
                let col = tok.col;
                self.advance();
                let mut bytes = Vec::new();
                loop {
                    let t = self.peek().clone();
                    match t.kind {
                        TokenKind::RawHex(chunk) => {
                            self.advance();
                            bytes.extend_from_slice(&chunk);
                        }
                        TokenKind::Keyword(Keyword::End) => {
                            self.advance();
                            return Ok(BinaryPayload {
                                flags,
                                language,
                                data: bytes,
                                line,
                                col,
                            });
                        }
                        TokenKind::Eof => {
                            return self.err_at(
                                format!("unexpected end of file in {what} data; expected END"),
                                t.line,
                                t.col,
                            );
                        }
                        other => {
                            return self.err_at(
                                format!(
                                    "expected raw-hex literal or END in {what} data, found {}",
                                    describe_kind(&other)
                                ),
                                t.line,
                                t.col,
                            );
                        }
                    }
                }
            }
            other => self.err_at(
                format!(
                    "expected file string or BEGIN raw data for {what}, found {}",
                    describe_kind(&other)
                ),
                tok.line,
                tok.col,
            ),
        }
    }

    fn read_resource_file(&self, rel: &str, line: u32, col: u32) -> PResult<Vec<u8>> {
        let Some(base) = &self.base_dir else {
            return Err(RcError {
                message: format!("file-backed resource `{rel}` requires rc::compile_file"),
                line,
                col,
            });
        };
        let full = base.join(rel);
        std::fs::read(&full).map_err(|e| RcError {
            message: format!("{}: {e}", full.display()),
            line,
            col,
        })
    }

    // ---- G5a: DIALOG -----------------------------------------------------

    /// `<id> DIALOG[EX] <x>, <y>, <cx>, <cy> [statements…] BEGIN
    /// <controls> END`.
    ///
    /// Statements before BEGIN: `STYLE <u32>`, `EXSTYLE <u32>`, `CAPTION
    /// "…"`, `FONT <pt>, "name"`, `MENU <id-or-string>`, `CLASS
    /// <id-or-string>`, plus any MemoryFlags / LANGUAGE override (per
    /// brc32). Order is free.
    ///
    /// Style resolution (verified against brc32 5.40):
    /// - If `STYLE` present: `style = explicit_value`. Else `style =
    ///   DIALOG_DEFAULT_STYLE` (0x80880000 = WS_POPUP|WS_BORDER|
    ///   WS_SYSMENU).
    /// - `CAPTION` present ⇒ `style |= WS_CAPTION` (0x00C00000).
    /// - `FONT` present ⇒ `style |= DS_SETFONT` (0x40).
    fn parse_dialog(&mut self) -> PResult<DialogResource> {
        let id = self.parse_resid_with_label("DIALOG resource id")?;
        // Eat DIALOG. DIALOGEX is rejected loudly — the writer cannot emit
        // DLGTEMPLATEEX (G-future-4) and the prior behaviour of silently
        // emitting classic DLGTEMPLATE bytes for a DIALOGEX source violated
        // the "never silently wrong" central discipline (MAJOR-2 from the
        // Phase G review).
        match self.peek_kind() {
            TokenKind::Keyword(Keyword::Dialog) => {
                self.advance();
            }
            TokenKind::Keyword(Keyword::DialogEx) => {
                let t = self.peek().clone();
                return self.err_at(
                    "DIALOGEX is not supported (mdbcc Phase G v1); use DIALOG \
                     instead — DLGTEMPLATEEX is tracked as G-future-4"
                        .to_string(),
                    t.line,
                    t.col,
                );
            }
            _ => {
                let t = self.peek();
                return self.err_at(
                    format!("expected DIALOG, found {}", describe_kind(&t.kind)),
                    t.line,
                    t.col,
                );
            }
        }

        // Required: x, y, cx, cy as a comma-separated list (commas are
        // optional in brc32, as elsewhere).
        let x = self.parse_i16_with_label("DIALOG x")?;
        self.eat_optional_comma();
        let y = self.parse_i16_with_label("DIALOG y")?;
        self.eat_optional_comma();
        let cx = self.parse_i16_with_label("DIALOG cx")?;
        self.eat_optional_comma();
        let cy = self.parse_i16_with_label("DIALOG cy")?;

        // Optional pre-BEGIN statements in any order.
        let mut style: Option<u32> = None;
        let mut ex_style: u32 = 0;
        let mut caption: Option<String> = None;
        let mut font: Option<(u16, String)> = None;
        let mut menu: Option<ResRef> = None;
        let mut class: Option<ResRef> = None;
        let mut flags = MemoryFlags::default();
        let mut language: Option<Language> = None;

        loop {
            match self.peek_kind() {
                TokenKind::Keyword(Keyword::Style) => {
                    self.advance();
                    style = Some(self.parse_style_expr_with_label("STYLE")?);
                }
                TokenKind::Keyword(Keyword::ExStyle) => {
                    self.advance();
                    ex_style = self.parse_style_expr_with_label("EXSTYLE")?;
                }
                TokenKind::Keyword(Keyword::Caption) => {
                    self.advance();
                    caption = Some(self.expect_string_with_label("CAPTION")?);
                }
                TokenKind::Keyword(Keyword::Font) => {
                    self.advance();
                    let pt = self.parse_u16_with_label("FONT point size")?;
                    self.eat_optional_comma();
                    let typeface = self.expect_string_with_label("FONT typeface")?;
                    font = Some((pt, typeface));
                }
                TokenKind::Keyword(Keyword::Menu) => {
                    self.advance();
                    menu = Some(self.parse_resref_with_label("MENU")?);
                }
                TokenKind::Keyword(Keyword::Class) => {
                    self.advance();
                    class = Some(self.parse_resref_with_label("CLASS")?);
                }
                TokenKind::Keyword(Keyword::Language) => {
                    language = Some(self.parse_language_stmt()?);
                }
                TokenKind::Keyword(Keyword::Discardable) => {
                    flags.discardable = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Preload) => {
                    flags.preload = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Loadoncall) => {
                    flags.loadoncall = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Moveable) => {
                    flags.moveable = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Fixed) => {
                    flags.fixed = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Begin) => break,
                _ => {
                    let t = self.peek();
                    return self.err_at(
                        format!(
                            "expected DIALOG statement (STYLE/EXSTYLE/CAPTION/FONT/MENU/CLASS/LANGUAGE) or BEGIN, found {}",
                            describe_kind(&t.kind)
                        ),
                        t.line,
                        t.col,
                    );
                }
            }
        }

        // Resolve the dialog style per brc32's observed rules.
        let mut resolved_style = style.unwrap_or(DIALOG_DEFAULT_STYLE);
        if caption.is_some() {
            resolved_style |= WS_CAPTION;
        }
        if font.is_some() {
            resolved_style |= DS_SETFONT;
        }

        self.expect_keyword(Keyword::Begin, "BEGIN")?;
        let mut controls = Vec::new();
        loop {
            match self.peek_kind() {
                TokenKind::Keyword(Keyword::End) => {
                    self.advance();
                    return Ok(DialogResource {
                        id,
                        flags,
                        language,
                        x,
                        y,
                        cx,
                        cy,
                        style: resolved_style,
                        ex_style,
                        caption,
                        font,
                        menu,
                        class,
                        controls,
                    });
                }
                TokenKind::Eof => {
                    let t = self.peek();
                    return self.err_at(
                        "unexpected end of file in DIALOG; expected END".to_string(),
                        t.line,
                        t.col,
                    );
                }
                _ => {
                    controls.push(self.parse_dialog_control()?);
                }
            }
        }
    }

    /// Parse a single control statement (PUSHBUTTON / DEFPUSHBUTTON /
    /// LTEXT / RTEXT / CTEXT / EDITTEXT / GROUPBOX / generic CONTROL).
    fn parse_dialog_control(&mut self) -> PResult<DialogControl> {
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Keyword(Keyword::PushButton) => {
                self.advance();
                self.parse_text_control(STYLE_PUSHBUTTON, ControlClass::Predefined(CC_BUTTON))
            }
            TokenKind::Keyword(Keyword::DefPushButton) => {
                self.advance();
                self.parse_text_control(STYLE_DEFPUSHBUTTON, ControlClass::Predefined(CC_BUTTON))
            }
            TokenKind::Keyword(Keyword::LText) => {
                self.advance();
                self.parse_text_control(STYLE_LTEXT, ControlClass::Predefined(CC_STATIC))
            }
            TokenKind::Keyword(Keyword::RText) => {
                self.advance();
                self.parse_text_control(STYLE_RTEXT, ControlClass::Predefined(CC_STATIC))
            }
            TokenKind::Keyword(Keyword::CText) => {
                self.advance();
                self.parse_text_control(STYLE_CTEXT, ControlClass::Predefined(CC_STATIC))
            }
            TokenKind::Keyword(Keyword::GroupBox) => {
                self.advance();
                self.parse_text_control(STYLE_GROUPBOX, ControlClass::Predefined(CC_BUTTON))
            }
            TokenKind::Keyword(Keyword::Icon) => {
                self.advance();
                self.parse_icon_control()
            }
            TokenKind::Keyword(Keyword::EditText) => {
                self.advance();
                // EDITTEXT has no text in source — title is empty. id is
                // first.
                let id = self.parse_i16_with_label("EDITTEXT id")?;
                self.eat_optional_comma();
                let x = self.parse_i16_with_label("EDITTEXT x")?;
                self.eat_optional_comma();
                let y = self.parse_i16_with_label("EDITTEXT y")?;
                self.eat_optional_comma();
                let cx = self.parse_i16_with_label("EDITTEXT cx")?;
                self.eat_optional_comma();
                let cy = self.parse_i16_with_label("EDITTEXT cy")?;
                let (style, ex_style) = self.parse_optional_control_styles(STYLE_EDITTEXT)?;
                Ok(DialogControl {
                    text: ResRef::Name(String::new()),
                    id,
                    class: ControlClass::Predefined(CC_EDIT),
                    style,
                    ex_style,
                    x,
                    y,
                    cx,
                    cy,
                })
            }
            TokenKind::Keyword(Keyword::Control) => {
                self.advance();
                self.parse_generic_control()
            }
            _ => self.err_at(
                format!(
                    "expected dialog control (PUSHBUTTON, DEFPUSHBUTTON, LTEXT, RTEXT, CTEXT, EDITTEXT, GROUPBOX, ICON, CONTROL) or END, found {}",
                    describe_kind(&tok.kind)
                ),
                tok.line,
                tok.col,
            ),
        }
    }

    /// Parse a text-bearing shorthand control:
    /// `KW "text", id, x, y, cx, cy [, style [, exstyle]]`. The
    /// `default_style` and `class` come from the caller (one per
    /// shorthand keyword).
    fn parse_text_control(
        &mut self,
        default_style: u32,
        class: ControlClass,
    ) -> PResult<DialogControl> {
        let text = self.expect_string_with_label("control text")?;
        self.eat_optional_comma();
        let id = self.parse_i16_with_label("control id")?;
        self.eat_optional_comma();
        let x = self.parse_i16_with_label("control x")?;
        self.eat_optional_comma();
        let y = self.parse_i16_with_label("control y")?;
        self.eat_optional_comma();
        let cx = self.parse_i16_with_label("control cx")?;
        self.eat_optional_comma();
        let cy = self.parse_i16_with_label("control cy")?;
        let (style, ex_style) = self.parse_optional_control_styles(default_style)?;
        Ok(DialogControl {
            text: ResRef::Name(text),
            id,
            class,
            style,
            ex_style,
            x,
            y,
            cx,
            cy,
        })
    }

    /// Parse an `ICON` shorthand control:
    /// `ICON "resname", id, x, y, cx, cy [, style [, exstyle]]`.
    /// brc32 emits it as a STATIC-class control whose title is the icon
    /// resource name string and whose class-specific style bit is SS_ICON.
    fn parse_icon_control(&mut self) -> PResult<DialogControl> {
        let text = self.parse_resref_with_label("ICON resource")?;
        self.eat_optional_comma();
        let id = self.parse_i16_with_label("ICON id")?;
        self.eat_optional_comma();
        let x = self.parse_i16_with_label("ICON x")?;
        self.eat_optional_comma();
        let y = self.parse_i16_with_label("ICON y")?;
        self.eat_optional_comma();
        let cx = self.parse_i16_with_label("ICON cx")?;
        self.eat_optional_comma();
        let cy = self.parse_i16_with_label("ICON cy")?;
        let (style, ex_style) = self.parse_optional_control_styles(STYLE_ICON)?;
        Ok(DialogControl {
            text,
            id,
            class: ControlClass::Predefined(CC_STATIC),
            style,
            ex_style,
            x,
            y,
            cx,
            cy,
        })
    }

    /// Parse the generic `CONTROL "text", id, "class"-or-ord, style, x,
    /// y, cx, cy [, exstyle]` form. brc32 case-insensitively normalises
    /// the class string to its ordinal when it matches one of the
    /// predefined classes (BUTTON/EDIT/STATIC/LISTBOX/SCROLLBAR/
    /// COMBOBOX); a user class becomes a UserClass string verbatim.
    fn parse_generic_control(&mut self) -> PResult<DialogControl> {
        // text — a string OR a numeric ordinal (for ICON-like title forms).
        let text = self.parse_resref_with_label("CONTROL text")?;
        self.eat_optional_comma();
        let id = self.parse_i16_with_label("CONTROL id")?;
        self.eat_optional_comma();
        // class — a string (predefined or user) or a numeric ordinal.
        let class_tok = self.peek().clone();
        let class = match class_tok.kind {
            TokenKind::Str(s) => {
                self.advance();
                match classify_class_name(&s) {
                    Some(ord) => ControlClass::Predefined(ord),
                    None => ControlClass::UserClass(s),
                }
            }
            TokenKind::Int(v) => {
                self.advance();
                let ord = u16::try_from(v).map_err(|_| RcError {
                    message: format!("CONTROL class ordinal {v} out of range for u16"),
                    line: class_tok.line,
                    col: class_tok.col,
                })?;
                ControlClass::Predefined(ord)
            }
            other => {
                return self.err_at(
                    format!(
                        "expected CONTROL class (string or integer), found {}",
                        describe_kind(&other)
                    ),
                    class_tok.line,
                    class_tok.col,
                );
            }
        };
        self.eat_optional_comma();
        let style = self.parse_style_expr_with_label("CONTROL style")?;
        self.eat_optional_comma();
        let x = self.parse_i16_with_label("CONTROL x")?;
        self.eat_optional_comma();
        let y = self.parse_i16_with_label("CONTROL y")?;
        self.eat_optional_comma();
        let cx = self.parse_i16_with_label("CONTROL cx")?;
        self.eat_optional_comma();
        let cy = self.parse_i16_with_label("CONTROL cy")?;
        // Optional trailing exstyle.
        let mut ex_style: u32 = 0;
        if matches!(self.peek_kind(), TokenKind::Comma) {
            self.advance();
            // After a trailing comma, an EXSTYLE u32 may follow. If the
            // next token is the next statement's keyword or END, treat
            // the comma as syntactic noise (no exstyle). Otherwise parse
            // the u32.
            if matches!(self.peek_kind(), TokenKind::Int(_) | TokenKind::Ident(_)) {
                ex_style = self.parse_style_expr_with_label("CONTROL exstyle")?;
            }
        }
        Ok(DialogControl {
            text,
            id,
            class,
            style,
            ex_style,
            x,
            y,
            cx,
            cy,
        })
    }

    /// Parse the optional `[, style [, exstyle]]` tail of a shorthand
    /// control. With an explicit style, brc32 keeps the user's window-style
    /// expression verbatim and ORs in only the shorthand class bits
    /// (`BS_DEFPUSHBUTTON`, `SS_ICON`, etc.). It does not force
    /// `WS_CHILD|WS_TABSTOP`; RAILC.RC's LTEXT controls prove that profile.
    fn parse_optional_control_styles(&mut self, default_style: u32) -> PResult<(u32, u32)> {
        // No comma → no override.
        if !matches!(self.peek_kind(), TokenKind::Comma) {
            return Ok((default_style, 0));
        }
        self.advance();
        // After the comma, expect an integer; if the next token is the
        // next control's keyword, treat the comma as noise.
        if !matches!(self.peek_kind(), TokenKind::Int(_) | TokenKind::Ident(_)) {
            return Ok((default_style, 0));
        }
        let user_style = self.parse_style_expr_with_label("control style")?;
        let style = user_style | (default_style & 0x0000_FFFF);
        let mut ex_style = 0;
        if matches!(self.peek_kind(), TokenKind::Comma) {
            self.advance();
            if matches!(self.peek_kind(), TokenKind::Int(_) | TokenKind::Ident(_)) {
                ex_style = self.parse_style_expr_with_label("control exstyle")?;
            }
        }
        Ok((style, ex_style))
    }

    /// Read a `u32` style expression: integer/known-symbol terms separated
    /// by `|`. `.rc` STYLE fields are bitmasks, and Borland brc has the
    /// common WS_/DS_/BS_/SS_ symbols built in even when no Windows header is
    /// included.
    fn parse_style_expr_with_label(&mut self, label: &str) -> PResult<u32> {
        let mut value = self.parse_style_term_with_label(label)?;
        while matches!(self.peek_kind(), TokenKind::Pipe) {
            self.advance();
            value |= self.parse_style_term_with_label(label)?;
        }
        Ok(value)
    }

    fn parse_style_term_with_label(&mut self, label: &str) -> PResult<u32> {
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Int(v) => {
                self.advance();
                Ok(v)
            }
            TokenKind::Ident(name) => {
                self.advance();
                style_symbol_value(&name).ok_or_else(|| RcError {
                    message: format!("unknown style symbol `{name}` in {label}"),
                    line: tok.line,
                    col: tok.col,
                })
            }
            other => self.err_at(
                format!(
                    "expected integer or style symbol for {label}, found {}",
                    describe_kind(&other)
                ),
                tok.line,
                tok.col,
            ),
        }
    }

    /// Read a signed-i16 integer literal. brc32 accepts `-1` for "no id";
    /// the lexer represents that as a wrapped u32, and this helper narrows
    /// it back to the Win32 16-bit signed field.
    fn parse_i16_with_label(&mut self, label: &str) -> PResult<i16> {
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Int(v) => {
                self.advance();
                // Wrap u32 → i16 via the u16 path (Win32 dialog units are
                // 16-bit signed). Accept the full u16 range, plus wrapped
                // negative literals produced by the lexer (`-1` =
                // 0xffff_ffff) when they fit in i16.
                if v <= u16::MAX as u32 {
                    Ok(v as i16)
                } else if v >= 0xFFFF_8000 {
                    Ok((v as i32) as i16)
                } else {
                    self.err_at(
                        format!("{label}: value {v} out of range for i16/u16"),
                        tok.line,
                        tok.col,
                    )
                }
            }
            other => self.err_at(
                format!(
                    "expected integer for {label}, found {}",
                    describe_kind(&other)
                ),
                tok.line,
                tok.col,
            ),
        }
    }

    /// Consume one identifier matching `expected` case-insensitively.
    fn expect_ident_ci(&mut self, expected: &str, what: &str) -> PResult<()> {
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Ident(s) if ident_eq(&s, expected) => {
                self.advance();
                Ok(())
            }
            other => self.err_at(
                format!("expected {what}, found {}", describe_kind(&other)),
                tok.line,
                tok.col,
            ),
        }
    }

    /// Consume one string literal, returning its UTF-8 contents.
    fn expect_string_with_label(&mut self, what: &str) -> PResult<String> {
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Str(s) => {
                self.advance();
                Ok(s)
            }
            other => self.err_at(
                format!(
                    "expected string literal for {what}, found {}",
                    describe_kind(&other)
                ),
                tok.line,
                tok.col,
            ),
        }
    }

    /// Parse a `MENU`/`CLASS`/CONTROL-text resource reference — either an
    /// integer ordinal or a string name.
    fn parse_resref_with_label(&mut self, what: &str) -> PResult<ResRef> {
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Int(v) => {
                self.advance();
                let ord = u16::try_from(v).map_err(|_| RcError {
                    message: format!("{what} ordinal {v} out of range for u16"),
                    line: tok.line,
                    col: tok.col,
                })?;
                Ok(ResRef::Numeric(ord))
            }
            TokenKind::Str(s) => {
                self.advance();
                Ok(ResRef::Name(s))
            }
            other => self.err_at(
                format!(
                    "expected integer or string for {what}, found {}",
                    describe_kind(&other)
                ),
                tok.line,
                tok.col,
            ),
        }
    }

    /// Parse a top-level resource id/name. Numeric ids remain ordinals;
    /// bare identifiers and quoted strings become named resources.
    fn parse_resid_with_label(&mut self, what: &str) -> PResult<ResId> {
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Int(v) => {
                self.advance();
                let ord = u16::try_from(v).map_err(|_| RcError {
                    message: format!("{what}: ordinal {v} out of range for u16"),
                    line: tok.line,
                    col: tok.col,
                })?;
                Ok(ResId::Ord(ord))
            }
            TokenKind::Ident(s) | TokenKind::Str(s) => {
                self.advance();
                Ok(ResId::Name(s))
            }
            other => self.err_at(
                format!(
                    "expected integer or name for {what}, found {}",
                    describe_kind(&other)
                ),
                tok.line,
                tok.col,
            ),
        }
    }

    /// Shared helper for MENU/ACCELERATORS: parse any prefix of memory
    /// flags and/or a LANGUAGE statement until BEGIN. STRINGTABLE has its
    /// own bespoke loop because its surrounding logic differs; here we
    /// just keep the two G4 resources symmetric and small.
    fn parse_optional_flags_and_language(
        &mut self,
        flags: &mut MemoryFlags,
        language: &mut Option<Language>,
        what: &str,
    ) -> PResult<()> {
        loop {
            match self.peek_kind() {
                TokenKind::Keyword(Keyword::Discardable) => {
                    flags.discardable = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Preload) => {
                    flags.preload = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Loadoncall) => {
                    flags.loadoncall = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Moveable) => {
                    flags.moveable = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Fixed) => {
                    flags.fixed = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Language) => {
                    *language = Some(self.parse_language_stmt()?);
                }
                TokenKind::Keyword(Keyword::Begin) => return Ok(()),
                _ => {
                    let t = self.peek();
                    return self.err_at(
                        format!(
                            "expected {what} flag, LANGUAGE, or BEGIN, found {}",
                            describe_kind(&t.kind)
                        ),
                        t.line,
                        t.col,
                    );
                }
            }
        }
    }

    /// Read one integer token and range-check it to `u16` (the natural
    /// width for resource ids and language ids). `label` names the slot
    /// for diagnostics.
    fn parse_u16_with_label(&mut self, label: &str) -> PResult<u16> {
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Int(v) => {
                self.advance();
                u16::try_from(v).map_err(|_| RcError {
                    message: format!("{label}: value {v} out of range for u16 (0..=65535)"),
                    line: tok.line,
                    col: tok.col,
                })
            }
            other => self.err_at(
                format!(
                    "expected integer for {label}, found {}",
                    describe_kind(&other)
                ),
                tok.line,
                tok.col,
            ),
        }
    }

    /// Read one integer token as a `u32`. VERSIONINFO fixed fields use this
    /// width and may be written with an `L` suffix, which the lexer already
    /// strips.
    fn parse_u32_with_label(&mut self, label: &str) -> PResult<u32> {
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::Int(v) => {
                self.advance();
                Ok(v)
            }
            other => self.err_at(
                format!(
                    "expected integer for {label}, found {}",
                    describe_kind(&other)
                ),
                tok.line,
                tok.col,
            ),
        }
    }
}

/// Render a [`TokenKind`] for diagnostics. Kept terse — the messages
/// follow the C parser's house style (cf. `src/parser.rs:108`).
fn describe_kind(k: &TokenKind) -> String {
    match k {
        TokenKind::Ident(s) => format!("identifier `{s}`"),
        TokenKind::Keyword(kw) => format!("keyword `{}`", keyword_name(*kw)),
        TokenKind::Int(v) => format!("integer {v}"),
        TokenKind::Str(_) => "string literal".to_string(),
        TokenKind::RawHex(_) => "raw-hex literal".to_string(),
        TokenKind::Comma => "`,`".to_string(),
        TokenKind::Pipe => "`|`".to_string(),
        TokenKind::Eof => "end of file".to_string(),
    }
}

fn keyword_name(kw: Keyword) -> &'static str {
    match kw {
        Keyword::StringTable => "STRINGTABLE",
        Keyword::Begin => "BEGIN",
        Keyword::End => "END",
        Keyword::Language => "LANGUAGE",
        Keyword::Discardable => "DISCARDABLE",
        Keyword::Preload => "PRELOAD",
        Keyword::Moveable => "MOVEABLE",
        Keyword::Loadoncall => "LOADONCALL",
        Keyword::Fixed => "FIXED",
        Keyword::Menu => "MENU",
        Keyword::MenuItem => "MENUITEM",
        Keyword::Popup => "POPUP",
        Keyword::Separator => "SEPARATOR",
        Keyword::Accelerators => "ACCELERATORS",
        Keyword::VirtKey => "VIRTKEY",
        Keyword::Ascii => "ASCII",
        Keyword::Control => "CONTROL",
        Keyword::Shift => "SHIFT",
        Keyword::Alt => "ALT",
        Keyword::NoInvert => "NOINVERT",
        Keyword::Dialog => "DIALOG",
        Keyword::DialogEx => "DIALOGEX",
        Keyword::Style => "STYLE",
        Keyword::ExStyle => "EXSTYLE",
        Keyword::Caption => "CAPTION",
        Keyword::Font => "FONT",
        Keyword::Class => "CLASS",
        Keyword::PushButton => "PUSHBUTTON",
        Keyword::DefPushButton => "DEFPUSHBUTTON",
        Keyword::LText => "LTEXT",
        Keyword::RText => "RTEXT",
        Keyword::CText => "CTEXT",
        Keyword::EditText => "EDITTEXT",
        Keyword::GroupBox => "GROUPBOX",
        Keyword::Icon => "ICON",
        Keyword::Bitmap => "BITMAP",
        Keyword::RcData => "RCDATA",
        Keyword::VersionInfo => "VERSIONINFO",
        Keyword::Grayed => "GRAYED",
        Keyword::Inactive => "INACTIVE",
        Keyword::Checked => "CHECKED",
        Keyword::MenuBarBreak => "MENUBARBREAK",
        Keyword::MenuBreak => "MENUBREAK",
        Keyword::Help => "HELP",
    }
}

fn ident_eq(found: &str, expected: &str) -> bool {
    found.eq_ignore_ascii_case(expected)
}

fn cook_ico_payload(raw: &[u8], ordinal: u16, line: u32, col: u32) -> PResult<(Vec<u8>, Vec<u8>)> {
    if raw.len() < 22 {
        return rc_data_err(
            "ICON data is too short for ICONDIR + ICONDIRENTRY",
            line,
            col,
        );
    }
    let reserved = read_u16(raw, 0);
    let kind = read_u16(raw, 2);
    let count = read_u16(raw, 4);
    if reserved != Some(0) || kind != Some(1) || count != Some(1) {
        return rc_data_err("only single-image ICO resources are supported", line, col);
    }

    let width = raw[6];
    let height = raw[7];
    let color_count = raw[8];
    let reserved_byte = raw[9];
    let bytes_in_res =
        read_u32(raw, 14).ok_or_else(|| rc_data_error("ICON entry is truncated", line, col))?;
    let image_offset =
        read_u32(raw, 18).ok_or_else(|| rc_data_error("ICON entry is truncated", line, col))?;
    let start = usize::try_from(image_offset)
        .map_err(|_| rc_data_error("ICON image offset is out of range", line, col))?;
    let len = usize::try_from(bytes_in_res)
        .map_err(|_| rc_data_error("ICON image size is out of range", line, col))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| rc_data_error("ICON image range overflows", line, col))?;
    if end > raw.len() {
        return rc_data_err("ICON image range runs past end of data", line, col);
    }
    let image_data = raw[start..end].to_vec();
    if image_data.len() < 16 {
        return rc_data_err(
            "ICON image is too short for BITMAPINFOHEADER fields",
            line,
            col,
        );
    }
    let planes = read_u16(&image_data, 12)
        .ok_or_else(|| rc_data_error("ICON image missing planes field", line, col))?;
    let bit_count = read_u16(&image_data, 14)
        .ok_or_else(|| rc_data_error("ICON image missing bit-count field", line, col))?;

    let mut group_data = Vec::with_capacity(20);
    push_u16(&mut group_data, 0);
    push_u16(&mut group_data, 1);
    push_u16(&mut group_data, 1);
    group_data.push(width);
    group_data.push(height);
    group_data.push(color_count);
    group_data.push(reserved_byte);
    push_u16(&mut group_data, planes);
    push_u16(&mut group_data, bit_count);
    push_u32(&mut group_data, bytes_in_res);
    push_u16(&mut group_data, ordinal);

    Ok((image_data, group_data))
}

fn cook_bmp_payload(raw: &[u8], line: u32, col: u32) -> PResult<Vec<u8>> {
    if raw.len() < 38 {
        return rc_data_err("BITMAP data is too short for BITMAPFILEHEADER", line, col);
    }
    if raw.get(0..2) != Some(b"BM") {
        return rc_data_err("BITMAP data must start with BM", line, col);
    }
    let bf_off_bits = read_u32(raw, 10)
        .ok_or_else(|| rc_data_error("BITMAP file header is truncated", line, col))?;
    if bf_off_bits < 14 {
        return rc_data_err("BITMAP bfOffBits is before the DIB header", line, col);
    }
    let bi_size_image = read_u32(raw, 34)
        .ok_or_else(|| rc_data_error("BITMAP info header is truncated", line, col))?;
    let effective_size_image = if bi_size_image == 0 {
        compute_bmp_size_image(raw, line, col)?
    } else {
        bi_size_image
    };
    let payload_len_u32 = (bf_off_bits - 14)
        .checked_add(effective_size_image)
        .ok_or_else(|| rc_data_error("BITMAP payload size overflows", line, col))?;
    let payload_len = usize::try_from(payload_len_u32)
        .map_err(|_| rc_data_error("BITMAP payload is too large", line, col))?;
    let end = 14usize
        .checked_add(payload_len)
        .ok_or_else(|| rc_data_error("BITMAP payload range overflows", line, col))?;
    if end > raw.len() {
        return rc_data_err("BITMAP payload range runs past end of data", line, col);
    }
    let mut data = raw[14..end].to_vec();
    if bi_size_image == 0 {
        data[20..24].copy_from_slice(&effective_size_image.to_le_bytes());
    }
    Ok(data)
}

fn compute_bmp_size_image(raw: &[u8], line: u32, col: u32) -> PResult<u32> {
    let dib_size = read_u32(raw, 14)
        .ok_or_else(|| rc_data_error("BITMAP info header is truncated", line, col))?;
    if dib_size < 40 {
        return rc_data_err(
            "BITMAPCOREHEADER size-image inference is unsupported",
            line,
            col,
        );
    }
    let width =
        read_i32(raw, 18).ok_or_else(|| rc_data_error("BITMAP width is truncated", line, col))?;
    let height =
        read_i32(raw, 22).ok_or_else(|| rc_data_error("BITMAP height is truncated", line, col))?;
    let planes =
        read_u16(raw, 26).ok_or_else(|| rc_data_error("BITMAP planes is truncated", line, col))?;
    let bit_count = read_u16(raw, 28)
        .ok_or_else(|| rc_data_error("BITMAP bit-count is truncated", line, col))?;
    let compression = read_u32(raw, 30)
        .ok_or_else(|| rc_data_error("BITMAP compression is truncated", line, col))?;
    if planes != 1 {
        return rc_data_err("BITMAP planes must be 1", line, col);
    }
    if compression != 0 {
        return rc_data_err(
            "compressed BITMAP with zero biSizeImage is unsupported",
            line,
            col,
        );
    }
    if width <= 0 {
        return rc_data_err("BITMAP width must be positive", line, col);
    }
    let height_abs = height
        .checked_abs()
        .ok_or_else(|| rc_data_error("BITMAP height is out of range", line, col))?;
    let row_bits = (width as u64)
        .checked_mul(bit_count as u64)
        .ok_or_else(|| rc_data_error("BITMAP row size overflows", line, col))?;
    let row_bytes = row_bits.div_ceil(32) * 4;
    let image_bytes = row_bytes
        .checked_mul(height_abs as u64)
        .ok_or_else(|| rc_data_error("BITMAP image size overflows", line, col))?;
    u32::try_from(image_bytes)
        .map_err(|_| rc_data_error("BITMAP image size is too large", line, col))
}

fn read_u16(bytes: &[u8], off: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(off..off + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_i32(bytes: &[u8], off: usize) -> Option<i32> {
    let raw: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn rc_data_err<T>(message: &str, line: u32, col: u32) -> PResult<T> {
    Err(rc_data_error(message, line, col))
}

fn rc_data_error(message: &str, line: u32, col: u32) -> RcError {
    RcError {
        message: message.to_string(),
        line,
        col,
    }
}

fn style_symbol_value(name: &str) -> Option<u32> {
    Some(match name.to_ascii_uppercase().as_str() {
        "WS_POPUP" => 0x8000_0000,
        "WS_CHILD" => 0x4000_0000,
        "WS_VISIBLE" => 0x1000_0000,
        "WS_CAPTION" => 0x00C0_0000,
        "WS_SYSMENU" => 0x0008_0000,
        "WS_GROUP" => 0x0002_0000,
        "WS_TABSTOP" => 0x0001_0000,
        "DS_MODALFRAME" => 0x0000_0080,
        "BS_AUTOCHECKBOX" => 0x0000_0003,
        "BS_AUTORADIOBUTTON" => 0x0000_0009,
        "BS_GROUPBOX" => 0x0000_0007,
        "SS_BLACKRECT" => 0x0000_0004,
        "SS_ICON" => 0x0000_0003,
        _ => return None,
    })
}

/// brc32 normalises these well-known class strings (case-insensitively)
/// into their ordinal form. Returns the ordinal when the input matches;
/// otherwise `None` means the string is a user-defined class and the
/// caller should preserve it verbatim.
fn classify_class_name(s: &str) -> Option<u16> {
    match s.to_ascii_lowercase().as_str() {
        "button" => Some(CC_BUTTON),
        "edit" => Some(CC_EDIT),
        "static" => Some(CC_STATIC),
        "listbox" => Some(CC_LISTBOX),
        "scrollbar" => Some(CC_SCROLLBAR),
        "combobox" => Some(CC_COMBOBOX),
        _ => None,
    }
}
