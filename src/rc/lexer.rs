//! Lexer for `.rc` (Win32 resource compiler) syntax — G1 subset.
//!
//! The `.rc` grammar this scans:
//!
//! - **Identifiers / keywords** — ASCII letters / digits / underscore.
//!   Keyword recognition is **case-insensitive** (`STRINGTABLE` ≡
//!   `stringtable` ≡ `StringTable`), matching brc32 and rc.exe.
//! - **Numeric literals** — decimal `123` or hex `0x7F` / `0X7F`. v1
//!   does not need octal/binary/suffixed integers (rare in real `.rc`).
//! - **String literals** — `"…"` with C-style escapes (`\n` `\t` `\r`
//!   `\\` `\"` `\NNN` octal `\xHH` hex). Adjacent literals are *not*
//!   concatenated at the lexer level (the parser does that if needed —
//!   `.rc` only uses single literals for STRINGTABLE entries).
//! - **Comments** — `//` line and `/* */` block, identical to C.
//! - **Punctuation** — only `,` is meaningful in G1 (between flags and
//!   between id/value pairs).
//! - **Whitespace** — spaces / tabs / newlines all collapse to nothing.
//!   Newlines are not significant: blocks are delimited by `BEGIN`/`END`,
//!   not by line breaks (this mirrors brc32 / rc.exe behaviour).
//!
//! Mirrors the C lexer's shape: a streaming byte scanner producing
//! `(TokenKind, line, col)` tuples, ending in `TokenKind::Eof`. Stays
//! separate from `src/lexer.rs` so `.rc` tokens never enter the C
//! namespace.

use super::RcError;

/// One `.rc` token plus its 1-based source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub line: u32,
    pub col: u32,
}

/// The classified content of a `.rc` token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    /// User identifier (e.g. a future `#define`d symbol). Stored
    /// case-preserved; keyword lookup folds case before classification.
    Ident(String),
    /// Reserved word recognised in the G1 keyword set.
    Keyword(Keyword),
    /// Integer literal. `.rc` IDs are typically 16-bit but the lexer
    /// is permissive — range-check happens in the parser.
    Int(u32),
    /// String literal contents with escapes resolved (UTF-8 / 8-bit
    /// bytes accepted; converted to UTF-16LE by the writer).
    Str(String),
    /// W5 (rc gap 3): Borland single-quoted RAW-HEX data — `'00 01 FF'`,
    /// one line of an inline ICON/BITMAP/RCDATA body. Decoded byte pairs.
    RawHex(Vec<u8>),
    /// Comma `,`.
    Comma,
    /// Pipe `|`. Used as a bitwise-OR separator in MENUITEM trailing flag
    /// expressions (e.g. `GRAYED | INACTIVE`). brc32 accepts both `,` and
    /// `|` interchangeably in that position.
    Pipe,
    /// End of input. Always the final token.
    Eof,
}

/// Reserved words recognised in the G1+G4 subset. Matched
/// case-insensitively against any identifier the scanner produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keyword {
    StringTable,
    Begin,
    End,
    Language,
    Discardable,
    Preload,
    Moveable,
    Loadoncall,
    Fixed,
    // ---- G4 additions: MENU / ACCELERATORS ----
    Menu,
    MenuItem,
    Popup,
    Separator,
    Accelerators,
    VirtKey,
    Ascii,
    Control,
    Shift,
    Alt,
    NoInvert,
    // ---- G5a additions: DIALOG ----
    /// `DIALOG` — classic DLGTEMPLATE.
    Dialog,
    /// `DIALOGEX` — DLGTEMPLATEEX. Parsed but writer rejects (G-future-4).
    DialogEx,
    /// `STYLE <u32>` — dialog or control style.
    Style,
    /// `EXSTYLE <u32>` — extended style.
    ExStyle,
    /// `CAPTION "string"` — title string; sets WS_CAPTION on the dialog
    /// style.
    Caption,
    /// `FONT <point>, "typeface"` — sets DS_SETFONT on the dialog style.
    Font,
    /// `CLASS <id-or-string>` — dialog's window class. Optional; default
    /// is "#32770" (the standard dialog class) when absent.
    Class,
    /// `PUSHBUTTON "text", id, x, y, cx, cy [, style [, exstyle]]` —
    /// shorthand for `CONTROL "text", id, "BUTTON",
    /// BS_PUSHBUTTON|WS_TABSTOP|WS_VISIBLE|WS_CHILD, x, y, cx, cy`.
    PushButton,
    /// `DEFPUSHBUTTON "text", id, ...` — same but `BS_DEFPUSHBUTTON`.
    DefPushButton,
    /// `LTEXT "text", id, x, y, cx, cy [, style [, exstyle]]` — static
    /// left-aligned text.
    LText,
    /// `RTEXT "text", id, x, y, cx, cy [, style [, exstyle]]` — static
    /// right-aligned text.
    RText,
    /// `CTEXT "text", id, x, y, cx, cy [, style [, exstyle]]` — static
    /// center-aligned text.
    CText,
    /// `EDITTEXT id, x, y, cx, cy [, style [, exstyle]]` — single-line
    /// edit control.
    EditText,
    /// `GROUPBOX "text", id, x, y, cx, cy [, style [, exstyle]]` —
    /// labeled group rectangle.
    GroupBox,
    /// `ICON "resname", id, x, y, cx, cy [, style [, exstyle]]` —
    /// shorthand static-icon control inside a DIALOG.
    Icon,
    /// Top-level `BITMAP` resource.
    Bitmap,
    /// Top-level `RCDATA` resource.
    RcData,
    /// Top-level `VERSIONINFO` resource.
    VersionInfo,
    // ---- MENUITEM / POPUP trailing flag keywords ----
    //
    // brc32-observed (5.40) constants for the optional MF_* identifiers
    // that may follow a MENUITEM's id (or a POPUP's text), separated by
    // `,` or `|`. Verified empirically — see `tests/corpus/rc/menu_flags.rc`
    // for the byte-exact differential. BITMAP is intentionally omitted
    // (requires bitmap-resource support which is G-future).
    /// `GRAYED` — MF_GRAYED = 0x0001.
    Grayed,
    /// `INACTIVE` — MF_DISABLED = 0x0002 (synonym semantics: the menu item
    /// is disabled but, unlike GRAYED, the text is rendered normally).
    Inactive,
    /// `CHECKED` — MF_CHECKED = 0x0008.
    Checked,
    /// `MENUBARBREAK` — MF_MENUBARBREAK = 0x0020.
    MenuBarBreak,
    /// `MENUBREAK` — MF_MENUBREAK = 0x0040.
    MenuBreak,
    /// `HELP` — MF_HELP = 0x4000.
    Help,
}

/// Byte-level streaming scanner producing [`Token`]s.
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    col: u32,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        Lexer {
            src,
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    /// Tokenize the whole input. The returned vector always ends with
    /// [`TokenKind::Eof`].
    pub fn tokenize(src: &'a [u8]) -> Result<Vec<Token>, RcError> {
        let mut lx = Lexer::new(src);
        let mut out = Vec::new();
        loop {
            let tok = lx.next_token()?;
            let is_eof = tok.kind == TokenKind::Eof;
            out.push(tok);
            if is_eof {
                return Ok(out);
            }
        }
    }

    // ---- low-level cursor -------------------------------------------------

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<u8> {
        self.src.get(self.pos + n).copied()
    }

    /// Advance one byte, maintaining line/column counters.
    fn bump(&mut self) -> Option<u8> {
        let b = self.src.get(self.pos).copied()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(b)
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, RcError> {
        Err(RcError {
            message: msg.into(),
            line: self.line,
            col: self.col,
        })
    }

    // ---- whitespace / comments -------------------------------------------

    /// Skip whitespace and both comment styles. Returns an error only on
    /// an unterminated block comment (matching the C lexer's behaviour).
    fn skip_trivia(&mut self) -> Result<(), RcError> {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') | Some(0x0b) | Some(0x0c) => {
                    self.bump();
                }
                Some(b'/') if self.peek_at(1) == Some(b'/') => {
                    self.bump();
                    self.bump();
                    while let Some(c) = self.peek() {
                        if c == b'\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some(b'/') if self.peek_at(1) == Some(b'*') => {
                    let (sl, sc) = (self.line, self.col);
                    self.bump();
                    self.bump();
                    loop {
                        match self.peek() {
                            None => {
                                return Err(RcError {
                                    message: "unterminated /* comment".into(),
                                    line: sl,
                                    col: sc,
                                });
                            }
                            Some(b'*') if self.peek_at(1) == Some(b'/') => {
                                self.bump();
                                self.bump();
                                break;
                            }
                            _ => {
                                self.bump();
                            }
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    // ---- main entry -------------------------------------------------------

    pub fn next_token(&mut self) -> Result<Token, RcError> {
        self.skip_trivia()?;
        let (line, col) = (self.line, self.col);
        let b = match self.peek() {
            None => {
                return Ok(Token {
                    kind: TokenKind::Eof,
                    line,
                    col,
                });
            }
            Some(b) => b,
        };

        if is_ident_start(b) {
            return Ok(self.lex_ident(line, col));
        }
        if b.is_ascii_digit() {
            return self.lex_number(line, col);
        }
        // W5 (rc gap 3): unary MINUS on an integer literal — RAILC.RC uses
        // control id -1 (emitted 0xFFFF) five times. Negate in u32
        // wrapping arithmetic (rc semantics are 16/32-bit two's complement).
        if b == b'-' && self.peek_at(1).is_some_and(|c| c.is_ascii_digit()) {
            self.bump(); // '-'
            let tok = self.lex_number(line, col)?;
            let TokenKind::Int(v) = tok.kind else {
                unreachable!()
            };
            return Ok(Token {
                kind: TokenKind::Int(v.wrapping_neg()),
                line,
                col,
            });
        }
        if b == b'"' {
            return self.lex_string(line, col);
        }
        // W5 (rc gap 3): Borland single-quoted RAW-HEX literal — `'00 01 FF'`
        // is a run of hex byte pairs (one inline-data line of an ICON/BITMAP
        // body in RAILC.RC).
        if b == b'\'' {
            return self.lex_raw_hex(line, col);
        }
        if b == b',' {
            self.bump();
            return Ok(Token {
                kind: TokenKind::Comma,
                line,
                col,
            });
        }
        if b == b'|' {
            self.bump();
            return Ok(Token {
                kind: TokenKind::Pipe,
                line,
                col,
            });
        }
        // W5 (rc gap 3): `{` / `}` are BEGIN/END aliases (RAILC.RC's
        // TB_MAINWIN inline bitmap uses the brace form).
        if b == b'{' {
            self.bump();
            return Ok(Token {
                kind: TokenKind::Keyword(Keyword::Begin),
                line,
                col,
            });
        }
        if b == b'}' {
            self.bump();
            return Ok(Token {
                kind: TokenKind::Keyword(Keyword::End),
                line,
                col,
            });
        }
        self.err(format!("unexpected character {:?}", b as char))
    }

    // ---- identifiers / keywords ------------------------------------------

    fn lex_ident(&mut self, line: u32, col: u32) -> Token {
        let start = self.pos;
        while self.peek().is_some_and(is_ident_continue) {
            self.bump();
        }
        // SAFETY of from_utf8: identifier bytes are all ASCII by
        // construction (is_ident_start / is_ident_continue).
        let text =
            std::str::from_utf8(&self.src[start..self.pos]).expect("invariant: ascii identifier");
        match keyword_lookup(text) {
            Some(kw) => Token {
                kind: TokenKind::Keyword(kw),
                line,
                col,
            },
            None => Token {
                kind: TokenKind::Ident(text.to_string()),
                line,
                col,
            },
        }
    }

    // ---- numbers ----------------------------------------------------------

    fn lex_number(&mut self, line: u32, col: u32) -> Result<Token, RcError> {
        // Hex `0x…` / `0X…`.
        if self.peek() == Some(b'0') && matches!(self.peek_at(1), Some(b'x') | Some(b'X')) {
            self.bump();
            self.bump();
            let ds = self.pos;
            while self.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                self.bump();
            }
            if self.pos == ds {
                return self.err("hexadecimal constant requires at least one digit");
            }
            let digits =
                std::str::from_utf8(&self.src[ds..self.pos]).expect("invariant: ascii hex digits");
            let value = u32::from_str_radix(digits, 16).map_err(|_| RcError {
                message: "integer constant out of range for u32".into(),
                line,
                col,
            })?;
            self.eat_int_suffix();
            return Ok(Token {
                kind: TokenKind::Int(value),
                line,
                col,
            });
        }

        // Plain decimal.
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.bump();
        }
        let digits = std::str::from_utf8(&self.src[start..self.pos])
            .expect("invariant: ascii decimal digits");
        let value = digits.parse::<u32>().map_err(|_| RcError {
            message: "integer constant out of range for u32".into(),
            line,
            col,
        })?;
        self.eat_int_suffix();
        Ok(Token {
            kind: TokenKind::Int(value),
            line,
            col,
        })
    }

    /// W5 (rc gap 3): consume an optional `L`/`l` integer suffix —
    /// RAILC.RC's VERSIONINFO writes `0x20L` / `0x0L` / `0x1L`. The value
    /// is unchanged (rc integers are 32-bit either way).
    fn eat_int_suffix(&mut self) {
        if matches!(self.peek(), Some(b'L') | Some(b'l')) {
            self.bump();
        }
    }

    /// W5 (rc gap 3): Borland single-quoted raw-hex literal — `'00 00 01 00'`
    /// (one line of an inline ICON/BITMAP data block). Whitespace-separated
    /// two-digit hex pairs between the quotes become raw bytes.
    fn lex_raw_hex(&mut self, line: u32, col: u32) -> Result<Token, RcError> {
        self.bump(); // opening '
        let mut bytes: Vec<u8> = Vec::new();
        let mut hi: Option<u8> = None;
        loop {
            match self.peek() {
                None => return self.err("unterminated raw-hex literal"),
                Some(b'\'') => {
                    self.bump();
                    break;
                }
                Some(c) if c.is_ascii_whitespace() => {
                    self.bump();
                }
                Some(c) if c.is_ascii_hexdigit() => {
                    self.bump();
                    let v = (c as char).to_digit(16).expect("hexdigit") as u8;
                    match hi.take() {
                        None => hi = Some(v),
                        Some(h) => bytes.push((h << 4) | v),
                    }
                }
                Some(c) => {
                    return self.err(format!(
                        "unexpected character {:?} in raw-hex literal",
                        c as char
                    ));
                }
            }
        }
        if hi.is_some() {
            return self.err("odd number of hex digits in raw-hex literal");
        }
        Ok(Token {
            kind: TokenKind::RawHex(bytes),
            line,
            col,
        })
    }

    // ---- string literals --------------------------------------------------

    fn lex_string(&mut self, line: u32, col: u32) -> Result<Token, RcError> {
        self.bump(); // opening "
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            match self.peek() {
                None => return self.err("unterminated string literal"),
                Some(b'\n') => return self.err("unterminated string literal"),
                Some(b'"') => {
                    self.bump();
                    break;
                }
                Some(b'\\') => {
                    // W5 (rc gap 2): an escape's VALUE is a LATIN-1 code
                    // point (ABOUTBOX.RC writes © as `\251` = 0xA9); encode
                    // it as UTF-8 so the buffer stays uniformly UTF-8 (the
                    // non-escape bytes already are — the byte front door
                    // transcoded them).
                    let v = self.lex_escape()?;
                    if v < 0x80 {
                        bytes.push(v);
                    } else {
                        let mut buf = [0u8; 4];
                        bytes.extend_from_slice((v as char).encode_utf8(&mut buf).as_bytes());
                    }
                }
                Some(_) => bytes.push(self.bump().expect("invariant: byte present")),
            }
        }
        // .rc source is conventionally Windows-1252 / OEM; the BYTE front
        // door (`rc::parse_bytes`) transcodes Latin-1 → UTF-8 before the
        // lexer runs, so any remaining invalid UTF-8 here is a real error.
        let value = String::from_utf8(bytes).map_err(|_| RcError {
            message: "non-UTF-8 bytes in string literal (v1: ASCII-7 only)".into(),
            line,
            col,
        })?;
        Ok(Token {
            kind: TokenKind::Str(value),
            line,
            col,
        })
    }

    /// Decode one escape sequence (cursor is on the backslash).
    fn lex_escape(&mut self) -> Result<u8, RcError> {
        self.bump(); // backslash
        let c = match self.peek() {
            None => return self.err("unterminated escape sequence"),
            Some(c) => c,
        };
        let v = match c {
            b'a' => {
                self.bump();
                0x07
            }
            b'b' => {
                self.bump();
                0x08
            }
            b'f' => {
                self.bump();
                0x0c
            }
            b'n' => {
                self.bump();
                b'\n'
            }
            b'r' => {
                self.bump();
                b'\r'
            }
            b't' => {
                self.bump();
                b'\t'
            }
            b'v' => {
                self.bump();
                0x0b
            }
            b'\\' => {
                self.bump();
                b'\\'
            }
            b'\'' => {
                self.bump();
                b'\''
            }
            b'"' => {
                self.bump();
                b'"'
            }
            b'?' => {
                self.bump();
                b'?'
            }
            b'0'..=b'7' => {
                // Octal — up to 3 digits.
                let mut val: u32 = 0;
                for _ in 0..3 {
                    match self.peek() {
                        Some(d @ b'0'..=b'7') => {
                            val = val * 8 + u32::from(d - b'0');
                            self.bump();
                        }
                        _ => break,
                    }
                }
                (val & 0xff) as u8
            }
            b'x' | b'X' => {
                self.bump();
                if !self.peek().is_some_and(|d| d.is_ascii_hexdigit()) {
                    return self.err("\\x used with no following hex digits");
                }
                let mut val: u32 = 0;
                while let Some(d) = self.peek() {
                    if !d.is_ascii_hexdigit() {
                        break;
                    }
                    val = val * 16 + (d as char).to_digit(16).expect("invariant: hex digit");
                    self.bump();
                }
                (val & 0xff) as u8
            }
            other => {
                // Unknown escape: keep the character verbatim (matches
                // brc32 / Borland, which only warns).
                self.bump();
                other
            }
        };
        Ok(v)
    }
}

fn is_ident_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

fn is_ident_continue(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

/// Case-insensitive keyword lookup. Compares ASCII-folded.
fn keyword_lookup(s: &str) -> Option<Keyword> {
    use Keyword::*;
    // ASCII fold-to-lowercase; allocate only on the (tiny) keyword path.
    let lower = s.to_ascii_lowercase();
    Some(match lower.as_str() {
        "stringtable" => StringTable,
        "begin" => Begin,
        "end" => End,
        "language" => Language,
        "discardable" => Discardable,
        "preload" => Preload,
        "moveable" => Moveable,
        "loadoncall" => Loadoncall,
        "fixed" => Fixed,
        // G4
        "menu" => Menu,
        "menuitem" => MenuItem,
        "popup" => Popup,
        "separator" => Separator,
        "accelerators" => Accelerators,
        "virtkey" => VirtKey,
        "ascii" => Ascii,
        "control" => Control,
        "shift" => Shift,
        "alt" => Alt,
        "noinvert" => NoInvert,
        // G5a
        "dialog" => Dialog,
        "dialogex" => DialogEx,
        "style" => Style,
        "exstyle" => ExStyle,
        "caption" => Caption,
        "font" => Font,
        "class" => Class,
        "pushbutton" => PushButton,
        "defpushbutton" => DefPushButton,
        "ltext" => LText,
        "rtext" => RText,
        "ctext" => CText,
        "edittext" => EditText,
        "groupbox" => GroupBox,
        "icon" => Icon,
        "bitmap" => Bitmap,
        "rcdata" => RcData,
        "versioninfo" => VersionInfo,
        // MENUITEM / POPUP trailing flag identifiers (G-fix-1 / MAJOR-1).
        "grayed" => Grayed,
        "inactive" => Inactive,
        "checked" => Checked,
        "menubarbreak" => MenuBarBreak,
        "menubreak" => MenuBreak,
        "help" => Help,
        _ => return None,
    })
}
