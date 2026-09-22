//! Lexical analysis for the Borland C/C++ dialect.
//!
//! Scope: ISO C89 token set, the core C++ (ARM-era) additions Borland C++
//! supported, and the headline Borland extension keywords (`near`, `far`,
//! `huge`, `__cdecl`, `__pascal`, `__fastcall`, `interrupt`, ...). The scanner
//! works on raw bytes: Borland-era source is effectively ASCII / OEM-codepage,
//! so identifiers are ASCII and string/char/comment bytes are passed through
//! verbatim. This matches the original compiler's behaviour and keeps the
//! scanner simple and fast.
//!
//! Maximal munch is used for operators (`>>=` beats `>>` beats `>`), and
//! `a+++b` lexes as `a ++ + b`, exactly as a conforming C tokenizer requires.
//!
//! Deferred (see scratchpad): full translation-phase-2 backslash-newline
//! splicing is only applied between tokens and inside string/char literals,
//! not mid-identifier. Float literals are kept as their raw lexeme; numeric
//! conversion (and Borland's 80-bit `long double`) happens later.

use std::fmt;

/// A lexed token plus its 1-based source position (of the first byte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub line: u32,
    pub col: u32,
    /// True if this is the first token of a logical source line (used by the
    /// preprocessor to find directives). `\`-newline continuations do *not*
    /// start a new logical line; comment-internal newlines do not either.
    pub start_of_line: bool,
}

impl Token {
    fn new(kind: TokenKind, line: u32, col: u32) -> Self {
        Token {
            kind,
            line,
            col,
            start_of_line: false,
        }
    }
}

/// The classified content of a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Ident(String),
    Keyword(Keyword),
    /// Integer constant, already converted, with C type-suffix flags.
    Int {
        value: u128,
        unsigned: bool,
        long: bool,
        longlong: bool,
    },
    /// Floating constant, kept as the original lexeme (parsed later).
    Float(String),
    /// Character constant. Multi-char constants pack big-endian, like Borland.
    Char {
        value: i64,
        wide: bool,
    },
    /// String literal bytes with escapes resolved (no implicit NUL appended).
    Str {
        bytes: Vec<u8>,
        wide: bool,
    },
    Punct(Punct),
    /// A single non-white-space byte that does not begin any other
    /// preprocessing-token — e.g. a lone `'` in directive free-text such as
    /// `#error Can't include both ...` (C89 §6.4: "each non-white-space
    /// character that cannot be one of the above" is itself a pp-token). The
    /// preprocessor treats it as ordinary line text; the parser rejects it
    /// (it never reaches parse in valid code).
    Other(u8),
    /// End of input. Always the final token.
    Eof,
}

/// Reserved words: C89, the core C++ additions Borland supported, and the
/// principal Borland extension keywords (both single- and double-underscore
/// spellings where Borland accepted both).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keyword {
    // --- C89 ---
    Auto,
    Break,
    Case,
    Char,
    Const,
    Continue,
    Default,
    Do,
    Double,
    Else,
    Enum,
    Extern,
    Float,
    For,
    Goto,
    If,
    Int,
    Long,
    Register,
    Return,
    Short,
    Signed,
    Sizeof,
    Static,
    Struct,
    Switch,
    Typedef,
    Union,
    Unsigned,
    Void,
    Volatile,
    While,
    // --- C++ (ARM-era subset Borland C++ implemented) ---
    // NB: `bool`, `true`, `false`, `mutable` are intentionally NOT keywords —
    // BC++ 4.52 predates them as reserved words, and CLASSLIB/COMPILER.H
    // unconditionally `#define`s BI_NO_BOOL / BI_NO_MUTABLE so CLASSLIB/DEFS.H
    // emulates them in the library: `enum TBool { false, true };`,
    // `typedef int bool;`, `#define mutable`. Treating them as keywords broke
    // exactly that (same rationale as `wchar_t` below). `bool` is provided as a
    // predefined typedef for header-free TUs; the Win32 target uses BC++'s
    // `int` spelling while the historical default path stays 1-byte
    // (see `Parser::new_for`).
    Asm,
    Catch,
    Class,
    ConstCast,
    Delete,
    DynamicCast,
    Explicit,
    Friend,
    Inline,
    Namespace,
    New,
    Operator,
    Private,
    Protected,
    Public,
    ReinterpretCast,
    StaticCast,
    Template,
    This,
    Throw,
    Try,
    Typeid,
    Typename,
    Using,
    Virtual,
    // --- Borland extensions (calling conventions / memory model / misc) ---
    Near,
    Far,
    Huge,
    Cdecl,
    Pascal,
    Interrupt,
    Fastcall,
    Stdcall,
    Export,
    Import,   // `_import` / `__import` (Borland dllimport qualifier)
    Asm2,     // `_asm` / `__asm` inline-assembly introducer
    Declspec, // `__declspec`
    Int8,
    Int16,
    Int32,
    Int64,
}

/// Punctuators and operators (full C / C++ set, including `::`, `.*`, `->*`,
/// `...`, and the preprocessing punctuators `#` and `##`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Punct {
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Semi,
    Comma,
    Dot,
    Arrow,
    Ellipsis,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Inc,
    Dec,
    Amp,
    Pipe,
    Caret,
    Tilde,
    Bang,
    Shl,
    Shr,
    Lt,
    Gt,
    Le,
    Ge,
    EqEq,
    Ne,
    AndAnd,
    OrOr,
    Assign,
    PlusEq,
    MinusEq,
    StarEq,
    SlashEq,
    PercentEq,
    AmpEq,
    PipeEq,
    CaretEq,
    ShlEq,
    ShrEq,
    Question,
    Colon,
    ColonColon,
    DotStar,
    ArrowStar,
    Hash,
    HashHash,
}

/// A lexer error with a human-readable message and 1-based position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    pub message: String,
    pub line: u32,
    pub col: u32,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: error: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for LexError {}

/// Tracks `#include` / `#import` directive context so the header-name that
/// follows is lexed as a literal header-name preprocessing token. Per the C
/// standard, a header-name's characters are taken verbatim — in particular `\`
/// is an ordinary path separator, NOT a string escape. Without this, a quoted
/// include such as `"classlib\vectimp.h"` would be escape-processed (`\v` → a
/// vertical tab 0x0B), silently corrupting the path to `classlib<VT>ectimp.h`
/// (the real Borland `STREAMBL.H` uses exactly this backslash form). See
/// [`Lexer::scan_token`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum HdrState {
    /// No directive context.
    None,
    /// The previous token was a `#` at start-of-line (a directive introducer).
    SawHash,
    /// `#include` / `#import` was just seen; a following `"..."` on the same
    /// line is a header-name and is lexed literally.
    ExpectHeader,
}

/// Streaming byte scanner that produces [`Token`]s.
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    col: u32,
    /// Set when a real (non-spliced) newline has been seen since the last
    /// token, so the next token begins a new logical line.
    bol: bool,
    /// `#include` header-name context (see [`HdrState`]).
    hdr: HdrState,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        Lexer {
            src,
            pos: 0,
            line: 1,
            col: 1,
            bol: true,
            hdr: HdrState::None,
        }
    }

    /// Tokenize the whole input. The returned vector always ends with
    /// [`TokenKind::Eof`].
    pub fn tokenize(src: &'a [u8]) -> Result<Vec<Token>, LexError> {
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

    /// If positioned on a `\<newline>` line-splice, consume it and return true.
    fn try_splice(&mut self) -> bool {
        if self.peek() == Some(b'\\') {
            match self.peek_at(1) {
                Some(b'\n') => {
                    self.bump();
                    self.bump();
                    return true;
                }
                Some(b'\r') if self.peek_at(2) == Some(b'\n') => {
                    self.bump();
                    self.bump();
                    self.bump();
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, LexError> {
        Err(LexError {
            message: msg.into(),
            line: self.line,
            col: self.col,
        })
    }

    // ---- whitespace & comments -------------------------------------------

    /// Skip whitespace, line splices, and both comment styles. Returns an
    /// error only on an unterminated block comment.
    fn skip_trivia(&mut self) -> Result<(), LexError> {
        loop {
            if self.try_splice() {
                continue;
            }
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') | Some(0x0b) | Some(0x0c) => {
                    if self.peek() == Some(b'\n') {
                        self.bol = true; // a real, non-spliced line break
                    }
                    self.bump();
                }
                Some(b'/') if self.peek_at(1) == Some(b'/') => {
                    // Line comment (C++ / Borland C). A spliced line continues it.
                    self.bump();
                    self.bump();
                    while let Some(c) = self.peek() {
                        if c == b'\n' {
                            break;
                        }
                        if !self.try_splice() {
                            self.bump();
                        }
                    }
                }
                Some(b'/') if self.peek_at(1) == Some(b'*') => {
                    let (sl, sc) = (self.line, self.col);
                    self.bump();
                    self.bump();
                    loop {
                        match self.peek() {
                            None => {
                                return Err(LexError {
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

    pub fn next_token(&mut self) -> Result<Token, LexError> {
        self.skip_trivia()?;
        let sol = std::mem::replace(&mut self.bol, false);
        let mut tok = self.scan_token()?;
        tok.start_of_line = sol;
        // Advance the `#include` header-name state machine for the NEXT token:
        // a `#` at start-of-line arms it, a following `include`/`import` on the
        // same line moves it to ExpectHeader (so `scan_token` lexes the next
        // `"..."` literally), and anything else clears it.
        self.hdr = match (&tok.kind, self.hdr) {
            (TokenKind::Punct(Punct::Hash), _) if sol => HdrState::SawHash,
            (TokenKind::Ident(s), HdrState::SawHash)
                if !sol && (s == "include" || s == "import") =>
            {
                HdrState::ExpectHeader
            }
            _ => HdrState::None,
        };
        Ok(tok)
    }

    fn scan_token(&mut self) -> Result<Token, LexError> {
        let (line, col) = (self.line, self.col);

        let b = match self.peek() {
            None => return Ok(Token::new(TokenKind::Eof, line, col)),
            // 0x1A (Ctrl-Z) is the DOS end-of-file marker. Borland's lexer
            // stops reading the source at it, and many real `\BC45\INCLUDE\`
            // headers carry a trailing 0x1A byte — so a token-start 0x1A is
            // logical EOF, not an unknown character. (Inside a string/char
            // literal it is ordinary data: `lex_string`/`lex_char` consume
            // bytes directly and never reach this dispatch.)
            Some(0x1A) => return Ok(Token::new(TokenKind::Eof, line, col)),
            Some(b) => b,
        };

        // `#include "..."` / `#include <...>` — lex the header-name VERBATIM (no
        // escape processing; `\` is a path separator here, not a string escape).
        // Both forms become a `Str` header-name token; `wide` marks the system
        // (`<...>`) form so `do_include` picks the right search path. This is what
        // lets real Borland source use backslash paths — `#include <owl\owlpch.h>`
        // (S4.2r), the form every OWL sample app and OBSOLETE header uses.
        if self.hdr == HdrState::ExpectHeader && b == b'"' {
            return self.lex_header_name_quoted(line, col);
        }
        if self.hdr == HdrState::ExpectHeader && b == b'<' {
            return self.lex_header_name_angle(line, col);
        }

        // Identifier / keyword, or a wide-prefixed literal (L'x' / L"...").
        if is_ident_start(b) {
            if b == b'L' {
                match self.peek_at(1) {
                    Some(b'\'') => {
                        self.bump();
                        return self.lex_char(true, line, col);
                    }
                    Some(b'"') => {
                        self.bump();
                        return self.lex_string(true, line, col);
                    }
                    _ => {}
                }
            }
            return Ok(self.lex_ident(line, col));
        }

        if b.is_ascii_digit() || (b == b'.' && self.peek_at(1).is_some_and(|c| c.is_ascii_digit()))
        {
            return self.lex_number(line, col);
        }

        if b == b'\'' {
            return self.lex_char(false, line, col);
        }
        if b == b'"' {
            return self.lex_string(false, line, col);
        }

        self.lex_punct(line, col)
    }

    // ---- identifiers / keywords ------------------------------------------

    fn lex_ident(&mut self, line: u32, col: u32) -> Token {
        let start = self.pos;
        while self.peek().is_some_and(is_ident_continue) {
            self.bump();
        }
        // SAFETY of from_utf8: identifier bytes are all ASCII by construction.
        let text = std::str::from_utf8(&self.src[start..self.pos])
            .expect("ascii identifier")
            .to_string();
        match keyword_lookup(&text) {
            Some(kw) => Token::new(TokenKind::Keyword(kw), line, col),
            None => Token::new(TokenKind::Ident(text), line, col),
        }
    }

    // ---- numbers ----------------------------------------------------------

    fn lex_number(&mut self, line: u32, col: u32) -> Result<Token, LexError> {
        let start = self.pos;

        // Hex / octal / decimal integer, unless a '.', 'e'/'E' exponent, or an
        // 'f'/'F'/'l'/'L' float suffix proves it is floating.
        let is_hex =
            self.peek() == Some(b'0') && matches!(self.peek_at(1), Some(b'x') | Some(b'X'));

        if is_hex {
            self.bump();
            self.bump();
            let ds = self.pos;
            while self.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                self.bump();
            }
            if self.pos == ds {
                return self.err("hexadecimal constant requires at least one digit");
            }
            let digits = std::str::from_utf8(&self.src[ds..self.pos]).unwrap();
            let value = u128::from_str_radix(digits, 16).map_err(|_| LexError {
                message: "integer constant out of range".into(),
                line,
                col,
            })?;
            let (u, l, ll) = self.int_suffix()?;
            return Ok(Token::new(
                TokenKind::Int {
                    value,
                    unsigned: u,
                    long: l,
                    longlong: ll,
                },
                line,
                col,
            ));
        }

        // Scan an optional integer part.
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.bump();
        }

        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.bump();
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.bump();
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.bump();
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.bump();
            }
            let ds = self.pos;
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.bump();
            }
            if self.pos == ds {
                return self.err("exponent has no digits");
            }
        }

        if is_float {
            if matches!(
                self.peek(),
                Some(b'f') | Some(b'F') | Some(b'l') | Some(b'L')
            ) {
                self.bump();
            }
            let lexeme = std::str::from_utf8(&self.src[start..self.pos])
                .unwrap()
                .to_string();
            return Ok(Token::new(TokenKind::Float(lexeme), line, col));
        }

        // Plain decimal or octal integer.
        let digits = std::str::from_utf8(&self.src[start..self.pos]).unwrap();
        let value = if digits.len() > 1 && digits.starts_with('0') {
            if let Some(bad) = digits.bytes().find(|c| !(b'0'..=b'7').contains(c)) {
                let _ = bad;
                return Err(LexError {
                    message: format!("invalid digit in octal constant: {digits}"),
                    line,
                    col,
                });
            }
            u128::from_str_radix(digits, 8).map_err(|_| LexError {
                message: "integer constant out of range".into(),
                line,
                col,
            })?
        } else {
            digits.parse::<u128>().map_err(|_| LexError {
                message: "integer constant out of range".into(),
                line,
                col,
            })?
        };
        let (u, l, ll) = self.int_suffix()?;
        Ok(Token::new(
            TokenKind::Int {
                value,
                unsigned: u,
                long: l,
                longlong: ll,
            },
            line,
            col,
        ))
    }

    /// Consume an optional integer suffix in any order/case: `u`, `l`, `ll`.
    fn int_suffix(&mut self) -> Result<(bool, bool, bool), LexError> {
        let (mut u, mut l, mut ll) = (false, false, false);
        loop {
            match self.peek() {
                Some(b'u') | Some(b'U') if !u => {
                    u = true;
                    self.bump();
                }
                Some(b'l') | Some(b'L') if !l && !ll => {
                    self.bump();
                    if matches!(self.peek(), Some(b'l') | Some(b'L')) {
                        self.bump();
                        ll = true;
                    } else {
                        l = true;
                    }
                }
                _ => break,
            }
        }
        Ok((u, l, ll))
    }

    // ---- character constants ---------------------------------------------

    fn lex_char(&mut self, wide: bool, line: u32, col: u32) -> Result<Token, LexError> {
        self.bump(); // opening '
        // Cursor immediately after the opening `'`. If no closing `'` is found
        // before end-of-line, this is not a character constant at all: the `'`
        // is a lone non-white-space pp-token (C89 §6.4) — common in directive
        // free-text like `#error Can't include ...`. We rewind to here so the
        // bytes after the `'` re-lex as ordinary tokens, and emit `Other('\'')`
        // for the stray quote. (A wide prefix `L'...` that fails the same way
        // also reduces to a stray `'`; the `L` was already lexed — here `L`
        // would have been consumed by the caller, leaving a lone `'`.)
        let (rb_pos, rb_line, rb_col, rb_bol) = (self.pos, self.line, self.col, self.bol);
        let mut value: i64 = 0;
        let mut count = 0;
        loop {
            self.try_splice();
            match self.peek() {
                None | Some(b'\n') => {
                    self.pos = rb_pos;
                    self.line = rb_line;
                    self.col = rb_col;
                    self.bol = rb_bol;
                    return Ok(Token::new(TokenKind::Other(b'\''), line, col));
                }
                Some(b'\'') => {
                    self.bump();
                    break;
                }
                Some(b'\\') => {
                    let byte = self.lex_escape()?;
                    value = (value << 8) | i64::from(byte);
                    count += 1;
                }
                Some(c) => {
                    self.bump();
                    value = (value << 8) | i64::from(c);
                    count += 1;
                }
            }
        }
        if count == 0 {
            return self.err("empty character constant");
        }
        // A single-character constant has type `int`; sign-extend from `char`
        // (Borland's default `char` is signed) to match its observable value.
        if count == 1 && !wide {
            value = i64::from(value as u8 as i8);
        }
        Ok(Token::new(TokenKind::Char { value, wide }, line, col))
    }

    // ---- string literals --------------------------------------------------

    /// Lex one string-literal fragment **plus** any adjacent fragments that
    /// follow (C89 §6.4.5 / translation phase 6 — performed at the lexer so
    /// the parser sees a single `Str` token). Mixing wide and narrow fragments
    /// is a constraint violation and an error.
    ///
    /// The `line`/`col` carried into the merged token are those of the FIRST
    /// fragment, matching standard diagnostic practice.
    fn lex_string(&mut self, wide: bool, line: u32, col: u32) -> Result<Token, LexError> {
        let mut bytes = self.lex_string_body()?;
        loop {
            // Peek across whitespace / comments / `\`-newline splices for an
            // adjacent fragment. `skip_trivia` is idempotent, so if no fragment
            // follows the next `next_token` call simply re-enters it as a no-op.
            self.skip_trivia()?;
            match self.peek() {
                Some(b'"') => {
                    if wide {
                        return self.err(
                            "adjacent string literals have mismatched encoding (wide + narrow)",
                        );
                    }
                    bytes.extend(self.lex_string_body()?);
                }
                Some(b'L') if self.peek_at(1) == Some(b'"') => {
                    if !wide {
                        return self.err(
                            "adjacent string literals have mismatched encoding (narrow + wide)",
                        );
                    }
                    self.bump(); // L
                    bytes.extend(self.lex_string_body()?);
                }
                _ => break,
            }
        }
        Ok(Token::new(TokenKind::Str { bytes, wide }, line, col))
    }

    /// Lex a quoted `#include "..."` header-name. Unlike [`Self::lex_string`],
    /// the body is taken VERBATIM: no escape decoding and no line splicing, so a
    /// path such as `classlib\vectimp.h` keeps its `\v` as two characters rather
    /// than collapsing to a vertical tab. Produces a [`TokenKind::Str`] so the
    /// preprocessor's existing quoted-include path consumes it unchanged. The
    /// cursor is on the opening quote.
    fn lex_header_name_quoted(&mut self, line: u32, col: u32) -> Result<Token, LexError> {
        self.bump(); // opening "
        let mut bytes = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'\n') => {
                    return self.err("unterminated header name in #include");
                }
                Some(b'"') => {
                    self.bump();
                    return Ok(Token::new(TokenKind::Str { bytes, wide: false }, line, col));
                }
                Some(_) => bytes.push(self.bump().unwrap()),
            }
        }
    }

    /// S4.2r: lex an angle `#include <...>` header-name. Like
    /// [`Self::lex_header_name_quoted`] the body is VERBATIM (a backslash path
    /// such as `owl\owlpch.h` keeps its `\o` as two characters), terminated by
    /// `>`. Marked `wide: true` so `do_include` resolves it as a SYSTEM header
    /// (a header-name token never carries a real wide-string meaning). The cursor
    /// is on the opening `<`.
    fn lex_header_name_angle(&mut self, line: u32, col: u32) -> Result<Token, LexError> {
        self.bump(); // opening <
        let mut bytes = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'\n') => {
                    return self.err("unterminated header name in #include");
                }
                Some(b'>') => {
                    self.bump();
                    return Ok(Token::new(TokenKind::Str { bytes, wide: true }, line, col));
                }
                Some(_) => bytes.push(self.bump().unwrap()),
            }
        }
    }

    /// Scan one `"..."` body. Cursor must be positioned on the opening quote;
    /// returns with the cursor just past the closing quote.
    fn lex_string_body(&mut self) -> Result<Vec<u8>, LexError> {
        self.bump(); // opening "
        let mut bytes = Vec::new();
        loop {
            self.try_splice();
            match self.peek() {
                None | Some(b'\n') => return self.err("unterminated string literal"),
                Some(b'"') => {
                    self.bump();
                    return Ok(bytes);
                }
                Some(b'\\') => bytes.push(self.lex_escape()?),
                Some(_) => bytes.push(self.bump().unwrap()),
            }
        }
    }

    /// Decode one escape sequence (cursor is on the backslash). Unknown
    /// escapes keep the escaped character verbatim, matching Borland (which
    /// only warns).
    fn lex_escape(&mut self) -> Result<u8, LexError> {
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
            b'x' => {
                self.bump();
                if !self.peek().is_some_and(|d| d.is_ascii_hexdigit()) {
                    return self.err("\\x used with no following hex digits");
                }
                let mut val: u32 = 0;
                while let Some(d) = self.peek() {
                    if !d.is_ascii_hexdigit() {
                        break;
                    }
                    val = val * 16 + (d as char).to_digit(16).unwrap();
                    self.bump();
                }
                (val & 0xff) as u8
            }
            other => {
                // Unknown escape: keep the character verbatim.
                self.bump();
                other
            }
        };
        Ok(v)
    }

    // ---- punctuators / operators (maximal munch) -------------------------

    fn lex_punct(&mut self, line: u32, col: u32) -> Result<Token, LexError> {
        use Punct::*;
        let b0 = self.peek().unwrap();
        let b1 = self.peek_at(1);
        let b2 = self.peek_at(2);

        // Three-byte operators first (maximal munch).
        if let Some(p) = match (b0, b1, b2) {
            (b'.', Some(b'.'), Some(b'.')) => Some(Ellipsis),
            (b'<', Some(b'<'), Some(b'=')) => Some(ShlEq),
            (b'>', Some(b'>'), Some(b'=')) => Some(ShrEq),
            (b'-', Some(b'>'), Some(b'*')) => Some(ArrowStar),
            _ => None,
        } {
            self.bump();
            self.bump();
            self.bump();
            return Ok(Token::new(TokenKind::Punct(p), line, col));
        }

        // Two-byte operators.
        if let Some(p) = match (b0, b1) {
            (b'-', Some(b'>')) => Some(Arrow),
            (b'+', Some(b'+')) => Some(Inc),
            (b'-', Some(b'-')) => Some(Dec),
            (b'<', Some(b'<')) => Some(Shl),
            (b'>', Some(b'>')) => Some(Shr),
            (b'<', Some(b'=')) => Some(Le),
            (b'>', Some(b'=')) => Some(Ge),
            (b'=', Some(b'=')) => Some(EqEq),
            (b'!', Some(b'=')) => Some(Ne),
            (b'&', Some(b'&')) => Some(AndAnd),
            (b'|', Some(b'|')) => Some(OrOr),
            (b'+', Some(b'=')) => Some(PlusEq),
            (b'-', Some(b'=')) => Some(MinusEq),
            (b'*', Some(b'=')) => Some(StarEq),
            (b'/', Some(b'=')) => Some(SlashEq),
            (b'%', Some(b'=')) => Some(PercentEq),
            (b'&', Some(b'=')) => Some(AmpEq),
            (b'|', Some(b'=')) => Some(PipeEq),
            (b'^', Some(b'=')) => Some(CaretEq),
            (b':', Some(b':')) => Some(ColonColon),
            (b'.', Some(b'*')) => Some(DotStar),
            (b'#', Some(b'#')) => Some(HashHash),
            _ => None,
        } {
            self.bump();
            self.bump();
            return Ok(Token::new(TokenKind::Punct(p), line, col));
        }

        // One-byte punctuators.
        let p = match b0 {
            b'(' => LParen,
            b')' => RParen,
            b'{' => LBrace,
            b'}' => RBrace,
            b'[' => LBracket,
            b']' => RBracket,
            b';' => Semi,
            b',' => Comma,
            b'.' => Dot,
            b'+' => Plus,
            b'-' => Minus,
            b'*' => Star,
            b'/' => Slash,
            b'%' => Percent,
            b'&' => Amp,
            b'|' => Pipe,
            b'^' => Caret,
            b'~' => Tilde,
            b'!' => Bang,
            b'<' => Lt,
            b'>' => Gt,
            b'=' => Assign,
            b'?' => Question,
            b':' => Colon,
            b'#' => Hash,
            other => {
                return self.err(format!("unexpected character {:?}", other as char));
            }
        };
        self.bump();
        Ok(Token::new(TokenKind::Punct(p), line, col))
    }
}

fn is_ident_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

fn is_ident_continue(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

fn keyword_lookup(s: &str) -> Option<Keyword> {
    use Keyword::*;
    Some(match s {
        // C89
        "auto" => Auto,
        "break" => Break,
        "case" => Case,
        "char" => Char,
        "const" => Const,
        "continue" => Continue,
        "default" => Default,
        "do" => Do,
        "double" => Double,
        "else" => Else,
        "enum" => Enum,
        "extern" => Extern,
        "float" => Float,
        "for" => For,
        "goto" => Goto,
        "if" => If,
        "int" => Int,
        "long" => Long,
        "register" => Register,
        "return" => Return,
        "short" => Short,
        "signed" => Signed,
        "sizeof" => Sizeof,
        "static" => Static,
        "struct" => Struct,
        "switch" => Switch,
        "typedef" => Typedef,
        "union" => Union,
        "unsigned" => Unsigned,
        "void" => Void,
        "volatile" => Volatile,
        "while" => While,
        // C++ (ARM-era subset)
        "asm" => Asm,
        "catch" => Catch,
        "class" => Class,
        "const_cast" => ConstCast,
        "delete" => Delete,
        "dynamic_cast" => DynamicCast,
        "explicit" => Explicit,
        "friend" => Friend,
        "inline" => Inline,
        "namespace" => Namespace,
        "new" => New,
        "operator" => Operator,
        "private" => Private,
        "protected" => Protected,
        "public" => Public,
        "reinterpret_cast" => ReinterpretCast,
        "static_cast" => StaticCast,
        "template" => Template,
        "this" => This,
        "throw" => Throw,
        "try" => Try,
        "typeid" => Typeid,
        "typename" => Typename,
        "using" => Using,
        "virtual" => Virtual,
        // `bool`/`true`/`false`/`mutable` deliberately omitted — see `Keyword`.
        // NB: `wchar_t` is intentionally NOT a keyword. In C mode it is an
        // ordinary identifier the RTL headers `typedef`; in C++ it would be a
        // built-in type, but mdbcc does not yet implement wide-char types (no
        // parser arm ever consumed the old `WcharT` keyword), so classifying it
        // as a keyword only broke `typedef unsigned short wchar_t;` (STDDEF.H).
        // Borland extensions (single- and double-underscore spellings)
        "near" | "_near" | "__near" => Near,
        "far" | "_far" | "__far" => Far,
        "huge" | "_huge" | "__huge" => Huge,
        "cdecl" | "_cdecl" | "__cdecl" => Cdecl,
        "pascal" | "_pascal" | "__pascal" => Pascal,
        "interrupt" | "_interrupt" | "__interrupt" => Interrupt,
        "_fastcall" | "__fastcall" => Fastcall,
        "_stdcall" | "__stdcall" => Stdcall,
        "_export" | "__export" => Export,
        "_import" | "__import" => Import,
        "_asm" | "__asm" => Asm2,
        "__declspec" => Declspec,
        "__int8" => Int8,
        "__int16" => Int16,
        "__int32" => Int32,
        "__int64" => Int64,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tokenize, panicking on lexer error (test helper).
    fn lex(src: &str) -> Vec<TokenKind> {
        Lexer::tokenize(src.as_bytes())
            .expect("lex ok")
            .into_iter()
            .map(|t| t.kind)
            .collect()
    }

    fn lex_res(src: &str) -> Result<Vec<Token>, LexError> {
        Lexer::tokenize(src.as_bytes())
    }

    use Keyword as K;
    use Punct as P;
    use TokenKind::{Char, Eof, Float, Ident, Int, Str};

    #[test]
    fn empty_input_is_just_eof() {
        assert_eq!(lex(""), vec![Eof]);
        assert_eq!(lex("   \t\r\n  "), vec![Eof]);
    }

    #[test]
    fn comments_are_trivia() {
        assert_eq!(lex("// line comment\n  /* block\n comment */ "), vec![Eof]);
        assert_eq!(
            lex("a /* mid */ b // tail"),
            vec![Ident("a".into()), Ident("b".into()), Eof]
        );
    }

    #[test]
    fn unterminated_block_comment_errors() {
        let e = lex_res("/* no end").unwrap_err();
        assert!(e.message.contains("unterminated"));
    }

    #[test]
    fn identifiers_vs_keywords() {
        assert_eq!(
            lex("int foo _bar baz123 return"),
            vec![
                TokenKind::Keyword(K::Int),
                Ident("foo".into()),
                Ident("_bar".into()),
                Ident("baz123".into()),
                TokenKind::Keyword(K::Return),
                Eof
            ]
        );
    }

    #[test]
    fn borland_keywords() {
        assert_eq!(
            lex("far near huge __cdecl _pascal interrupt __fastcall __int64"),
            vec![
                TokenKind::Keyword(K::Far),
                TokenKind::Keyword(K::Near),
                TokenKind::Keyword(K::Huge),
                TokenKind::Keyword(K::Cdecl),
                TokenKind::Keyword(K::Pascal),
                TokenKind::Keyword(K::Interrupt),
                TokenKind::Keyword(K::Fastcall),
                TokenKind::Keyword(K::Int64),
                Eof
            ]
        );
    }

    #[test]
    fn integer_forms_and_suffixes() {
        assert_eq!(
            lex("0 7 42 0x1F 0Xbeef 010 0777 100u 100UL 5ll 9LLU"),
            vec![
                Int {
                    value: 0,
                    unsigned: false,
                    long: false,
                    longlong: false
                },
                Int {
                    value: 7,
                    unsigned: false,
                    long: false,
                    longlong: false
                },
                Int {
                    value: 42,
                    unsigned: false,
                    long: false,
                    longlong: false
                },
                Int {
                    value: 0x1F,
                    unsigned: false,
                    long: false,
                    longlong: false
                },
                Int {
                    value: 0xbeef,
                    unsigned: false,
                    long: false,
                    longlong: false
                },
                Int {
                    value: 0o10,
                    unsigned: false,
                    long: false,
                    longlong: false
                },
                Int {
                    value: 0o777,
                    unsigned: false,
                    long: false,
                    longlong: false
                },
                Int {
                    value: 100,
                    unsigned: true,
                    long: false,
                    longlong: false
                },
                Int {
                    value: 100,
                    unsigned: true,
                    long: true,
                    longlong: false
                },
                Int {
                    value: 5,
                    unsigned: false,
                    long: false,
                    longlong: true
                },
                Int {
                    value: 9,
                    unsigned: true,
                    long: false,
                    longlong: true
                },
                Eof
            ]
        );
    }

    #[test]
    fn bad_octal_digit_errors() {
        assert!(lex_res("0778").unwrap_err().message.contains("octal"));
    }

    #[test]
    fn float_forms() {
        let toks = lex("1.0 .5 1. 3.14f 1e10 2.5E-3 6.022e23 100L 100.L");
        assert_eq!(
            toks,
            vec![
                Float("1.0".into()),
                Float(".5".into()),
                Float("1.".into()),
                Float("3.14f".into()),
                Float("1e10".into()),
                Float("2.5E-3".into()),
                Float("6.022e23".into()),
                Int {
                    value: 100,
                    unsigned: false,
                    long: true,
                    longlong: false
                },
                Float("100.L".into()),
                Eof
            ]
        );
    }

    #[test]
    fn char_constants_and_escapes() {
        assert_eq!(
            lex(r"'a' '\n' '\0' '\x41' '\101' '\\' '\'' "),
            vec![
                Char {
                    value: 97,
                    wide: false
                },
                Char {
                    value: 10,
                    wide: false
                },
                Char {
                    value: 0,
                    wide: false
                },
                Char {
                    value: 0x41,
                    wide: false
                },
                Char {
                    value: 0o101,
                    wide: false
                },
                Char {
                    value: 92,
                    wide: false
                },
                Char {
                    value: 39,
                    wide: false
                },
                Eof
            ]
        );
    }

    #[test]
    fn signed_char_constant_sign_extends() {
        // 0xFF as signed char -> -1 (Borland's default char is signed).
        assert_eq!(
            lex(r"'\xff'"),
            vec![
                Char {
                    value: -1,
                    wide: false
                },
                Eof
            ]
        );
    }

    #[test]
    fn multichar_constant_packs_big_endian() {
        assert_eq!(
            lex("'AB'"),
            vec![
                Char {
                    value: 0x4142,
                    wide: false
                },
                Eof
            ]
        );
    }

    #[test]
    fn wide_char_and_string() {
        assert_eq!(
            lex(r#"L'A' L"hi""#),
            vec![
                Char {
                    value: 65,
                    wide: true
                },
                Str {
                    bytes: b"hi".to_vec(),
                    wide: true
                },
                Eof
            ]
        );
    }

    #[test]
    fn string_with_escapes() {
        // Two adjacent string literals concatenate per C89 §6.4.5 / translation
        // phase 6 — escapes are resolved fragment-locally, then bytes are joined.
        assert_eq!(
            lex(r#""tab\there\n" "quote\"inside""#),
            vec![
                Str {
                    bytes: b"tab\there\nquote\"inside".to_vec(),
                    wide: false
                },
                Eof
            ]
        );
    }

    #[test]
    fn adjacent_strings_concatenate() {
        // Two-way, three-way, multi-line via newline, comment between fragments,
        // and escape-survival across the join boundary.
        assert_eq!(
            lex(r#""ab" "cd""#),
            vec![
                Str {
                    bytes: b"abcd".to_vec(),
                    wide: false
                },
                Eof
            ]
        );
        assert_eq!(
            lex(r#""a" "b" "c""#),
            vec![
                Str {
                    bytes: b"abc".to_vec(),
                    wide: false
                },
                Eof
            ]
        );
        assert_eq!(
            lex("\"hello \"\n\"world\""),
            vec![
                Str {
                    bytes: b"hello world".to_vec(),
                    wide: false
                },
                Eof
            ]
        );
        assert_eq!(
            lex(r#""a" /* mid */ "b" // tail
"c""#),
            vec![
                Str {
                    bytes: b"abc".to_vec(),
                    wide: false
                },
                Eof
            ]
        );
        // \1 followed by "0" must remain two bytes (0x01, '0') — escape scope
        // is per-fragment, not across the join.
        assert_eq!(
            lex(r#""\1" "0""#),
            vec![
                Str {
                    bytes: vec![0x01, b'0'],
                    wide: false
                },
                Eof
            ]
        );
        // Single fragment unchanged (regression for the non-adjacent case).
        assert_eq!(
            lex(r#""solo""#),
            vec![
                Str {
                    bytes: b"solo".to_vec(),
                    wide: false
                },
                Eof
            ]
        );
    }

    #[test]
    fn adjacent_wide_strings_concatenate() {
        assert_eq!(
            lex(r#"L"ab" L"cd""#),
            vec![
                Str {
                    bytes: b"abcd".to_vec(),
                    wide: true
                },
                Eof
            ]
        );
    }

    #[test]
    fn mixed_narrow_wide_strings_error() {
        assert!(
            lex_res(r#""a" L"b""#)
                .unwrap_err()
                .message
                .contains("mismatched encoding")
        );
        assert!(
            lex_res(r#"L"a" "b""#)
                .unwrap_err()
                .message
                .contains("mismatched encoding")
        );
    }

    #[test]
    fn unterminated_string_and_char_error() {
        assert!(lex_res("\"oops").unwrap_err().message.contains("string"));
        // An *empty* `''` is still a hard error (a `'` immediately closed by a
        // `'` is a malformed char-constant, not free-text).
        assert!(lex_res("''").unwrap_err().message.contains("empty"));
    }

    #[test]
    fn lone_quote_in_directive_text_is_not_an_error() {
        use TokenKind::Other;
        // A `'` with no closing `'` before end-of-line is NOT a char constant;
        // per C89 §6.4 it is a lone non-white-space pp-token. The bytes after
        // it must re-lex normally (here: `Can` `'` `t`), so a `#error Can't ...`
        // line tokenizes instead of failing the whole file.
        assert_eq!(
            lex("Can't"),
            vec![Ident("Can".into()), Other(b'\''), Ident("t".into()), Eof]
        );
        // Bare trailing `'` at end of input.
        assert_eq!(lex("'a"), vec![Other(b'\''), Ident("a".into()), Eof]);
        // Rewind must restore line/column: the `x` after the newline keeps its
        // real position (the failed-char scan does not consume past the `'`).
        let toks = Lexer::tokenize(b"'a\nx").unwrap();
        assert_eq!(toks[0].kind, Other(b'\''));
        assert_eq!((toks[0].line, toks[0].col), (1, 1));
        assert_eq!(toks[1].kind, Ident("a".into()));
        assert_eq!((toks[2].line, toks[2].col), (2, 1)); // x, line 2

        // VALID char constants are completely unaffected (regression guard).
        assert_eq!(
            lex("'c'"),
            vec![
                Char {
                    value: 99,
                    wide: false
                },
                Eof
            ]
        );
        assert_eq!(
            lex(r"'\n'"),
            vec![
                Char {
                    value: 10,
                    wide: false
                },
                Eof
            ]
        );
        assert_eq!(
            lex(r"'\0'"),
            vec![
                Char {
                    value: 0,
                    wide: false
                },
                Eof
            ]
        );
        assert_eq!(
            lex("'AB'"),
            vec![
                Char {
                    value: 0x4142,
                    wide: false
                },
                Eof
            ]
        );
    }

    #[test]
    fn ctrl_z_is_logical_eof() {
        // 0x1A (Ctrl-Z) is the DOS end-of-file marker; Borland stops reading
        // at it. A token-start 0x1A is logical EOF, so a trailing marker (as
        // in many real \BC45\INCLUDE\ headers) tokenizes cleanly.
        // A trailing 0x1A after a normal token is logical EOF.
        assert_eq!(lex("abc\x1a"), vec![Ident("abc".into()), Eof]);
        // Bytes after the 0x1A are not read (DOS EOF semantics).
        assert_eq!(lex("a\x1ab"), vec![Ident("a".into()), Eof]);
        // A lone 0x1A is just EOF.
        assert_eq!(lex("\x1a"), vec![Eof]);
    }

    #[test]
    fn maximal_munch_operators() {
        assert_eq!(
            lex("a >>= b <<= c ... ->* .* :: ## # -> ++ -- && || <= >= == !="),
            vec![
                Ident("a".into()),
                TokenKind::Punct(P::ShrEq),
                Ident("b".into()),
                TokenKind::Punct(P::ShlEq),
                Ident("c".into()),
                TokenKind::Punct(P::Ellipsis),
                TokenKind::Punct(P::ArrowStar),
                TokenKind::Punct(P::DotStar),
                TokenKind::Punct(P::ColonColon),
                TokenKind::Punct(P::HashHash),
                TokenKind::Punct(P::Hash),
                TokenKind::Punct(P::Arrow),
                TokenKind::Punct(P::Inc),
                TokenKind::Punct(P::Dec),
                TokenKind::Punct(P::AndAnd),
                TokenKind::Punct(P::OrOr),
                TokenKind::Punct(P::Le),
                TokenKind::Punct(P::Ge),
                TokenKind::Punct(P::EqEq),
                TokenKind::Punct(P::Ne),
                Eof
            ]
        );
    }

    #[test]
    fn classic_aplusplusplusb() {
        // Must lex as: a ++ + b
        assert_eq!(
            lex("a+++b"),
            vec![
                Ident("a".into()),
                TokenKind::Punct(P::Inc),
                TokenKind::Punct(P::Plus),
                Ident("b".into()),
                Eof
            ]
        );
    }

    #[test]
    fn line_and_column_tracking() {
        let toks = Lexer::tokenize(b"int\n  x;").unwrap();
        assert_eq!((toks[0].line, toks[0].col), (1, 1)); // int
        assert_eq!((toks[1].line, toks[1].col), (2, 3)); // x
        assert_eq!((toks[2].line, toks[2].col), (2, 4)); // ;
    }

    #[test]
    fn backslash_newline_splices() {
        // Splice inside a string literal and as plain trivia.
        assert_eq!(
            lex("\"ab\\\ncd\"  x\\\ny"),
            vec![
                Str {
                    bytes: b"abcd".to_vec(),
                    wide: false
                },
                Ident("x".into()),
                Ident("y".into()),
                Eof
            ]
        );
    }

    #[test]
    fn realistic_function_snippet() {
        let src = "int main(void) {\n    return 42;\n}\n";
        assert_eq!(
            lex(src),
            vec![
                TokenKind::Keyword(K::Int),
                Ident("main".into()),
                TokenKind::Punct(P::LParen),
                TokenKind::Keyword(K::Void),
                TokenKind::Punct(P::RParen),
                TokenKind::Punct(P::LBrace),
                TokenKind::Keyword(K::Return),
                Int {
                    value: 42,
                    unsigned: false,
                    long: false,
                    longlong: false
                },
                TokenKind::Punct(P::Semi),
                TokenKind::Punct(P::RBrace),
                Eof
            ]
        );
    }
}
