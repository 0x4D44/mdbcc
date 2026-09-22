//! Recursive-descent parser for the supported C subset.
//!
//! Now type-aware: declaration specifiers (`void/char/short/int/long`,
//! `signed/unsigned`, `__intN`), declarators with `*` and `[N]`, function
//! definitions/prototypes, file-scope globals, plus the `&` `*` `[]` `sizeof`
//! cast `?:` `++`/`--` and compound-assignment operators. `struct`/`enum`/
//! `typedef` and function pointers are a later slice.

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::lexer::{Keyword, Punct, Token, TokenKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub line: u32,
    pub col: u32,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: error: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for ParseError {}

type PResult<T> = Result<T, ParseError>;
type ClassTemplateArgs = (Vec<Type>, Vec<Option<i64>>, Vec<String>, String);

pub struct Parser<'t> {
    toks: &'t [Token],
    pos: usize,
    /// Target pointer width in bytes (8 = Win64/LLP64, 4 = Win32/ILP32).
    /// Record layout (`layout`) and the cached sizes on `Type::Record` are
    /// computed with this width, so a pointer member / the polymorphic vptr
    /// occupies the target-correct number of bytes. Defaults to 8 via
    /// [`Parser::new`] — every Win64 caller (`parse`, the in-tree tests, the
    /// `compile_to_pe*` path) lays out exactly as before; the Win32 path uses
    /// [`Parser::parse_for`] / [`Parser::new_for`].
    ptr_bytes: usize,
    /// `struct`/`union` definitions (moved into the AST at the end).
    records: Vec<Record>,
    /// struct/union tag -> record id.
    tags: HashMap<String, usize>,
    /// typedef name -> aliased type.
    typedefs: HashMap<String, Type>,
    /// S4: function templates captured so far (`template<class T> …`).
    fn_templates: Vec<crate::ast::TemplateDecl>,
    /// G41 (OWL SIGNATUR.H): names of SKIPPED pointer-to-member-function
    /// templates whose body is exactly the identity `{ return pmf; }` — the
    /// response-table signature checkers (`v_Sig`, `v_U_SIZE_Sig`, …, 65 in
    /// SIGNATUR.H + DOCVIEW.H/OCFEVENT.H). bcc32 always inlines them (the
    /// Borland OWL libs contain NO `_Sig` symbols), so a use site
    /// `(TMyPMF)v_Sig(&Cls::Handler)` folds to its argument at parse time.
    /// Non-identity PMF templates stay unregistered (clean unknown-identifier,
    /// never a silent miscompile).
    pmf_identity_templates: std::collections::HashSet<String>,
    /// S4.2b: class templates captured so far, keyed by tag → registry index.
    class_templates: Vec<ClassTemplateDecl>,
    class_template_idx: HashMap<String, usize>,
    /// S4.2b: concrete instantiations done so far, keyed `Tag<argcodes>` →
    /// the concrete record id (so a repeated `Box<int>` reuses one record).
    class_inst_cache: HashMap<String, usize>,
    /// #57: instantiations that were made from a FORWARD-declared template
    /// (opaque, member-less) and FROZEN into a typedef before the body appeared
    /// — OWL/EVENTHAN.H `typedef TResponseTableEntry<GENERIC> …` (body at :97).
    /// Each is `(opaque_record_id, tag_token_pos, template_name)`. A post-parse
    /// pass (`complete_forward_instantiations`) replays from `tag_token_pos` once
    /// the body is registered and copies the concrete layout INTO the frozen id.
    pending_fwd_inst: Vec<(usize, usize, String)>,
    /// S4.2f: explicit FULL specializations declared without a parsed body yet,
    /// keyed by the same `Tag<argcodes>` form as `class_inst_cache`. A complete
    /// definition (`class TPointer<char> : … { … };`) is parsed into a concrete
    /// record and cached; a declaration-only specialization still makes a
    /// matching use fail cleanly rather than silently instantiating the primary.
    class_specializations: HashSet<String>,
    /// S6 (G1 Stage-1): record ids whose derivation involves a VIRTUAL base
    /// anywhere in the chain (`: virtual public ios` transitively). Used to
    /// reject MI over a virtual-inheritance hierarchy with a clean error (the
    /// flat model would duplicate the shared vbase — a silent miscompile).
    virtual_heritage: HashSet<usize>,
    /// S6 (G1 Stage-3): names of virtual bases that are SHARED in a diamond —
    /// reachable via 2+ distinct base paths from some class (the iostream `ios`
    /// / persistent-stream `pstream` joins). Computed by a one-shot token
    /// pre-scan of all class base-clauses. ONLY these get the vbptr/shared-tail
    /// layout; a SINGLE-path data-bearing virtual base (OWL `TWindow` under
    /// `TFrameWindow`/`TDialog`, never joined in railc) stays on the plain
    /// base-at-0 path — the working pre-Stage-3 behaviour.
    shared_vbase_names: HashSet<String>,
    /// S6 (#64): record ids whose body is fully parsed.
    defined_records: HashSet<usize>,
    /// S6 (#64): stack of enclosing class BARE tag names (cur_class is None
    /// during nested member parse), to build the scoped `Outer::Inner` key.
    class_nest: Vec<String>,
    /// S4 (#49): out-of-line template member-function definitions captured for
    /// replay at the matching class-template instantiation (see
    /// `OutOfLineMemberTmpl`).
    oolt_members: Vec<OutOfLineMemberTmpl>,
    /// S4.2c: active class-template instantiation depth. `instantiate_class_template`
    /// re-parses the captured body, and the cache entry is only written *after*
    /// that parse completes — so a body that uses its own injected-class-name as
    /// a TYPE (`omanip2<T1,T2>& p;`) would recurse without bound. This guard
    /// converts a runaway recursion into a clean error instead of a stack
    /// overflow. Legitimate nesting never approaches the limit.
    inst_depth: usize,
    /// S4.2c: when `operator_name` parses a user-defined CONVERSION operator
    /// (`operator void*`, `ios::operator void*`), the target type lands here so
    /// the declarator can set the function's RETURN type to it (the generic
    /// declarator path would otherwise leave the implicit-int from
    /// `decl_specifiers`). Set at `operator_name`'s top to `None`, populated only
    /// in the conversion arm, and consumed by `declarator` when the declared name
    /// is a conversion operator (`operator@…`). IOSTREAM.H's out-of-line
    /// `inline ios::operator void _FAR *()` needs this.
    conv_ret: Option<Type>,
    /// enum constant name -> value.
    enum_consts: HashMap<String, i64>,
    /// S4.2#35: declared static DATA members, `Tag::member` -> type. Populated
    /// when a `static T member;` is parsed (the type is otherwise dropped).
    /// Consulted at parse-end to emit an `extern` global for any that is
    /// REFERENCED (see `referenced_statics`) but not DEFINED in this TU.
    static_member_types: HashMap<String, Type>,
    /// S4.2#35: qualified `Tag::member` names seen in expression position
    /// (recorded by the qualified-id primary-expression branch). Intersected
    /// with `static_member_types` at parse-end — minus defined globals — to
    /// register the minimal set of extern static-member references (so an
    /// unreferenced static member never adds an undefined COFF symbol, keeping
    /// standalone PEs and the byte-identity baselines unperturbed).
    referenced_statics: std::collections::HashSet<String>,
    /// S2e: per-class member typedefs that alias a CLASS — `class_id ->
    /// (typedef name -> target record id)`. mdbcc's typedef map is otherwise
    /// flat (global), so the SAME member-typedef name declared in many classes
    /// (OWL's `typedef cls TMyClass;` in DECLARE_RESPONSE_TABLE) collides
    /// last-write-wins. A class-scoped reference like `&TMyClass::EvSize` (in
    /// `cls::__entries[]`) must resolve via the ENCLOSING class (`cur_class`),
    /// not the global alias. Consulted in the qualified-id primary branch.
    member_class_typedefs:
        std::collections::HashMap<usize, std::collections::HashMap<String, usize>>,
    /// S4.5: the TU contains at least one `dynamic_cast`. Kept as a semantic
    /// marker; vtable RTTI prefixes are now uniform across dynamic_cast and
    /// non-dynamic_cast TUs so weak folding cannot pick an incompatible layout.
    saw_dynamic_cast: bool,
    /// Set while a `typedef`-storage declaration is being parsed.
    is_typedef: bool,
    /// S4.2h: the most recent `decl_specifiers` saw `inline`. Captured at
    /// function-construction sites (in-class member bodies are inline regardless).
    is_inline: bool,
    /// S4.2o: the most recent `decl_specifiers` saw `static`. Read at the
    /// LOCAL-declaration site to mark a function-local `static` (static storage
    /// duration); at file scope `static` is internal-linkage and ignored here.
    is_static: bool,
    /// S4.2#39: the most recent `decl_specifiers` saw `const`. Captured at the
    /// global-construction site to record a `const int X = <const>` constant in
    /// `int_consts` (for folding it inside an AGGREGATE global initializer).
    is_const: bool,
    /// S4.2#39: file-scope `const int` constants (name -> value), recorded as
    /// they are parsed. Consulted ONLY to fold const-int Vars inside aggregate
    /// (`{...}`) global initializers (`static int a[]={X|Y,...}`) — NOT in
    /// general expressions (that would break byte-identity + `&const_int`).
    int_consts: HashMap<String, i64>,
    /// S2b.3: calling convention named by the most recent
    /// `decl_specifiers` (`__cdecl`/`__stdcall`/`__fastcall`/`__pascal`).
    /// Reset to `None` at the start of every `decl_specifiers` and read
    /// by the function-building sites right after the top-level call
    /// (mirrors the `is_typedef` flag). `None` ⇒ no convention keyword
    /// was written ⇒ target default applies.
    last_call_conv: Option<CallConv>,
    /// Lowered C++ member functions / constructors (appended at the end).
    cxx_funcs: Vec<Function>,
    /// Per-class info keyed by record id (C++ classes/structs with methods).
    classes: HashMap<usize, ClassInfo>,
    /// Record id of the class whose member body is being parsed.
    cur_class: Option<usize>,
    /// Names bound as params/locals in the function body being parsed (so
    /// they shadow class members during unqualified-name resolution).
    fn_locals: HashSet<String>,
    /// S5: types of in-scope local variables, recorded at each local
    /// declaration, so a constant-expression `sizeof(localVar)` (e.g. an array
    /// dimension `char buf[sizeof(tmpl)+8]`, OWL/MODULE.CPP) folds to the
    /// variable's byte size. Consulted in `const_expr` ONLY when `fn_locals`
    /// confirms the name is a current local, so stale cross-function entries are
    /// never used (no per-function clearing needed).
    local_var_types: HashMap<String, Type>,
    /// S6 (#64-adjacent): block-scope `const int X = <const>;` values, so a
    /// later `T arr[X]` / enum / bit-field width const-folds (OWL DOCMANAG.CPP
    /// `const int MaxViewCount = 25; TDocTemplate* tplList[MaxViewCount];`).
    /// Like `local_var_types`, consulted in `const_expr` ONLY when `fn_locals`
    /// confirms the name is a CURRENT local — stale cross-function entries are
    /// inert, so no per-function clearing is needed.
    local_int_consts: HashMap<String, i64>,
    /// Default-argument expressions parsed by the most recent `param_list`,
    /// one slot per parameter (`None` if that parameter has no default).
    param_defaults: Vec<Option<Expr>>,
    /// Parameter TYPES parsed by the most recent `param_list` (no implicit
    /// `this`), parallel to `param_defaults`. Captured into `overload_defaults`
    /// so a defaulted overload's record is keyed by its param types, not merely
    /// its arity (so it never leaks to a same-arity sibling).
    param_types: Vec<Type>,
    /// G19: LOCAL anonymous-union/struct member promotion — `member name ->
    /// hidden local name (`$anonu.N`)`. A declarator-less `union { A a; B b; };`
    /// in a function emits a hidden local of the anon record and registers each
    /// of its members here; `primary` rewrites a bare member use to
    /// `$anonu.N.member`. Accumulates globally (the counter keeps names unique);
    /// the rewrite is GATED on the hidden local being in the current `fn_locals`
    /// (which IS function-scoped), so a stale entry from another function is
    /// inert. Empty for any function with no local anonymous aggregate.
    anonu_promotions: HashMap<String, String>,
    anonu_counter: usize,
    /// Per-function default arguments, keyed by the function's final (for
    /// members, mangled) name; aligned to the full parameter list.
    fn_defaults: HashMap<String, Vec<Option<Expr>>>,
    /// S4.2av: collision-free per-OVERLOAD defaults — `(name, no-`this` param
    /// types, this-prefixed defaults)` appended for every defaulted definition
    /// (no last-wins collapse). Feeds `TranslationUnit::overload_defaults`.
    overload_defaults: Vec<OverloadDefault>,
    /// Tick 64 (J-13 v1): names of free functions whose **prototype** was
    /// declared variadic but whose definition we haven't seen yet (or which
    /// is external, e.g. an extern declaration). Codegen's caller-side
    /// variadic FP-to-GPR copy needs the variadic bit even when only the
    /// prototype is in scope; the bit is folded into the AST at
    /// `parse`-completion (see `parse()`'s post-pass) by toggling
    /// `Function::variadic` for any name that has a matching prototype but
    /// shipped a non-variadic definition (and vice-versa: a definition that
    /// is variadic IS the source of truth — no override).
    variadic_protos: HashSet<String>,
    /// S1b.7 (RED 3): free-function prototypes — `int foo(int);` with no
    /// trailing `{ ... }`. Pre-S1b.7 these were silently discarded. For
    /// C++-linkage protos (`extern int helper(Bar&)` in a `.cpp`), bcc32
    /// emits the mangled symbol (`@helper$qr3Bar`) as the EXTDEF, so a
    /// call to `helper` must use the same mangled name in mdbcc's COFF
    /// (else the O13 symbol-set parity check rejects).
    ///
    /// Stored as body-less `Function` values (parser uses the existing
    /// `Function` shape rather than introducing a new AST variant). The
    /// `c_linkage` flag is the default `false` until we wire `extern "C"`
    /// parsing — `compile_module` uses it to pick `borland_c_symbol`
    /// vs `overload_symbol` for the mangled-name registration.
    extern_protos: Vec<Function>,
    /// S3 (C++ §7.5): whether the declaration currently being parsed sits
    /// inside an enclosing `extern "C" { ... }` linkage-specification.
    /// Functions / prototypes declared while this is `true` acquire **C
    /// linkage** (`Function.c_linkage = true`), so the mangler emits `_name`
    /// rather than the `@name$q...` C++ form. `linkage_specification`
    /// save/restores it around each block, so arbitrary nesting — including
    /// the tolerated `extern "C"` inside `extern "C"`, and `extern "C++"`
    /// inside `extern "C"` (which turns C linkage back OFF for its scope) —
    /// is handled correctly. Always `false` at top level (the historical
    /// default for every function the parser builds).
    c_linkage: bool,
    /// W6 (G48): `#pragma startup` registrations — `(function, priority)` in
    /// source order, recorded from the preprocessor's `__mdbcc_startup__`
    /// splice and exported on [`TranslationUnit::startup_fns`].
    startup_fns: Vec<(String, u32)>,
}

impl ClassInfo {
    fn note_method(&mut self, name: String, is_static: bool, param_tys: Vec<Type>) {
        if is_static {
            self.static_methods.insert(name.clone());
            self.static_sigs.push((name.clone(), param_tys));
        } else {
            self.instance_methods.insert(name.clone());
        }
        self.methods.insert(name);
    }

    /// Every declared overload of `name` is static.
    fn static_only(&self, name: &str) -> bool {
        self.static_methods.contains(name) && !self.instance_methods.contains(name)
    }

    /// Is the out-of-line definition `name(params)` a static overload?
    fn is_static_overload(&self, name: &str, params: &[(String, Type)]) -> bool {
        self.static_only(name)
            || self.static_sigs.iter().any(|(n, tys)| {
                n == name
                    && tys.len() == params.len()
                    && tys.iter().zip(params).all(|(actual, (_, expected))| {
                        Parser::signature_types_match(actual, expected)
                    })
            })
    }
}

#[derive(Default, Clone)]
struct ClassInfo {
    tag: String,
    members: HashSet<String>,
    methods: HashSet<String>,
    /// Names with at least one `static` overload.
    static_methods: HashSet<String>,
    /// SEM-04: each static overload's declared param types, so a same-named
    /// non-static overload (OWL `TGdiBase::CheckValid(uint)` beside
    /// `static CheckValid(HANDLE, uint)`) keeps its implicit `this`.
    static_sigs: Vec<(String, Vec<Type>)>,
    /// Names with at least one non-static overload declared in the class body.
    instance_methods: HashSet<String>,
    has_ctor: bool,
    has_dtor: bool,
    /// Single public base class (record id), if any.
    base: Option<usize>,
    /// Methods declared in *this* class body, in declaration order (Phase B
    /// vtable construction). The dtor is recorded with `key == "~"`.
    decl_methods: Vec<MethodDecl>,
    /// S4.2(e): OWL DDVT message handlers declared in this class body —
    /// `(method_key, message_index)` for each `virtual void WMxxx(RTMessage) =
    /// [WM_FIRST + WM_xxx];`. Drives the synthesised dispatching `WindowProc`.
    ddvt_handlers: Vec<(String, i64)>,
}

/// A method as declared in a class body — enough to build the vtable.
#[derive(Clone)]
struct MethodDecl {
    /// Dispatch key: method name, or `"~"` for the destructor.
    key: String,
    /// Mangled symbol if this class defines/overrides it (`Tag::name` /
    /// `Tag::~Tag`); ignored for pure declarations.
    sym: String,
    /// Explicit parameter types, excluding the implicit `this`.
    params: Vec<Type>,
    /// Trailing `const` qualifier on the member function.
    const_method: bool,
    /// This declaration occupies or overrides a virtual slot.
    virtual_: bool,
    /// Pure (`= 0`) — abstract, no definition.
    pure: bool,
}

/// S4.2b(ii): a captured class template, ready to instantiate. The body is held
/// as a token SPAN `[start, ..)` into the parser's input (the cursor on the
/// `class`/`struct`/`union` keyword); instantiation re-parses it with the type
/// parameters bound to concrete types. `is_union` selects the `record_specifier`
/// variant.
#[derive(Clone)]
struct ClassTemplateDecl {
    params: Vec<String>,
    /// S6 (#22): per-parameter kind — `true` = TYPE parameter (`class T`),
    /// `false` = NON-TYPE (value) parameter (`TWidthHeight widthOrHeight`,
    /// `int N`). Parallel to `params`. A value parameter binds an integer
    /// constant at instantiation (via `enum_consts`), not a typedef.
    type_param: Vec<bool>,
    tag: String,
    is_union: bool,
    start: usize,
    /// S4.2f: a FORWARD declaration (`template<class T> class TRE;`) with no body
    /// captured yet. The name is registered so a use site (typedef/pointer)
    /// recognises it as a template, but instantiation yields an opaque incomplete
    /// record (there is nothing to replay). A later full definition with the same
    /// tag overwrites this entry with `forward: false` and a real `start`.
    forward: bool,
}

/// S4 (#49): an OUT-OF-LINE template member-function definition captured for
/// replay — `template<class T,...> ret Tag<T,...>::member(...) { ... }`
/// (CLASSLIB's VECTIMP.H `void TMVectorImp<T,Alloc>::ForEach(...)`). The generic
/// body cannot be emitted standalone (its params are dependent); it is replayed
/// (cursor-jumped, params bound to concrete args) when `Tag<args>` is
/// instantiated, producing a concrete member function on that instance.
#[derive(Clone)]
struct OutOfLineMemberTmpl {
    /// The def's own template params (`["T","Alloc"]`), bound positionally to
    /// the instantiation's type arguments at replay.
    params: Vec<String>,
    /// The qualifier class-template tag (`TMVectorImp`) — matched against the
    /// tag of the class template being instantiated.
    tag: String,
    /// Token index of the definition start (the return-type token), where the
    /// replay re-enters `external_declaration`.
    start: usize,
}

impl<'t> Parser<'t> {
    /// Construct a parser with the Win64 (8-byte) pointer model — the
    /// historical default. Equivalent to `new_for(toks, 8)`.
    pub fn new(toks: &'t [Token]) -> Self {
        Parser::new_for(toks, 8)
    }

    /// Construct a parser laying records out for a target whose pointer width
    /// is `ptr_bytes` (8 = Win64, 4 = Win32). See the `ptr_bytes` field.
    pub fn new_for(toks: &'t [Token], ptr_bytes: usize) -> Self {
        // BC++ 4.52 has no native `bool` (CLASSLIB/COMPILER.H `#define`s
        // BI_NO_BOOL and CLASSLIB/DEFS.H emulates it with `typedef int bool;`).
        // `bool` is therefore an ordinary identifier here, not a keyword. The
        // Win32/Borland target predefines that spelling as `int` so inherited
        // virtual signatures match legacy `BOOL` overrides before headers are
        // replayed; the historical default Win64 path keeps the 1-byte type.
        // A real `typedef ... bool;` still overrides this entry.
        let mut typedefs: HashMap<String, Type> = HashMap::new();
        let bool_ty = if ptr_bytes == 4 {
            Type::int()
        } else {
            Type::Int {
                bytes: 1,
                signed: false,
            }
        };
        typedefs.insert("bool".to_string(), bool_ty);
        // `wchar_t` is likewise not a keyword (see lexer): C-mode RTL headers
        // `typedef unsigned short wchar_t;`, but the C++-mode headers assume the
        // compiler provides it (e.g. STDLIB.H `mbstowcs(wchar_t*, ...)`).
        // Predefine it as BC++'s 2-byte type; a real typedef just overrides it.
        typedefs.insert(
            "wchar_t".to_string(),
            Type::Int {
                bytes: 2,
                signed: false,
            },
        );
        Parser {
            toks,
            pos: 0,
            ptr_bytes,
            records: Vec::new(),
            tags: HashMap::new(),
            typedefs,
            fn_templates: Vec::new(),
            pmf_identity_templates: std::collections::HashSet::new(),
            class_templates: Vec::new(),
            class_template_idx: HashMap::new(),
            class_inst_cache: HashMap::new(),
            pending_fwd_inst: Vec::new(),
            class_specializations: HashSet::new(),
            virtual_heritage: HashSet::new(),
            shared_vbase_names: scan_shared_vbases(toks),
            defined_records: HashSet::new(),
            class_nest: Vec::new(),
            oolt_members: Vec::new(),
            inst_depth: 0,
            conv_ret: None,
            enum_consts: HashMap::new(),
            static_member_types: HashMap::new(),
            referenced_statics: HashSet::new(),
            member_class_typedefs: HashMap::new(),
            saw_dynamic_cast: false,
            is_const: false,
            int_consts: HashMap::new(),
            is_typedef: false,
            is_inline: false,
            is_static: false,
            last_call_conv: None,
            cxx_funcs: Vec::new(),
            classes: HashMap::new(),
            cur_class: None,
            fn_locals: HashSet::new(),
            local_var_types: HashMap::new(),
            local_int_consts: HashMap::new(),
            param_defaults: Vec::new(),
            param_types: Vec::new(),
            anonu_promotions: HashMap::new(),
            anonu_counter: 0,
            fn_defaults: HashMap::new(),
            overload_defaults: Vec::new(),
            variadic_protos: HashSet::new(),
            extern_protos: Vec::new(),
            c_linkage: false,
            startup_fns: Vec::new(),
        }
    }

    /// Struct-field alignment ceiling (the `#pragma pack` cap) for the active
    /// target. Win64 (`ptr_bytes == 8`) uses **natural** alignment (no cap);
    /// Win32 (`ptr_bytes == 4`) uses bcc32 4.52's default **byte** alignment
    /// (`1`). See [`layout`]'s `max_align` doc.
    fn max_align(&self) -> usize {
        if self.ptr_bytes >= 8 { usize::MAX } else { 1 }
    }

    /// Record default-argument expressions (from the latest `param_list`) for
    /// `name`. `this_prefixed` accounts for the injected `this` parameter on
    /// C++ members so the defaults stay aligned to the full parameter list.
    fn note_defaults(&mut self, name: &str, this_prefixed: bool) {
        if self.param_defaults.iter().all(Option::is_none) {
            return;
        }
        let mut v = self.param_defaults.clone();
        if this_prefixed {
            v.insert(0, None);
        }
        self.fn_defaults.insert(name.to_string(), v.clone());
        // S4.2av: also record collision-free (the HashMap above last-wins-
        // collapses same-named overloads; this list keeps every candidate).
        // Keyed by the DECLARED param types (no `this`) so the record matches
        // only THIS overload, not a same-arity sibling (see overload_defaults doc).
        self.overload_defaults
            .push((name.to_string(), self.param_types.clone(), v));
    }

    /// Parse a translation unit with the Win64 (8-byte) pointer model. The
    /// historical entry point; equivalent to `parse_for(toks, 8)`.
    pub fn parse(toks: &'t [Token]) -> PResult<TranslationUnit> {
        Parser::parse_for(toks, 8)
    }

    /// Parse a translation unit laying records out for a target whose pointer
    /// width is `ptr_bytes` (8 = Win64/LLP64, 4 = Win32/ILP32). The Win32
    /// compile path (`compile_to_object_with_target` with `TargetKind::Win32`)
    /// routes here so a pointer member / the polymorphic vptr occupies 4 bytes
    /// and struct `sizeof`/offsets match the i386 ABI. With `ptr_bytes == 8`
    /// this is byte-for-byte the historical `parse`.
    pub fn parse_for(toks: &'t [Token], ptr_bytes: usize) -> PResult<TranslationUnit> {
        let mut p = Parser::new_for(toks, ptr_bytes);
        let mut items = Vec::new();
        while !p.at_eof() {
            p.external_declaration(&mut items)?;
        }
        // #57: complete any class-template instantiations that were frozen from a
        // FORWARD declaration before the body appeared (now that all bodies are
        // registered) — e.g. OWL's `TGenericTableEntry`.
        p.complete_forward_instantiations();
        // An EMPTY translation unit is valid (C++ permits it) and matches bcc32,
        // which emits an empty `.obj`. Borland's CLASSLIB/OWL/RTL ships 16-bit-only
        // files (HEAPSEL.CPP, MEMMGR.CPP) whose entire body sits behind
        // `#if !defined(__FLAT__)`; under mdbcc's 32-bit `__FLAT__` target they
        // preprocess to nothing, so rejecting an empty TU would wrongly fail the
        // S5 library build. Fall through and build an empty TranslationUnit.
        // `mem::take` (not `for f in p.cxx_funcs`) so `p` stays fully borrowable
        // for the resolution sweep below (a by-value move would partially move
        // `p`, blocking `p.resolve_member_init`).
        let funcs = std::mem::take(&mut p.cxx_funcs);
        for f in funcs {
            items.push(Item::Func(f));
        }
        // S4 (#8/#34): final member-init resolution sweep over EVERY function.
        // `ctor_full_body` emits each `: field(args)` as a `Stmt::MemberInit`
        // marker (the member's TYPE is unknown during member parsing). Resolve
        // every marker now that all records/classes are finalized — a ctor call
        // for a class-typed member (so the sub-object is CONSTRUCTED with all
        // its args, e.g. `: Data(sz, delta)`) or `this->field = args[0]`
        // otherwise. Sweeping `items` (rather than only `cxx_funcs`) is what
        // reaches OUT-OF-LINE ctor definitions (`C::C(...) : m(args) {}`), which
        // are emitted straight into `items` at namespace scope, after the per-
        // class finalization pass already ran. The owning class id comes from
        // the ctor's `this` param (`this_ty` builds it as `Ptr(Record{id})`).
        for item in items.iter_mut() {
            let Item::Func(f) = item else { continue };
            let has_markers = f.body.iter().any(|s| matches!(s, Stmt::MemberInit { .. }));
            let id = f.params.first().and_then(|(_, ty)| match ty {
                Type::Ptr(inner) => match inner.as_ref() {
                    Type::Record { id, .. } => Some(*id),
                    _ => None,
                },
                _ => None,
            });
            let Some(id) = id else { continue };
            // S6 (G1 Stage-1): EXTRA-BASE construction/destruction for a
            // multiply-inheriting class — runs over EVERY ctor/dtor of the
            // class (inline, out-of-line, synthesized: all are in `items` by
            // now), so an extra base is never silently left unconstructed.
            //  * ctor: for each extra base with a ctor NOT named in the
            //    user's init list (the unresolved markers), insert
            //    `B::B(this)` BEFORE this class's `SetVptr` (i.e. after the
            //    primary base's construction), declaration order. Codegen's
            //    `base_ctor_call_adjust` shifts `this` to the subobject.
            //  * dtor: for each extra base with a dtor, REVERSE declaration
            //    order, insert `B::~B(this)` before the trailing primary-
            //    base dtor call (else append) — bases destroyed after the
            //    body, reverse construction order.
            if !p.records[id].extra_bases.is_empty()
                && let Some(tag) = p.records[id].tag.clone()
            {
                if f.name == format!("{tag}::{tag}") {
                    let named = collect_minit_names(&f.body);
                    let mut calls: Vec<Stmt> = Vec::new();
                    for eb in &p.records[id].extra_bases {
                        let Some(bt) = p.records[eb.id].tag.clone() else {
                            continue;
                        };
                        if named.contains(&bt) || !p.classes.get(&eb.id).is_some_and(|c| c.has_ctor)
                        {
                            continue;
                        }
                        calls.push(Stmt::ExprStmt(
                            Expr::Call {
                                name: format!("{bt}::{bt}"),
                                args: vec![Expr::Var("this".into(), Loc::default())],
                                loc: Loc::default(),
                            },
                            Loc::default(),
                        ));
                    }
                    if !calls.is_empty() {
                        let at = f
                            .body
                            .iter()
                            .position(|s| matches!(s, Stmt::SetVptr(sid, _) if *sid == id))
                            .unwrap_or(0);
                        f.body.splice(at..at, calls);
                    }
                } else if f.name == format!("{tag}::~{tag}") {
                    let mut calls: Vec<Stmt> = Vec::new();
                    for eb in p.records[id].extra_bases.iter().rev() {
                        let Some(bt) = p.records[eb.id].tag.clone() else {
                            continue;
                        };
                        if !p.classes.get(&eb.id).is_some_and(|c| c.has_dtor) {
                            continue;
                        }
                        calls.push(Stmt::ExprStmt(
                            Expr::Call {
                                name: format!("{bt}::~{bt}"),
                                args: vec![Expr::Var("this".into(), Loc::default())],
                                loc: Loc::default(),
                            },
                            Loc::default(),
                        ));
                    }
                    if !calls.is_empty() {
                        // Insert before a trailing PRIMARY-BASE dtor call, if
                        // any — `Bt::~Bt(this)`, distinguished from a member
                        // dtor (`M::~M(&this->m)`) by its bare-`this` arg, so
                        // the order stays: body, member dtors (reverse),
                        // extra-base dtors (reverse), primary-base dtor.
                        let at = match f.body.last() {
                            Some(Stmt::ExprStmt(Expr::Call { name, args, .. }, _))
                                if name.contains("::~")
                                    && matches!(
                                        args.first(),
                                        Some(Expr::Var(v, _)) if v == "this"
                                    ) =>
                            {
                                f.body.len() - 1
                            }
                            _ => f.body.len(),
                        };
                        f.body.splice(at..at, calls);
                    }
                }
            }
            if !has_markers {
                continue;
            }
            for s in f.body.iter_mut() {
                if let Stmt::MemberInit { field, args, loc } = s {
                    let field = field.clone();
                    let args = std::mem::take(args);
                    let loc = *loc;
                    *s = p.resolve_member_init(id, &field, args, loc);
                }
            }
        }
        // S6: default arguments are declared in the callee's class scope but
        // cloned into arbitrary caller contexts during codegen. Resolve static
        // data members now that the whole class body is known, before extern
        // static references are emitted below.
        p.qualify_default_arg_static_refs();
        // S4.2#35: emit an `extern` global for every REFERENCED static data
        // member (`Tag::member` seen in expression position) that is DECLARED
        // (`static_member_types`) but NOT DEFINED in this TU. The out-of-line
        // `T Tag::member = …` in the defining TU provides the bytes; here the
        // reference becomes an undefined COFF symbol the linker resolves.
        // Reference-driven + intersected with declarations, so an unreferenced
        // static member never adds a symbol (standalone PEs and the byte-
        // identity baselines, which reference none, are unperturbed). Emitted
        // BEFORE `refresh_record_types` so a record-typed member's size cache
        // (e.g. TColor::Black : TColor) is finalised with everything else.
        {
            let defined: std::collections::HashSet<String> = items
                .iter()
                .filter_map(|i| match i {
                    Item::Global { name, .. } | Item::ExternGlobal { name, .. } => {
                        Some(name.clone())
                    }
                    _ => None,
                })
                .collect();
            let mut externs: Vec<(String, Type)> = p
                .referenced_statics
                .iter()
                .filter(|n| p.static_member_types.contains_key(*n) && !defined.contains(*n))
                .map(|n| (n.clone(), p.static_member_types[n].clone()))
                .collect();
            externs.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic Item order
            for (name, ty) in externs {
                items.push(Item::ExternGlobal { name, ty });
            }
        }
        // Tick 55 (G-1/G-4): refresh every `Type::Record { id, size, align }`
        // cache in the AST. Inline member-function bodies (and the implicit
        // `this`) capture the enclosing class type via `decl_specifiers` /
        // `this_ty` BEFORE the class's layout finalises — so they cache
        // `size: 0, align: 1`, which trips the empty-struct-by-value check
        // and confuses Win64 ABI dispatch (HiddenPtr vs InReg) at call sites
        // in unrelated functions. The records vector IS finalised by now;
        // sweep the AST once and rewrite stale caches.
        refresh_record_types(&mut items, &p.records);
        for v in p.fn_defaults.values_mut() {
            for slot in v.iter_mut().flatten() {
                refresh_expr_record_types(slot, &p.records);
            }
        }
        for (_, ptys, defaults) in &mut p.overload_defaults {
            for ty in ptys {
                refresh_type(ty, &p.records);
            }
            for slot in defaults.iter_mut().flatten() {
                refresh_expr_record_types(slot, &p.records);
            }
        }
        // Tick 64 (J-13 v1): if a variadic prototype was declared but the
        // definition was non-variadic (or absent), propagate the variadic
        // bit onto the definition's AST node so callers marshal FP args
        // through the variadic XMM-AND-GPR path. A definition that itself
        // wrote `...` is already `variadic: true` and stays the source of
        // truth — the prototype only adds the bit, never removes it.
        for item in items.iter_mut() {
            if let Item::Func(f) = item
                && p.variadic_protos.contains(&f.name)
            {
                f.variadic = true;
            }
        }
        Ok(TranslationUnit {
            items,
            records: p.records,
            defaults: p.fn_defaults,
            overload_defaults: p.overload_defaults,
            extern_protos: p.extern_protos,
            fn_templates: p.fn_templates,
            uses_dynamic_cast: p.saw_dynamic_cast,
            // G13: export the scoped nested-type subset (`Outer::Inner` keys,
            // registered for every nested class by #64) so the monomorphiser can
            // resolve dependent nested types (`Base::Streamer`) at instantiation.
            nested_scopes: p
                .tags
                .iter()
                .filter(|(k, _)| k.contains("::"))
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            startup_fns: p.startup_fns,
        })
    }

    // ---- cursor -----------------------------------------------------------

    fn peek(&self) -> &Token {
        &self.toks[self.pos.min(self.toks.len() - 1)]
    }
    fn kind(&self) -> &TokenKind {
        &self.peek().kind
    }
    fn kind_at(&self, n: usize) -> Option<&TokenKind> {
        self.toks.get(self.pos + n).map(|t| &t.kind)
    }
    fn at_eof(&self) -> bool {
        *self.kind() == TokenKind::Eof
    }
    fn advance(&mut self) -> &Token {
        let t = &self.toks[self.pos.min(self.toks.len() - 1)];
        if self.pos < self.toks.len() {
            self.pos += 1;
        }
        t
    }
    fn error_here(&self, msg: impl Into<String>) -> ParseError {
        let t = self.peek();
        ParseError {
            message: msg.into(),
            line: t.line,
            col: t.col,
        }
    }
    /// Snapshot of the current lookahead token's source position, used to
    /// stamp the [`Loc`] field of an AST node at its construction site
    /// (J-8, tick 65). Captured **before** consuming the token, so a
    /// `Stmt::While { cond, body, loc }` records the column of `while`
    /// rather than of its body's first token.
    fn loc_here(&self) -> Loc {
        let t = self.peek();
        Loc {
            line: t.line,
            col: t.col,
        }
    }
    fn is_punct(&self, p: Punct) -> bool {
        *self.kind() == TokenKind::Punct(p)
    }
    fn is_kw(&self, kw: Keyword) -> bool {
        *self.kind() == TokenKind::Keyword(kw)
    }
    fn eat_punct(&mut self, p: Punct) -> bool {
        if self.is_punct(p) {
            self.advance();
            true
        } else {
            false
        }
    }
    fn eat_kw(&mut self, kw: Keyword) -> bool {
        if self.is_kw(kw) {
            self.advance();
            true
        } else {
            false
        }
    }
    fn expect_punct(&mut self, p: Punct, what: &str) -> PResult<()> {
        if self.eat_punct(p) {
            Ok(())
        } else {
            Err(self.error_here(format!("expected '{what}'")))
        }
    }

    /// After a member function / operator signature, consume an optional
    /// pure-virtual `= 0` or Borland OWL DDVT `= [ index-expr ]` suffix.
    /// Returns `true` iff the member is a pure virtual (`= 0`); `false` for no
    /// suffix or a DDVT message-index (a dispatched, non-pure method). Errors if
    /// `=` is followed by neither `0` nor `[`. Shared by the regular-method and
    /// conversion-operator member paths (both can be `= 0` / `= [idx]`).
    /// Returns `(is_pure, ddvt_msg_index)`: `is_pure` for `= 0`; `ddvt_msg_index`
    /// is `Some(idx)` for the OWL DDVT `= [ const-expr ]` form (the const-folded
    /// message index — `WM_FIRST` is 0, so `idx` equals the raw Windows message
    /// id, e.g. `WM_LBUTTONDOWN`). The index drives the synthesised dispatching
    /// `WindowProc` (S4.2(e)); previously the `[ ... ]` was parsed and DISCARDED.
    fn member_pure_or_ddvt_suffix(&mut self) -> PResult<(bool, Option<i64>)> {
        if !self.eat_punct(Punct::Assign) {
            return Ok((false, None));
        }
        if self.eat_punct(Punct::LBracket) {
            let idx = self.const_expr()?;
            self.expect_punct(Punct::RBracket, "]")?;
            Ok((false, Some(idx)))
        } else if matches!(self.kind(), TokenKind::Int { value: 0, .. }) {
            self.advance();
            Ok((true, None))
        } else {
            Err(self.error_here("expected '0' for a pure virtual"))
        }
    }
    // ---- types & declarators ---------------------------------------------

    /// True if the cursor is at the start of a declaration.
    fn at_decl(&self) -> bool {
        if !self.kind_starts_type(self.kind()) {
            return false;
        }
        // S4.2e most-vexing-parse: an Ident type-name (optionally `:: Ident`
        // qualified) IMMEDIATELY followed by a balanced `( … )` and then a
        // member-access (`. / -> / [`) is a functional-cast EXPRESSION — a
        // temporary then member access — not a declaration (CLASSLIB's
        // `Base::Streamer(base).Read(in,version)`). A declaration of that shape
        // is impossible (you cannot `.member` a declaration), so this is safe;
        // `Foo x;`, `Foo* p;`, `Foo x(args);`, and `Foo(x);` (redundant-parens
        // declaration, no trailing member access) all stay declarations.
        if !matches!(self.kind(), TokenKind::Ident(_)) {
            return true;
        }
        let n = self.toks.len();
        // S5 (#52): a qualified name whose ROOT is a template type-parameter is a
        // DEPENDENT type (`Base::Streamer` in
        // `template<class Base> … { Base::Streamer s(x); }`, OBJSTRM.H:980). Its
        // `::member` components need NOT be known types — they resolve at
        // instantiation — so the normal "`::Ident` must be a known type, else it's
        // an expression" rule (below) wrongly rejects it. Treat the whole
        // `(:: Ident)+` chain as a dependent type-name, and classify as a
        // DECLARATION iff a declarator (Ident / `*` / `&`) follows; if `(` /
        // operator / `;` follows instead it stays an EXPRESSION
        // (`Base::staticFn(x)`, `Base::value`).
        if matches!(
            self.kind(),
            TokenKind::Ident(s) if matches!(self.typedefs.get(s), Some(Type::TemplateParam(_)))
        ) {
            let mut j = self.pos + 1;
            while self.toks.get(j).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::ColonColon))
                && matches!(
                    self.toks.get(j + 1).map(|t| &t.kind),
                    Some(TokenKind::Ident(_))
                )
            {
                j += 2;
            }
            // Only the `T::member … IDENTIFIER` shape is decided here: a bare
            // identifier after a dependent qualified name is UNAMBIGUOUSLY a
            // declarator (no expression is `qualified-id identifier`), so this is
            // a declaration. Every other follower (`(`, `*`, `&`, operator, `;`)
            // is left to the existing logic below — `*`/`&` are ambiguous with
            // `Base::count * x` (a multiply on a dependent static), and `(` with a
            // functional-cast temporary, so we must NOT force a verdict on them.
            if j > self.pos + 1
                && matches!(self.toks.get(j).map(|t| &t.kind), Some(TokenKind::Ident(_)))
            {
                return true;
            }
        }
        let mut i = self.pos + 1;
        while self.toks.get(i).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::ColonColon)) {
            i += 1;
            match self.toks.get(i).map(|t| &t.kind) {
                // S5: a `::`-qualified component that names a KNOWN TYPE continues
                // a qualified type-name (`A::B::C`, `Base::Inner x;`) — keep
                // scanning. A component that is NOT a type means this is a
                // qualified-id EXPRESSION, never a local declaration (a block
                // cannot declare a qualified name): a qualified base-method call
                // `Base::foo(x);` (the C++ "call the base implementation" idiom),
                // a static data member `TColor::Black`, an enum constant
                // `ios::in`. Without this, `Base::foo(x);` was mis-parsed as a
                // declaration of a variable named `Base::foo` of type `Base`
                // (auto-invoking `Base::Base` ⇒ "no matching overload", task #41).
                Some(TokenKind::Ident(m))
                    if self.tags.contains_key(m) || self.typedefs.contains_key(m) =>
                {
                    i += 1;
                }
                Some(TokenKind::Ident(_)) => return false,
                // `::*` / `::~` / `::operator` — preserve historical handling.
                _ => return true,
            }
        }
        // S4.2f: a binary / assignment / member operator immediately after the
        // "type-name" means it is actually a VALUE in an expression — typically a
        // member variable that SHADOWS a global type (`Flags |= uint32(mask)` in
        // OWL/window.h, where CHECKS.H declares `struct Flags` but `Flags` here is
        // TWindow's member). No declaration has such an operator right after the
        // type name. `*`, `&`, `<`, `[` are deliberately NOT listed — they begin
        // pointer / reference / template-id / array declarator forms.
        if matches!(
            self.toks.get(i).map(|t| &t.kind),
            Some(TokenKind::Punct(
                Punct::Assign
                    | Punct::PlusEq
                    | Punct::MinusEq
                    | Punct::StarEq
                    | Punct::SlashEq
                    | Punct::PercentEq
                    | Punct::AmpEq
                    | Punct::PipeEq
                    | Punct::CaretEq
                    | Punct::ShlEq
                    | Punct::ShrEq
                    | Punct::Plus
                    | Punct::Minus
                    | Punct::Slash
                    | Punct::Percent
                    | Punct::Pipe
                    | Punct::Caret
                    | Punct::Shl
                    | Punct::Shr
                    | Punct::Gt
                    | Punct::Le
                    | Punct::Ge
                    | Punct::EqEq
                    | Punct::Ne
                    | Punct::AndAnd
                    | Punct::OrOr
                    | Punct::Question
                    | Punct::Dot
                    | Punct::Arrow
                    | Punct::DotStar
                    | Punct::ArrowStar
            ))
        ) {
            return false;
        }
        if self.toks.get(i).map(|t| &t.kind) != Some(&TokenKind::Punct(Punct::LParen)) {
            return true; // a declarator (name / `*` / …) follows ⇒ declaration
        }
        let mut depth = 0i32;
        while i < n {
            match &self.toks[i].kind {
                TokenKind::Punct(Punct::LParen) => depth += 1,
                TokenKind::Punct(Punct::RParen) => {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                TokenKind::Eof => return true,
                _ => {}
            }
            i += 1;
        }
        !matches!(
            self.toks.get(i).map(|t| &t.kind),
            Some(TokenKind::Punct(
                Punct::Dot | Punct::Arrow | Punct::LBracket
            ))
        )
    }

    /// True if `k` can begin a type / declaration specifier (a type keyword
    /// or storage/qualifier, or a known typedef/tag name). Factored out of
    /// [`Self::at_decl`] so a lookahead (e.g. the S4.2 `new (T)` vs
    /// `new (placement)` disambiguation) can test a token at any offset.
    fn kind_starts_type(&self, k: &TokenKind) -> bool {
        if let TokenKind::Ident(s) = k {
            return self.typedefs.contains_key(s)
                || self.tags.contains_key(s)
                || self.class_scoped_tag(s).is_some()
                // S4.2b(ii): a class-template name begins a type (`Box<int> b;`)
                // so a local declaration isn't mis-parsed as a `<` comparison.
                || self.class_template_idx.contains_key(s);
        }
        matches!(
            k,
            TokenKind::Keyword(
                Keyword::Void
                    | Keyword::Char
                    | Keyword::Short
                    | Keyword::Int
                    | Keyword::Long
                    | Keyword::Signed
                    | Keyword::Unsigned
                    | Keyword::Float
                    | Keyword::Double
                    | Keyword::Const
                    | Keyword::Volatile
                    | Keyword::Static
                    | Keyword::Extern
                    | Keyword::Register
                    | Keyword::Auto
                    | Keyword::Inline
                    | Keyword::Typedef
                    | Keyword::Int8
                    | Keyword::Int16
                    | Keyword::Int32
                    | Keyword::Int64
                    | Keyword::Near
                    | Keyword::Far
                    | Keyword::Huge
                    | Keyword::Cdecl
                    | Keyword::Pascal
                    | Keyword::Interrupt
                    | Keyword::Fastcall
                    | Keyword::Stdcall
                    | Keyword::Export
                    | Keyword::Declspec
                    | Keyword::Struct
                    | Keyword::Union
                    | Keyword::Enum
                    | Keyword::Class
            )
        )
    }

    /// C++ class-scope type lookup for unqualified nested class names.
    ///
    /// Nested classes are stored in the flat `tags` table under scoped keys
    /// (`Outer::Inner`) because OWL repeatedly declares sibling `TData`
    /// classes. While parsing a class body, `TData& Data;` must prefer the
    /// current class's scoped `TData` over an earlier flat `TData`.
    fn class_scoped_tag(&self, name: &str) -> Option<usize> {
        for depth in (1..=self.class_nest.len()).rev() {
            let key = format!("{}::{name}", self.class_nest[..depth].join("::"));
            if let Some(&id) = self.tags.get(&key) {
                return Some(id);
            }
        }
        None
    }

    /// Resolve a class-scoped typedef that aliases a class tag, such as OWL's
    /// per-response-table `typedef cls TMyClass;`.
    fn member_class_typedef_tag(&self, name: &str) -> Option<String> {
        let cid = self.cur_class?;
        let target = *self.member_class_typedefs.get(&cid)?.get(name)?;
        self.records.get(target)?.tag.clone()
    }

    /// S4.2(a): parse the type after `new` (or inside `new (T)`):
    /// `decl_specifiers` then a `*`/`&` abstract-declarator prefix. The
    /// bracketed array suffix is parsed by the caller (so a runtime
    /// `new T[i]` is accepted — `type_name`'s declarator allows only constant
    /// `[N]`). Shared by the placement and non-placement new-expr paths.
    fn new_type_prefix(&mut self) -> PResult<Type> {
        let mut ty = self.decl_specifiers()?;
        // S4.2f: a QUALIFIED type name in `new` context — `new (p)
        // TMutex::Lock(args)` (OWL/window.h). Here `A::B` is UNambiguously a type
        // (no out-of-line member declarator is possible after `new`), so consume
        // the `::` chain regardless of the following token (`qualify_nested`'s
        // declarator look-ahead would stop at the `(` of the ctor-args) and
        // resolve the final component to the flat global type.
        while self.is_punct(Punct::ColonColon)
            && matches!(self.kind_at(1), Some(TokenKind::Ident(_)))
        {
            self.advance(); // `::`
            let nested = match self.kind() {
                TokenKind::Ident(s) => s.clone(),
                _ => break,
            };
            self.advance();
            if let Some(&id) = self.tags.get(&nested) {
                let r = &self.records[id];
                ty = Type::Record {
                    id,
                    size: r.size,
                    align: r.align,
                };
            } else if let Some(nt) = self.typedefs.get(&nested).cloned() {
                ty = nt;
            }
        }
        while self.eat_punct(Punct::Star) {
            while matches!(
                self.kind(),
                TokenKind::Keyword(Keyword::Const | Keyword::Volatile)
            ) {
                self.advance();
            }
            ty = Type::Ptr(Box::new(ty));
        }
        if self.eat_punct(Punct::Amp) {
            ty = Type::Ref(Box::new(ty));
        }
        Ok(ty)
    }

    /// S4.2e: consume a `:: Nested` qualified-name suffix on a just-parsed type
    /// (`Base::Streamer` in CLASSLIB's `WriteBaseObject` function template).
    /// mdbcc's model is flat — resolve the FINAL component as a global type when
    /// known. A nested type of a TEMPLATE PARAMETER is DEPENDENT: it stays a
    /// `TemplateParam` (so codegen errors cleanly at any instantiation rather
    /// than silently mis-resolving), which is enough for the (eager-parsed)
    /// function-template BODY to parse. Only `:: Ident` is consumed; `::*`
    /// (ptr-to-member) is left for the declarator.
    fn qualify_nested(&mut self, mut t: Type) -> PResult<Type> {
        // Gated to a DEPENDENT outer (a template parameter): only then is a
        // `:: Ident` suffix a dependent nested TYPE that decl-specifiers must
        // absorb. For a CONCRETE outer (`string::outofrange::outofrange()`) the
        // `::` chain is an out-of-line member DECLARATOR — left for `declarator`
        // to handle (consuming it here would eat the member name).
        while matches!(t, Type::TemplateParam(_))
            && self.is_punct(Punct::ColonColon)
            && matches!(self.kind_at(1), Some(TokenKind::Ident(_)))
        {
            self.advance(); // `::`
            let nested = match self.kind() {
                TokenKind::Ident(s) => s.clone(),
                _ => break,
            };
            self.advance();
            // G13: KEEP the qualifier (`Base::Streamer`, not just `Streamer`) so
            // monomorphisation can substitute `Base` and resolve the concrete
            // nested record via the scoped `Tag::Inner` key (#64). Chains for
            // `A::B::C`. Previously this dropped the qualifier, leaving the
            // monomorphiser unable to substitute → "method call on non-class".
            let outer = match &t {
                Type::TemplateParam(o) => o.clone(),
                _ => unreachable!("loop guard requires a TemplateParam outer"),
            };
            t = Type::TemplateParam(format!("{outer}::{nested}")); // stays dependent
        }
        // S4.2f: a CONCRETE outer — a nested TYPE used as a return/variable type,
        // possibly MULTI-level: `TThread::Status …` and
        // `TThread::ThreadError::ErrorType TThread::ThreadError::…` (OWL/window.h).
        // Scan the whole `(:: Ident)+` chain by look-ahead WITHOUT consuming, then
        // commit only if a DECLARATOR (Ident / `*` / `&`) follows the last
        // component — resolving that final component to the flat global type. If
        // instead `(` (etc.) follows, the qualified name IS an out-of-line member
        // declarator (`string::outofrange::outofrange()`) — leave it for
        // `declarator`. Resolving the FINAL component matches mdbcc's flat model.
        if !matches!(t, Type::TemplateParam(_)) && self.is_punct(Punct::ColonColon) {
            let mut i = self.pos;
            let mut last: Option<String> = None;
            // S6 (#64): also collect the whole component chain to try the SCOPED
            // key `Outer::Inner` (a minted nested class lives only there, not
            // under the flat innermost name).
            let mut chain: Vec<String> = Vec::new();
            while self.toks.get(i).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::ColonColon)) {
                match self.toks.get(i + 1).map(|t| &t.kind) {
                    Some(TokenKind::Ident(s)) => {
                        last = Some(s.clone());
                        chain.push(s.clone());
                        i += 2;
                    }
                    _ => break,
                }
            }
            // The follow set also admits ABSTRACT-declarator positions: an
            // UNNAMED parameter `virtual streampos seekoff(streamoff,
            // ios::seek_dir, int)` (iostream.h) is followed by `,`/`)`, and a
            // defaulted one by `=`. Without these the chain stayed unconsumed,
            // the param typed as the OUTER record, and the out-of-line def
            // (named ⇒ enum ⇒ Int) mismatched ⇒ spurious overload ⇒ the def
            // mangled while vtable slots referenced the bare name (the
            // filebuf::seekoff/strstreambuf::seekoff link break). `(` stays
            // excluded: `string::outofrange::outofrange()` is an out-of-line
            // member declarator, not a nested-type use; and the commit below
            // still requires the final component to RESOLVE as a type, so
            // expression chains (`ios::beg`, enum constants) are untouched.
            let declarator_follows = matches!(
                self.toks.get(i).map(|t| &t.kind),
                Some(TokenKind::Ident(_))
                    | Some(TokenKind::Punct(Punct::Star))
                    | Some(TokenKind::Punct(Punct::Amp))
                    | Some(TokenKind::Punct(Punct::Comma))
                    | Some(TokenKind::Punct(Punct::RParen))
                    | Some(TokenKind::Punct(Punct::Assign))
            );
            if declarator_follows && let Some(nested) = last {
                // S6 (#64): the scoped key from the OUTER record's tag + chain
                // (`TButton::Streamer`) — resolves a minted nested class.
                let scoped = match &t {
                    Type::Record { id, .. } => self.records[*id]
                        .tag
                        .as_ref()
                        .map(|ot| format!("{ot}::{}", chain.join("::"))),
                    _ => None,
                };
                if let Some(&id) = scoped.as_ref().and_then(|k| self.tags.get(k)) {
                    self.pos = i;
                    let r = &self.records[id];
                    t = Type::Record {
                        id,
                        size: r.size,
                        align: r.align,
                    };
                } else if let Some(&id) = self.tags.get(&nested) {
                    self.pos = i;
                    let r = &self.records[id];
                    t = Type::Record {
                        id,
                        size: r.size,
                        align: r.align,
                    };
                } else if let Some(nt) = self.typedefs.get(&nested).cloned() {
                    self.pos = i;
                    t = nt;
                }
            }
        }
        Ok(t)
    }

    /// Parse declaration specifiers into a base [`Type`]. Storage-class,
    /// `const`/`volatile`, and Borland qualifiers are accepted and ignored.
    fn decl_specifiers(&mut self) -> PResult<Type> {
        let mut void = false;
        let mut sign: Option<bool> = None; // Some(true)=signed
        let mut chr = false;
        let mut shrt = false;
        let mut longs = 0u8;
        let mut bytes_override: Option<u8> = None;
        let mut saw_int = false;
        // Phase F-1: floating-point.
        let mut is_float_kw = false; // saw `float`
        let mut is_double_kw = false; // saw `double`
        let mut saw_any = false;
        // Pre-standard C++ / C89 "implicit int": a declaration carrying a cv-
        // or storage-class specifier but NO type defaults to `int`. Tracked so
        // `const NAME = 111;` (Borland CLASSLIB/RESOURCE.H) is accepted as
        // `const int NAME = 111;`. Only triggers when no type keyword/name is
        // seen, so explicitly-typed declarations are unaffected (byte-identical
        // for the 88 corpus).
        let mut saw_qualifier = false;
        self.is_typedef = false;
        self.is_inline = false;
        self.is_static = false;
        self.is_const = false;
        self.last_call_conv = None;

        loop {
            match self.kind() {
                TokenKind::Keyword(Keyword::Typedef) => {
                    self.is_typedef = true;
                    self.advance();
                }
                TokenKind::Keyword(
                    Keyword::Struct | Keyword::Union | Keyword::Class,
                ) => {
                    let is_union = self.is_kw(Keyword::Union);
                    return self.record_specifier(is_union);
                }
                TokenKind::Keyword(Keyword::Enum) => {
                    return self.enum_specifier();
                }
                TokenKind::Ident(name) if !saw_any => {
                    let name = name.clone();
                    // S4.2b(ii): a class-template-id `Tag < type-args >` —
                    // instantiate the captured template and use the concrete
                    // record. Checked before the typedef/tag paths so the
                    // `<…>` form always routes here.
                    if self.class_template_idx.contains_key(&name)
                        && self.kind_at(1) == Some(&TokenKind::Punct(Punct::Lt))
                    {
                        // S4.2f: `instantiate_class_template` re-enters
                        // `decl_specifiers` to parse the `<…>` arguments, which
                        // RESETS `self.is_typedef`. Preserve the enclosing
                        // declaration's typedef intent so
                        // `typedef TResponseTableEntry<GENERIC> TGenericTableEntry;`
                        // (OWL/EVENTHAN.H) registers an alias, not a variable.
                        let was_typedef = self.is_typedef;
                        let ty = self.instantiate_class_template(&name)?;
                        // S4.2f: a nested type of the instantiation —
                        // `TResponseTableEntry<TWindow>::PMF` (OWL/window.h's
                        // DECLARE_RESPONSE_TABLE `typedef …<cls>::PMF TMyPMF;`).
                        // Instantiation registered the member typedef flat, so
                        // `qualify_nested` resolves the `::PMF` suffix.
                        let ty = self.qualify_nested(ty)?;
                        self.is_typedef = was_typedef;
                        return Ok(ty);
                    }
                    // C++: a bare class/struct tag is a type name.
                    if let Some(id) = self.class_scoped_tag(&name) {
                        self.advance();
                        let r = &self.records[id];
                        let t = Type::Record { id, size: r.size, align: r.align };
                        return self.qualify_nested(t);
                    }
                    if let Some(t) = self.typedefs.get(&name).cloned() {
                        self.advance();
                        return self.qualify_nested(t);
                    }
                    if let Some(&id) = self.tags.get(&name) {
                        self.advance();
                        let r = &self.records[id];
                        let t = Type::Record { id, size: r.size, align: r.align };
                        return self.qualify_nested(t);
                    }
                    break;
                }
                // S2b.3: calling-convention keywords are recorded (not just
                // skipped) so the function-building sites can carry the
                // convention into the AST. The last one written wins (a
                // redundant `__cdecl __stdcall` is degenerate source).
                TokenKind::Keyword(kw @ (Keyword::Cdecl | Keyword::Stdcall
                    | Keyword::Fastcall | Keyword::Pascal)) => {
                    self.last_call_conv = Some(match kw {
                        Keyword::Cdecl => CallConv::Cdecl,
                        Keyword::Stdcall => CallConv::Stdcall,
                        Keyword::Fastcall => CallConv::Fastcall,
                        Keyword::Pascal => CallConv::Pascal,
                        _ => unreachable!(),
                    });
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Const | Keyword::Volatile
                    | Keyword::Static | Keyword::Extern | Keyword::Register
                    | Keyword::Auto | Keyword::Near
                    | Keyword::Far | Keyword::Huge
                    | Keyword::Interrupt | Keyword::Export | Keyword::Import
                    // `inline` is a function-specifier; mdbcc never actually
                    // inlines, so accept-and-ignore (and let it carry implicit
                    // int: `inline f(){}` ⇒ `inline int f(){}`). Pervasive in
                    // the C++ headers (e.g. STDLIB.H `inline int abs(int)`).
                    | Keyword::Inline) => {
                    saw_qualifier = true;
                    if self.is_kw(Keyword::Inline) {
                        self.is_inline = true; // S4.2h
                    }
                    if self.is_kw(Keyword::Static) {
                        self.is_static = true; // S4.2o
                    }
                    if self.is_kw(Keyword::Const) {
                        self.is_const = true; // S4.2#39
                    }
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Declspec) => {
                    self.advance();
                    // __declspec(...) — skip the balanced parens.
                    if self.eat_punct(Punct::LParen) {
                        let mut d = 1;
                        while d > 0 && !self.at_eof() {
                            if self.is_punct(Punct::LParen) {
                                d += 1;
                            } else if self.is_punct(Punct::RParen) {
                                d -= 1;
                            }
                            self.advance();
                        }
                    }
                }
                TokenKind::Keyword(Keyword::Void) => {
                    void = true;
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Signed) => {
                    sign = Some(true);
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Unsigned) => {
                    sign = Some(false);
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Char) => {
                    chr = true;
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Short) => {
                    shrt = true;
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Long) => {
                    longs += 1;
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Int) => {
                    saw_int = true;
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Int8) => {
                    bytes_override = Some(1);
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Int16) => {
                    bytes_override = Some(2);
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Int32) => {
                    bytes_override = Some(4);
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Int64) => {
                    bytes_override = Some(8);
                    saw_any = true;
                    self.advance();
                }
                // Phase F-1: float/double recognised as decl specifiers
                // (codegen sites still error explicitly until F2 lands).
                TokenKind::Keyword(Keyword::Float) => {
                    is_float_kw = true;
                    saw_any = true;
                    self.advance();
                }
                TokenKind::Keyword(Keyword::Double) => {
                    is_double_kw = true;
                    saw_any = true;
                    self.advance();
                }
                _ => break,
            }
        }

        if !saw_any {
            // Implicit int (pre-standard C++ / C89): a cv-/storage-qualified
            // declaration with no type names `int`. `const X = 1;` ⇒
            // `const int X = 1;`. Without a qualifier a bare unknown name stays
            // a hard "expected a type" error (we don't enable K&R implicit-int
            // for un-qualified declarations — too broad, and no header needs it).
            if saw_qualifier {
                return Ok(Type::int());
            }
            return Err(self.error_here(format!("expected a type, found {:?}", self.kind())));
        }
        if void
            && !chr
            && !shrt
            && longs == 0
            && !saw_int
            && sign.is_none()
            && !is_float_kw
            && !is_double_kw
        {
            return Ok(Type::Void);
        }
        // Phase F-1: float / double / `long double` (folded to double).
        // `signed`/`unsigned` + `float`/`double` is illegal in C; `int`
        // alongside is also illegal — caught explicitly (never silently
        // accepted, house style).
        if is_float_kw || is_double_kw {
            if sign.is_some() || chr || shrt || saw_int || bytes_override.is_some() {
                return Err(self.error_here(
                    "'signed'/'unsigned'/'int' is invalid with \
                     'float'/'double'",
                ));
            }
            if is_float_kw && is_double_kw {
                return Err(self.error_here("cannot combine 'float' and 'double'"));
            }
            // `double` alone or `long double` ⇒ 8; `long long double` is
            // not valid C and never written in the corpus.
            if is_double_kw {
                return Ok(Type::Float { bytes: 8 });
            }
            // `float` with `long` is not standard; bcc32 5.5.1 doesn't
            // accept it either — reject explicitly.
            if longs > 0 {
                return Err(self.error_here("'long float' is not a valid type"));
            }
            return Ok(Type::Float { bytes: 4 });
        }
        // `long double` with no explicit `double` keyword (i.e. `longs>=1`
        // and nothing else float-related) is integer `long` here. C++ also
        // permits the spelling `long double`, which lands above with
        // `is_double_kw && longs>=1`; the surrounding `if` already returned.
        let signed = sign.unwrap_or(true);
        let bytes = if let Some(b) = bytes_override {
            b
        } else if chr {
            1
        } else if shrt {
            2
        } else if longs >= 2 {
            8
        } else {
            4 // int / long / signed / unsigned (LLP64: long is 32-bit)
        };
        Ok(Type::Int { bytes, signed })
    }

    /// S6 (G1 Stage-3): does this virtual-base record carry real DATA (so it
    /// needs the SHARED-vbase machinery, vs a stateless interface mixin laid out
    /// as a plain base)? "Real data" = any field other than the synthetic
    /// `$vbptr` slot, transitively through bases/vbases. `ios` (state/flags) is
    /// data-bearing; OWL's `TEventHandler`/`TStreamableBase` mixins are not.
    fn vbase_is_data_bearing(&self, id: usize) -> bool {
        let Some(r) = self.records.get(id) else {
            return false;
        };
        if r.fields.iter().any(|f| f.name != "$vbptr") {
            return true;
        }
        if let Some(b) = r.base
            && b != id
            && self.vbase_is_data_bearing(b)
        {
            return true;
        }
        r.extra_bases
            .iter()
            .any(|eb| eb.id != id && self.vbase_is_data_bearing(eb.id))
            || r.vbases
                .iter()
                .any(|vb| vb.id != id && self.vbase_is_data_bearing(vb.id))
    }

    /// S6 (G1 Stage-3): the statements that set up a LOCAL object's SHARED
    /// virtual base(s) — emitted by the construction site, BEFORE the
    /// most-derived ctor runs (so the ctor chain can reach the vbase via the
    /// vbptr). For the single-vbase `ios` diamond: (1) store `&var +
    /// vbase.offset` into every vbptr field, then (2) default-construct the
    /// shared vbase once at `&var + vbase.offset`. Empty for any class without
    /// virtual bases (no statements injected ⇒ byte-identical).
    fn vbase_init_stmts(&self, var: &str, id: usize, loc: Loc) -> Vec<Stmt> {
        let mut out = Vec::new();
        let Some(rec) = self.records.get(id) else {
            return out;
        };
        if rec.vbases.is_empty() {
            return out;
        }
        let vbases = rec.vbases.clone();
        let vbptrs = rec.vbptr_offsets.clone();
        // `(char*)&var + off`
        let byte_ptr = |off: usize| -> Expr {
            let addr = Expr::Unary {
                op: UnOp::Addr,
                expr: Box::new(Expr::Var(var.to_string(), loc)),
            };
            let as_char = Expr::Cast {
                ty: Type::Ptr(Box::new(Type::char_())),
                expr: Box::new(addr),
            };
            if off == 0 {
                as_char
            } else {
                Expr::Binary {
                    op: BinOp::Add,
                    lhs: Box::new(as_char),
                    rhs: Box::new(Expr::Int(off as i64)),
                    loc,
                }
            }
        };
        // 1. `*(char**)(&var + vbptr_field) = (char*)&var + vbase.offset`.
        for (vid, vbptr_field) in &vbptrs {
            let vbase_off = vbases
                .iter()
                .find(|v| v.id == *vid)
                .map(|v| v.offset)
                .unwrap_or(0);
            let slot_pp = Expr::Cast {
                ty: Type::Ptr(Box::new(Type::Ptr(Box::new(Type::char_())))),
                expr: Box::new(byte_ptr(*vbptr_field)),
            };
            let lhs = Expr::Unary {
                op: UnOp::Deref,
                expr: Box::new(slot_pp),
            };
            out.push(Stmt::ExprStmt(
                Expr::Assign {
                    lhs: Box::new(lhs),
                    rhs: Box::new(byte_ptr(vbase_off)),
                    loc,
                },
                loc,
            ));
        }
        // 2. default-construct each shared vbase at `&var + offset` (if it has
        // a ctor — `ios()`/`Base()` do).
        for v in &vbases {
            let has_ctor = self.classes.get(&v.id).map(|c| c.has_ctor).unwrap_or(false);
            let vtag = self.records.get(v.id).and_then(|r| r.tag.clone());
            if let (true, Some(vtag)) = (has_ctor, vtag) {
                let castp = Expr::Cast {
                    ty: Type::Ptr(Box::new(Type::Record {
                        id: v.id,
                        size: 0,
                        align: 1,
                    })),
                    expr: Box::new(byte_ptr(v.offset)),
                };
                let recv = Expr::Unary {
                    op: UnOp::Deref,
                    expr: Box::new(castp),
                };
                out.push(Stmt::ExprStmt(
                    Expr::MethodCall {
                        recv: Box::new(recv),
                        name: vtag,
                        args: vec![],
                        loc,
                    },
                    loc,
                ));
            }
        }
        out
    }

    /// `struct`/`union` [tag] [ `{` fields `}` ]. The cursor is on the
    /// keyword. A tagged record is interned so recursive (`struct N *next;`)
    /// and forward references resolve.
    fn record_specifier(&mut self, is_union: bool) -> PResult<Type> {
        // Field parsing recurses through `decl_specifiers`, which resets
        // `is_typedef`; preserve the enclosing declaration's typedef intent.
        let was_typedef = self.is_typedef;
        self.advance(); // struct | union | class
        // A qualifier run may sit between the keyword and the tag after macro
        // expansion (`class _EXPORT Foo` → `class huge Foo`); skip it.
        self.skip_class_head_qualifiers();
        let mut tag = if let TokenKind::Ident(s) = self.kind() {
            let s = s.clone();
            self.advance();
            Some(s)
        } else {
            None
        };

        // S4.2f: Borland accepts an explicit full specialization without a
        // `template<>` prefix: `class TPointer<char> : ... { ... };`. Parse that
        // definition as a concrete record keyed by the specialized template-id.
        // The source tag stays `TPointer` for constructor/destructor detection,
        // but the actual record/member symbol tag is unique (`TPointer$i1`).
        let bare = tag.clone();
        let mut specialization_key: Option<String> = None;
        if let Some(name) = bare.clone()
            && self.class_template_idx.contains_key(&name)
            && self.is_punct(Punct::Lt)
        {
            let idx = *self
                .class_template_idx
                .get(&name)
                .expect("class-template idx");
            let (_type_args, _arg_vals, codes, key) = self.parse_class_template_args(&name, idx)?;
            if self.class_inst_cache.contains_key(&key) {
                return Err(self.error_here(format!(
                    "class-template specialization '{key}' is defined after it \
                     was already instantiated"
                )));
            }
            tag = Some(format!("{}${}", name, codes.join("$")));
            self.class_specializations.insert(key.clone());
            specialization_key = Some(key);
        }

        // S6 (#64): bare source name + scoped `Outer::Inner` key (if nested).
        let is_definition = matches!(self.kind(), TokenKind::Punct(Punct::LBrace | Punct::Colon));
        let scoped_key: Option<String> = match (&bare, self.class_nest.is_empty()) {
            (Some(t), false) => Some(format!("{}::{t}", self.class_nest.join("::"))),
            _ => None,
        };
        // A nested DEFINITION whose flat tag already names a DEFINED record is
        // a distinct nested class reusing an unqualified name (per-class
        // Streamer/Lock). Mint a fresh record with a UNIQUE tag so the classes
        // do not merge and their member symbols stay distinct. The flat tag
        // binding is left untouched (overwriting it is unnecessary; qualified
        // refs use the scoped key); ctor detection below uses the BARE name.
        let collide_fresh = is_definition
            && scoped_key.is_some()
            && matches!(&bare, Some(t)
                if self.tags.contains_key(t) && self.defined_records.contains(&self.tags[t]));
        // Resolve / create the record id.
        let id = if collide_fresh {
            let id = self.records.len();
            let uniq = format!("{}${id}", bare.as_deref().unwrap_or("anon"));
            self.records.push(Record {
                tag: Some(uniq.clone()),
                is_union,
                fields: Vec::new(),
                size: 0,
                align: 1,
                base: None,
                base_offset: 0,
                extra_bases: Vec::new(),
                mi_dropped: false,
                vtable: Vec::new(),
                vbases: Vec::new(),
                vbptr_offsets: Vec::new(),
            });
            tag = Some(uniq); // members register under the unique tag
            id
        } else {
            match &tag {
                Some(t) if self.tags.contains_key(t) => self.tags[t],
                _ => {
                    let id = self.records.len();
                    self.records.push(Record {
                        tag: tag.clone(),
                        is_union,
                        fields: Vec::new(),
                        size: 0,
                        align: 1,
                        base: None,
                        base_offset: 0,
                        extra_bases: Vec::new(),
                        mi_dropped: false,
                        vtable: Vec::new(),
                        vbases: Vec::new(),
                        vbptr_offsets: Vec::new(),
                    });
                    if let Some(t) = &tag {
                        self.tags.insert(t.clone(), id);
                    }
                    id
                }
            }
        };
        if let Some(key) = &specialization_key
            && is_definition
        {
            // The specialization body can mention its own template-id, e.g.
            // `const TPointer<char>&`. Cache the in-progress record exactly like
            // primary-template replay does, so those references resolve to this
            // concrete specialization instead of recursing into the primary.
            self.class_inst_cache.insert(key.clone(), id);
        }
        // S6 (#64): register the scoped `Outer::Inner` key for EVERY nested
        // class so qualified refs + out-of-line member defs resolve correctly.
        if let Some(sk) = &scoped_key {
            self.tags.insert(sk.clone(), id);
        }

        // Optional base-class clause: `: [public|private|protected] [virtual] Base`.
        let shared_data_vbase_target_ok = matches!(self.ptr_bytes, 4 | 8);
        let mut base_id: Option<usize> = None;
        // S6 (G1 Stage-1): the 2nd..nth direct bases — (record id, spelled
        // `virtual`). Subobject OFFSETS are computed after layout (below).
        let mut extra_base_infos: Vec<(usize, bool)> = Vec::new();
        // S6 (G1 Stage-3): DIRECT virtual bases (`: virtual public ios`). They
        // are NOT laid out at offset 0 / as extra subobjects; the shared vbase
        // is appended ONCE at the object tail and reached via a vbptr. Collected
        // here regardless of declaration position; transitive vbases (a vbase of
        // a non-virtual base) are gathered after layout.
        let mut direct_vbase_ids: Vec<usize> = Vec::new();
        // Was any base in THIS clause spelled `virtual`? (Transitive virtual
        // heritage is tracked in `self.virtual_heritage` — see below.)
        let mut clause_saw_virtual = false;
        // S6 (G1 Stage-3 slice): was THIS base entry spelled `virtual`? Reset
        // per iteration — the gate below must not poison a PLAIN data-bearing
        // base just because a SIBLING was virtual (TFrameWindow : public
        // TWindow, public virtual TEventHandler).
        let mut this_base_virtual = false;
        if self.is_punct(Punct::Colon) {
            self.advance();
            loop {
                this_base_virtual = false;
                // `virtual` and the access-specifier may appear in EITHER order
                // before the base name — `virtual public ios` (IOSTREAM.H's
                // istream/ostream) or `public virtual`. Consume any run of them.
                // Virtual bases are PARSED but laid out as a plain base: for a
                // single-base class (istream alone has one `ios`) that is exact;
                // only a DATA-BEARING shared-vbase join (the iostream diamond)
                // needs the true Stage-3 machinery (see the gate below).
                while matches!(
                    self.kind(),
                    TokenKind::Keyword(
                        Keyword::Public | Keyword::Private | Keyword::Protected | Keyword::Virtual
                    )
                ) {
                    if matches!(self.kind(), TokenKind::Keyword(Keyword::Virtual)) {
                        clause_saw_virtual = true;
                        this_base_virtual = true;
                    }
                    self.advance();
                }
                // S4.2e: a base that is a class-template INSTANTIATION
                // (`class X : public TMBlockList<Alloc>`). Instantiate the
                // template and use the concrete record as the base subobject.
                // CLASSLIB's BIDS containers derive this way pervasively.
                let tmpl_base = match self.kind() {
                    TokenKind::Ident(s)
                        if self.class_template_idx.contains_key(s)
                            && self.kind_at(1) == Some(&TokenKind::Punct(Punct::Lt)) =>
                    {
                        Some(s.clone())
                    }
                    _ => None,
                };
                if let Some(name) = tmpl_base {
                    let ty = self.instantiate_class_template(&name)?;
                    if let Type::Record { id: bid, .. } = ty {
                        if this_base_virtual
                            && shared_data_vbase_target_ok
                            && self.shared_vbase_names.contains(&name)
                            && self.vbase_is_data_bearing(bid)
                        {
                            if bid != id && !direct_vbase_ids.contains(&bid) {
                                direct_vbase_ids.push(bid);
                            }
                        } else if base_id.is_none() {
                            base_id = Some(bid);
                        } else if bid != id && base_id != Some(bid) {
                            extra_base_infos.push((bid, this_base_virtual));
                        }
                    }
                    if !self.eat_punct(Punct::Comma) {
                        break;
                    }
                    continue;
                }
                let mut bname = match self.kind() {
                    TokenKind::Ident(s) => s.clone(),
                    _ => return Err(self.error_here("expected a base class name")),
                };
                self.advance();
                // S4.2f: a QUALIFIED base name — `class Lock : private
                // TCriticalSection::Lock` (OWL/window.h, a class deriving from a
                // nested class). mdbcc's class model is FLAT, so keep the
                // INNERMOST component (`TCriticalSection::Lock` ≡ the nested class
                // registered flat as `Lock`), mirroring the out-of-line member
                // mapping `A::B::member` → `B::member`.
                while self.is_punct(Punct::ColonColon) {
                    self.advance(); // `::`
                    bname = match self.kind() {
                        TokenKind::Ident(s) => s.clone(),
                        _ => {
                            return Err(
                                self.error_here("expected a name after '::' in a base-class name")
                            );
                        }
                    };
                    self.advance();
                }
                // Resolve the base via a tag OR a typedef that names a record.
                // The typedef path covers a class-template's type-parameter base
                // (`template<class T, class Alloc> class V : public Alloc`): at
                // instantiation `Alloc` is bound as a typedef to the concrete
                // base record. S4.2b(iv).
                let bid = self
                    .tags
                    .get(&bname)
                    .copied()
                    .or_else(|| match self.typedefs.get(&bname) {
                        Some(Type::Record { id, .. }) => Some(*id),
                        _ => None,
                    })
                    .ok_or_else(|| self.error_here(format!("unknown base class '{bname}'")))?;
                // The FIRST base is the primary subobject (`Record::base`);
                // S6 (G1 Stage-1): subsequent bases become `extra_bases`.
                // A class is NEVER its own base. With mdbcc's FLAT class model,
                // three distinct nested classes all named `Lock` (TMutex::Lock,
                // TCriticalSection::Lock, TSync::Lock — CLASSLIB/THREAD.H) collapse
                // to the tag "Lock"; resolving the base `TCriticalSection::Lock` by
                // bare tag (above) can match the record being defined
                // (`self.tags["Lock"] == id`), yielding base == self. That 1-cycle
                // makes every base-chain walk (reachability scope-build, layout,
                // vtable) spin forever — APPLICAT.CPP hung the compiler here. Drop
                // the self-edge: the flattened `Lock`s are already conflated under
                // one tag, and reachability is conservative (a missed base edge is a
                // loud link error at worst, never a silent miscompile).
                if bid != id {
                    if this_base_virtual
                        && shared_data_vbase_target_ok
                        && self.shared_vbase_names.contains(&bname)
                        && self.vbase_is_data_bearing(bid)
                    {
                        if !direct_vbase_ids.contains(&bid) {
                            direct_vbase_ids.push(bid);
                        }
                    } else if base_id.is_none() {
                        base_id = Some(bid);
                    } else if base_id != Some(bid)
                        && !extra_base_infos.iter().any(|(b, _)| *b == bid)
                    {
                        extra_base_infos.push((bid, this_base_virtual));
                    }
                }
                if !self.eat_punct(Punct::Comma) {
                    break;
                }
            }
        }
        let _ = this_base_virtual;
        // S6 (G1 Stage-1): track TRANSITIVE virtual heritage — a class whose
        // own clause says `virtual`, or any of whose bases derives virtually,
        // carries the mark. Drives the DATA-BEARING shared-vbase deferral
        // below (the iostream diamond would silently get TWO `ios` subobjects
        // under the flat model — a miscompile, so defer loudly).
        if clause_saw_virtual
            || base_id.is_some_and(|b| self.virtual_heritage.contains(&b))
            || extra_base_infos
                .iter()
                .any(|(b, _)| self.virtual_heritage.contains(b))
        {
            self.virtual_heritage.insert(id);
        }
        // Stage deferral gates. NOT a definition-time error — `class
        // iostream : istream, ostream` lives in IOSTREAM.H, so erroring here
        // would break every TU that merely INCLUDES the header (a mass
        // regression of TUs that never construct one). Instead the
        // over-stage extras are DROPPED (the pre-Stage-1 model) and the
        // class is POISONED (`Record::mi_dropped`): every CONSTRUCTION site
        // rejects it cleanly (mirroring the abstract-class checks), so a
        // missing-subobject object can never be built silently.
        //
        // S6 (G1 Stage-3 slice — STATELESS virtual mixins): a virtual base
        // whose subtree carries NO DATA (an interface mixin — OWL's
        // `TWindow : virtual TEventHandler, virtual TStreamableBase`; both
        // are vptr-only) is laid out as a PLAIN base. Re-inheritance along a
        // derived chain then yields DUPLICATE (dataless) subobjects instead
        // of one shared copy — behaviorally sound (no state to split;
        // virtual dispatch through either copy reaches the same most-derived
        // overrides via the Stage-2 secondary vtables), with the documented
        // caveat that a mixin-pointer identity comparison across paths could
        // differ from bcc32. A DATA-BEARING virtual base (ios: state/flags)
        // still defers to full Stage-3 (the true shared-vbase join):
        //  * data-bearing virtual heritage needs shared-vbase layout support;
        //  * a POLYMORPHIC extra base only needs Stage-2 secondary vtables,
        //    now available for both i386 and Win64.
        let mut mi_dropped = false;
        let secondary_vtable_thunks_ok = matches!(self.ptr_bytes, 4 | 8);
        let shared_data_vbase_ok = shared_data_vbase_target_ok;
        let subtree_has_data =
            |p: &Self, b: usize| -> bool { p.records.get(b).is_some_and(|r| !r.fields.is_empty()) };
        let mut extra_base_ids: Vec<usize> = Vec::new();
        for &(b, b_virtual) in &extra_base_infos {
            let virtual_involved = b_virtual || self.virtual_heritage.contains(&b);
            // S6 (G1 Stage-3): when `shared_data_vbase_ok` a
            // data-bearing shared virtual base (the iostream diamond reached
            // transitively through a plain extra base, e.g. iostream's
            // `ostream`, whose `ios` is shared) is supported: the extra base is
            // laid out as a plain subobject (its NON-VIRTUAL part) and its
            // `ios` is collected into this class's single shared vbase at the
            // tail. A polymorphic extra base is separate Stage-2 machinery and
            // is supported when this-adjusting secondary-vtable thunks exist
            // for the target ABI.
            let needs_secondary_vtable = self.records.get(b).is_some_and(|r| r.is_polymorphic());
            let needs_shared_data_vbase = virtual_involved && subtree_has_data(self, b);
            let over_stage = (needs_secondary_vtable && !secondary_vtable_thunks_ok)
                || (needs_shared_data_vbase && !shared_data_vbase_ok);
            if over_stage {
                mi_dropped = true;
            } else {
                extra_base_ids.push(b);
            }
        }

        if self.eat_punct(Punct::LBrace) {
            // S6 (#64): track the BARE enclosing name for nested scoped keys.
            if let Some(b) = &bare {
                self.class_nest.push(b.clone());
            }
            let tag_s = tag.clone().unwrap_or_default();
            // S6 (#64): ctor/dtor are NAMED by the source token (`Streamer`),
            // not the possibly-rebound unique symbol tag — detect against the
            // bare name. Equals `tag_s` for every non-minted class.
            let name_tag = bare.clone().unwrap_or_default();
            self.classes.entry(id).or_insert_with(|| ClassInfo {
                tag: tag_s.clone(),
                ..Default::default()
            });
            self.classes.get_mut(&id).unwrap().base = base_id;
            // Inherit base member/method *names* up front so inline derived
            // methods can resolve unqualified inherited names while parsing.
            if let Some(bid) = base_id {
                // The base's `ClassInfo` may be ABSENT — a forward-declared or
                // not-yet-captured base whose `base_id` resolved as a tag but
                // whose body never populated `classes` (CLASSLIB/TMPLINST.CPP).
                // Deriving from an unmodelled base cannot be laid out and would
                // otherwise PANIC at the many downstream `self.classes[&bid]`
                // accesses (synthesized ctor/dtor tag lookups, base-call
                // emission). Fail CLEANLY here instead — never panic, and never
                // fabricate an empty base (a silent-miscompile hazard). A
                // currently-compiling class always has its base captured, so this
                // only converts the former panic into a diagnostic.
                if !self.classes.contains_key(&bid) {
                    return Err(self
                        .error_here("cannot derive from a base class that is not fully defined"));
                }
                let (bm, bmeth) = {
                    let b = &self.classes[&bid];
                    (b.members.clone(), b.methods.clone())
                };
                let d = self.classes.get_mut(&id).unwrap();
                d.members.extend(bm);
                d.methods.extend(bmeth);
            }
            // S6 (G1 Stage-1): the same member/method NAME inheritance for the
            // extra bases — inline derived methods must resolve their
            // unqualified names too. Same fail-cleanly rule for an unmodelled
            // base as the primary just above.
            for &eb in &extra_base_ids {
                if !self.classes.contains_key(&eb) {
                    return Err(self
                        .error_here("cannot derive from a base class that is not fully defined"));
                }
                let (bm, bmeth) = {
                    let b = &self.classes[&eb];
                    (b.members.clone(), b.methods.clone())
                };
                let d = self.classes.get_mut(&id).unwrap();
                d.members.extend(bm);
                d.methods.extend(bmeth);
            }
            // S6 (G1 Stage-3): inherit member/method NAMES from each DIRECT
            // virtual base too (`istream : virtual public ios` must resolve
            // unqualified `bp`/`state`/`clear` to the shared `ios`). The
            // subobject is laid out at the tail (below) and reached via the
            // vbptr; here we only need the names visible during inline parsing.
            for &vb in &direct_vbase_ids {
                if !self.classes.contains_key(&vb) {
                    return Err(self.error_here(
                        "cannot virtually derive from a base class that is not fully defined",
                    ));
                }
                let (bm, bmeth) = {
                    let b = &self.classes[&vb];
                    (b.members.clone(), b.methods.clone())
                };
                let d = self.classes.get_mut(&id).unwrap();
                d.members.extend(bm);
                d.methods.extend(bmeth);
            }
            // C++ complete-class context ([class.mem]/7): a member-function
            // body sees ALL of its class's members, including static DATA
            // members declared lexically LATER. mdbcc parses inline bodies
            // EAGERLY but registers a static data member into
            // `static_member_types` only when the member loop reaches its
            // declaration — so an inline accessor returning a later-declared
            // static (OWL `TClipboard::GetClipboard(){return TheClipboard;}`,
            // CLIPBOAR.H) could not resolve it ("no member named ..."). Mirror
            // the base-name inheritance just above: pre-register this class's
            // OWN static data-member NAMES up front via a NON-consuming token
            // scan. A placeholder type is safe — the per-member parse below
            // overwrites it with the true type before the only point the type
            // is read (parse-end ExternGlobal emission).
            if !tag_s.is_empty() {
                let mut static_keys: Vec<String> = Vec::new();
                let mut i = self.pos;
                let mut depth: i32 = 0; // nested class/brace depth in this body
                while i < self.toks.len() {
                    match &self.toks[i].kind {
                        TokenKind::Punct(Punct::LBrace) => depth += 1,
                        TokenKind::Punct(Punct::RBrace) => {
                            if depth == 0 {
                                break; // closes this class body
                            }
                            depth -= 1;
                        }
                        TokenKind::Keyword(Keyword::Static) if depth == 0 => {
                            // Scan one declaration. A top-level `(` or `{` marks
                            // a static member FUNCTION (declarator / inline body)
                            // ⇒ no data member. Otherwise collect each Ident
                            // whose next token ends a declarator (`;` `,` `=` `[`).
                            let mut j = i + 1;
                            let (mut paren, mut brack, mut brace) = (0i32, 0i32, 0i32);
                            let mut is_fn = false;
                            let mut saw_body = false;
                            let mut names: Vec<String> = Vec::new();
                            while j < self.toks.len() {
                                let nest = paren + brack + brace;
                                match &self.toks[j].kind {
                                    TokenKind::Punct(Punct::LParen) => {
                                        if nest == 0 {
                                            is_fn = true;
                                        }
                                        paren += 1;
                                    }
                                    TokenKind::Punct(Punct::RParen) => paren -= 1,
                                    TokenKind::Punct(Punct::LBracket) => brack += 1,
                                    TokenKind::Punct(Punct::RBracket) => brack -= 1,
                                    TokenKind::Punct(Punct::LBrace) => {
                                        if nest == 0 {
                                            is_fn = true;
                                            saw_body = true;
                                        }
                                        brace += 1;
                                    }
                                    TokenKind::Punct(Punct::RBrace) => {
                                        brace -= 1;
                                        if saw_body && brace == 0 {
                                            j += 1;
                                            break; // end of inline body
                                        }
                                        if brace < 0 {
                                            break; // malformed: hit class close
                                        }
                                    }
                                    TokenKind::Punct(Punct::Semi) if nest == 0 => {
                                        j += 1;
                                        break;
                                    }
                                    TokenKind::Ident(s) if nest == 0 && !is_fn => {
                                        let ends_name = self.toks.get(j + 1).is_some_and(|t| {
                                            matches!(
                                                t.kind,
                                                TokenKind::Punct(Punct::Semi)
                                                    | TokenKind::Punct(Punct::Comma)
                                                    | TokenKind::Punct(Punct::Assign)
                                                    | TokenKind::Punct(Punct::LBracket)
                                            )
                                        });
                                        if ends_name {
                                            names.push(s.clone());
                                        }
                                    }
                                    _ => {}
                                }
                                j += 1;
                            }
                            if !is_fn {
                                for n in names {
                                    static_keys.push(format!("{tag_s}::{n}"));
                                }
                            }
                            i = j;
                            continue;
                        }
                        _ => {}
                    }
                    i += 1;
                }
                for key in static_keys {
                    self.static_member_types
                        .entry(key)
                        .or_insert_with(Type::int);
                }
                // S6 (#26b): pre-register this class's own ENUM CONSTANTS up front
                // via a non-consuming token scan — the same complete-class-context
                // ([class.mem]/7) fix the static-data-member scan above applies. An
                // inline member-function body parsed EAGERLY sees a class enum
                // constant declared lexically LATER (OWL `TCommandEnabler::
                // GetHandled(){return Handled & WasHandled;}` with `enum {WasHandled
                // =1, NonSender=2}` declared after the accessors — WINDOW.H). Without
                // this, `WasHandled` was mistaken for a member access ("no member
                // named") and the accessor was deferred + dropped. Only simple
                // enumerator forms (implicit, `= <int|char literal>`, `= <prior
                // enumerator>`) are folded here; a complex initializer falls back to
                // the running value (the member-loop's `enum_specifier` re-parse
                // still records the exact value for LATER references). `enum_consts`
                // is already TU-global (enum_specifier inserts unqualified), so this
                // only changes WHEN a constant becomes visible, not its scope ⇒
                // classes whose enum precedes its methods are byte-identical.
                let mut i = self.pos;
                let mut depth: i32 = 0;
                while i < self.toks.len() {
                    match &self.toks[i].kind {
                        TokenKind::Punct(Punct::LBrace) => depth += 1,
                        TokenKind::Punct(Punct::RBrace) => {
                            if depth == 0 {
                                break;
                            }
                            depth -= 1;
                        }
                        TokenKind::Keyword(Keyword::Enum) if depth == 0 => {
                            let mut j = i + 1;
                            // optional enum tag
                            if matches!(
                                self.toks.get(j).map(|t| &t.kind),
                                Some(TokenKind::Ident(_))
                            ) {
                                j += 1;
                            }
                            if matches!(
                                self.toks.get(j).map(|t| &t.kind),
                                Some(TokenKind::Punct(Punct::LBrace))
                            ) {
                                j += 1;
                                let mut next: i64 = 0;
                                while j < self.toks.len() {
                                    match self.toks.get(j).map(|t| &t.kind) {
                                        Some(TokenKind::Punct(Punct::RBrace)) => {
                                            j += 1;
                                            break;
                                        }
                                        Some(TokenKind::Punct(Punct::Comma)) => {
                                            j += 1;
                                        }
                                        Some(TokenKind::Ident(name)) => {
                                            let nm = name.clone();
                                            j += 1;
                                            let mut val = next;
                                            if matches!(
                                                self.toks.get(j).map(|t| &t.kind),
                                                Some(TokenKind::Punct(Punct::Assign))
                                            ) {
                                                j += 1;
                                                let mut neg = false;
                                                if matches!(
                                                    self.toks.get(j).map(|t| &t.kind),
                                                    Some(TokenKind::Punct(Punct::Minus))
                                                ) {
                                                    neg = true;
                                                    j += 1;
                                                }
                                                match self.toks.get(j).map(|t| &t.kind) {
                                                    Some(TokenKind::Int { value, .. }) => {
                                                        val = *value as i64;
                                                        if neg {
                                                            val = -val;
                                                        }
                                                        j += 1;
                                                    }
                                                    Some(TokenKind::Char { value, .. }) => {
                                                        val = *value;
                                                        j += 1;
                                                    }
                                                    Some(TokenKind::Ident(other)) => {
                                                        if let Some(v) = self.enum_consts.get(other)
                                                        {
                                                            val = *v;
                                                        }
                                                        j += 1;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            self.enum_consts.insert(nm, val);
                                            next = val + 1;
                                        }
                                        _ => {
                                            j += 1;
                                        }
                                    }
                                }
                                i = j;
                                continue;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
            }
            let mut fields: Vec<Field> = Vec::new();
            while !self.eat_punct(Punct::RBrace) {
                if self.at_eof() {
                    return Err(self.error_here("expected '}'"));
                }
                // S4.2e: a stray `;` — an empty member-declaration, or the
                // (legal, redundant) semicolon after an inline member-function /
                // constructor body (`S(int x) : B(x) {} ;` in OWL's streaming
                // classes). Skip it rather than try to parse `;` as a member.
                if self.eat_punct(Punct::Semi) {
                    continue;
                }
                // Access labels: `public:` / `private:` / `protected:`.
                if matches!(
                    self.kind(),
                    TokenKind::Keyword(Keyword::Public | Keyword::Private | Keyword::Protected)
                ) {
                    self.advance();
                    self.expect_punct(Punct::Colon, ":")?;
                    continue;
                }
                // `friend` declaration — declares a NON-member (free function or
                // class) that may access private members. An INLINE friend
                // DEFINITION (`friend ret f(params){...}`) defines a free
                // function — ClassLib/RTL/OWL befriend `operator+`, `operator<<`,
                // `operator==`, and the allocators' `operator new[]`. Parse it as
                // a free function and register it globally (in `cxx_funcs`) so it
                // is callable + emitted — mdbcc does not enforce access control,
                // so the only thing lost by the old skip was the DEFINITION. A
                // friend CLASS (`friend class X;`) or a prototype-only friend has
                // no function body to emit; the try below produces no `Item::Func`
                // and any non-function leftover falls back to the historical skip.
                if self.eat_kw(Keyword::Friend) {
                    let save_pos = self.pos;
                    let save_class = self.cur_class.take();
                    let save_locals = std::mem::take(&mut self.fn_locals);
                    let mut scratch: Vec<Item> = Vec::new();
                    let parsed = self.external_declaration(&mut scratch);
                    self.cur_class = save_class;
                    self.fn_locals = save_locals;
                    match parsed {
                        Ok(()) if scratch.iter().any(|i| matches!(i, Item::Func(_))) => {
                            for item in scratch {
                                if let Item::Func(mut f) = item {
                                    // S4 (#27): a friend function DEFINED in a class
                                    // body has implicit INLINE (vague/COMDAT)
                                    // linkage, so it is DROPPABLE — an unreachable
                                    // one prunes instead of emitting as a root.
                                    // cstring.h's in-class `string` friend operators
                                    // were roots -> always emitted -> touched
                                    // `string` -> the RTL/CRT even for a TU that
                                    // never uses strings; with the type-aware
                                    // operator reachability + the new->operator-new
                                    // edge they now prune.
                                    f.inline = true;
                                    self.cxx_funcs.push(f);
                                }
                            }
                            self.eat_punct(Punct::Semi); // optional `;` after a def
                        }
                        _ => {
                            // Friend class / prototype / a form the free-function
                            // parser can't yet handle: restore and skip (the
                            // historical, parse-accepting behavior).
                            self.pos = save_pos;
                            self.skip_friend_declaration();
                        }
                    }
                    continue;
                }
                // `virtual` (Phase B) — applies to the next dtor/method.
                let is_virtual = self.eat_kw(Keyword::Virtual);
                let inherited_virtual = |p: &Parser,
                                         key: &str,
                                         params: &[(String, Type)],
                                         const_method: bool|
                 -> bool {
                    p.inherited_virtual_signature(
                        base_id,
                        &direct_vbase_ids,
                        key,
                        params,
                        const_method,
                    )
                };
                // A leading calling-convention on a member (Borland RTL/classlib
                // write `_RTLENTRY` == __cdecl on EVERY ctor/dtor/method, e.g.
                // `_RTLENTRY TReference(unsigned short = 0)` in REF.H). The
                // convention is dropped for members (it plays no part in C++
                // member mangling — members already record `calling_conv: None`);
                // skipping it here lets the ctor/dtor detection below see the
                // name. For a regular method with a return type the conv sits
                // after the type and is handled by the declarator instead, so
                // this run is a no-op there.
                self.skip_call_conv();
                // Destructor: `[virtual] ~Tag() { ... }`
                if self.is_punct(Punct::Tilde) {
                    self.advance();
                    self.advance(); // tag name
                    self.expect_punct(Punct::LParen, "(")?;
                    // Accept the explicit `~T(void)` form (POPUP's TSubWindow):
                    // a destructor takes no parameters, and `(void)` is the
                    // empty list spelled out. `~T()` (no `void`) is unaffected.
                    self.eat_kw(Keyword::Void);
                    self.expect_punct(Punct::RParen, ")")?;
                    self.skip_exception_spec(); // `~T() throw(...)`
                    self.classes.get_mut(&id).unwrap().has_dtor = true;
                    let dtor_virtual = is_virtual || inherited_virtual(self, "~", &[], false);
                    self.classes
                        .get_mut(&id)
                        .unwrap()
                        .decl_methods
                        .push(MethodDecl {
                            key: "~".into(),
                            sym: format!("{tag_s}::~{tag_s}"),
                            params: Vec::new(),
                            const_method: false,
                            virtual_: dtor_virtual,
                            pure: false,
                        });
                    if self.eat_punct(Punct::Semi) {
                        continue; // declared; defined out of line
                    }
                    let body = self.dtor_full_body(id)?;
                    self.cxx_funcs.push(Function {
                        name: format!("{tag_s}::~{tag_s}"),
                        ret: Type::Void,
                        params: vec![("this".into(), self.this_ty(id))],
                        body,
                        const_method: false,
                        virtual_method: dtor_virtual,
                        variadic: false,
                        c_linkage: false,
                        calling_conv: None,
                        inline: true, // S4.2h: in-class member def
                    });
                    continue;
                }
                // Constructor: `Tag(params) { ... }` — or Borland's qualified
                // in-class form `Tag::Tag(params);` (railc LAYOUT.H:76 declares
                // `TLayout::TLayout(TWindow*, int, int, int, int);` this way).
                // Both route through the identical ctor parsing below; the
                // qualified form just consumes the leading `Tag ::` first.
                let is_ctor = matches!(self.kind(), TokenKind::Ident(s) if *s == name_tag)
                    && self.kind_at(1) == Some(&TokenKind::Punct(Punct::LParen));
                let is_qual_ctor = matches!(self.kind(), TokenKind::Ident(s) if *s == name_tag)
                    && self.kind_at(1) == Some(&TokenKind::Punct(Punct::ColonColon))
                    && matches!(self.kind_at(2), Some(TokenKind::Ident(s)) if *s == name_tag)
                    && self.kind_at(3) == Some(&TokenKind::Punct(Punct::LParen));
                if is_ctor || is_qual_ctor {
                    if is_qual_ctor {
                        self.advance(); // Tag
                        self.advance(); // ::
                    }
                    self.advance(); // tag
                    self.advance(); // (
                    let (params, variadic) = self.param_list()?;
                    self.expect_punct(Punct::RParen, ")")?;
                    self.skip_exception_spec(); // `Ctor(...) throw(...)`
                    self.note_defaults(&format!("{tag_s}::{tag_s}"), true);
                    if self.eat_punct(Punct::Semi) {
                        self.classes.get_mut(&id).unwrap().has_ctor = true;
                        // S4.2u: a ctor DECLARED in-class but defined out-of-line
                        // (the body is in another TU / the runtime .lib — e.g.
                        // `TApplication(const char far*, …)` in OWL's applicat.h).
                        // Register its prototype so codegen knows the class HAS a
                        // ctor with these params: `T(args)` rvalue construction +
                        // `T v(args)` then marshal/emit a call to the external
                        // symbol (resolved at link). Without this, codegen's
                        // sigs.funcs lacks `Tag::Tag` ⇒ "no declared constructor".
                        let mut full = vec![("this".into(), self.this_ty(id))];
                        full.extend(params);
                        self.extern_protos.push(Function {
                            name: format!("{tag_s}::{tag_s}"),
                            ret: Type::Void,
                            params: full,
                            body: Vec::new(),
                            const_method: false,
                            virtual_method: false,
                            variadic,
                            c_linkage: false,
                            calling_conv: None,
                            inline: false, // a prototype — never emitted
                        });
                        continue; // declared; defined out of line
                    }
                    let body = self.ctor_full_body(id, &params)?;
                    let mut full = vec![("this".into(), self.this_ty(id))];
                    full.extend(params);
                    self.cxx_funcs.push(Function {
                        name: format!("{tag_s}::{tag_s}"),
                        ret: Type::Void,
                        params: full,
                        body,
                        // Constructors are never const.
                        const_method: false,
                        virtual_method: false,
                        variadic,
                        c_linkage: false,
                        calling_conv: None,
                        inline: true, // S4.2h: in-class member def
                    });
                    self.classes.get_mut(&id).unwrap().has_ctor = true;
                    continue;
                }
                // User-defined CONVERSION operator: `operator <type> () [const]
                // [throw(...)] { body } / ;` — no return type precedes `operator`
                // (distinguishing it from a normal `Ret operator+(...)`). The
                // target type is the "return type"; the symbol encodes it so
                // several conversion operators in one class stay distinct.
                // osl/defs.h's `uint64` declares `operator _ULARGE_INTEGER()
                // const`. (Implicit conversion at USE sites is a separate,
                // unimplemented concern — record-to-scalar conversion is already
                // unhandled regardless; this only adds the member itself.)
                if self.is_kw(Keyword::Operator) {
                    self.advance(); // `operator`
                    let conv_ty = self.type_name()?;
                    self.expect_punct(Punct::LParen, "(")?;
                    self.expect_punct(Punct::RParen, ")")?;
                    let is_const = self.trailing_cv_qualifiers();
                    self.skip_exception_spec();
                    let sym = format!("{tag_s}::operator@{}", type_arg_code(&conv_ty));
                    self.classes
                        .get_mut(&id)
                        .unwrap()
                        .methods
                        .insert(sym.clone());
                    if self.eat_punct(Punct::Semi) {
                        continue; // declared; defined out of line
                    }
                    // Pure-virtual / OWL-DDVT conversion operator —
                    // `virtual operator int() = 0;` (CLASSLIB's ContainerIterator)
                    // or `= [idx];`. A declaration, no body.
                    if self.is_punct(Punct::Assign) {
                        self.member_pure_or_ddvt_suffix()?;
                        self.expect_punct(Punct::Semi, ";")?;
                        continue;
                    }
                    let body = self.member_body(id, &[])?;
                    self.cxx_funcs.push(Function {
                        name: sym,
                        ret: conv_ty,
                        params: vec![("this".into(), self.this_ty(id))],
                        body,
                        const_method: is_const,
                        virtual_method: is_virtual,
                        variadic: false,
                        c_linkage: false,
                        calling_conv: None,
                        inline: true, // S4.2h: in-class member def
                    });
                    continue;
                }
                // Data member or member function.
                // S4.2e: Borland IMPLICIT-INT member function — `name(params)`
                // with NO return type (`AllocBlock( size_t );` in
                // CLASSLIB/MEMMGR.H; its out-of-line definition returns `int`).
                // In a class body, `Ident (` where `Ident` is not a type is
                // unambiguously such a method (no call statements at class
                // scope; a typed method is `Type name (` ⇒ Ident-Ident-`(`).
                // `decl_specifiers` only does implicit-int after a qualifier, so
                // synthesize `int` and let the declarator read the name.
                let implicit_int_method = matches!(
                    self.kind(),
                    TokenKind::Ident(s)
                        if self.kind_at(1) == Some(&TokenKind::Punct(Punct::LParen))
                            && !self.typedefs.contains_key(s)
                            && !self.tags.contains_key(s)
                            && !self.class_template_idx.contains_key(s)
                );
                let base = if implicit_int_method {
                    Type::int()
                } else {
                    self.decl_specifiers()?
                };
                // S2e: Borland allows a member to be DEFINED with explicit
                // qualification INSIDE the class body — `inline void
                // TMainWindow::CM_FileExit() {...}` (railc RAILC.H:115, an OWL
                // response-table command handler). Strip a leading `Tag::` (Tag ==
                // this class) so the declarator reads the unqualified member name
                // and registers under `Tag::member` like any in-class def. (The
                // qualified-CTOR form `Tag::Tag(` is caught earlier, before
                // decl_specifiers.)
                if matches!(self.kind(), TokenKind::Ident(s) if *s == tag_s)
                    && self.kind_at(1) == Some(&TokenKind::Punct(Punct::ColonColon))
                {
                    self.advance(); // Tag
                    self.advance(); // ::
                }
                // S4.2z: a `static` data member has NO per-instance storage —
                // it is a single program-wide object whose storage lives in
                // its out-of-line definition (`int Tag::member = ..;`, parsed
                // as `Item::Global { name: "Tag::member" }`). Capture the flag
                // now: the declarator loop below re-enters `decl_specifiers`
                // (via `param_list` for any member function), which would
                // clear it. Applies to every declarator in this member
                // declaration (`static int a, b;`).
                let member_is_static = self.is_static;
                // A bare nested TYPE definition with no declarator —
                // `enum StripType { ... };` (CSTRING.H), `struct S { ... };`,
                // `class C { ... };`. decl_specifiers already registered the
                // type / enum constants; there is no member to declare, so
                // consume the `;` and move on. EXCEPT: an ANONYMOUS aggregate
                // (`union { ... };` / `struct { ... };` — a Record with NO tag)
                // is an unnamed MEMBER whose named fields are promoted into this
                // record. Keep it as an unnamed `$anon.N` field so `layout()`
                // sizes/offsets it correctly; codegen's `field_of` recurses into
                // `$anon.*` so `parent.inner` resolves transparently. OWL's
                // `TMessage` (WINDOBJ.H) uses two anonymous unions —
                // `Msg.LP.Hi`, `Msg.WParam`. A NAMED nested def (`struct tagS{}` /
                // `enum E{}`) has a tag and stays a pure type declaration.
                // Additive: no x64 byte-identity fixture has an anonymous
                // aggregate member.
                if self.is_punct(Punct::Semi) {
                    if let Type::Record { id: anon_id, .. } = &base
                        && self.records[*anon_id].tag.is_none()
                    {
                        let anon_name = format!("$anon.{}", fields.len());
                        fields.push(Field {
                            name: anon_name.clone(),
                            ty: base.clone(),
                            offset: 0,
                        });
                        self.classes.get_mut(&id).unwrap().members.insert(anon_name);
                    }
                    self.advance(); // ';'
                    continue;
                }
                // S4.2e: a class-member TYPEDEF (`typedef int F;`, the fn-ptr
                // form `typedef void (*IterFunc)(T&, void*);` in CLASSLIB's BIDS,
                // or a function-TYPE typedef). mdbcc's model is flat — member
                // typedefs are global type names — so register them exactly like
                // a namespace-scope typedef instead of treating the name as a data
                // member. Without this, the member typedef's name is unknown at
                // its use site (`void ForEach(IterFunc, ...)` ⇒ "expected a type").
                if self.is_typedef {
                    // S2e: if this member typedef aliases a CLASS via the simple
                    // `typedef <Record> Name;` form, also record it per-class so a
                    // class-scoped `Name::member` reference (OWL response tables'
                    // `typedef cls TMyClass;` → `&TMyClass::method`) resolves via
                    // the enclosing class rather than the colliding global alias.
                    if let Type::Record { id: target, .. } = &base
                        && let TokenKind::Ident(tn) = self.kind()
                        && self.kind_at(1) == Some(&TokenKind::Punct(Punct::Semi))
                    {
                        let (tn, target) = (tn.clone(), *target);
                        self.member_class_typedefs
                            .entry(id)
                            .or_default()
                            .insert(tn, target);
                    }
                    self.register_typedefs(base)?;
                    self.expect_punct(Punct::Semi, ";")?;
                    continue;
                }
                loop {
                    let (mty, mname) = self.declarator(base.clone())?;
                    // S3 (bit-fields): `T name : width ;` and the anonymous
                    // `T : width ;` / `int : 0 ;` padding forms. Real C headers
                    // (WINNT.H's `_LDT_ENTRY`, IO.H's `ftime`, plus most of the
                    // Win32 SDK) declare bit-fields, so the parser must accept
                    // the syntax. SEMANTICS (true sub-byte packing) are deferred:
                    // a *named* bit-field is laid out as an ordinary full-width
                    // member, an *anonymous* one is dropped. `sizeof` of a
                    // bit-fielded struct is therefore not yet bcc32-accurate —
                    // out of scope for the parse-acceptance ratchet, and additive
                    // (no x64 fixture / cpp / end_to_end struct uses bit-fields).
                    if self.is_punct(Punct::Colon) {
                        self.advance(); // ':'
                        let _width = self.const_expr()?;
                        if let Some(n) = mname {
                            fields.push(Field {
                                name: n.clone(),
                                ty: mty,
                                offset: 0,
                            });
                            self.classes.get_mut(&id).unwrap().members.insert(n);
                        }
                        if !self.eat_punct(Punct::Comma) {
                            self.expect_punct(Punct::Semi, ";")?;
                            break;
                        }
                        continue;
                    }
                    // S3 (anonymous struct/union member): `struct { ... } ;` or
                    // `union { ... } ;` with no member name — the inner
                    // aggregate's members are notionally promoted into the
                    // enclosing record. MAPI's `DTPAGE` (`union { ... } ;`) uses
                    // this. The SYNTAX is accepted; member-promotion SEMANTICS
                    // (resolving `parent.inner_field`) are deferred — the
                    // anonymous member contributes no named field for now.
                    // Additive: no x64 fixture has an anonymous aggregate member.
                    if mname.is_none()
                        && matches!(mty, Type::Record { .. })
                        && self.is_punct(Punct::Semi)
                    {
                        self.advance(); // ';'
                        break;
                    }
                    let mname = mname.ok_or_else(|| self.error_here("expected a member name"))?;
                    if self.is_punct(Punct::LParen) {
                        // Member function.
                        self.advance();
                        let (params, variadic) = self.param_list()?;
                        self.expect_punct(Punct::RParen, ")")?;
                        // Phase J-1: trailing-`const` (and `volatile`)
                        // qualifiers sit between `)` and the body/`;`/`=0`.
                        // The const flag is recorded on the MethodDecl + the
                        // Function so codegen can mangle const overloads
                        // distinctly (see `overload_symbol`). `volatile` is
                        // accept-and-ignore (no semantics today).
                        let is_const_method = self.trailing_cv_qualifiers();
                        // Optional exception-spec: `) const throw(...)` before
                        // the body / `= 0` / `;` (EXCEPT.H `raise() throw(xmsg)`).
                        self.skip_exception_spec();
                        self.note_defaults(&format!("{tag_s}::{mname}"), !member_is_static);
                        let method_virtual =
                            !member_is_static
                                && (is_virtual
                                    || inherited_virtual(self, &mname, &params, is_const_method));
                        // Pure virtual `... ) [const] = 0 ;` — OR Borland OWL's
                        // DDVT message-index form `... ) = [ index-expr ] ;`
                        // (`virtual void WMVScroll(RTMessage) = [WM_FIRST+WM_VSCROLL];`,
                        // pervasive in OWL 1.x window classes).
                        let (pure, ddvt_idx) = self.member_pure_or_ddvt_suffix()?;
                        // S4.2(e): record an OWL DDVT message handler so the
                        // dispatching WindowProc can be synthesised after the
                        // class body (a `= [idx]` member is a non-pure virtual).
                        if let Some(idx) = ddvt_idx {
                            self.classes
                                .get_mut(&id)
                                .unwrap()
                                .ddvt_handlers
                                .push((mname.clone(), idx));
                        }
                        if !member_is_static {
                            self.classes
                                .get_mut(&id)
                                .unwrap()
                                .decl_methods
                                .push(MethodDecl {
                                    key: mname.clone(),
                                    sym: format!("{tag_s}::{mname}"),
                                    params: params.iter().map(|(_, ty)| ty.clone()).collect(),
                                    const_method: is_const_method,
                                    virtual_: method_virtual,
                                    pure,
                                });
                        }
                        if pure || self.eat_punct(Punct::Semi) {
                            // Pure, or declared-and-defined-out-of-line: no
                            // body here. (Pure consumes its own `;`.)
                            if pure {
                                self.expect_punct(Punct::Semi, ";")?;
                            }
                            // S4.2aj/S4.2ak: a member declared in-class but
                            // defined OUT-OF-LINE (extern — in another TU / the
                            // RTL .lib). Canonical cases: the reference-returning
                            // primitive `char& string::operator()(size_t)` (which
                            // the inline `operator[]`/`operator()` siblings
                            // delegate to via `return (*this)(pos);`) and the
                            // extra-arg overloads of `append`/`assign`/`replace`/
                            // `find`/… (the 1-arg form is inline; the rest live in
                            // the .lib). The overload SET is built only from
                            // inline DEFINITIONS, so an extern-only overload is
                            // invisible to the resolver: a call mis-resolves and
                            // the inline caller DEFERS. Record each declaration's
                            // full signature as an extern proto; `compile_module`
                            // counts the DISTINCT ones toward the overload tally
                            // (dedup'd against in-TU defs, after TYPE-COMPLETING
                            // the proto's self-referential record params — they
                            // are captured here mid-class-body with `size: 0`) and
                            // adds them to the overload set. Virtuals are excluded
                            // (vtable-keyed dispatch); ctors/dtors never reach this
                            // path, steering clear of the S4.2ab regression.
                            if !pure {
                                let mut full = if member_is_static {
                                    Vec::new()
                                } else {
                                    vec![("this".into(), self.this_ty(id))]
                                };
                                full.extend(params.clone());
                                self.extern_protos.push(Function {
                                    name: format!("{tag_s}::{mname}"),
                                    ret: mty.clone(),
                                    params: full,
                                    body: Vec::new(),
                                    const_method: is_const_method,
                                    virtual_method: method_virtual,
                                    variadic,
                                    c_linkage: false,
                                    calling_conv: None,
                                    inline: false, // proto — never emitted
                                });
                            }
                            let param_tys = params.iter().map(|(_, ty)| ty.clone()).collect();
                            self.classes.get_mut(&id).unwrap().note_method(
                                mname,
                                member_is_static,
                                param_tys,
                            );
                            break;
                        }
                        let body = if member_is_static {
                            self.static_member_body(id, &params)?
                        } else {
                            self.member_body(id, &params)?
                        };
                        let param_tys: Vec<Type> =
                            params.iter().map(|(_, ty)| ty.clone()).collect();
                        let mut full = if member_is_static {
                            Vec::new()
                        } else {
                            vec![("this".into(), self.this_ty(id))]
                        };
                        full.extend(params);
                        // Tick 72 (J-13b): variadic *member* functions are
                        // now supported — `this` occupies positional slot 0
                        // (RCX), shifting all explicit args by one, but the
                        // existing variadic machinery handles this naturally:
                        // `va_start`'s anchor index is computed from
                        // `f.params` (which includes `this`), exactly
                        // cancelling the shift in the shadow-home offset.
                        // See `Gen::run` (prologue spill) and
                        // `Gen::gen_va_start` for the math.
                        self.cxx_funcs.push(Function {
                            name: format!("{tag_s}::{mname}"),
                            ret: mty,
                            params: full,
                            body,
                            const_method: is_const_method,
                            virtual_method: method_virtual,
                            variadic,
                            c_linkage: false,
                            inline: true, // S4.2h: in-class member def
                            calling_conv: None,
                        });
                        self.classes.get_mut(&id).unwrap().note_method(
                            mname,
                            member_is_static,
                            param_tys,
                        );
                        break; // a function ends this member
                    }
                    // S4.2z: a static data member contributes NO instance
                    // field (no layout slot, no vptr shift, not in `members`
                    // so `this->name` never resolves it). An unqualified
                    // in-method reference resolves to the `Tag::name` global
                    // instead — see `Gen::this_member_fallback`.
                    if !member_is_static {
                        fields.push(Field {
                            name: mname.clone(),
                            ty: mty,
                            offset: 0,
                        });
                        self.classes.get_mut(&id).unwrap().members.insert(mname);
                    } else if let Some(tag) = self.records[id].tag.clone() {
                        // S4.2#35: record the static data member's type keyed
                        // `Tag::member`, so a reference in a TU that does NOT
                        // define it can be emitted as an extern global (the
                        // out-of-line `T Tag::member = …` defines it elsewhere).
                        self.static_member_types
                            .insert(format!("{tag}::{mname}"), mty);
                    }
                    if !self.eat_punct(Punct::Comma) {
                        self.expect_punct(Punct::Semi, ";")?;
                        break;
                    }
                }
            }
            // Phase B: build the virtual-method table — base slots first
            // (inherited, keeping their indices), then this class's new
            // virtuals in declaration order. A name match against an
            // existing slot is an override/redefinition and only swaps the
            // slot's `sym` (virtual-ness is inherited even if `virtual` is
            // omitted on the override — correct C++, and covers a derived
            // dtor overriding a virtual base dtor without repeating it).
            let mut vtable: Vec<VtSlot> = match base_id {
                Some(bid) => self.records[bid].vtable.clone(),
                None => Vec::new(),
            };
            // S6 (G1 Stage-3): a SHARED virtual base contributes its virtual
            // slots for virtual-ness INHERITANCE — `~fstreambase` overrides the
            // virtual `ios::~ios` WITHOUT repeating `virtual` (FSTREAM.H:121), so
            // without the vbase's `~ios` slot the dtor is mistaken for
            // non-virtual and the class wrongly becomes non-polymorphic (its
            // vtable + any secondary vtables then go un-emitted ⇒ a SetVptr
            // dangling-vtable panic). Merge each direct vbase's slots the
            // primary chain doesn't already provide; a same-key decl below
            // overrides the sym (the dtor slot ⇒ this class's dtor).
            for &vb in &direct_vbase_ids {
                for s in self.records[vb].vtable.clone() {
                    if !vtable.iter().any(|e| e.key == s.key) {
                        vtable.push(s);
                    }
                }
            }
            let dms = self.classes[&id].decl_methods.clone();
            for m in &dms {
                let sym = if m.pure { String::new() } else { m.sym.clone() };
                if let Some(slot) = vtable.iter_mut().find(|s| s.key == m.key) {
                    if m.virtual_ {
                        slot.sym = sym;
                    }
                } else if m.virtual_ {
                    vtable.push(VtSlot {
                        key: m.key.clone(),
                        params: m.params.clone(),
                        sym,
                    });
                }
            }
            let polymorphic = !vtable.is_empty();
            // S4.2d: a polymorphic class whose base is NON-polymorphic but
            // carries data members. The vptr occupies `[0, ptr_bytes)`, so the
            // base subobject is pushed to `ptr_bytes` and a `Derived*→Base*` /
            // base-method `this` must be adjusted by that offset (the Microsoft
            // object model). `base_offset` (set below, after layout) records the
            // delta; codegen gates every adjustment on it being non-zero.
            let needs_base_shift = polymorphic
                && base_id.is_some_and(|bid| {
                    !self.records[bid].is_polymorphic() && !self.records[bid].fields.is_empty()
                });
            // S4.2d: base ctor/dtor CHAINING `this` is adjusted in codegen
            // (`base_ctor_call_adjust` + the exception-cleanup pad), so a base
            // with a ctor/dtor is now supported too — no error here.
            // Single inheritance: re-lay [base fields ++ derived fields]. With a
            // front vptr (polymorphic) the base fields land at `ptr_bytes`,
            // reproducing the base's relative offsets shifted by the vptr.
            let base_first_off = base_id
                .and_then(|bid| self.records[bid].fields.first().map(|f| f.offset))
                .unwrap_or(0);
            if let Some(bid) = base_id {
                let mut all = self.records[bid].fields.clone();
                all.append(&mut fields);
                fields = all;
            }
            // S6 (G1 Stage-3): a class that DIRECTLY virtually-derives a
            // data-bearing vbase carries a hidden vbptr — a pointer to the
            // single shared vbase subobject (appended at the tail below).
            // Model it as a real `$vbptr` Field right after the vptr so the
            // existing flatten/re-lay machinery preserves it automatically when
            // this class is itself a base. (Borland stores a vbtable offset; we
            // store a direct pointer — same 4-byte width, simpler, and
            // self-consistent across an all-mdbcc link.)
            let has_vbptr = !direct_vbase_ids.is_empty();
            if has_vbptr {
                fields.insert(
                    0,
                    Field {
                        name: "$vbptr".into(),
                        ty: Type::Ptr(Box::new(Type::char_())),
                        offset: 0,
                    },
                );
            }
            let (size, align) = layout(
                &mut fields,
                is_union,
                polymorphic,
                self.ptr_bytes,
                self.max_align(),
            );
            // base_offset = where the base subobject now starts, minus where it
            // started in the base's own record (0 for a non-poly base).
            let base_offset = if needs_base_shift {
                fields.first().map(|f| f.offset).unwrap_or(0) - base_first_off
            } else {
                0
            };
            // S6 (G1 Stage-1): append each EXTRA base's subobject after the
            // `[primary ++ own]` content, at `align_up(size, b.align)`. The
            // base's fields are flattened in at `sub_off + b-relative offset`
            // — NOT re-laid — so the base's own internal layout is preserved
            // exactly and `B::method(this + sub_off)` reads the right bytes
            // on every target. ([A][own][B] order: self-consistent across an
            // all-mdbcc link; see `Record::extra_bases`.)
            let mut size = size;
            let mut align = align;
            let mut extra_bases: Vec<crate::ast::BaseSpec> = Vec::new();
            for &eb in &extra_base_ids {
                let (eb_fields, eb_nv_size, eb_align) = {
                    let r = &self.records[eb];
                    // S6 (G1 Stage-3): embed only the extra base's NON-VIRTUAL
                    // part — its shared vbase (if any) is collected and appended
                    // ONCE at THIS object's tail, not duplicated per subobject.
                    // `eb.fields` already excludes the vbase subobject (kept in
                    // the vbase record, reached via vbptr), so the NV byte count
                    // is the offset of the first vbase, or the full size when
                    // the extra base has none.
                    let nv = r.vbases.first().map(|v| v.offset).unwrap_or(r.size);
                    (r.fields.clone(), nv, r.align)
                };
                let a = eb_align.max(1).min(self.max_align());
                let sub_off = size.div_ceil(a) * a;
                for mut f in eb_fields {
                    f.offset += sub_off;
                    fields.push(f);
                }
                size = sub_off + eb_nv_size.max(1);
                align = align.max(a);
                // S6 (G1 Stage-2): a POLYMORPHIC extra base gets a SECONDARY
                // vtable, minted as a SYNTHETIC record so it rides the
                // record-id-keyed vtable machinery (codegen `RipRef::Vtable`,
                // COFF, linker) unchanged. Slot keys mirror the base's
                // vtable; a slot this class overrides (its `decl_methods`)
                // points at the this-adjusting thunk `$thunk$<off>$<sym>`
                // (codegen synthesizes the target-ABI adjustment), the rest
                // inherit the base's syms (`this` = the subobject, already
                // correct). The derived SetVptr installs it at
                // `[this+sub_off]` after the primary vptr store.
                let sec_vtable = if self.records[eb].is_polymorphic() {
                    let dms = self
                        .classes
                        .get(&id)
                        .map(|c| c.decl_methods.clone())
                        .unwrap_or_default();
                    let dtag = tag.clone().unwrap_or_default();
                    let mut slots: Vec<VtSlot> = Vec::new();
                    for s in &self.records[eb].vtable {
                        let m = dms.iter().find(|m| m.key == s.key);
                        let sym = match m {
                            Some(m) if m.pure => String::new(),
                            Some(m) => format!("$thunk${sub_off}${}", m.sym),
                            None => s.sym.clone(),
                        };
                        slots.push(VtSlot {
                            key: s.key.clone(),
                            params: s.params.clone(),
                            sym,
                        });
                    }
                    let sid = self.records.len();
                    self.records.push(Record {
                        tag: Some(format!("{dtag}$secvt${sid}")),
                        is_union: false,
                        fields: Vec::new(),
                        size: 1,
                        align: 1,
                        base: None,
                        base_offset: 0,
                        extra_bases: Vec::new(),
                        mi_dropped: false,
                        vtable: slots,
                        vbases: Vec::new(),
                        vbptr_offsets: Vec::new(),
                    });
                    Some(sid)
                } else {
                    None
                };
                extra_bases.push(crate::ast::BaseSpec {
                    id: eb,
                    offset: sub_off,
                    sec_vtable,
                });
            }
            // S6 (G1 Stage-3): collect the SHARED virtual bases — this class's
            // DIRECT `virtual` bases plus the (transitive) vbases of its primary
            // and extra bases — deduplicated by record id, then append each
            // ONCE at the object tail. Every subobject that virtually-derives a
            // vbase reaches it via a vbptr (set by the construction site).
            let mut vbase_ids: Vec<usize> = Vec::new();
            for &v in &direct_vbase_ids {
                if !vbase_ids.contains(&v) {
                    vbase_ids.push(v);
                }
            }
            {
                let mut inherited: Vec<usize> = Vec::new();
                if let Some(bid) = base_id {
                    inherited.extend(self.records[bid].vbases.iter().map(|x| x.id));
                }
                for &eb in &extra_base_ids {
                    inherited.extend(self.records[eb].vbases.iter().map(|x| x.id));
                }
                for v in inherited {
                    if !vbase_ids.contains(&v) {
                        vbase_ids.push(v);
                    }
                }
            }
            // Single-vbase scope (the only shape in railc/OWL/RTL — the `ios`
            // diamond): ≥2 DISTINCT virtual bases would need a vbptr-per-vbase
            // (or a vbtable); poison cleanly until a real need appears.
            if vbase_ids.len() > 1 {
                mi_dropped = true;
                vbase_ids.clear();
            }
            if base_id.is_some_and(|b| self.records[b].mi_dropped)
                || extra_base_ids.iter().any(|&b| self.records[b].mi_dropped)
            {
                mi_dropped = true;
                vbase_ids.clear();
            }
            let mut vbases: Vec<crate::ast::VBase> = Vec::new();
            if !mi_dropped {
                // Canonical vbptr offset for member access / upcast = the
                // smallest `$vbptr` field offset (the primary-spine vbptr).
                let canon_vbptr = fields
                    .iter()
                    .filter(|f| f.name == "$vbptr")
                    .map(|f| f.offset)
                    .min()
                    .unwrap_or(self.ptr_bytes);
                for &v in &vbase_ids {
                    let (vsz, val) = {
                        let r = &self.records[v];
                        (r.size, r.align)
                    };
                    let a = val.max(1).min(self.max_align());
                    let voff = size.div_ceil(a) * a;
                    vbases.push(crate::ast::VBase {
                        id: v,
                        offset: voff,
                        vbptr_offset: canon_vbptr,
                    });
                    size = voff + vsz.max(1);
                    align = align.max(a);
                }
            }
            // Every `$vbptr` field in the complete object, paired with the vbase
            // it points to (single-vbase scope ⇒ all reach `vbases[0]`). The
            // construction site stores `this + vbase.offset` into each.
            let vbptr_offsets: Vec<(usize, usize)> = if vbases.is_empty() {
                Vec::new()
            } else {
                let vid = vbases[0].id;
                fields
                    .iter()
                    .filter(|f| f.name == "$vbptr")
                    .map(|f| (vid, f.offset))
                    .collect()
            };
            let size = if extra_bases.is_empty() && vbases.is_empty() {
                size // untouched single-inheritance path (byte-identical)
            } else {
                size.div_ceil(align.max(1)) * align.max(1)
            };
            self.records[id] = Record {
                tag,
                is_union,
                fields,
                size,
                align,
                base: base_id,
                base_offset,
                extra_bases,
                mi_dropped,
                vtable,
                vbases,
                vbptr_offsets,
            };
            // Synthesize implicit derived ctor/dtor that chain to the base
            // when the base needs construction/destruction and the derived
            // class declares neither itself.
            self.synthesize_base_chaining(id);
            // S4.2(e): synthesise the dispatching WindowProc for OWL DDVT
            // message handlers (`virtual void WMxxx(RTMessage) = [idx];`).
            self.synthesize_ddvt_windowproc(id);
            // Phase B: a polymorphic class must run a constructor so its
            // vtable pointer is installed at `[this+0]`. If neither the
            // class nor base-chaining provided one, synthesize a default
            // ctor whose sole job is the vptr install; `T v;` auto-invokes
            // it (gated on `has_ctor`). No base here ⇒ SetVptr is the body.
            if self.records[id].is_polymorphic() && !self.classes[&id].has_ctor {
                let tag = self.classes[&id].tag.clone();
                self.cxx_funcs.push(Function {
                    name: format!("{tag}::{tag}"),
                    ret: Type::Void,
                    params: vec![("this".into(), self.this_ty(id))],
                    body: vec![Stmt::SetVptr(id, Loc::default())],
                    const_method: false,
                    virtual_method: false,
                    variadic: false,
                    c_linkage: false,
                    // S4.2af: an IMPLICITLY-defined default ctor is emitted by
                    // every TU that constructs the class, so `inline` (a) lets
                    // the prune drop it when unreachable and (b) makes its COFF
                    // symbol WeakExternal so the linker folds the cross-object
                    // duplicates (e.g. a COM interface's ctor from OBJIDL.H).
                    inline: true,
                    calling_conv: None,
                });
                self.classes.get_mut(&id).unwrap().has_ctor = true;
            }
            // Tick 70 (J-11b-members): now that this class's fields
            // are finalised, splice class-typed member ctor/dtor calls
            // into every user-written or synthesised ctor/dtor.
            self.inject_member_ctor_dtor_calls(id);
            // S6 (#64): body fully parsed — mark defined (so a later nested
            // class reusing this flat tag mints fresh) and pop the nesting.
            self.defined_records.insert(id);
            if let Some(key) = &specialization_key {
                self.class_specializations.remove(key);
            }
            if bare.is_some() {
                self.class_nest.pop();
            }
        }
        self.is_typedef = was_typedef;
        let r = &self.records[id];
        Ok(Type::Record {
            id,
            size: r.size,
            align: r.align,
        })
    }

    /// In a member body and `name` isn't shadowed by a param/local.
    fn in_class_method(&self, name: &str) -> bool {
        self.cur_class.is_some() && !self.fn_locals.contains(name)
    }

    fn member_qname_for_key(tag: &str, key: &str) -> String {
        if key == "~" {
            format!("{tag}::~{tag}")
        } else {
            format!("{tag}::{key}")
        }
    }

    fn function_matches_member_sig(
        f: &Function,
        params: &[(String, Type)],
        const_method: bool,
    ) -> bool {
        f.const_method == const_method
            && f.params.len() == params.len() + 1
            && f.params
                .iter()
                .skip(1)
                .zip(params)
                .all(|((_, actual), (_, expected))| Self::signature_types_match(actual, expected))
    }

    fn method_decl_matches_member_sig(
        m: &MethodDecl,
        key: &str,
        params: &[(String, Type)],
        const_method: bool,
    ) -> bool {
        m.key == key
            && m.virtual_
            && m.const_method == const_method
            && m.params.len() == params.len()
            && m.params
                .iter()
                .zip(params)
                .all(|(actual, (_, expected))| Self::signature_types_match(actual, expected))
    }

    fn signature_types_match(actual: &Type, expected: &Type) -> bool {
        if actual == expected {
            return true;
        }
        match (actual, expected) {
            (Type::Record { id: actual, .. }, Type::Record { id: expected, .. }) => {
                actual == expected
            }
            (Type::Ptr(actual), Type::Ptr(expected)) | (Type::Ref(actual), Type::Ref(expected)) => {
                Self::signature_types_match(actual, expected)
            }
            (Type::Array(actual, actual_len), Type::Array(expected, expected_len)) => {
                actual_len == expected_len && Self::signature_types_match(actual, expected)
            }
            (
                Type::Func {
                    ret: actual_ret,
                    params: actual_params,
                },
                Type::Func {
                    ret: expected_ret,
                    params: expected_params,
                },
            ) => {
                actual_params.len() == expected_params.len()
                    && Self::signature_types_match(actual_ret, expected_ret)
                    && actual_params
                        .iter()
                        .zip(expected_params)
                        .all(|(actual, expected)| Self::signature_types_match(actual, expected))
            }
            (
                Type::MemFn {
                    class_id: actual_class,
                    ret: actual_ret,
                    params: actual_params,
                },
                Type::MemFn {
                    class_id: expected_class,
                    ret: expected_ret,
                    params: expected_params,
                },
            ) => {
                actual_class == expected_class
                    && actual_params.len() == expected_params.len()
                    && Self::signature_types_match(actual_ret, expected_ret)
                    && actual_params
                        .iter()
                        .zip(expected_params)
                        .all(|(actual, expected)| Self::signature_types_match(actual, expected))
            }
            _ => false,
        }
    }

    fn inherited_virtual_signature(
        &self,
        base_id: Option<usize>,
        direct_vbase_ids: &[usize],
        key: &str,
        params: &[(String, Type)],
        const_method: bool,
    ) -> bool {
        let mut seen = HashSet::new();
        base_id.is_some_and(|bid| {
            self.record_has_virtual_signature(bid, key, params, const_method, &mut seen)
        }) || direct_vbase_ids
            .iter()
            .any(|&vb| self.record_has_virtual_signature(vb, key, params, const_method, &mut seen))
    }

    fn record_has_virtual_signature(
        &self,
        id: usize,
        key: &str,
        params: &[(String, Type)],
        const_method: bool,
        seen: &mut HashSet<usize>,
    ) -> bool {
        if !seen.insert(id) {
            return false;
        }
        let Some(rec) = self.records.get(id) else {
            return false;
        };
        if let Some(tag) = rec.tag.as_deref() {
            if self.classes.get(&id).is_some_and(|ci| {
                ci.decl_methods
                    .iter()
                    .any(|m| Self::method_decl_matches_member_sig(m, key, params, const_method))
            }) {
                return true;
            }
            let q = Self::member_qname_for_key(tag, key);
            if self
                .cxx_funcs
                .iter()
                .chain(self.extern_protos.iter())
                .any(|f| {
                    f.name == q
                        && f.virtual_method
                        && Self::function_matches_member_sig(f, params, const_method)
                })
            {
                return true;
            }
        }
        if rec.base.is_some_and(|bid| {
            self.record_has_virtual_signature(bid, key, params, const_method, seen)
        }) {
            return true;
        }
        if rec
            .extra_bases
            .iter()
            .any(|b| self.record_has_virtual_signature(b.id, key, params, const_method, seen))
        {
            return true;
        }
        rec.vbases
            .iter()
            .any(|b| self.record_has_virtual_signature(b.id, key, params, const_method, seen))
    }

    fn virtual_member_definition_declared(
        &self,
        name: &str,
        params: &[(String, Type)],
        const_method: bool,
    ) -> bool {
        self.cxx_funcs
            .iter()
            .chain(self.extern_protos.iter())
            .any(|f| {
                f.name == name
                    && f.virtual_method
                    && Self::function_matches_member_sig(f, params, const_method)
            })
    }

    /// S4 (#50): if `name` is a STATIC data member of the current class (or any
    /// single-inheritance base), return its qualified `Tag::name`; else `None`.
    /// Static members are recorded in `static_member_types` (keyed `Tag::name`)
    /// during class parsing and are deliberately NOT in the instance `members`
    /// set, so an unqualified in-method reference needs this to find them.
    fn unqualified_static_member(&self, name: &str) -> Option<String> {
        lookup_static_member_from_class(
            &self.classes,
            &self.static_member_types,
            self.cur_class?,
            name,
        )
    }

    /// Resolve unqualified static data-member names captured inside default
    /// arguments after the full class body has been parsed.
    fn qualify_default_arg_static_refs(&mut self) {
        let tags = &self.tags;
        let classes = &self.classes;
        let static_member_types = &self.static_member_types;
        let referenced_statics = &mut self.referenced_statics;

        for (name, defaults) in &mut self.fn_defaults {
            let Some(cid) = default_owner_class(tags, name) else {
                continue;
            };
            for default in defaults.iter_mut().flatten() {
                qualify_default_static_refs_expr(
                    default,
                    cid,
                    classes,
                    static_member_types,
                    referenced_statics,
                );
            }
        }

        for (name, _, defaults) in &mut self.overload_defaults {
            let Some(cid) = default_owner_class(tags, name) else {
                continue;
            };
            for default in defaults.iter_mut().flatten() {
                qualify_default_static_refs_expr(
                    default,
                    cid,
                    classes,
                    static_member_types,
                    referenced_statics,
                );
            }
        }
    }

    /// `Tag*` for the implicit `this` parameter (size filled by codegen via
    /// the record registry once the class is finalized).
    fn this_ty(&self, id: usize) -> Type {
        Type::Ptr(Box::new(Type::Record {
            id,
            size: 0,
            align: 1,
        }))
    }

    /// Parse a member-function/ctor/dtor body with class context active so
    /// unqualified members resolve through `this`.
    fn member_body(&mut self, id: usize, params: &[(String, Type)]) -> PResult<Vec<Stmt>> {
        self.member_body_with_this(id, params, true)
    }

    /// Parse a static member-function body with class context active but no
    /// implicit `this` parameter.
    fn static_member_body(
        &mut self,
        id: usize,
        params: &[(String, Type)],
    ) -> PResult<Vec<Stmt>> {
        self.member_body_with_this(id, params, false)
    }

    fn member_body_with_this(
        &mut self,
        id: usize,
        params: &[(String, Type)],
        has_this: bool,
    ) -> PResult<Vec<Stmt>> {
        let prev_class = self.cur_class;
        let prev_locals = std::mem::take(&mut self.fn_locals);
        self.cur_class = Some(id);
        self.fn_locals = HashSet::new();
        if has_this {
            self.fn_locals.insert("this".into());
        }
        for (n, _) in params {
            self.fn_locals.insert(n.clone());
        }
        let body = self.block();
        self.cur_class = prev_class;
        self.fn_locals = prev_locals;
        body
    }

    /// Constructor body with member-initializer list. Builds, in order: the
    /// base constructor call (explicit `: Base(args)` or implicit default),
    /// `this->member = init` for each member initializer, then the user body.
    fn ctor_full_body(&mut self, id: usize, params: &[(String, Type)]) -> PResult<Vec<Stmt>> {
        let base_id = self.classes.get(&id).and_then(|c| c.base);
        let base_tag = base_id.map(|b| self.classes[&b].tag.clone());
        let base_has_ctor = base_id.map(|b| self.classes[&b].has_ctor).unwrap_or(false);

        let prev_class = self.cur_class;
        let prev_locals = std::mem::take(&mut self.fn_locals);
        self.cur_class = Some(id);
        self.fn_locals = HashSet::new();
        self.fn_locals.insert("this".into());
        for (n, _) in params {
            self.fn_locals.insert(n.clone());
        }

        let mut base_args: Vec<Expr> = Vec::new();
        // S4 (#8/#34): carry the FULL argument list for each member init. A
        // class-typed member `: Data(upper-lower+1, delta)` is a CONSTRUCTION
        // (all args matter), not an assignment of the first arg. The member's
        // type is unknown here (fields aren't laid out yet), so the ctor-vs-
        // assign decision is deferred to `inject_member_ctor_dtor_calls`.
        let mut minits: Vec<(String, Vec<Expr>, Loc)> = Vec::new();
        let parsed: PResult<()> = (|| {
            if self.eat_punct(Punct::Colon) {
                loop {
                    let init_loc = self.loc_here();
                    let mut nm = match self.kind() {
                        TokenKind::Ident(s) => s.clone(),
                        _ => {
                            return Err(self.error_here("expected an initializer name"));
                        }
                    };
                    self.advance();
                    // S4.2f: a QUALIFIED base initializer — `: TCriticalSection::
                    // Lock(sync)` (OWL/window.h's out-of-line nested-class ctor
                    // `TSync::Lock::Lock(...) : TCriticalSection::Lock(...)`). Keep
                    // the innermost component to match the FLAT base tag (a member
                    // initializer is never qualified, so this only fires on bases).
                    while self.is_punct(Punct::ColonColon) {
                        self.advance();
                        nm = match self.kind() {
                            TokenKind::Ident(s) => s.clone(),
                            _ => {
                                return Err(
                                    self.error_here("expected a name after '::' in an initializer")
                                );
                            }
                        };
                        self.advance();
                    }
                    // S4.2e: a template-id base initializer
                    // `: TMBlockList<Alloc>(blk)`. Only a BASE can be a template-id
                    // in the init list (a data member is never `Name<...>`), so the
                    // `<...>` marks this as the base initializer — consume the args
                    // and route it to `base_args`.
                    let is_template_base = self.is_punct(Punct::Lt);
                    if is_template_base {
                        self.skip_angle_brackets();
                    }
                    self.expect_punct(Punct::LParen, "(")?;
                    let mut args = Vec::new();
                    if !self.is_punct(Punct::RParen) {
                        loop {
                            args.push(self.assignment()?);
                            if !self.eat_punct(Punct::Comma) {
                                break;
                            }
                        }
                    }
                    self.expect_punct(Punct::RParen, ")")?;
                    if is_template_base || base_tag.as_deref() == Some(nm.as_str()) {
                        base_args = args;
                    } else {
                        minits.push((nm, args, init_loc));
                    }
                    if !self.eat_punct(Punct::Comma) {
                        break;
                    }
                }
            }
            Ok(())
        })();
        let body = parsed.and_then(|()| self.block());
        self.cur_class = prev_class;
        self.fn_locals = prev_locals;
        let body = body?;

        let mut out = Vec::new();
        if base_has_ctor {
            let bt = base_tag.clone().unwrap();
            let mut a = vec![Expr::Var("this".into(), Loc::default())];
            a.extend(base_args);
            out.push(Stmt::ExprStmt(
                Expr::Call {
                    name: format!("{bt}::{bt}"),
                    args: a,
                    loc: Loc::default(),
                },
                Loc::default(),
            ));
        }
        // Install this class's vtable AFTER base construction and BEFORE
        // member-inits / user body: most-derived vtable wins, runs on
        // every exit path (incl. early `return`), and in-ctor virtual
        // calls dispatch correctly. No-op in codegen if non-polymorphic.
        out.push(Stmt::SetVptr(id, Loc::default()));
        // Tick 70 (J-11b-members): the class-typed-member default-ctor
        // calls are inserted in a class-finalisation post-pass (in
        // `inject_member_ctor_dtor_calls`); records[id].fields is not
        // yet populated when ctor_full_body runs during member parsing.
        // The post-pass scans every ctor for this class's tag and
        // splices the member-ctor calls in right after SetVptr.
        for (m, args, loc) in minits {
            // Emit the deferred member-init marker; `inject_member_ctor_dtor_calls`
            // resolves it to a ctor call (class-typed member) or `this->m = args[0]`
            // (scalar) once the member's type is known.
            out.push(Stmt::MemberInit {
                field: m,
                args,
                loc,
            });
        }
        out.extend(body);
        Ok(out)
    }

    /// Destructor body, with the base destructor appended (runs last).
    /// Tick 70 (J-11b-members): class-typed member dtor calls are
    /// inserted by `inject_member_ctor_dtor_calls` after the class is
    /// fully parsed (records[id].fields is finalised). They land
    /// between the user body and the base dtor, in REVERSE declaration
    /// order, per the C++ [class.dtor]/9 destruction sequence.
    fn dtor_full_body(&mut self, id: usize) -> PResult<Vec<Stmt>> {
        let base_id = self.classes.get(&id).and_then(|c| c.base);
        let base_tag = base_id.map(|b| self.classes[&b].tag.clone());
        let base_has_dtor = base_id.map(|b| self.classes[&b].has_dtor).unwrap_or(false);
        let body = self.member_body(id, &[]);
        let mut out = body?;
        if base_has_dtor {
            let bt = base_tag.unwrap();
            out.push(Stmt::ExprStmt(
                Expr::Call {
                    name: format!("{bt}::~{bt}"),
                    args: vec![Expr::Var("this".into(), Loc::default())],
                    loc: Loc::default(),
                },
                Loc::default(),
            ));
        }
        Ok(out)
    }

    /// Tick 70 (J-11b-members): post-pass run AFTER `records[id].fields`
    /// is finalised. Walks `self.cxx_funcs` and splices class-typed
    /// member ctor/dtor calls into every member function whose
    /// mangled name is `Tag::Tag` or `Tag::~Tag` for this class.
    ///
    /// Ctor injection points:
    ///   * After `Stmt::SetVptr(id, _)` (the parser places it right
    ///     after the base ctor call). Member ctor calls go BEFORE
    ///     any subsequent statements (which are minit assigns + user
    ///     body in `ctor_full_body`, or none in synthesised ctors).
    ///   * Members already mentioned in the user's minit list are
    ///     identified by the `Assign{Member{this, m, ..}, ..}` shape
    ///     appearing later in the body and SKIPPED here (v1: minit-list
    ///     class-typed members go through the assign path and do not
    ///     receive a ctor call — out of scope for tick 70).
    ///
    /// Dtor injection points: between the user body and the base dtor
    /// call. Identified by the trailing `Call("Base::~Base", [this])`.
    /// If no base dtor, member dtors are appended at the end.
    fn inject_member_ctor_dtor_calls(&mut self, id: usize) {
        let dtag = self.classes[&id].tag.clone();
        let ctor_name = format!("{dtag}::{dtag}");
        let dtor_name = format!("{dtag}::~{dtag}");
        // Collect skip-set for ctor injection: members mentioned by
        // the user's minit list (identified by Assign{Member,..} after
        // SetVptr, before user-body statements).
        // We do this on a per-function basis since the minit list is
        // function-specific.
        // To avoid borrow-checker issues, take the funcs vector out,
        // mutate it, put it back.
        let mut funcs = std::mem::take(&mut self.cxx_funcs);
        for f in funcs.iter_mut() {
            if f.name == ctor_name {
                let minit_names = collect_minit_names(&f.body);
                let extra = self.class_typed_member_ctor_stmts(id, &minit_names);
                if !extra.is_empty() {
                    splice_after_setvptr(&mut f.body, id, extra);
                }
                // NB: the `MemberInit` markers in this ctor are resolved by the
                // single end-of-parse sweep in `parse_for` (which also reaches
                // OUT-OF-LINE ctor definitions this per-class pass never sees).
            } else if f.name == dtor_name {
                let extra = self.member_dtor_stmts(id);
                if !extra.is_empty() {
                    splice_before_base_dtor(&mut f.body, id, extra);
                }
            }
        }
        self.cxx_funcs = funcs;
    }

    /// Tick 70 (J-11b-members): collect the class-typed members of `id`
    /// whose record has a ctor — these need an implicit default-ctor
    /// call inserted into the enclosing class's ctor body (unless the
    /// user listed them in a member-initialiser list). Returns
    /// `(field_name, ctor_tag)` pairs in DECLARATION order.
    ///
    /// `exclude_minits` is the set of field names that already appear
    /// in the user's `: a(...), b(...)` member-initialiser list; those
    /// are handled via the existing `this->m = expr` assignment lower
    /// down. (v1 limitation: a class-typed member listed in the minit
    /// list with class-typed args still goes through the assign path
    /// and does NOT invoke a ctor — out of scope for tick 70.)
    fn class_typed_member_ctor_stmts(
        &self,
        id: usize,
        exclude_minits: &HashSet<String>,
    ) -> Vec<Stmt> {
        let (own_start, own_end) = self.own_field_range(id);
        let mut out = Vec::new();
        let fields = &self.records[id].fields[..own_end];
        for f in fields.iter().skip(own_start) {
            if exclude_minits.contains(&f.name) {
                continue;
            }
            let Type::Record { id: fid, .. } = &f.ty else {
                continue;
            };
            let Some(ci) = self.classes.get(fid) else {
                continue;
            };
            if !ci.has_ctor {
                continue;
            }
            let tag = ci.tag.clone();
            // `this->m.Tag()` — codegen's MethodCall lowering takes the
            // address of the Member expr and passes it as `this` to
            // `Tag::Tag`. No user-provided arguments (default ctor).
            out.push(Stmt::ExprStmt(
                Expr::MethodCall {
                    recv: Box::new(Expr::Member {
                        base: Box::new(Expr::Var("this".into(), Loc::default())),
                        field: f.name.clone(),
                        arrow: true,
                        loc: Loc::default(),
                    }),
                    name: tag,
                    args: Vec::new(),
                    loc: Loc::default(),
                },
                Loc::default(),
            ));
        }
        out
    }

    /// S6 (G1 Stage-1): the index range of this class's OWN data members
    /// within the flattened `records[id].fields` — `[primary-base fields |
    /// own fields | extra-base fields]`. The member ctor/dtor injection
    /// passes iterate exactly the own slice (an extra base's members are
    /// constructed/destroyed by ITS ctor/dtor, never directly).
    fn own_field_range(&self, id: usize) -> (usize, usize) {
        let start = self.records[id]
            .base
            .map(|b| self.records[b].fields.len())
            .unwrap_or(0);
        let extra: usize = self.records[id]
            .extra_bases
            .iter()
            .map(|eb| self.records[eb.id].fields.len())
            .sum();
        (start, self.records[id].fields.len() - extra)
    }

    /// S4 (#8/#34): resolve a `Stmt::MemberInit { field, args }` into its
    /// concrete lowering, now that `records[id].fields` is finalized:
    ///   * S6 (G1 Stage-1): `field` naming an EXTRA direct base (`: B(args)`
    ///     in a multiply-inheriting ctor) -> `B::B(this, args)`; codegen's
    ///     `base_ctor_call_adjust` shifts `this` to the B subobject. A
    ///     ctor-less extra base init (`: B()` on a POD base) is a no-op.
    ///   * a class-typed member WITH a constructor -> a ctor call
    ///     (`this->field.<MemberTag>(args)`, which codegen lowers to
    ///     `MemberTag::MemberTag(&this->field, args)`), so the sub-object is
    ///     CONSTRUCTED with all supplied arguments (e.g. `: Data(sz, delta)`);
    ///   * anything else (scalar / pointer / POD record without a ctor) ->
    ///     `this->field = args[0]`, byte-identical to the historical lowering.
    fn resolve_member_init(&self, id: usize, field: &str, mut args: Vec<Expr>, loc: Loc) -> Stmt {
        if let Some(eb) = self.records[id]
            .extra_bases
            .iter()
            .find(|eb| self.records[eb.id].tag.as_deref() == Some(field))
        {
            if self.classes.get(&eb.id).is_some_and(|c| c.has_ctor) {
                let mut a = vec![Expr::Var("this".into(), loc)];
                a.append(&mut args);
                return Stmt::ExprStmt(
                    Expr::Call {
                        name: format!("{field}::{field}"),
                        args: a,
                        loc,
                    },
                    loc,
                );
            }
            return Stmt::Block(Vec::new(), loc); // ctor-less base: no-op
        }
        if let Some(vb) = self.records[id]
            .vbases
            .iter()
            .find(|vb| self.records[vb.id].tag.as_deref() == Some(field))
        {
            if self.classes.get(&vb.id).is_some_and(|c| c.has_ctor) {
                let mut a = vec![Expr::Var("this".into(), loc)];
                a.append(&mut args);
                return Stmt::ExprStmt(
                    Expr::Call {
                        name: format!("{field}::{field}"),
                        args: a,
                        loc,
                    },
                    loc,
                );
            }
            return Stmt::Block(Vec::new(), loc); // ctor-less vbase: no-op
        }
        if let Some(base_id) = self.reachable_base_by_tag(id, field) {
            if self.classes.get(&base_id).is_some_and(|c| c.has_ctor) {
                let mut a = vec![Expr::Var("this".into(), loc)];
                a.append(&mut args);
                return Stmt::ExprStmt(
                    Expr::Call {
                        name: format!("{field}::{field}"),
                        args: a,
                        loc,
                    },
                    loc,
                );
            }
            return Stmt::Block(Vec::new(), loc); // ctor-less reachable base: no-op
        }
        // A poisoned MI/vbase shape may have dropped base-layout edges before
        // this sweep. Construction sites for the complete class are rejected by
        // codegen via `Record::mi_dropped`; compiling the constructor body itself
        // should not mis-resolve a known base initializer as `this->Base`.
        if self.records[id].mi_dropped
            && self.tags.contains_key(field)
            && !self.records[id].fields.iter().any(|f| f.name == field)
        {
            return Stmt::Block(Vec::new(), loc);
        }
        let member = Expr::Member {
            base: Box::new(Expr::Var("this".into(), loc)),
            field: field.to_string(),
            arrow: true,
            loc,
        };
        // G40: a REFERENCE member's init BINDS the reference (stores the
        // initializer's address into the slot) — it must NOT fall to the
        // `this->field = arg` Assign below, whose lowering auto-derefs the
        // (uninitialized!) slot and, for a class referent with a user
        // `operator=`, rewrites to that call (CLASSLIB THREAD.H `TMutex::Lock
        // : MutexObj(mutex)` referenced the declared-but-never-defined private
        // `TMutex::operator=` — unlinkable by design, miscompiled regardless).
        // A non-1-arg ref init is ill-formed; leave it to the historical path
        // (codegen errors on the non-lvalue, never silently wrong).
        if args.len() == 1
            && self.records[id]
                .fields
                .iter()
                .any(|f| f.name == field && matches!(f.ty, Type::Ref(_)))
        {
            return Stmt::RefBindMember {
                field: field.to_string(),
                rhs: args.remove(0),
                loc,
            };
        }
        if let Some(fld) = self.records[id].fields.iter().find(|f| f.name == field)
            && let Type::Record { id: fid, .. } = &fld.ty
            && let Some(ci) = self.classes.get(fid)
            && ci.has_ctor
        {
            return Stmt::ExprStmt(
                Expr::MethodCall {
                    recv: Box::new(member),
                    name: ci.tag.clone(),
                    args,
                    loc,
                },
                loc,
            );
        }
        let rhs = if args.is_empty() {
            Expr::Int(0)
        } else {
            args.remove(0)
        };
        Stmt::ExprStmt(
            Expr::Assign {
                lhs: Box::new(member),
                rhs: Box::new(rhs),
                loc,
            },
            loc,
        )
    }

    fn reachable_base_by_tag(&self, id: usize, tag: &str) -> Option<usize> {
        let rec = self.records.get(id)?;
        if let Some(b) = rec.base {
            if self.records[b].tag.as_deref() == Some(tag) {
                return Some(b);
            }
            if let Some(found) = self.reachable_base_by_tag(b, tag) {
                return Some(found);
            }
        }
        for eb in &rec.extra_bases {
            if self.records[eb.id].tag.as_deref() == Some(tag) {
                return Some(eb.id);
            }
            if let Some(found) = self.reachable_base_by_tag(eb.id, tag) {
                return Some(found);
            }
        }
        for vb in &rec.vbases {
            if self.records[vb.id].tag.as_deref() == Some(tag) {
                return Some(vb.id);
            }
            if let Some(found) = self.reachable_base_by_tag(vb.id, tag) {
                return Some(found);
            }
        }
        None
    }

    /// Tick 70 (J-11b-members): dtor calls for class-typed members in
    /// REVERSE declaration order. Each emitted statement passes
    /// `&this->m` as `this` to `Tag::~Tag`. Only members whose record
    /// has a dtor are emitted; trivially-destructible class members
    /// (no dtor) emit nothing.
    fn member_dtor_stmts(&self, id: usize) -> Vec<Stmt> {
        let (own_start, own_end) = self.own_field_range(id);
        let mut out = Vec::new();
        let fields = &self.records[id].fields[..own_end];
        for f in fields.iter().skip(own_start).rev() {
            let Type::Record { id: fid, .. } = &f.ty else {
                continue;
            };
            let Some(ci) = self.classes.get(fid) else {
                continue;
            };
            if !ci.has_dtor {
                continue;
            }
            let tag = ci.tag.clone();
            // `Tag::~Tag(&this->m)`. Use an explicit Addr+Member so the
            // codegen sees a Tag* argument matching the dtor's `this`
            // parameter.
            out.push(Stmt::ExprStmt(
                Expr::Call {
                    name: format!("{tag}::~{tag}"),
                    args: vec![Expr::Unary {
                        op: UnOp::Addr,
                        expr: Box::new(Expr::Member {
                            base: Box::new(Expr::Var("this".into(), Loc::default())),
                            field: f.name.clone(),
                            arrow: true,
                            loc: Loc::default(),
                        }),
                    }],
                    loc: Loc::default(),
                },
                Loc::default(),
            ));
        }
        out
    }

    /// When a derived class declares no constructor/destructor of its own but
    /// a base needs one, synthesize a trivial one that chains to the PRIMARY
    /// base. S6 (G1 Stage-1): an extra base needing construction/destruction
    /// also triggers the synthesis — its chained calls are spliced in by the
    /// end-of-parse sweep (`parse_for`), which reaches every ctor/dtor of an
    /// MI class uniformly; the synthesized body here only carries the primary
    /// call (when the primary needs one) + SetVptr, exactly as before.
    fn synthesize_base_chaining(&mut self, id: usize) {
        let (any_extra_ctor, any_extra_dtor) = {
            let ebs = &self.records[id].extra_bases;
            (
                ebs.iter()
                    .any(|eb| self.classes.get(&eb.id).is_some_and(|c| c.has_ctor)),
                ebs.iter()
                    .any(|eb| self.classes.get(&eb.id).is_some_and(|c| c.has_dtor)),
            )
        };
        let base_id = self.classes.get(&id).and_then(|c| c.base);
        if base_id.is_none() && !any_extra_ctor && !any_extra_dtor {
            return;
        }
        let dtag = self.classes[&id].tag.clone();
        let btag = base_id.map(|b| self.classes[&b].tag.clone());
        let base_has_ctor = base_id.is_some_and(|b| self.classes[&b].has_ctor);
        let base_has_dtor = base_id.is_some_and(|b| self.classes[&b].has_dtor);
        let d_has_ctor = self.classes[&id].has_ctor;
        let d_has_dtor = self.classes[&id].has_dtor;
        if (base_has_ctor || any_extra_ctor) && !d_has_ctor {
            let mut body: Vec<Stmt> = Vec::new();
            if base_has_ctor {
                let bt = btag.clone().expect("primary base tag");
                body.push(Stmt::ExprStmt(
                    Expr::Call {
                        name: format!("{bt}::{bt}"),
                        args: vec![Expr::Var("this".into(), Loc::default())],
                        loc: Loc::default(),
                    },
                    Loc::default(),
                ));
            }
            // vptr after base ctor (no-op if non-polymorphic). The parse_for
            // sweep splices extra-base ctor calls BEFORE this SetVptr.
            body.push(Stmt::SetVptr(id, Loc::default()));
            self.cxx_funcs.push(Function {
                name: format!("{dtag}::{dtag}"),
                ret: Type::Void,
                params: vec![("this".into(), self.this_ty(id))],
                body,
                const_method: false,
                virtual_method: false,
                variadic: false,
                c_linkage: false,
                calling_conv: None,
                // S4.2af: an implicitly-defined special member (base-chaining
                // ctor/dtor) is emitted by every TU that uses it — `inline`
                // makes it prune-eligible AND WeakExternal so the linker folds
                // the cross-object duplicates.
                inline: true,
            });
            self.classes.get_mut(&id).unwrap().has_ctor = true;
        }
        if (base_has_dtor || any_extra_dtor) && !d_has_dtor {
            // Body carries only the primary-base dtor call (when needed);
            // the parse_for sweep appends the extra-base dtor calls in
            // reverse declaration order before it.
            let mut body: Vec<Stmt> = Vec::new();
            if base_has_dtor {
                let bt = btag.expect("primary base tag");
                body.push(Stmt::ExprStmt(
                    Expr::Call {
                        name: format!("{bt}::~{bt}"),
                        args: vec![Expr::Var("this".into(), Loc::default())],
                        loc: Loc::default(),
                    },
                    Loc::default(),
                ));
            }
            self.cxx_funcs.push(Function {
                name: format!("{dtag}::~{dtag}"),
                ret: Type::Void,
                params: vec![("this".into(), self.this_ty(id))],
                body,
                const_method: false,
                virtual_method: false,
                variadic: false,
                c_linkage: false,
                calling_conv: None,
                // S4.2af: an implicitly-defined special member (base-chaining
                // ctor/dtor) is emitted by every TU that uses it — `inline`
                // makes it prune-eligible AND WeakExternal so the linker folds
                // the cross-object duplicates.
                inline: true,
            });
            self.classes.get_mut(&id).unwrap().has_dtor = true;
        }
    }

    /// S4.2(e): synthesise the dispatching `WindowProc` for a class that
    /// declares OWL DDVT message handlers (`virtual void WMxxx(RTMessage) =
    /// [WM_FIRST + WM_xxx];`). The synthesised override (signature
    /// `LRESULT(UINT,WPARAM,LPARAM)`, matching `TWindow::WindowProc`) is an
    /// if-chain on the incoming message id that packs a `TMessage` (by value)
    /// and calls the matching handler, falling through to the inherited
    /// `WindowProc` for unhandled messages. It is registered as a virtual
    /// override (its vtable slot replaces the base's), so the runtime's
    /// `self->WindowProc(m,w,l)` static-thunk dispatch lands here. Modelled on
    /// `synthesize_base_chaining` (Function → `cxx_funcs`; `inline` ⇒ prune-
    /// eligible + WeakExternal). No-op for any class without DDVT handlers
    /// (every non-OWL TU) ⇒ the byte-identity baselines are untouched.
    fn synthesize_ddvt_windowproc(&mut self, id: usize) {
        let handlers = self.classes[&id].ddvt_handlers.clone();
        if handlers.is_empty() {
            return;
        }
        // `TMessage` must be in scope (the OWL runtime provides it). If absent,
        // leave the handlers as plain virtuals rather than synthesise a broken
        // dispatcher (never silently wrong).
        let tmsg_id = match self.tags.get("TMessage") {
            Some(&i) => i,
            None => return,
        };
        // The inherited WindowProc symbol to fall through to (e.g.
        // "TWindow::WindowProc"). Bail if there is no such slot to override.
        let base_wndproc = match self.records[id]
            .vtable
            .iter()
            .find(|s| s.key == "WindowProc")
        {
            Some(s) if !s.sym.is_empty() => s.sym.clone(),
            _ => return,
        };
        let tag = self.classes[&id].tag.clone();
        let tmsg_ty = Type::Record {
            id: tmsg_id,
            size: 0,
            align: 1,
        };
        let word_ty = Type::Int {
            bytes: 2,
            signed: false,
        };
        let loc = Loc::default();
        let var = |n: &str| Expr::Var(n.into(), loc);
        let member = |base: Expr, f: &str| Expr::Member {
            base: Box::new(base),
            field: f.into(),
            arrow: false,
            loc,
        };
        let assign = |lhs: Expr, rhs: Expr| {
            Stmt::ExprStmt(
                Expr::Assign {
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    loc,
                },
                loc,
            )
        };

        let mut body: Vec<Stmt> = Vec::new();
        for (key, idx) in &handlers {
            let then = Stmt::Block(
                vec![
                    Stmt::Decl {
                        name: "__m".into(),
                        ty: tmsg_ty.clone(),
                        init: None,
                        loc,
                        is_static: false,
                    },
                    assign(member(var("__m"), "WParam"), var("__wp")),
                    assign(member(var("__m"), "LParam"), var("__lp")),
                    // LP.Lo / LP.Hi = LOWORD / HIWORD of LParam (mouse x,y etc.)
                    assign(
                        member(member(var("__m"), "LP"), "Lo"),
                        Expr::Cast {
                            ty: word_ty.clone(),
                            expr: Box::new(var("__lp")),
                        },
                    ),
                    assign(
                        member(member(var("__m"), "LP"), "Hi"),
                        Expr::Cast {
                            ty: word_ty.clone(),
                            expr: Box::new(Expr::Binary {
                                op: BinOp::Shr,
                                lhs: Box::new(var("__lp")),
                                rhs: Box::new(Expr::Int(16)),
                                loc,
                            }),
                        },
                    ),
                    Stmt::ExprStmt(
                        Expr::MethodCall {
                            recv: Box::new(var("this")),
                            name: key.clone(),
                            args: vec![var("__m")],
                            loc,
                        },
                        loc,
                    ),
                    Stmt::Return(Some(Expr::Int(0)), loc),
                ],
                loc,
            );
            body.push(Stmt::If {
                cond: Expr::Binary {
                    op: BinOp::Eq,
                    lhs: Box::new(var("__msg")),
                    rhs: Box::new(Expr::Int(*idx)),
                    loc,
                },
                then: Box::new(then),
                els: None,
                loc,
            });
        }
        // default: forward unhandled messages to the inherited WindowProc.
        body.push(Stmt::Return(
            Some(Expr::Call {
                name: base_wndproc,
                args: vec![var("this"), var("__msg"), var("__wp"), var("__lp")],
                loc,
            }),
            loc,
        ));

        self.cxx_funcs.push(Function {
            name: format!("{tag}::WindowProc"),
            ret: Type::Int {
                bytes: 8,
                signed: true,
            }, // LRESULT
            params: vec![
                ("this".into(), self.this_ty(id)),
                (
                    "__msg".into(),
                    Type::Int {
                        bytes: 4,
                        signed: false,
                    },
                ), // UINT
                (
                    "__wp".into(),
                    Type::Int {
                        bytes: 8,
                        signed: false,
                    },
                ), // WPARAM
                (
                    "__lp".into(),
                    Type::Int {
                        bytes: 8,
                        signed: true,
                    },
                ), // LPARAM
            ],
            body,
            const_method: false,
            virtual_method: true,
            variadic: false,
            c_linkage: false,
            calling_conv: None,
            inline: true,
        });
        // Override the WindowProc vtable slot so the virtual dispatch from the
        // runtime's static thunk (`self->WindowProc(...)`) lands on the
        // synthesised override.
        if let Some(slot) = self.records[id]
            .vtable
            .iter_mut()
            .find(|s| s.key == "WindowProc")
        {
            slot.sym = format!("{tag}::WindowProc");
        }
        self.classes
            .get_mut(&id)
            .unwrap()
            .methods
            .insert(format!("{tag}::WindowProc"));
    }

    /// `enum` [tag] [ `{` name [= const] , ... `}` ]. Constants are recorded;
    /// the type itself is just `int`.
    fn enum_specifier(&mut self) -> PResult<Type> {
        self.advance(); // enum
        let tag = if let TokenKind::Ident(s) = self.kind() {
            let s = s.clone();
            self.advance();
            Some(s)
        } else {
            None
        };
        // An enum's underlying type is `int` in mdbcc. Register the tag as a
        // type name so it can be used WITHOUT the `enum` keyword (the C++ form
        // `StripType s;`), as CSTRING.H does: `enum StripType { ... };` then
        // `strip(StripType s = Trailing)`. `or_insert` so a real typedef of the
        // same name (rare) is not clobbered. The `enum`-keyword form is handled
        // by this function directly and is unaffected. Additive: C code uses the
        // `enum E` keyword form, so the bare-name lookup never fires for it.
        if let Some(t) = tag {
            self.typedefs.entry(t).or_insert_with(Type::int);
        }
        if self.eat_punct(Punct::LBrace) {
            let mut next = 0i64;
            while !self.eat_punct(Punct::RBrace) {
                let name = match self.kind() {
                    TokenKind::Ident(s) => s.clone(),
                    _ => return Err(self.error_here("expected an enumerator name")),
                };
                self.advance();
                if self.eat_punct(Punct::Assign) {
                    next = self.const_expr()?;
                }
                self.enum_consts.insert(name, next);
                next += 1;
                if !self.eat_punct(Punct::Comma) {
                    self.expect_punct(Punct::RBrace, "}")?;
                    break;
                }
            }
        }
        Ok(Type::int())
    }

    /// Parse an overloaded-operator name (cursor on the `operator` keyword),
    /// returning its canonical spelling, e.g. `"operator+"`, `"operator[]"`.
    fn operator_name(&mut self) -> PResult<String> {
        self.advance(); // `operator`
        self.conv_ret = None; // cleared; set only by the conversion arm below
        let sp = match self.kind() {
            TokenKind::Punct(Punct::Plus) => "+",
            TokenKind::Punct(Punct::Minus) => "-",
            TokenKind::Punct(Punct::Star) => "*",
            TokenKind::Punct(Punct::Slash) => "/",
            TokenKind::Punct(Punct::Percent) => "%",
            TokenKind::Punct(Punct::EqEq) => "==",
            TokenKind::Punct(Punct::Ne) => "!=",
            TokenKind::Punct(Punct::Lt) => "<",
            TokenKind::Punct(Punct::Gt) => ">",
            TokenKind::Punct(Punct::Le) => "<=",
            TokenKind::Punct(Punct::Ge) => ">=",
            TokenKind::Punct(Punct::Assign) => "=",
            // Compound-assignment, bitwise, shift, logical, inc/dec and member
            // operators. Recognised at parse time (the BIDS/RTL classes declare
            // `operator +=`, `operator <<`, `operator !`, etc. throughout);
            // lowering of the not-yet-implemented ones stays a separate concern
            // (a declaration in a header never needs codegen).
            TokenKind::Punct(Punct::PlusEq) => "+=",
            TokenKind::Punct(Punct::MinusEq) => "-=",
            TokenKind::Punct(Punct::StarEq) => "*=",
            TokenKind::Punct(Punct::SlashEq) => "/=",
            TokenKind::Punct(Punct::PercentEq) => "%=",
            TokenKind::Punct(Punct::AmpEq) => "&=",
            TokenKind::Punct(Punct::PipeEq) => "|=",
            TokenKind::Punct(Punct::CaretEq) => "^=",
            TokenKind::Punct(Punct::ShlEq) => "<<=",
            TokenKind::Punct(Punct::ShrEq) => ">>=",
            TokenKind::Punct(Punct::Shl) => "<<",
            TokenKind::Punct(Punct::Shr) => ">>",
            TokenKind::Punct(Punct::Amp) => "&",
            TokenKind::Punct(Punct::Pipe) => "|",
            TokenKind::Punct(Punct::Caret) => "^",
            TokenKind::Punct(Punct::Tilde) => "~",
            TokenKind::Punct(Punct::Bang) => "!",
            TokenKind::Punct(Punct::AndAnd) => "&&",
            TokenKind::Punct(Punct::OrOr) => "||",
            TokenKind::Punct(Punct::Inc) => "++",
            TokenKind::Punct(Punct::Dec) => "--",
            TokenKind::Punct(Punct::Arrow) => "->",
            TokenKind::Punct(Punct::Comma) => ",",
            TokenKind::Punct(Punct::LBracket) => {
                self.advance();
                if !self.eat_punct(Punct::RBracket) {
                    return Err(self.error_here("expected ']' after 'operator['"));
                }
                return Ok("operator[]".into());
            }
            TokenKind::Punct(Punct::LParen) => {
                self.advance();
                if !self.eat_punct(Punct::RParen) {
                    return Err(self.error_here("expected ')' after 'operator('"));
                }
                return Ok("operator()".into());
            }
            // `operator new` / `operator new[]` / `operator delete` /
            // `operator delete[]` — the allocation operators (keyword names).
            // CLASSLIB/ALLOCTR.H declares all four on TStandardAllocator.
            TokenKind::Keyword(kw @ (Keyword::New | Keyword::Delete)) => {
                let base = if matches!(kw, Keyword::New) {
                    "new"
                } else {
                    "delete"
                };
                self.advance(); // new | delete
                if self.is_punct(Punct::LBracket)
                    && self.kind_at(1) == Some(&TokenKind::Punct(Punct::RBracket))
                {
                    self.advance(); // [
                    self.advance(); // ]
                    return Ok(format!("operator {base}[]"));
                }
                return Ok(format!("operator {base}"));
            }
            // User-defined CONVERSION operator: `operator <type>` — the token
            // after `operator` begins a type, not a symbolic operator. Handles
            // `operator int`, `operator void *`, `operator const char *`
            // (CLASSLIB/RTL idioms; IOSTREAM.H's `ios::operator void _FAR *`).
            // The target type is stashed in `conv_ret` for `declarator` to use
            // as the return type, and encoded into the symbol so several
            // conversion operators on one class stay distinct.
            _ if self.kind_starts_type(self.kind()) => {
                let ty = self.type_name()?;
                let sym = format!("operator@{}", type_arg_code(&ty));
                self.conv_ret = Some(ty);
                return Ok(sym);
            }
            _ => {
                return Err(self.error_here("unsupported or missing overloaded operator"));
            }
        };
        self.advance();
        Ok(format!("operator{sp}"))
    }

    /// Parse a declarator given the base type. Returns the full type and the
    /// declared name (`None` for an abstract declarator).
    /// Consume any run of calling-convention keywords at the cursor, recording
    /// the last one into `self.last_call_conv` (the convention is a declarator
    /// qualifier in the Borland/MSVC `T * __cdecl name(...)` form). No-op when
    /// the cursor is not on a convention keyword.
    /// Lookahead for a grouped (function-pointer) declarator: the cursor is on
    /// `(`, and after skipping a run of declarator qualifiers
    /// (`__cdecl`/`__import`/`__export`/`near`/…) the next token is `*`. Does
    /// not consume. `( <type> )` (a parenthesised abstract declarator / a
    /// redundant-parens declarator) is NOT matched — it has no `*`.
    fn lparen_then_star(&self) -> bool {
        debug_assert!(self.is_punct(Punct::LParen));
        let mut n = 1;
        while is_ptr_decl_qualifier_kw(self.kind_at(n)) {
            n += 1;
        }
        matches!(self.kind_at(n), Some(TokenKind::Punct(Punct::Star)))
    }

    /// S4.2f: look-ahead for a parenthesised POINTER-TO-MEMBER declarator
    /// `( Type:: [Type::]* * NAME )( params )` — `void (T::*PMF)()`
    /// (OWL/EVENTHAN.H's response-table typedef, surfaced when the enclosing class
    /// template is instantiated). mdbcc does not model pointer-to-member; it is
    /// parsed like a function pointer with the `Type::` qualifier consumed and
    /// ignored. The cursor is on `(`; does not consume.
    fn lparen_then_member_star(&self) -> bool {
        debug_assert!(self.is_punct(Punct::LParen));
        let mut n = 1;
        let mut saw_qualifier = false;
        while matches!(self.kind_at(n), Some(TokenKind::Ident(_)))
            && self.kind_at(n + 1) == Some(&TokenKind::Punct(Punct::ColonColon))
        {
            n += 2;
            saw_qualifier = true;
        }
        saw_qualifier && matches!(self.kind_at(n), Some(TokenKind::Punct(Punct::Star)))
    }

    /// Lookahead for a parenthesised function-*type* declarator with no pointer
    /// star: `( [qual-run] NAME ) (`. The cursor is on `(`; after an optional
    /// run of declarator qualifiers comes an identifier, then `)`, then `(`
    /// (the parameter list — what tells this apart from a redundant-parens
    /// simple declarator `( NAME ) ;`). Does not consume.
    fn lparen_then_fn_type_name(&self) -> bool {
        debug_assert!(self.is_punct(Punct::LParen));
        let mut n = 1;
        while is_ptr_decl_qualifier_kw(self.kind_at(n)) {
            n += 1;
        }
        matches!(self.kind_at(n), Some(TokenKind::Ident(_)))
            && matches!(self.kind_at(n + 1), Some(TokenKind::Punct(Punct::RParen)))
            && matches!(self.kind_at(n + 2), Some(TokenKind::Punct(Punct::LParen)))
    }

    fn skip_call_conv(&mut self) {
        // A run of declarator qualifiers: calling conventions (recorded) plus
        // the accept-and-ignore Borland linkage/memory-model qualifiers
        // (`__import`/`__export`/`near`/`far`/`huge`). The Win32 SDK's `WINAPI`
        // (= `__stdcall __import`) puts two of these before a function-pointer's
        // `*`, so they may interleave; consume the whole run.
        while is_ptr_decl_qualifier_kw(Some(self.kind())) {
            if let TokenKind::Keyword(
                kw @ (Keyword::Cdecl | Keyword::Stdcall | Keyword::Fastcall | Keyword::Pascal),
            ) = self.kind()
            {
                self.last_call_conv = Some(match kw {
                    Keyword::Cdecl => CallConv::Cdecl,
                    Keyword::Stdcall => CallConv::Stdcall,
                    Keyword::Fastcall => CallConv::Fastcall,
                    Keyword::Pascal => CallConv::Pascal,
                    _ => unreachable!(),
                });
            }
            self.advance();
        }
    }

    /// S5: a PARENTHESIZED conv-led function declarator at file scope —
    /// `int (_RTLENTRY _EXPFUNC isalnum)(int c) { … }` (RTL LOCALE/IS.C and the
    /// whole ctype `is*` family: the parens suppress the same-named ctype.h
    /// function-like macro, since `isalnum` followed by `)` is no invocation).
    /// `declarator`'s grouped path parses this via `param_type_list`, which
    /// DISCARDS parameter names — unusable for a definition body. When the
    /// unambiguous shape `[*-run] ( conv-kw+ Ident ) (` is ahead (a
    /// paren-EXPRESSION can never start with a conv keyword), consume up to —
    /// but not including — the parameter `(` and return the (pointer-wrapped)
    /// return type + name: exactly the state `external_declaration`'s standard
    /// function path expects, so prototypes (`;`) and definitions (`{`) both
    /// flow through the unchanged machinery with named parameters.
    /// Returns `None` (cursor untouched) when the shape is not present.
    fn paren_conv_fn_declarator(&mut self, base: &Type) -> PResult<Option<(Type, Option<String>)>> {
        let mut j = self.pos;
        let mut nptr = 0usize;
        while self.toks.get(j).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::Star)) {
            j += 1;
            nptr += 1;
        }
        if self.toks.get(j).map(|t| &t.kind) != Some(&TokenKind::Punct(Punct::LParen)) {
            return Ok(None);
        }
        let mut k = j + 1;
        let mut saw_conv = false;
        while is_ptr_decl_qualifier_kw(self.toks.get(k).map(|t| &t.kind)) {
            saw_conv = true;
            k += 1;
        }
        if !(saw_conv
            && matches!(self.toks.get(k).map(|t| &t.kind), Some(TokenKind::Ident(_)))
            && self.toks.get(k + 1).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::RParen))
            && self.toks.get(k + 2).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::LParen)))
        {
            return Ok(None);
        }
        // Commit: consume the `*`-run, `(`, the conv run, the name, and `)`.
        let mut ty = base.clone();
        for _ in 0..nptr {
            self.advance(); // `*`
            ty = Type::Ptr(Box::new(ty));
        }
        self.advance(); // the grouping `(`
        self.skip_call_conv(); // records the convention (`last_call_conv`)
        let name = if let TokenKind::Ident(s) = self.kind() {
            let s = s.clone();
            self.advance();
            Some(s)
        } else {
            None // unreachable: the lookahead required an Ident here
        };
        self.expect_punct(Punct::RParen, ")")?;
        Ok(Some((ty, name))) // cursor is ON the parameter list `(`
    }

    /// Skip the qualifier run that can sit between `class`/`struct`/`union` and
    /// the tag name (after macro expansion): `__declspec(...)`, calling
    /// conventions, and the Borland memory-model / linkage keywords
    /// (`near`/`far`/`huge`/`__export`/`__import`). OWL's `_EXPORT` macro
    /// expands to `_CLASSTYPE` → `huge` under the 16-bit headers' memory model,
    /// so `class _EXPORT TApplication` reaches the parser as
    /// `class huge TApplication`; bcc32 ignores these obsolete keywords for the
    /// flat target, and so do we. A no-op when the tag (or `{`) follows
    /// directly, so a plain `struct Foo` / `class Bar` is unaffected.
    fn skip_class_head_qualifiers(&mut self) {
        if self.is_kw(Keyword::Declspec) {
            self.advance();
            // __declspec(...) — skip the balanced parens.
            if self.eat_punct(Punct::LParen) {
                let mut d = 1;
                while d > 0 && !self.at_eof() {
                    if self.is_punct(Punct::LParen) {
                        d += 1;
                    } else if self.is_punct(Punct::RParen) {
                        d -= 1;
                    }
                    self.advance();
                }
            }
        }
        self.skip_call_conv();
    }

    fn declarator(&mut self, base: Type) -> PResult<(Type, Option<String>)> {
        // S3: leading `const`/`volatile` that qualify the base type in the
        // "east const" spelling — `T const *p` / `typedef T const *PCT`. When
        // the base type is a typedef-name or tag, `decl_specifiers` returns as
        // soon as it consumes that name (it cannot keep scanning specifiers
        // without re-classifying a following declarator), so a trailing cv-qual
        // reaches the declarator here. The Win32 SDK uses this for every
        // `typedef STRUCT const *LPCSTRUCT;` (e.g. `MENUITEMINFOA const *`).
        // Accept-and-ignore (mdbcc models no const semantics). Additive: no x64
        // fixture writes a cv-qualifier before the declarator's stars.
        while matches!(
            self.kind(),
            TokenKind::Keyword(Keyword::Const | Keyword::Volatile)
        ) {
            self.advance();
        }
        // A memory-model / calling-convention qualifier run may sit between a
        // (tag/typedef) base type and the `*` — `string __far * str` in the RTL
        // classes (`_FAR` == `__far`). `decl_specifiers` returns as soon as it
        // consumes a tag name, so the `__far` reaches the declarator here. The
        // `*`-grouped and `*`-prefixed forms already call `skip_call_conv` after
        // the `(`/`*`; this covers the leading (pre-star) position. No-op when no
        // such qualifier is present (byte-identical for the corpus).
        self.skip_call_conv();
        let mut nptr = 0;
        while self.eat_punct(Punct::Star) {
            // pointer qualifiers
            while matches!(
                self.kind(),
                TokenKind::Keyword(Keyword::Const | Keyword::Volatile)
            ) {
                self.advance();
            }
            nptr += 1;
        }
        // S3: a calling-convention keyword may sit between the pointer stars
        // and the declared name — `void * __cdecl memcpy(...)` is how the real
        // Borland RTL headers spell every pointer-returning prototype (the
        // `_RTLENTRY`/`_RTLENTRYF` macros expand to `__cdecl` right after the
        // `*`). The convention is recorded so a *definition* in this form still
        // carries it (`external_declaration` re-reads `last_call_conv` after
        // the declarator). Additive: no existing fixture writes `T* <conv>`.
        self.skip_call_conv();
        // C++ reference: a single `&` after any pointer stars.
        let is_ref = self.eat_punct(Punct::Amp);
        // A calling convention can also sit AFTER the reference `&`, before the
        // name — the RTL classes write `const string & _RTLENTRY why() const`
        // and `xmsg & _RTLENTRY operator=(...)` (`_RTLENTRY` == `__cdecl`). The
        // run before `&` (above) doesn't cover this position. No-op otherwise.
        if is_ref {
            self.skip_call_conv();
        }
        // J-14 v1 (tick 62): grouped member-function-pointer declarator:
        //   `( Class :: * [name] ) ( param-type-list )`
        // e.g. `int (Foo::*p)(int)`. Must be checked BEFORE the regular
        // fn-ptr `(*` path, since after the `(` the next token is an
        // identifier (the class tag), not `*`.
        if self.is_punct(Punct::LParen)
            && let Some(TokenKind::Ident(tag)) = self.kind_at(1)
            && self.kind_at(2) == Some(&TokenKind::Punct(Punct::ColonColon))
            && self.kind_at(3) == Some(&TokenKind::Punct(Punct::Star))
            && let Some(&class_id) = self.tags.get(tag)
        {
            self.advance(); // '('
            self.advance(); // Class tag
            self.advance(); // '::'
            self.advance(); // '*'
            let gname = if let TokenKind::Ident(s) = self.kind() {
                let s = s.clone();
                self.advance();
                Some(s)
            } else {
                None
            };
            self.expect_punct(Punct::RParen, ")")?;
            let params = self.param_type_list()?;
            let mut ret = base;
            for _ in 0..nptr {
                ret = Type::Ptr(Box::new(ret));
            }
            let mut ty = Type::MemFn {
                class_id,
                ret: Box::new(ret),
                params,
            };
            if is_ref {
                ty = Type::Ref(Box::new(ty));
            }
            return Ok((ty, gname));
        }
        // S3: a parenthesised function-*type* declarator with NO pointer star —
        // `( [conv-run] NAME ) ( params )`. The Win32 SDK / MAPI declare callback
        // *types* this way: `typedef void (_stdcall DRVCALLBACK)(HDRVR,...)` and
        // `typedef HRESULT (HPPROVIDERINIT)(LPMAPISESSION,...)`. The trailing `(`
        // (the parameter list) disambiguates this from a redundant-parens simple
        // declarator (`int (x);`). Builds a `Type::Func` (not a pointer).
        //
        // Two cases, both additive:
        //  * a leading convention (`(_stdcall NAME)(...)`) is unambiguous — it
        //    can never be a plain prototype — so accept it anywhere;
        //  * a *bare* `(NAME)(...)` is only treated as a function-TYPE inside a
        //    `typedef` (where `external_declaration`'s prototype/definition
        //    detection does not apply). Outside a typedef, `int (foo)(int)`
        //    keeps its historical flat-declarator handling untouched.
        if self.is_punct(Punct::LParen)
            && self.lparen_then_fn_type_name()
            && (is_ptr_decl_qualifier_kw(self.kind_at(1)) || self.is_typedef)
        {
            self.advance(); // '('
            self.skip_call_conv(); // optional conv run (records the convention)
            let gname = if let TokenKind::Ident(s) = self.kind() {
                let s = s.clone();
                self.advance();
                Some(s)
            } else {
                None
            };
            self.expect_punct(Punct::RParen, ")")?;
            let params = self.param_type_list()?;
            let mut ret = base;
            for _ in 0..nptr {
                ret = Type::Ptr(Box::new(ret));
            }
            let mut ty = Type::Func {
                ret: Box::new(ret),
                params,
            };
            if is_ref {
                ty = Type::Ref(Box::new(ty));
            }
            return Ok((ty, gname));
        }
        // Grouped function-pointer declarator:
        //   `( [quals] * [* …] [name] [ [N] … ] ) ( param-type-list )`
        // e.g. `int (*fp)(int)`, `int (*ops[3])(int,int)`, from the RTL headers
        // `void (__cdecl *atexit_t)(void)`, and from the Win32 SDK
        // `int (__stdcall __import *FARPROC)()` — a *run* of declarator
        // qualifiers (convention + `__import`/`__export`/memory-model) may sit
        // between the `(` and the `*`. Other forms keep the flat path below.
        if self.is_punct(Punct::LParen)
            && (self.lparen_then_star() || self.lparen_then_member_star())
        {
            self.advance(); // '('
            self.skip_call_conv(); // run of conv / __import / __export / … before `*`
            // S4.2f: a POINTER-TO-MEMBER declarator `(T::*name)(...)` — consume and
            // IGNORE the `Type::` qualifier(s). mdbcc models it as a plain function
            // pointer (adequate for single-inheritance PMFs and for parse-
            // acceptance; full pointer-to-member layout is a later item).
            while matches!(self.kind(), TokenKind::Ident(_))
                && self.kind_at(1) == Some(&TokenKind::Punct(Punct::ColonColon))
            {
                self.advance(); // Type
                self.advance(); // ::
            }
            let mut inner_ptr = 0;
            while self.eat_punct(Punct::Star) {
                while matches!(
                    self.kind(),
                    TokenKind::Keyword(Keyword::Const | Keyword::Volatile)
                ) {
                    self.advance();
                }
                inner_ptr += 1;
            }
            // A convention/qualifier run may ALSO sit between the `*` and the
            // pointer's name — the RTL headers spell `void (_USERENTRY *
            // _RTLENTRY name)(...)` (both `_USERENTRY` and `_RTLENTRY` fold to
            // `__cdecl`). Accept-and-record. Additive.
            self.skip_call_conv();
            let gname = if let TokenKind::Ident(s) = self.kind() {
                let mut name = s.clone();
                self.advance();
                // A QUALIFIED name `Class::member` — the OUT-OF-LINE definition of
                // a static member function pointer: `bool (*C::fp)(int) = …;`
                // (OWL DOCTPL.CPP `bool (*TDocTemplate::SelectSave_)(...) = …`).
                // Carry the qualifier so codegen emits it under the static
                // member's symbol. Byte-safe: a simple `(*fp)` has no `::`.
                while self.is_punct(Punct::ColonColon) {
                    self.advance(); // ::
                    if let TokenKind::Ident(m) = self.kind() {
                        let m = m.clone();
                        name.push_str("::");
                        name.push_str(&m);
                        self.advance();
                    } else {
                        break;
                    }
                }
                Some(name)
            } else {
                None
            };
            let mut dims = Vec::new();
            while self.eat_punct(Punct::LBracket) {
                if self.is_punct(Punct::RBracket) {
                    dims.push(0usize);
                } else {
                    let n = self.const_expr()?;
                    if n < 0 {
                        return Err(self.error_here("array size must be non-negative"));
                    }
                    dims.push(n as usize);
                }
                self.expect_punct(Punct::RBracket, "]")?;
            }
            // S5 #23: a function-returning-function-pointer declarator —
            // `RET (* NAME ( p1 )) ( p2 )`. NAME has its OWN parameter list
            // INSIDE the grouping parens, so NAME is a function taking `p1`
            // whose return type is the (pointed-to) function type built below.
            // The canonical case is `signal()`; Borland's dos.h spells
            // `void interrupt(far * _Cdecl _dos_getvect(unsigned))(...)`
            // (reached via OWL's WINDOBJ.H → OBJSTRM.H → dos.h). A `(` here is
            // unambiguous — a plain function pointer's NAME is followed by `)`,
            // so this is additive (no existing `(*fp)(…)` form is affected).
            let name_params = if self.is_punct(Punct::LParen) {
                Some(self.param_type_list()?)
            } else {
                None
            };
            self.expect_punct(Punct::RParen, ")")?;
            let params = self.param_type_list()?;
            let mut ret = base;
            for _ in 0..nptr {
                ret = Type::Ptr(Box::new(ret));
            }
            let mut ty = Type::Func {
                ret: Box::new(ret),
                params,
            };
            for _ in 0..inner_ptr {
                ty = Type::Ptr(Box::new(ty));
            }
            for n in dims.into_iter().rev() {
                ty = Type::Array(Box::new(ty), n);
            }
            // #23: wrap as the outer function type when NAME carried a param
            // list — NAME is `fn(p1) -> (the pointer-to-function above)`.
            if let Some(p1) = name_params {
                ty = Type::Func {
                    ret: Box::new(ty),
                    params: p1,
                };
            }
            if is_ref {
                ty = Type::Ref(Box::new(ty));
            }
            return Ok((ty, gname));
        }
        let mut name = if let TokenKind::Ident(s) = self.kind() {
            let s = s.clone();
            self.advance();
            Some(s)
        } else if self.is_kw(Keyword::Operator) {
            Some(self.operator_name()?)
        } else {
            None
        };
        // S4 (#49): a TEMPLATE-ID qualifier in an out-of-line member declarator —
        // `Tag<args>::member` (CLASSLIB's `void TMVectorImp<T,Alloc>::ForEach(..)`).
        // `decl_specifiers` parsed the return type and stopped at the class-
        // template tag, which is followed by `<` (not `::`), so the qualified-name
        // loop below would not fire. Resolve the template-id to its already-
        // instantiated record tag (the enclosing instantiation pre-registered it
        // in `class_inst_cache`), so the member attaches to the concrete instance
        // and `member_def_tail` emits it. Only fires for a registered class-
        // template name followed by `<` — a shape that reaches the declarator ONLY
        // for out-of-line template member defs (a `Tag<args> x;` variable has its
        // type consumed by `decl_specifiers`), so it is additive and never appears
        // in the 88-baseline corpus.
        if let Some(n0) = name.clone()
            && self.is_punct(Punct::Lt)
            && self.class_template_idx.contains_key(&n0)
        {
            let tag_pos = self.pos - 1; // the Tag token (consumed just above)
            self.advance(); // `<`
            let mut targs: Vec<Type> = Vec::new();
            if !self.is_punct(Punct::Gt) {
                loop {
                    targs.push(self.type_name()?);
                    if self.eat_punct(Punct::Comma) {
                        continue;
                    }
                    break;
                }
            }
            self.expect_punct(Punct::Gt, ">")?;
            let key = format!(
                "{n0}<{}>",
                targs
                    .iter()
                    .map(type_arg_code)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            // Resolve to the concrete instance's tag if it is already built
            // (the normal replay case).
            if let Some(&id) = self.class_inst_cache.get(&key)
                && let Some(t) = self.records.get(id).and_then(|r| r.tag.clone())
            {
                name = Some(t);
            } else {
                // S6 (G9): NOT yet instantiated — Borland's `template<>`-less
                // specialization member definitions (`inline void
                // TAutoEnumerator<short>::Value(short&) {…}`, OCF/AUTODEFS.H)
                // reach this declarator BEFORE any use has built the
                // instance. REWIND to the tag and instantiate on demand (the
                // exact machinery the base-clause path uses — it re-parses
                // the angle args and leaves the cursor after `>`, where the
                // `::member` walk below picks up). Previously this fell
                // through to "no class named '<tag>'".
                self.pos = tag_pos;
                let ty = self.instantiate_class_template(&n0)?;
                if let Type::Record { id, .. } = ty
                    && let Some(t) = self.records.get(id).and_then(|r| r.tag.clone())
                {
                    name = Some(t);
                }
            }
        }
        // Leading-`::` recovery (S4.2b: nested-class out-of-line members). A
        // ctor/dtor has no return type, so `string::outofrange::outofrange()`
        // makes decl_specifiers eat `string` as the "base type", leaving the
        // declarator on `::outofrange::…`. Recover the base record's tag as the
        // leading qualifier so the chain below reconstructs the full name.
        if name.is_none()
            && self.is_punct(Punct::ColonColon)
            && let Type::Record { id, .. } = &base
            && let Some(t) = self.records.get(*id).and_then(|r| r.tag.clone())
        {
            name = Some(t);
        }
        // Qualified declarator, possibly MULTI-`::` for nested classes:
        // `Tag::member` / `Tag::~Tag` / `Tag::operator@` / `A::B::member`
        // (out-of-line definition).
        while let Some(n0) = name.clone()
            && self.eat_punct(Punct::ColonColon)
        {
            let member = if self.eat_punct(Punct::Tilde) {
                let m = match self.kind() {
                    TokenKind::Ident(s) => s.clone(),
                    _ => {
                        return Err(self.error_here("expected a destructor name after '::'"));
                    }
                };
                self.advance();
                format!("~{m}")
            } else if self.is_kw(Keyword::Operator) {
                self.operator_name()?
            } else {
                let m = match self.kind() {
                    TokenKind::Ident(s) => s.clone(),
                    _ => {
                        return Err(self.error_here("expected a member name after '::'"));
                    }
                };
                self.advance();
                m
            };
            name = Some(format!("{n0}::{member}"));
        }
        // Array suffixes. An empty `[]` is size 0 (a placeholder that
        // `maybe_initializer` resolves from a string/initializer).
        let mut dims = Vec::new();
        while self.eat_punct(Punct::LBracket) {
            if self.is_punct(Punct::RBracket) {
                dims.push(0usize);
            } else {
                let n = self.const_expr()?;
                if n < 0 {
                    return Err(self.error_here("array size must be non-negative"));
                }
                dims.push(n as usize);
            }
            self.expect_punct(Punct::RBracket, "]")?;
        }

        let mut ty = base;
        for _ in 0..nptr {
            ty = Type::Ptr(Box::new(ty));
        }
        for n in dims.into_iter().rev() {
            ty = Type::Array(Box::new(ty), n);
        }
        if is_ref {
            ty = Type::Ref(Box::new(ty));
        }
        // S4.2c: a conversion operator's real return type is the conversion
        // target (parsed into `conv_ret`), not the implicit-int that
        // `decl_specifiers` produced for `inline ios::operator void*()`. Apply it
        // only when THIS declarator named a conversion operator, so a stale
        // `conv_ret` from an `obj.operator T()` expression cannot leak in.
        if name.as_deref().is_some_and(|n| n.contains("operator@"))
            && let Some(ct) = self.conv_ret.take()
        {
            ty = ct;
        }
        Ok((ty, name))
    }

    /// `( )` / `( void )` / `( type [, type]… )` — the parameter *types* of a
    /// function (-pointer) declarator. Parameter names, if written, are
    /// parsed and discarded; array/function params decay to pointers.
    fn param_type_list(&mut self) -> PResult<Vec<Type>> {
        self.expect_punct(Punct::LParen, "(")?;
        let mut params = Vec::new();
        if self.eat_punct(Punct::RParen) {
            return Ok(params);
        }
        if self.is_kw(Keyword::Void)
            && matches!(self.kind_at(1), Some(TokenKind::Punct(Punct::RParen)))
        {
            self.advance(); // void
            self.advance(); // )
            return Ok(params);
        }
        loop {
            // A trailing (or sole) `...` makes this function TYPE variadic.
            // Unlike a free-function DEFINITION (which needs a named param to
            // anchor `va_start`, so `param_list` rejects a bare `...`), a
            // function-TYPE / function-POINTER carries no body, so `(...)` and
            // `(T, ...)` are both well-formed. `Type::Func` does not model the
            // variadic bit (it is irrelevant to layout/`sizeof` of the pointer
            // and to the parse-acceptance ratchet), so we consume `...` and stop.
            // Borland's RTL spells interrupt-vector callbacks this way —
            // `void cdecl _chain_intr(void interrupt (far *)(...))` — and it
            // gated all 34 OWL apps via `<windows.h>`.
            if self.is_punct(Punct::Ellipsis) {
                self.advance();
                break;
            }
            let base = self.decl_specifiers()?;
            let (ty, _) = self.declarator(base)?;
            params.push(ty.decay());
            // S6: a DEFAULT ARGUMENT in a function-TYPE / function-pointer
            // parameter list — `typedef IUnknown* (*TComponentFactory)(...,
            // uint32 id = 0);` (OCF/OCREG.H, included by all 12 OWL OCF/OLE
            // files). The default is irrelevant to the pointer's TYPE, so
            // parse-and-discard it. Without this the `= 0` errored "expected
            // ')'". `param_list` (function DEFINITIONS) handles defaults
            // separately; this is the type-only list.
            if self.eat_punct(Punct::Assign) {
                let _ = self.assignment()?;
            }
            if !self.eat_punct(Punct::Comma) {
                break;
            }
        }
        self.expect_punct(Punct::RParen, ")")?;
        Ok(params)
    }

    fn type_name(&mut self) -> PResult<Type> {
        let base = self.decl_specifiers()?;
        let (ty, _) = self.declarator(base)?;
        Ok(ty)
    }

    /// Register `typedef`-storage declarators as type aliases.
    fn register_typedefs(&mut self, base: Type) -> PResult<()> {
        loop {
            let (mut ty, name) = self.declarator(base.clone())?;
            let name = name.ok_or_else(|| self.error_here("expected a typedef name"))?;
            // S3: a function-type typedef — `typedef RET NAME ( params );`
            // (NOT a function *pointer*; the grouped `(*NAME)(...)` form is
            // handled in `declarator`). The Win32 SDK declares callback
            // *types* this way (`typedef DWORD QUERYHANDLER(LPVOID,...);`).
            // The flat `declarator` stops at the name (its trailing-`(`
            // function form is the prototype path's job, not the declarator's),
            // so consume the parameter list here and alias NAME to the function
            // type. Additive: no x64 fixture defines a function-type typedef.
            if self.is_punct(Punct::LParen) {
                let params = self.param_type_list()?;
                ty = Type::Func {
                    ret: Box::new(ty),
                    params,
                };
            }
            // W6 (G49): `typedef struct { … } NAME;` — a TAGLESS record
            // adopts its first unadorned typedef name as the class name for
            // LINKAGE (C++ [dcl.typedef]/9). bcc32 mangles `FILE*` as
            // `p4FILE` (oracle: `@takefoo$qp3FOO` for a tagless typedef'd
            // struct); without adoption mdbcc fell back to the TU-LOCAL
            // synthetic `R<id>` — so the RTL's `_allocbuf(FILE*,…)` definer
            // (`@_allocbuf$qp2R0…`, ALLOCBUF.C) and its STREAMS.C reference
            // (`@_allocbuf$qp4R165…`) never matched. Linkage-only: the name
            // is NOT registered in `self.tags` (an elaborated `struct NAME`
            // afterwards stays invalid). First adoption wins; derived
            // declarators (`*PFILE`) and already-tagged records unchanged.
            if let Type::Record { id, .. } = &ty
                && let Some(rec) = self.records.get_mut(*id)
                && rec.tag.is_none()
            {
                rec.tag = Some(name.clone());
            }
            self.typedefs.insert(name, ty);
            if !self.eat_punct(Punct::Comma) {
                break;
            }
        }
        Ok(())
    }

    // ---- external declarations -------------------------------------------

    /// S4.1: parse a template declaration whose `template` keyword has already
    /// been eaten. Parses `< class T, … >`, then the templated declaration
    /// with each type parameter registered as a type name (so `T` parses as a
    /// type via [`Type::TemplateParam`]). S4.1 captures **function templates**
    /// (one templated function definition) into [`Self::fn_templates`]; other
    /// templated forms (class templates, etc.) are a clean deferral error
    /// until S4.2+. The parameter-name registrations are scoped — any shadowed
    /// typedef is restored on exit, success or failure.
    fn template_declaration(&mut self, _items: &mut Vec<Item>) -> PResult<()> {
        self.expect_punct(Punct::Lt, "<")?;
        let mut params: Vec<String> = Vec::new();
        // Parallel to `params`: whether each parameter is a TYPE parameter
        // (`class`/`typename`) vs a NON-TYPE (value) parameter (`int N`,
        // `TWidthHeight widthOrHeight`). Only type parameters are registered as
        // type names for the function-template fall-through below — registering
        // a value parameter as a type would mis-resolve a value use.
        let mut type_param: Vec<bool> = Vec::new();
        if !self.is_punct(Punct::Gt) {
            loop {
                let is_type = self.eat_kw(Keyword::Class) || self.eat_kw(Keyword::Typename);
                if !is_type {
                    // NON-TYPE (value) parameter: `<type> name [= const-expr]`.
                    // OWL `TEdgeOrSizeConstraint<TWidthHeight widthOrHeight>`
                    // (LAYOUTCO.H) and OCF `TAutoArgs<int N>` (AUTODEFS.H) are
                    // CLASS templates whose body is captured as tokens, so only
                    // the NAME matters here — the value binds at instantiation
                    // (deferred). `decl_specifiers` parses the type-SPECIFIER
                    // only and stops at the declarator, so the parameter name is
                    // left for us (unlike `type_name`, which would absorb it).
                    let _ty = self.decl_specifiers()?;
                    let name = match self.kind() {
                        TokenKind::Ident(s) => {
                            let s = s.clone();
                            self.advance();
                            s
                        }
                        _ => {
                            return Err(
                                self.error_here("expected a non-type template parameter name")
                            );
                        }
                    };
                    // Optional default value `= <const-expr>` (an expression,
                    // not a type — parsed and dropped; binds at instantiation).
                    if self.eat_punct(Punct::Assign) {
                        let _ = self.assignment()?;
                    }
                    params.push(name);
                    type_param.push(false);
                    if self.eat_punct(Punct::Comma) {
                        continue;
                    }
                    break;
                }
                let name = match self.kind() {
                    TokenKind::Ident(s) => {
                        let s = s.clone();
                        self.advance();
                        s
                    }
                    _ => {
                        return Err(self.error_here("expected a template parameter name"));
                    }
                };
                // Optional default type argument `= <type>` (parsed; the
                // default value is applied at instantiation in S4.1b).
                if self.eat_punct(Punct::Assign) {
                    let _ = self.type_name()?;
                }
                params.push(name);
                type_param.push(true);
                if self.eat_punct(Punct::Comma) {
                    continue;
                }
                break;
            }
        }
        self.expect_punct(Punct::Gt, ">")?;

        // S4.2b(i): a CLASS template (`template<...> class/struct/union Tag
        // {...};`) is captured as a TOKEN RANGE (tag + type-params + body
        // tokens) and is NOT parsed into records/tags/classes/cxx_funcs here —
        // parsing a generic body whose members are `TemplateParam`-typed would
        // pollute the concrete-codegen machinery the 88 SipHash baselines depend
        // on. Instantiation (replaying the captured tokens with the params bound
        // to concrete types) is a later stage. Function templates fall through
        // to the S4.1 capture path below.
        if matches!(
            self.kind(),
            TokenKind::Keyword(Keyword::Class | Keyword::Struct | Keyword::Union)
        ) {
            return self.capture_class_template(params, type_param);
        }

        // S4.2e: an OUT-OF-LINE template-member definition —
        // `template<class A> ret Tag<A>::member(...) [: init] { ... }`
        // (CLASSLIB's BIDS implementation, e.g. `TMBlockList<Alloc>::
        // TMBlockList(...) : Next(0)`). The function-template path below parses a
        // single free function and cannot handle the `Tag<A>::` qualifier or a
        // ctor init-list. These definitions are the template's IMPLEMENTATION
        // (replayed at the matching instantiation, not emitted standalone).
        // Detected by a `::` at angle-depth 0 before the first `(` (a qualified
        // declarator).
        //
        // S4 (#49): CAPTURE the definition (its template params, the qualifier
        // class-template tag, and its token start) so it can be replayed when
        // `Tag<args>` is instantiated — producing a concrete member function (e.g.
        // the 4-arg `TMVectorImp<T,Alloc>::ForEach` whose absence left the oracle's
        // `ForEach` call unresolved). If the qualifier tag is not a known class
        // template, fall back to the historical SKIP (parse-acceptance only) — the
        // member stays undefined, a clean link error, never a silent miscompile.
        if self.upcoming_is_qualified_definition() {
            let start = self.pos;
            let tag = self.upcoming_qualifier_tag();
            self.skip_balanced_definition();
            if let Some(tag) = tag {
                self.oolt_members
                    .push(OutOfLineMemberTmpl { params, tag, start });
            }
            return Ok(());
        }

        // S4.2f: a function template whose declarator returns/takes a
        // POINTER-TO-MEMBER — OWL/SIGNATUR.H's `bool(T::*B_Sig(...))()` message-
        // handler signatures. mdbcc does not model pointer-to-member types, and
        // (like an out-of-line member) the generic is replayed at instantiation,
        // not emitted here, so SKIP the definition for parse-acceptance. The
        // template is left unregistered: a use-site naming `B_Sig` gets a clean
        // "unknown identifier", never a silent miscompile.
        if self.upcoming_has_pointer_to_member() {
            // G41: before skipping, recognise the IDENTITY shape
            // (`inline void(T::*v_Sig(void(T::*pmf)(…)))(…) { return pmf; }`)
            // and record the template's name so use sites fold to their
            // argument (exactly what bcc32's inliner produces — Borland's OWL
            // libs contain no `_Sig` symbols). Anything else keeps today's
            // unregistered-skip behaviour.
            if let Some(tname) = self.scan_pmf_identity_template() {
                self.pmf_identity_templates.insert(tname);
            }
            self.skip_balanced_definition();
            return Ok(());
        }

        // Register each TYPE parameter as a type name (scoped); remember any
        // shadowed typedef so the scope is restored exactly on exit. NON-TYPE
        // (value) parameters are NOT registered as types — a value use resolves
        // as an ordinary identifier (a clean "unknown" if unbound), never a
        // silent type/value confusion.
        let shadowed: Vec<(String, Option<Type>)> = params
            .iter()
            .zip(type_param.iter())
            .filter(|(_, is_ty)| **is_ty)
            .map(|(p, _)| {
                let prev = self
                    .typedefs
                    .insert(p.clone(), Type::TemplateParam(p.clone()));
                (p.clone(), prev)
            })
            .collect();

        // Parse the templated declaration into a scratch list (the generic is
        // captured, not emitted).
        let mut captured: Vec<Item> = Vec::new();
        let parsed = self.external_declaration(&mut captured);

        // Restore the typedef scope (reverse order) regardless of outcome.
        for (p, prev) in shadowed.into_iter().rev() {
            match prev {
                Some(t) => {
                    self.typedefs.insert(p, t);
                }
                None => {
                    self.typedefs.remove(&p);
                }
            }
        }
        parsed?;

        match captured.pop() {
            Some(Item::Func(func)) if captured.is_empty() => {
                self.fn_templates
                    .push(crate::ast::TemplateDecl { params, func });
                Ok(())
            }
            _ => Err(self.error_here(
                "only function templates and (definition-only) class templates \
                 are supported; this templated form (e.g. an out-of-line member \
                 template or a variable template) is not yet handled",
            )),
        }
    }

    /// S4.2e: true if the upcoming declaration is a QUALIFIED definition — a
    /// `::` at angle-bracket depth 0 appears before the first depth-0 `(`. That
    /// is the shape of an out-of-line member definition `Tag<args>::member(...)`
    /// / `Tag::member(...)`, as distinct from a free function (`ret name(...)`,
    /// no `::`). Used to route out-of-line template-member definitions to a skip.
    fn upcoming_is_qualified_definition(&self) -> bool {
        let mut i = self.pos;
        let mut angle = 0i32;
        while i < self.toks.len() {
            match &self.toks[i].kind {
                TokenKind::Punct(Punct::Lt) => angle += 1,
                TokenKind::Punct(Punct::Gt) if angle > 0 => angle -= 1,
                TokenKind::Punct(Punct::ColonColon) if angle == 0 => return true,
                TokenKind::Punct(Punct::LParen | Punct::LBrace | Punct::Semi) if angle == 0 => {
                    return false;
                }
                TokenKind::Eof => return false,
                _ => {}
            }
            i += 1;
        }
        false
    }

    /// S4 (#49): the qualifier class-template tag of an upcoming out-of-line
    /// template member definition — the identifier that, scanning from the
    /// cursor, is the LAST depth-0 identifier immediately followed by `<` or `::`
    /// before the first depth-0 `::` (which separates the qualifier from the
    /// member). For `void TMVectorImp<T,Alloc>::ForEach(..)` this is `TMVectorImp`
    /// (the return type `void` is followed by an identifier, not `<`/`::`, so it
    /// is skipped). Returns the tag only when it is a registered class template;
    /// `None` otherwise (the caller then falls back to skipping the definition).
    fn upcoming_qualifier_tag(&self) -> Option<String> {
        let mut i = self.pos;
        let mut angle = 0i32;
        let mut tag: Option<String> = None;
        while i < self.toks.len() {
            match &self.toks[i].kind {
                TokenKind::Punct(Punct::Lt) => angle += 1,
                TokenKind::Punct(Punct::Gt) if angle > 0 => angle -= 1,
                TokenKind::Punct(Punct::Shr) if angle > 0 => angle -= 2,
                TokenKind::Punct(Punct::ColonColon) if angle == 0 => break,
                TokenKind::Punct(Punct::LParen | Punct::LBrace | Punct::Semi) if angle == 0 => {
                    break;
                }
                TokenKind::Ident(s) if angle == 0 => {
                    if matches!(
                        self.toks.get(i + 1).map(|t| &t.kind),
                        Some(TokenKind::Punct(Punct::Lt | Punct::ColonColon))
                    ) {
                        tag = Some(s.clone());
                    }
                }
                TokenKind::Eof => break,
                _ => {}
            }
            i += 1;
        }
        tag.filter(|t| self.class_template_idx.contains_key(t))
    }

    /// S4.2f: does the upcoming function-template declarator contain a
    /// POINTER-TO-MEMBER (`Class::*`)? OWL/SIGNATUR.H's message-handler signature
    /// templates — `template<class T> inline bool(T::*B_Sig(bool(T::*pmf)()))()` —
    /// declare functions whose return AND parameter are pointer-to-member-function
    /// types. mdbcc does not model pointer-to-member, and these are function
    /// templates whose instantiation is deferred (token-replay) regardless. The
    /// `::` IMMEDIATELY followed by `*` is unambiguous — it appears only in a
    /// pointer-to-member type, never in a plain qualified name — so scanning to
    /// the body `{` (or a `;` for a bare declaration) reliably flags the form.
    /// G41: does the upcoming (to-be-skipped) PMF template definition have the
    /// SIGNATUR.H identity shape? Token-level scan from the cursor:
    ///
    /// ```text
    /// inline void ( T :: * v_Sig ( void ( T :: * pmf ) (…) ) ) (…) { return pmf ; }
    ///              ^^^^^^^ fn name (1st `::*`-ident, `(` follows)
    ///                              ^^^^^^^^^^ param (2nd `::*`-ident)
    /// ```
    ///
    /// Requirements: exactly the body `{ return <param> ; }` where `<param>`
    /// is the SECOND identifier appearing right after a `:: *` sequence, and
    /// the FIRST such identifier (the function name) is directly followed by
    /// `(`. Returns the function name, or `None` (→ caller keeps the plain
    /// unregistered skip — a clean unknown-identifier at any use site).
    fn scan_pmf_identity_template(&self) -> Option<String> {
        let mut i = self.pos;
        let mut pm_idents: Vec<(String, usize)> = Vec::new(); // (name, tok idx)
        // Scan the declarator up to the body `{` (a `;` means no body).
        loop {
            match &self.toks.get(i)?.kind {
                TokenKind::Punct(Punct::LBrace) => break,
                TokenKind::Punct(Punct::Semi) | TokenKind::Eof => return None,
                TokenKind::Punct(Punct::ColonColon)
                    if matches!(
                        self.toks.get(i + 1).map(|t| &t.kind),
                        Some(TokenKind::Punct(Punct::Star))
                    ) =>
                {
                    if let Some(TokenKind::Ident(s)) = self.toks.get(i + 2).map(|t| &t.kind) {
                        pm_idents.push((s.clone(), i + 2));
                    }
                    i += 2;
                }
                _ => {}
            }
            i += 1;
        }
        // Exactly two `::*`-idents: the fn name (with `(` following) + param.
        let [(fname, fidx), (pname, _)] = pm_idents.as_slice() else {
            return None;
        };
        if !matches!(
            self.toks.get(fidx + 1).map(|t| &t.kind),
            Some(TokenKind::Punct(Punct::LParen))
        ) {
            return None;
        }
        // Body must be exactly `{ return <param> ; }`.
        let body_ok = matches!(
            self.toks.get(i + 1).map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::Return))
        ) && matches!(
            self.toks.get(i + 2).map(|t| &t.kind),
            Some(TokenKind::Ident(s)) if s == pname
        ) && matches!(
            self.toks.get(i + 3).map(|t| &t.kind),
            Some(TokenKind::Punct(Punct::Semi))
        ) && matches!(
            self.toks.get(i + 4).map(|t| &t.kind),
            Some(TokenKind::Punct(Punct::RBrace))
        );
        body_ok.then(|| fname.clone())
    }

    fn upcoming_has_pointer_to_member(&self) -> bool {
        let mut i = self.pos;
        while i < self.toks.len() {
            match &self.toks[i].kind {
                TokenKind::Punct(Punct::LBrace | Punct::Semi) => return false,
                TokenKind::Punct(Punct::ColonColon)
                    if self.toks.get(i + 1).map(|t| &t.kind)
                        == Some(&TokenKind::Punct(Punct::Star)) =>
                {
                    return true;
                }
                TokenKind::Eof => return false,
                _ => {}
            }
            i += 1;
        }
        false
    }

    /// S4.2e: consume a balanced `< ... >` template-argument list (cursor on the
    /// `<`). Handles a `>>` token closing two levels (`Tmpl<A<B>>`).
    fn skip_angle_brackets(&mut self) {
        let mut depth = 0i32;
        loop {
            match self.kind() {
                TokenKind::Punct(Punct::Lt) => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::Punct(Punct::Gt) => {
                    depth -= 1;
                    self.advance();
                    if depth <= 0 {
                        return;
                    }
                }
                TokenKind::Punct(Punct::Shr) => {
                    depth -= 2;
                    self.advance();
                    if depth <= 0 {
                        return;
                    }
                }
                TokenKind::Eof => return,
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// S4.2e: skip a definition's tokens — a balanced `{...}` body, or the
    /// terminating `;` of a bare declaration if no body precedes it. Used to drop
    /// an out-of-line template-member definition the parser cannot model yet.
    fn skip_balanced_definition(&mut self) {
        while !self.at_eof() {
            match self.kind() {
                TokenKind::Punct(Punct::LBrace) => {
                    let mut depth = 0i32;
                    loop {
                        if self.is_punct(Punct::LBrace) {
                            depth += 1;
                        } else if self.is_punct(Punct::RBrace) {
                            depth -= 1;
                            if depth == 0 {
                                self.advance(); // closing `}`
                                self.eat_punct(Punct::Semi); // optional `;`
                                return;
                            }
                        } else if self.at_eof() {
                            return;
                        }
                        self.advance();
                    }
                }
                TokenKind::Punct(Punct::Semi) => {
                    self.advance();
                    return;
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// S4.2b(i): capture a CLASS template definition by SKIPPING its tokens.
    /// The cursor is on the `class`/`struct`/`union` keyword; on return it is
    /// just past the trailing `;`. The generic body is NOT parsed — doing so
    /// would lay out a record with `TemplateParam`-typed members and pollute the
    /// concrete-codegen machinery (records/tags/classes/cxx_funcs) that the 88
    /// SipHash baselines depend on. This lets a header that *defines* class
    /// templates parse cleanly; instantiation at use sites (which needs the
    /// captured tokens replayed with the params bound) is a later stage.
    fn capture_class_template(
        &mut self,
        params: Vec<String>,
        type_param: Vec<bool>,
    ) -> PResult<()> {
        let start = self.pos; // the `class`/`struct`/`union` keyword
        let is_union = self.is_kw(Keyword::Union);
        self.advance(); // class | struct | union
        // Skip `__declspec(...)` and any memory-model/export/conv qualifier run
        // between the keyword and the tag (`class _RTLCLASS Foo`, after macro
        // expansion `class __declspec(...) Foo` / `class __export Foo` /
        // `class huge Foo`).
        self.skip_class_head_qualifiers();
        // The tag name (then an optional base-clause and the body).
        let tag = match self.kind() {
            TokenKind::Ident(s) => s.clone(),
            _ => {
                return Err(
                    self.error_here("expected a class-template name after class/struct/union")
                );
            }
        };
        self.advance();
        // Advance to the end of the declaration: a `;` (a forward declaration)
        // or a brace-matched `{ ... }` body then a trailing `;`. A base-clause
        // (`: public Base`) carries no braces, so we just advance over it.
        loop {
            match self.kind() {
                TokenKind::Punct(Punct::Semi) => {
                    // S4.2f: a FORWARD declaration — no body. REGISTER the name so
                    // a use site (OWL/EVENTHAN.H's
                    // `typedef TResponseTableEntry<GENERIC> …`, written before the
                    // body at line 97) recognises it as a template; instantiation
                    // yields an opaque incomplete record. A re-declaration that
                    // DOES carry a body overwrites this entry below. Skip a
                    // duplicate forward decl so the registry stays clean.
                    self.advance();
                    if !self.class_template_idx.contains_key(&tag) {
                        let entry = ClassTemplateDecl {
                            params,
                            type_param,
                            tag: tag.clone(),
                            is_union,
                            start,
                            forward: true,
                        };
                        let idx = self.class_templates.len();
                        self.class_templates.push(entry);
                        self.class_template_idx.insert(tag, idx);
                    }
                    return Ok(());
                }
                TokenKind::Punct(Punct::LBrace) => {
                    let mut depth = 0i32;
                    loop {
                        match self.kind() {
                            TokenKind::Punct(Punct::LBrace) => {
                                depth += 1;
                                self.advance();
                            }
                            TokenKind::Punct(Punct::RBrace) => {
                                depth -= 1;
                                self.advance();
                                if depth == 0 {
                                    break;
                                }
                            }
                            TokenKind::Eof => {
                                return Err(self.error_here("unterminated class-template body"));
                            }
                            _ => {
                                self.advance();
                            }
                        }
                    }
                    self.eat_punct(Punct::Semi); // trailing `;` after the body
                    // Register the template (with a body) for instantiation. A
                    // later capture of the same tag (re-declaration) overwrites.
                    // S4.2f: a full definition overwrites any prior FORWARD entry
                    // for this tag (the idx is replaced; later instantiations get
                    // the real body).
                    let entry = ClassTemplateDecl {
                        params,
                        type_param,
                        tag: tag.clone(),
                        is_union,
                        start,
                        forward: false,
                    };
                    let idx = self.class_templates.len();
                    self.class_templates.push(entry);
                    self.class_template_idx.insert(tag, idx);
                    return Ok(());
                }
                TokenKind::Eof => {
                    return Err(self.error_here("unterminated class template"));
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// S4.2b(ii): instantiate a class template at a use site `Tag < type-args >`
    /// (cursor on the tag). Parses the argument list, then — if this exact
    /// instantiation isn't cached — binds the type parameters to the concrete
    /// arguments (as scoped typedefs) and RE-PARSES the captured generic body
    /// through the ordinary `record_specifier` path, jumping the cursor to the
    /// stored token start and restoring it afterwards. The result is a concrete
    /// record + member functions, indistinguishable from a hand-written class.
    /// #57: complete every class-template instantiation that was frozen from a
    /// FORWARD declaration (opaque, member-less) before its body was defined.
    /// Each was recorded with the `Tag<args>` token position; now that the whole
    /// TU has parsed (all bodies registered), replay from that position to get a
    /// CONCRETE instantiation and copy its layout into the frozen record id — so
    /// the `typedef` that captured the id (OWL `TGenericTableEntry`) gains the
    /// real members. Best-effort: a template that never got a body, or a replay
    /// that errors, leaves the record opaque (a clean later error, not a silent
    /// miscompile). The freshly-produced concrete record is left as a duplicate
    /// (a POD layout carries no emitted symbols; vague-linkage methods COMDAT-fold).
    fn complete_forward_instantiations(&mut self) {
        let pending = std::mem::take(&mut self.pending_fwd_inst);
        let saved_pos = self.pos;
        for (opaque_id, tag_pos, name) in pending {
            let Some(&idx) = self.class_template_idx.get(&name) else {
                continue;
            };
            if self.class_templates[idx].forward {
                continue; // never got a body — genuinely incomplete
            }
            self.pos = tag_pos;
            let Ok(Type::Record {
                id: complete_id, ..
            }) = self.instantiate_class_template(&name)
            else {
                continue;
            };
            if complete_id == opaque_id {
                continue;
            }
            let src = self.records[complete_id].clone();
            let dst = &mut self.records[opaque_id];
            dst.fields = src.fields;
            dst.size = src.size;
            dst.align = src.align;
            dst.base = src.base;
            dst.base_offset = src.base_offset;
            dst.vtable = src.vtable;
            dst.is_union = src.is_union;
            // Carry the ClassInfo (methods) so member-FUNCTION resolution on the
            // typedef'd type works too.
            if let Some(ci) = self.classes.get(&complete_id).cloned() {
                self.classes.insert(opaque_id, ci);
            }
        }
        self.pos = saved_pos;
    }

    /// S6 (#22): parse a NON-TYPE (value) template argument and fold it to an
    /// integer constant. Restricted to a single primary — an int literal or an
    /// identifier naming an enum constant / `const int` (the OWL layout cluster
    /// uses `<lmWidth>` / `<lmHeight>`; `<N>` also works). Parsing only a primary
    /// avoids the template-arg `>` ambiguity (a full expression would consume the
    /// closing `>` as greater-than). Richer constant-expression args are deferred.
    fn template_value_arg(&mut self) -> PResult<i64> {
        match self.kind().clone() {
            TokenKind::Int { value, .. } => {
                self.advance();
                Ok(value as i64)
            }
            TokenKind::Ident(s) => {
                self.advance();
                if let Some(&v) = self.enum_consts.get(&s) {
                    Ok(v)
                } else if let Some(&v) = self.int_consts.get(&s) {
                    Ok(v)
                } else {
                    Err(self.error_here(format!(
                        "non-type template argument '{s}' is not an integer \
                         constant (enum constant / const int)"
                    )))
                }
            }
            _ => Err(self.error_here("expected a constant non-type template argument")),
        }
    }

    fn parse_class_template_args(&mut self, name: &str, idx: usize) -> PResult<ClassTemplateArgs> {
        // S6 (#22): per-parameter kind, so a NON-TYPE param's arg parses as a
        // VALUE (not a type).
        let tmpl_tp = self.class_templates[idx].type_param.clone();
        self.expect_punct(Punct::Lt, "<")?;
        let mut type_args: Vec<Type> = Vec::new();
        // S6 (#22): parallel to `type_args` — `Some(v)` for a non-type (value)
        // argument; its `type_args` slot holds an `int` placeholder (never used as
        // a type). Drives the value binding + the value-coded key/mangle below.
        let mut arg_vals: Vec<Option<i64>> = Vec::new();
        if !self.is_punct(Punct::Gt) {
            loop {
                let is_value = tmpl_tp.get(type_args.len()) == Some(&false);
                if is_value {
                    let v = self.template_value_arg()?;
                    type_args.push(Type::Int {
                        bytes: 4,
                        signed: true,
                    });
                    arg_vals.push(Some(v));
                } else {
                    type_args.push(self.type_name()?);
                    arg_vals.push(None);
                }
                if self.eat_punct(Punct::Comma) {
                    continue;
                }
                break;
            }
        }
        self.expect_punct(Punct::Gt, ">")?;
        if self.class_templates[idx].params.len() != type_args.len() {
            return Err(self.error_here(format!(
                "class template '{name}' expects {} type argument(s), got {}",
                self.class_templates[idx].params.len(),
                type_args.len()
            )));
        }
        // S6 (#22): per-arg code for the cache key + mangled tag — a value arg
        // codes as `V<n>` (so `<lmWidth>` vs `<lmHeight>` are distinct), a type
        // arg via `type_arg_code`. Precomputed once, reused for key + mangle.
        let codes: Vec<String> = type_args
            .iter()
            .zip(arg_vals.iter())
            .map(|(t, v)| match v {
                Some(n) => format!("V{n}"),
                None => type_arg_code(t),
            })
            .collect();

        let key = format!("{name}<{}>", codes.join(","));
        Ok((type_args, arg_vals, codes, key))
    }

    fn instantiate_class_template(&mut self, name: &str) -> PResult<Type> {
        let idx = *self
            .class_template_idx
            .get(name)
            .expect("class-template idx");
        let tag_pos = self.pos; // the `Tag` token — replayable for #57 completion
        self.advance(); // tag
        let (type_args, arg_vals, codes, key) = self.parse_class_template_args(name, idx)?;
        if let Some(&id) = self.class_inst_cache.get(&key) {
            let r = &self.records[id];
            return Ok(Type::Record {
                id,
                size: r.size,
                align: r.align,
            });
        }
        // S4.2f: a declaration-only explicit FULL specialization was seen, but
        // no concrete record body has been parsed. Using the primary here would
        // silently miscompile if the specialization's members differ.
        if self.class_specializations.contains(&key) {
            return Err(self.error_here(format!(
                "class-template specialization '{key}' has no parsed definition"
            )));
        }

        let tmpl = self.class_templates[idx].clone();
        // The concrete tag — unique per type-argument set — so multiple
        // instantiations of one template don't collide (`Box$i4`, `Box$i1`).
        let mangled = format!("{}${}", tmpl.tag, codes.join("$"));

        // S4.2f: a FORWARD-declared template with no body yet — OWL/EVENTHAN.H
        // typedefs `TResponseTableEntry<GENERIC>` before the body at line 97.
        // There is nothing to replay, so yield an opaque INCOMPLETE record (size
        // 0, like the dependent case). Deliberately NOT cached: once the full body
        // is registered (overwriting `class_template_idx`), a fresh mention
        // re-instantiates against the real body. (An incomplete record used as a
        // sized object is mdbcc's existing lenient behaviour — not introduced
        // here; the header uses these typedefs opaquely / as pointers.)
        if tmpl.forward {
            let id = self.records.len();
            self.records.push(Record {
                tag: Some(mangled),
                is_union: tmpl.is_union,
                fields: Vec::new(),
                size: 0,
                align: 1,
                base: None,
                base_offset: 0,
                extra_bases: Vec::new(),
                mi_dropped: false,
                vtable: Vec::new(),
                vbases: Vec::new(),
                vbptr_offsets: Vec::new(),
            });
            // #57: record this frozen opaque instantiation so the post-parse pass
            // can complete it once the body is registered (the typedef that
            // captured `id` will then see the real members).
            self.pending_fwd_inst.push((id, tag_pos, name.to_string()));
            return Ok(Type::Record {
                id,
                size: 0,
                align: 1,
            });
        }

        // S4.2e: a DEPENDENT instantiation — at least one argument is still a
        // generic template parameter (`TMMemStack<Alloc>` inside a function
        // template, where `Alloc` is bound to `TemplateParam`). Re-parsing the
        // body with a generic argument is wrong (the body's `: public Alloc`
        // would have no concrete base — the CLASSLIB BIDS failure). A dependent
        // type is opaque until the enclosing template is instantiated with a
        // concrete argument (at which point the tokens are replayed and this is
        // reached again with a real type), so return an incomplete placeholder
        // record now and DON'T re-parse the body.
        if type_args
            .iter()
            .any(|t| matches!(t, Type::TemplateParam(_)))
        {
            let id = self.records.len();
            self.records.push(Record {
                tag: Some(mangled),
                is_union: tmpl.is_union,
                fields: Vec::new(),
                size: 0,
                align: 1,
                base: None,
                base_offset: 0,
                extra_bases: Vec::new(),
                mi_dropped: false,
                vtable: Vec::new(),
                vbases: Vec::new(),
                vbptr_offsets: Vec::new(),
            });
            self.class_inst_cache.insert(key, id);
            return Ok(Type::Record {
                id,
                size: 0,
                align: 1,
            });
        }

        // Bind params → concrete args (scoped), re-parse the body, restore.
        // S6 (#22): a TYPE param binds a typedef (its uses resolve as a type); a
        // NON-TYPE (value) param binds an enum-constant (its uses fold to the int
        // value), with separate restore lists.
        let mut shadowed: Vec<(String, Option<Type>)> = Vec::new();
        let mut shadowed_vals: Vec<(String, Option<i64>)> = Vec::new();
        for (i, p) in tmpl.params.iter().enumerate() {
            match arg_vals[i] {
                Some(v) => {
                    shadowed_vals.push((p.clone(), self.enum_consts.insert(p.clone(), v)));
                }
                None => {
                    shadowed.push((
                        p.clone(),
                        self.typedefs.insert(p.clone(), type_args[i].clone()),
                    ));
                }
            }
        }
        let saved_pos = self.pos;
        let cxx_start = self.cxx_funcs.len();
        // S4.2e: PRE-REGISTER the cache before re-parsing, so a self-referential
        // body (a template that uses its own injected-class-name, or a recursive
        // BIDS container like `TVectorImpBase`) resolves to this IN-PROGRESS
        // record instead of recursing without bound. `record_specifier` creates
        // the record at `self.records.len()` for the (fresh, soon-renamed)
        // generic tag, so that is the id this instantiation will own. The
        // `inst_depth` guard remains a backstop for a genuine non-self chain.
        let predicted_id = self.records.len();
        self.class_inst_cache.insert(key.clone(), predicted_id);
        self.inst_depth += 1;
        if self.inst_depth > 8 {
            self.inst_depth -= 1;
            return Err(self.error_here(format!(
                "class template '{name}' instantiated too deeply \
                 (recursive instantiation?)"
            )));
        }
        self.pos = tmpl.start; // the class/struct/union keyword
        let result = self.record_specifier(tmpl.is_union);
        self.pos = saved_pos;
        self.inst_depth -= 1;
        for (p, prev) in shadowed.into_iter().rev() {
            match prev {
                Some(t) => {
                    self.typedefs.insert(p, t);
                }
                None => {
                    self.typedefs.remove(&p);
                }
            }
        }
        // S6 (#22): restore the enum-constant bindings of any value parameters.
        for (p, prev) in shadowed_vals.into_iter().rev() {
            match prev {
                Some(v) => {
                    self.enum_consts.insert(p, v);
                }
                None => {
                    self.enum_consts.remove(&p);
                }
            }
        }
        let ty = result?;
        let Type::Record { id, .. } = ty else {
            return Ok(ty);
        };
        // The pre-registered cache id must be the record this instantiation
        // actually produced (record_specifier creates the fresh generic tag at
        // `self.records.len()`); otherwise a self-reference resolved to the wrong
        // record.
        debug_assert_eq!(
            id, predicted_id,
            "instantiation cache pre-registration id mismatch for '{name}'"
        );

        // Rename the just-parsed record from the generic tag to the unique
        // `mangled` tag (record + tags + ClassInfo + member fns + vtable +
        // defaults), so a later instantiation with different arguments gets a
        // fresh `tags` slot instead of colliding on the generic name.
        let old = tmpl.tag.clone();
        if old != mangled {
            self.records[id].tag = Some(mangled.clone());
            for slot in &mut self.records[id].vtable {
                slot.sym = rename_sym(&slot.sym, &old, &mangled);
            }
            self.tags.remove(&old);
            self.tags.insert(mangled.clone(), id);
            if let Some(ci) = self.classes.get_mut(&id) {
                ci.tag = mangled.clone();
                for m in &mut ci.decl_methods {
                    m.sym = rename_sym(&m.sym, &old, &mangled);
                }
            }
            for f in &mut self.cxx_funcs[cxx_start..] {
                f.name = rename_sym(&f.name, &old, &mangled);
            }
            let pfx = format!("{old}::");
            let keys: Vec<String> = self
                .fn_defaults
                .keys()
                .filter(|k| k.starts_with(&pfx))
                .cloned()
                .collect();
            for k in keys {
                if let Some(v) = self.fn_defaults.remove(&k) {
                    self.fn_defaults.insert(rename_sym(&k, &old, &mangled), v);
                }
            }
            // S4.2av: keep the collision-free list in sync with the rename so a
            // template-instantiated class's defaulted ctors still match their
            // (renamed) Function at Overload construction.
            for entry in self.overload_defaults.iter_mut() {
                if entry.0.starts_with(&pfx) {
                    entry.0 = rename_sym(&entry.0, &old, &mangled);
                }
            }
        }
        self.class_inst_cache.insert(key, id);
        // S4 (#49): replay any out-of-line template member definitions belonging
        // to this class template, binding their params to the concrete type
        // arguments — producing concrete member functions on this instance (e.g.
        // the 4-arg `TMVectorImp<T,Alloc>::ForEach`). Without this the member is
        // declared (parsed from the class body) but never defined, so a call to it
        // is left unresolved (the oracle's `ForEach` link blocker).
        self.replay_oolt_members(&tmpl.tag, &type_args, id);
        let r = &self.records[id];
        Ok(Type::Record {
            id,
            size: r.size,
            align: r.align,
        })
    }

    /// S4 (#49): replay the captured out-of-line template member definitions for
    /// the class template `tag`, binding each def's params to `type_args`, and
    /// route the produced member function(s) into `cxx_funcs` (the collection
    /// `compile_module` drains). Called at the END of `instantiate_class_template`
    /// (cache-miss path only), AFTER the record is renamed to its concrete tag and
    /// the instantiation is cached — so the declarator's template-id-qualifier
    /// resolution finds this instance. A parse error replaying a single def is
    /// non-fatal: that member stays undefined (a clean link error, not a silent
    /// miscompile), and the other defs still replay. `_id` is the instance record
    /// (the declarator re-derives it from the cache via the template-id key).
    fn replay_oolt_members(&mut self, tag: &str, type_args: &[Type], _id: usize) {
        // Snapshot the matching defs first: the replay mutates self heavily
        // (typedefs, pos, records, cxx_funcs) and may itself instantiate further
        // templates, so we must not hold a borrow of `self.oolt_members`.
        let defs: Vec<OutOfLineMemberTmpl> = self
            .oolt_members
            .iter()
            .filter(|d| d.tag == tag && d.params.len() == type_args.len())
            .cloned()
            .collect();
        if defs.is_empty() {
            return;
        }
        let saved_pos = self.pos;
        for def in defs {
            // Bind the def's own params → the concrete type args (scoped), so the
            // replayed `Tag<T,Alloc>::member` and its body see concrete types.
            let shadowed: Vec<(String, Option<Type>)> = def
                .params
                .iter()
                .zip(type_args.iter())
                .map(|(p, a)| (p.clone(), self.typedefs.insert(p.clone(), a.clone())))
                .collect();
            self.pos = def.start;
            let mut scratch: Vec<Item> = Vec::new();
            let parsed = self.external_declaration(&mut scratch);
            // Restore the typedef scope (reverse order) regardless of outcome.
            for (p, prev) in shadowed.into_iter().rev() {
                match prev {
                    Some(t) => {
                        self.typedefs.insert(p, t);
                    }
                    None => {
                        self.typedefs.remove(&p);
                    }
                }
            }
            if parsed.is_ok() {
                for item in scratch {
                    if let Item::Func(mut f) = item {
                        // An implicitly-instantiated template member function has
                        // VAGUE (COMDAT) linkage — every TU that uses it emits an
                        // identical copy, folded by the linker. Marking it `inline`
                        // gives it that linkage AND routes it into codegen's
                        // prune/defer machinery: an UNREACHABLE instantiated member
                        // (e.g. `TMBaseMemBlocks::AllocBlock`, never called by this
                        // TU) is pruned, and a reachable one whose body hits a not-
                        // yet-supported construct is deferred — neither aborts the
                        // whole compile. A REACHABLE, codegen-able member (the
                        // oracle's 4-arg `TMVectorImp::ForEach`) is emitted normally.
                        f.inline = true;
                        self.cxx_funcs.push(f);
                    }
                }
            }
        }
        self.pos = saved_pos;
    }

    /// S4.2b2: at namespace scope, disambiguate a `(` after a declared name as
    /// either a function parameter list or a DIRECT-INITIALISER (`T name(args)`
    /// / `T C::m(args)` — a file-scope/static object construction). The cursor is
    /// AT the `(`. Returns `Some(args)` (consuming `( … )`) when the contents are
    /// EXPRESSIONS — i.e. the token after `(` neither starts a type nor closes an
    /// empty list; otherwise returns `None` and leaves the cursor untouched so
    /// the caller takes its existing function-declarator path. `T name()` stays a
    /// function (the C++ most-vexing parse), and `int f(int)` etc. are unchanged
    /// (a type-start ⇒ params), so the 88 byte-identity console fixtures — none
    /// of which file-scope-direct-init — are unaffected.
    fn try_direct_init_args(&mut self) -> PResult<Option<Vec<Expr>>> {
        debug_assert!(self.is_punct(Punct::LParen));
        match self.kind_at(1) {
            // empty `()` ⇒ function (most-vexing parse); a type-start ⇒ params.
            Some(TokenKind::Punct(Punct::RParen)) => return Ok(None),
            // S6: a `Type :: value` first argument (a QUALIFIED name whose tail
            // is NOT itself a type — an enum constant / static member) is an
            // EXPRESSION, so the whole `( … )` is a direct-init, not a param
            // list. OWL BUTTONGA.CPP: `static THatch8x8Brush ditherBrush(
            // THatch8x8Brush::Hatch11F1, ::GetSysColor(...), …)`. Without this
            // the leading type-name `THatch8x8Brush` made the one-token peek
            // assume a function declaration, which then tried to parse the
            // following `::GetSysColor` argument as a parameter TYPE ("expected
            // a type, found '::'"). A genuine nested-TYPE param (`Outer::Inner`)
            // still returns None (the tail names a type) ⇒ unchanged.
            Some(k)
                if self.kind_starts_type(k)
                    && self.kind_at(2) == Some(&TokenKind::Punct(Punct::ColonColon))
                    && matches!(self.kind_at(3), Some(TokenKind::Ident(m)) if {
                        !self.typedefs.contains_key(m)
                            && !self.tags.contains_key(m)
                            && !self.class_template_idx.contains_key(m)
                    }) => {}
            Some(k) if self.kind_starts_type(k) => return Ok(None),
            _ => {}
        }
        self.advance(); // (
        let mut args = Vec::new();
        loop {
            args.push(self.assignment()?);
            if !self.eat_punct(Punct::Comma) {
                break;
            }
        }
        self.expect_punct(Punct::RParen, ")")?;
        Ok(Some(args))
    }

    /// S4.2b2: the bare record tag a direct-init constructs, if `ty` is a record
    /// (const-qualification is not modelled in `Type`, so `ty` is the record
    /// itself). Used to build the ctor-rvalue `Tag(args)` init expression.
    fn direct_init_tag(&self, ty: &Type) -> Option<String> {
        match ty {
            Type::Record { id, .. } => self.records.get(*id).and_then(|r| r.tag.clone()),
            _ => None,
        }
    }

    fn external_declaration(&mut self, items: &mut Vec<Item>) -> PResult<()> {
        // A stray top-level `;` is an empty-declaration (C++ §7) — common after
        // a class/function definition, e.g. EXCEPT.H's `inline ... why() const
        // { return *str; };`. Skip it (no item).
        if self.eat_punct(Punct::Semi) {
            return Ok(());
        }
        // W6 (G48): the preprocessor's `#pragma startup` splice —
        // `__mdbcc_startup__ <fn> <prio> ;` (see pp.rs). Record (fn, prio) on
        // the TU; codegen emits the ordered startup thunk. The reserved
        // double-underscore identifier is produced ONLY by the pp.
        if matches!(self.kind(), TokenKind::Ident(n) if n == "__mdbcc_startup__") {
            self.advance();
            let fname = match &self.advance().kind {
                TokenKind::Ident(n) => n.clone(),
                _ => return Err(self.error_here("#pragma startup expects a function name")),
            };
            let prio = match &self.advance().kind {
                TokenKind::Int { value, .. } => *value as u32,
                _ => return Err(self.error_here("#pragma startup expects a priority")),
            };
            self.expect_punct(Punct::Semi, ";")?;
            self.startup_fns.push((fname, prio));
            return Ok(());
        }
        // S4: a template declaration — `template < class T, … > <decl>`.
        // S4.1 captures function templates (a single templated function
        // definition); the generic is stored for later monomorphisation
        // (S4.1b), not emitted here.
        if self.eat_kw(Keyword::Template) {
            return self.template_declaration(items);
        }
        // S3 (C++ §7.5): a linkage-specification — `extern "C" { decls }` or
        // `extern "C" decl`. Detected by `extern` IMMEDIATELY followed by a
        // string-literal token (the normal `extern int x;` storage-class path
        // is `extern` followed by a type/declarator and is untouched). Nearly
        // every real Borland header wraps its prototypes in
        // `#ifdef __cplusplus extern "C" { #endif ... #endif`, which in C++
        // mode becomes this construct.
        if self.is_kw(Keyword::Extern) && matches!(self.kind_at(1), Some(TokenKind::Str { .. })) {
            return self.linkage_specification(items);
        }
        // S4.2#24: a storage-class `extern` (NOT `extern "C"`, handled above).
        // Captured here before `decl_specifiers` consumes it; a data declarator
        // with no initializer under it becomes a cross-TU ExternGlobal below.
        // S4 (#48): a declaration INSIDE an `extern "C"` linkage-spec
        // (`self.c_linkage`) is likewise external — C++ [dcl.link]/7 treats it
        // as if `extern`-specified, so a no-initializer data decl is a
        // DECLARATION, not a definition. The OLE GUID headers `EXTERN_C const
        // IID name;` (DEFINE_GUID without INITGUID) expand to exactly this; w/o
        // this, EVERY TU that includes <windows.h> emitted a definition ->
        // "duplicate symbol 'IID_IAdviseSink'" at a multi-TU link.
        let is_extern_decl = self.is_kw(Keyword::Extern) || self.c_linkage;
        // Out-of-line constructor/destructor `Tag::Tag(..){}` / `Tag::~Tag(){}`
        // (no return type, so it must be detected before `decl_specifiers`).
        // S4.2al: route here ONLY when the name after `Tag::` is the tag itself
        // (ctor) or `~` (dtor). Otherwise `Tag::` begins a QUALIFIED NESTED TYPE
        // used as a RETURN type — `TRegexp::StatVal TRegexp::status() {…}`
        // (STRING/STATUS.CPP) — which must fall through to `decl_specifiers` so
        // the nested type is read as the return type and `TRegexp::status` as the
        // out-of-line member. Previously every `Tag::` was assumed to be a
        // ctor/dtor, so a nested-type return errored "does not name a
        // constructor or destructor". Pure widening: only currently-erroring
        // `Tag::NestedType` cases change behaviour, so the 88 baselines (no such
        // construct) stay byte-identical.
        if let TokenKind::Ident(tag) = self.kind() {
            let tag = tag.clone();
            let is_ctor_or_dtor = matches!(
                self.kind_at(2),
                Some(TokenKind::Ident(n)) if *n == tag
            ) || self.kind_at(2) == Some(&TokenKind::Punct(Punct::Tilde));
            if self.kind_at(1) == Some(&TokenKind::Punct(Punct::ColonColon))
                && self.tags.contains_key(&tag)
                && is_ctor_or_dtor
            {
                return self.out_of_line_ctor_dtor(items, &tag);
            }
        }
        let base = self.decl_specifiers()?;
        let is_typedef = self.is_typedef;
        // S4 (#48): capture `const`-ness NOW (set by decl_specifiers for `const
        // T x`), before the declarator/param-list below re-enters
        // decl_specifiers and clears it. A namespace-scope `const` (no `extern`)
        // has INTERNAL linkage -> a TU-local global (see Item::Global.is_const).
        // C++ [basic.link]/3: `extern` (incl. `extern "C"`, `is_extern_decl`)
        // overrides const's internal linkage -> external, so `extern "C" const
        // int X = 5;` stays an external definition, not a TU-local copy.
        let is_const_decl = self.is_const && !is_extern_decl;
        // S2b.3: capture the convention from the decl-specifiers now — parsing
        // the parameter list below re-enters `decl_specifiers` (per param),
        // which would clear `self.last_call_conv` before we build the Function.
        let spec_call_conv = self.last_call_conv;
        // S4.2h: likewise capture `inline` NOW, before the declarator/param list
        // re-enters `decl_specifiers` and clears it — a free or out-of-line
        // definition declared `inline` (header `inline bool operator==(TPoint,
        // TPoint)`) is vague-linkage and droppable on demand. Restore it before
        // each construction site below (param parsing will have cleared the field).
        let decl_is_inline = self.is_inline;

        // A bare type declaration: `struct X { ... };` / `enum E { ... };`.
        if self.eat_punct(Punct::Semi) {
            return Ok(());
        }
        if is_typedef {
            self.register_typedefs(base)?;
            self.expect_punct(Punct::Semi, ";")?;
            return Ok(());
        }

        // First declarator. The parenthesized conv-led form is tried first —
        // `int (_RTLENTRY _EXPFUNC isalnum)(int c) { … }` (see
        // `paren_conv_fn_declarator`); the generic declarator handles the rest.
        let (ty, name) = if let Some(tn) = self.paren_conv_fn_declarator(&base)? {
            tn
        } else {
            self.declarator(base.clone())?
        };
        // S3: the declarator may itself carry a calling convention in the
        // `T * __cdecl name(...)` position (`skip_call_conv` records it). Prefer
        // it; fall back to the decl-specifier convention. Re-read now, before
        // `param_list` below re-enters `decl_specifiers` and clears the field.
        let call_conv = self.last_call_conv.or(spec_call_conv);
        let name = name.ok_or_else(|| self.error_here("expected a declared name"))?;

        // Out-of-line member: `Ret Tag::method(..) {}`, `Tag::Tag(..){}`,
        // `Tag::~Tag(){}`, or a nested form `Outer::Inner::member(..)`. mdbcc's
        // class model is FLAT, so map `A::B::…::member` to the INNERMOST class
        // (`B`) + member — `string::outofrange::outofrange` ≡
        // `outofrange::outofrange`. Single-`::` names map to themselves.
        //
        // S4.2y: a `::`-name with the cursor on `(` is a member function /
        // ctor / dtor definition (→ `member_def_tail`). A `::`-name with the
        // cursor on `=` or `;` is a STATIC DATA MEMBER definition
        // (`int string::case_sensitive = 1;`) — it falls through to the
        // global-object path below, producing `Item::Global { name:
        // "string::case_sensitive", .. }`, a single program-wide object keyed
        // by its qualified name. (Direct-init `Type C::m(args);` would also
        // show `(`; rare for statics and not yet exercised — deferred.)
        if self.is_punct(Punct::LParen)
            && let Some((class_path, member)) = name.rsplit_once("::")
        {
            let cls = class_path
                .rsplit_once("::")
                .map(|(_, c)| c)
                .unwrap_or(class_path)
                .to_string();
            let member = member.to_string();
            // S6 (#64): resolve via the SCOPED key `Outer::Inner` first (the
            // out-of-line def of a nested class minted under a unique tag —
            // IMPLEMENT_STREAMABLE's `TButton::Streamer::Read`), falling back to
            // the flat innermost tag. The SYMBOL is keyed off the resolved
            // record's actual tag (`rtag`, e.g. `Streamer$N`) so it matches the
            // inline member registration; ctor/dtor are still NAMED by the bare
            // inner `cls`.
            let id = *self
                .tags
                .get(class_path)
                .or_else(|| self.tags.get(&cls))
                .ok_or_else(|| self.error_here(format!("no class named '{cls}'")))?;
            let rtag = self.records[id].tag.clone().unwrap_or_else(|| cls.clone());
            let is_ctor = member == cls;
            // S4.2b2: a static-member DIRECT-INIT `T C::m(expr-args);` (e.g.
            // CSTRING/OWL `const TColor TColor::Black(0,0,0);`) — a file-scope
            // object definition, NOT a member-function def. Only when it is not a
            // ctor/dtor, `ty` is a record, and the `(` is followed by EXPRESSIONS
            // (`try_direct_init_args`); `T C::m(types)` stays a member function.
            if !is_ctor
                && !member.starts_with('~')
                && let Some(tag) = self.direct_init_tag(&ty)
                && let Some(args) = self.try_direct_init_args()?
            {
                self.expect_punct(Punct::Semi, ";")?;
                items.push(Item::Global {
                    name: format!("{cls}::{member}"),
                    ty,
                    init: Some(Expr::Call {
                        name: tag,
                        args,
                        loc: Loc::default(),
                    }),
                    is_const: is_const_decl,
                });
                return Ok(());
            }
            let ret = if is_ctor || member.starts_with('~') {
                Type::Void // ctor/dtor: leading token was misread as a type
            } else {
                if let Some(ci) = self.classes.get_mut(&id) {
                    ci.methods.insert(member.clone());
                }
                ty
            };
            if is_ctor && let Some(ci) = self.classes.get_mut(&id) {
                ci.has_ctor = true;
            }
            // S6 (#64): build the symbol from the RESOLVED record's tag so a
            // minted nested class's out-of-line members match its inline
            // registrations (`Streamer$N::Read`, ctor `Streamer$N::Streamer$N`,
            // dtor `Streamer$N::~Streamer$N`). For a non-minted class rtag==cls
            // and member==cls (ctor) so this is byte-identical to the old form.
            let sym_member = if is_ctor {
                rtag.clone()
            } else if member.starts_with('~') {
                format!("~{rtag}")
            } else {
                member.clone()
            };
            let flat_sym = format!("{rtag}::{sym_member}");
            // S4.2h: the declarator above re-entered `decl_specifiers` and cleared
            // `is_inline`; restore the value captured before it so an `inline`
            // out-of-line member def is recognised as droppable-on-demand.
            self.is_inline = decl_is_inline;
            return self.member_def_tail(items, id, flat_sym, ret);
        }

        // S4.2b2: `T name(expr-args);` is a file-scope object DIRECT-INIT, not a
        // function decl — build the same `Global { init: Some(Tag(args)) }` repr
        // as `T name = T(args);`. Only fires for EXPRESSION args (see
        // `try_direct_init_args`); `T f(types)` / `T f()` stay functions.
        if self.is_punct(Punct::LParen)
            && let Some(tag) = self.direct_init_tag(&ty)
            && let Some(args) = self.try_direct_init_args()?
        {
            self.expect_punct(Punct::Semi, ";")?;
            items.push(Item::Global {
                name,
                ty,
                init: Some(Expr::Call {
                    name: tag,
                    args,
                    loc: Loc::default(),
                }),
                is_const: is_const_decl,
            });
            return Ok(());
        }

        if self.is_punct(Punct::LParen) {
            // Function definition or prototype.
            self.advance();
            let (params, variadic) = self.param_list()?;
            self.expect_punct(Punct::RParen, ")")?;
            self.skip_exception_spec(); // `f(...) throw(...)` exception-spec
            self.note_defaults(&name, false);
            if self.eat_punct(Punct::Semi) {
                // Tick 64 (J-13 v1): a variadic *prototype* still needs to
                // teach the codegen that the symbol is variadic — calls to
                // it must marshal FP args into BOTH the positional XMM and
                // GPR slots per Win64 §A.5.1.2. Capture the bit on a
                // synthetic body-less Function via the proto channel.
                if variadic {
                    self.variadic_protos.insert(name.clone());
                }
                // S1b.7 (RED 3): preserve the prototype's typed-parameter
                // shape so `compile_module` can mangle calls to truly-
                // external functions. A subsequent definition with the
                // same name OVERRIDES the proto (codegen's pass 1
                // ignores extern_protos whose name appears in the
                // defined set). Body is left empty; nothing in codegen
                // ever lowers a proto's body.
                self.extern_protos.push(Function {
                    name: name.clone(),
                    ret: ty.clone(),
                    params: params.clone(),
                    body: Vec::new(),
                    const_method: false,
                    virtual_method: false,
                    variadic,
                    // S3: a prototype inside `extern "C" { ... }` has C
                    // linkage; top-level keeps the historical `false`.
                    c_linkage: self.c_linkage,
                    calling_conv: call_conv,
                    inline: false, // S4.2h: prototype — not emitted
                });
                return Ok(()); // prototype: accepted, registered
            }
            // S4 (#27): track this FREE function's locals (params + body decls)
            // in `fn_locals` for the body parse, so a local SHADOWS a same-named
            // enum constant (the `enum seek_dir{…,cur,…}` vs a `cur` loop variable
            // — see the enum-fold guard in `primary`). Member bodies already do
            // this (member_body/ctor/dtor); free functions did not, so a free
            // function's local that collided with an enumerator silently folded to
            // the enumerator's value. `fn_locals` is consulted by `in_class_method`
            // only when `cur_class.is_some()`, so populating it for a free function
            // (cur_class == None) affects nothing but the enum-fold guard. Saved /
            // restored so nested definitions don't leak locals to each other.
            let prev_locals = std::mem::take(&mut self.fn_locals);
            for (pn, _) in &params {
                self.fn_locals.insert(pn.clone());
            }
            let body = self.block()?;
            self.fn_locals = prev_locals;
            // Free functions are never `const`-qualified — the J-1 helper
            // is only invoked at the member-function sites, so a trailing
            // `const` here still hits the existing `expected '{'`
            // diagnostic (no silent acceptance, house style).
            items.push(Item::Func(Function {
                name,
                ret: ty,
                params,
                body,
                const_method: false,
                virtual_method: false,
                variadic,
                // S3: a definition inside `extern "C" { ... }` has C linkage.
                c_linkage: self.c_linkage,
                calling_conv: call_conv,
                // S4.2h: inline iff declared `inline` (captured pre-declarator).
                // A header `inline bool operator==(TPoint, TPoint)` is droppable
                // on demand; a plain C function is a root (always emitted).
                inline: decl_is_inline,
            }));
            return Ok(());
        }

        // One or more global object declarators.
        let was_const = self.is_const; // S4.2#39
        let mut cur_ty = ty;
        // G39 (TAppMutex::NotWIN32s): a MULTI-level qualified static
        // data-member definition (`int TApplication::TAppMutex::NotWIN32s =
        // …;`, OWL APPLICAT.CPP) must be keyed by the RESOLVED record's flat
        // tag — every REFERENCE resolves through the record tag
        // (`TAppMutex::NotWIN32s`), so a verbatim three-level item name never
        // links. Mirror the member-function path above: scoped key
        // (`Outer::Inner`, a minted nested class) first, then the flat
        // innermost tag. Single-level `Tag::member` defs are left verbatim
        // (byte-identical); an unresolvable qualifier is also left verbatim.
        let name = if let Some((class_path, member)) = name.rsplit_once("::")
            && class_path.contains("::")
            && let Some(&id) = self.tags.get(class_path).or_else(|| {
                let cls = class_path
                    .rsplit_once("::")
                    .map(|(_, c)| c)
                    .unwrap_or(class_path);
                self.tags.get(cls)
            }) {
            let rtag = self.records[id].tag.clone().unwrap_or_else(|| {
                class_path
                    .rsplit_once("::")
                    .map(|(_, c)| c)
                    .unwrap_or(class_path)
                    .to_string()
            });
            format!("{rtag}::{member}")
        } else {
            name
        };
        let mut cur_name = name;
        loop {
            // S2e: a qualified static-member definition (`cls::__entries[] =
            // {...}`) is in the class's scope — set `cur_class` so the
            // initializer resolves class-scoped names (member typedefs like OWL's
            // `TMyClass`). Restored after the initializer. Non-qualified globals
            // and statics with no in-scope class leave cur_class untouched.
            let prev_class = self.cur_class;
            if let Some((cpath, _)) = cur_name.rsplit_once("::") {
                let cls = cpath.rsplit_once("::").map(|(_, c)| c).unwrap_or(cpath);
                if let Some(&cid) = self.tags.get(cls) {
                    self.cur_class = Some(cid);
                }
            }
            let (final_ty, mut init) = self.maybe_initializer(cur_ty)?;
            self.cur_class = prev_class;
            // S4.2#39: fold known file-scope `const int` constants inside an
            // AGGREGATE global initializer (`static int a[]={X|Y,...}`), so the
            // array's elements const-evaluate (a scalar `int g=K` init is left
            // untouched — it takes the #29 dynamic-init path, byte-identical).
            if let Some(e) = init.as_mut()
                && matches!(e, Expr::InitList(..))
            {
                substitute_int_consts(e, &self.int_consts);
            }
            // S4.2#39: record this `const int X = <const>` for LATER aggregate
            // inits (the value is a pure map entry — no AST/codegen change).
            if was_const
                && matches!(final_ty, Type::Int { .. })
                && let Some(v) = init.as_ref().and_then(const_eval)
            {
                self.int_consts.insert(cur_name.clone(), v);
            }
            // S4.2#24: `extern T g;` (extern storage, NO initializer) is a
            // cross-TU DECLARATION → ExternGlobal (no local def). `extern T g=v;`
            // (with an initializer) IS a definition, so it stays Global.
            if is_extern_decl && init.is_none() {
                items.push(Item::ExternGlobal {
                    name: cur_name,
                    ty: final_ty,
                });
            } else {
                items.push(Item::Global {
                    name: cur_name,
                    ty: final_ty,
                    init,
                    is_const: is_const_decl,
                });
            }
            if self.eat_punct(Punct::Comma) {
                let (t2, n2) = self.declarator(base.clone())?;
                cur_ty = t2;
                cur_name = n2.ok_or_else(|| self.error_here("expected a name"))?;
            } else {
                break;
            }
        }
        self.expect_punct(Punct::Semi, ";")?;
        Ok(())
    }

    /// C++ §7.5 linkage-specification. Cursor is on `extern`, with a string
    /// literal at `+1` (the caller in `external_declaration` guaranteed this).
    ///
    /// Two forms:
    ///   * **block**:  `extern "C" { declaration-seq }` — each inner
    ///     declaration parses exactly like a top-level one (so prototypes,
    ///     typedefs, `struct` definitions, nested `extern "C"`, … all reuse
    ///     the existing machinery) but acquires the block's linkage;
    ///   * **single**: `extern "C" declaration` — one declaration.
    ///
    /// `"C"` ⇒ C linkage (`_name` mangling); `"C++"` ⇒ C++ linkage; any other
    /// string is accepted leniently as C linkage (real headers only use
    /// `"C"`/`"C++"`). `self.c_linkage` is save/restored so arbitrary nesting
    /// is handled and the top-level default (`false`) is always restored.
    fn linkage_specification(&mut self, items: &mut Vec<Item>) -> PResult<()> {
        self.advance(); // `extern`
        let is_cxx_linkage = match self.kind() {
            TokenKind::Str { bytes, wide } => {
                if *wide {
                    return Err(self.error_here(
                        "a linkage-specification string may not be wide \
                         (L\"...\")",
                    ));
                }
                // C linkage unless the string is exactly "C++".
                bytes.as_slice() == b"C++"
            }
            // The caller already checked `kind_at(1)` is a string.
            _ => unreachable!("linkage_specification: expected a string"),
        };
        self.advance(); // the linkage string

        let saved = self.c_linkage;
        self.c_linkage = !is_cxx_linkage;

        let result = (|| {
            if self.eat_punct(Punct::LBrace) {
                // Block form: parse declarations until the matching `}`.
                while !self.is_punct(Punct::RBrace) && !self.at_eof() {
                    self.external_declaration(items)?;
                }
                self.expect_punct(Punct::RBrace, "}")?;
            } else {
                // Single-declaration form.
                self.external_declaration(items)?;
            }
            Ok(())
        })();

        self.c_linkage = saved;
        result
    }

    /// Out-of-line `Tag::Tag(params){}` / `Tag::~Tag(){}`. Cursor is on the
    /// leading `Tag` identifier (a known class tag, followed by `::`).
    fn out_of_line_ctor_dtor(&mut self, items: &mut Vec<Item>, tag: &str) -> PResult<()> {
        let id = self.tags[tag];
        self.advance(); // tag
        self.expect_punct(Punct::ColonColon, "::")?;
        let is_dtor = self.eat_punct(Punct::Tilde);
        let m = match self.kind() {
            TokenKind::Ident(s) => s.clone(),
            _ => {
                return Err(self.error_here("expected a constructor/destructor name"));
            }
        };
        self.advance();
        if m != tag {
            return Err(self.error_here(format!(
                "'{tag}::{m}' does not name a constructor or destructor"
            )));
        }
        self.expect_punct(Punct::LParen, "(")?;
        let (params, variadic) = if is_dtor {
            self.eat_kw(Keyword::Void); // accept the explicit `~T(void)` form
            (Vec::new(), false)
        } else {
            self.param_list()?
        };
        self.expect_punct(Punct::RParen, ")")?;
        // S4.2x: an out-of-line ctor/dtor definition may carry an exception
        // specification before its body — `string::~string() throw()`,
        // `string::string(...) throw(xalloc)` (pervasive in the RTL/CLASSLIB
        // source). Skip it (mdbcc models EH structurally, not the spec).
        self.skip_exception_spec();
        if !is_dtor {
            self.note_defaults(&format!("{tag}::{tag}"), true);
        }
        let (mangled, mut body) = if is_dtor {
            if let Some(ci) = self.classes.get_mut(&id) {
                ci.has_dtor = true;
            }
            (format!("{tag}::~{tag}"), self.dtor_full_body(id)?)
        } else {
            if let Some(ci) = self.classes.get_mut(&id) {
                ci.has_ctor = true;
            }
            (format!("{tag}::{tag}"), self.ctor_full_body(id, &params)?)
        };
        // W6 (G53): splice class-typed member ctor/dtor calls into THIS
        // definition. The per-class `inject_member_ctor_dtor_calls` pass runs
        // at class-definition END — before an out-of-line ctor/dtor body
        // exists — so members not named in the minit list were never
        // default-constructed (OWL APPLICAT.CPP `TApplication::TApplication`:
        // the `string CmdLine` member's TStringRef stayed NULL and the body's
        // `CmdLine = InitCmdLine` faulted in `string::assign` — railc startup
        // crash, take 9). Same helpers, same splice points as the in-class
        // pass; a class with no class-typed members splices nothing.
        if is_dtor {
            let extra = self.member_dtor_stmts(id);
            if !extra.is_empty() {
                splice_before_base_dtor(&mut body, id, extra);
            }
        } else {
            let minit_names = collect_minit_names(&body);
            let extra = self.class_typed_member_ctor_stmts(id, &minit_names);
            if !extra.is_empty() {
                splice_after_setvptr(&mut body, id, extra);
            }
        }
        let mut full = vec![("this".into(), self.this_ty(id))];
        full.extend(params);
        items.push(Item::Func(Function {
            name: mangled,
            ret: Type::Void,
            params: full,
            body,
            // Ctors/dtors are never const.
            const_method: false,
            virtual_method: false,
            variadic,
            c_linkage: false,
            calling_conv: None,
            inline: false, // S4.2h: out-of-line def — always emitted (root)
        }));
        Ok(())
    }

    /// Parse `(params) [const] [volatile] { body }` for an out-of-line
    /// member and record the lowered free function (`this` prepended) as a
    /// top-level item. Phase J-1: the trailing-cv qualifiers are read after
    /// the `)`; `const` lands on the Function so the codegen mangler can
    /// distinguish const overloads.
    fn member_def_tail(
        &mut self,
        items: &mut Vec<Item>,
        id: usize,
        mangled: String,
        ret: Type,
    ) -> PResult<()> {
        // S4.2h: capture BEFORE `param_list` re-enters `decl_specifiers` (which
        // resets the flag). An out-of-line member defined `inline`
        // (`inline string::string(char c) { p = new TStringRef(c,1); }`,
        // CSTRING.H) is vague-linkage and droppable on-demand.
        let is_inline = self.is_inline;
        self.expect_punct(Punct::LParen, "(")?;
        let (params, variadic) = self.param_list()?;
        self.expect_punct(Punct::RParen, ")")?;
        let is_const_method = self.trailing_cv_qualifiers();
        self.skip_exception_spec(); // `Tag::m(...) throw(...)`
        let (cls, member) = mangled.split_once("::").unwrap_or(("", mangled.as_str()));
        let is_static_member = !member.is_empty()
            && member != cls
            && !member.starts_with('~')
            && self
                .classes
                .get(&id)
                .is_some_and(|ci| ci.is_static_overload(member, &params));
        self.note_defaults(&mangled, !is_static_member);
        // An out-of-line ctor/dtor (flat form `Cls::Cls` / `Cls::~Cls`) needs the
        // member-initializer-list + base-ctor/dtor chaining that the in-class
        // path uses (CSTRING.H `string::outofrange::outofrange() : xmsg(...)`).
        // A plain method just parses its block.
        let body = if !member.is_empty() && member == cls {
            self.ctor_full_body(id, &params)?
        } else if member.starts_with('~') {
            self.dtor_full_body(id)?
        } else if is_static_member {
            self.static_member_body(id, &params)?
        } else {
            self.member_body(id, &params)?
        };
        let virtual_method = !is_static_member
            && !member.is_empty()
            && member != cls
            && (self.virtual_member_definition_declared(&mangled, &params, is_const_method)
                || (member.starts_with('~')
                    && self
                        .records
                        .get(id)
                        .is_some_and(|r| r.vtable.iter().any(|s| s.key == "~"))));
        let mut full = if is_static_member {
            Vec::new()
        } else {
            vec![("this".into(), self.this_ty(id))]
        };
        full.extend(params);
        // Tick 72 (J-13b): variadic member functions are lifted from the
        // J-13 v1 rejection — propagate the variadic bit to the function
        // record (see in-class arm above for the rationale).
        items.push(Item::Func(Function {
            name: mangled,
            ret,
            params: full,
            body,
            const_method: is_const_method,
            virtual_method,
            variadic,
            c_linkage: false,
            calling_conv: None,
            inline: is_inline, // S4.2h: out-of-line member, inline iff declared so
        }));
        Ok(())
    }

    /// Parameter list (cursor is past `(`). `void` alone means none.
    fn param_list(&mut self) -> PResult<(Vec<(String, Type)>, bool)> {
        self.param_defaults = Vec::new();
        if self.is_punct(Punct::RParen) {
            return Ok((Vec::new(), false));
        }
        if self.is_kw(Keyword::Void) && self.kind_at(1) == Some(&TokenKind::Punct(Punct::RParen)) {
            self.advance();
            return Ok((Vec::new(), false));
        }
        let mut params = Vec::new();
        let mut defaults = Vec::new();
        let mut anon = 0;
        let mut variadic = false;
        loop {
            if self.is_punct(Punct::Ellipsis) {
                // Tick 64 (J-13 v1): `...` ends the named-parameter list and
                // marks the function variadic. At least one named parameter
                // is required by C/C++ (the `va_start` macro needs a "last"
                // to anchor against); reject `f(...)` cleanly so the failure
                // is a parse-time error not a codegen surprise.
                self.advance();
                if params.is_empty() {
                    return Err(self.error_here(
                        "a variadic function needs at least one named \
                         parameter before '...' (mdbcc does not support the \
                         C23 `void f(...)` form)",
                    ));
                }
                variadic = true;
                break;
            }
            let base = self.decl_specifiers()?;
            let (ty, name) = self.declarator(base)?;
            let name = name.unwrap_or_else(|| {
                anon += 1;
                format!("$arg{anon}")
            });
            // `int a[]` as a parameter is really `int *a`.
            let ty = match ty {
                Type::Array(e, _) => Type::Ptr(e),
                t => t,
            };
            // Optional default argument: `= <assignment-expr>`.
            let def = if self.eat_punct(Punct::Assign) {
                Some(self.assignment()?)
            } else {
                None
            };
            params.push((name, ty));
            defaults.push(def);
            if !self.eat_punct(Punct::Comma) {
                break;
            }
        }
        self.param_defaults = defaults;
        self.param_types = params.iter().map(|(_, t)| t.clone()).collect();
        Ok((params, variadic))
    }

    /// Phase J-1: consume trailing cv-qualifiers (`const` / `volatile`) on a
    /// member function declarator, between the closing `)` of the parameter
    /// list and the body's `{` (or the terminating `;` for a declaration, or
    /// `= 0` for a pure virtual). Returns `true` iff `const` appeared; the
    /// `volatile` qualifier is **accepted-and-ignored** because mdbcc has no
    /// volatile semantics today (no AST flag, no mangling impact). Both
    /// qualifiers in either order are tolerated.
    ///
    /// House style: the trailing-const flag is only meaningful on
    /// **member functions** — a free function with `int f() const { … }`
    /// is ill-formed C++ but mdbcc's free-function path never calls this
    /// helper, so the qualifier produces the existing `expected '{'`
    /// diagnostic at the free-function site (no silent acceptance).
    fn trailing_cv_qualifiers(&mut self) -> bool {
        let mut is_const = false;
        loop {
            if self.eat_kw(Keyword::Const) {
                is_const = true;
            } else if self.eat_kw(Keyword::Volatile) {
                // Accept-and-ignore: no semantics, no AST, no mangling.
            } else {
                break;
            }
        }
        is_const
    }

    /// Skip an optional function **exception-specification** that follows a
    /// parameter list (and any trailing cv-qualifiers): `throw ( type-list )` or
    /// the empty `throw()`. Borland's RTL/classlib declare these throughout
    /// (EXCEPT.H `void raise() throw(xmsg);`). Parsed and discarded — the
    /// `throw()` empty-spec's terminate-on-violation semantics are deferred
    /// (HLD S4). A `throw` NOT followed by `(` is left untouched: that is a
    /// throw *statement*, not a specification.
    fn skip_exception_spec(&mut self) {
        if self.is_kw(Keyword::Throw) && self.kind_at(1) == Some(&TokenKind::Punct(Punct::LParen)) {
            self.advance(); // throw
            self.advance(); // (
            let mut depth = 1;
            while depth > 0 && !self.at_eof() {
                if self.is_punct(Punct::LParen) {
                    depth += 1;
                } else if self.is_punct(Punct::RParen) {
                    depth -= 1;
                }
                self.advance();
            }
        }
    }

    /// Skip a `friend` declaration inside a class body (the `friend` keyword has
    /// already been consumed). It declares a non-member entity, so it owns no
    /// field/method slot; for parse-acceptance we consume up to the end of the
    /// declaration — a `;` (the prototype form) or a balanced `{ ... }` (an
    /// inline friend-function definition) followed by an optional `;`.
    fn skip_friend_declaration(&mut self) {
        let mut depth = 0i32;
        while !self.at_eof() {
            if self.is_punct(Punct::LBrace) {
                depth += 1;
                self.advance();
            } else if self.is_punct(Punct::RBrace) {
                if depth == 0 {
                    return; // class's own `}` — malformed friend, bail safely
                }
                depth -= 1;
                self.advance();
                if depth == 0 {
                    self.eat_punct(Punct::Semi); // optional `;` after a body
                    return;
                }
            } else if depth == 0 && self.is_punct(Punct::Semi) {
                self.advance();
                return;
            } else {
                self.advance();
            }
        }
    }

    /// `[ "=" initializer ]`, resolving an unsized `char[]` from a string.
    fn maybe_initializer(&mut self, ty: Type) -> PResult<(Type, Option<Expr>)> {
        if !self.eat_punct(Punct::Assign) {
            // Unsized array with no initializer is an error.
            if matches!(&ty, Type::Array(_, 0)) {
                // 0 is our placeholder; only allowed when initialized.
            }
            return Ok((ty, None));
        }
        // String initializer for char arrays / pointers.
        if let TokenKind::Str { bytes, wide } = self.kind() {
            let is_wide = *wide;
            let bytes = bytes.clone();
            self.advance();
            if is_wide {
                // #53: `wchar_t buf[] = L"AB";` / `const wchar_t* p = L"AB";`.
                // Store the UTF-16LE bytes (incl. the 2-byte NUL); an unsized
                // `wchar_t[]` gets its length from the literal (utf16 bytes / 2).
                let u = utf16le_with_nul(&bytes);
                let final_ty = match &ty {
                    Type::Array(e, n) if e.size() == 2 => {
                        let len = if *n == 0 { u.len() / 2 } else { *n };
                        Type::Array(e.clone(), len)
                    }
                    _ => ty.clone(),
                };
                return Ok((final_ty, Some(Expr::WideStr(u))));
            }
            let final_ty = match &ty {
                Type::Array(e, n) if e.size() == 1 => {
                    let len = if *n == 0 { bytes.len() + 1 } else { *n };
                    Type::Array(e.clone(), len)
                }
                _ => ty.clone(),
            };
            return Ok((final_ty, Some(Expr::Str(bytes))));
        }
        // J-9 (tick 57): aggregate (brace) initializer.
        // `int a[3] = {1, 2, 3};`, `Point p = {3, 4};`, nested forms.
        if self.is_punct(Punct::LBrace) {
            let list = self.init_list()?;
            // Resolve unsized array length from list length.
            let final_ty = match &ty {
                Type::Array(e, 0) => {
                    let n = match &list {
                        Expr::InitList(items) => items.len(),
                        _ => 0,
                    };
                    Type::Array(e.clone(), n)
                }
                _ => ty.clone(),
            };
            return Ok((final_ty, Some(list)));
        }
        let e = self.assignment()?;
        Ok((ty, Some(e)))
    }

    /// J-9 (tick 57): parse a brace-enclosed init list (cursor on `{`).
    ///
    /// Grammar: `'{' [ elt { ',' elt } [ ',' ] ] '}'` where `elt` is
    /// either a nested `init_list` (when the next token is `{`) or an
    /// assignment expression. An *empty* list `{}` is parsed (returned
    /// as `InitList(vec![])`) but rejected at codegen until J-9b lifts
    /// the empty-brace path.
    ///
    /// Trailing comma is consumed silently. Nested aggregates are
    /// nested `InitList`s.
    fn init_list(&mut self) -> PResult<Expr> {
        self.expect_punct(Punct::LBrace, "{")?;
        let mut items = Vec::new();
        if !self.is_punct(Punct::RBrace) {
            loop {
                let e = if self.is_punct(Punct::LBrace) {
                    self.init_list()?
                } else {
                    self.assignment()?
                };
                items.push(e);
                if !self.eat_punct(Punct::Comma) {
                    break;
                }
                // Trailing-comma support: `{1,2,3,}` reaches `}` here.
                if self.is_punct(Punct::RBrace) {
                    break;
                }
            }
        }
        self.expect_punct(Punct::RBrace, "}")?;
        Ok(Expr::InitList(items))
    }

    fn block(&mut self) -> PResult<Vec<Stmt>> {
        self.expect_punct(Punct::LBrace, "{")?;
        let mut stmts = Vec::new();
        while !self.eat_punct(Punct::RBrace) {
            if self.at_eof() {
                return Err(self.error_here("expected '}'"));
            }
            // Splice declarations flat so all objects in this block share
            // one scope (gives correct, reverse-order destruction).
            if self.at_decl() {
                stmts.extend(self.local_declaration_list()?);
            } else {
                stmts.push(self.statement()?);
            }
        }
        Ok(stmts)
    }

    // ---- statements -------------------------------------------------------

    /// Consume an inline-assembly construct: `asm { ... }`, `asm ( ... )`,
    /// or a single `asm <instr>` terminated by `;` or end of line.
    fn skip_inline_asm(&mut self) {
        self.advance(); // `asm` / `__asm`
        if self.is_punct(Punct::LBrace) {
            self.advance();
            let mut depth = 1;
            while depth > 0 && !self.at_eof() {
                if self.is_punct(Punct::LBrace) {
                    depth += 1;
                } else if self.is_punct(Punct::RBrace) {
                    depth -= 1;
                }
                self.advance();
            }
        } else if self.is_punct(Punct::LParen) {
            self.advance();
            let mut depth = 1;
            while depth > 0 && !self.at_eof() {
                if self.is_punct(Punct::LParen) {
                    depth += 1;
                } else if self.is_punct(Punct::RParen) {
                    depth -= 1;
                }
                self.advance();
            }
            self.eat_punct(Punct::Semi);
        } else {
            // `asm mov ax, 1` — to `;`, the enclosing `}`, or next line.
            let mut n = 0;
            while !self.at_eof() {
                if self.is_punct(Punct::Semi) {
                    self.advance();
                    break;
                }
                if self.is_punct(Punct::RBrace) {
                    break;
                }
                if n > 0 && self.peek().start_of_line {
                    break;
                }
                self.advance();
                n += 1;
            }
        }
    }

    fn statement(&mut self) -> PResult<Stmt> {
        // Capture the source position of the leading token BEFORE consuming
        // it — J-8 (tick 65) source-loc threading. Used to stamp every
        // Stmt variant constructed in this function.
        let loc = self.loc_here();
        // Inline assembly (`asm`/`__asm`). 16-bit/32-bit x86 asm cannot be
        // honored on the Win64 target, so the block is parsed and dropped.
        if self.is_kw(Keyword::Asm) || self.is_kw(Keyword::Asm2) {
            self.skip_inline_asm();
            return Ok(Stmt::Empty);
        }
        if self.is_punct(Punct::LBrace) {
            return Ok(Stmt::Block(self.block()?, loc));
        }
        if self.eat_punct(Punct::Semi) {
            return Ok(Stmt::Empty);
        }
        // W6 (G48): `#pragma startup` is valid ANYWHERE in Borland C — the
        // RTL puts it INSIDE the registered function's own body (HEAP.C:203,
        // first statement of `_init_heap`). Same pp splice as the top-level
        // arm (external_declaration); record and emit no statement.
        if matches!(self.kind(), TokenKind::Ident(n) if n == "__mdbcc_startup__") {
            self.advance();
            let fname = match &self.advance().kind {
                TokenKind::Ident(n) => n.clone(),
                _ => return Err(self.error_here("#pragma startup expects a function name")),
            };
            let prio = match &self.advance().kind {
                TokenKind::Int { value, .. } => *value as u32,
                _ => return Err(self.error_here("#pragma startup expects a priority")),
            };
            self.expect_punct(Punct::Semi, ";")?;
            self.startup_fns.push((fname, prio));
            return Ok(Stmt::Empty);
        }
        // S4.2m: a labeled statement `name:` (a goto target). An identifier
        // immediately followed by a SINGLE `:` — not `::` (a qualified name,
        // tokenised as one `ColonColon`) and not `?:` (after `name` would come
        // `?`). Emitted as a flat marker like case/default; the labeled
        // statement follows as the next statement in the enclosing block.
        if let TokenKind::Ident(name) = self.kind()
            && self.kind_at(1) == Some(&TokenKind::Punct(Punct::Colon))
        {
            let name = name.clone();
            self.advance(); // name
            self.advance(); // ':'
            return Ok(Stmt::Label(name, loc));
        }
        if self.at_decl() {
            return self.local_declaration();
        }
        if self.eat_kw(Keyword::Return) {
            if self.eat_punct(Punct::Semi) {
                return Ok(Stmt::Return(None, loc));
            }
            let e = self.expr()?;
            self.expect_punct(Punct::Semi, ";")?;
            return Ok(Stmt::Return(Some(e), loc));
        }
        if self.eat_kw(Keyword::If) {
            return self.if_statement(loc);
        }
        if self.eat_kw(Keyword::While) {
            self.expect_punct(Punct::LParen, "(")?;
            let cond = self.expr()?;
            self.expect_punct(Punct::RParen, ")")?;
            let body = Box::new(self.statement()?);
            return Ok(Stmt::While { cond, body, loc });
        }
        // S4.2k: `do body while (cond);` — body parses first, then the trailing
        // `while (cond);`. The body runs once before the test (codegen lowers it
        // test-last); `continue` re-tests, `break` exits.
        if self.eat_kw(Keyword::Do) {
            let body = Box::new(self.statement()?);
            if !self.eat_kw(Keyword::While) {
                return Err(self.error_here("expected 'while' after a do-statement body"));
            }
            self.expect_punct(Punct::LParen, "(")?;
            let cond = self.expr()?;
            self.expect_punct(Punct::RParen, ")")?;
            self.expect_punct(Punct::Semi, ";")?;
            return Ok(Stmt::DoWhile { cond, body, loc });
        }
        if self.eat_kw(Keyword::For) {
            return self.for_statement(loc);
        }
        // S3: `switch`/`case`/`default`/`break`/`continue`. Case and default
        // are parsed as flat label-marker statements inside the switch
        // block; codegen's `Stmt::Switch` arm binds them to jump targets.
        if self.eat_kw(Keyword::Switch) {
            self.expect_punct(Punct::LParen, "(")?;
            let scrutinee = self.expr()?;
            self.expect_punct(Punct::RParen, ")")?;
            let body = Box::new(self.statement()?);
            return Ok(Stmt::Switch {
                scrutinee,
                body,
                loc,
            });
        }
        if self.eat_kw(Keyword::Case) {
            // A `case`'s constant-expression is a conditional-expression
            // (it may itself contain a `?:`, whose inner `:` is consumed by
            // the expression parser); the trailing `:` is the label.
            let value = self.expr()?;
            self.expect_punct(Punct::Colon, ":")?;
            return Ok(Stmt::Case { value, loc });
        }
        if self.eat_kw(Keyword::Default) {
            self.expect_punct(Punct::Colon, ":")?;
            return Ok(Stmt::Default(loc));
        }
        if self.eat_kw(Keyword::Break) {
            self.expect_punct(Punct::Semi, ";")?;
            return Ok(Stmt::Break(loc));
        }
        if self.eat_kw(Keyword::Continue) {
            self.expect_punct(Punct::Semi, ";")?;
            return Ok(Stmt::Continue(loc));
        }
        // S4.2m: `goto name;` — an unconditional jump to a label.
        if self.eat_kw(Keyword::Goto) {
            let name = match self.kind() {
                TokenKind::Ident(s) => s.clone(),
                _ => return Err(self.error_here("expected a label name after 'goto'")),
            };
            self.advance();
            self.expect_punct(Punct::Semi, ";")?;
            return Ok(Stmt::Goto(name, loc));
        }
        // Phase H3: exception syntax — parse-only.
        // `throw [<expr>];` and `try { … } catch (…) { … } …`. Codegen
        // rejects with a Phase-H4-tagged diagnostic until H4a wires the
        // SEH runtime; we ALWAYS parse so Phase-I fixtures using these
        // keywords don't fall over with a syntax error.
        if self.eat_kw(Keyword::Throw) {
            return self.throw_statement(loc);
        }
        if self.eat_kw(Keyword::Try) {
            return self.try_statement(loc);
        }
        // A stray `catch` outside any `try` is a programming error.
        // Catch its (terse) lexical form here rather than producing a
        // confusing "expected ';'" further down the expression parser.
        if self.is_kw(Keyword::Catch) {
            return Err(self.error_here("'catch' without a preceding 'try'"));
        }
        let e = self.expr()?;
        self.expect_punct(Punct::Semi, ";")?;
        Ok(Stmt::ExprStmt(e, loc))
    }

    /// Statement-position local declaration. Multiple declarators collapse
    /// to a `Block` only here (body position); inside a real block the
    /// caller splices [`local_declaration_list`] flat so the objects share
    /// the enclosing block's scope (correct destructor timing).
    fn local_declaration(&mut self) -> PResult<Stmt> {
        let loc = self.loc_here();
        let mut v = self.local_declaration_list()?;
        Ok(match v.len() {
            0 => Stmt::Empty,
            1 => v.pop().unwrap(),
            _ => Stmt::Block(v, loc),
        })
    }

    /// `decl-specifiers declarator [= init] { , declarator [= init] } ;`
    /// — yields the `Decl`s (and any auto constructor-call statements).
    fn local_declaration_list(&mut self) -> PResult<Vec<Stmt>> {
        let decl_loc = self.loc_here();
        let base = self.decl_specifiers()?;
        let is_typedef = self.is_typedef;
        // S4.2o: capture `static` NOW — `maybe_initializer` below may re-enter
        // `decl_specifiers` (e.g. a functional-cast init) and clear the flag.
        let is_static = self.is_static;
        // S6 (#64-adjacent): capture `const` too, before the initializer parse
        // re-enters `decl_specifiers`. A `const int X = <const>` local feeds the
        // array-bound / enum const-folder (`local_int_consts`).
        let is_const = self.is_const;
        if self.eat_punct(Punct::Semi) {
            // G19: a declarator-less ANONYMOUS union/struct (`union { A a; B b;
            // };`) as a LOCAL promotes its members into the enclosing function
            // scope. Emit a hidden local of the anon record and register each
            // member name -> the hidden local, so `primary` rewrites a bare `a`
            // to `$anonu.N.a`. (OWL DIB.CPP's bitmap-header union.)
            if let Type::Record { id, .. } = &base
                && self.records[*id].tag.is_none()
                && !self.records[*id].fields.is_empty()
            {
                let hidden = format!("$anonu.{}", self.anonu_counter);
                self.anonu_counter += 1;
                let members: Vec<String> = self.records[*id]
                    .fields
                    .iter()
                    .map(|f| f.name.clone())
                    .filter(|n| !n.starts_with("$anon"))
                    .collect();
                for m in members {
                    self.anonu_promotions.insert(m, hidden.clone());
                }
                self.fn_locals.insert(hidden.clone());
                self.local_var_types.insert(hidden.clone(), base.clone());
                return Ok(vec![Stmt::Decl {
                    name: hidden,
                    ty: base,
                    init: None,
                    loc: decl_loc,
                    is_static: false,
                }]);
            }
            return Ok(Vec::new()); // local type declaration only
        }
        if is_typedef {
            self.register_typedefs(base)?;
            self.expect_punct(Punct::Semi, ";")?;
            return Ok(Vec::new());
        }
        let mut decls = Vec::new();
        loop {
            let (ty, name) = self.declarator(base.clone())?;
            let name = name.ok_or_else(|| self.error_here("expected a name"))?;
            // S6: block-scope FUNCTION DECLARATION — a local forward-declaration
            // of a (usually file-scope) function, e.g. `void CacheFlush(uint32 id);`
            // (WINDOW.CPP:273; defined at :756, called at :274). The declarator left
            // the `(param-list)` unconsumed (the flat path defers function
            // declarators to `external_declaration`, which never runs in statement
            // position). Distinguish from scalar direct-init `int x(5);` (the
            // most-vexing-parse): a PARAMETER list starts with a TYPE, an
            // initializer with an EXPRESSION. Restrict to NON-record types — a
            // `Tag v(args)` ctor-call is handled just below — and to the sole
            // declarator. Parse-and-DISCARD the prototype: mdbcc parses the whole
            // TU before codegen, so the call resolves via the file-scope definition
            // (or as an extern call if defined in another TU).
            if decls.is_empty()
                && self.is_punct(Punct::LParen)
                && !matches!(ty, Type::Record { .. } | Type::TemplateParam(_))
                && self.kind_at(1).is_some_and(|k| self.kind_starts_type(k))
            {
                let _proto_params = self.param_type_list()?;
                self.expect_punct(Punct::Semi, ";")?;
                return Ok(Vec::new());
            }
            // S4 (#27): record every local declaration in `fn_locals` (member AND
            // free functions — see the free-function body setup above) so a local
            // SHADOWS a same-named enum constant in `primary`. Member-only before;
            // `in_class_method` ignores `fn_locals` when `cur_class == None`, so
            // tracking free-function locals here is otherwise inert.
            self.fn_locals.insert(name.clone());
            // `Tag v(args);` constructor-call declarator (class types only).
            let mut ctor_args: Option<Vec<Expr>> = None;
            let decl_ty;
            let mut has_init = false;
            // Direct-initialization `Type name(args)`. Also accept a DEPENDENT
            // (TemplateParam) type — `Base::Streamer strmr(base);` in CLASSLIB's
            // `WriteBaseObject` function template — so the (eager-parsed) body
            // parses; codegen of a TemplateParam-typed local errors cleanly at any
            // instantiation (real instantiation needs fn-template token-replay).
            if self.is_punct(Punct::LParen)
                && matches!(ty, Type::Record { .. } | Type::TemplateParam(_))
            {
                self.advance();
                let mut a = Vec::new();
                if !self.is_punct(Punct::RParen) {
                    loop {
                        a.push(self.assignment()?);
                        if !self.eat_punct(Punct::Comma) {
                            break;
                        }
                    }
                }
                self.expect_punct(Punct::RParen, ")")?;
                ctor_args = Some(a);
                decl_ty = ty.clone();
                decls.push(Stmt::Decl {
                    name: name.clone(),
                    ty,
                    init: None,
                    loc: decl_loc,
                    is_static,
                });
            } else {
                let (final_ty, init) = self.maybe_initializer(ty)?;
                decl_ty = final_ty.clone();
                has_init = init.is_some();
                decls.push(Stmt::Decl {
                    name: name.clone(),
                    ty: final_ty,
                    init,
                    loc: decl_loc,
                    is_static,
                });
            }
            // S5: record the local's FINAL type (unsized `char[]` already resolved
            // by `maybe_initializer`) so a later `sizeof(thisLocal)` in a constant
            // context folds (OWL/MODULE.CPP `char buf[sizeof(tmpl)+8]`).
            self.local_var_types.insert(name.clone(), decl_ty.clone());
            // S6 (#64-adjacent): a `const int X = <constant>` local — record its
            // value so a later constant context (`arr[X]`, enum, bit-field width)
            // folds. Only integer-typed, const-qualified locals with a
            // const-evaluable initializer (file-scope int_consts already
            // substituted via `substitute_int_consts` at use). Gated by
            // `fn_locals` at the use site, so a stale same-named entry is inert.
            if is_const
                && matches!(decl_ty, Type::Int { .. })
                && let Some(d) = decls.last()
                && let Stmt::Decl { init: Some(e), .. } = d
            {
                let mut folded = e.clone();
                substitute_int_consts(&mut folded, &self.int_consts);
                substitute_int_consts(&mut folded, &self.local_int_consts);
                if let Some(v) = const_eval(&folded) {
                    self.local_int_consts.insert(name.clone(), v);
                }
            }
            // Auto-invoke the constructor for class objects.
            //
            // Tick 58 (J-10): emit as a `MethodCall` (not `Call`). For a non-
            // overloaded ctor this is byte-identical (the MethodCall arm in
            // `gen_expr` routes through `emit_call(mangled, None, [&a, args],
            // None)`, which is exactly what the prior `Call` path did via
            // `gen_call_with_lead`'s fall-through). For an overloaded ctor it
            // enables real overload resolution through `method_target`, so
            // `Foo a;` in a class with both `Foo()` and `Foo(const Foo&)`
            // picks the default ctor (the resolver compares against
            // candidate params that already exclude the implicit `this`,
            // so the prior `Call` shape's leading `&a` arg defeated
            // resolution).
            //
            // Tick 58: SKIP the auto-invoke when the declaration carries an
            // `= initializer` (i.e. `Foo r = some_expr;`). The initialiser
            // already populates the storage (struct copy in `Stmt::Decl`'s
            // record arm); running the default ctor afterwards would
            // overwrite the freshly-initialised object with zeros. Required
            // to make `Foo r = make_foo();` (HiddenPtr-return through copy
            // ctor on the caller's buffer) work correctly. The `Tag v(args)`
            // explicit-args form is unaffected (no `=`, so `ctor_args` is
            // `Some(_)`).
            if let Type::Record { id, .. } = decl_ty
                && let Some(ci) = self.classes.get(&id)
                && ci.has_ctor
                && !has_init
            {
                let tag = ci.tag.clone();
                let args = ctor_args.take().unwrap_or_default();
                // S6 (G1 Stage-3): set up the shared virtual base(s) (vbptrs +
                // default vbase construction) BEFORE the most-derived ctor, so
                // its base-ctor chain can reach the vbase via the vbptr. No-op
                // for any class without virtual bases (byte-identical).
                for s in self.vbase_init_stmts(&name, id, decl_loc) {
                    decls.push(s);
                }
                decls.push(Stmt::ExprStmt(
                    Expr::MethodCall {
                        recv: Box::new(Expr::Var(name.clone(), decl_loc)),
                        name: tag,
                        args,
                        loc: decl_loc,
                    },
                    decl_loc,
                ));
            }
            // G13: a DEPENDENT direct-init `Base::Inner n(args)` inside a
            // function-template body (CLASSLIB's `WriteBaseObject<Base>`'s
            // `Base::Streamer strmr(base);`). The ctor's class tag is unknown
            // until instantiation, so emit a MethodCall whose name is a sentinel
            // encoding the dependent type (`$depctor$Base::Inner`); the
            // monomorphiser resolves it to the concrete nested record's tag once
            // `Base` is bound (G13 in `template.rs`). Only the explicit-args form
            // (`strmr(base)`, `ctor_args` is `Some`) — a default-init dependent
            // local needs no synthesised call here.
            if let Type::TemplateParam(dep) = &decl_ty
                && let Some(args) = ctor_args.take()
            {
                decls.push(Stmt::ExprStmt(
                    Expr::MethodCall {
                        recv: Box::new(Expr::Var(name.clone(), decl_loc)),
                        name: format!("$depctor${dep}"),
                        args,
                        loc: decl_loc,
                    },
                    decl_loc,
                ));
            }
            if !self.eat_punct(Punct::Comma) {
                break;
            }
        }
        self.expect_punct(Punct::Semi, ";")?;
        Ok(decls)
    }

    fn if_statement(&mut self, loc: Loc) -> PResult<Stmt> {
        self.expect_punct(Punct::LParen, "(")?;
        let cond = self.expr()?;
        self.expect_punct(Punct::RParen, ")")?;
        let then = Box::new(self.statement()?);
        let els = if self.eat_kw(Keyword::Else) {
            Some(Box::new(self.statement()?))
        } else {
            None
        };
        Ok(Stmt::If {
            cond,
            then,
            els,
            loc,
        })
    }

    fn for_statement(&mut self, loc: Loc) -> PResult<Stmt> {
        self.expect_punct(Punct::LParen, "(")?;
        let init = if self.eat_punct(Punct::Semi) {
            None
        } else if self.at_decl() {
            Some(Box::new(self.local_declaration()?))
        } else {
            let init_loc = self.loc_here();
            let e = self.expr()?;
            self.expect_punct(Punct::Semi, ";")?;
            Some(Box::new(Stmt::ExprStmt(e, init_loc)))
        };
        let cond = if self.is_punct(Punct::Semi) {
            None
        } else {
            Some(self.expr()?)
        };
        self.expect_punct(Punct::Semi, ";")?;
        let step = if self.is_punct(Punct::RParen) {
            None
        } else {
            Some(self.expr()?)
        };
        self.expect_punct(Punct::RParen, ")")?;
        let body = Box::new(self.statement()?);
        Ok(Stmt::For {
            init,
            cond,
            step,
            body,
            loc,
        })
    }

    // ---- exceptions (parse-only — Phase H3) -------------------------------

    /// `throw [<expr>] ;` — the `throw` keyword has already been eaten.
    /// A bare `throw;` is a rethrow (`Stmt::Throw(None, _)`); H3 doesn't
    /// validate it's inside a `catch` (that's a runtime concern deferred
    /// to H4a). Any expression form is permitted at parse time.
    fn throw_statement(&mut self, loc: Loc) -> PResult<Stmt> {
        if self.eat_punct(Punct::Semi) {
            return Ok(Stmt::Throw(None, loc));
        }
        let e = self.expr()?;
        self.expect_punct(Punct::Semi, ";")?;
        Ok(Stmt::Throw(Some(e), loc))
    }

    /// `try { body } catch (…) { … } …` — the `try` keyword has already
    /// been eaten. A `try` MUST be followed by at least one `catch` (per
    /// the grammar); 0 handlers is a parse error to keep the diagnostic
    /// close to the source.
    fn try_statement(&mut self, loc: Loc) -> PResult<Stmt> {
        let body = self.block()?;
        if !self.is_kw(Keyword::Catch) {
            return Err(self.error_here("expected 'catch' after 'try' block"));
        }
        let mut catches = Vec::new();
        while self.is_kw(Keyword::Catch) {
            catches.push(self.catch_clause()?);
        }
        Ok(Stmt::Try { body, catches, loc })
    }

    /// `catch ( ... ) { … }` (catch-all) or
    /// `catch ( type-id [name] ) { … }` (typed). The leading `catch`
    /// is consumed here (caller has confirmed via [`is_kw`]).
    fn catch_clause(&mut self) -> PResult<CatchClause> {
        debug_assert!(self.is_kw(Keyword::Catch));
        self.advance(); // 'catch'
        self.expect_punct(Punct::LParen, "(")?;
        let kind = if self.eat_punct(Punct::Ellipsis) {
            CatchKind::All
        } else {
            // `catch (T)` / `catch (T name)` — accept any decl-spec
            // sequence with an optional declarator. Reuses the same
            // pair of helpers function parameters and casts use, so any
            // type the rest of the language can name (incl. `T&` / `T*`
            // / qualified `const T*`) is accepted by H3.
            let base = self.decl_specifiers()?;
            let (ty, name) = self.declarator(base)?;
            // `T[]` in a catch is really `T*`, mirroring `param_list`.
            let ty = match ty {
                Type::Array(e, _) => Type::Ptr(e),
                t => t,
            };
            CatchKind::Typed { ty, name }
        };
        self.expect_punct(Punct::RParen, ")")?;
        let body = self.block()?;
        Ok(CatchClause { kind, body })
    }

    // ---- expressions ------------------------------------------------------

    fn expr(&mut self) -> PResult<Expr> {
        // S4.2l: the comma operator — `a, b, c`. Lowest precedence, left-
        // associative, below assignment. Only `expr()` (the full-expression
        // contexts: statements, conditions, for-init/step, parenthesised
        // groups, return, ternary-middle) parses it; argument/initialiser lists
        // call `assignment()` directly, where commas remain separators.
        // Byte-identical for comma-free expressions (the loop never fires).
        let mut e = self.assignment()?;
        while self.is_punct(Punct::Comma) {
            let loc = self.loc_here();
            self.advance(); // ','
            let rhs = self.assignment()?;
            e = Expr::Binary {
                op: BinOp::Comma,
                lhs: Box::new(e),
                rhs: Box::new(rhs),
                loc,
            };
        }
        Ok(e)
    }

    fn assignment(&mut self) -> PResult<Expr> {
        let lhs = self.conditional()?;
        let op = match self.kind() {
            TokenKind::Punct(Punct::Assign) => None,
            TokenKind::Punct(Punct::PlusEq) => Some(BinOp::Add),
            TokenKind::Punct(Punct::MinusEq) => Some(BinOp::Sub),
            TokenKind::Punct(Punct::StarEq) => Some(BinOp::Mul),
            TokenKind::Punct(Punct::SlashEq) => Some(BinOp::Div),
            TokenKind::Punct(Punct::PercentEq) => Some(BinOp::Mod),
            TokenKind::Punct(Punct::AmpEq) => Some(BinOp::BitAnd),
            TokenKind::Punct(Punct::PipeEq) => Some(BinOp::BitOr),
            TokenKind::Punct(Punct::CaretEq) => Some(BinOp::BitXor),
            TokenKind::Punct(Punct::ShlEq) => Some(BinOp::Shl),
            TokenKind::Punct(Punct::ShrEq) => Some(BinOp::Shr),
            _ => return Ok(lhs),
        };
        // Capture loc at the assignment operator BEFORE consuming so the
        // diagnostic points at `=` / `+=` / etc., not at the rhs's first
        // token (J-8b, tick 74).
        let assign_loc = self.loc_here();
        self.advance(); // the assignment operator
        let rhs = self.assignment()?; // right-associative
        let value = match op {
            None => rhs,
            // a OP= b  ==>  a = a OP b  (lvalue is re-evaluated; acceptable
            // for the side-effect-free lvalues old code uses here).
            Some(op) => Expr::Binary {
                op,
                lhs: Box::new(lhs.clone()),
                rhs: Box::new(rhs),
                loc: assign_loc,
            },
        };
        Ok(Expr::Assign {
            lhs: Box::new(lhs),
            rhs: Box::new(value),
            loc: assign_loc,
        })
    }

    fn conditional(&mut self) -> PResult<Expr> {
        let c = self.logical_or()?;
        if self.eat_punct(Punct::Question) {
            let then = self.expr()?;
            self.expect_punct(Punct::Colon, ":")?;
            let els = self.conditional()?;
            return Ok(Expr::Cond {
                cond: Box::new(c),
                then: Box::new(then),
                els: Box::new(els),
            });
        }
        Ok(c)
    }

    fn binary_level(
        &mut self,
        ops: &[(Punct, BinOp)],
        next: fn(&mut Self) -> PResult<Expr>,
    ) -> PResult<Expr> {
        let mut lhs = next(self)?;
        'outer: loop {
            for &(p, op) in ops {
                if self.is_punct(p) {
                    // J-8b (tick 74): capture the operator token's position
                    // BEFORE consuming so a "no overloaded operator@ for T"
                    // diagnostic points at the operator, not the rhs.
                    let op_loc = self.loc_here();
                    self.advance();
                    let rhs = next(self)?;
                    lhs = Expr::Binary {
                        op,
                        lhs: Box::new(lhs),
                        rhs: Box::new(rhs),
                        loc: op_loc,
                    };
                    continue 'outer;
                }
            }
            break;
        }
        Ok(lhs)
    }

    fn logical_or(&mut self) -> PResult<Expr> {
        self.binary_level(&[(Punct::OrOr, BinOp::LOr)], Self::logical_and)
    }
    fn logical_and(&mut self) -> PResult<Expr> {
        self.binary_level(&[(Punct::AndAnd, BinOp::LAnd)], Self::bit_or)
    }
    fn bit_or(&mut self) -> PResult<Expr> {
        self.binary_level(&[(Punct::Pipe, BinOp::BitOr)], Self::bit_xor)
    }
    fn bit_xor(&mut self) -> PResult<Expr> {
        self.binary_level(&[(Punct::Caret, BinOp::BitXor)], Self::bit_and)
    }
    fn bit_and(&mut self) -> PResult<Expr> {
        self.binary_level(&[(Punct::Amp, BinOp::BitAnd)], Self::equality)
    }
    fn equality(&mut self) -> PResult<Expr> {
        self.binary_level(
            &[(Punct::EqEq, BinOp::Eq), (Punct::Ne, BinOp::Ne)],
            Self::relational,
        )
    }
    fn relational(&mut self) -> PResult<Expr> {
        self.binary_level(
            &[
                (Punct::Lt, BinOp::Lt),
                (Punct::Le, BinOp::Le),
                (Punct::Gt, BinOp::Gt),
                (Punct::Ge, BinOp::Ge),
            ],
            Self::shift,
        )
    }
    fn shift(&mut self) -> PResult<Expr> {
        self.binary_level(
            &[(Punct::Shl, BinOp::Shl), (Punct::Shr, BinOp::Shr)],
            Self::additive,
        )
    }
    fn additive(&mut self) -> PResult<Expr> {
        self.binary_level(
            &[(Punct::Plus, BinOp::Add), (Punct::Minus, BinOp::Sub)],
            Self::multiplicative,
        )
    }
    fn multiplicative(&mut self) -> PResult<Expr> {
        self.binary_level(
            &[
                (Punct::Star, BinOp::Mul),
                (Punct::Slash, BinOp::Div),
                (Punct::Percent, BinOp::Mod),
            ],
            Self::unary,
        )
    }

    fn unary(&mut self) -> PResult<Expr> {
        // Prefix ++ / --
        if self.is_punct(Punct::Inc) || self.is_punct(Punct::Dec) {
            let inc = self.is_punct(Punct::Inc);
            self.advance();
            let target = self.unary()?;
            return Ok(Expr::IncDec {
                inc,
                pre: true,
                target: Box::new(target),
            });
        }
        // C++ named casts `kind < type > ( expr )`. `static_cast` /
        // `const_cast` / `reinterpret_cast` lower to a C-style cast — exactly
        // what `Expr::Cast` models for the scalar/pointer/bit cases these are
        // used for (osl/defs.h `static_cast<bool>(t)` in the `ToBool` template,
        // and throughout the C++ headers). `dynamic_cast` is deliberately NOT
        // accepted here — its run-time downcast semantics are RTTI (S4.5);
        // treating it as a plain cast would silently miscompile a real downcast.
        if matches!(
            self.kind(),
            TokenKind::Keyword(Keyword::StaticCast | Keyword::ConstCast | Keyword::ReinterpretCast)
        ) {
            self.advance(); // the cast keyword
            self.expect_punct(Punct::Lt, "<")?;
            let ty = self.type_name()?;
            self.expect_punct(Punct::Gt, ">")?;
            self.expect_punct(Punct::LParen, "(")?;
            let e = self.expr()?;
            self.expect_punct(Punct::RParen, ")")?;
            // A named cast is a postfix-expression: its result may be chained
            // (`static_cast<T*>(p)->m()`, `static_cast<T*>(p)[i]`).
            let cast = Expr::Cast {
                ty,
                expr: Box::new(e),
            };
            return self.postfix_tail(cast);
        }
        // `dynamic_cast` is deliberately rejected with a SPECIFIC message
        // rather than the generic "expected an expression": its run-time
        // checked-downcast semantics (yield 0 / throw on a type mismatch)
        // require RTTI, which mdbcc does not model yet (S4.5). Lowering it to
        // a plain pointer cast would silently miscompile a *failing* downcast
        // (a non-null pointer where the program expects 0). This is the OWL
        // `TYPESAFE_DOWNCAST` macro (CLASSLIB/DEFS.H); the honest error names
        // the blocker instead of leaving a cryptic parse failure.
        if matches!(self.kind(), TokenKind::Keyword(Keyword::DynamicCast)) {
            // S4.5: `dynamic_cast<T*>(e)` — a checked downcast. Parsed to
            // `Expr::DynamicCast`; codegen walks e's runtime type (RTTI
            // registry) and yields e (single-inheritance, base@0) on a match,
            // else null. This is OWL's `TYPESAFE_DOWNCAST` (CLASSLIB/DEFS.H).
            self.advance(); // `dynamic_cast`
            self.expect_punct(Punct::Lt, "<")?;
            let ty = self.type_name()?;
            self.expect_punct(Punct::Gt, ">")?;
            self.expect_punct(Punct::LParen, "(")?;
            let e = self.expr()?;
            self.expect_punct(Punct::RParen, ")")?;
            self.saw_dynamic_cast = true; // S4.5: checked-downcast marker
            let dc = Expr::DynamicCast {
                ty,
                expr: Box::new(e),
            };
            return self.postfix_tail(dc);
        }
        // S4.2e / S6 minimal RTTI: the `typeid ( expr | type )` operator. The
        // operand is CAPTURED (was dropped): a type-id `typeid(int)` is wrapped
        // in a synthetic `Cast{ty, 0}` (only its type is ever read), an
        // expression `typeid(*this)` is kept verbatim. `typeid(X).name()` then
        // lowers to a string of X's static type name in codegen — the only form
        // the BC45 corpus uses (APPLICAT/DIALOG/WINDOW catch handlers +
        // IMPLEMENT_STREAMABLE's `typeid(cls).name()` registry key).
        if self.is_kw(Keyword::Typeid) {
            let tloc = self.loc_here();
            self.advance(); // `typeid`
            self.expect_punct(Punct::LParen, "(")?;
            let operand = if self.kind_starts_type(self.kind()) {
                let ty = self.type_name()?;
                Expr::Cast {
                    ty,
                    expr: Box::new(Expr::Int(0)),
                }
            } else {
                self.expr()?
            };
            self.expect_punct(Punct::RParen, ")")?;
            return self.postfix_tail(Expr::Typeid(Box::new(operand), tloc));
        }
        // S4.2e: a functional cast to a BUILT-IN type — `long(expr)`, `int(x)`
        // (CLASSLIB's `return long(Width() * Height())`). mdbcc already handles
        // the `Ident(expr)` (typedef/tag) functional cast in `primary`; this adds
        // the scalar-keyword form. A leading scalar type-keyword in expression
        // position can only begin a functional cast (a declaration is routed away
        // by `at_decl`), so parse the type then `( expr )` and chain as postfix.
        if matches!(
            self.kind(),
            TokenKind::Keyword(
                Keyword::Void
                    | Keyword::Char
                    | Keyword::Short
                    | Keyword::Int
                    | Keyword::Long
                    | Keyword::Signed
                    | Keyword::Unsigned
                    | Keyword::Float
                    | Keyword::Double
                    | Keyword::Int8
                    | Keyword::Int16
                    | Keyword::Int32
                    | Keyword::Int64
            )
        ) {
            let ty = self.decl_specifiers()?;
            self.expect_punct(Punct::LParen, "(")?;
            let e = self.expr()?;
            self.expect_punct(Punct::RParen, ")")?;
            return self.postfix_tail(Expr::Cast {
                ty,
                expr: Box::new(e),
            });
        }
        if self.is_kw(Keyword::New) {
            let new_loc = self.loc_here();
            self.advance();
            // S4.2(a): an optional placement-argument list precedes the type
            // (`new (a, b) T`). It is distinguished from the parenthesised-
            // TYPE form `new (T)` by the token after `(`: a type-start ⇒ the
            // parens hold the type; otherwise they hold a placement-arg
            // expression list (no backtracking — sufficient for the BIDS
            // containers' `new(*this) T[n]`). The type itself is then parsed
            // by `new_type_prefix` (decl-specifiers + `*`/`&`), the bracketed
            // array suffix held back so a runtime `new T[i]` is accepted.
            let mut placement = Vec::new();
            let ty = if self.is_punct(Punct::LParen)
                && self.kind_at(1).is_some_and(|k| self.kind_starts_type(k))
            {
                // `new ( Type )` — type in parentheses.
                self.advance(); // (
                let t = self.new_type_prefix()?;
                self.expect_punct(Punct::RParen, ")")?;
                t
            } else {
                if self.eat_punct(Punct::LParen) {
                    if !self.is_punct(Punct::RParen) {
                        loop {
                            placement.push(self.assignment()?);
                            if !self.eat_punct(Punct::Comma) {
                                break;
                            }
                        }
                    }
                    self.expect_punct(Punct::RParen, ")")?;
                }
                self.new_type_prefix()?
            };
            if self.eat_punct(Punct::LBracket) {
                // `new T[n]` — `n` is any int-valued expression. Reject the
                // multi-dim `new T[m][n]` form here so the silent bug from
                // §H6 (the const-only declarator) is not just relocated.
                let count = self.expr()?;
                self.expect_punct(Punct::RBracket, "]")?;
                if self.is_punct(Punct::LBracket) {
                    return Err(self.error_here(
                        "multi-dimensional 'new T[m][n]' is not yet \
                         supported (Phase H-future)",
                    ));
                }
                if self.eat_punct(Punct::LParen) {
                    return Err(self.error_here(
                        "'new T[n](init)' array-with-initializer is not \
                         yet supported (Phase H-future)",
                    ));
                }
                return Ok(Expr::NewArray {
                    ty,
                    count: Box::new(count),
                    placement,
                    loc: new_loc,
                });
            }
            let mut args = Vec::new();
            if self.eat_punct(Punct::LParen) {
                if !self.is_punct(Punct::RParen) {
                    loop {
                        args.push(self.assignment()?);
                        if !self.eat_punct(Punct::Comma) {
                            break;
                        }
                    }
                }
                self.expect_punct(Punct::RParen, ")")?;
            }
            // A (non-array) new-expression can be the receiver of a postfix
            // chain — the OWL idiom `new TEdit(this, id)->SetValidator(v)` creates
            // a child window and immediately configures it. Parse `->`/`.`/`()`/
            // `[]` on the result. Byte-safe: with no trailing postfix token
            // `postfix_tail` returns the `Expr::New` unchanged; a new-expression
            // FOLLOWED by `->`/`.` previously errored ("expected ';'"), so no
            // existing parse is altered. Array-new keeps its early return (a
            // postfix `[i]` would be ambiguous with the `[n]` size suffix).
            return self.postfix_tail(Expr::New {
                ty,
                args,
                placement,
            });
        }
        if self.is_kw(Keyword::Delete) {
            self.advance();
            // Phase H6: `delete[] p` records the array form so codegen runs
            // N destructors in reverse order from the 8-byte cookie. Before
            // H6 the brackets were *consumed and discarded* and the
            // single-element dtor path was reused — a silent miscompile
            // for any array allocated with `new T[n]`.
            let is_array = self.eat_punct(Punct::LBracket);
            if is_array {
                self.expect_punct(Punct::RBracket, "]")?;
            }
            let expr = Box::new(self.unary()?);
            return Ok(if is_array {
                Expr::DeleteArray { expr }
            } else {
                Expr::Delete { expr }
            });
        }
        // J-14 v1 (tick 62): `& Class :: method` — member-function-pointer
        // construction. Pattern-match BEFORE the generic `&` unary path
        // so we don't first produce an `Ident` Var and then choke on
        // `::`. Only the simple `&Tag::name` form is supported in v1
        // (no `&Tag::~Tag`, no `&Tag::operator+`).
        if self.is_punct(Punct::Amp)
            && let Some(TokenKind::Ident(tag)) = self.kind_at(1)
            && self.kind_at(2) == Some(&TokenKind::Punct(Punct::ColonColon))
            && let Some(TokenKind::Ident(_)) = self.kind_at(3)
            && (self.tags.contains_key(tag) || self.member_class_typedef_tag(tag).is_some())
        {
            let amp_loc = self.loc_here();
            self.advance(); // '&'
            // Collect every `ident (:: ident)+` component. A 2-segment name
            // (`&Tag::method`) yields `parts == [Tag, method]`; a deeper
            // qualified-id (`&cls::Streamer::Build` — a nested class's static
            // member, the OWL `IMPLEMENT_STREAMABLE` registration form) keeps
            // consuming so the trailing `::Build` is no longer left for the
            // caller to choke on. The last component is the method; everything
            // before it (joined by `::`) is the class. For the 2-segment case
            // this is byte-identical to the previous fixed-shape parse.
            let mut parts: Vec<String> = Vec::new();
            loop {
                match self.kind() {
                    TokenKind::Ident(s) => parts.push(s.clone()),
                    _ => unreachable!("matcher guaranteed an Ident here"),
                }
                self.advance(); // component ident
                if self.is_punct(Punct::ColonColon)
                    && matches!(self.kind_at(1), Some(TokenKind::Ident(_)))
                {
                    self.advance(); // '::'
                    continue;
                }
                break;
            }
            // `parts.len() >= 2` (the matcher guaranteed `Ident :: Ident`).
            let method = parts.pop().expect("at least the method component");
            let class = parts.join("::");
            let class = self.member_class_typedef_tag(&class).unwrap_or(class);
            return Ok(Expr::AddressOfMember {
                class,
                method,
                loc: amp_loc,
            });
        }
        let unop = match self.kind() {
            TokenKind::Punct(Punct::Minus) => Some(UnOp::Neg),
            TokenKind::Punct(Punct::Plus) => Some(UnOp::Pos),
            TokenKind::Punct(Punct::Bang) => Some(UnOp::LogNot),
            TokenKind::Punct(Punct::Tilde) => Some(UnOp::BitNot),
            TokenKind::Punct(Punct::Amp) => Some(UnOp::Addr),
            TokenKind::Punct(Punct::Star) => Some(UnOp::Deref),
            _ => None,
        };
        if let Some(op) = unop {
            self.advance();
            return Ok(Expr::Unary {
                op,
                expr: Box::new(self.unary()?),
            });
        }
        if self.is_kw(Keyword::Sizeof) {
            self.advance();
            // sizeof ( type )  vs  sizeof unary
            if self.is_punct(Punct::LParen) && self.peek_is_type_after_lparen() {
                self.advance();
                let ty = self.type_name()?;
                self.expect_punct(Punct::RParen, ")")?;
                return Ok(Expr::SizeofType(ty));
            }
            return Ok(Expr::SizeofExpr(Box::new(self.unary()?)));
        }
        // Cast: ( type ) unary
        if self.is_punct(Punct::LParen) && self.peek_is_type_after_lparen() {
            self.advance();
            let ty = self.type_name()?;
            self.expect_punct(Punct::RParen, ")")?;
            let e = self.unary()?;
            return Ok(Expr::Cast {
                ty,
                expr: Box::new(e),
            });
        }
        self.postfix()
    }

    fn peek_is_type_after_lparen(&self) -> bool {
        // Walk a type-specifier sequence starting at the token after `(`; `i`
        // ends just past it. A C-style cast then REQUIRES (cv-quals + `*`/`&`,
        // then) a closing `)` — `(T)`, `(T*)`, `(T&)`, `(const T*)`, `(A::B*)`,
        // `(unsigned long)`. If anything else follows the type, the parens hold
        // an EXPRESSION, not a cast:
        //  * `(long(5))` / `(int(x))` — a parenthesised FUNCTIONAL CAST (the type
        //    is followed by `(`, not `)`); mis-read as `(long)…` it errored with
        //    "expected ')'" (OWL GADGETWI/GAUGE `int((long(u)*h)/d)`).
        //  * `(Flags & mask)` — bit-and on a member that SHADOWS a global
        //    `struct Flags` (OWL/window.h `IsFlagSet`); the `&` is consumed as a
        //    ref declarator, then `mask` (not `)`) ⇒ expression.
        //  * `(ios::in | ios::out)` — `::in` is not a type ⇒ expression.
        let mut i = self.pos + 1; // token after `(`
        // Leading cv-qualifiers precede ANY type-specifier — strip them FIRST so a
        // `const`/`volatile` before a TYPEDEF/TAG name (`(const TFoo)x`, pervasive
        // in the OWL/RTL headers) reaches the Ident arm below. Without this the
        // `const` entered the built-in-keyword arm and the following typedef name
        // was left unconsumed, so the cast was mis-read as a paren-expr and
        // `const` parsed as an expression ("expected an expression") — the
        // regression this restores (it had broken real-header parsing, e.g.
        // OWL/applicat.h → HELLOAPP, though the 88 baselines have no `(const T)`).
        while matches!(
            self.toks.get(i).map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::Const | Keyword::Volatile))
        ) {
            i += 1;
        }
        fn skip_template_args(toks: &[Token], mut i: usize) -> Option<usize> {
            if toks.get(i).map(|t| &t.kind) != Some(&TokenKind::Punct(Punct::Lt)) {
                return Some(i);
            }
            let mut depth = 0i32;
            while i < toks.len() {
                match toks.get(i).map(|t| &t.kind) {
                    Some(TokenKind::Punct(Punct::Lt)) => {
                        depth += 1;
                        i += 1;
                    }
                    Some(TokenKind::Punct(Punct::Gt)) => {
                        depth -= 1;
                        i += 1;
                        if depth <= 0 {
                            return Some(i);
                        }
                    }
                    Some(TokenKind::Punct(Punct::Shr)) => {
                        depth -= 2;
                        i += 1;
                        if depth <= 0 {
                            return Some(i);
                        }
                    }
                    Some(TokenKind::Eof) | None => return None,
                    _ => i += 1,
                }
            }
            None
        }
        match self.toks.get(i).map(|t| &t.kind) {
            Some(TokenKind::Keyword(
                Keyword::Void
                | Keyword::Char
                | Keyword::Short
                | Keyword::Int
                | Keyword::Long
                | Keyword::Signed
                | Keyword::Unsigned
                | Keyword::Float
                | Keyword::Double
                | Keyword::Const
                | Keyword::Volatile
                | Keyword::Int8
                | Keyword::Int16
                | Keyword::Int32
                | Keyword::Int64,
            )) => {
                // A run of built-in type / cv keywords (`unsigned long`, etc.).
                while matches!(
                    self.toks.get(i).map(|t| &t.kind),
                    Some(TokenKind::Keyword(
                        Keyword::Void
                            | Keyword::Char
                            | Keyword::Short
                            | Keyword::Int
                            | Keyword::Long
                            | Keyword::Signed
                            | Keyword::Unsigned
                            | Keyword::Float
                            | Keyword::Double
                            | Keyword::Const
                            | Keyword::Volatile
                            | Keyword::Int8
                            | Keyword::Int16
                            | Keyword::Int32
                            | Keyword::Int64,
                    ))
                ) {
                    i += 1;
                }
            }
            Some(TokenKind::Keyword(
                Keyword::Struct | Keyword::Union | Keyword::Enum | Keyword::Class,
            )) => {
                // `struct Tag` / `class Tag` — the elaborated-type keyword + tag.
                i += 1;
                if matches!(self.toks.get(i).map(|t| &t.kind), Some(TokenKind::Ident(_))) {
                    i += 1;
                } else {
                    return false;
                }
            }
            Some(TokenKind::Ident(s)) => {
                let is_template = self.class_template_idx.contains_key(s);
                if !(self.typedefs.contains_key(s) || self.tags.contains_key(s) || is_template) {
                    return false;
                }
                i += 1; // past the type Ident
                if is_template {
                    i = match skip_template_args(self.toks, i) {
                        Some(next) => next,
                        None => return false,
                    };
                }
                while self.toks.get(i).map(|t| &t.kind)
                    == Some(&TokenKind::Punct(Punct::ColonColon))
                {
                    match self.toks.get(i + 1).map(|t| &t.kind) {
                        Some(TokenKind::Ident(m))
                            if self.typedefs.contains_key(m) || self.tags.contains_key(m) =>
                        {
                            i += 2;
                        }
                        _ => return false, // `::value` ⇒ expression
                    }
                }
            }
            _ => return false,
        }
        // cv-quals and pointer/reference declarators, then the cast REQUIRES `)`.
        while let Some(TokenKind::Keyword(Keyword::Const | Keyword::Volatile))
        | Some(TokenKind::Punct(Punct::Star | Punct::Amp)) = self.toks.get(i).map(|t| &t.kind)
        {
            i += 1;
        }
        // S5: cast to a FUNCTION-POINTER type — `(int (*)(void *))fgetc`. The
        // RTL scanf family (FSCANF/SSCANF/SCANF/VFSCANF/VSCANF/CSCANF) and the
        // strto* family pass `fgetc`/`ungetc` to `_scanner`/`_scantod` through
        // exactly this cast. After a CONFIRMED type-specifier (the match above),
        // a grouped abstract declarator `( [conv-kw run] * … )` followed by a
        // parameter list `( … )` and the cast's closing `)` can only be a type:
        // no expression continues a type-specifier with `(*`. `type_name`'s
        // `declarator` already parses the abstract grouped form (gname = None);
        // only this gate rejected it. Both paren groups are balance-scanned so
        // nested parens in the parameter list (`void (*)(int, void *)`) work.
        if self.toks.get(i).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::LParen)) {
            // Inside the group: an optional calling-convention/qualifier
            // keyword run, then the `*` that makes it a pointer declarator.
            let mut j = i + 1;
            while matches!(
                self.toks.get(j).map(|t| &t.kind),
                Some(TokenKind::Keyword(_))
            ) {
                j += 1;
            }
            if self.toks.get(j).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::Star)) {
                // Balance-scan the `(*…)` group, then the `(params)` group.
                let mut k = i;
                for _group in 0..2 {
                    if self.toks.get(k).map(|t| &t.kind) != Some(&TokenKind::Punct(Punct::LParen)) {
                        return false;
                    }
                    let mut depth = 0usize;
                    loop {
                        match self.toks.get(k).map(|t| &t.kind) {
                            Some(TokenKind::Punct(Punct::LParen)) => depth += 1,
                            Some(TokenKind::Punct(Punct::RParen)) => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            None => return false,
                            _ => {}
                        }
                        k += 1;
                    }
                    k += 1; // past this group's `)`
                }
                return self.toks.get(k).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::RParen));
            }
        }
        self.toks.get(i).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::RParen))
    }

    fn postfix(&mut self) -> PResult<Expr> {
        let e = self.primary()?;
        self.postfix_tail(e)
    }

    /// Apply postfix operators (`[]`, `.`/`->`, `()`, `.*`/`->*`) to an
    /// already-parsed primary `e`. Shared by `postfix` and the named-cast path
    /// so a cast result chains too (`static_cast<T*>(p)->m()` in OWL's
    /// streaming classes).
    fn postfix_tail(&mut self, mut e: Expr) -> PResult<Expr> {
        loop {
            if self.is_punct(Punct::LBracket) {
                let lb_loc = self.loc_here();
                self.advance();
                let idx = self.expr()?;
                self.expect_punct(Punct::RBracket, "]")?;
                e = Expr::Index {
                    base: Box::new(e),
                    idx: Box::new(idx),
                    loc: lb_loc,
                };
            } else if self.is_punct(Punct::DotStar) || self.is_punct(Punct::ArrowStar) {
                // J-14 v1 (tick 62): `obj.*p` or `ptr->*p` — pointer-to-
                // member access. v1 requires the result to be immediately
                // called, i.e. `(obj.*p)(args)`. We park the partial
                // shape as `CallMemberPtr` with empty args; the
                // surrounding LParen arm fills in args, OR an outer
                // operator (e.g. `==` for MFP-equality compares) can
                // observe the empty-args form. Currently the only
                // contexts that produce useful semantics from a bare
                // `obj.*p` are: (a) immediate call, (b) the rare
                // `(obj.*p) == ...` comparison shape — covered by codegen
                // (the unfilled CallMemberPtr is rejected by codegen
                // with a clear diagnostic if it leaks out as a value).
                let arrow = self.is_punct(Punct::ArrowStar);
                let dot_loc = self.loc_here();
                self.advance();
                let ptr_e = self.unary()?;
                e = Expr::CallMemberPtr {
                    recv: Box::new(e),
                    ptr: Box::new(ptr_e),
                    args: Vec::new(),
                    arrow,
                    loc: dot_loc,
                };
            } else if self.is_punct(Punct::Dot) || self.is_punct(Punct::Arrow) {
                let arrow = self.is_punct(Punct::Arrow);
                let dot_loc = self.loc_here();
                self.advance();
                // J-21 G-5: accept `obj.operator+(...)` / `obj->operator[](...)`
                // explicit-form. `operator_name()` advances past `operator` +
                // its symbol token and returns the mangled-friendly name
                // (e.g. "operator+"). The Ident path advances exactly one
                // token; both branches converge with `field` holding the
                // member name and the cursor sitting on the next token.
                let field_loc = self.loc_here();
                // S4.2f: an explicit (pseudo-)destructor call and/or a qualified
                // member name — `p->~TMutex()`, `p->TMutex::~TMutex()`
                // (OWL/window.h's TAppMutex dtor), `p->Base::method()`. Parse an
                // optional leading `~`, then any `::`-qualified chain, keeping the
                // FINAL component (mdbcc's flat model); a destructor becomes the
                // method name `~Tag`.
                let mut is_dtor = self.eat_punct(Punct::Tilde);
                let mut field = match self.kind() {
                    TokenKind::Ident(s) => {
                        let n = s.clone();
                        self.advance();
                        n
                    }
                    TokenKind::Keyword(Keyword::Operator) => self.operator_name()?,
                    _ => return Err(self.error_here("expected a field name")),
                };
                while self.is_punct(Punct::ColonColon) {
                    self.advance();
                    is_dtor = self.eat_punct(Punct::Tilde);
                    field = match self.kind() {
                        TokenKind::Ident(s) => {
                            let n = s.clone();
                            self.advance();
                            n
                        }
                        _ => {
                            return Err(
                                self.error_here("expected a name after '::' in a member access")
                            );
                        }
                    };
                }
                let field = if is_dtor { format!("~{field}") } else { field };
                if self.is_punct(Punct::LParen) {
                    self.advance();
                    let mut args = Vec::new();
                    if !self.is_punct(Punct::RParen) {
                        loop {
                            args.push(self.assignment()?);
                            if !self.eat_punct(Punct::Comma) {
                                break;
                            }
                        }
                    }
                    self.expect_punct(Punct::RParen, ")")?;
                    e = Expr::MethodCall {
                        recv: Box::new(e),
                        name: field,
                        args,
                        loc: field_loc,
                    };
                } else {
                    e = Expr::Member {
                        base: Box::new(e),
                        field,
                        arrow,
                        loc: dot_loc,
                    };
                }
            } else if self.is_punct(Punct::Inc) || self.is_punct(Punct::Dec) {
                let inc = self.is_punct(Punct::Inc);
                self.advance();
                e = Expr::IncDec {
                    inc,
                    pre: false,
                    target: Box::new(e),
                };
            } else if self.is_punct(Punct::LParen) {
                let lp_loc = self.loc_here();
                self.advance();
                // Indirect call through a function-pointer value, e.g.
                // `tbl[i](x)` or `(*p)(x)`. (`ident(...)` is already a
                // direct `Call` built in `primary`.)
                let mut args = Vec::new();
                if !self.is_punct(Punct::RParen) {
                    loop {
                        args.push(self.assignment()?);
                        if !self.eat_punct(Punct::Comma) {
                            break;
                        }
                    }
                }
                self.expect_punct(Punct::RParen, ")")?;
                // J-14 v1 (tick 62): if `e` is a partially-built
                // `CallMemberPtr` (produced by `.*`/`->*` with empty
                // args), this `(args)` IS its argument list — fill them
                // in instead of wrapping with `CallPtr`.
                let is_pending_mfp = matches!(
                    &e,
                    Expr::CallMemberPtr { args: prev, .. } if prev.is_empty()
                );
                if is_pending_mfp {
                    if let Expr::CallMemberPtr {
                        recv,
                        ptr,
                        arrow,
                        loc,
                        ..
                    } = e
                    {
                        e = Expr::CallMemberPtr {
                            recv,
                            ptr,
                            args,
                            arrow,
                            loc,
                        };
                    } else {
                        unreachable!();
                    }
                } else {
                    e = Expr::CallPtr {
                        target: Box::new(e),
                        args,
                        loc: lp_loc,
                    };
                }
            } else {
                break;
            }
        }
        Ok(e)
    }

    fn primary(&mut self) -> PResult<Expr> {
        // J-8b (tick 74): capture loc at the first token of this primary
        // expression. Stamped on every Expr variant that carries a `loc`
        // field (Var, Call, MethodCall, Member, ...). For variants that
        // don't (Int, Float, Str, ...), the loc is unused — `Expr::loc()`
        // returns synthetic and codegen falls back to `Gen::current_loc`.
        let p_loc = self.loc_here();
        // C++ boolean literals `true` / `false`. They lower as the integer
        // constants 1 / 0. They are RESERVED keywords (the lexer emits them as
        // identifiers), so intercepting them here cannot shadow a variable.
        // Pervasive in the real headers — e.g. OWL/applicat.h's `bool enable =
        // true` default args — which previously failed "expected an expression"
        // and blocked the real HELLOAPP sample app. Byte-safe: no baseline uses
        // a bool literal (they errored), so no existing parse changes.
        if let TokenKind::Ident(s) = self.kind() {
            if s == "true" {
                self.advance();
                return Ok(Expr::Int(1));
            }
            if s == "false" {
                self.advance();
                return Ok(Expr::Int(0));
            }
        }
        // A leading `::` is the global-scope qualifier on a name (`::AnsiToOem(x)`
        // in CSTRING.H's inline methods). mdbcc's model is flat, so we consume it
        // and resolve the following name normally — which, for the free functions
        // these qualify (never class members), yields the intended global Call /
        // Var. (`::operator …` — a global *operator* function — is a separate,
        // deeper case left to the `_` arm.)
        //
        // S4.2aa: capture the qualifier. Inside a member function an
        // *unqualified* call to a name that is also a sibling method collapses
        // to `this->name(...)` (below); a `::`-qualified call must NOT — it
        // forces free-function resolution. The RTL relies on this: e.g.
        // CSTRING.H's `string::find_index` calls the FREE `::to_upper(*this)`
        // (returns a new `string`), distinct from the member `to_upper()`
        // (in-place, void). Without the guard `::to_upper(*this).find_case_index`
        // mis-binds to the void member ⇒ "method call on non-class".
        let global_qualified = self.eat_punct(Punct::ColonColon);
        match self.kind().clone() {
            TokenKind::Int {
                value,
                unsigned,
                longlong,
                ..
            } => {
                self.advance();
                let v = value as i64;
                // 64-bit literal typing (so `long long` ops use 64-bit codegen
                // rather than the 32-bit path — `x >> 32` wrapping mod 32, `/`
                // using `cdq` not `cqo`):
                //   * a 32-bit-range `long long`-suffixed literal (`1LL`,
                //     `0xFFFFFFFFULL`) is wrapped in a Cast to the 64-bit type.
                //     Above `i32::MAX`, the inner expression is first tagged as
                //     unsigned 32-bit so the outer int64 widening zero-extends
                //     the bit pattern instead of sign-extending it.
                //   * a LARGE literal (magnitude past 32-bit unsigned) is typed
                //     64-bit directly by `expr_type`'s magnitude rule — it must
                //     NOT go through a Cast, whose signed `movsxd` widening would
                //     corrupt the high-bit-set value that `mov rax,imm64` already
                //     materialised.
                // A single `long` (L) is 32-bit on LLP64/ILP32, so it never
                // triggers the wrap.
                if longlong && value <= u32::MAX as u128 {
                    let expr = if value <= i32::MAX as u128 {
                        Expr::Int(v)
                    } else {
                        Expr::Cast {
                            ty: Type::Int {
                                bytes: 4,
                                signed: false,
                            },
                            expr: Box::new(Expr::Int(v)),
                        }
                    };
                    Ok(Expr::Cast {
                        ty: Type::Int {
                            bytes: 8,
                            signed: !unsigned,
                        },
                        expr: Box::new(expr),
                    })
                } else {
                    Ok(Expr::Int(v))
                }
            }
            TokenKind::Float(lexeme) => {
                self.advance();
                let (digits, bytes) = match lexeme.as_bytes().last() {
                    Some(b'f') | Some(b'F') => (&lexeme[..lexeme.len() - 1], 4u8),
                    // `long double` is folded to `double` in Phase F-1
                    // (backlog F-1; no Win64 80-bit extended path).
                    Some(b'l') | Some(b'L') => (&lexeme[..lexeme.len() - 1], 8u8),
                    _ => (lexeme.as_str(), 8u8),
                };
                let v: f64 = digits
                    .parse()
                    .map_err(|_| self.error_here("malformed floating-point literal"))?;
                if !v.is_finite() {
                    // House style: never silently `inf` for an over-range
                    // literal (`f64::from_str` returns `Ok(inf)`).
                    return Err(self.error_here("floating-point literal out of range"));
                }
                Ok(Expr::Float { value: v, bytes })
            }
            TokenKind::Char { value, .. } => {
                self.advance();
                Ok(Expr::Char(value))
            }
            TokenKind::Str { bytes, wide } => {
                // #53: `L"..."` is a wide literal. Concatenate adjacent string
                // literals (a narrow/wide mix is ill-formed C++ and never appears
                // in Borland source, so we take the first literal's width and
                // append the bodies), then encode wide to UTF-16LE.
                let is_wide = wide;
                let mut all = bytes;
                self.advance();
                while let TokenKind::Str { bytes: b, wide: _ } = self.kind() {
                    all.extend_from_slice(b);
                    self.advance();
                }
                if is_wide {
                    Ok(Expr::WideStr(utf16le_with_nul(&all)))
                } else {
                    Ok(Expr::Str(all))
                }
            }
            TokenKind::Keyword(Keyword::This) => {
                self.advance();
                Ok(Expr::Var("this".into(), p_loc))
            }
            TokenKind::Ident(name) => {
                self.advance();
                // G19: a bare reference to a LOCAL anonymous-aggregate member
                // (`infoHeader` from `union { … infoHeader; … };`) rewrites to
                // `$anonu.N.infoHeader` — a member access on the hidden local.
                // Gated on the hidden local being a CURRENT local (`fn_locals`,
                // which is function-scoped) so a promotion from another function
                // is inert. Not for a qualified `Tag::name` (next is `::`).
                if !self.is_punct(Punct::ColonColon)
                    && let Some(hidden) = self.anonu_promotions.get(&name)
                    && self.fn_locals.contains(hidden)
                {
                    let hidden = hidden.clone();
                    return Ok(Expr::Member {
                        base: Box::new(Expr::Var(hidden, p_loc)),
                        field: name,
                        arrow: false,
                        loc: p_loc,
                    });
                }
                // Qualified-id `Tag::member` (and `A::B::member`) in expression
                // position. mdbcc's model is flat — nested types live at global
                // scope and enum constants are global — so we drop the class
                // qualifier(s) and resolve the FINAL component exactly like a
                // bare name. IOSTREAM.H's default arguments read
                // `ios::in | ios::out` (constants of the nested `enum open_mode`),
                // and `string::npos` resolves the same way.
                let mut name = name;
                let mut qualifier: Option<String> = None;
                while self.is_punct(Punct::ColonColon) {
                    self.advance(); // ::
                    match self.kind() {
                        TokenKind::Ident(s) => {
                            qualifier = Some(name);
                            name = s.clone();
                            self.advance();
                        }
                        // S6: a qualified OPERATOR name — `Base::operator int()`
                        // (an explicit conversion-operator / operator call;
                        // OCF/OCPART.H `return Base::operator int();`). The
                        // operator is always the FINAL component, so resolve it
                        // and stop. `operator_name` yields the same method key
                        // (`operator@<typecode>` / `operator@sp`) the class
                        // registered, so the qualified-call path below dispatches
                        // it statically on the `(Base*)this` subobject.
                        TokenKind::Keyword(Keyword::Operator) => {
                            qualifier = Some(name);
                            name = self.operator_name()?;
                            break;
                        }
                        _ => {
                            return Err(self.error_here("expected a name after '::'"));
                        }
                    }
                }
                // S4.2z+: a qualified CALL `Tag::method(...)` to a known member
                // function keeps the QUALIFIED symbol `Tag::method` (mdbcc's
                // member-fn key) instead of flattening to the bare `method` —
                // which would reference a non-existent free function and go
                // unresolved at link (the `S::get()` / `string::get_*()` shape).
                // Enum constants (`ios::in`) and static-data constants
                // (`string::npos`) are NOT member functions, so they still
                // flatten via the loop above.
                // S5 #41: a QUALIFIED base/self method call `Qual::method(args)`
                // inside a member function — the C++ non-virtual "call the base
                // implementation" idiom. mdbcc resolves methods STATICALLY, so a
                // method call on `(Qual*)this` (the Qual subobject) dispatches
                // directly to Qual's method (non-virtual), which is exactly the
                // required semantics. Gated to a qualifier whose class HAS the
                // method (the same condition that renamed `name` below) and that
                // we are inside SOME member function (so `this` exists) — `Qual`
                // is then `cur_class` or a base (the only way a member calls
                // `Qual::method`). The record's base-chain is not yet finalized
                // mid-body, so the method-presence check stands in for the
                // base-chain check. Other qualified ids keep the existing
                // handling (enum constants, static data members, `::free`).
                // Without this, `Base::foo(x);` lost its `this` (a silent
                // miscompile) — or, at statement scope, was mis-parsed as a
                // declaration (see `at_decl`).
                if self.is_punct(Punct::LParen)
                    && !global_qualified
                    && self.cur_class.is_some()
                    && let Some(qual) = qualifier.clone()
                    && let Some(&qid) = self.tags.get(&qual)
                    && self
                        .classes
                        .get(&qid)
                        .is_some_and(|c| c.methods.contains(&name) && !c.static_only(&name))
                {
                    self.advance(); // (
                    let mut args = Vec::new();
                    if !self.is_punct(Punct::RParen) {
                        loop {
                            args.push(self.assignment()?);
                            if !self.eat_punct(Punct::Comma) {
                                break;
                            }
                        }
                    }
                    self.expect_punct(Punct::RParen, ")")?;
                    let qrec = {
                        let r = &self.records[qid];
                        Type::Record {
                            id: qid,
                            size: r.size,
                            align: r.align,
                        }
                    };
                    let recv = Expr::Cast {
                        ty: Type::Ptr(Box::new(qrec)),
                        expr: Box::new(Expr::Var("this".into(), p_loc)),
                    };
                    return Ok(Expr::MethodCall {
                        recv: Box::new(recv),
                        name,
                        args,
                        loc: p_loc,
                    });
                }
                if self.is_punct(Punct::LParen)
                    && let Some(tag) = &qualifier
                    && let Some(&cid) = self.tags.get(tag)
                    && self
                        .classes
                        .get(&cid)
                        .is_some_and(|c| c.methods.contains(&name))
                {
                    name = format!("{tag}::{name}");
                }
                // Functional-cast syntax `Type(expr)` for a SCALAR type name
                // (`size_t(-1)` in CSTRING.H's `const size_t NPOS = size_t(-1)`,
                // `int(x)`, ...). Lowers to a C-style cast so it const-folds. A
                // record type `T(args)` is a temporary construction — left to the
                // call path for now (deferred).
                if self.is_punct(Punct::LParen)
                    && let Some(t) = self.typedefs.get(&name).cloned().or_else(|| {
                        self.tags.get(&name).map(|&id| {
                            let r = &self.records[id];
                            Type::Record {
                                id,
                                size: r.size,
                                align: r.align,
                            }
                        })
                    })
                    && !t.is_record()
                {
                    self.advance(); // (
                    if self.eat_punct(Punct::RParen) {
                        // `T()` value-initialises to zero.
                        return Ok(Expr::Cast {
                            ty: t,
                            expr: Box::new(Expr::Int(0)),
                        });
                    }
                    let e = self.assignment()?;
                    self.expect_punct(Punct::RParen, ")")?;
                    return Ok(Expr::Cast {
                        ty: t,
                        expr: Box::new(e),
                    });
                }
                if self.is_punct(Punct::LParen) {
                    // Tick 64 (J-13 v1): variadic intrinsics — recognised
                    // BEFORE the regular `ident(args)` path because
                    // `va_arg(ap, T)`'s second argument is a TYPE-id, not
                    // an expression. mdbcc declares only `va_list` (a
                    // `typedef char*`) in the intrinsic `<stdarg.h>`; the
                    // three macros below are compiled in directly so the
                    // preprocessor's comma-expression and type-as-argument
                    // edges never come into play.
                    if name == "va_start" {
                        self.advance(); // (
                        let ap = self.assignment()?;
                        self.expect_punct(Punct::Comma, ",")?;
                        // `last` must be a bare identifier — the name of an
                        // actual named parameter of the enclosing variadic
                        // function. Anything else is a hard error at parse
                        // time (saves codegen from having to walk an
                        // arbitrary lvalue back to its parameter slot).
                        let last_name = match self.kind() {
                            TokenKind::Ident(s) => {
                                let s = s.clone();
                                self.advance();
                                s
                            }
                            _ => {
                                return Err(self.error_here(
                                    "va_start's second argument must be the \
                                     name of the last named parameter",
                                ));
                            }
                        };
                        self.expect_punct(Punct::RParen, ")")?;
                        return Ok(Expr::VaStart {
                            ap: Box::new(ap),
                            last_name,
                        });
                    }
                    if name == "va_arg" {
                        self.advance(); // (
                        let ap = self.assignment()?;
                        self.expect_punct(Punct::Comma, ",")?;
                        let ty = self.type_name()?;
                        self.expect_punct(Punct::RParen, ")")?;
                        return Ok(Expr::VaArg {
                            ap: Box::new(ap),
                            ty,
                        });
                    }
                    if name == "va_end" {
                        self.advance(); // (
                        let ap = self.assignment()?;
                        self.expect_punct(Punct::RParen, ")")?;
                        return Ok(Expr::VaEnd { ap: Box::new(ap) });
                    }
                    self.advance();
                    let mut args = Vec::new();
                    if !self.is_punct(Punct::RParen) {
                        loop {
                            args.push(self.assignment()?);
                            if !self.eat_punct(Punct::Comma) {
                                break;
                            }
                        }
                    }
                    self.expect_punct(Punct::RParen, ")")?;
                    // G41 (OWL *_Sig): a 1-arg call to a SKIPPED
                    // pointer-to-member IDENTITY template (`(TMyPMF)
                    // v_U_SIZE_Sig(&TMyClass::EvSize)` in every response
                    // table) folds to its argument — exactly bcc32's inlining
                    // (Borland's OWL libs define no `_Sig` symbols, so a
                    // symbol reference could never link). The use-site cast
                    // carries the typing.
                    if args.len() == 1 && self.pmf_identity_templates.contains(&name) {
                        return Ok(args.pop().expect("len checked"));
                    }
                    // Unqualified call to a sibling method inside a member.
                    // S4.2aa: a `::`-qualified call is global-scoped — it never
                    // collapses to a sibling method (forces free-function lookup).
                    if !global_qualified && self.in_class_method(&name) {
                        let cid = self.cur_class.unwrap();
                        // SEM-04: only an all-static name bypasses `this`; a
                        // mixed overload set goes through MethodCall, whose
                        // codegen resolution drops `this` for a static pick.
                        // A static body has no `this` at all, so it keeps the
                        // bare call below; codegen's `enclosing_member_call`
                        // then finds the (static) member through the bases,
                        // which inherit only method NAMES here.
                        let has_this = self.fn_locals.contains("this");
                        if self.classes[&cid].static_only(&name) {
                            let tag = self.classes[&cid].tag.clone();
                            return Ok(Expr::Call {
                                name: format!("{tag}::{name}"),
                                args,
                                loc: p_loc,
                            });
                        }
                        if has_this && self.classes[&cid].methods.contains(&name) {
                            return Ok(Expr::MethodCall {
                                recv: Box::new(Expr::Var("this".into(), p_loc)),
                                name,
                                args,
                                loc: p_loc,
                            });
                        }
                    }
                    Ok(Expr::Call {
                        name,
                        args,
                        loc: p_loc,
                    })
                } else if qualifier.is_some() && !self.enum_consts.contains_key(&name) {
                    // A QUALIFIED non-call id `Tag::member` whose final
                    // component is NOT an enum constant: keep it QUALIFIED so
                    // codegen resolves the `Tag::member` global — a STATIC DATA
                    // member (TColor::Black, C::x). The flatten-to-bare-`member`
                    // path dropped the qualifier, leaving it "undeclared":
                    // a static data member lives at global scope as `Tag::name`
                    // (it is NOT in the class's instance `members`), and the
                    // out-of-line definition `T Tag::name = …` registers exactly
                    // that global. Enum constants (`ios::in`) still flatten via
                    // the branch below — keeping them out of this branch.
                    // Additive: a flattened non-enum qualified id otherwise
                    // fails to resolve (gen_addr falls through to "undeclared").
                    let qual = qualifier.as_deref().unwrap();
                    // S2e: resolve a CLASS-typedef qualifier via the enclosing
                    // class. OWL response tables declare `typedef cls TMyClass;`
                    // per class and reference `&TMyClass::method` inside
                    // `cls::__entries[]` (cur_class == cls there) — the method is
                    // registered as `cls::method`, but the global `TMyClass` alias
                    // is last-write-wins across all classes. Prefer the per-class
                    // member typedef (member_class_typedefs[cur_class][qual]) so it
                    // resolves to THIS class. Falls back to the raw qualifier.
                    let qual_tag = self
                        .cur_class
                        .and_then(|cid| self.member_class_typedefs.get(&cid))
                        .and_then(|m| m.get(qual))
                        .and_then(|&tid| self.records[tid].tag.clone())
                        .unwrap_or_else(|| qual.to_string());
                    let qname = format!("{qual_tag}::{name}");
                    // S4.2#35: note the qualified reference; parse-end emits an
                    // extern global for it iff it names a declared static data
                    // member not defined in this TU.
                    self.referenced_statics.insert(qname.clone());
                    Ok(Expr::Var(qname, p_loc))
                } else if self.in_class_method(&name)
                    && let Some(qname) = self.unqualified_static_member(&name)
                {
                    // S4 (#50): an UNQUALIFIED reference to a STATIC data member
                    // of the enclosing class — e.g. `return case_sensitive;`
                    // inside the out-of-line `string::get_case_sensitive_flag`.
                    // Resolve it to the qualified `Tag::name` and register it
                    // (referenced_statics), exactly like the explicit-`Tag::name`
                    // path above — so an UNDEFINED static (defined out-of-line /
                    // in another TU, e.g. the RTL string flags) gets a #35 extern
                    // and links. Statics are NOT in `members`, so without this
                    // the name fell through to a bare `Var`, which codegen could
                    // resolve only via `this_member_fallback` ->
                    // `static_member_global` -> `sigs.globals` (empty for an
                    // undefined static) -> "no member named ...". MUST precede
                    // the instance-member check (a static and an instance member
                    // can't share a name, so ordering is otherwise immaterial).
                    self.referenced_statics.insert(qname.clone());
                    Ok(Expr::Var(qname, p_loc))
                } else if self.in_class_method(&name)
                    && self.classes[&self.cur_class.unwrap()]
                        .members
                        .contains(&name)
                {
                    // Unqualified data member -> this->member. C++ name lookup
                    // searches CLASS scope (members, incl. inherited — see the
                    // base-member inheritance at class registration) BEFORE the
                    // enclosing/global scope, so a member shadows a same-named
                    // global enum constant. This MUST be checked before
                    // `enum_consts`: OWL geometry's TRect has members
                    // left/top/right/bottom, which collide with the `ios`
                    // formatting enum constants (left/right/internal) that
                    // <iostream.h> places in mdbcc's flat global enum-constant
                    // namespace. Resolving `left` to ios::left (a const int)
                    // instead of `this->left` made every TRect method (Offset,
                    // Set, TopLeft, ...) error "expression is not an lvalue" and
                    // DEFER — the dominant OWL "not an lvalue" cluster.
                    Ok(Expr::Member {
                        base: Box::new(Expr::Var("this".into(), p_loc)),
                        field: name,
                        arrow: true,
                        loc: p_loc,
                    })
                } else if !self.fn_locals.contains(&name)
                    && let Some(v) = self.enum_consts.get(&name)
                {
                    // S4 (#27): an enum constant resolves to its value ONLY when no
                    // LOCAL of that name is in scope — a local declaration SHADOWS
                    // an enclosing-scope enumerator (C++ [basic.scope]). CLASSLIB
                    // VECTIMP.H's `for( unsigned cur = …; … ) … Data[cur] …` uses
                    // `cur` as a loop variable, but `<iostream>` (transitively
                    // included) declares `enum seek_dir { beg, cur, end }` — without
                    // the shadow guard every `cur` USE folded to the enumerator `1`,
                    // so the instantiated ForEach/FirstThat/LastThat indexed
                    // `Data[1]` and deferred ("expression is not an lvalue"). The
                    // local is in `fn_locals`, so skip the enum fold for it.
                    Ok(Expr::Int(*v))
                } else {
                    Ok(Expr::Var(name, p_loc))
                }
            }
            TokenKind::Punct(Punct::LParen) => {
                self.advance();
                let e = self.expr()?;
                self.expect_punct(Punct::RParen, ")")?;
                Ok(e)
            }
            // Calling an overloaded operator BY NAME: `operator==(x)`. Inside a
            // member this is `this->operator==(x)` (CSTRING.H's TSubString does
            // exactly this); otherwise a free-function call. Same resolution as
            // the unqualified-identifier-call path above.
            TokenKind::Keyword(Keyword::Operator) => {
                let opname = self.operator_name()?;
                if self.is_punct(Punct::LParen) {
                    self.advance();
                    let mut args = Vec::new();
                    if !self.is_punct(Punct::RParen) {
                        loop {
                            args.push(self.assignment()?);
                            if !self.eat_punct(Punct::Comma) {
                                break;
                            }
                        }
                    }
                    self.expect_punct(Punct::RParen, ")")?;
                    if self.in_class_method(&opname)
                        && self.classes[&self.cur_class.unwrap()]
                            .methods
                            .contains(&opname)
                    {
                        return Ok(Expr::MethodCall {
                            recv: Box::new(Expr::Var("this".into(), p_loc)),
                            name: opname,
                            args,
                            loc: p_loc,
                        });
                    }
                    return Ok(Expr::Call {
                        name: opname,
                        args,
                        loc: p_loc,
                    });
                }
                Err(self.error_here("expected '(' after an operator name in an expression"))
            }
            _ => Err(self.error_here("expected an expression")),
        }
    }

    /// Evaluate a constant integer expression (array sizes, etc.).
    fn const_expr(&mut self) -> PResult<i64> {
        let mut e = self.conditional()?;
        // S5 (#39 extension): fold file-scope `const int` constants used in a
        // constant context — array dimensions (`char Buf[MAX_TEXTLEN]`,
        // `BYTE RedVals[NumColors]`), enum values, bit-field widths. `const_eval`
        // alone can't resolve a const-int Var (Type::Int carries no const-ness),
        // so substitute the recorded `int_consts` first. Byte-safe: before #39 a
        // const-int in a constant context errored here, so no byte-identity
        // baseline reaches this path with one; literals/macros/enums are
        // unaffected (they aren't in `int_consts`).
        // S5: fold `sizeof(localVar)` (e.g. `char buf[sizeof(tmpl)+8]`) — resolve
        // the in-scope local's recorded type to its byte size. Gated on
        // `fn_locals` so only a CURRENT local is used (stale map entries inert);
        // at file scope `fn_locals` is empty, so global array dims are unaffected.
        substitute_local_sizeof(&mut e, &self.local_var_types, &self.fn_locals);
        substitute_int_consts(&mut e, &self.int_consts);
        // S6 (#64-adjacent): fold block-scope `const int` locals, but ONLY a
        // name confirmed as a CURRENT local (mirrors `substitute_local_sizeof`'s
        // gating) so a stale cross-function entry is never used.
        let in_scope: HashMap<String, i64> = self
            .local_int_consts
            .iter()
            .filter(|(n, _)| self.fn_locals.contains(*n))
            .map(|(n, v)| (n.clone(), *v))
            .collect();
        substitute_int_consts(&mut e, &in_scope);
        const_eval(&e).ok_or_else(|| self.error_here("expected a constant expression"))
    }
}

/// True if `k` is a calling-convention keyword (`__cdecl`/`__stdcall`/
/// `__fastcall`/`__pascal`, any underscore spelling — all fold to one
/// `Keyword` variant in the lexer). Used to peek for a convention inside a
/// grouped function-pointer declarator (`void (__cdecl *p)(void)`).
/// Rename a class member symbol from one tag to another, used when a
/// class-template instantiation is given a unique concrete tag (`Box` →
/// `Box$i4`) so multiple instantiations don't collide. Handles the three member
/// symbol shapes: `Old::name` → `New::name`, the constructor `Old::Old` →
/// `New::New`, and the destructor `Old::~Old` → `New::~New`. A symbol that
/// doesn't belong to `old` (e.g. a nested class's `Inner::…`) is unchanged.
fn rename_sym(sym: &str, old: &str, new: &str) -> String {
    match sym.strip_prefix(&format!("{old}::")) {
        Some(rest) if rest == old => format!("{new}::{new}"),
        Some(rest) if rest == format!("~{old}") => format!("{new}::~{new}"),
        Some(rest) => format!("{new}::{rest}"),
        None => sym.to_string(),
    }
}

/// A short, stable code for a type argument, used to key class-template
/// instantiations (`Box<int>` → `Box<i4>`). Only needs to be unique per type;
/// not a faithful Borland mangling.
/// S4.2#39: replace file-scope `const int` Var references with their literal
/// values inside an aggregate global initializer, so the elements const-fold
/// (`static int a[]={pfGetText|pfConstant,...}`). Recurses the const-expression
/// forms; deliberately does NOT descend into `&x` (address-of) so a pointer
/// array `{&X,...}` keeps its address operand intact.
/// S5: replace `sizeof(localVar)` with the variable's byte size inside a
/// constant-expression, for a name confirmed to be a CURRENT local (`locals`).
/// `types` maps each declared local to its final type; `t.size()` matches how
/// `const_eval` folds `sizeof(Type)`. Recurses the const-expression operators
/// (mirrors `substitute_int_consts`). A `sizeof(var)` whose name is not a current
/// local, or whose type is absent, is left untouched (stays non-constant).
fn substitute_local_sizeof(e: &mut Expr, types: &HashMap<String, Type>, locals: &HashSet<String>) {
    if let Expr::SizeofExpr(inner) = e
        && let Expr::Var(n, _) = inner.as_ref()
        && locals.contains(n)
        && let Some(t) = types.get(n)
    {
        *e = Expr::Int(t.size() as i64);
        return;
    }
    match e {
        Expr::SizeofExpr(inner)
        | Expr::Unary { expr: inner, .. }
        | Expr::Cast { expr: inner, .. } => substitute_local_sizeof(inner, types, locals),
        Expr::Binary { lhs, rhs, .. } => {
            substitute_local_sizeof(lhs, types, locals);
            substitute_local_sizeof(rhs, types, locals);
        }
        Expr::Cond { cond, then, els } => {
            substitute_local_sizeof(cond, types, locals);
            substitute_local_sizeof(then, types, locals);
            substitute_local_sizeof(els, types, locals);
        }
        _ => {}
    }
}

fn substitute_int_consts(e: &mut Expr, consts: &HashMap<String, i64>) {
    match e {
        Expr::Var(name, _) => {
            if let Some(&v) = consts.get(name) {
                *e = Expr::Int(v);
            }
        }
        Expr::Binary { lhs, rhs, .. } => {
            substitute_int_consts(lhs, consts);
            substitute_int_consts(rhs, consts);
        }
        Expr::Unary { op, expr } if !matches!(op, UnOp::Addr) => {
            substitute_int_consts(expr, consts);
        }
        Expr::Cast { expr, .. } => substitute_int_consts(expr, consts),
        Expr::Cond { cond, then, els } => {
            substitute_int_consts(cond, consts);
            substitute_int_consts(then, consts);
            substitute_int_consts(els, consts);
        }
        Expr::InitList(items) => {
            for it in items {
                substitute_int_consts(it, consts);
            }
        }
        _ => {}
    }
}

fn default_owner_class(tags: &HashMap<String, usize>, name: &str) -> Option<usize> {
    let (class_path, _) = name.rsplit_once("::")?;
    tags.get(class_path).copied().or_else(|| {
        class_path
            .rsplit_once("::")
            .and_then(|(_, last)| tags.get(last).copied())
    })
}

fn lookup_static_member_from_class(
    classes: &HashMap<usize, ClassInfo>,
    static_member_types: &HashMap<String, Type>,
    mut cid: usize,
    name: &str,
) -> Option<String> {
    loop {
        let ci = classes.get(&cid)?;
        let qname = format!("{}::{}", ci.tag, name);
        if static_member_types.contains_key(&qname) {
            return Some(qname);
        }
        cid = ci.base?;
    }
}

fn qualify_default_static_refs_expr(
    e: &mut Expr,
    cid: usize,
    classes: &HashMap<usize, ClassInfo>,
    static_member_types: &HashMap<String, Type>,
    referenced_statics: &mut HashSet<String>,
) {
    match e {
        Expr::Var(name, _) => {
            if !name.contains("::")
                && let Some(qname) =
                    lookup_static_member_from_class(classes, static_member_types, cid, name)
            {
                referenced_statics.insert(qname.clone());
                *name = qname;
            }
        }
        Expr::Int(_)
        | Expr::Char(_)
        | Expr::Float { .. }
        | Expr::Str(_)
        | Expr::WideStr(_)
        | Expr::SizeofType(_)
        | Expr::AddressOfMember { .. } => {}
        Expr::Typeid(operand, _) => qualify_default_static_refs_expr(
            operand,
            cid,
            classes,
            static_member_types,
            referenced_statics,
        ),
        Expr::Assign { lhs, rhs, .. } => {
            qualify_default_static_refs_expr(
                lhs,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
            qualify_default_static_refs_expr(
                rhs,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
        }
        Expr::Unary { expr, .. }
        | Expr::IncDec { target: expr, .. }
        | Expr::SizeofExpr(expr)
        | Expr::Delete { expr }
        | Expr::DeleteArray { expr } => qualify_default_static_refs_expr(
            expr,
            cid,
            classes,
            static_member_types,
            referenced_statics,
        ),
        Expr::Binary { lhs, rhs, .. }
        | Expr::Index {
            base: lhs,
            idx: rhs,
            ..
        } => {
            qualify_default_static_refs_expr(
                lhs,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
            qualify_default_static_refs_expr(
                rhs,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
        }
        Expr::Member { base, .. } => qualify_default_static_refs_expr(
            base,
            cid,
            classes,
            static_member_types,
            referenced_statics,
        ),
        Expr::Cond { cond, then, els } => {
            qualify_default_static_refs_expr(
                cond,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
            qualify_default_static_refs_expr(
                then,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
            qualify_default_static_refs_expr(
                els,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
        }
        Expr::Call { args, .. } => {
            for a in args {
                qualify_default_static_refs_expr(
                    a,
                    cid,
                    classes,
                    static_member_types,
                    referenced_statics,
                );
            }
        }
        Expr::CallPtr { target, args, .. } => {
            qualify_default_static_refs_expr(
                target,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
            for a in args {
                qualify_default_static_refs_expr(
                    a,
                    cid,
                    classes,
                    static_member_types,
                    referenced_statics,
                );
            }
        }
        Expr::MethodCall { recv, args, .. } => {
            qualify_default_static_refs_expr(
                recv,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
            for a in args {
                qualify_default_static_refs_expr(
                    a,
                    cid,
                    classes,
                    static_member_types,
                    referenced_statics,
                );
            }
        }
        Expr::New {
            args, placement, ..
        } => {
            for a in args.iter_mut().chain(placement.iter_mut()) {
                qualify_default_static_refs_expr(
                    a,
                    cid,
                    classes,
                    static_member_types,
                    referenced_statics,
                );
            }
        }
        Expr::NewArray {
            count, placement, ..
        } => {
            qualify_default_static_refs_expr(
                count,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
            for a in placement {
                qualify_default_static_refs_expr(
                    a,
                    cid,
                    classes,
                    static_member_types,
                    referenced_statics,
                );
            }
        }
        Expr::Cast { expr, .. } | Expr::DynamicCast { expr, .. } => {
            qualify_default_static_refs_expr(
                expr,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
        }
        Expr::InitList(items) => {
            for item in items {
                qualify_default_static_refs_expr(
                    item,
                    cid,
                    classes,
                    static_member_types,
                    referenced_statics,
                );
            }
        }
        Expr::CallMemberPtr {
            recv, ptr, args, ..
        } => {
            qualify_default_static_refs_expr(
                recv,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
            qualify_default_static_refs_expr(
                ptr,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
            for a in args {
                qualify_default_static_refs_expr(
                    a,
                    cid,
                    classes,
                    static_member_types,
                    referenced_statics,
                );
            }
        }
        Expr::VaStart { ap, .. } | Expr::VaEnd { ap } => {
            qualify_default_static_refs_expr(
                ap,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
        }
        Expr::VaArg { ap, .. } => {
            qualify_default_static_refs_expr(
                ap,
                cid,
                classes,
                static_member_types,
                referenced_statics,
            );
        }
    }
}

pub(crate) fn type_arg_code(ty: &Type) -> String {
    match ty {
        Type::Void => "v".into(),
        Type::Int { bytes, signed } => {
            format!("{}{}", if *signed { "i" } else { "u" }, bytes)
        }
        Type::Float { bytes } => format!("f{bytes}"),
        Type::Ptr(inner) => format!("P{}", type_arg_code(inner)),
        Type::Ref(inner) => format!("R{}", type_arg_code(inner)),
        Type::Array(inner, n) => format!("A{n}_{}", type_arg_code(inner)),
        Type::Record { id, .. } => format!("S{id}"),
        Type::Func { .. } | Type::MemFn { .. } => "F".into(),
        Type::TemplateParam(p) => format!("T{p}"),
    }
}

fn is_call_conv_kw(k: Option<&TokenKind>) -> bool {
    matches!(
        k,
        Some(TokenKind::Keyword(
            Keyword::Cdecl | Keyword::Stdcall | Keyword::Fastcall | Keyword::Pascal
        ))
    )
}

/// True if `k` is a Borland declarator qualifier that may legally appear in a
/// pointer declarator before the `*` (or between the stars and the name): a
/// calling convention OR a linkage/memory-model qualifier (`__import`,
/// `__export`, `near`/`far`/`huge`). The Win32 SDK spells `WINAPI` as
/// `__stdcall __import`, so a function-pointer typedef reads
/// `int ( __stdcall __import * FARPROC )( )` — a *run* of these keywords sits
/// between the `(` and the `*`. All are accept-and-ignore except the calling
/// convention, which `skip_ptr_decl_qualifiers` records. Additive: no x64
/// fixture writes a qualifier in this declarator position.
fn is_ptr_decl_qualifier_kw(k: Option<&TokenKind>) -> bool {
    is_call_conv_kw(k)
        || matches!(
            k,
            Some(TokenKind::Keyword(
                Keyword::Import | Keyword::Export | Keyword::Near | Keyword::Far | Keyword::Huge
            ))
        )
}

/// S6 (G1 Stage-3): one-shot token pre-scan to find SHARED virtual bases — a
/// virtual base reachable via 2+ distinct direct-base paths from some class (the
/// iostream `ios` / persistent-stream `pstream` diamonds: `iostream : istream,
/// ostream` joins the two `virtual ios` paths). ONLY these need the
/// vbptr/shared-tail layout; a SINGLE-path data-bearing virtual base (OWL
/// `TWindow` under `TFrameWindow`/`TDialog`, never joined in railc) stays on the
/// plain base-at-0 path — the working pre-Stage-3 behaviour. Name-based (records
/// aren't built yet); a base name is the last component before `,`/`{`/`<` (so
/// `A::B`→`B`, `Tmpl<X>`→`Tmpl`). Robust to template/qualified bases: only the
/// simple-named stream vbases matter for sharing.
fn scan_shared_vbases(toks: &[Token]) -> HashSet<String> {
    // class name -> Vec<(base_name, is_virtual)>
    let mut bases: HashMap<String, Vec<(String, bool)>> = HashMap::new();
    let mut i = 0;
    while i + 1 < toks.len() {
        let is_cls = matches!(
            &toks[i].kind,
            TokenKind::Keyword(Keyword::Class) | TokenKind::Keyword(Keyword::Struct)
        );
        if !is_cls {
            i += 1;
            continue;
        }
        // The class name is the LAST identifier before `:`/`{`/`;` (macros like
        // `_EXPCLASS` are identifiers too).
        let mut j = i + 1;
        let mut cname: Option<String> = None;
        while let Some(TokenKind::Ident(s)) = toks.get(j).map(|t| &t.kind) {
            cname = Some(s.clone());
            j += 1;
        }
        let Some(cname) = cname else {
            i += 1;
            continue;
        };
        if matches!(
            toks.get(j).map(|t| &t.kind),
            Some(TokenKind::Punct(Punct::Colon))
        ) {
            j += 1;
            let mut entries: Vec<(String, bool)> = Vec::new();
            let mut cand: Option<String> = None;
            let mut cur_virtual = false;
            let mut depth = 0i32; // <...> template-arg nesting
            while j < toks.len() {
                match &toks[j].kind {
                    TokenKind::Punct(Punct::Lt) => depth += 1,
                    TokenKind::Punct(Punct::Gt) if depth > 0 => depth -= 1,
                    _ if depth > 0 => {}
                    TokenKind::Punct(Punct::LBrace) => {
                        if let Some(n) = cand.take() {
                            entries.push((n, cur_virtual));
                        }
                        break;
                    }
                    TokenKind::Punct(Punct::Semi) => {
                        entries.clear();
                        break;
                    }
                    TokenKind::Keyword(Keyword::Virtual) => cur_virtual = true,
                    TokenKind::Keyword(Keyword::Public)
                    | TokenKind::Keyword(Keyword::Private)
                    | TokenKind::Keyword(Keyword::Protected) => {}
                    TokenKind::Ident(s) => cand = Some(s.clone()),
                    TokenKind::Punct(Punct::ColonColon) => {} // keep last component
                    TokenKind::Punct(Punct::Comma) => {
                        if let Some(n) = cand.take() {
                            entries.push((n, cur_virtual));
                        }
                        cur_virtual = false;
                    }
                    _ => {}
                }
                j += 1;
            }
            if !entries.is_empty() {
                bases.entry(cname).or_default().extend(entries);
            }
        }
        i = j.max(i + 1);
    }
    // vb_reach(name): set of virtual-base names reachable from `name`.
    fn vb_reach(
        name: &str,
        bases: &HashMap<String, Vec<(String, bool)>>,
        memo: &mut HashMap<String, HashSet<String>>,
        stack: &mut HashSet<String>,
    ) -> HashSet<String> {
        if let Some(r) = memo.get(name) {
            return r.clone();
        }
        if !stack.insert(name.to_string()) {
            return HashSet::new(); // cycle guard
        }
        let mut out: HashSet<String> = HashSet::new();
        if let Some(bs) = bases.get(name) {
            for (b, is_virt) in bs.clone() {
                if is_virt {
                    out.insert(b.clone());
                }
                for v in vb_reach(&b, bases, memo, stack) {
                    out.insert(v);
                }
            }
        }
        stack.remove(name);
        memo.insert(name.to_string(), out.clone());
        out
    }
    let mut memo: HashMap<String, HashSet<String>> = HashMap::new();
    let mut shared: HashSet<String> = HashSet::new();
    let names: Vec<String> = bases.keys().cloned().collect();
    for c in &names {
        let bs = bases[c].clone();
        // Each direct base contributes its reachable vbases (+ itself if it is a
        // DIRECT virtual base of `c`). A vbase in 2+ contributions is shared.
        let mut counts: HashMap<String, usize> = HashMap::new();
        for (b, is_virt) in &bs {
            let mut stack = HashSet::new();
            let mut s = vb_reach(b, &bases, &mut memo, &mut stack);
            if *is_virt {
                s.insert(b.clone());
            }
            for v in s {
                *counts.entry(v).or_insert(0) += 1;
            }
        }
        for (v, n) in counts {
            if n >= 2 {
                shared.insert(v);
            }
        }
    }
    shared
}

/// Assign field offsets and compute (size, align) for the active target.
///
/// `ptr_bytes` is the target pointer width (8 = Win64, 4 = Win32): pointer
/// members and the polymorphic vptr occupy this many bytes, so an i386 layout
/// (`ptr_bytes == 4`) matches bcc32's ILP32 ABI while Win64 (`ptr_bytes == 8`)
/// is byte-for-byte unchanged.
///
/// `max_align` is the alignment ceiling (the `#pragma pack` cap). Win64 uses
/// **natural** alignment (`usize::MAX` ⇒ no cap — every field sits at a
/// multiple of its own alignment, the MSVC/modern-Windows layout that keeps
/// rebuilt x64 binaries ABI-sane). Win32 passes `1`: **byte** alignment, which
/// is bcc32 4.52's *default* (`-a1` — Borland keeps the historical
/// no-padding layout for backward compatibility, unlike MSVC's natural
/// alignment). With `max_align == 1` a `struct { char c; int i; }` is 5 bytes
/// (no 3-byte gap before `i`, no tail pad) — matching bcc32. Records whose
/// members are already naturally aligned at their offsets (all-`int`, ptr-then-
/// int, …) are unaffected, so most fixtures' Win32 layouts are unchanged.
///
/// `polymorphic` (Phase B): a hidden vptr (a pointer ⇒ `ptr_bytes` wide)
/// occupies `[0, ptr_bytes)`, so data members start at offset `ptr_bytes` and
/// the record is ≥`ptr_bytes`-aligned. Non-polymorphic classes are unchanged
/// ⇒ all pre-Phase-B layouts/tests stay byte-identical on Win64. (Single
/// inheritance: a polymorphic derived re-lays `[base ++ derived]` fields with
/// the same reservation, reproducing the base's offsets — one shared vptr, no
/// duplication.)
fn layout(
    fields: &mut [Field],
    is_union: bool,
    polymorphic: bool,
    ptr_bytes: usize,
    max_align: usize,
) -> (usize, usize) {
    // The vptr is a pointer, so it honours `max_align` too (byte-packed on
    // Win32). Its own size is `ptr_bytes`, so its alignment is
    // `min(ptr_bytes, max_align)`.
    let vptr_align = ptr_bytes.min(max_align);
    let mut align = if polymorphic { vptr_align } else { 1usize };
    let mut size = if polymorphic && !is_union {
        ptr_bytes
    } else {
        0usize
    };
    for f in fields.iter_mut() {
        let a = f.ty.align_for(ptr_bytes).max(1).min(max_align);
        let s = f.ty.size_for(ptr_bytes);
        align = align.max(a);
        if is_union {
            f.offset = 0;
            size = size.max(s);
        } else {
            let off = size.div_ceil(a) * a;
            f.offset = off;
            size = off + s;
        }
    }
    let size = if align == 0 {
        size
    } else {
        size.div_ceil(align) * align
    };
    (size.max(1), align.max(1))
}

/// Tick 55 (G-1/G-4): walk every `Type::Record { id, size, align }` cache
/// in the parsed AST and rewrite it from `records[id]`. The parser caches
/// the record's size/align on each `Type::Record` value at the site it's
/// constructed; for an inline member function (or its implicit `this`)
/// that site is reached BEFORE `record_specifier` finalises the layout,
/// so the cached `size: 0, align: 1` lingers in `Function::ret`,
/// `Function::params[].1`, and any record-typed Decl/Cast/New inside
/// the body. After parsing completes, `records` is finalised; this
/// sweep refreshes every cache so downstream codegen sees the correct
/// size (avoids spurious "empty struct by value" rejection in
/// `Gen::new` and HiddenPtr/InReg misclassification at call sites).
///
/// Idempotent: a record whose cache is already correct rewrites to the
/// same value (still byte-identical), so this pass is safe to run on
/// programs where every Record was constructed post-finalisation. The
/// O1 88 e2e byte-identity contract holds because:
///  - Free functions never reference their own class through inline
///    member parsing (they have no enclosing class).
///  - Out-of-line member definitions resolve their return/param types
///    via `decl_specifiers` AFTER `record_specifier` returns, so the
///    cache was already correct → rewrite is a no-op.
///  - Inline member functions: pre-tick-55 paths errored at codegen,
///    so they had no compiled output to preserve — anything that now
///    compiles is net-new.
fn refresh_record_types(items: &mut [Item], records: &[Record]) {
    for item in items.iter_mut() {
        match item {
            Item::Func(f) => {
                refresh_type(&mut f.ret, records);
                for (_, t) in &mut f.params {
                    refresh_type(t, records);
                }
                for s in &mut f.body {
                    refresh_stmt_record_types(s, records);
                }
            }
            Item::Global { ty, init, .. } => {
                refresh_type(ty, records);
                if let Some(e) = init {
                    refresh_expr_record_types(e, records);
                }
            }
            Item::ExternGlobal { ty, .. } => {
                refresh_type(ty, records);
            }
        }
    }
}

// ---------------------------------------------------------------------
// Tick 70 (J-11b-members) helpers: class-typed member ctor/dtor body
// splicing. Free functions because they operate on a borrowed body
// vector (`Parser::cxx_funcs` is `take`n and re-`set` around the
// injection pass to avoid double-borrowing `self`).
// ---------------------------------------------------------------------

/// Tick 70: identify class-typed member NAMES already mentioned in the
/// user's `: m(expr)` minit list of a ctor body. Detection matches any
/// `Stmt::ExprStmt(Assign{ lhs: Member{base: Var("this"), field, arrow:
/// true}, ..})` in the body — both parser-inserted minits and explicit
/// user-body assigns. Ctor bodies are small so the full sweep is cheap.
fn collect_minit_names(body: &[Stmt]) -> HashSet<String> {
    let mut out = HashSet::new();
    for s in body {
        // S4 (#8/#34): member inits are now carried as `Stmt::MemberInit`
        // (resolved to a ctor call / assign later in this same post-pass).
        // A member named here is EXCLUDED from implicit default-ctor injection
        // — the user's initializer constructs it.
        if let Stmt::MemberInit { field, .. } = s {
            out.insert(field.clone());
        }
    }
    out
}

/// Tick 70: splice `extra` statements right after the first
/// `Stmt::SetVptr(id, _)` in `body`. If no SetVptr is found (no
/// base-bearing / non-polymorphic ctor where the parser inserts it),
/// splice at index 0.
fn splice_after_setvptr(body: &mut Vec<Stmt>, id: usize, extra: Vec<Stmt>) {
    let insert_at = body
        .iter()
        .position(|s| matches!(s, Stmt::SetVptr(i, _) if *i == id))
        .map(|i| i + 1)
        .unwrap_or(0);
    for (offset, s) in extra.into_iter().enumerate() {
        body.insert(insert_at + offset, s);
    }
}

/// Tick 70: splice `extra` statements right before the trailing base
/// dtor call `Base::~Base(this)`. If no such call is found (no base),
/// append at end.
fn splice_before_base_dtor(body: &mut Vec<Stmt>, _id: usize, extra: Vec<Stmt>) {
    // The parser always places the base dtor call (if any) at the END
    // of the dtor body (added by `dtor_full_body` or
    // `synthesize_base_chaining`). Checking the last statement
    // suffices — the call shape is `Call("X::~X", [Var("this")])`.
    let insert_at = match body.last() {
        Some(Stmt::ExprStmt(Expr::Call { name, args, .. }, _))
            if name.contains("::~") && args.len() == 1 =>
        {
            if matches!(&args[0], Expr::Var(v, _) if v == "this") {
                body.len() - 1
            } else {
                body.len()
            }
        }
        _ => body.len(),
    };
    for (offset, s) in extra.into_iter().enumerate() {
        body.insert(insert_at + offset, s);
    }
}

/// Refresh a single `Type` node in place. `Type::Record { id }` reads
/// `records[id]`'s finalised size/align and overwrites the cache;
/// composite types (Ptr/Ref/Array/Func) recurse into their components.
fn refresh_type(t: &mut Type, records: &[Record]) {
    match t {
        Type::Record { id, size, align } => {
            if let Some(r) = records.get(*id) {
                *size = r.size;
                *align = r.align;
            }
        }
        Type::Ptr(inner) | Type::Ref(inner) => refresh_type(inner, records),
        Type::Array(elem, _) => refresh_type(elem, records),
        Type::Func { ret, params } => {
            refresh_type(ret, records);
            for p in params {
                refresh_type(p, records);
            }
        }
        Type::MemFn { ret, params, .. } => {
            refresh_type(ret, records);
            for p in params {
                refresh_type(p, records);
            }
        }
        // S4: a template parameter references no record to refresh.
        Type::TemplateParam(_) => {}
        Type::Void | Type::Int { .. } | Type::Float { .. } => {}
    }
}

fn refresh_stmt_record_types(s: &mut Stmt, records: &[Record]) {
    match s {
        Stmt::Return(Some(e), _) | Stmt::ExprStmt(e, _) | Stmt::Throw(Some(e), _) => {
            refresh_expr_record_types(e, records);
        }
        Stmt::Return(None, _) | Stmt::Throw(None, _) | Stmt::Empty | Stmt::SetVptr(_, _) => {}
        Stmt::Decl { ty, init, .. } => {
            refresh_type(ty, records);
            if let Some(e) = init {
                refresh_expr_record_types(e, records);
            }
        }
        Stmt::If {
            cond, then, els, ..
        } => {
            refresh_expr_record_types(cond, records);
            refresh_stmt_record_types(then, records);
            if let Some(e) = els {
                refresh_stmt_record_types(e, records);
            }
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
            refresh_expr_record_types(cond, records);
            refresh_stmt_record_types(body, records);
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(i) = init {
                refresh_stmt_record_types(i, records);
            }
            if let Some(c) = cond {
                refresh_expr_record_types(c, records);
            }
            if let Some(s) = step {
                refresh_expr_record_types(s, records);
            }
            refresh_stmt_record_types(body, records);
        }
        Stmt::Block(ss, _) => {
            for s in ss {
                refresh_stmt_record_types(s, records);
            }
        }
        Stmt::Try { body, catches, .. } => {
            for s in body {
                refresh_stmt_record_types(s, records);
            }
            for c in catches {
                if let CatchKind::Typed { ty, .. } = &mut c.kind {
                    refresh_type(ty, records);
                }
                for s in &mut c.body {
                    refresh_stmt_record_types(s, records);
                }
            }
        }
        Stmt::Switch {
            scrutinee, body, ..
        } => {
            refresh_expr_record_types(scrutinee, records);
            refresh_stmt_record_types(body, records);
        }
        Stmt::Case { value, .. } => refresh_expr_record_types(value, records),
        // G40: a reference-member bind's rhs is an ordinary expression.
        Stmt::RefBindMember { rhs, .. } => refresh_expr_record_types(rhs, records),
        // S4 (#8/#34): a member-init marker carries ctor-arg expressions whose
        // record-type ids must be refreshed like any other (e.g. when a class
        // template instantiation renames its records).
        Stmt::MemberInit { args, .. } => {
            for a in args {
                refresh_expr_record_types(a, records);
            }
        }
        Stmt::Default(_)
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(..)
        | Stmt::Goto(..) => {}
    }
}

fn refresh_expr_record_types(e: &mut Expr, records: &[Record]) {
    match e {
        Expr::Int(_)
        | Expr::Char(_)
        | Expr::Float { .. }
        | Expr::Str(_)
        | Expr::WideStr(_)
        | Expr::Var(..) => {}
        Expr::Typeid(operand, _) => refresh_expr_record_types(operand, records),
        Expr::Assign { lhs, rhs, .. } => {
            refresh_expr_record_types(lhs, records);
            refresh_expr_record_types(rhs, records);
        }
        Expr::Unary { expr, .. }
        | Expr::IncDec { target: expr, .. }
        | Expr::SizeofExpr(expr)
        | Expr::Delete { expr }
        | Expr::DeleteArray { expr } => {
            refresh_expr_record_types(expr, records);
        }
        Expr::Binary { lhs, rhs, .. }
        | Expr::Index {
            base: lhs,
            idx: rhs,
            ..
        } => {
            refresh_expr_record_types(lhs, records);
            refresh_expr_record_types(rhs, records);
        }
        Expr::Member { base, .. } => {
            refresh_expr_record_types(base, records);
        }
        Expr::Cond { cond, then, els } => {
            refresh_expr_record_types(cond, records);
            refresh_expr_record_types(then, records);
            refresh_expr_record_types(els, records);
        }
        Expr::Call { args, .. } => {
            for a in args {
                refresh_expr_record_types(a, records);
            }
        }
        Expr::CallPtr { target, args, .. } => {
            refresh_expr_record_types(target, records);
            for a in args {
                refresh_expr_record_types(a, records);
            }
        }
        Expr::MethodCall { recv, args, .. } => {
            refresh_expr_record_types(recv, records);
            for a in args {
                refresh_expr_record_types(a, records);
            }
        }
        Expr::New {
            ty,
            args,
            placement,
        } => {
            refresh_type(ty, records);
            for a in args.iter_mut().chain(placement.iter_mut()) {
                refresh_expr_record_types(a, records);
            }
        }
        Expr::NewArray {
            ty,
            count,
            placement,
            ..
        } => {
            refresh_type(ty, records);
            refresh_expr_record_types(count, records);
            for a in placement {
                refresh_expr_record_types(a, records);
            }
        }
        Expr::Cast { ty, expr } | Expr::DynamicCast { ty, expr } => {
            refresh_type(ty, records);
            refresh_expr_record_types(expr, records);
        }
        Expr::SizeofType(ty) => refresh_type(ty, records),
        // J-9 (tick 57): an aggregate-init list has no Type field of its
        // own (its target type lives on the parent Stmt::Decl). Recurse
        // into the elements so any nested record literals or sub-lists
        // see refreshed caches.
        Expr::InitList(items) => {
            for e in items {
                refresh_expr_record_types(e, records);
            }
        }
        // J-14 v1 (tick 62): MFP construction has no inline Type to
        // refresh; the receiver + args at the call site recurse.
        Expr::AddressOfMember { .. } => {}
        Expr::CallMemberPtr {
            recv, ptr, args, ..
        } => {
            refresh_expr_record_types(recv, records);
            refresh_expr_record_types(ptr, records);
            for a in args {
                refresh_expr_record_types(a, records);
            }
        }
        // Tick 64 (J-13 v1): variadic intrinsics carry a Type only on
        // `va_arg`; recurse into the `ap` sub-expression in all three.
        Expr::VaStart { ap, .. } => {
            refresh_expr_record_types(ap, records);
        }
        Expr::VaArg { ap, ty } => {
            refresh_expr_record_types(ap, records);
            refresh_type(ty, records);
        }
        Expr::VaEnd { ap } => {
            refresh_expr_record_types(ap, records);
        }
    }
}

/// Encode a narrow (ASCII/Latin-1) string-literal body as the UTF-16LE bytes of
/// an `L"..."` literal, INCLUDING the trailing 2-byte NUL — the storage form of
/// [`Expr::WideStr`]. Borland's wide literals are ASCII, so a byte-wise widen
/// (`b -> b, 0`) is exact; a non-ASCII byte would need real UTF-16 (not seen in
/// BC45 source). `wchar_t` is 2 bytes on Win32/Win64, so the result length is a
/// multiple of 2 and `len/2` is the element count. (#53)
fn utf16le_with_nul(narrow: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(narrow.len() * 2 + 2);
    for &b in narrow {
        out.push(b);
        out.push(0);
    }
    out.push(0);
    out.push(0);
    out
}

/// Fold a constant integer expression. Handles literals, the usual integer
/// operators, `sizeof`, casts to integer, and `?:`.
pub fn const_eval(e: &Expr) -> Option<i64> {
    Some(match e {
        Expr::Int(v) | Expr::Char(v) => *v,
        Expr::SizeofType(t) => t.size() as i64,
        Expr::Cast { expr, .. } => const_eval(expr)?,
        Expr::Unary { op, expr } => {
            let v = const_eval(expr)?;
            match op {
                UnOp::Neg => -v,
                UnOp::Pos => v,
                UnOp::LogNot => (v == 0) as i64,
                UnOp::BitNot => !v,
                _ => return None,
            }
        }
        Expr::Cond { cond, then, els } => {
            if const_eval(cond)? != 0 {
                const_eval(then)?
            } else {
                const_eval(els)?
            }
        }
        Expr::Binary { op, lhs, rhs, .. } => {
            let a = const_eval(lhs)?;
            let b = const_eval(rhs)?;
            match op {
                BinOp::Add => a.wrapping_add(b),
                BinOp::Sub => a.wrapping_sub(b),
                BinOp::Mul => a.wrapping_mul(b),
                BinOp::Div => {
                    if b == 0 {
                        return None;
                    }
                    a.wrapping_div(b)
                }
                BinOp::Mod => {
                    if b == 0 {
                        return None;
                    }
                    a.wrapping_rem(b)
                }
                BinOp::Shl => a.wrapping_shl(b as u32),
                BinOp::Shr => {
                    if let Some(bytes) = const_eval_unsigned_bytes(lhs) {
                        let bits = (bytes as u32).saturating_mul(8).min(64);
                        let mask = if bits == 64 {
                            u64::MAX
                        } else {
                            (1u64 << bits) - 1
                        };
                        (((a as u64) & mask).wrapping_shr(b as u32)) as i64
                    } else {
                        a.wrapping_shr(b as u32)
                    }
                }
                BinOp::BitAnd => a & b,
                BinOp::BitOr => a | b,
                BinOp::BitXor => a ^ b,
                BinOp::Lt => (a < b) as i64,
                BinOp::Le => (a <= b) as i64,
                BinOp::Gt => (a > b) as i64,
                BinOp::Ge => (a >= b) as i64,
                BinOp::Eq => (a == b) as i64,
                BinOp::Ne => (a != b) as i64,
                BinOp::LAnd => ((a != 0) && (b != 0)) as i64,
                BinOp::LOr => ((a != 0) || (b != 0)) as i64,
                // The comma operator yields its right operand (the left is still
                // required to be constant here, so a non-constant left correctly
                // makes the whole expression non-constant via `const_eval` above).
                BinOp::Comma => b,
            }
        }
        // `sizeof("literal")` is the byte size of the implied `char` array
        // (length + NUL) — a compile-time constant used as an array dimension
        // (CLASSLIB/VERSION.CPP: `char id[sizeof("CLASSLIB")]`, via `#define ID
        // "CLASSLIB"`). Other operand shapes need type inference this pure-integer
        // folder lacks, so they stay non-constant.
        Expr::SizeofExpr(inner) => match &**inner {
            Expr::Str(b) => b.len() as i64 + 1,
            _ => return None,
        },
        _ => return None,
    })
}

fn const_eval_unsigned_bytes(e: &Expr) -> Option<u8> {
    match e {
        Expr::Int(v) => {
            if !(i32::MIN as i64..=u32::MAX as i64).contains(v) && *v < 0 {
                Some(8)
            } else {
                None
            }
        }
        Expr::Cast {
            ty: Type::Int {
                bytes,
                signed: false,
            },
            ..
        } => Some(*bytes),
        Expr::Cast { .. } => None,
        Expr::Unary { op, expr } => match op {
            UnOp::LogNot => None,
            UnOp::Neg | UnOp::Pos | UnOp::BitNot => const_eval_unsigned_bytes(expr),
            _ => None,
        },
        Expr::Cond { then, els, .. } => max_unsigned_bytes(
            const_eval_unsigned_bytes(then),
            const_eval_unsigned_bytes(els),
        ),
        Expr::Binary { op, lhs, rhs, .. } => match op {
            BinOp::Shl | BinOp::Shr => const_eval_unsigned_bytes(lhs),
            BinOp::Add
            | BinOp::Sub
            | BinOp::Mul
            | BinOp::Div
            | BinOp::Mod
            | BinOp::BitAnd
            | BinOp::BitOr
            | BinOp::BitXor => max_unsigned_bytes(
                const_eval_unsigned_bytes(lhs),
                const_eval_unsigned_bytes(rhs),
            ),
            BinOp::Comma => const_eval_unsigned_bytes(rhs),
            _ => None,
        },
        _ => None,
    }
}

fn max_unsigned_bytes(lhs: Option<u8>, rhs: Option<u8>) -> Option<u8> {
    match (lhs, rhs) {
        (Some(lhs), Some(rhs)) => Some(lhs.max(rhs)),
        (Some(bytes), None) | (None, Some(bytes)) => Some(bytes),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;

    fn parse(src: &str) -> PResult<TranslationUnit> {
        let toks = Lexer::tokenize(src.as_bytes()).expect("lex ok");
        Parser::parse(&toks)
    }

    fn func<'a>(tu: &'a TranslationUnit, name: &str) -> &'a Function {
        tu.items
            .iter()
            .find_map(|i| match i {
                Item::Func(f) if f.name == name => Some(f),
                _ => None,
            })
            .expect("function")
    }

    fn parse_ret(src: &str) -> Expr {
        let body = format!("int main(void) {{ return {src}; }}");
        let tu = parse(&body).expect("parse ok");
        match &func(&tu, "main").body[0] {
            Stmt::Return(Some(e), _) => e.clone(),
            other => panic!("expected return, got {other:?}"),
        }
    }

    // ---- J-14 ext: multi-segment qualified-id in `&` (OWL streamable) -----

    /// Extract the `init` expression of a file-scope global by name.
    fn global_init<'a>(tu: &'a TranslationUnit, name: &str) -> &'a Expr {
        tu.items
            .iter()
            .find_map(|i| match i {
                Item::Global {
                    name: n,
                    init: Some(e),
                    ..
                } if n == name => Some(e),
                _ => None,
            })
            .expect("global with initializer")
    }

    #[test]
    fn address_of_three_segment_qualified_member_parses() {
        // The OWL `IMPLEMENT_STREAMABLE` registration uses `&cls::Streamer::Build`
        // — a nested class's static member. The previous fixed-shape parse
        // consumed only `&Class::method` and left the trailing `::Build`, so the
        // caller choked ("expected ')'" at OBJSTRM.H:1296 across 31 OWL files).
        let tu = parse("struct A { struct B { static int C(); }; }; void* g = &A::B::C;")
            .expect("parse ok");
        match global_init(&tu, "g") {
            Expr::AddressOfMember { class, method, .. } => {
                assert_eq!(class, "A::B", "all-but-last joined by :: is the class");
                assert_eq!(method, "C", "the last component is the method");
            }
            other => panic!("expected AddressOfMember, got {other:?}"),
        }
    }

    #[test]
    fn address_of_two_segment_qualified_member_unchanged() {
        // The 2-segment form must parse byte-identically to before the
        // multi-segment loop was added (`class == "A"`, `method == "C"`).
        let tu = parse("struct A { static int C(); }; void* g = &A::C;").expect("parse ok");
        match global_init(&tu, "g") {
            Expr::AddressOfMember { class, method, .. } => {
                assert_eq!(class, "A");
                assert_eq!(method, "C");
            }
            other => panic!("expected AddressOfMember, got {other:?}"),
        }
    }

    #[test]
    fn dynamic_cast_parses_to_a_dynamic_cast_node() {
        // S4.5: `dynamic_cast<T*>(e)` now PARSES into `Expr::DynamicCast` (it
        // was previously a parse-reject). Codegen of the runtime checked
        // downcast is the next RTTI increment; until then codegen errors
        // cleanly (never a silent plain-cast lowering). Here we only assert the
        // PARSE shape — a `DynamicCast` node with the target type and operand.
        let tu = parse("struct B{}; struct D: B{}; D* f(B* b){ return dynamic_cast<D*>(b); }")
            .expect("dynamic_cast must parse");
        let f = tu
            .items
            .iter()
            .find_map(|i| match i {
                Item::Func(f) if f.name == "f" => Some(f),
                _ => None,
            })
            .expect("function f");
        let has_dc = format!("{:?}", f.body).contains("DynamicCast");
        assert!(has_dc, "f's body should contain a DynamicCast node");
    }

    // ---- non-type template parameters (OWL LAYOUTCO / OCF AUTODEFS) -------

    #[test]
    fn non_type_template_parameter_class_template_is_accepted() {
        // OWL `template<TWidthHeight widthOrHeight> struct TEdgeOrSizeConstraint`
        // (LAYOUTCO.H:130) and OCF `template<int N> struct TAutoArgs`
        // (AUTODEFS.H:1005). A non-type (value) parameter: the class-template
        // body is captured as tokens, so the declaration must PARSE (the value
        // binds at instantiation, which is deferred). Previously a hard error
        // ("templates support only class/typename type parameters").
        parse(
            "template<int N> struct Arr { int data[N]; int n(){ return N; } }; \
             int main(void){ return 0; }",
        )
        .expect("non-type-param class template declaration parses");
        // Mixed type + non-type parameters in one list.
        parse(
            "template<class T, unsigned Sz> struct Vec { T data[Sz]; }; \
             int main(void){ return 0; }",
        )
        .expect("mixed type + non-type params parse");
    }

    #[test]
    fn non_type_template_argument_instantiation_binds_the_value() {
        // S6 (#22): binding a VALUE at instantiation now WORKS (was a deferred
        // clean error). `Arr<4>` instantiates with N=4 — the value binds as a
        // scoped enum-constant, so `int data[N]` folds to `int data[4]`. The
        // RUN-behaviour (distinct instantiations, array sizes, value uses) is
        // covered by tests/end_to_end.rs::non_type_template_parameters_bind_values.
        parse(
            "template<int N> struct Arr { int data[N]; }; \
             int main(void){ Arr<4> a; a.data[0]=9; return a.data[0]; }",
        )
        .expect("value-arg instantiation binds the value (#22)");
    }

    // ---- S4.1a: function-template capture ---------------------------------

    #[test]
    fn function_template_is_captured_with_param_typed_signature() {
        let tu = parse(
            "template<class T> T maxv(T a, T b){ return a>b?a:b; } \
             int main(void){ return 0; }",
        )
        .expect("parse ok");
        // The template is captured separately, NOT emitted as a normal item.
        assert!(
            !tu.items
                .iter()
                .any(|i| matches!(i, Item::Func(f) if f.name == "maxv")),
            "the generic template must not appear in tu.items"
        );
        assert_eq!(tu.fn_templates.len(), 1, "one function template captured");
        let t = &tu.fn_templates[0];
        assert_eq!(t.params, vec!["T".to_string()]);
        assert_eq!(t.func.name, "maxv");
        // Return + both params are the template parameter T.
        assert_eq!(t.func.ret, Type::TemplateParam("T".into()));
        assert_eq!(t.func.params.len(), 2);
        assert!(
            t.func
                .params
                .iter()
                .all(|(_, ty)| *ty == Type::TemplateParam("T".into())),
            "both params must be Type::TemplateParam(T)"
        );
    }

    #[test]
    fn function_template_multiple_params_and_default() {
        let tu = parse(
            "template<class A, typename B = int> A pick(A a, B b){ return a; } \
             int main(void){ return 0; }",
        )
        .expect("parse ok");
        assert_eq!(tu.fn_templates.len(), 1);
        let t = &tu.fn_templates[0];
        assert_eq!(t.params, vec!["A".to_string(), "B".to_string()]);
        assert_eq!(t.func.ret, Type::TemplateParam("A".into()));
        assert_eq!(t.func.params[0].1, Type::TemplateParam("A".into()));
        assert_eq!(t.func.params[1].1, Type::TemplateParam("B".into()));
    }

    #[test]
    fn template_param_scope_does_not_leak() {
        // `T` must NOT remain a known type name after the template — a later
        // `T` is an ordinary identifier, so `int T;` is a valid declaration.
        let tu = parse(
            "template<class T> T id(T a){ return a; } \
             int main(void){ int T; T = 5; return T; }",
        )
        .expect("parse ok — template parameter scope must not leak");
        assert_eq!(tu.fn_templates.len(), 1);
    }

    #[test]
    fn empty_translation_unit_is_accepted() {
        // S5: a TU that preprocesses to nothing is VALID (C++ permits it; bcc32
        // emits an empty `.obj`). Borland's 16-bit-only HEAPSEL.CPP / MEMMGR.CPP
        // sit entirely behind `#if !defined(__FLAT__)`, so under mdbcc's 32-bit
        // `__FLAT__` target they are empty — mdbcc must accept them, not error
        // "expected a declaration".
        let tu = parse("").expect("an empty translation unit must parse");
        assert!(tu.items.is_empty());
        assert!(
            parse("// only a comment\n").is_ok(),
            "a comment-only translation unit must parse"
        );
    }

    // ---- S4.2(a): placement / array new -----------------------------------

    fn main_decl_init(tu: &TranslationUnit) -> &Expr {
        let f = func(tu, "main");
        f.body
            .iter()
            .find_map(|s| match s {
                Stmt::Decl { init: Some(e), .. } => Some(e),
                _ => None,
            })
            .expect("a local declaration with an initializer in main")
    }

    #[test]
    fn placement_new_captures_placement_args() {
        let tu = parse("int main(){ char b[8]; int* p = new(b) int(5); return 0; }")
            .expect("placement-new must parse");
        match main_decl_init(&tu) {
            Expr::New {
                placement, args, ..
            } => {
                assert_eq!(placement.len(), 1, "one placement arg (b)");
                assert_eq!(args.len(), 1, "one ctor arg (5)");
            }
            other => panic!("expected Expr::New, got {other:?}"),
        }
    }

    #[test]
    fn placement_array_new_captures_placement() {
        let tu = parse("int main(){ char b[8]; int* p = new(b) int[4]; return 0; }")
            .expect("placement array-new must parse");
        match main_decl_init(&tu) {
            Expr::NewArray { placement, .. } => {
                assert_eq!(placement.len(), 1, "one placement arg (b)");
            }
            other => panic!("expected Expr::NewArray, got {other:?}"),
        }
    }

    #[test]
    fn parenthesized_type_new_has_no_placement() {
        // `new (int)` is the parenthesised-TYPE form, NOT placement.
        let tu = parse("int main(){ int* p = new(int); return 0; }").expect("new(int) must parse");
        match main_decl_init(&tu) {
            Expr::New { placement, .. } => {
                assert!(placement.is_empty(), "new(int) has no placement args");
            }
            other => panic!("expected Expr::New, got {other:?}"),
        }
    }

    #[test]
    fn class_template_definition_is_captured_cleanly() {
        // S4.2b(i): a class-template DEFINITION is captured by skipping its
        // tokens, so it parses cleanly — never an error and never a panic (a
        // bare `T v;` member used to crash `size_for`; the capture path doesn't
        // parse the body at all). Instantiation at use sites is a later stage.
        let tu = parse("template<class T> struct Box { T v; }; int main(){return 0;}")
            .expect("a class-template definition parses (captured, not emitted)");
        // `main` is intact, and the generic did NOT pollute the record table
        // with a concrete `Box` tag (it was skipped, not parsed).
        let _ = func(&tu, "main");
        assert!(
            !tu.records.iter().any(|r| r.tag.as_deref() == Some("Box")),
            "the generic class template must not register a concrete record"
        );
    }

    #[test]
    fn minimal_function() {
        let tu = parse("int main(void) { return 42; }").unwrap();
        let f = func(&tu, "main");
        assert_eq!(f.ret, Type::int());
        // The Return's loc is the column of `return` on the synthesized line —
        // we don't pin the exact value here (it's tied to fixture formatting),
        // only the structural shape.
        assert!(matches!(&f.body[0], Stmt::Return(Some(Expr::Int(42)), _)));
    }

    #[test]
    fn pointer_and_array_types() {
        let tu = parse(
            "int main(void){ char *p; int a[10]; char buf[]=\"hi\"; \
             unsigned long x; return 0; }",
        )
        .unwrap();
        let b = &func(&tu, "main").body;
        assert!(matches!(&b[0], Stmt::Decl { ty: Type::Ptr(p), .. } if **p == Type::char_()));
        assert!(matches!(&b[1], Stmt::Decl { ty: Type::Array(e, 10), .. } if **e == Type::int()));
        assert!(matches!(
            &b[2],
            Stmt::Decl {
                ty: Type::Array(_, 3),
                ..
            }
        )); // "hi"+NUL
        assert!(matches!(
            &b[3],
            Stmt::Decl {
                ty: Type::Int {
                    bytes: 4,
                    signed: false
                },
                ..
            }
        ));
    }

    #[test]
    fn function_with_typed_params_and_pointer_return() {
        let tu = parse("char *dup(char *s, int n) { return s; }").unwrap();
        let f = func(&tu, "dup");
        assert_eq!(f.ret, Type::Ptr(Box::new(Type::char_())));
        assert_eq!(f.params[0].1, Type::Ptr(Box::new(Type::char_())));
        assert_eq!(f.params[1].1, Type::int());
    }

    #[test]
    fn calling_convention_captured_on_free_functions() {
        // S2b.3: the convention keyword sits between return type and name
        // (the common Borland form); the parser records it on the Function.
        let tu = parse(
            "int __cdecl    ac(int a){ return a; }\
             int __stdcall  as(int a){ return a; }\
             int __fastcall af(int a){ return a; }\
             int __pascal   ap(int a){ return a; }\
             int            plain(int a){ return a; }",
        )
        .unwrap();
        assert_eq!(func(&tu, "ac").calling_conv, Some(CallConv::Cdecl));
        assert_eq!(func(&tu, "as").calling_conv, Some(CallConv::Stdcall));
        assert_eq!(func(&tu, "af").calling_conv, Some(CallConv::Fastcall));
        assert_eq!(func(&tu, "ap").calling_conv, Some(CallConv::Pascal));
        // No keyword ⇒ None (target default applies at codegen time).
        assert_eq!(func(&tu, "plain").calling_conv, None);
    }

    #[test]
    fn calling_convention_leading_position_and_underscore_variants() {
        // Leading position (`__stdcall int f()`) and single-underscore
        // spellings both fold to the same CallConv. Params re-enter
        // decl_specifiers but must not clobber the captured convention.
        let tu = parse(
            "__stdcall int lead(int a, int b){ return a + b; }\
             int _cdecl underscore(int a){ return a; }",
        )
        .unwrap();
        assert_eq!(func(&tu, "lead").calling_conv, Some(CallConv::Stdcall));
        assert_eq!(func(&tu, "underscore").calling_conv, Some(CallConv::Cdecl));
    }

    #[test]
    fn global_variables() {
        let tu = parse("int g = 7; char *msg = \"hi\"; int main(void){ return g; }").unwrap();
        assert!(matches!(
            &tu.items[0],
            Item::Global { name, init: Some(Expr::Int(7)), .. } if name == "g"
        ));
        assert!(matches!(&tu.items[1], Item::Global { .. }));
    }

    #[test]
    fn prototype_is_discarded_but_definition_kept() {
        let tu = parse("int add(int, int); int add(int a,int b){return a+b;}").unwrap();
        assert_eq!(tu.items.len(), 1);
    }

    #[test]
    fn unary_address_deref_index_sizeof_cast() {
        assert!(matches!(
            parse_ret("&x"),
            Expr::Unary { op: UnOp::Addr, .. }
        ));
        assert!(matches!(
            parse_ret("*p"),
            Expr::Unary {
                op: UnOp::Deref,
                ..
            }
        ));
        assert!(matches!(parse_ret("a[2]"), Expr::Index { .. }));
        assert_eq!(parse_ret("sizeof(int)"), Expr::SizeofType(Type::int()));
        assert_eq!(
            parse_ret("sizeof(char*)"),
            Expr::SizeofType(Type::Ptr(Box::new(Type::char_())))
        );
        assert!(matches!(parse_ret("(char)x"), Expr::Cast { .. }));
    }

    #[test]
    fn ternary_and_incdec_and_compound_assign() {
        assert!(matches!(parse_ret("a ? 1 : 2"), Expr::Cond { .. }));
        assert!(matches!(
            parse_ret("i++"),
            Expr::IncDec {
                inc: true,
                pre: false,
                ..
            }
        ));
        assert!(matches!(
            parse_ret("--i"),
            Expr::IncDec {
                inc: false,
                pre: true,
                ..
            }
        ));
        // x += 2  =>  x = x + 2
        match parse_ret("x += 2") {
            Expr::Assign { rhs, .. } => {
                assert!(matches!(*rhs, Expr::Binary { op: BinOp::Add, .. }))
            }
            _ => panic!("expected assign"),
        }
    }

    #[test]
    fn precedence_still_holds() {
        // J-8b (tick 74): the inner Binary nodes now carry source-loc
        // metadata which makes structural assert_eq! awkward. We pin the
        // shape via a nested `matches!` so any future loc semantic
        // (e.g. tracking the operator column) doesn't churn this lock.
        let e = parse_ret("2 + 3 * 4");
        let Expr::Binary {
            op: BinOp::Add,
            lhs,
            rhs,
            ..
        } = e
        else {
            panic!("expected Add at root, got {e:?}");
        };
        assert!(matches!(*lhs, Expr::Int(2)));
        let Expr::Binary {
            op: BinOp::Mul,
            lhs: ml,
            rhs: mr,
            ..
        } = *rhs
        else {
            panic!("expected Mul on rhs");
        };
        assert!(matches!(*ml, Expr::Int(3)));
        assert!(matches!(*mr, Expr::Int(4)));
    }

    #[test]
    fn error_missing_semicolon() {
        // A missing `;` is still a hard error.
        assert!(parse("int main(void){ return 1 }").is_err());
        // (An EMPTY translation unit is NOW valid — see
        // `empty_translation_unit_is_accepted`. bcc32 emits an empty `.obj` for
        // the 16-bit-only CLASSLIB files that vanish under `__FLAT__`.)
    }

    #[test]
    fn derive_from_incomplete_base_is_a_clean_error_not_a_panic() {
        // Robustness: deriving from a base whose ClassInfo was never captured (a
        // forward-declared / not-yet-defined base) must yield a CLEAN diagnostic,
        // never a panic at the downstream `self.classes[&bid]` accesses
        // (CLASSLIB/TMPLINST.CPP hit this on a not-yet-captured base). bcc32 also
        // rejects an incomplete base.
        let err = parse("class Fwd; class D : public Fwd { int x; }; int main(void){return 0;}")
            .expect_err("deriving from an incomplete base must be an error");
        assert!(
            err.message.contains("not fully defined"),
            "expected an incomplete-base diagnostic, got: {}",
            err.message
        );
    }

    #[test]
    fn struct_layout_natural_alignment() {
        // char(0), int aligned to 4 -> offset 4, size 8.
        let tu = parse("struct S { char c; int i; }; int main(void){ return 0; }").unwrap();
        let r = &tu.records[0];
        assert_eq!(r.tag.as_deref(), Some("S"));
        assert_eq!(r.fields[0].offset, 0);
        assert_eq!(r.fields[1].offset, 4);
        assert_eq!((r.size, r.align), (8, 4));
    }

    #[test]
    fn union_layout_overlaps() {
        let tu = parse("union U { int i; char c[8]; }; int main(void){return 0;}").unwrap();
        let r = &tu.records[0];
        assert!(r.is_union);
        assert_eq!(r.fields[0].offset, 0);
        assert_eq!(r.fields[1].offset, 0);
        assert_eq!(r.size, 8);
    }

    #[test]
    fn self_referential_record_resolves() {
        let tu = parse("struct N { int v; struct N *next; }; int main(void){return 0;}").unwrap();
        let r = &tu.records[0];
        match &r.fields[1].ty {
            Type::Ptr(inner) => {
                assert!(matches!(**inner, Type::Record { id: 0, .. }))
            }
            other => panic!("expected struct N*, got {other:?}"),
        }
    }

    #[test]
    fn typedef_alias_used_as_type() {
        let tu = parse(
            "typedef unsigned char byte; byte gb; \
             int main(void){ byte x; x = 1; return x; }",
        )
        .unwrap();
        // `byte gb;` is a global of the aliased type.
        assert!(matches!(
            &tu.items[0],
            Item::Global {
                ty: Type::Int {
                    bytes: 1,
                    signed: false
                },
                ..
            }
        ));
    }

    #[test]
    fn enum_constants_fold_to_ints() {
        // GREEN=5 then BLUE=6; used in a constant array size.
        let tu = parse(
            "enum E { RED, GREEN = 5, BLUE }; \
             int main(void){ int a[BLUE]; return sizeof(a); }",
        )
        .unwrap();
        match &func(&tu, "main").body[0] {
            Stmt::Decl {
                ty: Type::Array(_, 6),
                ..
            } => {}
            other => panic!("expected int[6], got {other:?}"),
        }
    }

    #[test]
    fn member_access_parses() {
        assert!(matches!(
            parse_ret("p->next->val"),
            Expr::Member { arrow: true, .. }
        ));
        assert!(matches!(
            parse_ret("s.a.b"),
            Expr::Member { arrow: false, .. }
        ));
    }

    // ---- S3: real-header C declaration forms (parse-acceptance ratchet) ----

    #[test]
    fn bitfield_members_parse() {
        // Named + anonymous bit-fields (WINNT.H `_LDT_ENTRY`, IO.H `ftime`).
        // SYNTAX accepted; named ones become full-width members, anonymous are
        // dropped (sub-byte packing deferred).
        let tu = parse(
            "struct B { unsigned a : 3; unsigned : 2; unsigned b : 1; int : 0; }; \
             int main(void){ return 0; }",
        )
        .unwrap();
        let r = &tu.records[0];
        // Only the two NAMED bit-fields contribute fields here.
        let names: Vec<&str> = r.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn import_qualifier_accepted() {
        // `__import` (Borland dllimport) is an accept-and-ignore declarator
        // qualifier, like `__export`. `WINAPI` == `__stdcall __import`.
        let tu = parse("int __stdcall __import f(int a){ return a; }").unwrap();
        assert_eq!(func(&tu, "f").calling_conv, Some(CallConv::Stdcall));
    }

    /// Resolve the type of a file-scope global named `name` (typedefs are an
    /// internal parser map, so the new typedef forms are observed by USING the
    /// alias on a global and inspecting the global's resolved type).
    fn global_ty<'a>(tu: &'a TranslationUnit, name: &str) -> &'a Type {
        tu.items
            .iter()
            .find_map(|i| match i {
                Item::Global { name: n, ty, .. } if n == name => Some(ty),
                _ => None,
            })
            .expect("global")
    }

    #[test]
    fn grouped_fnptr_typedef_with_winapi_quals() {
        // `int (__stdcall __import *FARPROC)()` — a run of qualifiers between
        // `(` and `*`. FARPROC aliases a pointer-to-function; observe via a
        // global of that type.
        let tu = parse(
            "typedef int (__stdcall __import *FARPROC)(int); FARPROC fp; \
             int main(void){ return 0; }",
        )
        .unwrap();
        match global_ty(&tu, "fp") {
            Type::Ptr(inner) => assert!(matches!(**inner, Type::Func { .. })),
            other => panic!("expected ptr-to-func, got {other:?}"),
        }
    }

    #[test]
    fn east_const_pointer_typedef() {
        // `typedef T const *PCT;` — a cv-qualifier between a typedef-name base
        // and the `*` (the Win32 SDK's `MENUITEMINFOA const *LPCMENUITEMINFOA`).
        let tu = parse(
            "typedef int MIA; typedef MIA const *PMIA; PMIA p; \
             int main(void){ return 0; }",
        )
        .unwrap();
        match global_ty(&tu, "p") {
            Type::Ptr(inner) => assert_eq!(**inner, Type::int()),
            other => panic!("expected ptr-to-int, got {other:?}"),
        }
    }

    #[test]
    fn function_type_typedef_plain_and_grouped() {
        // `typedef RET NAME(params);` (QUERYHANDLER) and the parenthesised
        // `typedef RET (NAME)(params);` (HPPROVIDERINIT) + conv-bearing
        // `typedef void (__stdcall NAME)(params);` (DRVCALLBACK) forms — all
        // alias a function TYPE. Observe each by declaring a POINTER global of
        // that type (`QH *`), which must resolve to Ptr(Func).
        let tu = parse(
            "typedef int QH(int, long); QH *pqh; \
             typedef int (HP)(int); HP *php; \
             typedef void (__stdcall DRV)(int); DRV *pdrv; \
             int main(void){ return 0; }",
        )
        .unwrap();
        for n in ["pqh", "php", "pdrv"] {
            match global_ty(&tu, n) {
                Type::Ptr(inner) => assert!(
                    matches!(**inner, Type::Func { .. }),
                    "{n} should be ptr-to-func, got {inner:?}"
                ),
                other => panic!("{n}: expected ptr-to-func, got {other:?}"),
            }
        }
    }

    #[test]
    fn bare_fn_type_paren_gated_to_typedef_context() {
        // The bare-name function-type branch (`( NAME )( params )`) is gated on
        // `is_typedef`, so it only fires for `typedef int (HP)(int);`. A
        // non-typedef `int (foo)(int);` keeps its historical handling untouched
        // (the flat declarator never supported a leading `(` here, so this
        // still errors rather than being silently miscaptured as a global).
        assert!(
            parse("int (foo)(int); int main(void){ return 0; }").is_err(),
            "redundant-paren prototype must keep its historical (error) behaviour"
        );
        // …while the typedef form parses (covered by
        // `function_type_typedef_plain_and_grouped`). Confirm the gate does not
        // leak: the conv-bearing form is accepted in BOTH contexts (it is
        // unambiguous), but the bare form must not turn `int (foo)(int);` into a
        // function-typed global.
    }

    #[test]
    fn anonymous_union_member_parses() {
        // `union { ... } ;` with no member name (MAPI `DTPAGE`, OWL `TMessage`).
        // S5: the anonymous aggregate is kept as an unnamed `$anon.N` field
        // (N = its index when added) so `layout()` sizes/offsets it; codegen's
        // `field_of` recurses into `$anon.*` so `S.i` / `S.s` resolve at the
        // union's offset. The marker name can't collide with a real member
        // (`$` cannot begin a C identifier).
        let tu = parse(
            "struct S { int tag; union { int i; char *s; }; int after; }; \
             int main(void){ return 0; }",
        )
        .unwrap();
        let r = &tu.records[0];
        let names: Vec<&str> = r.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["tag", "$anon.1", "after"]);
    }

    // ---- S3: `extern "C"` linkage-specifications (C++ §7.5) ---------------

    /// Find a body-less prototype registered under `name`.
    fn proto<'a>(tu: &'a TranslationUnit, name: &str) -> &'a Function {
        tu.extern_protos
            .iter()
            .find(|f| f.name == name)
            .expect("prototype")
    }

    #[test]
    fn extern_c_block_prototype_has_c_linkage() {
        // The headline real-header form: a prototype wrapped in an
        // `extern "C" { ... }` block parses (reusing the proto machinery) and
        // is flagged C-linkage so the mangler emits `_addc`.
        let tu = parse("extern \"C\" { int addc(int, int); }\nint main(void){return 0;}").unwrap();
        let p = proto(&tu, "addc");
        assert!(p.c_linkage, "extern \"C\" prototype must be C-linkage");
        assert_eq!(p.params.len(), 2);
    }

    #[test]
    fn extern_c_block_definition_has_c_linkage_and_runs() {
        // A definition inside the block lands in `items` with C linkage; a
        // caller in the same TU resolves it. Mirrors a declared+defined fn.
        let tu = parse(
            "extern \"C\" { int addc(int a, int b) { return a + b; } }\n\
             int main(void){ return addc(2, 4); }",
        )
        .unwrap();
        let f = func(&tu, "addc");
        assert!(f.c_linkage, "extern \"C\" definition must be C-linkage");
        // `main` itself is outside the block → ordinary (non-C) linkage flag.
        assert!(!func(&tu, "main").c_linkage);
    }

    #[test]
    fn extern_c_single_declaration_form() {
        // No braces: `extern "C"` applies to exactly one following decl.
        let tu = parse("extern \"C\" int subc(int, int);\nint main(void){return 0;}").unwrap();
        assert!(proto(&tu, "subc").c_linkage);
    }

    #[test]
    fn extern_c_block_with_many_decls() {
        // A multi-declaration block (the common header shape: a run of
        // prototypes) — every prototype is C-linkage.
        let tu = parse(
            "extern \"C\" {\n\
               int    f1(int);\n\
               long   f2(long, long);\n\
               void   f3(void);\n\
             }\nint main(void){return 0;}",
        )
        .unwrap();
        for n in ["f1", "f2", "f3"] {
            assert!(proto(&tu, n).c_linkage, "{n} must be C-linkage");
        }
    }

    #[test]
    fn nested_extern_c_is_tolerated() {
        // `extern "C"` inside `extern "C"` (some headers `#include` one
        // another's already-wrapped declarations). Inner protos stay
        // C-linkage; the outer scope is restored on exit.
        let tu = parse(
            "extern \"C\" {\n\
               int outer(int);\n\
               extern \"C\" { int inner(int); }\n\
               int after(int);\n\
             }\nint main(void){return 0;}",
        )
        .unwrap();
        for n in ["outer", "inner", "after"] {
            assert!(proto(&tu, n).c_linkage, "{n} must be C-linkage");
        }
    }

    #[test]
    fn extern_cpp_inside_extern_c_turns_linkage_off() {
        // `extern "C++"` nested in `extern "C"` overrides linkage for its
        // own scope, and the outer C linkage is restored afterwards.
        let tu = parse(
            "extern \"C\" {\n\
               int c_one(int);\n\
               extern \"C++\" { int cpp_one(int); }\n\
               int c_two(int);\n\
             }\nint main(void){return 0;}",
        )
        .unwrap();
        assert!(proto(&tu, "c_one").c_linkage);
        assert!(
            !proto(&tu, "cpp_one").c_linkage,
            "extern \"C++\" ⇒ C++ linkage"
        );
        assert!(proto(&tu, "c_two").c_linkage, "outer C linkage restored");
    }

    #[test]
    fn plain_extern_is_undisturbed() {
        // The storage-class `extern` path (NOT followed by a string) is not
        // flagged C-linkage by the `extern "C"` code (top-level default `false`).
        // #24: `extern int g;` (no initializer) is a cross-TU DECLARATION —
        // Item::ExternGlobal, NOT a local Global definition (previously it
        // silently emitted a local zero `g`). `extern int ef(int);` stays a
        // (non-C-linkage) prototype.
        let tu = parse("extern int g;\nextern int ef(int);\nint main(void){return 0;}").unwrap();
        assert!(
            tu.items
                .iter()
                .any(|i| matches!(i, Item::ExternGlobal { name, .. } if name == "g"))
        );
        assert!(
            !proto(&tu, "ef").c_linkage,
            "plain extern proto stays non-C-linkage"
        );
    }
}
