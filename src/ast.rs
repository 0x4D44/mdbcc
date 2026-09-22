//! Abstract syntax tree and the C type model.
//!
//! Type sizes follow the Win64 (LLP64) model — `char`=1, `short`=2, `int`=4,
//! `long`=4, `long long`=8, pointer=8 — which is what lets rebuilt programs
//! run natively on modern Windows. (The faithful 16-bit DOS model, where
//! `int`=2, is a separate back-end target; see the scratchpad.)

/// Source-position attached to AST nodes for error diagnostics (J-8, tick 65).
///
/// Carries the 1-based line and column of the **first byte** of the construct
/// the node represents. A `Loc { line: 0, col: 0 }` (i.e. [`Loc::default()`])
/// indicates "no source location available" — synthetic / compiler-injected
/// nodes (such as the implicit `Stmt::SetVptr` inserted into a constructor
/// body) carry this sentinel and the codegen error helper drops the prefix
/// in that case so the message reads naturally for synthetic targets.
///
/// `Loc` is `Copy` so threading it through pattern destructures stays cheap;
/// it participates in `PartialEq`/`Eq`/`Hash` so AST equality is total (no
/// "node looks equal but has a different loc" subtle bugs in tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Loc {
    pub line: u32,
    pub col: u32,
}

impl Loc {
    /// True for synthetic / unsourced positions (`line == 0`). The codegen
    /// error helper uses this to suppress the `"line:col: "` prefix on a
    /// message whose target lacks a real source location (parser-injected
    /// SetVptr, default-constructed locs in tests, etc.).
    pub fn is_synthetic(&self) -> bool {
        self.line == 0
    }
}

/// A C type. `struct`/`union`/`enum`/`typedef`/function-pointer support is
/// added in a later slice; this models scalars, pointers and arrays.
///
/// **Eq vs PartialEq (Phase F-1 decision)**: `Type::Float` doesn't carry
/// `f64` directly (only `bytes: u8`), so it could derive `Eq` — but `Expr`
/// gains `Float { value: f64, .. }` which can't (NaN ≠ NaN). For symmetry
/// and to keep equality semantics consistent across the AST, both drop the
/// `Eq` derive and rely on `PartialEq` only. No `HashSet<Type>` / `HashMap<
/// Type, _>` / `HashSet<Expr>` exists in the tree (checked 2026-05-18), so
/// `Eq` was unused; `==` comparisons (which only need `PartialEq`) and
/// `assert_eq!` keep working unchanged.
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Void,
    /// Integer family. `bytes` ∈ {1,2,4,8}; `signed` selects sign behavior.
    Int {
        bytes: u8,
        signed: bool,
    },
    /// IEEE-754 binary scalar. `bytes` ∈ {4, 8} for `float`/`double`.
    /// **Storage and ABI are SSE2 / xmm-based** (Win64). 80-bit `long
    /// double` is explicitly deferred (Phase F-1 backlog): bcc32 5.5.1's
    /// 80-bit x87 backend has no Win64 SSE2 counterpart and no Phase F
    /// target needs it; `long double` is folded to `double` (bytes=8)
    /// at the parser boundary.
    Float {
        bytes: u8,
    },
    Ptr(Box<Type>),
    /// Fixed-size array of `elem`, decays to `Ptr(elem)` in value contexts.
    Array(Box<Type>, usize),
    /// A `struct`/`union`. `id` indexes [`TranslationUnit::records`];
    /// `size`/`align` are cached so [`Type::size`] stays registry-free.
    Record {
        id: usize,
        size: usize,
        align: usize,
    },
    /// A C++ reference `T&` — 8-byte storage holding the referent's address;
    /// expressions see it as `T` (an lvalue alias).
    Ref(Box<Type>),
    /// A function type `ret(params...)`. A function *designator* decays to
    /// `Ptr(Func{..})` in value contexts (like array→pointer decay), so the
    /// only storable form is `Ptr(Func)` (8 bytes).
    Func {
        ret: Box<Type>,
        params: Vec<Type>,
    },
    /// J-14 v1 (tick 62): a **member-function pointer** type
    /// `Ret (Class::*)(params...)`. Storable in 8 bytes (the function's
    /// absolute address — same shape as a regular fn pointer; the `class_id`
    /// is type-only metadata used by codegen to set up `this` at call
    /// sites). Virtual-target MFPs are rejected at the `&Class::method`
    /// construction site with a Grep-pinned deferral phrase (J-14b).
    MemFn {
        class_id: usize,
        ret: Box<Type>,
        params: Vec<Type>,
    },
    /// S4: a **template type parameter** (`T` in `template<class T> …`).
    /// Exists ONLY inside a captured-but-uninstantiated template body; every
    /// real codegen entity is a monomorphised instantiation in which each
    /// `TemplateParam` has been substituted by a concrete type. A
    /// `TemplateParam` reaching codegen (size/align/emit) is a bug — those
    /// arms are `unreachable!`.
    TemplateParam(String),
}

/// A `struct` or `union` definition with computed layout.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub tag: Option<String>,
    pub is_union: bool,
    pub fields: Vec<Field>,
    pub size: usize,
    pub align: usize,
    /// Single public base class (record id), if this class derives.
    pub base: Option<usize>,
    /// S4.2d: byte offset of the base subobject within this record. Normally 0
    /// (a `Derived*` is also a valid `Base*`). NON-zero only when a polymorphic
    /// class derives from a NON-polymorphic base that has data members: the
    /// vptr occupies `[0, ptr_bytes)` and the base subobject is pushed to
    /// `ptr_bytes`, so `Derived*→Base*` and a base-method `this` must add this
    /// offset (the Microsoft object model). Gated everywhere on `!= 0`, so all
    /// existing classes (base@0) stay byte-identical.
    pub base_offset: usize,
    /// S6 (G1 Stage-1, plain MI): the SECOND and subsequent direct bases of a
    /// multiply-inheriting class (`struct C : A, B` → `base` = A,
    /// `extra_bases` = [B@offset]). Each extra base's subobject is appended
    /// AFTER `[primary ++ own]` content at `align_up(size, b.align)` with its
    /// fields flattened into `fields` at `offset + b-relative` (the flat class
    /// model) — a layout self-consistent across an all-mdbcc link ([A][own][B],
    /// not Borland's [A][B][own]; no bcc-object interop exists to observe it).
    /// Empty for every single-inheritance class ⇒ all existing layouts,
    /// lookups, and the 88 byte-identity baselines are untouched. Stage-1
    /// restricts extras to NON-polymorphic bases (no secondary vptr/thunks)
    /// and NON-virtual inheritance — both rejected with clean errors at the
    /// class definition.
    pub extra_bases: Vec<BaseSpec>,
    /// S6 (G1 Stage-1): true when this class's MI shape exceeds Stage-1 (an
    /// extra base over a VIRTUAL-inheritance hierarchy — the iostream diamond
    /// — or a POLYMORPHIC extra base needing a secondary vptr + thunks). The
    /// extra bases were DROPPED from the model (the pre-Stage-1 behavior, so
    /// TUs that merely parse the class header keep compiling), and every
    /// CONSTRUCTION site (local, `new`, placement-new, array-new) rejects the
    /// class with a clean diagnostic instead of building a missing-subobject
    /// object — never a silent miscompile.
    pub mi_dropped: bool,
    /// Virtual-method table (Phase B). Empty ⇒ non-polymorphic: no vptr,
    /// layout/dispatch byte-identical to pre-Phase-B. Non-empty ⇒ a hidden
    /// vptr occupies bytes `[0,8)` (all data-member offsets are +8) and slot
    /// order is base-virtuals-first then this class's new virtuals; an
    /// override replaces the inherited slot's `sym`.
    pub vtable: Vec<VtSlot>,
    /// S6 (G1 Stage-3): SHARED virtual bases (the iostream `ios` diamond),
    /// appended ONCE at the object tail (deduplicated across the whole
    /// hierarchy). Empty for every non-virtual-inheriting class ⇒ layout, ctor,
    /// member access all byte-identical. See [`VBase`].
    pub vbases: Vec<VBase>,
    /// S6 (G1 Stage-3): byte offset of EVERY vbptr field in this complete
    /// object — one per subobject that DIRECTLY virtually-derives a vbase —
    /// paired with the vbase record id it points to (`(vbase_id, field_off)`).
    /// The construction site stores `this + vbase.offset` into each. Empty ⇒
    /// no vbptrs (byte-identical).
    pub vbptr_offsets: Vec<(usize, usize)>,
}

/// S6 (G1 Stage-3): a SHARED virtual base of a class. The single-vbase scope
/// (the iostream `ios` diamond is the only one in railc/OWL/RTL): `ios` appears
/// once, shared across `istream`/`ostream`/`fstreambase`. `id` = the vbase
/// record; `offset` = byte offset of the shared vbase subobject within this
/// class laid out as the MOST-DERIVED object (tail); `vbptr_offset` = the
/// canonical byte offset, within this class, of a vbptr field pointing to the
/// shared vbase (used for member access + a `Derived*`→vbase upcast — both
/// MANDATORY indirections, since a base-typed `this` cannot use a static
/// offset to reach a shared vbase).
#[derive(Debug, Clone, PartialEq)]
pub struct VBase {
    pub id: usize,
    pub offset: usize,
    pub vbptr_offset: usize,
}

/// S6 (G1 Stage-1): one EXTRA direct base (the 2nd..nth of a multiply-
/// inheriting class) — its record id and the byte offset of its subobject
/// within the derived object. A `Derived*` → this base's pointer conversion
/// adds `offset`; a method of this base runs on `this + offset`.
#[derive(Debug, Clone, PartialEq)]
pub struct BaseSpec {
    pub id: usize,
    pub offset: usize,
    /// S6 (G1 Stage-2): for a POLYMORPHIC extra base, the SYNTHETIC record id
    /// whose `vtable` is the derived class's SECONDARY vtable for this base
    /// subobject (slot keys mirror the base's vtable; a slot the derived
    /// class overrides points at a this-adjusting THUNK symbol
    /// `<Derived>::$thunk$<n>$<key>`, the rest inherit the base's syms). The
    /// derived ctor's SetVptr installs `RipRef::Vtable(sec)` at
    /// `[this+offset]` — the synthetic id rides the existing record-id-keyed
    /// vtable machinery end-to-end (codegen, COFF, linker) with no new
    /// relocation kinds. `None` for a non-polymorphic extra base.
    pub sec_vtable: Option<usize>,
}

/// One virtual-table slot. Slot index is the position in [`Record::vtable`]
/// and is stable across a single-inheritance hierarchy (a derived class keeps
/// the base's slot indices and only swaps `sym` for overrides).
#[derive(Debug, Clone, PartialEq)]
pub struct VtSlot {
    /// Dispatch key: the method name, or `"~"` for the (one) virtual
    /// destructor slot. Matched by name (single inheritance, no virtual
    /// overloading in this subset) to find a call's slot index.
    pub key: String,
    /// Explicit parameter types, excluding the implicit `this`. Kept on the
    /// slot so calls through pure virtual declarations can still marshal
    /// reference/scalar parameters correctly even though there is no concrete
    /// function definition in `sigs.funcs`.
    pub params: Vec<Type>,
    /// Mangled function symbol to place in this slot for this class
    /// (`Tag::name` / `Tag::~Tag`). Empty ⇒ pure (unimplemented): the class
    /// is abstract and the slot is filled with a "pure virtual called" trap.
    pub sym: String,
}

impl Record {
    /// Polymorphic ⇒ has a vptr at offset 0 (data members shifted +8).
    pub fn is_polymorphic(&self) -> bool {
        !self.vtable.is_empty()
    }
    /// Abstract ⇒ at least one pure (unimplemented) virtual slot remains;
    /// instantiating it must be a clean `CodegenError`.
    pub fn is_abstract(&self) -> bool {
        self.vtable.iter().any(|s| s.sym.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: String,
    pub ty: Type,
    pub offset: usize,
}

impl Type {
    pub const fn int() -> Type {
        Type::Int {
            bytes: 4,
            signed: true,
        }
    }
    pub const fn char_() -> Type {
        Type::Int {
            bytes: 1,
            signed: true,
        }
    }

    /// `sizeof` in bytes, **Win64 (LLP64)**: pointers are 8 bytes. This is the
    /// historical default; callers that are inherently Win64 (or that read a
    /// `Type::Record`'s already-laid-out cache) use it unchanged. The
    /// target-aware path uses [`Type::size_for`].
    pub fn size(&self) -> usize {
        self.size_for(8)
    }

    /// `sizeof` in bytes for a target whose pointer width is `ptr_bytes` (8 on
    /// Win64/LLP64, 4 on Win32/ILP32). `sizeof(void)` is 1 (Borland/GCC
    /// extension, handy for `void*` arithmetic).
    ///
    /// Only pointer-shaped types (`Ptr`/`Ref`/`Func`/`MemFn`) and aggregates
    /// that *transitively contain* one depend on `ptr_bytes`. A `Type::Record`
    /// reads its cached `size`, which the parser already laid out with the
    /// correct `ptr_bytes` for the active target (see `parser::layout`), so the
    /// cache is authoritative and `ptr_bytes` is not re-applied here.
    pub fn size_for(&self, ptr_bytes: usize) -> usize {
        match self {
            Type::Void => 1,
            Type::Int { bytes, .. } => *bytes as usize,
            Type::Float { bytes } => *bytes as usize,
            Type::Ptr(_) => ptr_bytes,
            Type::Array(e, n) => e.size_for(ptr_bytes) * n,
            Type::Record { size, .. } => *size,
            Type::Ref(_) => ptr_bytes,
            // `sizeof` a function is invalid C; a fn pointer is `ptr_bytes`.
            // Returning it keeps any accidental slot sane (we only ever store
            // Ptr(Func)).
            Type::Func { .. } => ptr_bytes,
            // J-14 v1: a member-function pointer is just the absolute function
            // address (non-virtual targets only; virtual-target construction is
            // rejected), so it is one pointer wide.
            Type::MemFn { .. } => ptr_bytes,
            // S4: a template parameter has no real size until a monomorphised
            // instantiation substitutes it for a concrete type. It is only
            // queried here on the (currently unsupported) CLASS-template path,
            // where the parser provisionally lays out a generic record before
            // codegen rejects it with a clean "class templates deferred to
            // S4.2" error — so return a harmless placeholder (`ptr_bytes`)
            // rather than panicking. A FUNCTION template substitutes every
            // TemplateParam before any size query, so this is never reached on
            // the supported (S4.1) path.
            Type::TemplateParam(_) => ptr_bytes,
        }
    }

    /// Natural alignment, **Win64**: see [`Type::size`]. [`Type::align_for`] is
    /// the target-aware form.
    pub fn align(&self) -> usize {
        self.align_for(8)
    }

    /// Natural alignment for a target whose pointer width is `ptr_bytes`. A
    /// scalar aligns to its own size (clamped to `[1, 8]` — 8 is the maximum
    /// fundamental alignment, e.g. `double`, which is 8-aligned on BOTH targets;
    /// only the *pointer's* alignment shrinks, and that falls out of its size
    /// being `ptr_bytes`); an array inherits its element's alignment; a record
    /// reads its cached `align` (laid out by the parser for the active target).
    pub fn align_for(&self, ptr_bytes: usize) -> usize {
        match self {
            Type::Array(e, _) => e.align_for(ptr_bytes),
            Type::Record { align, .. } => (*align).max(1),
            other => other.size_for(ptr_bytes).clamp(1, 8),
        }
    }

    pub fn is_record(&self) -> bool {
        matches!(self, Type::Record { .. })
    }

    pub fn is_integer(&self) -> bool {
        matches!(self, Type::Int { .. })
    }

    /// True for an IEEE-754 scalar (`float` or `double`).
    pub fn is_float(&self) -> bool {
        matches!(self, Type::Float { .. })
    }

    pub fn is_pointer(&self) -> bool {
        matches!(self, Type::Ptr(_) | Type::Array(..))
    }

    pub fn is_signed(&self) -> bool {
        matches!(self, Type::Int { signed: true, .. })
    }

    /// The pointee of a pointer or array element type.
    pub fn pointee(&self) -> Option<&Type> {
        match self {
            Type::Ptr(t) | Type::Array(t, _) => Some(t),
            _ => None,
        }
    }

    /// Array-to-pointer / nothing-else decay used in value contexts.
    pub fn decay(&self) -> Type {
        match self {
            Type::Array(e, _) => Type::Ptr(e.clone()),
            Type::Func { .. } => Type::Ptr(Box::new(self.clone())),
            t => t.clone(),
        }
    }
}

/// Parser-owned default-argument record for one overload candidate:
/// `(source name, explicit parameter types, defaults aligned to full params)`.
pub type OverloadDefault = (String, Vec<Type>, Vec<Option<Expr>>);

#[derive(Debug, Clone, PartialEq)]
pub struct TranslationUnit {
    pub items: Vec<Item>,
    /// `struct`/`union` definitions, referenced by [`Type::Record`].
    pub records: Vec<Record>,
    /// Default arguments per function (final/mangled name), aligned to the
    /// full parameter list; `None` for parameters without a default.
    pub defaults: std::collections::HashMap<String, Vec<Option<Expr>>>,
    /// S4.2av: collision-free per-OVERLOAD default-argument record — one entry
    /// per function DEFINITION that has any default (source name, the DECLARED
    /// parameter TYPES *without* the implicit `this`, and the defaults aligned to
    /// the full parameter list incl. `this`). The `defaults` HashMap above
    /// collapses overloads of the same source name (last-wins), which is fine for
    /// its non-overloaded users but loses the per-candidate defaults overload
    /// resolution needs. This list keeps every candidate, matched to its
    /// `Overload` in codegen by (name, no-`this` param types) — keying on the
    /// types, not just arity, so a defaulted overload's record does NOT leak to a
    /// SAME-ARITY sibling that declared no defaults (e.g. `C(const void* = 0)`
    /// vs the copy ctor `C(const C&)` — the leak made the copy ctor spuriously
    /// viable for a 0-arg `C c;`, yielding a false "ambiguous call").
    pub overload_defaults: Vec<OverloadDefault>,
    /// S1b.7 (RED 3): body-less function prototypes — `int foo(int);` /
    /// `extern int helper(Bar&);`. Used by `compile_module` to mangle
    /// calls to externally-defined functions. A proto whose name is
    /// also defined in the TU is shadowed by the definition (codegen
    /// drops the proto's mangled-symbol mapping in that case). Empty
    /// for any pre-S1b.7 TU ⇒ existing programs unchanged.
    pub extern_protos: Vec<Function>,
    /// S4: function templates captured at parse time. Each holds the type-
    /// parameter names and the generic [`Function`] whose param/return/local
    /// types may reference them via [`Type::TemplateParam`]. The generic is
    /// NOT codegen'd directly; S4.1b monomorphises one concrete [`Function`]
    /// per distinct deduced type-argument set. Empty for any TU with no
    /// `template` declaration ⇒ pre-S4 programs are byte-identical.
    pub fn_templates: Vec<TemplateDecl>,
    /// S4.5: the TU uses `dynamic_cast`. Kept as a semantic marker for checked
    /// downcasts; vtable RTTI prefixes are now emitted uniformly so weak-folded
    /// vtables have one ABI shape across TUs.
    pub uses_dynamic_cast: bool,
    /// G13: scoped nested-type map `"Outer::Inner" -> record id` (the `::`
    /// subset of the parser's tag table, registered for EVERY nested class by
    /// #64). Lets function-template monomorphisation resolve a DEPENDENT nested
    /// type `Base::Inner` (CLASSLIB's `WriteBaseObject<Base>`'s
    /// `Base::Streamer strmr(base);`) once `Base` is bound to a concrete record:
    /// the scoped key `<Base's tag>::Inner` yields the concrete nested record.
    /// Empty for any TU with no nested classes ⇒ pre-G13 programs unchanged.
    pub nested_scopes: std::collections::HashMap<String, usize>,
    /// W6 (G48): `#pragma startup <fn> [priority]` registrations — Borland's
    /// INIT-record mechanism (TU-local functions run before `main`/`WinMain`,
    /// ascending priority; 0–63 are RTL-reserved, default 100). The RTL leans
    /// on it everywhere (`_init_heap` 2, `_setargv` 3, `_init_handles` 4,
    /// `_init_streams` 5, `_cvt_init` 10, `Iostream_init` 16, …): without it
    /// the recompiled HEAP.C `malloc` walks uninitialised heap variables (the
    /// railc.exe startup segfault). Codegen emits one `.mdbcc_ctor.$startup$
    /// NNN$<fn>` thunk per entry; mdlink orders them before the plain ctor
    /// thunks. Empty for any TU without the pragma ⇒ byte-identical.
    pub startup_fns: Vec<(String, u32)>,
}

/// S4: a captured function template — its type-parameter names and the generic
/// function recipe (see [`TranslationUnit::fn_templates`]).
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateDecl {
    pub params: Vec<String>,
    pub func: Function,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Func(Function),
    /// File-scope variable (optionally initialized with a constant).
    /// `is_const` (S4 #48): the declaration was `const` (no `extern`). A
    /// namespace-scope `const` has INTERNAL linkage in C++ ([basic.link]), so
    /// codegen emits it as a TU-local (Static) COFF symbol — multiple TUs that
    /// include the same `const T X = v;` header (e.g. `const size_t NPOS =
    /// size_t(-1);` in cstring.h) then do not collide at link.
    Global {
        name: String,
        ty: Type,
        init: Option<Expr>,
        is_const: bool,
    },
    /// S4.2#24: a file-scope `extern T g;` DECLARATION (no initializer) — the
    /// object is DEFINED in another TU. Unlike `Global`, this must NOT emit a
    /// local definition; codegen registers it so reads resolve, and the object
    /// writer emits an UNDEFINED COFF symbol the linker resolves cross-TU.
    ExternGlobal {
        name: String,
        ty: Type,
    },
}

/// Source-level calling convention (S2b.3). Borland accepts the keyword
/// with one or two leading underscores (`_cdecl` / `__cdecl`); the lexer
/// folds both to the same token, so all map to one `CallConv` variant.
///
/// On Win64 the convention is informational (there is one ABI); on Win32
/// it selects arg order, stack cleanup, and name decoration (S2b.5/.6,
/// HLD 2026-05-27 §6). A `None` `calling_conv` means "use the target
/// default" (Win64: the x64 ABI; Win32: `__cdecl`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallConv {
    Cdecl,
    Stdcall,
    Fastcall,
    Pascal,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Function {
    pub name: String,
    pub ret: Type,
    pub params: Vec<(String, Type)>,
    pub body: Vec<Stmt>,
    /// Phase J-1: trailing-`const` member-function qualifier
    /// (`T& f() const`). `false` for free functions, ctors/dtors,
    /// synthesised functions, and non-const member functions —
    /// i.e. every Function emitted before J-1. The flag participates
    /// in overload mangling (a const member of an overloaded name gets
    /// an extra `K` suffix per `overload_symbol`) and tie-breaks
    /// otherwise-identical overload candidates: the non-const
    /// (`const_method: false`) overload wins. **J-1a fallback**:
    /// receiver-constness is NOT propagated through call sites, so a
    /// call on a `const T` receiver still resolves to the non-const
    /// overload. Full receiver-const resolution is filed as J-1b.
    pub const_method: bool,
    /// True iff this member function occupies a virtual-table slot. The
    /// overload-aware vtable rebuild must exclude same-named non-virtual
    /// overloads (OWL's `TWindow::GetClassName(char*, int) const`) or it shifts
    /// inherited virtual slots.
    pub virtual_method: bool,
    /// Tick 64 (J-13 v1): variadic user function (`T f(named..., ...)`).
    /// When `true`, the callee declared a trailing `...` after the
    /// named parameter list — `params` records only the named ones.
    /// Affects two paths:
    ///   - **Callee prologue**: spill RCX/RDX/R8/R9 into the caller-
    ///     allocated home space at `[rbp+16..40]` so `va_start` sees a
    ///     contiguous array of 8-byte slots starting at the first
    ///     variadic position.
    ///   - **Caller marshalling**: for an FP argument at slot 0..3, the
    ///     Win64 variadic ABI requires the bits in BOTH the positional
    ///     XMM and the corresponding GPR (so the callee, which reads
    ///     `va_arg` through the GPR-spilled shadow slot, recovers the
    ///     IEEE-754 image regardless of the requested `T`). Non-
    ///     variadic call sites are unchanged ⇒ byte-identical for the
    ///     O1 88 corpus (none of which calls a variadic user fn).
    pub variadic: bool,
    /// S1b.3: the function has **C linkage** (`extern "C"`, or the
    /// source file is `.c` rather than `.cpp`). Used by Borland symbol
    /// mangling to pick the `_<name>` form (single leading underscore,
    /// no `@`, no `$q...`) instead of the `@<chain>$q<types>` C++ form.
    ///
    /// Currently the parser sets this to `false` for every function
    /// (mdbcc does not yet parse `extern "C"` declarations and treats
    /// `.c` and `.cpp` sources identically). The flag exists today so
    /// the codegen helpers can carry C-linkage information through to
    /// the eventual COFF emit work (S1b.4+) without churning the AST
    /// again — and so the mangling regression suite can exercise the
    /// `_main` / `_extc_fn` cases against a real `Function`.
    pub c_linkage: bool,
    /// S2b.3: the source-declared calling convention (`__cdecl` /
    /// `__stdcall` / `__fastcall` / `__pascal`), or `None` when the
    /// declaration named none (⇒ use the target default).
    ///
    /// The parser captures this for free functions / prototypes; C++
    /// member functions, ctors/dtors, and synthesised functions record
    /// `None` (the convention does not participate in C++ name mangling —
    /// HLD 2026-05-27 §6.8). Inert until S2b.5/.6 wire it into the Win32
    /// ABI marshalling and name decoration (mirrors how `c_linkage`
    /// landed ahead of its codegen consumer).
    pub calling_conv: Option<CallConv>,
    /// S4.2h: INLINE definition — an in-class member body, or a free/out-of-line
    /// definition declared `inline`. Vague-linkage in C++: emitted on demand. The
    /// codegen inline-on-demand pass drops an inline function no emitted code
    /// reaches, so a header's unreachable inline bodies stop forcing codegen of
    /// constructs mdbcc can't yet handle. Non-inline definitions are always
    /// emitted. The 88 baselines are C (no inline) or C++ fixtures whose inline
    /// members are all reached ⇒ nothing dropped ⇒ byte-identical.
    pub inline: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// `return [<expr>];`
    Return(Option<Expr>, Loc),
    /// `<ty> <name> [= <init>];`. `is_static` marks a function-local `static`
    /// (S4.2o): one instance with static storage duration, initialized once —
    /// codegen lowers it to a uniquely-named module global, not a stack slot.
    Decl {
        name: String,
        ty: Type,
        init: Option<Expr>,
        loc: Loc,
        is_static: bool,
    },
    ExprStmt(Expr, Loc),
    /// Phase B: install record `id`'s vtable pointer at `[this+0]`.
    /// Parser-injected into constructor bodies immediately after the
    /// base-constructor call (so the most-derived vtable wins) and before
    /// the user body (so it runs on every exit path — incl. early
    /// `return` — and in-ctor virtual calls see the right vtable).
    /// Codegen emits nothing for a non-polymorphic record ⇒ pre-Phase-B
    /// constructors stay byte-identical. The loc is synthetic
    /// ([`Loc::default()`]) for parser-injected instances.
    SetVptr(usize, Loc),
    /// S4 (#8/#34): a constructor member-initializer `: field(args...)`. The
    /// parser emits this from `ctor_full_body` carrying the FULL argument list
    /// (the member's TYPE is not yet known during member parsing). The end-of-
    /// parse sweep in `Parser::parse_for` rewrites every `MemberInit` once all
    /// records/classes are finalized, into one of:
    ///
    /// - a class-typed member WITH a constructor: a ctor call
    ///   (`MethodCall{ recv: this->field, name: <member class tag>, args }`), so
    ///   the sub-object is CONSTRUCTED with all the supplied arguments;
    /// - anything else (scalar / pointer / POD): `this->field = args[0]`,
    ///   byte-identical to the historical lowering.
    ///
    /// Codegen never sees a `MemberInit` (the sweep always rewrites it); its
    /// `gen_stmt` arm is a loud internal error, not a silent no-op.
    MemberInit {
        field: String,
        args: Vec<Expr>,
        loc: Loc,
    },
    /// G40: ctor-init of a REFERENCE member — BIND `this->field`'s slot to the
    /// ADDRESS of the initializer (`struct S { const M& mo; S(const M& m) :
    /// mo(m) {} }`, CLASSLIB THREAD.H `TMutex::Lock`). Distinct from `Assign`:
    /// assignment through a Ref member auto-derefs the slot (and rewrites to a
    /// user `operator=` for class referents — for `TMutex` one that is
    /// DECLARED-private-never-DEFINED, an unlinkable bogus call through an
    /// uninitialized reference). Binding stores the referent's address into
    /// the slot itself, exactly like a reference LOCAL's `Decl` init.
    RefBindMember {
        field: String,
        rhs: Expr,
        loc: Loc,
    },
    If {
        cond: Expr,
        then: Box<Stmt>,
        els: Option<Box<Stmt>>,
        loc: Loc,
    },
    While {
        cond: Expr,
        body: Box<Stmt>,
        loc: Loc,
    },
    /// `do body while (cond);` — the body runs once before `cond` is tested,
    /// then repeats while `cond` is true. Same fields as `While` (so most match
    /// arms share an OR-pattern); only codegen lowers it distinctly (test-last).
    DoWhile {
        cond: Expr,
        body: Box<Stmt>,
        loc: Loc,
    },
    For {
        init: Option<Box<Stmt>>,
        cond: Option<Expr>,
        step: Option<Expr>,
        body: Box<Stmt>,
        loc: Loc,
    },
    Block(Vec<Stmt>, Loc),
    Empty,
    /// `throw [<expr>];` — `None` is a bare `throw;` (rethrow). Phase H3
    /// parses both forms; codegen rejects until Phase H4a wires the SEH
    /// runtime. Standards require that bare `throw;` only appears inside
    /// a `catch`, but H3 leaves that runtime check to H4a (the parser
    /// accepts the form regardless).
    Throw(Option<Expr>, Loc),
    /// `try { body } catch (...) { … } catch (T) { … } …` — Phase H3
    /// parses any number (≥1) of handlers, including the catch-all
    /// `(...)` form. Codegen rejects until Phase H4a.
    Try {
        body: Vec<Stmt>,
        catches: Vec<CatchClause>,
        loc: Loc,
    },
    /// S3: `switch (scrutinee) { case C: … default: … }`. `body` is the
    /// switch block (a [`Stmt::Block`]) whose statement list interleaves
    /// [`Stmt::Case`] / [`Stmt::Default`] label markers with ordinary
    /// statements — the flat representation that yields C fall-through.
    Switch {
        scrutinee: Expr,
        body: Box<Stmt>,
        loc: Loc,
    },
    /// S3: a `case <const-expr>:` label marker inside a switch body.
    Case {
        value: Expr,
        loc: Loc,
    },
    /// S3: a `default:` label marker inside a switch body.
    Default(Loc),
    /// S3: `break;` — exits the innermost enclosing loop or switch.
    Break(Loc),
    /// S3: `continue;` — jumps to the innermost enclosing LOOP's next
    /// iteration (a `continue` inside a switch targets the loop, not the
    /// switch — C semantics).
    Continue(Loc),
    /// S4.2m: `name:` — a labeled statement target. Carries only the label
    /// name; the statement it labels follows as the next statement (the parser
    /// emits the label marker, then the labeled statement, flat).
    Label(String, Loc),
    /// S4.2m: `goto name;` — an unconditional jump to a `Label` in the same
    /// function. Forward references are resolved by codegen at the label site.
    Goto(String, Loc),
}

impl Stmt {
    /// Best-effort source location of this statement. For [`Stmt::Empty`]
    /// (which has no fields), returns [`Loc::default()`]; otherwise returns
    /// the embedded loc. Used by codegen's error helpers to format errors
    /// with `"line:col: "` prefixes.
    pub fn loc(&self) -> Loc {
        match self {
            Stmt::Return(_, l)
            | Stmt::ExprStmt(_, l)
            | Stmt::SetVptr(_, l)
            | Stmt::Block(_, l)
            | Stmt::Throw(_, l)
            | Stmt::Default(l)
            | Stmt::Break(l)
            | Stmt::Continue(l)
            | Stmt::Label(_, l)
            | Stmt::Goto(_, l) => *l,
            Stmt::Decl { loc, .. }
            | Stmt::If { loc, .. }
            | Stmt::While { loc, .. }
            | Stmt::DoWhile { loc, .. }
            | Stmt::For { loc, .. }
            | Stmt::Try { loc, .. }
            | Stmt::Switch { loc, .. }
            | Stmt::Case { loc, .. }
            | Stmt::MemberInit { loc, .. }
            | Stmt::RefBindMember { loc, .. } => *loc,
            Stmt::Empty => Loc::default(),
        }
    }
}

/// Shape of a single `catch` clause's parameter.
///
/// Phase H3 distinguishes the catch-all form `catch (...)` from a typed
/// handler `catch (T)` / `catch (T name)`; the name is optional because
/// C++ permits `catch (int)` (handler matches but the value isn't
/// bound). Stored on [`CatchClause`].
#[derive(Debug, Clone, PartialEq)]
pub enum CatchKind {
    /// `catch (...)` — matches any exception.
    All,
    /// `catch (T)` or `catch (T name)` — typed handler.
    Typed { ty: Type, name: Option<String> },
}

/// One `catch` clause attached to a `try` (see [`Stmt::Try`]).
#[derive(Debug, Clone, PartialEq)]
pub struct CatchClause {
    pub kind: CatchKind,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Integer constant (type `int`).
    Int(i64),
    /// Character literal (`'a'`). Value is the (sign-extended) code unit.
    /// Distinct from `Int` ONLY in type: a C++ char literal has type `char`
    /// (`Int{bytes:1, signed:true}`), not `int` — this drives overload
    /// resolution (e.g. `string += 'c'` selects `string(char)` exactly,
    /// where `Int` would tie `string(char)` vs `string(unsigned char)`).
    /// Codegen and constant-folding treat it identically to `Int(value)`.
    Char(i64),
    /// Floating-point literal. `value` is the parsed lexeme at f64 precision
    /// (single-precision values losslessly fit); `bytes` is the declared
    /// type at the literal site (`f`/`F` suffix ⇒ 4 ⇒ `float`; default or
    /// `l`/`L` ⇒ 8 ⇒ `double`; `long double` folded to `double`, Phase F-1
    /// backlog). Codegen narrows on store via `cvtsd2ss` when `bytes==4`.
    Float {
        value: f64,
        bytes: u8,
    },
    /// String literal bytes; has type `char[len+1]` (implicit NUL).
    Str(Vec<u8>),
    /// Wide (`L"..."`) string literal, stored as its UTF-16LE bytes INCLUDING
    /// the 2-byte NUL terminator (encoded at parse time). Has type
    /// `wchar_t[len/2]` (`wchar_t` is 2 bytes on Win32/Win64). A separate
    /// variant — rather than a flag on [`Self::Str`] — so every existing `Str`
    /// codegen site is untouched (narrow strings stay byte-identical); the wide
    /// arms are added only where needed (#53).
    WideStr(Vec<u8>),
    /// A variable or parameter reference. The trailing [`Loc`] (J-8b, tick
    /// 74) pinpoints the identifier's column so "use of undeclared
    /// identifier" diagnostics point at the name itself, not at the
    /// enclosing statement's first token.
    Var(String, Loc),
    /// `lhs = rhs` (the lvalue is an arbitrary lvalue expression). The
    /// [`Loc`] (J-8b, tick 74) records the `=` token's position so a
    /// non-lvalue error points at the operator, not the start of the
    /// containing statement.
    Assign {
        lhs: Box<Expr>,
        rhs: Box<Expr>,
        loc: Loc,
    },
    Unary {
        op: UnOp,
        expr: Box<Expr>,
    },
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
        /// J-8b (tick 74): position of the binary operator. Overload-
        /// resolution failures and arithmetic-type errors report this
        /// column rather than the enclosing statement's.
        loc: Loc,
    },
    /// `base[idx]` — sugar for `*(base + idx)`.
    Index {
        base: Box<Expr>,
        idx: Box<Expr>,
        loc: Loc,
    },
    /// `base.field` (arrow=false) or `base->field` (arrow=true). The
    /// [`Loc`] (J-8b, tick 74) records the `.` / `->` token's position so
    /// "no member named" diagnostics point at the access site.
    Member {
        base: Box<Expr>,
        field: String,
        arrow: bool,
        loc: Loc,
    },
    /// `cond ? then : els`
    Cond {
        cond: Box<Expr>,
        then: Box<Expr>,
        els: Box<Expr>,
    },
    /// `++x` / `x++` / `--x` / `x--` (target must be an lvalue).
    IncDec {
        inc: bool,
        pre: bool,
        target: Box<Expr>,
    },
    /// J-8b (tick 74): `loc` records the call's name-token position so
    /// "undefined function" / overload-resolution errors report the name's
    /// own column, not the enclosing statement's.
    Call {
        name: String,
        args: Vec<Expr>,
        loc: Loc,
    },
    /// `expr(args)` — indirect call through a function-pointer value
    /// (`fp(x)`, `tbl[i](x)`, `(*p)(x)`). The [`Loc`] (J-8b, tick 74)
    /// records the open-paren position.
    CallPtr {
        target: Box<Expr>,
        args: Vec<Expr>,
        loc: Loc,
    },
    /// J-14 v1 (tick 62): `&Class::method` — produces a member-function
    /// pointer value of type [`Type::MemFn`]. The class is named for
    /// codegen virtual-target rejection; the method is the simplest name
    /// match (no signature disambiguation in v1). For an overloaded method,
    /// the first declared overload wins. The trailing [`Loc`] (J-8b, tick
    /// 74) points at the `&` token so the virtual-rejection diagnostic
    /// pins the construction site.
    AddressOfMember {
        class: String,
        method: String,
        loc: Loc,
    },
    /// J-14 v1 (tick 62): `(obj.*ptr)(args)` (arrow=false) or
    /// `(ptr_to_obj->*ptr)(args)` (arrow=true) — indirect call through a
    /// member-function pointer. `recv` provides the `this` object (an
    /// lvalue for `.*`, a pointer for `->*`); `ptr` provides the function
    /// address. Lowers to a standard Win64 indirect call with `this` set
    /// up in RCX and explicit args shifted by one positional slot.
    /// The [`Loc`] (J-8b, tick 74) records the `.*` / `->*` token's
    /// position.
    CallMemberPtr {
        recv: Box<Expr>,
        ptr: Box<Expr>,
        args: Vec<Expr>,
        arrow: bool,
        loc: Loc,
    },
    /// `recv.name(args)` / `recv->name(args)` — C++ method call; codegen
    /// resolves the class from `recv`'s type and mangles the symbol. The
    /// [`Loc`] (J-8b, tick 74) records the method-name token position so
    /// "class X has no member named Y" diagnostics pin the call site.
    MethodCall {
        recv: Box<Expr>,
        name: String,
        args: Vec<Expr>,
        loc: Loc,
    },
    /// `new T` / `new T(args)` — heap-allocates a `T` (via `HeapAlloc`) and,
    /// if the class declares one, runs its constructor. Has type `T*`.
    ///
    /// S4.2(a): `placement` holds the placement-new arguments `new (p…) T`
    /// (empty for an ordinary `new`). Captured so template bodies that use
    /// placement-new (the BIDS containers' `new(*this) T[n]`) parse; codegen
    /// of a non-empty placement is deferred (a clean error) until S4.2b.
    New {
        ty: Type,
        args: Vec<Expr>,
        placement: Vec<Expr>,
    },
    /// `delete p` — runs `p`'s destructor (if any) then frees it. Type `void`.
    Delete {
        expr: Box<Expr>,
    },
    /// `new T[n]` — Phase H6. Heap-allocates `8 + n*sizeof(T)` bytes,
    /// stores `n` as a `size_t` cookie at offset 0, default-constructs
    /// each of the `n` elements in index order (skipped when `T` has no
    /// user-declared constructor), and yields the pointer to element 0
    /// (cookie is at `result-8`). `count` is any int-valued expression
    /// (constant or runtime). The brackets-in-init form `new T[n](init)`
    /// and brace-init `new T[]{a,b,c}` remain H-future. The [`Loc`]
    /// (J-8b, tick 74) records the `new` keyword position so a constant-
    /// negative-count or overflow trap reports the array-new site, not
    /// the enclosing statement.
    NewArray {
        ty: Type,
        count: Box<Expr>,
        placement: Vec<Expr>,
        loc: Loc,
    },
    /// `delete[] p` — Phase H6. Loads `n = *(size_t*)(p-8)` from the
    /// cookie, destructs elements `n-1..0` (reverse construction order,
    /// per the standard), then `HeapFree`s the original block at `p-8`.
    /// For a trivial `T` (no user-declared destructor) the dtor loop is
    /// elided but the cookie + free path are unchanged.
    DeleteArray {
        expr: Box<Expr>,
    },
    /// `(ty) expr`
    Cast {
        ty: Type,
        expr: Box<Expr>,
    },
    /// `dynamic_cast<ty>(expr)` — a checked DOWNCAST. `ty` is a pointer-to-record
    /// (the OWL `TYPESAFE_DOWNCAST` form); codegen walks `expr`'s runtime type
    /// (via the RTTI registry) up its base chain and yields `expr` (single-
    /// inheritance, base@0) if the target record is found, else a null pointer.
    DynamicCast {
        ty: Type,
        expr: Box<Expr>,
    },
    /// `sizeof(type)`
    SizeofType(Type),
    /// `sizeof expr`
    SizeofExpr(Box<Expr>),
    /// S4.2e: the RTTI `typeid(expr)` / `typeid(type)` operator — yields a
    /// `const typeinfo&` (Borland's RTTI class). Parsed so real OWL source
    /// (`typeid(*this).name()` in the streaming classes) gets PAST the operator;
    /// the operand is consumed and dropped. CODEGEN is a clean error (real RTTI —
    /// `type_info` in vtables for the dynamic case — is the S4.5 stone); never a
    /// silent wrong-type result. The [`Loc`] pins the `typeid` keyword.
    /// `typeid(operand)`. The operand is captured as an expression whose
    /// `expr_type` is the queried type — for the `typeid(TYPE)` form the parser
    /// wraps the type in a synthetic `Cast{ty, 0}` (never code-generated; only
    /// its type is read). Minimal RTTI: `typeid(X).name()` lowers to a string
    /// of X's static type name (the only way typeid is used in the BC45 corpus).
    Typeid(Box<Expr>, Loc),
    /// J-9 (tick 57): aggregate (brace) initializer — `{e1, e2, …}`.
    ///
    /// An InitList is **always a child of an initialiser context**: it is
    /// produced only by [`crate::parser::Parser::maybe_initializer`]
    /// (and never appears as a free-standing expression). Codegen lowers
    /// it element-by-element against the target type at the
    /// `Stmt::Decl { init: Some(Expr::InitList(_)), … }` site. Outside
    /// that context, `expr_type` and `gen_expr` reject with a clear
    /// diagnostic — there is no type or value to take on its own.
    ///
    /// Nested aggregates are nested `InitList`s: `{{1,2},{3,4}}` is
    /// `InitList([InitList([1,2]), InitList([3,4])])`. Trailing-comma
    /// is consumed at parse time and does not appear in the AST.
    ///
    /// J-9b (deferred): designated init `{.x = 3}`, empty `{}`, C++11
    /// ctor brace-init `T x{a, b};`, file-scope aggregate globals.
    InitList(Vec<Expr>),
    /// Tick 64 (J-13 v1): `va_start(ap, last)` — initialise `ap` to point
    /// just past the named parameter `last` (which must be the source
    /// name of an actual parameter of the enclosing variadic function).
    /// Lowered to `ap = rbp + 16 + 8 * (idx_of_last + 1)` — i.e. the
    /// address of the first slot in the caller-allocated home space
    /// AFTER `last`'s positional shadow slot. The result value of the
    /// expression is unspecified (statement-context only in idiomatic
    /// use; mdbcc's codegen leaves rax holding the computed ap so the
    /// expression form `(va_start(ap, n), ...)` would also be valid if
    /// a comma-expression were available — it isn't, but the codegen
    /// is honest about what it produces).
    VaStart {
        ap: Box<Expr>,
        last_name: String,
    },
    /// Tick 64 (J-13 v1): `va_arg(ap, T)` — read a `T`-typed value from
    /// the slot at `*ap`, then advance `ap` by 8 bytes (Win64 variadic
    /// slot width is always 8 regardless of `T`). Result is the loaded
    /// `T` value. For `T: float/double`, the value lands in xmm0
    /// (mirroring mdbcc's FP expression convention); for any other
    /// `T`, the value lands in eax/rax. Lowered in `gen_expr`.
    VaArg {
        ap: Box<Expr>,
        ty: Type,
    },
    /// Tick 64 (J-13 v1): `va_end(ap)` — no-op in the Win64 ABI
    /// (the `char*` va_list owns no heap state). Codegen emits zero
    /// bytes; semantically a `void` evaluation of `ap` for the
    /// "must consume the argument" rule, though `ap` is read-only
    /// for the lowering and may be a non-trivial expression.
    VaEnd {
        ap: Box<Expr>,
    },
}

impl Expr {
    /// J-8b (tick 74): best-effort source location of this expression. The
    /// codegen `Gen::err_at_expr` helper consults this to format an error
    /// with `"<line>:<col>: "` taken from the offending expression itself
    /// rather than from the enclosing statement's `Gen::current_loc`.
    ///
    /// Variants that don't carry a [`Loc`] (literals, ad-hoc combinators
    /// like `Cond`/`Unary`/`IncDec`/`Cast`/`New`/`Delete`/`Sizeof*`/
    /// `InitList`/`Va*`) return [`Loc::default()`] (synthetic), in which
    /// case the error helper falls back to `Gen::current_loc` — the
    /// enclosing statement's column — which is precisely the J-8 pre-
    /// expression precision.
    ///
    /// Adding loc coverage to additional variants is a strict extension:
    /// constructions that gain a loc start producing more precise
    /// diagnostics at the corresponding error sites, while the rest
    /// continue to report the statement-level position.
    pub fn loc(&self) -> Loc {
        match self {
            Expr::Var(_, l) => *l,
            Expr::Assign { loc, .. }
            | Expr::Binary { loc, .. }
            | Expr::Index { loc, .. }
            | Expr::Member { loc, .. }
            | Expr::Call { loc, .. }
            | Expr::CallPtr { loc, .. }
            | Expr::AddressOfMember { loc, .. }
            | Expr::CallMemberPtr { loc, .. }
            | Expr::MethodCall { loc, .. }
            | Expr::NewArray { loc, .. } => *loc,
            _ => Loc::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Pos,
    LogNot,
    BitNot,
    /// `&x` — address-of (operand must be an lvalue).
    Addr,
    /// `*p` — pointer dereference.
    Deref,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Shl,
    Shr,
    BitAnd,
    BitOr,
    BitXor,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    /// `&&` — short-circuit; code generated specially.
    LAnd,
    /// `||` — short-circuit; code generated specially.
    LOr,
    /// `,` — the comma operator: evaluate the left operand for its side effects,
    /// discard it, then yield the right. Lowest precedence; code generated
    /// specially (it does not combine operands like a real arithmetic op).
    Comma,
}
