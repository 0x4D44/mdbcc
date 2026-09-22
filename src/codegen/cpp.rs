//! C++-specific codegen helpers: Borland C++ 4.52 symbol mangling,
//! vtable finalisation, overload-resolution argument compatibility, and
//! the synthesised memberwise copy-ctor builder.
//!
//! Most of the per-method C++ codegen (virtual dispatch, member-ptr call,
//! ctor cleanup, class-typed throw) still lives on `impl Gen` in
//! `src/codegen.rs` because it threads through `Gen` state (slots,
//! temps, scopes, RipRefs). What lives HERE are the pure / non-Gen
//! helpers — every function in this file is invoked from either
//! `compile_module`'s pre-pass (mangling, vtable rebuild, copy-ctor
//! synthesis) or from `impl Gen` resolution sites (overload-resolution
//! type compatibility).
//!
//! ## Mangling convention — Borland C++ 4.52
//!
//! S1b.3 (HLD 2026-05-27 §3) rewrites the previously Itanium-flavoured
//! codes to match BCC 4.52 exactly, derived from observed `.obj` PUBDEFs
//! emitted by `wrk_oracle/bc452/BC45/BIN/BCC32.EXE`. The anatomy is:
//!
//! ```text
//! @ <qualified-name> $ <quals?> q <type-encoding>
//! ```
//!
//! - Leading `@` for every C++ symbol (members, overloaded free
//!   functions, operators); leading `_` for C linkage (`_main`,
//!   `_extc_fn`) — see [`borland_c_symbol`].
//! - `<qualified-name>` joins the class chain with `@`
//!   (`Bar@m`, `Outer@Inner@get`).
//! - `<quals?>` is zero or more per-symbol qualifiers:
//!   - `b<code>$` — built-in special name (`$bctr$` ctor, `$bdtr$`
//!     dtor, `$badd$` operator+, …); see [`borland_operator_special_name`].
//!   - `x` — trailing-`const` member function (sits between `$` and `q`).
//! - `q` introduces the parameter type list (one type code per parameter,
//!   no separators).
//!
//! Type codes (`v` void, `c/s/i/l` char/short/int/long, `f` float,
//! `d` double, `u` unsigned prefix, `p` pointer-to, `r` reference-to,
//! `x` const, `<N><name>` user type) recurse for compound types.
//!
//! ## O1 byte-identity invariant
//!
//! The mangling change is **observable** in the symbol-table-equivalent
//! keys (HashMap lookups in `codegen.rs`, `pe.rs`), but every emitted
//! PE byte is a function of (function body bytes, fixup target RVAs).
//! User function names never reach the PE bytes — they're only used as
//! internal keys to resolve `CallSite::callee` and `RipRef::Func` to
//! function offsets. Therefore changing the mangled-name format leaves
//! the 88 O1 fixture hashes unchanged; the regression lock holds.

use std::collections::HashMap;

use crate::ast::{Function, Item, Loc, Record, Type, VtSlot};
use crate::codegen::target::TargetKind;
use crate::codegen::{
    CallSite, CodegenError, CompiledFn, Overload, RipRef, RipReloc, Sigs, complete_record_sizes,
};

// ---------------------------------------------------------------------------
// Borland C++ 4.52 name mangling (HLD §3 derivation).
// ---------------------------------------------------------------------------

/// Encode a single parameter type into Borland's per-type code(s).
///
/// Examples (per HLD §3.2, validated against `bcc32 -c` PUBDEF output):
/// - `int` → `i`, `unsigned int` → `ui`, `short` → `s`,
///   `unsigned short` → `us`, `char` → `c`.
/// - `float` → `f`, `double` → `d`.
/// - `void` → `v` (only meaningful as the sole entry for a no-arg list).
/// - `int*` → `pi`, `const int*` → `pxi` (`p` then `x` is "pointer to
///   const"; `xpi` would be "const pointer to int").
/// - `int&` → `ri`, `const int&` → `rxi`.
/// - `Bar` (class with `tag = "Bar"`) → `3Bar`; `Bar*` → `p3Bar`;
///   `const Bar&` → `rx3Bar` (resolved via
///   [`borland_mangle_type_with_records`] when the record table is in
///   scope; the bare [`type_code`] path falls back to a placeholder
///   `<len>R<id>` since codegen-internal callers don't have the table
///   threaded through).
///
/// **Long-vs-int caveat** (HLD §3.5 deferred): BCC distinguishes `long`
/// from `int` even though both are 32-bit on Win32 (`int` → `i`, `long`
/// → `l`). mdbcc's AST collapses both into `Type::Int { bytes: 4,
/// signed: … }`, so we emit `i` (signed) or `ui` (unsigned) for any
/// 4-byte integer — a divergence from BCC for source that declares
/// `long`. Closing this gap requires an AST split (a separate `Long`
/// variant) and is filed for the S1b.7 mangling-closure phase.
pub fn type_code(t: &Type) -> String {
    borland_mangle_type(t)
}

/// Mangle an overloaded function's symbol from its parameter types.
///
/// `base` is the source-visible name as the parser stores it:
/// - free function: `"foo"` → `@foo$q<types>`
/// - member function: `"Bar::m"` → `@Bar@m$q<types>`
/// - nested member: `"Outer::Inner::get"` → `@Outer@Inner@get$q<types>`
/// - constructor: `"Bar::Bar"` → `@Bar@$bctr$q<types>`
/// - destructor: `"Bar::~Bar"` → `@Bar@$bdtr$q<types>`
/// - member operator: `"Bar::operator+"` → `@Bar@$badd$q<types>`
///
/// The implicit `this` parameter (parser-injected as the first entry of
/// `params` for non-static members) is excluded from the type list so
/// calls and definitions agree on the mangled string.
///
/// `const_method = true` inserts an `x` qualifier between the `$` and
/// the `q`, matching BCC's trailing-`const` member-function form
/// (`@Bar@read$xqv` for `int Bar::read() const`).
pub fn overload_symbol(base: &str, params: &[(String, Type)], const_method: bool) -> String {
    overload_symbol_impl(base, params, const_method, None)
}

/// Variant of [`overload_symbol`] that resolves `Type::Record` to its
/// source-visible class tag (`Bar` ⇒ `3Bar`) instead of the placeholder
/// record-id form. Used by `compile_module` when registering extern-
/// prototype mangled symbols (S1b.7 RED 3): bcc32 emits the user-visible
/// tag in every PUBDEF/EXTDEF, so a call against an extern proto must
/// use the same form to satisfy O13 parity.
pub fn overload_symbol_with_records(
    base: &str,
    params: &[(String, Type)],
    const_method: bool,
    records: &[Record],
) -> String {
    overload_symbol_impl(base, params, const_method, Some(records))
}

fn overload_symbol_impl(
    base: &str,
    params: &[(String, Type)],
    const_method: bool,
    records: Option<&[Record]>,
) -> String {
    // Split the source-presented name into (class_chain, member).
    let (class_chain, raw_member) = split_qualified(base);
    let parts: Vec<&str> = if class_chain.is_empty() {
        Vec::new()
    } else {
        class_chain.split("::").collect()
    };

    // Pick the bare or special-name portion of the symbol. Constructor
    // names match the innermost class name; destructor names begin with
    // `~`; operator names start with the literal `operator` keyword.
    let last_class = parts.last().copied();
    let special: Option<&'static str> = if last_class == Some(raw_member) {
        Some(borland_special_name("ctor"))
    } else if let Some(rest) = raw_member.strip_prefix('~') {
        // The destructor's `rest` is always the class name; mdbcc never
        // synthesises a free `~name` function. Defensive fallback if it
        // ever does: emit a verbatim `~name` member rather than mistaking
        // it for a special-name.
        if Some(rest) == last_class {
            Some(borland_special_name("dtor"))
        } else {
            None
        }
    } else if let Some(op) = raw_member.strip_prefix("operator") {
        borland_operator_special_name(op)
    } else {
        None
    };

    let mut s = String::with_capacity(base.len() + 8);
    s.push('@');
    for part in &parts {
        s.push_str(part);
        s.push('@');
    }
    if let Some(sp) = special {
        // Special-name suffix forms like `$bctr$` already wrap their own
        // `$` delimiters; the upcoming `$q...` is appended below.
        s.push_str(sp);
    } else {
        // A plain method or free overloaded function name: `@<chain>@name$`.
        s.push_str(raw_member);
        s.push('$');
    }
    if const_method {
        s.push('x');
    }
    s.push('q');
    let has_explicit = params.iter().any(|(n, _)| n != "this");
    if has_explicit {
        for (n, t) in params {
            if n == "this" {
                continue;
            }
            let code = match records {
                Some(recs) => borland_mangle_type_with_records(t, recs),
                None => borland_mangle_type(t),
            };
            s.push_str(&code);
        }
    } else {
        // A zero-arg function still gets one type code; BCC uses `v`.
        s.push('v');
    }
    s
}

/// Split `"Outer::Inner::method"` into `("Outer::Inner", "method")`.
/// `"foo"` becomes `("", "foo")` (free function: no class chain).
fn split_qualified(name: &str) -> (&str, &str) {
    match name.rfind("::") {
        Some(i) => (&name[..i], &name[i + 2..]),
        None => ("", name),
    }
}

/// Borland's `$b<code>$` special-name forms for constructors and
/// destructors. The `"ctor"` / `"dtor"` keys are mdbcc-internal —
/// `overload_symbol` translates the parser's `Tag::Tag` /
/// `Tag::~Tag` names into the right special-name string.
fn borland_special_name(kind: &str) -> &'static str {
    match kind {
        "ctor" => "$bctr$",
        "dtor" => "$bdtr$",
        // Defensive: an unknown special name falls back to a bare `$`
        // (so the symbol is still distinguishable, just non-standard).
        // Today's callers only ever pass "ctor" / "dtor".
        _ => "$",
    }
}

/// Borland's `$b<code>$` special-name forms for overloaded operators.
/// `op` is the operator spelling without the `operator` prefix
/// (e.g. `"+"`, `"[]"`, `"new"`). Returns `None` when the operator is
/// not yet derived — the caller falls back to the verbatim member name.
///
/// Validated against `bcc32 -c` output (HLD §3.3 plus the in-session
/// derivation for the operator zoo):
/// - `+` → `$badd$`, `-` → `$bsub$` (also unary `-`), `*` → `$bmul$`,
///   `/` → `$bdiv$`, `%` → `$bmod$`.
/// - `==` → `$beql$`, `!=` → `$bneq$`.
/// - `<` → `$blss$`, `>` → `$bgtr$`, `<=` → `$bleq$`, `>=` → `$bgeq$`
///   (HLD conjectured `$blt$`/`$bgt$`/`$ble$`/`$bge$` — corrected here).
/// - `=` → `$basg$`, `+=` → `$brplu$`, `-=` → `$brmin$`,
///   `*=` → `$brmul$`, `/=` → `$brdiv$`.
/// - `&&` → `$bland$`, `||` → `$blor$` (HLD conjectured `$band$`/`$bor$`
///   — corrected here; those forms are reserved for bitwise `&`/`|`).
/// - `&` → `$band$`, `|` → `$bor$`, `^` → `$bxor$`.
/// - `!` → `$bnot$`, `~` → `$bcmp$`.
/// - `<<` → `$blsh$`, `>>` → `$brsh$`.
/// - `[]` → `$bsubs$`, `()` → `$bcall$`, `->` → `$barow$`, `,` → `$bcoma$`.
/// - `++` → `$binc$`, `--` → `$bdec$` (postfix/prefix disambiguated by
///   the `q<types>` suffix: postfix carries a dummy `int` argument).
/// - `new` → `$bnew$`, `delete` → `$bdele$` (the leading-space forms
///   absorb the whitespace some parsers leave between `operator` and the
///   keyword; both spellings normalise to the same special-name).
pub fn borland_operator_special_name(op: &str) -> Option<&'static str> {
    Some(match op {
        "+" => "$badd$",
        "-" => "$bsub$",
        "*" => "$bmul$",
        "/" => "$bdiv$",
        "%" => "$bmod$",
        "==" => "$beql$",
        "!=" => "$bneq$",
        "<" => "$blss$",
        ">" => "$bgtr$",
        "<=" => "$bleq$",
        ">=" => "$bgeq$",
        "=" => "$basg$",
        "+=" => "$brplu$",
        "-=" => "$brmin$",
        "*=" => "$brmul$",
        "/=" => "$brdiv$",
        "&&" => "$bland$",
        "||" => "$blor$",
        "&" => "$band$",
        "|" => "$bor$",
        "^" => "$bxor$",
        "!" => "$bnot$",
        "~" => "$bcmp$",
        "<<" => "$blsh$",
        ">>" => "$brsh$",
        "[]" => "$bsubs$",
        "()" => "$bcall$",
        "->" => "$barow$",
        "," => "$bcoma$",
        "++" => "$binc$",
        "--" => "$bdec$",
        " new" | "new" => "$bnew$",
        " delete" | "delete" => "$bdele$",
        _ => return None,
    })
}

/// Borland's recursive type-code encoder (the workhorse behind
/// [`type_code`]). See [`type_code`] for the per-shape examples and the
/// long-vs-int caveat.
pub fn borland_mangle_type(t: &Type) -> String {
    match t {
        Type::Void => "v".into(),
        Type::Int { bytes, signed } => {
            let base: &str = match bytes {
                1 => "c",
                2 => "s",
                4 => "i",
                // 8-byte integers (`long long` / `__int64`) are not yet
                // observed in mdbcc test sources or in the HLD §3.2
                // table. The Itanium-parallel guess is `j`/`J`; we emit
                // `i` for now so an accidental 8-byte signed integer
                // still produces a *stable* string rather than a panic.
                // Re-derive against the oracle in S1b.7 if a test
                // surfaces an `__int64` argument.
                _ => "i",
            };
            if *signed {
                base.into()
            } else {
                format!("u{base}")
            }
        }
        Type::Float { bytes: 4 } => "f".into(),
        Type::Float { bytes: 8 } => "d".into(),
        // Reserved for `long double`, which the parser already folds to
        // `double`. An unexpected width would emit a stable placeholder.
        Type::Float { .. } => "g".into(),
        // `T*` and `T[N]` both encode as `p<inner>` — arrays decay to
        // pointers at any call-site context, and Borland's mangling
        // matches that decay.
        Type::Ptr(p) | Type::Array(p, _) => format!("p{}", borland_mangle_type(p)),
        Type::Ref(p) => format!("r{}", borland_mangle_type(p)),
        Type::Record { id, .. } => borland_user_type_code(*id),
        Type::Func { ret, params } => {
            // No HLD-pinned encoding for raw function-type parameters
            // (S1b.7 deferral); emit a compact Borland-ish form so the
            // mangled string is at least stable.
            let mut s = String::from("pq");
            s.push_str(&borland_mangle_type(ret));
            for p in params {
                s.push_str(&borland_mangle_type(p));
            }
            s
        }
        Type::MemFn {
            class_id,
            ret,
            params,
        } => {
            let mut s = format!("m{class_id}q");
            s.push_str(&borland_mangle_type(ret));
            for p in params {
                s.push_str(&borland_mangle_type(p));
            }
            s
        }
        // S4: a template instantiation mangles its CONCRETE substituted types;
        // a raw parameter reaching here means substitution was skipped.
        Type::TemplateParam(p) => {
            unreachable!("mangling unsubstituted template parameter '{p}'")
        }
    }
}

/// `<N><name>` length-prefixed encoding for a user-defined record type.
/// Anonymous records fall back to the record-id form — mdbcc doesn't
/// actually expose anonymous-record parameters today, so this is
/// defensive.
fn borland_user_type_code(record_id: usize) -> String {
    // The codegen helpers in this module receive a `Type` without a back-
    // reference to the record table, so the natural-language tag must
    // travel through this call indirectly. We don't have it here; the
    // caller (compile_module pass 1) holds the record table but doesn't
    // route it through to type_code. As a pragmatic shim, encode the
    // record id (a stable per-TU integer) as the "name" — every call site
    // that needs the source-visible tag (`3Bar`) is in test/oracle code
    // and uses [`borland_mangle_type_with_records`] instead.
    let name = format!("R{record_id}");
    format!("{}{}", name.len(), name)
}

/// Variant of [`borland_mangle_type`] that resolves `Type::Record` to its
/// source-visible class tag (`Bar` ⇒ `3Bar`) instead of the placeholder
/// record-id form. Used by test code that needs to compare against BCC
/// PUBDEF strings; codegen-internal call sites can keep using the
/// record-id-only form because cross-TU symbol resolution doesn't exist
/// yet (and they're internal keys, not on-the-wire names).
pub fn borland_mangle_type_with_records(t: &Type, records: &[Record]) -> String {
    match t {
        Type::Record { id, .. } => match records.get(*id).and_then(|r| r.tag.as_ref()) {
            Some(tag) => format!("{}{}", tag.len(), tag),
            None => borland_user_type_code(*id),
        },
        Type::Ptr(p) | Type::Array(p, _) => {
            format!("p{}", borland_mangle_type_with_records(p, records))
        }
        Type::Ref(p) => format!("r{}", borland_mangle_type_with_records(p, records)),
        // S6 (#25b): thread the records table THROUGH function / member-function
        // types so a record buried in a function-pointer parameter resolves to
        // its stable class TAG, not the per-TU placeholder. The records-LESS
        // `borland_mangle_type` renders the member-fn-pointer class as `m<id>`
        // and any inner record as `R<id>` — per-TU integers that differ between
        // objects and never link. OWL's DDVT dispatchers are free functions
        // `v_Dispatch(GENERIC&, void(GENERIC::*)(…), …)`; with the records-less
        // path the PMF mangled `m966` in DISPATCH.CPP but `m969` in the
        // referencing TU (GENERIC's record id differs), so the `@v_Dispatch$q…`
        // reference never matched its definition. Resolving the class id to its
        // tag (`m7GENERIC…`) makes both sides agree. mdbcc's own structural form
        // is kept (ret-before-params, lowercase `m`) — self-consistent across the
        // all-mdbcc link; symbol bytes are internal, never observed at runtime.
        Type::Func { ret, params } => {
            let mut s = String::from("pq");
            s.push_str(&borland_mangle_type_with_records(ret, records));
            for p in params {
                s.push_str(&borland_mangle_type_with_records(p, records));
            }
            s
        }
        Type::MemFn {
            class_id,
            ret,
            params,
        } => {
            let cls = borland_mangle_type_with_records(
                &Type::Record {
                    id: *class_id,
                    size: 0,
                    align: 0,
                },
                records,
            );
            let mut s = format!("m{cls}q");
            s.push_str(&borland_mangle_type_with_records(ret, records));
            for p in params {
                s.push_str(&borland_mangle_type_with_records(p, records));
            }
            s
        }
        _ => borland_mangle_type(t),
    }
}

/// Mangle a virtual table symbol — `@<Class>@3` per HLD §3.4 (observed
/// in BCC's COMDEF output, e.g. `@Bar@3`, `@Base@3`, `@Derived@3`). The
/// trailing `3` is Borland's documented vtable sentinel (unrelated to
/// the digit-string lengths used in user-type codes).
pub fn borland_vtable_symbol(class_name: &str) -> String {
    format!("@{class_name}@3")
}

/// Mangle a typeinfo symbol — `@$xt$<encoding>` per HLD §3.4 (observed
/// as `@$xt$3Bar`, `@$xt$p3Bar`, `@$xt$4Base`, `@$xt$1D`). The encoding
/// is the type's [`borland_mangle_type_with_records`] form when a record
/// table is available, else the placeholder record-id form.
pub fn borland_typeinfo_symbol(ty: &Type, records: &[Record]) -> String {
    format!("@$xt${}", borland_mangle_type_with_records(ty, records))
}

/// Mangle a C-linkage function symbol — `_<name>` per HLD §3.1. Used for
/// `extern "C"` declarations and the canonical entry-point `main`. No
/// type encoding (C linkage has no overloading).
pub fn borland_c_symbol(name: &str) -> String {
    format!("_{name}")
}

/// Overload-resolution compatibility of an argument type `a` (already
/// decayed) with a parameter type `p`. Lower score = better match;
/// `None` means the parameter cannot accept the argument.
pub(crate) fn arg_compat(p: &Type, a: &Type) -> Option<i32> {
    if let Type::Ref(inner) = p {
        // A reference parameter binds to an lvalue of the referent type.
        if inner.as_ref() == a {
            return Some(0);
        }
        if inner.is_integer() && a.is_integer() {
            return Some(1);
        }
        if inner.is_pointer() && a.is_pointer() {
            return Some(1);
        }
        return None;
    }
    if p == a {
        return Some(0);
    }
    if p.is_integer() && a.is_integer() {
        return Some(1);
    }
    if p.is_pointer() && a.is_pointer() {
        return Some(1);
    }
    None
}

/// Phase H5: for every polymorphic class that has at least one overloaded
/// virtual method, replace the single inherited slot (parser builds at
/// most one slot per bare name) with one slot per overload, keyed by the
/// mangled symbol so [`crate::codegen::Gen::virtual_slot`] can disambiguate.
///
/// A non-overloaded virtual is left untouched ⇒ its vtable slot's key is
/// the bare name, its sym is `Tag::name` (the pre-H5 byte image). A class
/// without overloaded virtuals at all (the case in every `end_to_end.rs`
/// fixture) sees zero change ⇒ byte-identical.
///
/// Inheritance: the base class's slots are rewritten first (records are
/// stored in declaration order; the parser fully constructs each
/// record's `base` before any derived). The derived class then walks its
/// own `decl_methods`-equivalent (the methods of `tu.items` matching
/// `Tag::*`) and replaces the inherited slots with its own overrides
/// (keyed by mangled symbol). A derived class that introduces an
/// override of a single overload does NOT shadow the others (mdbcc
/// keeps all base slots; the C++ "any-derived-overload-shadows-all-
/// base-overloads-of-the-same-name" rule is documented as H-future).
pub(crate) fn rebuild_vtables_for_overloads(
    records: &mut [Record],
    overloads: &HashMap<String, Vec<Overload>>,
    name_counts: &HashMap<&str, usize>,
    items: &[Item],
    extern_protos: &[Function],
) {
    // Quickly answer "is `Tag::name` overloaded in this TU?" — used both to
    // decide whether to rewrite a slot and to choose its mangled key.
    let is_overloaded = |qname: &str| -> bool { name_counts.get(qname).copied().unwrap_or(0) > 1 };
    // Index into functions/prototypes for each `Tag::name` (declaration order
    // preserved). Out-of-line virtual declarations live in `extern_protos`, not
    // `items`, but still own vtable slots and overload signatures.
    fn same_sig(records: &[Record], a: &Function, b: &Function) -> bool {
        a.name == b.name
            && a.const_method == b.const_method
            && a.params.len() == b.params.len()
            && a.params.iter().zip(&b.params).all(|((_, aty), (_, bty))| {
                complete_record_sizes(aty, records) == complete_record_sizes(bty, records)
            })
    }
    fn qualified_method_name(tag: &str, base: &str) -> String {
        if base == "~" {
            format!("{tag}::~{tag}")
        } else {
            format!("{tag}::{base}")
        }
    }
    fn methods_of<'a>(
        records: &[Record],
        items: &'a [Item],
        extern_protos: &'a [Function],
        tag: &str,
        base: &str,
    ) -> Vec<&'a Function> {
        let q = qualified_method_name(tag, base);
        let mut out: Vec<&Function> = Vec::new();
        for f in items.iter().filter_map(|i| match i {
            Item::Func(f) if f.name == q => Some(f),
            _ => None,
        }) {
            if let Some(pos) = out
                .iter()
                .position(|existing| same_sig(records, existing, f))
            {
                if f.virtual_method && !out[pos].virtual_method {
                    out[pos] = f;
                }
            } else {
                out.push(f);
            }
        }
        for proto in extern_protos.iter().filter(|p| p.name == q) {
            if let Some(pos) = out.iter().position(|f| same_sig(records, f, proto)) {
                if proto.virtual_method && !out[pos].virtual_method {
                    out[pos] = proto;
                }
            } else {
                out.push(proto);
            }
        }
        out
    }
    let slot_source_name = |key: &str| -> String {
        if let Some(rest) = key.strip_prefix('@') {
            let head = rest.rsplit_once('$').map(|(h, _)| h).unwrap_or(rest);
            head.rsplit('@').next().unwrap_or(key).to_string()
        } else {
            key.to_string()
        }
    };
    fn overload_suffix(sym: &str) -> Option<&str> {
        sym.rsplit_once('$').map(|(_, suffix)| suffix)
    }
    // Walk classes in declaration order. After rewriting class `id`, its
    // (potentially expanded) vtable is the source of truth for any
    // derived class's inherited slots — but the parser's `vtable` field
    // captured a SNAPSHOT before H5, so a derived class's vtable is the
    // base's stale (single-slot-per-name) snapshot plus the derived's own
    // contributions. We re-derive the inherited prefix from the base's
    // freshly rewritten vtable to keep slot indices consistent end-to-end.
    let record_count = records.len();
    for id in 0..record_count {
        if !records[id].is_polymorphic() {
            continue;
        }
        let tag = match records[id].tag.clone() {
            Some(t) => t,
            None => continue,
        };
        // Bases first: inherit the (already-rewritten) base vtable.
        let base_vtable: Vec<VtSlot> = match records[id].base {
            Some(bid) => records[bid].vtable.clone(),
            None => Vec::new(),
        };
        // Collect this class's virtual base-names from its existing
        // vtable (anything beyond the base's slot count is a new virtual
        // introduced here; anything covered by the base's range is an
        // override candidate).
        let cur = records[id].vtable.clone();
        // Distinct base method names (the unmangled keys) introduced in
        // THIS class. The parser's derived vtable is a stale pre-rebuild
        // snapshot of the inherited slots, so do not use slot positions here:
        // once a base overloaded virtual expands from one slot to several,
        // positional `skip(base_vtable.len())` would skip real local virtuals.
        let mut new_local_names: Vec<String> = Vec::new();
        let base_names: std::collections::HashSet<String> = base_vtable
            .iter()
            .map(|s| slot_source_name(&s.key))
            .collect();
        for s in &cur {
            if !base_names.contains(&s.key) && !new_local_names.iter().any(|n| n == &s.key) {
                new_local_names.push(s.key.clone());
            }
        }
        // For each base slot: if this class overrides it (by name) with an
        // overloaded method set, keep the slot's KEY (mangled by base
        // alignment is impossible since we never had multi-slot bases pre-
        // H5 — see invariant), but rewrite its SYM to the matching
        // overload. The first-pass simplification: an override of a single
        // overload uses positional matching against the base's mangled
        // slot key.
        let mut new_vtable: Vec<VtSlot> = base_vtable.clone();
        // Apply overrides from THIS class by source name/signature. A derived
        // record's parser-built vtable still contains stale inherited slots;
        // copying those by position after the base expanded overloaded virtuals
        // can overwrite an inherited slot with a bare base symbol (OWL
        // `TStartup` inheriting `TWindow::GetClassName`).
        for slot in &mut new_vtable {
            let base_name = slot_source_name(&slot.key);
            let virtual_methods: Vec<&Function> =
                methods_of(records, items, extern_protos, &tag, &base_name)
                    .into_iter()
                    .filter(|f| f.virtual_method)
                    .collect();
            if virtual_methods.is_empty() {
                continue;
            }
            if slot.key.starts_with('@') {
                let Some(slot_suffix) = overload_suffix(&slot.key) else {
                    continue;
                };
                let q = qualified_method_name(&tag, &base_name);
                for f in virtual_methods {
                    let sym =
                        overload_symbol_with_records(&f.name, &f.params, f.const_method, records);
                    if overload_suffix(&sym) == Some(slot_suffix) {
                        slot.sym = if overloads.contains_key(&q) {
                            sym
                        } else {
                            f.name.clone()
                        };
                        break;
                    }
                }
            } else {
                let f = virtual_methods[0];
                let q = qualified_method_name(&tag, &base_name);
                slot.sym = if overloads.contains_key(&q) {
                    overload_symbol_with_records(&f.name, &f.params, f.const_method, records)
                } else {
                    f.name.clone()
                };
            }
        }
        // Now expand new virtuals introduced in this class (after the
        // base's slot range) — these may each be a single virtual OR an
        // overload set.
        for base_name in &new_local_names {
            let q = qualified_method_name(&tag, base_name);
            if is_overloaded(&q) {
                // One slot per overload (mangled key + mangled sym).
                // Phase J-1: a const member function gets the `K` suffix
                // so const/non-const virtual overloads occupy distinct
                // slots — `virtual int f(int)` and `virtual int f(int)
                // const` are independent virtual functions in C++.
                let ms = methods_of(records, items, extern_protos, &tag, base_name);
                for f in ms.into_iter().filter(|f| f.virtual_method) {
                    // G14: mangle the vtable-slot symbol with the RECORD TABLE so
                    // a record-typed parameter resolves to its real class tag
                    // (`4TPen`) instead of the per-TU placeholder `R<id>`. The
                    // function DEFINITION and every CALL site already mangle via
                    // `*_with_records`; the slot was the sole tagless site, so an
                    // overloaded virtual taking a record arg (TDC::SelectObject(
                    // TPen&) …) emitted a vtable slot pointing at `@TDC@
                    // SelectObject$qr4R972` while the body was `…$qr4TPen` — a
                    // split symbol that left the slot's target unresolved at link.
                    let sym =
                        overload_symbol_with_records(&f.name, &f.params, f.const_method, records);
                    new_vtable.push(VtSlot {
                        key: sym.clone(),
                        params: f.params.iter().skip(1).map(|(_, t)| t.clone()).collect(),
                        sym,
                    });
                }
            } else {
                // Non-overloaded by NAME: keep the parser's dispatch KEY (name-
                // based virtual dispatch finds the slot by `key`). But if the
                // method's DEFINITION is emitted MANGLED — i.e. it is in
                // `overloads` even though its name appears once (the default-arg
                // case: a single `virtual bool Find(TEventInfo&, TEqualOperator
                // = 0)` registers as an overload via its two arities) — the
                // parser's bare `Tag::method` slot SYM mismatches the mangled
                // def and never links. Re-mangle the SYM (only) to match the def
                // (same `overload_symbol_with_records(name, params, …)` the
                // emit pass uses at the `sigs.overloads.contains` gate). Fixes
                // the OWL response-table cluster (TEventHandler/TWindow/…::Find
                // & ::Dispatch and every railc class's own Find/Dispatch).
                if let Some(slot) = cur.iter().find(|s| &s.key == base_name) {
                    let mut slot = slot.clone();
                    let q = qualified_method_name(&tag, base_name);
                    if overloads.contains_key(&q)
                        && let Some(f) = methods_of(records, items, extern_protos, &tag, base_name)
                            .into_iter()
                            .find(|f| f.virtual_method)
                    {
                        slot.sym = overload_symbol_with_records(
                            &f.name,
                            &f.params,
                            f.const_method,
                            records,
                        );
                    }
                    new_vtable.push(slot);
                }
            }
        }
        records[id].vtable = new_vtable;
    }
}

/// Tick 66 (J-10b): build a synthesised memberwise copy ctor for class
/// `id` (record `rec`). The body is a flat list of per-field operations:
/// a class-typed sub-object whose type has a user copy ctor invokes that
/// ctor with rcx/rdx pointing into the destination/source sub-objects;
/// every other field type (plain data, int arrays, etc.) is byte-copied
/// directly. The compiled function has the canonical mdbcc prologue +
/// epilogue (matching `Gen::run`) so `pe::read_prolog_alloc` accepts it
/// when emitting UNWIND_INFO.
///
/// The resulting `CompiledFn`'s name is `"Tag::Tag"` — same key the
/// parser would have used for a user-written copy ctor. Pre-condition:
/// `rec.tag.is_some()` (anonymous classes can't synthesise; the entry
/// errors loudly if reached with a tagless record).
pub(crate) fn build_synth_copy_ctor(
    id: usize,
    rec: &Record,
    sigs: &Sigs,
    target: TargetKind,
) -> Result<CompiledFn, CodegenError> {
    // S-i386copy: emit the body for the actual target. The historical body was
    // Win64-only (this/src in rcx/rdx, REX.W throughout, RIP-relative vtable) —
    // garbage on i386, where ctor args arrive on the stack (this=[ebp+8],
    // src=[ebp+12]) and there is no REX.W / RIP-relative. The i386 path mirrors
    // the Win64 one byte-for-byte except for these target-specific shapes, so a
    // Win64 build stays byte-identical.
    let is_i386 = target == TargetKind::Win32;
    let tag = rec.tag.clone().ok_or_else(|| {
        CodegenError(
            "synthesised copy ctor requires a tagged class; an anonymous \
             record reached the synthesis path (defensive)"
                .into(),
        )
    })?;
    // S4.2ay: emit under the SAME symbol the registration recorded — the
    // mangled `$bctr$` form when the synth is an OVERLOAD (the class also has a
    // user ctor), or the bare `Tag::Tag` when it is the sole `funcs` entry.
    // `copy_ctor_symbol` returns exactly that (overloads path 1, else funcs
    // path 2), so callers (`copy_ctor_symbol` at the copy site) and this
    // definition agree on the linker symbol.
    let name = sigs
        .copy_ctor_symbol(id)
        .unwrap_or_else(|| format!("{tag}::{tag}"));
    let mut code: Vec<u8> = Vec::with_capacity(128);
    let mut calls: Vec<CallSite> = Vec::new();
    // ---- prologue ----
    //
    // Matches the historical mdbcc prologue (`Gen::run`) verbatim —
    // `pe::read_prolog_alloc` validates these exact bytes when emitting
    // UNWIND_INFO, so the synthesised function MUST use the imm32-`sub
    // rsp` encoding (NOT the 1-byte `83 EC <i8>` short form, which the
    // pdata builder rejects).
    if is_i386 {
        // i386 cdecl: `this` and `src` arrive on the stack at [ebp+8] and
        // [ebp+12]; no register spill and no shadow space.
        code.extend_from_slice(&[0x55]); // push ebp
        code.extend_from_slice(&[0x89, 0xE5]); // mov ebp, esp
    } else {
        code.extend_from_slice(&[0x55]); // push rbp
        code.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp
        code.extend_from_slice(&[0x48, 0x81, 0xEC]); // sub rsp, imm32
        code.extend_from_slice(&48u32.to_le_bytes()); // 48 bytes — 16 locals + 32 shadow
        // mov [rbp-8],  rcx  (this)
        code.extend_from_slice(&[0x48, 0x89, 0x4D, 0xF8]);
        // mov [rbp-16], rdx  (src)
        code.extend_from_slice(&[0x48, 0x89, 0x55, 0xF0]);
    }

    // Emit a byte-copy of `size` bytes from [rdx+rdx_off] to [rcx+rcx_off].
    // rcx and rdx point at the destination object and source object
    // respectively (re-derived from [rbp-8] / [rbp-16] right before the
    // copy emission — kept self-contained per field).
    let emit_field_bytes = |code: &mut Vec<u8>, off: i32, sz: usize| {
        // Load rcx/ecx = this (dst base), rdx/edx = src (src base). The per-byte
        // `mov al,[edx+d]` / `mov [ecx+d],al` below are 8-bit (no REX.W) so they
        // are byte-identical across targets; only this base load differs.
        if is_i386 {
            code.extend_from_slice(&[0x8B, 0x4D, 0x08]); // mov ecx, [ebp+8]  (this)
            code.extend_from_slice(&[0x8B, 0x55, 0x0C]); // mov edx, [ebp+12] (src)
        } else {
            code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF8]); // mov rcx, [rbp-8]
            code.extend_from_slice(&[0x48, 0x8B, 0x55, 0xF0]); // mov rdx, [rbp-16]
        }
        for i in 0..sz as i32 {
            let disp = off + i;
            // mov al, [rdx+disp32]
            code.extend_from_slice(&[0x8A, 0x82]);
            code.extend_from_slice(&disp.to_le_bytes());
            // mov [rcx+disp32], al
            code.extend_from_slice(&[0x88, 0x81]);
            code.extend_from_slice(&disp.to_le_bytes());
        }
    };

    // Emit one copy-ctor invocation for a class-typed sub-object at byte
    // offset `off` from the object base, using `inner_ctor_sym` as the
    // callee. rcx = this + off (dst), rdx = src + off (src). Both
    // additions are LEAs from the spilled base pointers.
    let emit_inner_ctor_call =
        |code: &mut Vec<u8>, calls: &mut Vec<CallSite>, off: i32, sym: String| {
            if is_i386 {
                // i386 cdecl: call inner(this+off, src+off) — push src+off, then
                // this+off (so `this` lands at [esp]/[ebp+8] in the callee), call,
                // caller cleans the 8 bytes.
                code.extend_from_slice(&[0x8B, 0x55, 0x0C]); // mov edx, [ebp+12] (src)
                if off != 0 {
                    code.extend_from_slice(&[0x8D, 0x92]); // lea edx, [edx+off]
                    code.extend_from_slice(&off.to_le_bytes());
                }
                code.extend_from_slice(&[0x52]); // push edx (inner src)
                code.extend_from_slice(&[0x8B, 0x4D, 0x08]); // mov ecx, [ebp+8] (this)
                if off != 0 {
                    code.extend_from_slice(&[0x8D, 0x89]); // lea ecx, [ecx+off]
                    code.extend_from_slice(&off.to_le_bytes());
                }
                code.extend_from_slice(&[0x51]); // push ecx (inner this)
                code.extend_from_slice(&[0xE8]); // call rel32
                let at = code.len();
                code.extend_from_slice(&[0, 0, 0, 0]);
                calls.push(CallSite {
                    at,
                    callee: sym,
                    loc: Loc::default(),
                });
                code.extend_from_slice(&[0x83, 0xC4, 0x08]); // add esp, 8 (cdecl cleanup)
            } else {
                // mov rcx, [rbp-8]   ; rcx = this
                code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF8]);
                // lea rcx, [rcx+off] (combine via 48 8D 89 imm32 when off!=0)
                if off != 0 {
                    code.extend_from_slice(&[0x48, 0x8D, 0x89]);
                    code.extend_from_slice(&off.to_le_bytes());
                }
                // mov rdx, [rbp-16]  ; rdx = src
                code.extend_from_slice(&[0x48, 0x8B, 0x55, 0xF0]);
                // lea rdx, [rdx+off]
                if off != 0 {
                    code.extend_from_slice(&[0x48, 0x8D, 0x92]);
                    code.extend_from_slice(&off.to_le_bytes());
                }
                // call <inner copy ctor> — direct relative call, patched by
                // the PE writer via `CallSite`.
                code.extend_from_slice(&[0xE8]);
                let at = code.len();
                code.extend_from_slice(&[0, 0, 0, 0]);
                calls.push(CallSite {
                    at,
                    callee: sym,
                    loc: Loc::default(),
                });
            }
        };

    let mut riprefs: Vec<RipReloc> = Vec::new();

    // ---- base subobject (S4.2b1 / J-10b-base-chain) ----
    // If the base has its OWN copy ctor (user or synthesised), CHAIN into it on
    // the base subobject (`this + base_offset`, via the same 2-arg this+src ABI
    // as a member copy ctor) and SKIP the base's re-laid fields in the loop
    // (parser.rs ~1486 lays `[base fields ++ derived fields]`). A TRIVIAL base
    // (no copy ctor) needs no call — its fields are copied by the loop.
    let base_skip: Option<(i32, i32)> = match rec.base {
        Some(bid) => match sigs.copy_ctor_symbol(bid) {
            Some(base_copy_sym) => {
                let base_off = rec.base_offset as i32;
                emit_inner_ctor_call(&mut code, &mut calls, base_off, base_copy_sym);
                let base_size = sigs.records.get(bid).map(|r| r.size).unwrap_or(0) as i32;
                Some((base_off, base_off + base_size))
            }
            None => None,
        },
        None => None,
    };

    // ---- body: one entry per field ----
    for f in &rec.fields {
        // S4.2b1: a field inside the base subobject was already copied by the
        // chained base copy ctor above — don't copy it twice.
        if let Some((lo, hi)) = base_skip
            && (f.offset as i32) >= lo
            && (f.offset as i32) < hi
        {
            continue;
        }
        // Walk into arrays to discover the element type.
        let (elem_ty, count) = {
            let mut t = &f.ty;
            let mut c: usize = 1;
            while let Type::Array(inner, n) = t {
                c *= *n;
                t = inner;
            }
            (t, c)
        };
        let off = f.offset as i32;
        match elem_ty {
            Type::Record { id: inner_id, .. }
                if *inner_id != id
                    && let Some(sym) = sigs.copy_ctor_symbol(*inner_id) =>
            {
                let elem_size = sigs.records.get(*inner_id).map(|r| r.size).unwrap_or(0);
                for k in 0..count {
                    emit_inner_ctor_call(
                        &mut code,
                        &mut calls,
                        off + (k * elem_size) as i32,
                        sym.clone(),
                    );
                }
            }
            _ => {
                // Trivial: byte-copy the whole field (size already
                // accounts for array extents through `f.ty.size()`).
                emit_field_bytes(&mut code, off, f.ty.size());
            }
        }
    }

    // ---- vptr install (S4.2az / J-10b-base, polymorphic) ----
    // The hidden vptr at `[this+0]` is NOT a field, so the copies above never
    // touched it (a chained polymorphic-base ctor leaves the BASE's vtable
    // there). Install THIS class's vtable so virtual dispatch on the COPY is
    // correct — `lea rax,[rip+vtable(id)]; mov [this], rax`, mirroring the
    // parser-injected `SetVptr` a normal ctor emits. A synth-copy-ctor class is
    // forced live in `compile_module`, so `RipRef::Vtable(id)` resolves.
    if rec.is_polymorphic() {
        if is_i386 {
            // i386: `lea eax,[abs vtable]` (no REX.W; ModRM 0x05 = disp32
            // ABSOLUTE, an Addr32 reloc the PE writer applies for I386 objects —
            // same RipRef::Vtable the Stmt::SetVptr path uses). Then store the
            // 4-byte vptr at [this+0].
            code.extend_from_slice(&[0x8D, 0x05]); // lea eax, [abs]
            let at = code.len();
            code.extend_from_slice(&[0, 0, 0, 0]);
            riprefs.push(RipReloc {
                at,
                target: RipRef::Vtable(id),
            });
            code.extend_from_slice(&[0x8B, 0x4D, 0x08]); // mov ecx, [ebp+8] (this)
            code.extend_from_slice(&[0x89, 0x01]); // mov [ecx], eax
        } else {
            code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF8]); // mov rcx, [rbp-8] (this)
            code.extend_from_slice(&[0x48, 0x8D, 0x05]); // lea rax, [rip+disp32]
            let at = code.len();
            code.extend_from_slice(&[0, 0, 0, 0]);
            riprefs.push(RipReloc {
                at,
                target: RipRef::Vtable(id),
            });
            code.extend_from_slice(&[0x48, 0x89, 0x01]); // mov [rcx], rax
        }
    }

    // ---- epilogue ----
    // `leave` (`c9`) = `mov rsp, rbp; pop rbp` — matches `Gen::epilogue`.
    code.extend_from_slice(&[0xC9]); // leave
    code.extend_from_slice(&[0xC3]); // ret

    Ok(CompiledFn {
        name,
        code,
        calls,
        riprefs,
        strings: Vec::new(),
        fp_literals: Vec::new(),
        try_scopes: Vec::new(),
        extern_refs: Vec::new(),
        // S4.2af: a synthesised copy-ctor is emitted (identically) by every TU
        // that copies the class, so its symbol folds across objects.
        inline: true,
    })
}
