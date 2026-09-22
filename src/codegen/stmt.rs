//! Statement-level codegen support helpers.
//!
//! The bulk of statement lowering — `Gen::gen_stmt`, `Gen::gen_stmt_inner`,
//! `Gen::gen_throw_int`, `Gen::gen_rethrow`, `Gen::gen_try`,
//! `Gen::gen_init_list_into_slot`, and friends — still lives on `impl Gen`
//! in `src/codegen.rs` because every one of those methods threads through
//! the full per-function code stream, slot allocator, scope stack, dtor
//! tracking, catch-context stack, and PC tracking. Splitting them into a
//! separate file would require making roughly two dozen `Gen` fields and
//! at least as many helper methods `pub(crate)` for a marginal readability
//! win; the eh.rs precedent already demonstrated that pattern works, but
//! we land it incrementally if/when a later S1 sub-phase needs it.
//!
//! What lives HERE is the rethrow-scan free function pair that drives the
//! catch-context push in `Gen::gen_try` (deciding whether a catch handler
//! body contains a bare `throw;` and therefore needs a CatchCtx pushed
//! onto the stack so rethrows can find the caught value). These are pure
//! AST walks — no `Gen` state, no codegen emission — so they extract
//! cleanly.
//!
//! ## O1 byte-identity invariant
//!
//! Pure refactor. The scans return identical bool decisions to before
//! the split, so the codegen emission they gate is unchanged.

use crate::ast::Stmt;

/// J-7: does this catch body contain a bare `throw;` (rethrow) at any
/// nesting depth (including inside `if`/`while`/`for`/blocks)? Returns
/// `true` if at least one such statement exists. Inner nested
/// try/catches whose own catch bodies contain a `throw;` count as their
/// OWN catch's rethrow — that inner catch's lowering handles it — so
/// we must NOT recurse into `Stmt::Try { catches }`: a rethrow inside a
/// nested catch belongs to that nested catch, not the outer one.
///
/// Used by `Gen::gen_try` to decide whether to push a `CatchCtx` for a
/// given catch clause: if its body doesn't rethrow, no context push
/// happens and (for anonymous catches) no RAX spill either, keeping
/// byte-identity for the common (non-rethrow) case.
pub(crate) fn catch_body_rethrows(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_rethrows)
}

pub(crate) fn stmt_rethrows(s: &Stmt) -> bool {
    match s {
        Stmt::Throw(None, _) => true,
        Stmt::Throw(Some(_), _) => false,
        Stmt::Block(b, _) => catch_body_rethrows(b),
        Stmt::If { then, els, .. } => {
            stmt_rethrows(then) || els.as_deref().is_some_and(stmt_rethrows)
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => stmt_rethrows(body),
        Stmt::For { init, body, .. } => {
            init.as_deref().is_some_and(stmt_rethrows) || stmt_rethrows(body)
        }
        // A nested `try`'s body still belongs to the outer catch — a
        // bare `throw;` inside that body is the outer catch's rethrow.
        // But a `throw;` inside one of the NESTED `try`'s catch bodies
        // belongs to that inner catch — exclude those.
        Stmt::Try { body, catches: _, .. } => catch_body_rethrows(body),
        // S3: a `throw;` inside a `switch` belongs to the enclosing catch.
        Stmt::Switch { body, .. } => stmt_rethrows(body),
        Stmt::Return(..)
        | Stmt::ExprStmt(..)
        | Stmt::SetVptr(..)
        | Stmt::Decl { .. }
        | Stmt::Case { .. }
        | Stmt::Default(_)
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(..)
        | Stmt::Goto(..)
        // MemberInit (a ctor member-initializer marker) never appears in a
        // catch body and is rewritten away before codegen; it cannot rethrow.
        | Stmt::MemberInit { .. }
        // G40: a reference-member bind is a plain address store — no rethrow.
        | Stmt::RefBindMember { .. }
        | Stmt::Empty => false,
    }
}
