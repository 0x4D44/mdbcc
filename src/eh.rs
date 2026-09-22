//! Phase H SEH (Structured Exception Handling) machinery for mdbcc.
//!
//! This module centralises the EH-specific surface that was previously
//! interleaved with general codegen:
//!
//! * The two custom NTSTATUS-shaped exception codes
//!   (`EXCEPTION_MDBCC_INT` / `EXCEPTION_MDBCC_CLASS`) and the synthetic
//!   per-thread exception-buffer global name (`EH_BUFFER_NAME`).
//! * The runtime scope-table descriptor types ([`TryScope`],
//!   [`CatchPolicy`], [`TypeInfoEntry`]) and the codegen-internal
//!   catch-context stack types ([`CatchCtx`], [`CatchKindLow`]) used by
//!   the `throw` / `try` / rethrow lowerings.
//! * The synthetic SEH personality function emitter
//!   ([`build_personality_function`]) — ~165 bytes of hand-emitted
//!   x86-64 that implements the search-phase dispatch for our custom
//!   exception codes.
//! * The pre-pass predicate [`tu_has_try_or_throw`] that the
//!   `compile_module` orchestration uses to gate buffer allocation and
//!   personality emission.
//!
//! The throw / try / rethrow lowering METHODS themselves remain in
//! `src/codegen.rs` because they are tightly coupled to `Gen` state
//! (the codegen context — local slots, temps, scopes, RipRef emission).
//! They reference the types here via `use crate::eh::*;`.
//!
//! The PE-section builders (`build_pdata` / `build_xdata` /
//! `build_typeinfo` / `read_prolog_alloc`) likewise remain in
//! `src/pe.rs` because they reach into pe-writer internals
//! (`Buf`, `stub_len`, the `UWOP_*` / `UNW_FLAG_EHANDLER` /
//! `MDBCC_PROLOG_*` constants); moving them would leak more pe-writer
//! private state through the module boundary than the centralisation
//! benefit justifies.
//!
//! ## O1 byte-identity invariant
//!
//! This module is a pure refactor of pre-existing code. The personality
//! function's emitted byte stream is identical to the previous
//! `codegen::build_personality_function` output; the constants and type
//! shapes are unchanged. `tests/o1_byte_identity.rs` (88 SipHash
//! baselines) is the regression lock — if anything in this module
//! changes a single emitted byte, those baselines diverge.

use crate::ast::{Item, Stmt, TranslationUnit};
use crate::codegen::{CompiledFn, RipRef, RipReloc};

/// Phase H4a: the custom NTSTATUS-shaped exception code we throw from
/// `throw <int-expr>;`. Layout (top down, 32 bits):
///
/// * `Sev = 0b11` (ERROR — `STATUS_SEVERITY_ERROR`, `0x8000_0000`).
/// * `C = 1` (Customer bit — `0x2000_0000`; tells the OS "this is a
///   non-Microsoft code", so it never collides with `STATUS_*` system
///   codes the kernel might define).
/// * `R = 0` (Reserved).
/// * `Fac = 0` (Facility — none; reserved for any future H-mdbcc
///   sub-facility).
/// * `Code = 1` (Our throw-int marker; H4b will add `0xE0000002` for
///   class-typed throws).
///
/// Together: `0xE0000001`. The personality function recognises this
/// code and reads `EXCEPTION_RECORD.ExceptionInformation[0]` as the
/// thrown int value (zero-extended to 64 bits — RaiseException's
/// `lpArguments` array is copied INTO ExceptionInformation by value).
pub(crate) const EXCEPTION_MDBCC_INT: u32 = 0xE000_0001;

/// Phase H4b: the custom NTSTATUS-shaped exception code we throw from
/// `throw <class-expr>;`. Same `Sev|C` bit pattern as
/// [`EXCEPTION_MDBCC_INT`] but `Code = 2` so the personality function
/// can dispatch on it and read the two `ExceptionInformation` slots
/// the throw lowering populates:
/// * `[0]` — the thrown object's vtable ABSOLUTE address (the
///   personality function converts to an RVA by subtracting
///   `DispatcherContext->ImageBase` before walking the hierarchy).
/// * `[1]` — the absolute address of the shared exception buffer
///   `.mdbcc_eh_buffer` (the value delivered to a `Tag&` / `Tag*`
///   catch as the reference / pointer it sees).
pub(crate) const EXCEPTION_MDBCC_CLASS: u32 = 0xE000_0002;

/// Phase H4b: synthetic global symbol name for the shared exception
/// buffer that class throws copy their value into. Naming convention
/// mirrors `.flit.*` (FP literals) and `.mdbcc_seh_personality`: a
/// leading dot guarantees no clash with user-defined C identifiers.
pub(crate) const EH_BUFFER_NAME: &str = ".mdbcc_eh_buffer";

/// Tick 69 (J-11b / J-15b): synthetic global symbol name for the
/// EXCEPTION_RECORD save area the personality function copies before
/// calling `RtlUnwindEx`. A cleanup landing pad needs to re-raise with
/// the original code+args, but the ExceptionRecord pointer that the
/// personality function holds points into the (now-unwound)
/// `RtlDispatchException` stack frame which is reclaimed after the
/// unwind transfer. The save area keeps the values stable across the
/// unwind so the re-raise reads valid bytes.
///
/// Layout (24 bytes):
/// ```text
///   [+0]  u32 code         (ExceptionCode, e.g. 0xE0000001)
///   [+4]  u32 numparams    (ExceptionRecord.NumberParameters)
///   [+8]  u64 args[0]      (ExceptionInformation[0])
///   [+16] u64 args[1]      (ExceptionInformation[1])
/// ```
/// We only carry args[0..1] because both supported throw shapes (int
/// throw and class throw) use at most 2 args.
pub(crate) const EH_SAVE_NAME: &str = ".mdbcc_eh_save";

/// Size in bytes of the [`EH_SAVE_NAME`] global. Kept as a named
/// constant so the personality function and the cleanup-pad emitter
/// share one source of truth.
pub(crate) const EH_SAVE_SIZE: usize = 24;

/// Phase H4a: stable symbol the PE writer references when filling in
/// `UNWIND_INFO.ExceptionHandler`. Exposed for `crate::pe` so the
/// "synthesise here, reference there" wiring goes through one named
/// constant (mirrors how `WIN32_IMPORTS` is the single source of truth
/// for symbol resolution between codegen and pe).
pub(crate) const PERSONALITY_FN_NAME: &str = ".mdbcc_seh_personality";

/// S2e (i386 fs:[0] SEH): stable symbol for the module-wide x86 frame-based
/// exception handler. The x86 SEH model is a `fs:[0]`-rooted linked list of
/// `EXCEPTION_REGISTRATION` records (HLD §7); the per-function prologue pushes
/// one record naming this handler and the epilogue pops it. The handler is the
/// x86 analogue of [`build_personality_function`] (the x64 personality). The
/// leading dot guarantees no clash with user-named C/C++ identifiers (mirrors
/// `.flit.*` / [`PERSONALITY_FN_NAME`]). Win32-only — never emitted for Win64.
pub(crate) const SEH3_HANDLER_NAME: &str = ".mdbcc_seh3_handler";

/// S2e (class EH): stable symbol for the x86 fs:[0] handler installed by a
/// function whose `try` has a CLASS catch (see [`build_seh3_class_handler`]).
pub(crate) const SEH3_CLASS_HANDLER_NAME: &str = ".mdbcc_seh3_class_handler";

/// S2e: build the module-wide x86 frame-based exception handler.
///
/// This is the x86 (Win32) analogue of [`build_personality_function`]. Where
/// the x64 personality is referenced from `.xdata` UNWIND_INFO and unwinds via
/// `RtlUnwindEx`, the x86 handler is reached through the thread's `fs:[0]`
/// `EXCEPTION_REGISTRATION` chain and resumes the catch block by *editing the
/// trap CONTEXT* and returning `ExceptionContinueExecution` (no `RtlUnwind`
/// call — the minimal-int-catch milestone handles only same-frame `try`).
///
/// ## Registration record the prologue installs (HLD §7.1, extended)
///
/// The per-function prologue (`Gen::run`, Win32 + has-try) pushes a 16-byte
/// record so that, with `regptr = EstablisherFrame`:
/// ```text
///   [regptr+0]  prev        (previous fs:[0] link)
///   [regptr+4]  handler     (= this function; the OS reads + calls it)
///   [regptr+8]  catch_pad   (absolute VA of the catch landing pad)
///   [regptr+12] frame       (the function's `sub esp, N` frame size)
/// ```
/// and `regptr = ebp - 16` (the prologue does `push ebp; mov ebp,esp` first),
/// so `ebp = regptr + 16` and the function's working `esp = regptr - frame`.
///
/// ## Calling convention
///
/// The OS exception dispatcher (`RtlpExecuteHandlerForException`) invokes a
/// frame handler as `__cdecl`:
/// ```c
/// EXCEPTION_DISPOSITION __cdecl handler(
///     EXCEPTION_RECORD        *er,    // [ebp+8]
///     void                    *frame, // [ebp+12]  (= regptr)
///     CONTEXT                 *ctx,   // [ebp+16]
///     void                    *dc);   // [ebp+20]
/// ```
/// We restore the stack with `pop ebp; ret` (caller cleans — NOT `ret N`).
///
/// ## Behaviour
///
/// 1. `er->ExceptionCode != EXCEPTION_MDBCC_INT` → `ExceptionContinueSearch`.
/// 2. `er->ExceptionFlags & (EH_UNWINDING|EH_EXIT_UNWIND)` → ContinueSearch
///    (we own the search phase; we resume directly, never re-dispatch).
/// 3. Otherwise deliver: set `ctx->Eax = er->ExceptionInformation[0]` (the
///    thrown int), `ctx->Eip = catch_pad`, `ctx->Ebp = regptr+16`,
///    `ctx->Esp = regptr - frame`, return `ExceptionContinueExecution` (0).
///    The OS resumes the thread at the catch pad, which stores `eax` into the
///    catch parameter's slot (the same `mov [ebp-slot], eax` the x64 path
///    lands on).
///
/// Class throws / nested try / rethrow / dtor-during-unwind are out of scope
/// for this milestone (follow-on ticks); this handler recognises only
/// `EXCEPTION_MDBCC_INT` and a single catch pad per frame.
pub(crate) fn build_seh3_handler() -> CompiledFn {
    // EXCEPTION_RECORD field offsets (32-bit).
    const ER_FLAGS: u8 = 0x04;
    const ER_INFO0: u8 = 0x14; // ExceptionInformation[0]

    let mut code = Vec::with_capacity(96);
    let mut riprefs: Vec<RipReloc> = Vec::new();

    // --- prologue: a normal frame; we abandon it via `jmp` on the match
    //     path (transferring into the catch with the establisher's frame),
    //     and unwind cleanly on the continue-search path.
    code.extend_from_slice(&[0x55]); // push ebp
    code.extend_from_slice(&[0x89, 0xE5]); // mov ebp, esp

    // eax = er  (= [ebp+8])
    code.extend_from_slice(&[0x8B, 0x45, 0x08]); // mov eax, [ebp+8]
    // ecx = er->ExceptionCode ([eax+0])
    code.extend_from_slice(&[0x8B, 0x08]); // mov ecx, [eax]
    // cmp ecx, EXCEPTION_MDBCC_INT
    code.extend_from_slice(&[0x81, 0xF9]);
    code.extend_from_slice(&EXCEPTION_MDBCC_INT.to_le_bytes()); // cmp ecx, imm32
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne continue_search
    let jne_cs = code.len() - 4;

    // test er->ExceptionFlags, EH_UNWINDING|EH_EXIT_UNWIND (2|4 = 6) — during
    // the unwind phase we have nothing to do (we transfer directly), so bow out.
    code.extend_from_slice(&[0xF7, 0x40, ER_FLAGS, 0x06, 0x00, 0x00, 0x00]); // test dword [eax+4], 6
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne continue_search
    let jnz_cs = code.len() - 4;

    // --- match: unwind intermediate frames, then transfer into the catch. ---
    //
    // x86 `RtlUnwind` returns to ITS CALLER after unwinding the fs:[0] chain
    // down to `TargetFrame` (calling each intervening handler with
    // EH_UNWINDING). It is documented to preserve EBP for its caller (it must,
    // to return) but its handling of EBX/ESI/EDI is implementation-quirky — so
    // we rely on NOTHING but our own intact EBP frame across the call. Both the
    // handler's argument slots (`[ebp+8]` er, `[ebp+12]` regptr) and the
    // establisher record memory (`regptr` = main's stack, NOT unwound, so
    // `[regptr+8]` catch pad / `[regptr+12]` frame) survive the call.
    //
    // The thrown int lives in the EXCEPTION_RECORD, which RaiseException built
    // on a now-unwound frame; stash it BEFORE the unwind so we can re-read it
    // after from stable memory. We park it at [regptr-4] (= [ebp_target-20],
    // the establisher's first-local region, which is NOT unwound). This may
    // overlap the function's first local slot, but the write+read-back both
    // happen here in the handler BEFORE we transfer — the catch landing pad's
    // first act is to store the delivered EAX into the catch parameter, so the
    // transient use of this byte range cannot be observed by user code.
    //
    // edx = regptr (EstablisherFrame) = [ebp+12]
    code.extend_from_slice(&[0x8B, 0x55, 0x0C]); // mov edx, [ebp+12]
    // ecx = thrown int = er->ExceptionInformation[0] = [eax+0x14]
    code.extend_from_slice(&[0x8B, 0x48, ER_INFO0]); // mov ecx, [eax+0x14]
    // [regptr-4] = thrown int  (stable across RtlUnwind)
    code.extend_from_slice(&[0x89, 0x4A, 0xFC]); // mov [edx-4], ecx

    // RtlUnwind(TargetFrame=regptr, TargetIp=NULL, ExceptionRecord=er, ReturnValue)
    //   __stdcall ⇒ push right-to-left, callee cleans (no `add esp`).
    code.extend_from_slice(&[0x51]); // push ecx              (ReturnValue = int)
    code.extend_from_slice(&[0xFF, 0x75, 0x08]); // push dword [ebp+8]    (ExceptionRecord)
    code.extend_from_slice(&[0x6A, 0x00]); // push 0                (TargetIp; x86-ignored)
    code.extend_from_slice(&[0x52]); // push edx              (TargetFrame = regptr)
    // call dword [__imp_RtlUnwind]
    code.extend_from_slice(&[0xFF, 0x15, 0, 0, 0, 0]);
    riprefs.push(RipReloc {
        at: code.len() - 4,
        target: RipRef::Import("RtlUnwind".to_string()),
    });

    // --- transfer into the catch landing pad (does NOT return) ---
    // Re-derive everything from the intact EBP frame + establisher record.
    // The catch pad runs with the establisher's frame: EBP = regptr+16,
    // ESP = regptr - frame, EAX = thrown int (the catch pad stores it into
    // the catch parameter's slot, exactly as the x64 path does).
    code.extend_from_slice(&[0x8B, 0x55, 0x0C]); // mov edx, [ebp+12]     (regptr)
    code.extend_from_slice(&[0x8B, 0x42, 0xFC]); // mov eax, [edx-4]      (thrown int)
    code.extend_from_slice(&[0x8B, 0x4A, 0x0C]); // mov ecx, [edx+12]     (frame size)
    code.extend_from_slice(&[0x8B, 0x5A, 0x08]); // mov ebx, [edx+8]      (catch pad VA)
    code.extend_from_slice(&[0x8D, 0x6A, 0x10]); // lea ebp, [edx+16]     (main's ebp)
    code.extend_from_slice(&[0x89, 0xD4]); // mov esp, edx          (= regptr)
    code.extend_from_slice(&[0x29, 0xCC]); // sub esp, ecx          (= regptr - frame)
    code.extend_from_slice(&[0xFF, 0xE3]); // jmp ebx               (catch pad)

    // --- continue_search: return ExceptionContinueSearch (1) ---
    let continue_search = code.len();
    code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    code.extend_from_slice(&[0xC9]); // leave
    code.extend_from_slice(&[0xC3]); // ret

    for at in [jne_cs, jnz_cs] {
        let rel = (continue_search as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    }

    CompiledFn {
        name: SEH3_HANDLER_NAME.into(),
        code,
        calls: Vec::new(),
        riprefs,
        strings: Vec::new(),
        fp_literals: Vec::new(),
        try_scopes: Vec::new(),
        extern_refs: Vec::new(),
        // S4.2af: identical in every TU that uses SEH ⇒ foldable across objects.
        inline: true,
    }
}

/// S2e (class EH): the i386 fs:[0] handler for a function whose `try` has a
/// CLASS catch. Like [`build_seh3_handler`] but (1) matches
/// `EXCEPTION_MDBCC_CLASS`, (2) GATES on the thrown type RVA
/// (`ExceptionInformation[0]`, `[er+0x14]`) equalling the catch's expected
/// type at `[regptr+20]` (the prologue's extended 24-byte record), and (3)
/// delivers the buffer POINTER (`ExceptionInformation[1]`, `[er+0x18]`) via EAX
/// — a by-ref/by-ptr catch's landing pad stores it into the catch slot. The
/// extended record is 24 bytes, so main's EBP is `regptr+24` (vs +16 for int).
/// Exact-type match only (non-polymorphic BC++ `xmsg`); a base-chain typeinfo
/// walk is a follow-on tick.
pub(crate) fn build_seh3_class_handler() -> CompiledFn {
    const ER_FLAGS: u8 = 0x04;
    const ER_INFO0: u8 = 0x14; // ExceptionInformation[0] = thrown type RVA
    const ER_INFO1: u8 = 0x18; // ExceptionInformation[1] = &eh_buffer

    let mut code = Vec::with_capacity(128);
    let mut riprefs: Vec<RipReloc> = Vec::new();
    let mut cs_patches: Vec<usize> = Vec::new();

    code.extend_from_slice(&[0x55]); // push ebp
    code.extend_from_slice(&[0x89, 0xE5]); // mov ebp, esp
    code.extend_from_slice(&[0x8B, 0x45, 0x08]); // mov eax, [ebp+8]   (er)
    code.extend_from_slice(&[0x8B, 0x08]); // mov ecx, [eax]      (ExceptionCode)
    code.extend_from_slice(&[0x81, 0xF9]); // cmp ecx, imm32
    code.extend_from_slice(&EXCEPTION_MDBCC_CLASS.to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne continue_search
    cs_patches.push(code.len() - 4);
    // Bow out during the unwind phase (EH_UNWINDING|EH_EXIT_UNWIND = 6).
    code.extend_from_slice(&[0xF7, 0x40, ER_FLAGS, 0x06, 0x00, 0x00, 0x00]); // test [eax+4], 6
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne continue_search
    cs_patches.push(code.len() - 4);
    // TYPE GATE (G55): walk the thrown class's BASE CHAIN. cur starts at
    // the thrown tag (ExceptionInformation[0], an absolute vtable/typeinfo
    // VA); each non-match follows the RTTI/EH descriptor word at `[cur-4]`
    // (the BASE class's vtable VA, 0 at a root) — but ONLY when the throw
    // marked the tag POLYMORPHIC (args[2] bit 0; a non-poly typeinfo tag
    // has no descriptor word and keeps the historical exact match). The
    // 32-step cap bounds a corrupt chain. esi is the cap counter — pushed
    // here, popped on the search exit; the deliver path rewrites ESP (and
    // mdbcc i386 codegen never holds live state in esi), matching the
    // multi handler's register discipline.
    const ER_NPARAMS: u8 = 0x10;
    const ER_INFO2: u8 = 0x1C;
    code.extend_from_slice(&[0x56]); // push esi
    code.extend_from_slice(&[0x8B, 0x55, 0x0C]); // mov edx, [ebp+12]   (regptr)
    code.extend_from_slice(&[0x8B, 0x48, ER_INFO0]); // mov ecx, [eax+0x14] (thrown tag)
    code.extend_from_slice(&[0xBE, 0x20, 0x00, 0x00, 0x00]); // mov esi, 32 (cap)
    let l_walk = code.len();
    code.extend_from_slice(&[0x3B, 0x4A, 0x14]); // cmp ecx, [edx+20]   (expected)
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je matched
    let je_matched = code.len() - 4;
    code.extend_from_slice(&[0x83, 0x78, ER_NPARAMS, 0x03]); // cmp dword [eax+0x10], 3
    code.extend_from_slice(&[0x0F, 0x82, 0, 0, 0, 0]); // jb no_match
    let jb_nm = code.len() - 4;
    code.extend_from_slice(&[0xF7, 0x40, ER_INFO2, 0x01, 0x00, 0x00, 0x00]); // test [eax+0x1C], 1
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je no_match
    let je_nm = code.len() - 4;
    code.extend_from_slice(&[0x8B, 0x49, 0xFC]); // mov ecx, [ecx-4]  (base tag)
    code.extend_from_slice(&[0x85, 0xC9]); // test ecx, ecx
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je no_match (chain end)
    let je_nm2 = code.len() - 4;
    code.extend_from_slice(&[0x4E]); // dec esi
    {
        let rel = (l_walk as i32) - (code.len() as i32 + 6);
        code.extend_from_slice(&[0x0F, 0x85]); // jnz walk
        code.extend_from_slice(&rel.to_le_bytes());
    }
    // no_match: restore esi, continue the search.
    let l_no_match = code.len();
    code.extend_from_slice(&[0x5E]); // pop esi
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp continue_search
    cs_patches.push(code.len() - 4);
    for (at, target) in [
        (jb_nm, l_no_match),
        (je_nm, l_no_match),
        (je_nm2, l_no_match),
    ] {
        let rel = (target as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    }
    // matched: discard the cap counter (the deliver path rewrites ESP).
    let l_matched = code.len();
    code.extend_from_slice(&[0x5E]); // pop esi
    {
        let rel = (l_matched as i32) - (je_matched as i32 + 4);
        code[je_matched..je_matched + 4].copy_from_slice(&rel.to_le_bytes());
    }
    // DELIVER: stash the buffer ptr (ExceptionInformation[1]) at [regptr-4].
    code.extend_from_slice(&[0x8B, 0x48, ER_INFO1]); // mov ecx, [eax+0x18] (&buffer)
    code.extend_from_slice(&[0x89, 0x4A, 0xFC]); // mov [edx-4], ecx
    // RtlUnwind(TargetFrame=regptr, NULL, er, ReturnValue=&buffer) — __stdcall.
    code.extend_from_slice(&[0x51]); // push ecx              (ReturnValue = &buffer)
    code.extend_from_slice(&[0xFF, 0x75, 0x08]); // push dword [ebp+8]    (er)
    code.extend_from_slice(&[0x6A, 0x00]); // push 0                (TargetIp)
    code.extend_from_slice(&[0x52]); // push edx              (TargetFrame)
    code.extend_from_slice(&[0xFF, 0x15, 0, 0, 0, 0]); // call [__imp_RtlUnwind]
    riprefs.push(RipReloc {
        at: code.len() - 4,
        target: RipRef::Import("RtlUnwind".to_string()),
    });
    // Transfer into the catch pad. The extended record is 24 bytes, so the
    // establisher EBP is `regptr+24` (the int handler's +16 would land 8 bytes
    // low and corrupt the catch frame).
    code.extend_from_slice(&[0x8B, 0x55, 0x0C]); // mov edx, [ebp+12]   (regptr)
    // S2e (rethrow): POP this frame's record off fs:[0] (set fs:[0] = prev =
    // [regptr]) BEFORE transferring to the catch pad, so a `throw;` in the catch
    // body propagates to the CALLER instead of re-entering this same handler
    // (which would infinite-loop). The epilogue's later fs:[0]=prev on normal
    // completion is then idempotent (same value). eax is scratch here — it is
    // reloaded with &buffer on the next instruction.
    code.extend_from_slice(&[0x8B, 0x02]); // mov eax, [edx]      (prev fs:[0] link)
    code.extend_from_slice(&[0x64, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00]); // mov fs:[0], eax
    code.extend_from_slice(&[0x8B, 0x42, 0xFC]); // mov eax, [edx-4]    (&buffer)
    code.extend_from_slice(&[0x8B, 0x4A, 0x0C]); // mov ecx, [edx+12]   (frame size)
    code.extend_from_slice(&[0x8B, 0x5A, 0x08]); // mov ebx, [edx+8]    (catch pad VA)
    code.extend_from_slice(&[0x8D, 0x6A, 0x18]); // lea ebp, [edx+24]   (main's ebp)
    code.extend_from_slice(&[0x89, 0xD4]); // mov esp, edx
    code.extend_from_slice(&[0x29, 0xCC]); // sub esp, ecx
    code.extend_from_slice(&[0xFF, 0xE3]); // jmp ebx             (catch pad)

    let continue_search = code.len();
    code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    code.extend_from_slice(&[0xC9]); // leave
    code.extend_from_slice(&[0xC3]); // ret

    for at in cs_patches {
        let rel = (continue_search as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    }

    CompiledFn {
        name: SEH3_CLASS_HANDLER_NAME.into(),
        code,
        calls: Vec::new(),
        riprefs,
        strings: Vec::new(),
        fp_literals: Vec::new(),
        try_scopes: Vec::new(),
        extern_refs: Vec::new(),
        inline: true,
    }
}

/// S6 (G5): stable symbol for the x86 fs:[0] MULTI-TRY handler — installed by
/// any Win32 function with more than one `try` block (or more than one catch
/// clause). See [`build_seh3_multi_handler`].
pub(crate) const SEH3_MULTI_HANDLER_NAME: &str = ".mdbcc_seh3_multi_handler";

/// S6 (G5): the i386 fs:[0] handler for a MULTI-TRY function — the table-
/// driven generalisation of [`build_seh3_handler`] (int) and
/// [`build_seh3_class_handler`] (class), handling BOTH exception codes.
///
/// ## Registration record the multi prologue installs (regptr = EstablisherFrame)
/// ```text
///   [regptr+0]  prev        (previous fs:[0] link)
///   [regptr+4]  handler     (this function)
///   [regptr+8]  table       (absolute VA of the function's SCOPE TABLE)
///   [regptr+12] frame       (the function's `sub esp, N` frame size)
///   [regptr+16] trylevel    (u32; 0xFFFF_FFFF = no try active)
/// ```
/// regptr = ebp-20; the establisher's EBP = regptr+20. The BODY maintains
/// `trylevel` ([ebp-4]): the index of the innermost active `try` on entry,
/// restored to the enclosing level after its `try_end` or at catch-pad entry
/// (`-1` when there is no enclosing try). This lets nested try bodies search
/// inner handlers first while throws from an inner catch body participate in
/// the outer try.
///
/// ## Scope table (emitted INLINE in the function's own code, after `ret`)
/// ```text
///   u32 count;
///   struct { u32 level; u32 parent; u32 kind; u32 type_va; u32 pad_va; } rows[count];
/// ```
/// `parent` is the enclosing try level, or `0xFFFF_FFFF` for none. `kind`:
/// 0 = int catch, 1 = class catch (`type_va` = the expected vtable/descriptor
/// absolute VA, exact-match like the class handler), 2 = catch-all (matches
/// either code). `pad_va` is the catch landing pad's absolute VA (funcVA +
/// offset via a DIR32-with-addend reloc, same mechanism as the single-try
/// record's pad field).
///
/// ## Behaviour
/// 1. Code not EXCEPTION_MDBCC_INT/CLASS, or unwinding flags set, or
///    trylevel == -1 → ContinueSearch.
/// 2. Walk the rows: a row matches when `row.level == trylevel` AND the kind
///    accepts the code (kind 1 also requires `row.type_va ==
///    ExceptionInformation[0]`). First match wins (clause order — the rows
///    are emitted in `try_scopes` order, which is clause order within a try).
///    If no row at that level accepts the exception, retry with that level's
///    `parent`; only `parent == -1` continues the search in caller frames.
/// 3. Deliver: stash the value ([regptr-4]) and pad ([regptr-8]) below the
///    record (the establisher's locals region — not unwound; transient until
///    the transfer, exactly the int handler's [regptr-4] trick), set
///    trylevel = -1, RtlUnwind(regptr), then transfer: EAX = value
///    (int: ExceptionInformation[0]; class buffer ptr: [1]), EBP = regptr+20,
///    ESP = regptr-frame, jmp pad.
/// 4. No row matches at any enclosing level → ContinueSearch.
pub(crate) fn build_seh3_multi_handler() -> CompiledFn {
    const ER_FLAGS: u8 = 0x04;
    const ER_INFO0: u8 = 0x14;
    const ER_INFO1: u8 = 0x18;

    let mut code = Vec::with_capacity(256);
    let mut riprefs: Vec<RipReloc> = Vec::new();
    let mut cs_patches: Vec<usize> = Vec::new();
    let mut nx_patches: Vec<usize> = Vec::new();
    let mut level_done_patches: Vec<usize> = Vec::new();

    code.extend_from_slice(&[0x55]); // push ebp
    code.extend_from_slice(&[0x89, 0xE5]); // mov ebp, esp
    code.extend_from_slice(&[0x53]); // push ebx
    code.extend_from_slice(&[0x56]); // push esi
    code.extend_from_slice(&[0x57]); // push edi
    code.extend_from_slice(&[0x8B, 0x45, 0x08]); // mov eax, [ebp+8]   (er)
    code.extend_from_slice(&[0x8B, 0x08]); // mov ecx, [eax]          (code)
    code.extend_from_slice(&[0x8B, 0x55, 0x0C]); // mov edx, [ebp+12]  (regptr)
    code.extend_from_slice(&[0x81, 0xF9]); // cmp ecx, EXCEPTION_MDBCC_INT
    code.extend_from_slice(&EXCEPTION_MDBCC_INT.to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je code_ok
    let je_code_ok = code.len() - 4;
    code.extend_from_slice(&[0x81, 0xF9]); // cmp ecx, EXCEPTION_MDBCC_CLASS
    code.extend_from_slice(&EXCEPTION_MDBCC_CLASS.to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne continue_search
    cs_patches.push(code.len() - 4);
    let code_ok = code.len();
    {
        let rel = (code_ok as i32) - (je_code_ok as i32 + 4);
        code[je_code_ok..je_code_ok + 4].copy_from_slice(&rel.to_le_bytes());
    }
    // Bow out during the unwind phase.
    code.extend_from_slice(&[0xF7, 0x40, ER_FLAGS, 0x06, 0x00, 0x00, 0x00]); // test [eax+4],6
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne continue_search
    cs_patches.push(code.len() - 4);
    // ebx = trylevel; -1 ⇒ nothing active in this frame.
    code.extend_from_slice(&[0x8B, 0x5A, 0x10]); // mov ebx, [edx+16]
    code.extend_from_slice(&[0x83, 0xFB, 0xFF]); // cmp ebx, -1
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je continue_search
    cs_patches.push(code.len() - 4);
    // Search rows at the current level. [regptr-12] carries that level's
    // parent candidate while scanning; it is in the same reserved pad area as
    // [regptr-4]/[regptr-8], which are used only after a row matches.
    let l_level = code.len();
    code.extend_from_slice(&[0xC7, 0x42, 0xF4, 0xFF, 0xFF, 0xFF, 0xFF]); // mov dword [edx-12], -1
    // esi = first row, edi = count.
    code.extend_from_slice(&[0x8B, 0x72, 0x08]); // mov esi, [edx+8]   (table)
    code.extend_from_slice(&[0x8B, 0x3E]); // mov edi, [esi]          (count)
    code.extend_from_slice(&[0x83, 0xC6, 0x04]); // add esi, 4

    let l_loop = code.len();
    code.extend_from_slice(&[0x85, 0xFF]); // test edi, edi
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je level_done
    level_done_patches.push(code.len() - 4);
    code.extend_from_slice(&[0x39, 0x1E]); // cmp [esi], ebx    (row.level)
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne next
    nx_patches.push(code.len() - 4);
    code.extend_from_slice(&[0x51]); // push ecx (preserve exception code)
    code.extend_from_slice(&[0x8B, 0x4E, 0x04]); // mov ecx, [esi+4] (row.parent)
    code.extend_from_slice(&[0x89, 0x4A, 0xF4]); // mov [edx-12], ecx
    code.extend_from_slice(&[0x59]); // pop ecx
    code.extend_from_slice(&[0x83, 0x7E, 0x08, 0x02]); // cmp dword [esi+8], 2
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je k2 (catch-all)
    let je_k2 = code.len() - 4;
    code.extend_from_slice(&[0x83, 0x7E, 0x08, 0x00]); // cmp dword [esi+8], 0
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je k0 (int row)
    let je_k0 = code.len() - 4;
    // kind 1 (class row): code must be CLASS and the type must match the
    // row tag — EXACTLY, or (G55) anywhere on the thrown class's BASE
    // CHAIN, walked through the RTTI/EH descriptor word at `[cur-4]` when
    // the throw marked the tag POLYMORPHIC (args[2] bit 0). 32-step cap.
    // ecx (the exception code) and edx (regptr) are saved around the walk.
    const ER_NPARAMS: u8 = 0x10;
    const ER_INFO2: u8 = 0x1C;
    code.extend_from_slice(&[0x81, 0xF9]); // cmp ecx, EXCEPTION_MDBCC_CLASS
    code.extend_from_slice(&EXCEPTION_MDBCC_CLASS.to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne next
    nx_patches.push(code.len() - 4);
    code.extend_from_slice(&[0x51]); // push ecx (save code)
    code.extend_from_slice(&[0x52]); // push edx (save regptr; edx = walk cap)
    code.extend_from_slice(&[0x8B, 0x48, ER_INFO0]); // mov ecx, [eax+0x14] (cur = thrown tag)
    code.extend_from_slice(&[0xBA, 0x20, 0x00, 0x00, 0x00]); // mov edx, 32 (cap)
    let l_cwalk = code.len();
    code.extend_from_slice(&[0x39, 0x4E, 0x0C]); // cmp [esi+12], ecx
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je class_match
    let je_cmatch = code.len() - 4;
    code.extend_from_slice(&[0x83, 0x78, ER_NPARAMS, 0x03]); // cmp dword [eax+0x10], 3
    code.extend_from_slice(&[0x0F, 0x82, 0, 0, 0, 0]); // jb class_nomatch
    let jb_cnm = code.len() - 4;
    code.extend_from_slice(&[0xF7, 0x40, ER_INFO2, 0x01, 0x00, 0x00, 0x00]); // test [eax+0x1C], 1
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je class_nomatch
    let je_cnm = code.len() - 4;
    code.extend_from_slice(&[0x8B, 0x49, 0xFC]); // mov ecx, [ecx-4]  (base tag)
    code.extend_from_slice(&[0x85, 0xC9]); // test ecx, ecx
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je class_nomatch (chain end)
    let je_cnm2 = code.len() - 4;
    code.extend_from_slice(&[0x4A]); // dec edx
    {
        let rel = (l_cwalk as i32) - (code.len() as i32 + 6);
        code.extend_from_slice(&[0x0F, 0x85]); // jnz class_walk
        code.extend_from_slice(&rel.to_le_bytes());
    }
    // class_nomatch: restore regptr + code, advance to the next row.
    let l_cnm = code.len();
    code.extend_from_slice(&[0x5A]); // pop edx
    code.extend_from_slice(&[0x59]); // pop ecx
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp next
    nx_patches.push(code.len() - 4);
    for (at, target) in [(jb_cnm, l_cnm), (je_cnm, l_cnm), (je_cnm2, l_cnm)] {
        let rel = (target as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    }
    // class_match: restore regptr + code, deliver.
    let l_cmatch = code.len();
    code.extend_from_slice(&[0x5A]); // pop edx
    code.extend_from_slice(&[0x59]); // pop ecx
    {
        let rel = (l_cmatch as i32) - (je_cmatch as i32 + 4);
        code[je_cmatch..je_cmatch + 4].copy_from_slice(&rel.to_le_bytes());
    }
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp deliver_class
    let jmp_dc1 = code.len() - 4;
    // k0: int row — code must be INT.
    let l_k0 = code.len();
    code.extend_from_slice(&[0x81, 0xF9]); // cmp ecx, EXCEPTION_MDBCC_INT
    code.extend_from_slice(&EXCEPTION_MDBCC_INT.to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne next
    nx_patches.push(code.len() - 4);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp deliver_int
    let jmp_di1 = code.len() - 4;
    // k2: catch-all — deliver by code kind (value unused by the pad).
    let l_k2 = code.len();
    code.extend_from_slice(&[0x81, 0xF9]); // cmp ecx, EXCEPTION_MDBCC_CLASS
    code.extend_from_slice(&EXCEPTION_MDBCC_CLASS.to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je deliver_class
    let je_dc2 = code.len() - 4;
    // deliver_int: value = ExceptionInformation[0] (the thrown int).
    let l_di = code.len();
    code.extend_from_slice(&[0x8B, 0x48, ER_INFO0]); // mov ecx, [eax+0x14]
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp stash
    let jmp_st = code.len() - 4;
    // deliver_class: value = ExceptionInformation[1] (the buffer pointer).
    let l_dc = code.len();
    code.extend_from_slice(&[0x8B, 0x48, ER_INFO1]); // mov ecx, [eax+0x18]
    // stash: park value + pad below the record; disarm trylevel; unwind.
    let l_st = code.len();
    code.extend_from_slice(&[0x89, 0x4A, 0xFC]); // mov [edx-4], ecx   (value)
    code.extend_from_slice(&[0x8B, 0x4E, 0x10]); // mov ecx, [esi+16]  (pad VA)
    code.extend_from_slice(&[0x89, 0x4A, 0xF8]); // mov [edx-8], ecx   (pad)
    code.extend_from_slice(&[0xC7, 0x42, 0x10, 0xFF, 0xFF, 0xFF, 0xFF]); // mov dword [edx+16], -1
    // RtlUnwind(TargetFrame=regptr, NULL, er, ReturnValue=value) — __stdcall.
    code.extend_from_slice(&[0xFF, 0x72, 0xFC]); // push dword [edx-4]
    code.extend_from_slice(&[0xFF, 0x75, 0x08]); // push dword [ebp+8]
    code.extend_from_slice(&[0x6A, 0x00]); // push 0
    code.extend_from_slice(&[0x52]); // push edx
    code.extend_from_slice(&[0xFF, 0x15, 0, 0, 0, 0]); // call [__imp_RtlUnwind]
    riprefs.push(RipReloc {
        at: code.len() - 4,
        target: RipRef::Import("RtlUnwind".to_string()),
    });
    // Transfer into the catch pad with the establisher's frame.
    code.extend_from_slice(&[0x8B, 0x55, 0x0C]); // mov edx, [ebp+12]  (regptr)
    code.extend_from_slice(&[0x8B, 0x42, 0xFC]); // mov eax, [edx-4]   (value)
    code.extend_from_slice(&[0x8B, 0x5A, 0xF8]); // mov ebx, [edx-8]   (pad)
    code.extend_from_slice(&[0x8B, 0x4A, 0x0C]); // mov ecx, [edx+12]  (frame)
    code.extend_from_slice(&[0x8D, 0x6A, 0x14]); // lea ebp, [edx+20]  (main's ebp)
    code.extend_from_slice(&[0x89, 0xD4]); // mov esp, edx
    code.extend_from_slice(&[0x29, 0xCC]); // sub esp, ecx
    code.extend_from_slice(&[0xFF, 0xE3]); // jmp ebx
    // next: advance to the following row.
    let l_next = code.len();
    code.extend_from_slice(&[0x83, 0xC6, 0x14]); // add esi, 20
    code.extend_from_slice(&[0x4F]); // dec edi
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp loop (backward)
    {
        let at = code.len() - 4;
        let rel = (l_loop as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    }
    // level_done: no row at this level accepted the exception. Retry at the
    // parent level in the same frame before continuing search in caller frames.
    let l_level_done = code.len();
    code.extend_from_slice(&[0x8B, 0x5A, 0xF4]); // mov ebx, [edx-12] (parent)
    code.extend_from_slice(&[0x83, 0xFB, 0xFF]); // cmp ebx, -1
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne level_search
    {
        let at = code.len() - 4;
        let rel = (l_level as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    }
    // continue_search: restore callee-saved regs, return 1.
    let continue_search = code.len();
    code.extend_from_slice(&[0x5F]); // pop edi
    code.extend_from_slice(&[0x5E]); // pop esi
    code.extend_from_slice(&[0x5B]); // pop ebx
    code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    code.extend_from_slice(&[0x5D]); // pop ebp
    code.extend_from_slice(&[0xC3]); // ret

    for at in cs_patches {
        let rel = (continue_search as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    }
    for at in level_done_patches {
        let rel = (l_level_done as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    }
    for at in nx_patches {
        let rel = (l_next as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    }
    for (at, target) in [
        (je_k2, l_k2),
        (je_k0, l_k0),
        (jmp_dc1, l_dc),
        (jmp_di1, l_di),
        (je_dc2, l_dc),
        (jmp_st, l_st),
    ] {
        let rel = (target as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    }

    CompiledFn {
        name: SEH3_MULTI_HANDLER_NAME.into(),
        code,
        calls: Vec::new(),
        riprefs,
        strings: Vec::new(),
        fp_literals: Vec::new(),
        try_scopes: Vec::new(),
        extern_refs: Vec::new(),
        inline: true,
    }
}

/// Phase H4b: what kind of value a `catch` clause binds, and (for class
/// catches) which class hierarchy it accepts. Recorded per scope-table
/// entry; the personality function dispatches on the matching `int` vs
/// `class` exception code and walks the type-info chain for class catches.
#[derive(Debug, Clone, Copy)]
pub enum CatchPolicy {
    /// `catch (int <name>)` — H4a. Personality matches exception code
    /// `EXCEPTION_MDBCC_INT` and delivers the int via RAX.
    Int,
    /// `catch (Tag& <name>)` — class catch by reference. `class_record_id`
    /// is the record id whose vtable RVA the personality function uses to
    /// match against the thrown object's vtable (walking the base chain
    /// via the typeinfo table). Delivers a POINTER to the (heap-side)
    /// exception buffer via RAX; the handler reinterprets it as a `Tag&`.
    ByRef { class_record_id: usize },
    /// `catch (Tag* <name>)` — class catch by pointer (for `throw &obj`
    /// patterns). Same matching semantics as ByRef; delivers the same
    /// buffer address via RAX (the handler treats it as a `Tag*`).
    ByPtr { class_record_id: usize },
    /// Tick 69 (J-11b / J-15b): cleanup scope — when an exception
    /// propagates through `[try_begin, try_end)`, the personality function
    /// runs the cleanup landing pad (which performs resource recovery
    /// such as calling partial-construction dtors and freeing array
    /// HeapAlloc blocks) and the landing pad re-raises the same
    /// exception, continuing the search from its own PC. The personality
    /// function does NOT type-check (any in-range exception triggers);
    /// it delivers the `ExceptionRecord` pointer in RAX so the landing
    /// pad can read the original code+args for the re-raise.
    Cleanup,
    /// `catch (...)` — the catch-all handler. Like `Cleanup` the personality
    /// matches ANY in-range exception WITHOUT a type check, but unlike Cleanup
    /// it is a real handler: the landing pad runs the user body and the search
    /// TERMINATES (the exception is handled, not re-raised). No catch parameter
    /// (no value delivered; the handler reads nothing from RAX). Used by the
    /// real OWL TApplication::Run's outermost handler.
    CatchAll,
}

/// One `try { … } catch (…) { … }` scope, recorded by codegen and
/// consumed by [`crate::link::pe_writer::build_xdata`]. Offsets are within `CompiledFn.code`
/// (function-relative); the PE writer adds the function's `.text` RVA at
/// xdata emission time to produce the absolute RVAs the personality function
/// reads from the language-specific-data block.
///
/// Phase H4b extends H4a's int-only model: `policy` selects the catch
/// shape, and for class catches the personality function compares
/// vtable RVAs (walking the base chain via the module's typeinfo table).
#[derive(Debug, Clone, Copy)]
pub struct TryScope {
    /// First code offset that is inside the `try` body (the instruction the
    /// `try { …` brace lowers to).
    pub try_begin: u32,
    /// First code offset NOT in the `try` body (exclusive end; the
    /// unconditional `jmp end_of_handler` the codegen emits right after the
    /// last instruction of the `try` body).
    pub try_end: u32,
    /// Code offset of the catch landing pad: the very first instruction the
    /// personality function unwinds control to (a `mov [rbp-slot], rax`
    /// store of the delivered value — int for `catch (int)`, buffer
    /// address for class catches — into the catch parameter's local slot).
    pub handler: u32,
    /// Phase H4b: the catch shape (int / class-by-ref / class-by-ptr).
    /// The PE writer translates `ByRef { class_record_id }` /
    /// `ByPtr { class_record_id }` to the corresponding vtable RVA when
    /// it emits the scope table (record-id space is private to codegen;
    /// only vtable RVAs survive into the runtime scope-table image).
    pub policy: CatchPolicy,
}

/// J-7: tracks the active catch handler so a bare `throw;` (rethrow)
/// inside its body can find the caught value to re-raise. One entry per
/// nested catch clause currently being lowered; pushed on entry to the
/// catch body, popped on exit. A `Stmt::Throw(None)` peeks the innermost
/// entry; an empty stack is a compile-time error
/// ("'throw;' only valid inside a 'catch' block").
///
/// `value_off` is the rbp-relative offset of an 8-byte slot holding the
/// caught value: for `CatchKindLow::Int` the slot contains the thrown
/// int (zero-extended); for `Class` it contains the buffer pointer the
/// personality function delivered to the catch handler. For named
/// catches this reuses the existing catch-parameter slot (no extra
/// instructions emitted, preserving byte-identity for catches without a
/// rethrow); for anonymous catches a fresh tmp is allocated and RAX
/// spilled at landing-pad entry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CatchCtx {
    pub(crate) kind: CatchKindLow,
    /// rbp-relative offset (positive number; emitter negates) of the
    /// 8-byte slot holding the caught int (low 32 bits) or buffer ptr.
    pub(crate) value_off: i32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CatchKindLow {
    Int,
    /// `catch (T&)` / `catch (T*)` — both deliver a buffer pointer to
    /// the handler; rethrow re-raises with `EXCEPTION_MDBCC_CLASS` and
    /// an args array `[vtable_abs(T), buffer_ptr]`. The static type
    /// `T` is what feeds the args[0] vtable lookup.
    Class {
        class_record_id: usize,
    },
    /// S6: `catch (...)` — rethrow re-raises the ORIGINAL exception verbatim
    /// from `.mdbcc_eh_save` (the personality's catch-all branch stamps the
    /// caught ExceptionRecord's code+NumberParameters+args there before
    /// transferring to the handler). Type-agnostic — works for any caught
    /// exception (int or class), exactly like the cleanup-pad re-raise.
    CatchAll,
}

/// Phase H4b: one entry in the module-wide type-info table that the
/// personality function uses to walk the class hierarchy at exception
/// dispatch time. Stored by record id; the PE writer translates each
/// id to its vtable RVA when emitting `.rdata`. Entries are emitted
/// only when SEH is active AND the module has at least one polymorphic
/// class; the table is referenced from each try-bearing function's
/// scope-table header (so int-only programs see no new bytes).
#[derive(Debug, Clone)]
pub struct TypeInfoEntry {
    /// Record id of the class this entry describes (must have a vtable).
    pub class_record_id: usize,
    /// Record id of the immediate base class, or `None` for a root class.
    pub base_record_id: Option<usize>,
    /// W6 (G54): the LINK-CANONICAL symbol for this entry — bcc32's
    /// `@$xt$<encoding>` form, emitted WeakExternal so mdlink folds the
    /// per-TU copies to one address. A NON-polymorphic class's EH identity
    /// is its typeinfo-entry RVA; with per-TU `.Lxt.<id>` statics a class
    /// thrown in one TU never matched a `catch` in another. `None` for a
    /// tag-less class (keeps the TU-local static).
    pub weak_sym: Option<String>,
}

/// Phase H4b: does this TU contain at least one `try` or `throw`?
/// Used by `compile_module` to decide whether to reserve the shared
/// exception buffer global up-front (so the throw lowering can resolve
/// it by name). Pure AST walk — no side effects, no codegen state.
/// A TU that never names `try`/`throw` is byte-identical to pre-H4b
/// (gates the O1 88 e2e regression).
pub(crate) fn tu_has_try_or_throw(tu: &TranslationUnit) -> bool {
    fn in_stmt(s: &Stmt) -> bool {
        match s {
            Stmt::Throw(..) | Stmt::Try { .. } => true,
            Stmt::If { then, els, .. } => in_stmt(then) || els.as_deref().is_some_and(in_stmt),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => in_stmt(body),
            Stmt::For { init, body, .. } => init.as_deref().is_some_and(in_stmt) || in_stmt(body),
            Stmt::Switch { body, .. } => in_stmt(body),
            Stmt::Block(b, _) => b.iter().any(in_stmt),
            _ => false,
        }
    }
    tu.items.iter().any(|i| match i {
        Item::Func(f) => f.body.iter().any(in_stmt),
        _ => false,
    })
}

/// S2e: count the `try` blocks in a function body (DFS, recursing into
/// nested control flow AND into the bodies/handlers of inner `try`s).
///
/// The x86 fs:[0] SEH lowering installs one `EXCEPTION_REGISTRATION` per
/// try-bearing function. The minimal milestone supports exactly one `try`
/// per function (the record carries a single catch-pad VA); `Gen::run`
/// uses this count to (a) decide whether to install the SEH record at all
/// and (b) reject `> 1` with a clean diagnostic rather than silently
/// mis-resuming. A function that only `throw`s (no `try`) needs no record —
/// the throw propagates to a caller's frame — so this counts `try` only.
pub(crate) fn fn_body_try_count(body: &[Stmt]) -> usize {
    fn in_stmt(s: &Stmt) -> usize {
        match s {
            Stmt::Try { body, catches, .. } => {
                let mut n = 1; // this try
                n += body.iter().map(in_stmt).sum::<usize>();
                for c in catches {
                    n += c.body.iter().map(in_stmt).sum::<usize>();
                }
                n
            }
            Stmt::If { then, els, .. } => in_stmt(then) + els.as_deref().map(in_stmt).unwrap_or(0),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => in_stmt(body),
            Stmt::For { init, body, .. } => {
                init.as_deref().map(in_stmt).unwrap_or(0) + in_stmt(body)
            }
            Stmt::Switch { body, .. } => in_stmt(body),
            Stmt::Block(b, _) => b.iter().map(in_stmt).sum(),
            _ => 0,
        }
    }
    body.iter().map(in_stmt).sum()
}

/// S6 (G5): count the CATCH CLAUSES across every `try` in a function body
/// (same DFS shape as [`fn_body_try_count`]). The i386 single-try record
/// carries exactly ONE catch pad, so a lone `try` with 2+ clauses needs the
/// multi-try scope table just like 2+ `try`s do; `Gen::run` switches to the
/// table-driven record when either count exceeds 1.
pub(crate) fn fn_body_catch_clause_count(body: &[Stmt]) -> usize {
    fn in_stmt(s: &Stmt) -> usize {
        match s {
            Stmt::Try { body, catches, .. } => {
                let mut n = catches.len();
                n += body.iter().map(in_stmt).sum::<usize>();
                for c in catches {
                    n += c.body.iter().map(in_stmt).sum::<usize>();
                }
                n
            }
            Stmt::If { then, els, .. } => in_stmt(then) + els.as_deref().map(in_stmt).unwrap_or(0),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => in_stmt(body),
            Stmt::For { init, body, .. } => {
                init.as_deref().map(in_stmt).unwrap_or(0) + in_stmt(body)
            }
            Stmt::Switch { body, .. } => in_stmt(body),
            Stmt::Block(b, _) => b.iter().map(in_stmt).sum(),
            _ => 0,
        }
    }
    body.iter().map(in_stmt).sum()
}

/// Phase H4a/H4b: build the synthetic personality function. The body is
/// hand-emitted x86-64; no `Gen` framework involvement (it has no
/// parameters / locals / temps the framework would otherwise allocate),
/// but the prologue/epilogue + frame shape are the SAME as a regular
/// mdbcc function so the .xdata UNWIND_INFO emitter does not need a
/// special case for it.
///
/// Signature (Win64 personality calling convention):
/// ```c
/// EXCEPTION_DISPOSITION handler(
///     EXCEPTION_RECORD   *er,    // rcx
///     PVOID               frame, // rdx — EstablisherFrame
///     CONTEXT            *ctx,   // r8
///     DISPATCHER_CONTEXT *dc);   // r9
/// ```
///
/// Dispatch:
/// 1. Recognise both `EXCEPTION_MDBCC_INT` (`0xE0000001`, H4a) and
///    `EXCEPTION_MDBCC_CLASS` (`0xE0000002`, H4b). Other codes return
///    `ExceptionContinueSearch` (1).
/// 2. If `er->ExceptionFlags & EH_UNWINDING` (=2) → `ExceptionContinueSearch`
///    (we own only the search phase; the unwind phase is the OS's job once
///    we've picked a target).
/// 3. The scope table (`dc->HandlerData`) is laid out as:
///    ```text
///      u32  scope_count        N (number of entries)
///      u32  tyinf_rva          Module-wide class type-info table RVA (0
///                              when no polymorphic class in the TU)
///      u32  tyinf_count        Number of TypeInfoEntry records
///      [ N × (try_begin_rva, try_end_rva, handler_rva,
///             catch_kind, catch_type_rva) ]   — 20 bytes per entry
///    ```
///    `catch_kind`: 0=int, 1=class-by-ref, 2=class-by-ptr, 3=cleanup
///    (tick 69 J-11b / J-15b — partial-construction unwind).
///    `catch_type_rva` is 0 for `catch (int)` and cleanup scopes, the
///    catch's vtable RVA for class catches.
/// 4. For each scope whose `[try_begin, try_end)` range contains
///    `dc->ControlPc - ImageBase`, test the type match:
///    - `Int`: matches iff exception code == `EXCEPTION_MDBCC_INT`.
///    - `ByRef`/`ByPtr`: matches iff exception code == `EXCEPTION_MDBCC_CLASS`
///      AND the thrown class's vtable RVA either equals `catch_type_rva`
///      OR walks up the typeinfo chain to it.
///    - `Cleanup`: matches unconditionally (any in-range exception
///      triggers the cleanup landing pad — only our two codes get past
///      the top-of-function dispatch in step 1).
/// 5. On match: call `RtlUnwindEx(EstablisherFrame, handler_abs, er,
///    ReturnValue, ctx, NULL)`. `ReturnValue` is the thrown int for `Int`
///    catches; for class catches it is the ABSOLUTE address of the
///    shared exception buffer (the caught reference / pointer's value);
///    for cleanup it is the ExceptionRecord POINTER itself (so the
///    cleanup landing pad can read the original code+args and re-raise
///    after running its dtor chain / HeapFree).
/// 6. If no scope matches → `ExceptionContinueSearch`.
///
/// Local frame (offsets from rbp, all 8-byte):
/// ```text
///   [rbp-8]   saved rcx  (er)
///   [rbp-16]  saved rdx  (frame / EstablisherFrame)
///   [rbp-24]  saved r8   (ctx)
///   [rbp-32]  saved r9   (dc)
///   [rbp-40]  handler_abs scratch
///   [rbp-48]  thrown class vtable RVA (during hierarchy walk)
///   [rbp-56]  typeinfo table absolute address (ImageBase + tyinf_rva)
///   [rbp-64]  typeinfo entry count
///   [rbp-72]  catch_type_rva (target of hierarchy walk)
///   [rbp-80]  ReturnValue (the thrown int OR the buffer addr)
///   [rbp-88]  reserved
/// ```
/// Frame size = 0x80 (128 bytes, still alloc-small ≤ 128 in UNWIND_INFO):
/// 32 shadow + 16 caller stack-arg slots + 80 of locals = 128. The
/// `sub rsp, 0x80` keeps the 16-byte RSP alignment Win64 requires.
pub(crate) fn build_personality_function(eh_save_global_idx: usize) -> CompiledFn {
    let mut code = Vec::with_capacity(384);
    let mut riprefs: Vec<RipReloc> = Vec::new();

    // Helpers — keep the bytes self-documenting. Register conventions:
    //  - Win64 callee-saved (NEVER clobbered here): RBX, RBP, RDI, RSI,
    //    RSP, R12-R15. We deliberately use ONLY RAX, RCX, RDX, R8, R9,
    //    R10, R11 plus stack slots; this avoids any save/restore work
    //    and keeps the personality function a non-leaf-yet-still-tidy
    //    frame the UNWIND_INFO can describe with just `push rbp` +
    //    `sub rsp, imm`.
    //  - R10 = ControlPc, R11 = ImageBase (set up once, never reloaded).
    //  - Scope-table cursor lives in [rbp-88] (loaded into RAX as needed).
    //
    // Frame layout (rbp-relative):
    //   [rbp-8]   saved rcx (er)
    //   [rbp-16]  saved rdx (frame / EstablisherFrame)
    //   [rbp-24]  saved r8  (ctx)
    //   [rbp-32]  saved r9  (dc)
    //   [rbp-40]  handler_abs scratch
    //   [rbp-48]  current vtable RVA during hierarchy walk
    //   [rbp-56]  tyinf table absolute address
    //   [rbp-64]  tyinf entry count
    //   [rbp-72]  catch_type_rva (target of walk)
    //   [rbp-80]  ReturnValue (thrown int or buffer abs)
    //   [rbp-88]  scope-table cursor (advances by 20 per entry)
    //   [rbp-96]  scope remaining count
    // Frame size 0x80 (128 B): 32 shadow + 16 stack args + 80 locals.

    // --- prologue ---
    code.extend_from_slice(&[0x55]); // push rbp
    code.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp
    code.extend_from_slice(&[0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00]); // sub rsp, 0x80

    // --- save args ---
    code.extend_from_slice(&[0x48, 0x89, 0x4D, 0xF8]); // mov [rbp-8],  rcx (er)
    code.extend_from_slice(&[0x48, 0x89, 0x55, 0xF0]); // mov [rbp-16], rdx (frame)
    code.extend_from_slice(&[0x4C, 0x89, 0x45, 0xE8]); // mov [rbp-24], r8  (ctx)
    code.extend_from_slice(&[0x4C, 0x89, 0x4D, 0xE0]); // mov [rbp-32], r9  (dc)

    // --- ExceptionCode dispatch: only 0xE0000001 / 0xE0000002 proceed ---
    let mut jumps_to_continue: Vec<usize> = Vec::new();
    code.extend_from_slice(&[0x8B, 0x01]); // mov eax, [rcx] (ExceptionCode)
    code.extend_from_slice(&[0x3D]);
    code.extend_from_slice(&EXCEPTION_MDBCC_INT.to_le_bytes()); // cmp eax, 0xE0000001
    // je +11 — skip the cmp/jne pair that handles the class code, since
    // the int code already matched. cmp eax, imm32 = 5 B, jne rel32 = 6 B.
    code.extend_from_slice(&[0x74, 0x0B]); // je +11
    code.extend_from_slice(&[0x3D]);
    code.extend_from_slice(&EXCEPTION_MDBCC_CLASS.to_le_bytes()); // cmp eax, 0xE0000002
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne continue_search
    jumps_to_continue.push(code.len() - 4);

    // --- ignore unwind phase (we own only search) ---
    code.extend_from_slice(&[0xF7, 0x41, 0x04, 0x02, 0x00, 0x00, 0x00]); // test [rcx+4], 2
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne continue_search
    jumps_to_continue.push(code.len() - 4);

    // --- r10 = dc->ControlPc, r11 = dc->ImageBase ---
    code.extend_from_slice(&[0x4C, 0x8B, 0x55, 0xE0]); // mov r10, [rbp-32]
    code.extend_from_slice(&[0x4D, 0x8B, 0x12]); // mov r10, [r10]
    code.extend_from_slice(&[0x4C, 0x8B, 0x5D, 0xE0]); // mov r11, [rbp-32]
    code.extend_from_slice(&[0x4D, 0x8B, 0x5B, 0x08]); // mov r11, [r11+8]

    // --- scope-table header at dc->HandlerData (dc[56]) ---
    code.extend_from_slice(&[0x48, 0x8B, 0x45, 0xE0]); // mov rax, [rbp-32]
    code.extend_from_slice(&[0x48, 0x8B, 0x40, 0x38]); // mov rax, [rax+56]
    // scope_count
    code.extend_from_slice(&[0x8B, 0x10]); // mov edx, [rax]
    code.extend_from_slice(&[0x48, 0x89, 0x55, 0xA0]); // mov [rbp-96], rdx
    // tyinf_rva → abs, save
    code.extend_from_slice(&[0x8B, 0x50, 0x04]); // mov edx, [rax+4]
    code.extend_from_slice(&[0x4C, 0x01, 0xDA]); // add rdx, r11
    code.extend_from_slice(&[0x48, 0x89, 0x55, 0xC8]); // mov [rbp-56], rdx
    // tyinf_count
    code.extend_from_slice(&[0x8B, 0x50, 0x08]); // mov edx, [rax+8]
    code.extend_from_slice(&[0x48, 0x89, 0x55, 0xC0]); // mov [rbp-64], rdx
    // first scope entry = rax + 12
    code.extend_from_slice(&[0x48, 0x83, 0xC0, 0x0C]); // add rax, 12
    code.extend_from_slice(&[0x48, 0x89, 0x45, 0xA8]); // mov [rbp-88], rax

    // === scope loop ===
    let loop_top = code.len();
    code.extend_from_slice(&[0x48, 0x83, 0x7D, 0xA0, 0x00]); // cmp qword [rbp-96], 0
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je continue_search
    jumps_to_continue.push(code.len() - 4);
    code.extend_from_slice(&[0x48, 0x8B, 0x45, 0xA8]); // mov rax, [rbp-88] (entry ptr)

    // PC-range filter: try_begin_rva + ImageBase ≤ ControlPc ≤ try_end_rva + ImageBase
    code.extend_from_slice(&[0x8B, 0x10]); // mov edx, [rax]   try_begin
    code.extend_from_slice(&[0x4C, 0x01, 0xDA]); // add rdx, r11
    code.extend_from_slice(&[0x49, 0x39, 0xD2]); // cmp r10, rdx
    code.extend_from_slice(&[0x0F, 0x82, 0, 0, 0, 0]); // jb .next
    let jb_next = code.len() - 4;
    code.extend_from_slice(&[0x8B, 0x50, 0x04]); // mov edx, [rax+4] try_end
    code.extend_from_slice(&[0x4C, 0x01, 0xDA]); // add rdx, r11
    code.extend_from_slice(&[0x49, 0x39, 0xD2]); // cmp r10, rdx
    code.extend_from_slice(&[0x0F, 0x87, 0, 0, 0, 0]); // ja .next  (STRICT > — H4a comment)
    let ja_next = code.len() - 4;

    // PC matched — branch on catch_kind.
    // r8d = catch_kind, r9d = catch_type_rva.
    code.extend_from_slice(&[0x44, 0x8B, 0x40, 0x0C]); // mov r8d, [rax+12]
    code.extend_from_slice(&[0x44, 0x8B, 0x48, 0x10]); // mov r9d, [rax+16]
    // ECX still has the previous edx in a dirty state; reload er into rcx.
    code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF8]); // mov rcx, [rbp-8] (er)
    code.extend_from_slice(&[0x8B, 0x11]); // mov edx, [rcx]   (code)

    // S6: catch-all kind (4) — `catch (...)`. Match ANY in-range exception with
    // NO type check (mirrors Cleanup's unconditional match) and TERMINATE the
    // search (deliver to the handler, unlike Cleanup which re-raises). No catch
    // param, so ReturnValue is unused (zeroed). Checked before the typed kinds.
    code.extend_from_slice(&[0x41, 0x83, 0xF8, 0x04]); // cmp r8d, 4
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne skip_catchall
    let jne_skip_catchall = code.len() - 4;
    // S6 rethrow: stamp the caught ExceptionRecord into `.mdbcc_eh_save`
    // (code + NumberParameters + args[0..1]) so a `throw;` inside the
    // catch-all body can re-raise the ORIGINAL exception verbatim — exactly
    // like the cleanup pad below. The ER pointer the personality holds dies
    // with the dispatch frame after the unwind transfer, so the save area is
    // the only stable source. Always stamped (harmless if the body never
    // rethrows; the handler simply never reads it). rcx = er here.
    code.extend_from_slice(&[0x48, 0x8D, 0x05]); // lea rax, [rip+save]
    let at_save_ca = code.len();
    code.extend_from_slice(&[0, 0, 0, 0]);
    riprefs.push(RipReloc {
        at: at_save_ca,
        target: RipRef::Data(eh_save_global_idx),
    });
    code.extend_from_slice(&[0x8B, 0x11]); // mov edx, [rcx]      (code)
    code.extend_from_slice(&[0x89, 0x10]); // mov [rax], edx
    code.extend_from_slice(&[0x8B, 0x51, 0x18]); // mov edx, [rcx+0x18] (NumberParameters)
    code.extend_from_slice(&[0x89, 0x50, 0x04]); // mov [rax+4], edx
    code.extend_from_slice(&[0x48, 0x8B, 0x51, 0x20]); // mov rdx, [rcx+0x20] (args[0])
    code.extend_from_slice(&[0x48, 0x89, 0x50, 0x08]); // mov [rax+8], rdx
    code.extend_from_slice(&[0x48, 0x8B, 0x51, 0x28]); // mov rdx, [rcx+0x28] (args[1])
    code.extend_from_slice(&[0x48, 0x89, 0x50, 0x10]); // mov [rax+16], rdx
    code.extend_from_slice(&[0x48, 0x31, 0xC0]); // xor rax, rax (ret=0)
    code.extend_from_slice(&[0x48, 0x89, 0x45, 0xB0]); // mov [rbp-80], rax
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp deliver
    let jmp_catchall_to_deliver = code.len() - 4;
    // skip_catchall: the typed/cleanup kind checks follow immediately.
    let skip_catchall_off = code.len();
    let rel_skip = (skip_catchall_off as i32) - (jne_skip_catchall as i32 + 4);
    code[jne_skip_catchall..jne_skip_catchall + 4].copy_from_slice(&rel_skip.to_le_bytes());

    // Tick 69 (J-11b / J-15b): cleanup kind (3) — no type check; copy
    // ExceptionCode + NumberParameters + args[0..1] into the
    // module-wide save area `.mdbcc_eh_save` so the cleanup landing
    // pad can re-raise from a stable source. The ER pointer the
    // personality function holds points into the (now-unwound)
    // RtlDispatchException frame which is reclaimed after the unwind
    // transfer; reading it from the cleanup pad observes garbage.
    //
    // We pass any nonzero value as ReturnValue (RAX in the cleanup
    // pad). The cleanup pad does not read it; the save area is the
    // source of truth.
    code.extend_from_slice(&[0x41, 0x83, 0xF8, 0x03]); // cmp r8d, 3
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne not_cleanup
    let jne_not_cleanup = code.len() - 4;
    // rcx = er (re-loaded; the test above already saw it).
    // RAX = &.mdbcc_eh_save (rip-relative).
    code.extend_from_slice(&[0x48, 0x8D, 0x05]); // lea rax, [rip+save]
    let at_save = code.len();
    code.extend_from_slice(&[0, 0, 0, 0]);
    riprefs.push(RipReloc {
        at: at_save,
        target: RipRef::Data(eh_save_global_idx),
    });
    // Copy ExceptionCode (4 bytes at [rcx+0]) → [rax+0].
    code.extend_from_slice(&[0x8B, 0x11]); // mov edx, [rcx]
    code.extend_from_slice(&[0x89, 0x10]); // mov [rax], edx
    // Copy NumberParameters (4 bytes at [rcx+0x18]) → [rax+4].
    code.extend_from_slice(&[0x8B, 0x51, 0x18]); // mov edx, [rcx+0x18]
    code.extend_from_slice(&[0x89, 0x50, 0x04]); // mov [rax+4], edx
    // Copy args[0] (8 bytes at [rcx+0x20]) → [rax+8].
    code.extend_from_slice(&[0x48, 0x8B, 0x51, 0x20]); // mov rdx, [rcx+0x20]
    code.extend_from_slice(&[0x48, 0x89, 0x50, 0x08]); // mov [rax+8], rdx
    // Copy args[1] (8 bytes at [rcx+0x28]) → [rax+16].
    code.extend_from_slice(&[0x48, 0x8B, 0x51, 0x28]); // mov rdx, [rcx+0x28]
    code.extend_from_slice(&[0x48, 0x89, 0x50, 0x10]); // mov [rax+16], rdx
    // ReturnValue = 0 (placeholder; cleanup pad doesn't read it).
    code.extend_from_slice(&[0x48, 0x31, 0xC0]); // xor rax, rax
    code.extend_from_slice(&[0x48, 0x89, 0x45, 0xB0]); // mov [rbp-80], rax
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp deliver
    let jmp_cleanup_to_deliver = code.len() - 4;

    // ---- not_cleanup ----
    let not_cleanup_off = code.len();
    let rel_nc = (not_cleanup_off as i32) - (jne_not_cleanup as i32 + 4);
    code[jne_not_cleanup..jne_not_cleanup + 4].copy_from_slice(&rel_nc.to_le_bytes());

    code.extend_from_slice(&[0x45, 0x85, 0xC0]); // test r8d, r8d
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je int_kind
    let je_int_kind = code.len() - 4;

    // ---- class catch (kind 1 or 2) ----
    // exception code must be 0xE0000002
    code.extend_from_slice(&[0x81, 0xFA]);
    code.extend_from_slice(&EXCEPTION_MDBCC_CLASS.to_le_bytes()); // cmp edx, 0xE0000002
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne .next
    let jne_to_next_class = code.len() - 4;
    // thrown vtable abs = er[+0x20]; convert to RVA by subtracting ImageBase.
    code.extend_from_slice(&[0x48, 0x8B, 0x41, 0x20]); // mov rax, [rcx+0x20]
    code.extend_from_slice(&[0x4C, 0x29, 0xD8]); // sub rax, r11
    code.extend_from_slice(&[0x48, 0x89, 0x45, 0xD0]); // mov [rbp-48], rax  (current RVA)
    code.extend_from_slice(&[0x4C, 0x89, 0x4D, 0xB8]); // mov [rbp-72], r9   (catch_type RVA)

    // ---- hierarchy walk loop ----
    let walk_top = code.len();
    // current = [rbp-48]; if current == 0 → no match
    code.extend_from_slice(&[0x48, 0x8B, 0x45, 0xD0]); // mov rax, [rbp-48]
    code.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // jz .next
    let jz_to_next_walk_root = code.len() - 4;
    code.extend_from_slice(&[0x48, 0x3B, 0x45, 0xB8]); // cmp rax, [rbp-72]
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // je class_match
    let je_class_match = code.len() - 4;
    // Scan tyinf table: rcx = base, rdx = count.
    code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xC8]); // mov rcx, [rbp-56]
    code.extend_from_slice(&[0x48, 0x8B, 0x55, 0xC0]); // mov rdx, [rbp-64]
    let scan_top = code.len();
    code.extend_from_slice(&[0x48, 0x85, 0xD2]); // test rdx, rdx
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); // jz .next (not found)
    let jz_to_next_scan = code.len() - 4;
    // compare [rcx] (class_rva u32) with low 32 of rax
    code.extend_from_slice(&[0x39, 0x01]); // cmp [rcx], eax
    code.extend_from_slice(&[0x74, 0x09]); // je .found (+9)
    code.extend_from_slice(&[0x48, 0x83, 0xC1, 0x08]); // add rcx, 8
    code.extend_from_slice(&[0x48, 0xFF, 0xCA]); // dec rdx
    let scan_back_at = code.len();
    code.extend_from_slice(&[0xEB]); // jmp scan_top (short)
    let scan_back_rel = (scan_top as i32) - (scan_back_at as i32 + 2);
    debug_assert!((-128..=127).contains(&scan_back_rel));
    code.extend_from_slice(&[scan_back_rel as i8 as u8]);
    let found_off = code.len();
    // Found: current = [rcx+4] (base_rva)
    code.extend_from_slice(&[0x8B, 0x41, 0x04]); // mov eax, [rcx+4]
    code.extend_from_slice(&[0x48, 0x89, 0x45, 0xD0]); // mov [rbp-48], rax
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp walk_top
    let jmp_back_walk = code.len() - 4;
    let walk_rel = (walk_top as i32) - (jmp_back_walk as i32 + 4);
    code[jmp_back_walk..jmp_back_walk + 4].copy_from_slice(&walk_rel.to_le_bytes());

    // Sanity: the `je .found` short jump skipped exactly 9 bytes from
    // its end to reach the `.found` mov-instruction; assert layout.
    // Promoted from debug_assert_eq! to assert! per Phase H code-review
    // NIT-4: this is a load-bearing layout invariant, and silently
    // emitting a wrong-target jump in a release build would reincarnate
    // the H4b je-offset re-count bug. The personality function is built
    // once per module, so the cost is irrelevant.
    assert_eq!(found_off, scan_back_at + 2);

    // ---- class_match ----
    let class_match_off = code.len();
    // ReturnValue = er[+0x28] (buffer abs)
    code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF8]); // mov rcx, [rbp-8] (er)
    code.extend_from_slice(&[0x48, 0x8B, 0x41, 0x28]); // mov rax, [rcx+0x28]
    code.extend_from_slice(&[0x48, 0x89, 0x45, 0xB0]); // mov [rbp-80], rax
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp .deliver
    let jmp_to_deliver_long = code.len() - 4;

    // Patch je_class_match to class_match_off.
    let rel_cm = (class_match_off as i32) - (je_class_match as i32 + 4);
    code[je_class_match..je_class_match + 4].copy_from_slice(&rel_cm.to_le_bytes());

    // ---- int_kind ----
    let int_kind_off = code.len();
    let int_jmp_rel = (int_kind_off as i32) - (je_int_kind as i32 + 4);
    code[je_int_kind..je_int_kind + 4].copy_from_slice(&int_jmp_rel.to_le_bytes());
    // int catches accept ONLY EXCEPTION_MDBCC_INT.
    code.extend_from_slice(&[0x81, 0xFA]);
    code.extend_from_slice(&EXCEPTION_MDBCC_INT.to_le_bytes()); // cmp edx, 0xE0000001
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jne .next
    let jne_to_next_int = code.len() - 4;
    // ReturnValue = er[+0x20] (the int — full 64 bits; high bits unused)
    code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF8]); // mov rcx, [rbp-8]
    code.extend_from_slice(&[0x48, 0x8B, 0x41, 0x20]); // mov rax, [rcx+0x20]
    code.extend_from_slice(&[0x48, 0x89, 0x45, 0xB0]); // mov [rbp-80], rax
    // fall through to .deliver

    // ---- deliver ----
    let deliver_off = code.len();
    let dist = (deliver_off as i32) - (jmp_to_deliver_long as i32 + 4);
    code[jmp_to_deliver_long..jmp_to_deliver_long + 4].copy_from_slice(&dist.to_le_bytes());
    // Tick 69: cleanup match also jumps here.
    let dist_cu = (deliver_off as i32) - (jmp_cleanup_to_deliver as i32 + 4);
    code[jmp_cleanup_to_deliver..jmp_cleanup_to_deliver + 4]
        .copy_from_slice(&dist_cu.to_le_bytes());
    // S6: catch-all match also jumps here.
    let dist_ca = (deliver_off as i32) - (jmp_catchall_to_deliver as i32 + 4);
    code[jmp_catchall_to_deliver..jmp_catchall_to_deliver + 4]
        .copy_from_slice(&dist_ca.to_le_bytes());

    // handler_abs = ImageBase + scope[8].
    code.extend_from_slice(&[0x48, 0x8B, 0x45, 0xA8]); // mov rax, [rbp-88] (entry ptr)
    code.extend_from_slice(&[0x8B, 0x50, 0x08]); // mov edx, [rax+8]
    code.extend_from_slice(&[0x4C, 0x01, 0xDA]); // add rdx, r11
    code.extend_from_slice(&[0x48, 0x89, 0x55, 0xD8]); // mov [rbp-40], rdx

    // RtlUnwindEx(TargetFrame, TargetIp, ExceptionRecord, ReturnValue,
    //             ContextRecord, NULL)
    code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF0]); // mov rcx, [rbp-16] (frame)
    code.extend_from_slice(&[0x48, 0x8B, 0x55, 0xD8]); // mov rdx, [rbp-40] (handler)
    code.extend_from_slice(&[0x4C, 0x8B, 0x45, 0xF8]); // mov r8,  [rbp-8]  (er)
    code.extend_from_slice(&[0x4C, 0x8B, 0x4D, 0xB0]); // mov r9,  [rbp-80] (ret val)
    code.extend_from_slice(&[0x48, 0x8B, 0x45, 0xE8]); // mov rax, [rbp-24] (ctx)
    code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]); // mov [rsp+32], rax
    code.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+40], 0
    code.extend_from_slice(&[0xFF, 0x15]);
    let at = code.len();
    code.extend_from_slice(&[0, 0, 0, 0]);
    riprefs.push(RipReloc {
        at,
        target: RipRef::Import("RtlUnwindEx".to_string()),
    });
    code.extend_from_slice(&[0x0F, 0x0B]); // ud2

    // ---- .next ----
    let next_off = code.len();
    let patch_to_next = |code: &mut Vec<u8>, at: usize| {
        let rel = (next_off as i32) - (at as i32 + 4);
        code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
    };
    patch_to_next(&mut code, jb_next);
    patch_to_next(&mut code, ja_next);
    patch_to_next(&mut code, jne_to_next_class);
    patch_to_next(&mut code, jz_to_next_walk_root);
    patch_to_next(&mut code, jz_to_next_scan);
    patch_to_next(&mut code, jne_to_next_int);
    // Advance cursor and decrement count, then jmp loop_top.
    code.extend_from_slice(&[0x48, 0x83, 0x45, 0xA8, 0x14]); // add qword [rbp-88], 20
    code.extend_from_slice(&[0x48, 0xFF, 0x4D, 0xA0]); // dec qword [rbp-96]
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); // jmp loop_top
    let jmp_back_at = code.len() - 4;
    let rel_back = (loop_top as i32) - (jmp_back_at as i32 + 4);
    code[jmp_back_at..jmp_back_at + 4].copy_from_slice(&rel_back.to_le_bytes());

    // ---- continue_search ----
    let continue_search = code.len();
    code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    code.extend_from_slice(&[0xC9]); // leave
    code.extend_from_slice(&[0xC3]); // ret

    for jp in jumps_to_continue {
        let rel = (continue_search as i32) - (jp as i32 + 4);
        code[jp..jp + 4].copy_from_slice(&rel.to_le_bytes());
    }

    CompiledFn {
        name: PERSONALITY_FN_NAME.into(),
        code,
        calls: Vec::new(),
        riprefs,
        strings: Vec::new(),
        fp_literals: Vec::new(),
        try_scopes: Vec::new(),
        extern_refs: Vec::new(),
        // S4.2af: one fixed personality, identical in every EH TU ⇒ foldable.
        inline: true,
    }
}
