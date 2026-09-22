//! Minimal PE32+ (x64) console-executable writer.
//!
//! Lives under `src/link/` as the first home of the future `mdlink` linker
//! library (HLD `2026.05.27 - HLD - S1c mdlink linker.md` §1.1). S1c.2
//! moved this file verbatim from `src/pe.rs`; `src/pe.rs` is now a thin
//! `pub use crate::link::pe_writer::*;` stub so existing consumers
//! (`compile.rs`, `codegen.rs`, the `pe_*` integration tests) stay
//! unchanged. Subsequent S1c phases (S1c.3 onward) reshape this module
//! into the multi-input linker; for now it is byte-identical to the
//! previous `pe.rs`.
//!
//! We emit the whole binary ourselves — no external assembler or linker (none
//! are installed, and owning the pipeline is the point of reimplementing
//! BCC+TLINK). The file has four sections: `.text` (an entry stub plus the
//! generated functions), `.idata` (imports), `.rdata` (string literals), and
//! `.data` (globals). Each section's RVA is `align_up(prev_end, SECT_ALIGN)`,
//! so a section larger than one page no longer overlaps the next (see below).
//!
//! Dynamic layout (ImageBase 0x1_4000_0000, file align 0x200, sect align
//! 0x1000). Sections keep their order — `.text, .idata, .rdata, .data` — but
//! each one's RVA is computed from the previous section's actual size
//! (`align_up` to the section alignment), so a section larger than 0x1000
//! no longer overlaps the next. A program whose every section fits in
//! 0x1000 reproduces the historical fixed RVAs (0x1000/0x2000/0x3000/0x4000)
//! byte-for-byte. `.text` starts at `align_up(SizeOfHeaders, 0x1000)`:
//! ```text
//!   headers          file 0x0000          (<= 0x400)
//!   .text            file 0x0400  RVA 0x1000
//!   .idata           file 0x0400+csz RVA align_up(0x1000+|.text|, 0x1000)
//!   .rdata           …            RVA align_up(idata_rva+|.idata|, 0x1000)
//!   .data            …            RVA align_up(rdata_rva+|.rdata|, 0x1000)
//! ```
//! The entry stub is `sub rsp,0x28; call main; mov ecx,eax; call [ExitProcess]`
//! so the process exit code is `main`'s return value.

use std::collections::HashMap;

use crate::codegen::{CodegenError, CompiledFn, Module};
use crate::coff::{self, RelocKind, SectionName, SectionRef, StorageClass};
use crate::link::{LinkError, LinkOpts, Subsystem};
use crate::rc::{RcUnit, write_res};

const IMAGE_BASE: u64 = 0x1_4000_0000;
/// PE32 ImageBase (32-bit). Conventional default for Win32 console/GUI
/// EXEs (Borland + MSVC both ship with this); per HLD §5.2 / §5.4 our
/// PE32 writer uses fixed ImageBase + IMAGE_FILE_RELOCS_STRIPPED, so no
/// `.reloc` section is needed. Q-Reloc ratification (2026-05-27).
const IMAGE_BASE_PE32: u32 = 0x0040_0000;
const SECT_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
// Four section headers push the header block past 0x200; round to 0x400.
const HEADERS_SIZE: u32 = 0x400;
const PE_OFF: usize = 0x80; // e_lfanew
/// BC4.5 tlink32's OS (1.0) and subsystem (3.10) versions, which the object
/// linker stamps on PE32 and PE32+ images alike. USER keys legacy metrics on
/// the subsystem version: below 6.0 a window gets the thin pre-Vista frame
/// (no padded border) and a dialog keeps Win3.x-era font base units. BC4.5
/// programs
/// lay out fixed-pixel windows and paint fixed-pixel bitmaps against those
/// metrics; 6.0 shrinks every WS_DLGFRAME client by 10px and narrows every
/// dialog (RailC boards overflow their frames and About bitmaps misplace).
const OS_VERSION: (u16, u16) = (1, 0);
const SUBSYSTEM_VERSION: (u16, u16) = (3, 10);

fn align_up(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

struct Buf(Vec<u8>);

impl Buf {
    fn new() -> Self {
        Buf(Vec::new())
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn pad_to(&mut self, len: usize) {
        if self.0.len() < len {
            self.0.resize(len, 0);
        }
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Single source of truth: every Win32 symbol the compiler can import, mapped
/// to its DLL. Ordered, deterministic (no HashMap feeds emitted bytes). The
/// existing six `KERNEL32` symbols MUST stay first and in this order so the
/// `.idata` for a console program is byte-identical (the C1 golden lock).
/// `ExitProcess` must stay index 0 (the entry stub calls it). Phase C/D append
/// `USER32`/`GDI32` symbols here *only when codegen emits them* — never
/// speculatively (house style).
const WIN32_IMPORTS: &[(&str, &str)] = &[
    ("ExitProcess", "KERNEL32.dll"),
    ("GetStdHandle", "KERNEL32.dll"),
    ("WriteFile", "KERNEL32.dll"),
    ("GetProcessHeap", "KERNEL32.dll"),
    ("HeapAlloc", "KERNEL32.dll"),
    ("HeapFree", "KERNEL32.dll"),
    // S5 (railc W2/W5): more KERNEL32 APIs the RTL/OWL closure references
    // (GetTimeZoneInformation from the RTL TIME code; GetVersion/GetModuleHandleA/
    // GetLastError/LockResource from OWL + resource handling). All in
    // EXTENDED_ON_DEMAND below, so any image not referencing them is unchanged.
    ("GetLastError", "KERNEL32.dll"),
    ("GetModuleHandleA", "KERNEL32.dll"),
    ("GetVersion", "KERNEL32.dll"),
    ("LockResource", "KERNEL32.dll"),
    ("GetTimeZoneInformation", "KERNEL32.dll"),
    // S6 (OWL link): CLASSLIB/THREAD.H's `TMutex` ctor calls
    // `::CreateMutex(0,FALSE,0)` → `CreateMutexA` (non-UNICODE); the object-
    // streaming machinery (OBJSTRM.CPP) drags `TMutex` in. In EXTENDED_ON_DEMAND
    // so it is emitted ONLY when a TU imports it (on both targets) — keeping
    // every program that does not call it byte-identical.
    ("CreateMutexA", "KERNEL32.dll"),
    ("CloseHandle", "KERNEL32.dll"),
    ("WaitForSingleObject", "KERNEL32.dll"),
    ("ReleaseMutex", "KERNEL32.dll"),
    // W2 (railc RTL self-host I/O shim — wrk_rtlshim/rtlio.c): the file-I/O
    // syscalls the mdbcc-built `open`/`read`/`write`/`lseek` wrappers call, plus
    // `GetExitCodeThread` (CLASSLIB TThread). All in EXTENDED_ON_DEMAND ⇒
    // byte-identical for any image that does not reference them.
    ("CreateFileA", "KERNEL32.dll"),
    ("ReadFile", "KERNEL32.dll"),
    ("SetFilePointer", "KERNEL32.dll"),
    ("GetExitCodeThread", "KERNEL32.dll"),
    // W2 (railc RTL): `time()` (TIME/WIN32/TIME.C) reads the wall clock via
    // `GetLocalTime(&st)`; pulled in once stdlib.h's inline `randomize()`
    // (srand+time) started compiling. In EXTENDED_ON_DEMAND ⇒ byte-identical
    // for any image that does not reference it.
    ("GetLocalTime", "KERNEL32.dll"),
    // W6 (honest closure, post ctor-thunk GC roots): KERNEL32 Local* heap
    // family (OWL TMenu/clipboard paths + RTL), `LoadLibraryA` (OWL TModule),
    // and GDI32's `GetObjectA` (OWL TGdiObject introspection). All in
    // EXTENDED_ON_DEMAND ⇒ byte-identical for any image not naming them.
    ("LocalHandle", "KERNEL32.dll"),
    ("LocalLock", "KERNEL32.dll"),
    ("LocalReAlloc", "KERNEL32.dll"),
    ("LocalUnlock", "KERNEL32.dll"),
    ("LoadLibraryA", "KERNEL32.dll"),
    ("GetObjectA", "GDI32.dll"),
    // W6 (Bug C layer 1): APIs referenced by OWL bodies whose names were
    // missing from this table, so the compiler fell back to Borland C++
    // mangling (the extern "C" gate is parked — see notes). `UnregisterClassA`
    // pairs with `RegisterClassA` (OWL TApplication shutdown); the four
    // common-dialog launchers are the TFindReplaceDialog/TChooseColorDialog/
    // TChooseFontDialog entry points. All in EXTENDED_ON_DEMAND ⇒
    // byte-identical for any image not naming them.
    ("UnregisterClassA", "USER32.dll"),
    ("FindTextA", "COMDLG32.dll"),
    ("ReplaceTextA", "COMDLG32.dll"),
    ("ChooseColorA", "COMDLG32.dll"),
    ("ChooseFontA", "COMDLG32.dll"),
    // W6: the KERNEL32 Global* heap family — the moveable-HGLOBAL twin of
    // the Local* batch above. OWL DIB/LISTVIEW/METAFILE/OLEMETA/PRINTDIA
    // GlobalAlloc/Lock/Unlock DIB bits, clipboard payloads and the
    // PRINTDLG DEVMODE; Free/ReAlloc/Size/Handle ride along (DIB.CPP /
    // EDIT.CPP call them from not-yet-live members). All in
    // EXTENDED_ON_DEMAND ⇒ byte-identical for any image not naming them.
    ("GlobalAlloc", "KERNEL32.dll"),
    ("GlobalFree", "KERNEL32.dll"),
    ("GlobalLock", "KERNEL32.dll"),
    ("GlobalUnlock", "KERNEL32.dll"),
    ("GlobalReAlloc", "KERNEL32.dll"),
    ("GlobalSize", "KERNEL32.dll"),
    ("GlobalHandle", "KERNEL32.dll"),
    // W6 (G48 fallout): KERNEL32 surface the now-RUNNING `#pragma startup`
    // RTL init chain calls — HANDLES.C `_init_handles` (GetStartupInfoA,
    // SetHandleCount), FSTAT/STAT/__ISATTY (GetFileType), and the rtlshim's
    // C0 seeding of `_oscmd`/`_osenv` (GetCommandLineA, GetEnvironment-
    // StringsA — STARTUP.C:394-395 verbatim). On-demand ⇒ byte-identical.
    ("GetStartupInfoA", "KERNEL32.dll"),
    ("GetFileType", "KERNEL32.dll"),
    ("SetHandleCount", "KERNEL32.dll"),
    ("GetCommandLineA", "KERNEL32.dll"),
    ("GetEnvironmentStringsA", "KERNEL32.dll"),
    // S3 (Win32 API-call): the `lstr*A` legacy string helpers are KERNEL32
    // exports (historically they live in KERNEL32 on 32-bit Windows, not
    // USER32), so they belong in this group. They were first exercised by the
    // i386 `emit_win32_call` __stdcall path (`lstrlenA(s)` → `EAX = strlen`;
    // `lstrcmpA(a,b)` proves multi-arg right-to-left push order). RailC's
    // source-built Win64 OWL closure also references `lstrlenA`/`lstrcmpiA`.
    // All three are in EXTENDED_ON_DEMAND, so x64 images import them only when
    // an object actually names their `__imp_*` symbol.
    ("lstrlenA", "KERNEL32.dll"),
    ("lstrcmpA", "KERNEL32.dll"),
    ("lstrcmpiA", "KERNEL32.dll"),
    // USER32 — Phase C / C3 GUI minimum: `MessageBoxA` is all O6 needs.
    // `used_dlls`/`grouped_imports` only emit a DLL whose symbol is
    // actually referenced, so a console program (no `MessageBoxA`) still
    // resolves to `["KERNEL32.dll"]` → `.idata` byte-identical. Phase D
    // appends the rest of the USER32/GDI32 set *when its codegen emits
    // them* — never speculatively (house style).
    ("MessageBoxA", "USER32.dll"),
    // S4.2b11: USER32 ANSI/OEM converters — the RTL `string::ansi_to_oem()` /
    // `oem_to_ansi()` (CSTRING.H) call `CharToOemA`/`OemToCharA`. Adding them
    // lets a real STRING-RTL link resolve. A console program names neither, so
    // the per-symbol `used` filter (PE32) / non-emission (x64) keeps its imports
    // unchanged; the 88 byte-identity baselines import only KERNEL32.
    ("CharToOemA", "USER32.dll"),
    ("OemToCharA", "USER32.dll"),
    // Phase D / D1 USER32 hello-window set (per `wrk_docs/2026.05.18 - HLD -
    // Phase D (minimal OWL runtime).md` §D-a (1)): the irreducible set for
    // RegisterClassExA / CreateWindowExA / ShowWindow+UpdateWindow / the
    // message-loop trio / DefWindowProcA / PostQuitMessage, plus
    // LoadCursorA (well-formed class) and Set/GetWindowLongPtrA (the
    // GWLP_USERDATA HWND->TWindow* binding). Dormant for any program that
    // does not reference them: a console program (no RipRef::Import here)
    // still yields used_dlls == ["KERNEL32.dll"] ⇒ `.idata` byte-identical
    // (locked by `tests/pe_imports.rs`). No GDI32 — a blank
    // WS_OVERLAPPEDWINDOW needs no painting; GDI is Phase E/G.
    ("RegisterClassExA", "USER32.dll"),
    ("CreateWindowExA", "USER32.dll"),
    ("ShowWindow", "USER32.dll"),
    ("UpdateWindow", "USER32.dll"),
    ("GetMessageA", "USER32.dll"),
    ("TranslateMessage", "USER32.dll"),
    ("DispatchMessageA", "USER32.dll"),
    ("DefWindowProcA", "USER32.dll"),
    ("PostQuitMessage", "USER32.dll"),
    ("LoadCursorA", "USER32.dll"),
    ("SetWindowLongPtrA", "USER32.dll"),
    ("GetWindowLongPtrA", "USER32.dll"),
    // Phase E / E2 USER32 paint pair (per `wrk_docs/2026.05.18 - HLD -
    // Phase E (OWL event handling).md` §E-d / §E-f E2): the OWL `TPaintDC`
    // RAII over `BeginPaint`/`EndPaint`. Still USER32 — `BeginPaint`/
    // `EndPaint` are USER32 ordinals, NOT GDI32 (confirmed against the
    // Win32 docs and the Win16 reference). The first GDI32 symbol is
    // E3's `TextOutA`. Dormant for any TU that does not construct a
    // `TPaintDC` (a `<windows.h>`-only or non-OWL program emits zero new
    // bytes — `tests/pe_imports.rs` / D1's byte-identical console lock
    // remains in force).
    ("BeginPaint", "USER32.dll"),
    ("EndPaint", "USER32.dll"),
    // Phase E / E3 (per `wrk_docs/2026.05.18 - HLD - Phase E (OWL event
    // handling).md` §E-d / §E-f E3): `TextOutA` — the **first GDI32 symbol
    // in mdbcc**. Exercises the C1b multi-descriptor `.idata` machinery
    // end-to-end with 3 DLLs (KERNEL32 + USER32 + GDI32) for the first
    // time outside the synthetic two-DLL unit test. The `used_dlls` /
    // `grouped_imports` / `emit_idata` path is k-agnostic by construction
    // (descriptors emitted in a loop, ILT/IAT per group); adding a third
    // DLL row is data, not a code change. Dormant for any TU that does
    // not call `TPaintDC::TextOut` (or `TextOutA` directly): a console
    // program references no GDI32 symbol ⇒ no GDI32 descriptor ⇒
    // `.idata` byte-identical (the C1a console lock in
    // `tests/pe_imports.rs` is the executable proof).
    ("TextOutA", "GDI32.dll"),
    // S4.2(f): the GDI/USER32 surface the SCRIBAPP OWL sample draws with (a DDVT
    // mouse-scribble window). MoveToEx/LineTo are GDI32 (the windows.h
    // MoveTo(h,x,y) macro maps to MoveToEx(h,x,y,0)); the rest are USER32. Safe
    // now that the #47 qualified-base-call recursion is fixed (adding these no
    // longer crashes CURSAPP). Dormant for any TU that doesn't draw.
    ("MoveToEx", "GDI32.dll"),
    ("LineTo", "GDI32.dll"),
    ("GetDC", "USER32.dll"),
    ("ReleaseDC", "USER32.dll"),
    ("SetCapture", "USER32.dll"),
    ("ReleaseCapture", "USER32.dll"),
    ("InvalidateRect", "USER32.dll"),
    // Phase G / G3 (per `wrk_docs/2026.05.18 - HLD - Phase G (resource
    // compiler).md` §G3): `LoadStringA` is the runtime side of the
    // `.rsrc`/STRINGTABLE pair — a program calls it to fetch a string
    // resource by id at runtime. The caller passes `hInstance = NULL`
    // (documented Win32 contract: when `LoadStringA` sees NULL it
    // searches the module that created the calling process — exactly
    // what an EXE-internal STRINGTABLE wants), so we deliberately do
    // NOT add `GetModuleHandleA` to KERNEL32: doing so would force every
    // existing console program's `.idata` to grow (current grouping is
    // per-DLL, not per-symbol; the C1a console-`.idata` golden in
    // `tests/pe_imports.rs` pins exactly six KERNEL32 entries). USER32
    // already has many entries from C/D/E; appending one more affects
    // *only* TUs that already use USER32 (the existing tests' GUI
    // programs do). For a TU that imports nothing from USER32 (a plain
    // console `main`), USER32 is excluded by `used_dlls` ⇒ `.idata`
    // byte-identical.
    ("LoadStringA", "USER32.dll"),
    // Phase G / G4 (per `wrk_docs/2026.05.18 - HLD - Phase G (resource
    // compiler).md` §G4): the MENU + ACCELERATOR runtime trio.
    // `LoadMenuA` / `LoadAcceleratorsA` retrieve a `HMENU` / `HACCEL`
    // from the calling module's `.rsrc` by id (passing `hInstance = NULL`
    // means "the module that created the process"); `TranslateAcceleratorA`
    // is the message-pump-side dispatch for accelerator keystrokes.
    // Same dormancy invariant as `LoadStringA`: USER32 is only emitted
    // when used, so a TU referencing none of these stays byte-identical
    // (the KERNEL32 golden in `tests/pe_imports.rs` is unchanged).
    ("LoadMenuA", "USER32.dll"),
    ("LoadAcceleratorsA", "USER32.dll"),
    ("TranslateAcceleratorA", "USER32.dll"),
    // Phase G / G5a (per `wrk_docs/2026.05.18 - HLD - Phase G (resource
    // compiler).md` §G5): the DIALOG runtime pair. `DialogBoxParamA`
    // creates a modal dialog from an `.rsrc` DLGTEMPLATE by id; `EndDialog`
    // dismisses it from the dialog procedure. Added now (G5a, structural)
    // so the runtime test increment (G5b) is purely test/codegen work,
    // not a `.idata` reshuffle. Same dormancy invariant: USER32 only
    // emitted when used; KERNEL32 golden (`tests/pe_imports.rs`)
    // unaffected because USER32 is a separate descriptor.
    ("DialogBoxParamA", "USER32.dll"),
    ("EndDialog", "USER32.dll"),
    // S3 (HELLOWIN.C — the Petzold "hello, windows" finale): the remaining
    // USER32/GDI32 symbols the canonical sample names (via the windows.h
    // macro chain: RegisterClass→RegisterClassA, DrawText→DrawTextA, …).
    // `LoadIconA`/`GetClientRect`/`DrawTextA` are USER32; `GetStockObject` is
    // GDI32; `RegisterClassA` is the non-Ex class registrar (HELLOWIN uses
    // WNDCLASS, not WNDCLASSEX). They are **i386-only** here (all five are in
    // `WIN32_IMPORTS_X64_EXCLUDE`): the x64 grouping is non-pruning, so
    // emitting them would grow every USER32/GDI32-using PE32+ image and break
    // the byte-identity stripe; the PE32 path prunes per-symbol so an i386 TU
    // imports them only when it actually calls them (HELLOWIN does). x64 GUI
    // (S7) will revisit x64 per-symbol pruning to enable them there.
    ("LoadIconA", "USER32.dll"),
    ("RegisterClassA", "USER32.dll"),
    ("GetClientRect", "USER32.dll"),
    ("DrawTextA", "USER32.dll"),
    ("GetStockObject", "GDI32.dll"),
    // Phase H / H4a (per `wrk_docs/2026.05.18 - HLD - Phase H (C++
    // maturation).md` §H4a): the Win64 SEH runtime pair. `RaiseException`
    // is the throw site's lowering target (`throw <int-expr>;` lowers to a
    // `RaiseException(0xE0000001, 0, 1, &slot)` call). `RtlUnwindEx` is
    // the personality function's "transfer control to catch handler"
    // primitive — it unwinds intermediate frames and resumes execution
    // at the catch landing pad with the thrown int placed in RAX.
    //
    // Both are KERNEL32 ordinals. Adding them shifts the historical
    // KERNEL32-six golden in `tests/pe_imports.rs` (H4a updates the
    // golden in lockstep — the per-DLL grouping deliberately does NOT
    // per-symbol prune, so every KERNEL32 program now imports all 8
    // symbols, even though only programs with `try`/`throw` actually
    // call them). This is the same dormancy-via-aggregation pattern
    // every other Phase C/D/E/G import follows.
    ("RaiseException", "KERNEL32.dll"),
    ("RtlUnwindEx", "KERNEL32.dll"),
    // S2e (i386 fs:[0] SEH): the x86 `__mdbcc_seh3_handler`'s "unwind
    // intermediate frames then transfer into the catch" primitive. x86 uses
    // `RtlUnwind` (4-arg __stdcall, exported by the 32-bit SysWOW64
    // kernel32.dll) where x64 uses `RtlUnwindEx`. PE32 per-symbol pruning
    // keeps it out of non-throwing i386 images; the x64 (non-pruning)
    // grouping explicitly EXCLUDES it (see `WIN32_IMPORTS_X64_EXCLUDE`) so
    // the 8-symbol KERNEL32 golden + 88 SipHash baselines stay byte-identical.
    ("RtlUnwind", "KERNEL32.dll"),
    // S5 (railc W5): Win32 APIs called from INLINED OWL/RTL bodies that
    // mdbcc previously emitted C++-MANGLED (no __imp_) because they were
    // absent from this table. All are in EXTENDED_ON_DEMAND below, so they
    // emit per-symbol on BOTH targets (x64 byte-identity preserved — no x64
    // test references them). DLL attribution from Borland IMPORT32.LIB IMPDEFs.
    // Kept for PE32 / foreign `__imp_` object compatibility. Native Win64
    // codegen deliberately does not route these names to CTL3D32.dll because
    // that legacy decoration DLL is not present as a 64-bit system DLL; the
    // source-built RailC path satisfies direct calls via wrk_rtlshim.
    ("Ctl3dRegister", "CTL3D32.dll"),
    ("Ctl3dAutoSubclass", "CTL3D32.dll"),
    ("Ctl3dUnregister", "CTL3D32.dll"),
    ("sndPlaySoundA", "WINMM.dll"),
    ("GetOpenFileNameA", "COMDLG32.dll"),
    ("CommDlgExtendedError", "COMDLG32.dll"),
    ("DragAcceptFiles", "SHELL32.dll"),
    ("DragFinish", "SHELL32.dll"),
    ("DragQueryFileA", "SHELL32.dll"),
    ("DragQueryPoint", "SHELL32.dll"),
    ("ExtractIconA", "SHELL32.dll"),
    ("FindResourceA", "KERNEL32.dll"),
    ("GetModuleFileNameA", "KERNEL32.dll"),
    ("GetProcAddress", "KERNEL32.dll"),
    ("LoadResource", "KERNEL32.dll"),
    ("SizeofResource", "KERNEL32.dll"),
    ("FreeResource", "KERNEL32.dll"),
    ("GetPrivateProfileIntA", "KERNEL32.dll"),
    ("GetPrivateProfileStringA", "KERNEL32.dll"),
    ("WritePrivateProfileStringA", "KERNEL32.dll"),
    ("OpenFile", "KERNEL32.dll"),
    ("BitBlt", "GDI32.dll"),
    ("CreateCompatibleBitmap", "GDI32.dll"),
    ("CreateCompatibleDC", "GDI32.dll"),
    ("CreateDiscardableBitmap", "GDI32.dll"),
    ("CreateFontIndirectA", "GDI32.dll"),
    ("DeleteDC", "GDI32.dll"),
    ("Ellipse", "GDI32.dll"),
    ("EqualRgn", "GDI32.dll"),
    ("ExtTextOutA", "GDI32.dll"),
    ("CombineRgn", "GDI32.dll"),
    ("GetTextExtentPoint32A", "GDI32.dll"),
    ("GetTextExtentPointA", "GDI32.dll"),
    ("Polygon", "GDI32.dll"),
    ("Rectangle", "GDI32.dll"),
    ("SelectObject", "GDI32.dll"),
    ("SetBkColor", "GDI32.dll"),
    ("SetTextAlign", "GDI32.dll"),
    ("SetTextColor", "GDI32.dll"),
    ("StretchBlt", "GDI32.dll"),
    ("CreateFontA", "GDI32.dll"),
    ("CreatePen", "GDI32.dll"),
    ("CreateRectRgn", "GDI32.dll"),
    ("CreateSolidBrush", "GDI32.dll"),
    ("DeleteObject", "GDI32.dll"),
    ("AdjustWindowRect", "USER32.dll"),
    ("AdjustWindowRectEx", "USER32.dll"),
    ("BringWindowToTop", "USER32.dll"),
    ("CheckDlgButton", "USER32.dll"),
    ("CheckMenuItem", "USER32.dll"),
    ("CheckRadioButton", "USER32.dll"),
    ("ChildWindowFromPoint", "USER32.dll"),
    ("ClientToScreen", "USER32.dll"),
    ("CopyIcon", "USER32.dll"),
    ("CreateCaret", "USER32.dll"),
    ("DestroyIcon", "USER32.dll"),
    ("DrawMenuBar", "USER32.dll"),
    ("EnableMenuItem", "USER32.dll"),
    ("EnableScrollBar", "USER32.dll"),
    ("EnableWindow", "USER32.dll"),
    ("EnumPropsA", "USER32.dll"),
    ("FlashWindow", "USER32.dll"),
    ("GetCaretPos", "USER32.dll"),
    ("GetClassInfoA", "USER32.dll"),
    ("GetClassLongA", "USER32.dll"),
    ("GetClassNameA", "USER32.dll"),
    ("GetClassWord", "USER32.dll"),
    ("GetCursorPos", "USER32.dll"),
    ("GetDlgCtrlID", "USER32.dll"),
    // S5 (railc W5): USER32 dialog/MDI APIs referenced by OWL DIALOG.CPP
    // (TDialog::DoCreate / DialogFunction / MDI accel translation).
    ("CreateDialogParamA", "USER32.dll"),
    ("IsDialogMessageA", "USER32.dll"),
    ("TranslateMDISysAccel", "USER32.dll"),
    ("GetDlgItem", "USER32.dll"),
    ("GetDlgItemInt", "USER32.dll"),
    ("GetDlgItemTextA", "USER32.dll"),
    ("GetLastActivePopup", "USER32.dll"),
    ("GetMenu", "USER32.dll"),
    ("GetMenuState", "USER32.dll"),
    ("GetNextDlgGroupItem", "USER32.dll"),
    ("GetNextDlgTabItem", "USER32.dll"),
    ("GetParent", "USER32.dll"),
    ("GetPropA", "USER32.dll"),
    ("GetScrollPos", "USER32.dll"),
    ("GetScrollRange", "USER32.dll"),
    ("GetSystemMenu", "USER32.dll"),
    ("GetTopWindow", "USER32.dll"),
    ("GetUpdateRect", "USER32.dll"),
    ("GetWindow", "USER32.dll"),
    ("GetWindowLongA", "USER32.dll"),
    ("GetWindowPlacement", "USER32.dll"),
    ("GetWindowRect", "USER32.dll"),
    ("GetWindowTextA", "USER32.dll"),
    ("GetWindowTextLengthA", "USER32.dll"),
    ("GetWindowThreadProcessId", "USER32.dll"),
    ("GetWindowWord", "USER32.dll"),
    ("HideCaret", "USER32.dll"),
    ("HiliteMenuItem", "USER32.dll"),
    ("InvalidateRgn", "USER32.dll"),
    ("IsChild", "USER32.dll"),
    ("IsDlgButtonChecked", "USER32.dll"),
    ("IsIconic", "USER32.dll"),
    ("IsMenu", "USER32.dll"),
    ("IsWindow", "USER32.dll"),
    ("IsWindowEnabled", "USER32.dll"),
    ("IsWindowVisible", "USER32.dll"),
    ("IsZoomed", "USER32.dll"),
    ("KillTimer", "USER32.dll"),
    ("LoadBitmapA", "USER32.dll"),
    ("LockWindowUpdate", "USER32.dll"),
    ("MapWindowPoints", "USER32.dll"),
    ("MessageBoxExA", "USER32.dll"),
    ("ModifyMenuA", "USER32.dll"),
    ("MoveWindow", "USER32.dll"),
    ("OpenClipboard", "USER32.dll"),
    ("OpenIcon", "USER32.dll"),
    ("PeekMessageA", "USER32.dll"),
    ("PostMessageA", "USER32.dll"),
    ("RedrawWindow", "USER32.dll"),
    ("RegisterHotKey", "USER32.dll"),
    ("RemoveMenu", "USER32.dll"),
    ("RemovePropA", "USER32.dll"),
    ("ScreenToClient", "USER32.dll"),
    ("ScrollWindow", "USER32.dll"),
    ("ScrollWindowEx", "USER32.dll"),
    ("SendDlgItemMessageA", "USER32.dll"),
    ("SendMessageA", "USER32.dll"),
    ("SetActiveWindow", "USER32.dll"),
    ("SetClassLongA", "USER32.dll"),
    ("SetClassWord", "USER32.dll"),
    ("SetClipboardData", "USER32.dll"),
    ("SetClipboardViewer", "USER32.dll"),
    ("SetDlgItemInt", "USER32.dll"),
    ("SetDlgItemTextA", "USER32.dll"),
    ("SetFocus", "USER32.dll"),
    ("SetMenu", "USER32.dll"),
    ("SetPropA", "USER32.dll"),
    ("SetScrollPos", "USER32.dll"),
    ("SetScrollRange", "USER32.dll"),
    ("SetTimer", "USER32.dll"),
    ("SetWindowLongA", "USER32.dll"),
    ("SetWindowPlacement", "USER32.dll"),
    ("SetWindowPos", "USER32.dll"),
    ("SetWindowTextA", "USER32.dll"),
    ("SetWindowWord", "USER32.dll"),
    ("ShowCaret", "USER32.dll"),
    ("ShowCursor", "USER32.dll"),
    ("ShowOwnedPopups", "USER32.dll"),
    ("ShowScrollBar", "USER32.dll"),
    ("UnregisterHotKey", "USER32.dll"),
    ("ValidateRect", "USER32.dll"),
    ("ValidateRgn", "USER32.dll"),
    ("WinHelpA", "USER32.dll"),
    ("WindowFromPoint", "USER32.dll"),
    ("CloseClipboard", "USER32.dll"),
    ("CountClipboardFormats", "USER32.dll"),
    ("DestroyCaret", "USER32.dll"),
    ("EmptyClipboard", "USER32.dll"),
    ("GetActiveWindow", "USER32.dll"),
    ("GetCapture", "USER32.dll"),
    ("GetCaretBlinkTime", "USER32.dll"),
    ("GetClipboardData", "USER32.dll"),
    ("GetClipboardFormatNameA", "USER32.dll"),
    ("GetClipboardOwner", "USER32.dll"),
    ("GetClipboardViewer", "USER32.dll"),
    ("GetDesktopWindow", "USER32.dll"),
    ("GetFocus", "USER32.dll"),
    ("GetOpenClipboardWindow", "USER32.dll"),
    ("GetPriorityClipboardFormat", "USER32.dll"),
    ("GetSysColor", "USER32.dll"),
    ("IsClipboardFormatAvailable", "USER32.dll"),
    ("MessageBeep", "USER32.dll"),
    ("RegisterClipboardFormatA", "USER32.dll"),
    ("SetCaretBlinkTime", "USER32.dll"),
    ("SetCaretPos", "USER32.dll"),
    ("wsprintfA", "USER32.dll"),
    // S6 (G8b — railc W5): GDI32/USER32 API surface OWL library bodies
    // call. Declared `extern "C" WINAPI` in the windows headers; codegen
    // recognises them via `is_win32_import` and emits an IAT import instead
    // of a C++-mangled call. All in EXTENDED_ON_DEMAND ⇒ unused images
    // (the 88 baselines, x64 goldens) stay byte-identical.
    ("AngleArc", "GDI32.dll"),
    ("AppendMenuA", "USER32.dll"),
    ("Arc", "GDI32.dll"),
    ("BeginPath", "GDI32.dll"),
    ("CallWindowProcA", "USER32.dll"),
    ("Chord", "GDI32.dll"),
    ("CloseFigure", "GDI32.dll"),
    ("CreateBrushIndirect", "GDI32.dll"),
    ("CreatePalette", "GDI32.dll"),
    ("CreatePatternBrush", "GDI32.dll"),
    ("DPtoLP", "GDI32.dll"),
    ("DeleteMenu", "USER32.dll"),
    ("DestroyCursor", "USER32.dll"),
    ("DestroyMenu", "USER32.dll"),
    ("DestroyWindow", "USER32.dll"),
    ("DrawFocusRect", "USER32.dll"),
    ("DrawIcon", "USER32.dll"),
    ("EndPath", "GDI32.dll"),
    ("EnumFontFamiliesA", "GDI32.dll"),
    ("EnumFontsA", "GDI32.dll"),
    ("EnumMetaFile", "GDI32.dll"),
    ("EnumObjects", "GDI32.dll"),
    ("EnumThreadWindows", "USER32.dll"),
    ("ExcludeClipRect", "GDI32.dll"),
    ("ExcludeUpdateRgn", "USER32.dll"),
    ("ExtFloodFill", "GDI32.dll"),
    ("FillPath", "GDI32.dll"),
    ("FillRect", "USER32.dll"),
    ("FillRgn", "GDI32.dll"),
    ("FlattenPath", "GDI32.dll"),
    ("FloodFill", "GDI32.dll"),
    ("FrameRect", "USER32.dll"),
    ("FrameRgn", "GDI32.dll"),
    ("FreeLibrary", "KERNEL32.dll"),
    ("GetAspectRatioFilterEx", "GDI32.dll"),
    ("GetBkColor", "GDI32.dll"),
    ("GetBkMode", "GDI32.dll"),
    ("GetBoundsRect", "GDI32.dll"),
    ("GetBrushOrgEx", "GDI32.dll"),
    ("GetCharABCWidthsA", "GDI32.dll"),
    ("GetCharWidthA", "GDI32.dll"),
    ("GetClipBox", "GDI32.dll"),
    ("GetClipRgn", "GDI32.dll"),
    ("GetCurrentObject", "GDI32.dll"),
    ("GetCurrentPositionEx", "GDI32.dll"),
    ("GetDCOrgEx", "GDI32.dll"),
    ("GetDIBits", "GDI32.dll"),
    ("GetDeviceCaps", "GDI32.dll"),
    ("GetFontData", "GDI32.dll"),
    ("GetGlyphOutlineA", "GDI32.dll"),
    ("GetKerningPairsA", "GDI32.dll"),
    ("GetMapMode", "GDI32.dll"),
    ("GetMenuItemCount", "USER32.dll"),
    ("GetMenuItemID", "USER32.dll"),
    ("GetMenuStringA", "USER32.dll"),
    ("GetNearestColor", "GDI32.dll"),
    ("GetOutlineTextMetricsA", "GDI32.dll"),
    ("GetPaletteEntries", "GDI32.dll"),
    ("GetPixel", "GDI32.dll"),
    ("GetPolyFillMode", "GDI32.dll"),
    ("GetROP2", "GDI32.dll"),
    ("GetStretchBltMode", "GDI32.dll"),
    ("GetSubMenu", "USER32.dll"),
    ("GetSystemPaletteEntries", "GDI32.dll"),
    ("GetSystemPaletteUse", "GDI32.dll"),
    ("GetTabbedTextExtentA", "USER32.dll"),
    ("GetTextAlign", "GDI32.dll"),
    ("GetTextCharacterExtra", "GDI32.dll"),
    ("GetTextColor", "GDI32.dll"),
    ("GetTextFaceA", "GDI32.dll"),
    ("GetTextMetricsA", "GDI32.dll"),
    ("GetUpdateRgn", "USER32.dll"),
    ("GetViewportExtEx", "GDI32.dll"),
    ("GetViewportOrgEx", "GDI32.dll"),
    ("GetWindowExtEx", "GDI32.dll"),
    ("GetWindowOrgEx", "GDI32.dll"),
    ("GrayStringA", "USER32.dll"),
    ("InsertMenuA", "USER32.dll"),
    ("IntersectClipRect", "GDI32.dll"),
    ("InvertRect", "USER32.dll"),
    ("InvertRgn", "GDI32.dll"),
    ("LPtoDP", "GDI32.dll"),
    ("MaskBlt", "GDI32.dll"),
    ("ModifyWorldTransform", "GDI32.dll"),
    ("OffsetClipRgn", "GDI32.dll"),
    ("OffsetViewportOrgEx", "GDI32.dll"),
    ("OffsetWindowOrgEx", "GDI32.dll"),
    ("PaintRgn", "GDI32.dll"),
    ("PatBlt", "GDI32.dll"),
    ("PathToRegion", "GDI32.dll"),
    ("Pie", "GDI32.dll"),
    ("PlayMetaFile", "GDI32.dll"),
    ("PlayMetaFileRecord", "GDI32.dll"),
    ("PlgBlt", "GDI32.dll"),
    ("PolyBezier", "GDI32.dll"),
    ("PolyBezierTo", "GDI32.dll"),
    ("PolyDraw", "GDI32.dll"),
    ("PolyPolygon", "GDI32.dll"),
    ("PolyPolyline", "GDI32.dll"),
    ("Polyline", "GDI32.dll"),
    ("PolylineTo", "GDI32.dll"),
    ("PtInRegion", "GDI32.dll"),
    ("PtVisible", "GDI32.dll"),
    ("RealizePalette", "GDI32.dll"),
    ("RectVisible", "GDI32.dll"),
    ("ResetDCA", "GDI32.dll"),
    ("RestoreDC", "GDI32.dll"),
    ("RoundRect", "GDI32.dll"),
    ("SaveDC", "GDI32.dll"),
    ("ScaleViewportExtEx", "GDI32.dll"),
    ("ScaleWindowExtEx", "GDI32.dll"),
    ("ScrollDC", "USER32.dll"),
    ("SelectClipPath", "GDI32.dll"),
    ("SelectClipRgn", "GDI32.dll"),
    ("SelectPalette", "GDI32.dll"),
    ("SetBkMode", "GDI32.dll"),
    ("SetBoundsRect", "GDI32.dll"),
    ("SetBrushOrgEx", "GDI32.dll"),
    ("SetCursor", "USER32.dll"),
    ("SetDIBits", "GDI32.dll"),
    ("SetDIBitsToDevice", "GDI32.dll"),
    ("SetMapMode", "GDI32.dll"),
    ("SetMapperFlags", "GDI32.dll"),
    ("SetMenuItemBitmaps", "USER32.dll"),
    ("SetMiterLimit", "GDI32.dll"),
    ("SetParent", "USER32.dll"),
    ("SetPixel", "GDI32.dll"),
    ("SetPolyFillMode", "GDI32.dll"),
    ("SetROP2", "GDI32.dll"),
    ("SetStretchBltMode", "GDI32.dll"),
    ("SetSystemPaletteUse", "GDI32.dll"),
    ("SetTextCharacterExtra", "GDI32.dll"),
    ("SetTextJustification", "GDI32.dll"),
    ("SetViewportExtEx", "GDI32.dll"),
    ("SetViewportOrgEx", "GDI32.dll"),
    ("SetWindowExtEx", "GDI32.dll"),
    ("SetWindowOrgEx", "GDI32.dll"),
    ("SetWorldTransform", "GDI32.dll"),
    ("StretchDIBits", "GDI32.dll"),
    ("StrokeAndFillPath", "GDI32.dll"),
    ("StrokePath", "GDI32.dll"),
    ("TabbedTextOutA", "USER32.dll"),
    ("TrackPopupMenu", "USER32.dll"),
    ("UpdateColors", "GDI32.dll"),
    ("WidenPath", "GDI32.dll"),
    // G26 (railc W5 closure): direct-call Win32 APIs the OWL framework body
    // references that were not yet in the table — KERNEL32 process/memory
    // primitives (TThread / the memory-block RTL) and USER32 menu/metrics/
    // message helpers (TMenu / TWindow geometry / the message loop). All in
    // EXTENDED_ON_DEMAND below, so any image not calling them is byte-identical.
    ("VirtualAlloc", "KERNEL32.dll"),
    ("VirtualFree", "KERNEL32.dll"),
    ("GetCurrentProcessId", "KERNEL32.dll"),
    ("GetCurrentThreadId", "KERNEL32.dll"),
    ("CreateMenu", "USER32.dll"),
    ("GetSystemMetrics", "USER32.dll"),
    ("PostThreadMessageA", "USER32.dll"),
    ("RegisterWindowMessageA", "USER32.dll"),
    ("WaitMessage", "USER32.dll"),
];

/// S2e: symbols present in [`WIN32_IMPORTS`] that the **x64** (non-pruning)
/// import grouping must NOT emit — they are x86-only and would otherwise be
/// dragged into every KERNEL32-using PE32+ image, breaking the byte-identity
/// stripe. The PE32 path prunes per-symbol and is unaffected by this list.
///
/// `RtlUnwind` is the x86 SEH-unwind primitive (x64 uses `RtlUnwindEx`).
/// Old HELLOWIN.C-era USER32/GDI32 imports used to live here while only the
/// PE32 Petzold sample referenced them. As OWL/RailC reached x64, the live
/// subset (`LoadIconA`, `RegisterClassA`, `GetClientRect`, `DrawTextA`, and
/// `GetStockObject`) moved out of this exclusion list. The broad x64 grouping
/// still avoids unrelated image growth through `EXTENDED_ON_DEMAND` where
/// needed.
const WIN32_IMPORTS_X64_EXCLUDE: &[&str] = &[
    "RtlUnwind",
    // S4.2ag: `LoadIconA` is NO LONGER x64-excluded — the real HELLOAPP OWL
    // sample (x64) loads its frame-window icon via it, so it must reach the
    // USER32 import group on x64. With the grouping still per-DLL-non-pruning
    // on x64, this means every x64 USER32 image now also carries LoadIconA
    // (harmless/unused for the non-OWL GUI tests, whose import goldens are
    // updated to match). Console images (the 88 baselines) reference no
    // USER32 symbol ⇒ no USER32 descriptor ⇒ byte-identical. True per-symbol
    // x64 pruning stays deferred (it would shrink the all-8-KERNEL32 console
    // .idata the 88 baselines pin).
    //
    // S4.2(d): `RegisterClassA` is likewise NO LONGER x64-excluded — the OWL
    // runtime's `TWindow::Create()` now registers its window class through the
    // overridable `GetWindowClass(WNDCLASS&)` hook + the (non-Ex)
    // `RegisterClassA` (the faithful OWL 1.0 idiom: WNDCLASS, not WNDCLASSEX),
    // so every x64 OWL window — HELLOAPP/INSTTEST/CURSAPP and the D5/E/J21
    // fixtures — needs it on x64. Same non-pruning consequence + golden-update
    // discipline as LoadIconA above; console baselines stay byte-identical.
];

/// Whether `name` is a Win32 symbol the compiler can import (it appears in
/// [`WIN32_IMPORTS`]). The single source of truth shared with codegen so the
/// "recognise this name as an import" decision and the symbol→DLL resolution
/// can never disagree (the same single-table discipline `is_builtin`/
/// `libc_ret` use for libc). Codegen still applies the "the TU may define it
/// itself" override guard before routing a call here.
pub(crate) fn is_win32_import(name: &str) -> bool {
    use std::sync::OnceLock;
    // Built once: the linear scan over the ~400-entry table ran per undefined
    // external per link pass. A hashed membership test keeps the single-source-
    // of-truth table but answers in O(1).
    static SET: OnceLock<std::collections::HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| WIN32_IMPORTS.iter().map(|(s, _)| *s).collect())
        .contains(name)
}

/// The DLL whose symbols the entry stub itself needs (`ExitProcess`), so it is
/// always part of the used set even for a program with no `RipRef::Import`.
const STUB_DLL: &str = "KERNEL32.dll";

/// S6: `WIN32_IMPORTS` entries that are emitted ONLY when a TU actually imports
/// them — on BOTH targets (x86 already prunes per-symbol; this list makes the
/// x64 non-pruning grouping prune these specific symbols too). The historical
/// core entries are deliberately ABSENT: their always-emit-on-x64 behaviour is
/// what the pe_imports console/bare goldens + the 88 SipHash baselines lock, so
/// a program that does NOT call an on-demand symbol stays byte-identical, while
/// an OWL app that streams (→ `CreateMutexA` via CLASSLIB `TMutex`) pulls it in.
const EXTENDED_ON_DEMAND: &[&str] = &[
    "CreateMutexA",
    "CloseHandle",
    "WaitForSingleObject",
    "ReleaseMutex",
    // S5 (railc W2/W5): the 5 extra KERNEL32 APIs the RTL/OWL closure references.
    "GetLastError",
    "GetModuleHandleA",
    "GetVersion",
    "LockResource",
    "GetTimeZoneInformation",
    // W2 (railc RTL I/O shim) — file syscalls + TThread exit code.
    "CreateFileA",
    "ReadFile",
    "SetFilePointer",
    "GetExitCodeThread",
    // W2 (railc RTL) — time() wall-clock read (TIME/WIN32/TIME.C).
    "GetLocalTime",
    // W6 (honest closure) — Local* heap family, LoadLibraryA, GetObjectA.
    "LocalHandle",
    "LocalLock",
    "LocalReAlloc",
    "LocalUnlock",
    "LoadLibraryA",
    "GetObjectA",
    // W6 (Bug C layer 1) — UnregisterClassA + the COMDLG32 dialog launchers.
    "UnregisterClassA",
    "FindTextA",
    "ReplaceTextA",
    "ChooseColorA",
    "ChooseFontA",
    // W6 — the KERNEL32 Global* heap family (OWL DIB/clipboard/PRINTDLG).
    "GlobalAlloc",
    "GlobalFree",
    "GlobalLock",
    "GlobalUnlock",
    "GlobalReAlloc",
    "GlobalSize",
    "GlobalHandle",
    // W6 (G48 fallout) — the RTL startup-chain KERNEL32 surface.
    "GetStartupInfoA",
    "GetFileType",
    "SetHandleCount",
    "GetCommandLineA",
    "GetEnvironmentStringsA",
    // RailC Win64 source-slice link: OWL string helpers are live x64 imports.
    // Keep them on-demand so the historical KERNEL32 grouping does not grow for
    // images that do not reference their `__imp_*` symbols.
    "lstrlenA",
    "lstrcmpA",
    "lstrcmpiA",
    // RailC Win64 source-slice link: these HELLOWIN/OWL paint helpers are live
    // x64 imports now. Keep them on-demand so unrelated USER32/GDI32 PE32+
    // images do not grow while object links that reference their `__imp_*`
    // symbols resolve them.
    "GetClientRect",
    "DrawTextA",
    "GetStockObject",
    // S5 (railc W5): the 163 OWL/RTL-inline Win32 APIs — emit per-symbol
    // (both targets) so no x64 image changes (none reference them).
    "AdjustWindowRect",
    "AdjustWindowRectEx",
    "BitBlt",
    "BringWindowToTop",
    "CheckDlgButton",
    "CheckMenuItem",
    "CheckRadioButton",
    "ChildWindowFromPoint",
    "ClientToScreen",
    "CloseClipboard",
    "CombineRgn",
    "CommDlgExtendedError",
    "CopyIcon",
    "CountClipboardFormats",
    "CreateCaret",
    "CreateCompatibleBitmap",
    "CreateCompatibleDC",
    "CreateDiscardableBitmap",
    "CreateFontA",
    "CreateFontIndirectA",
    "CreatePen",
    "CreateRectRgn",
    "CreateSolidBrush",
    "Ctl3dAutoSubclass",
    "Ctl3dRegister",
    "Ctl3dUnregister",
    "DeleteDC",
    "DeleteObject",
    "DestroyCaret",
    "DestroyIcon",
    "DragAcceptFiles",
    "DragFinish",
    "DragQueryFileA",
    "DragQueryPoint",
    "DrawMenuBar",
    "Ellipse",
    "EmptyClipboard",
    "EnableMenuItem",
    "EnableScrollBar",
    "EnableWindow",
    "EnumPropsA",
    "EqualRgn",
    "ExtTextOutA",
    "ExtractIconA",
    "FindResourceA",
    "FlashWindow",
    "FreeResource",
    "GetActiveWindow",
    "GetCapture",
    "GetCaretBlinkTime",
    "GetCaretPos",
    "GetClassInfoA",
    "GetClassLongA",
    "GetClassNameA",
    "GetClassWord",
    "GetClipboardData",
    "GetClipboardFormatNameA",
    "GetClipboardOwner",
    "GetClipboardViewer",
    "GetCursorPos",
    "GetDesktopWindow",
    "GetDlgCtrlID",
    "CreateDialogParamA",
    "IsDialogMessageA",
    "TranslateMDISysAccel",
    "GetDlgItem",
    "GetDlgItemInt",
    "GetDlgItemTextA",
    "GetFocus",
    "GetLastActivePopup",
    "GetMenu",
    "GetMenuState",
    "GetModuleFileNameA",
    "GetNextDlgGroupItem",
    "GetNextDlgTabItem",
    "GetOpenClipboardWindow",
    "GetOpenFileNameA",
    "GetParent",
    "GetPriorityClipboardFormat",
    "GetPrivateProfileIntA",
    "GetPrivateProfileStringA",
    "GetProcAddress",
    "GetPropA",
    "GetScrollPos",
    "GetScrollRange",
    "GetSysColor",
    "GetSystemMenu",
    "GetTextExtentPoint32A",
    "GetTextExtentPointA",
    "GetTopWindow",
    "GetUpdateRect",
    "GetWindow",
    "GetWindowLongA",
    "GetWindowPlacement",
    "GetWindowRect",
    "GetWindowTextA",
    "GetWindowTextLengthA",
    "GetWindowThreadProcessId",
    "GetWindowWord",
    "HideCaret",
    "HiliteMenuItem",
    "InvalidateRgn",
    "IsChild",
    "IsClipboardFormatAvailable",
    "IsDlgButtonChecked",
    "IsIconic",
    "IsMenu",
    "IsWindow",
    "IsWindowEnabled",
    "IsWindowVisible",
    "IsZoomed",
    "KillTimer",
    "LoadBitmapA",
    "LoadResource",
    "LockWindowUpdate",
    "MapWindowPoints",
    "MessageBeep",
    "MessageBoxExA",
    "ModifyMenuA",
    "MoveWindow",
    "OpenClipboard",
    "OpenFile",
    "OpenIcon",
    "PeekMessageA",
    "Polygon",
    "PostMessageA",
    "Rectangle",
    "RedrawWindow",
    "RegisterClipboardFormatA",
    "RegisterHotKey",
    "RemoveMenu",
    "RemovePropA",
    "ScreenToClient",
    "ScrollWindow",
    "ScrollWindowEx",
    "SelectObject",
    "SendDlgItemMessageA",
    "SendMessageA",
    "SetActiveWindow",
    "SetBkColor",
    "SetCaretBlinkTime",
    "SetCaretPos",
    "SetClassLongA",
    "SetClassWord",
    "SetClipboardData",
    "SetClipboardViewer",
    "SetDlgItemInt",
    "SetDlgItemTextA",
    "SetFocus",
    "SetMenu",
    "SetPropA",
    "SetScrollPos",
    "SetScrollRange",
    "SetTextAlign",
    "SetTextColor",
    "SetTimer",
    "SetWindowLongA",
    "SetWindowPlacement",
    "SetWindowPos",
    "SetWindowTextA",
    "SetWindowWord",
    "ShowCaret",
    "ShowCursor",
    "ShowOwnedPopups",
    "ShowScrollBar",
    "SizeofResource",
    "StretchBlt",
    "UnregisterHotKey",
    "ValidateRect",
    "ValidateRgn",
    "WinHelpA",
    "WindowFromPoint",
    "WritePrivateProfileStringA",
    "sndPlaySoundA",
    "wsprintfA",
    // S6 (G8b): the GDI32/USER32 OWL import surface (prune when unused).
    "AngleArc",
    "AppendMenuA",
    "Arc",
    "BeginPath",
    "CallWindowProcA",
    "Chord",
    "CloseFigure",
    "CreateBrushIndirect",
    "CreatePalette",
    "CreatePatternBrush",
    "DPtoLP",
    "DeleteMenu",
    "DestroyCursor",
    "DestroyMenu",
    "DestroyWindow",
    "DrawFocusRect",
    "DrawIcon",
    "EndPath",
    "EnumFontFamiliesA",
    "EnumFontsA",
    "EnumMetaFile",
    "EnumObjects",
    "EnumThreadWindows",
    "ExcludeClipRect",
    "ExcludeUpdateRgn",
    "ExtFloodFill",
    "FillPath",
    "FillRect",
    "FillRgn",
    "FlattenPath",
    "FloodFill",
    "FrameRect",
    "FrameRgn",
    "FreeLibrary",
    "GetAspectRatioFilterEx",
    "GetBkColor",
    "GetBkMode",
    "GetBoundsRect",
    "GetBrushOrgEx",
    "GetCharABCWidthsA",
    "GetCharWidthA",
    "GetClipBox",
    "GetClipRgn",
    "GetCurrentObject",
    "GetCurrentPositionEx",
    "GetDCOrgEx",
    "GetDIBits",
    "GetDeviceCaps",
    "GetFontData",
    "GetGlyphOutlineA",
    "GetKerningPairsA",
    "GetMapMode",
    "GetMenuItemCount",
    "GetMenuItemID",
    "GetMenuStringA",
    "GetNearestColor",
    "GetOutlineTextMetricsA",
    "GetPaletteEntries",
    "GetPixel",
    "GetPolyFillMode",
    "GetROP2",
    "GetStretchBltMode",
    "GetSubMenu",
    "GetSystemPaletteEntries",
    "GetSystemPaletteUse",
    "GetTabbedTextExtentA",
    "GetTextAlign",
    "GetTextCharacterExtra",
    "GetTextColor",
    "GetTextFaceA",
    "GetTextMetricsA",
    "GetUpdateRgn",
    "GetViewportExtEx",
    "GetViewportOrgEx",
    "GetWindowExtEx",
    "GetWindowOrgEx",
    "GrayStringA",
    "InsertMenuA",
    "IntersectClipRect",
    "InvertRect",
    "InvertRgn",
    "LPtoDP",
    "MaskBlt",
    "ModifyWorldTransform",
    "OffsetClipRgn",
    "OffsetViewportOrgEx",
    "OffsetWindowOrgEx",
    "PaintRgn",
    "PatBlt",
    "PathToRegion",
    "Pie",
    "PlayMetaFile",
    "PlayMetaFileRecord",
    "PlgBlt",
    "PolyBezier",
    "PolyBezierTo",
    "PolyDraw",
    "PolyPolygon",
    "PolyPolyline",
    "Polyline",
    "PolylineTo",
    "PtInRegion",
    "PtVisible",
    "RealizePalette",
    "RectVisible",
    "ResetDCA",
    "RestoreDC",
    "RoundRect",
    "SaveDC",
    "ScaleViewportExtEx",
    "ScaleWindowExtEx",
    "ScrollDC",
    "SelectClipPath",
    "SelectClipRgn",
    "SelectPalette",
    "SetBkMode",
    "SetBoundsRect",
    "SetBrushOrgEx",
    "SetCursor",
    "SetDIBits",
    "SetDIBitsToDevice",
    "SetMapMode",
    "SetMapperFlags",
    "SetMenuItemBitmaps",
    "SetMiterLimit",
    "SetParent",
    "SetPixel",
    "SetPolyFillMode",
    "SetROP2",
    "SetStretchBltMode",
    "SetSystemPaletteUse",
    "SetTextCharacterExtra",
    "SetTextJustification",
    "SetViewportExtEx",
    "SetViewportOrgEx",
    "SetWindowExtEx",
    "SetWindowOrgEx",
    "SetWorldTransform",
    "StretchDIBits",
    "StrokeAndFillPath",
    "StrokePath",
    "TabbedTextOutA",
    "TrackPopupMenu",
    "UpdateColors",
    "WidenPath",
    // G26: per-symbol prune for the new direct-call Win32 APIs (both targets) —
    // no image not calling them changes.
    "VirtualAlloc",
    "VirtualFree",
    "GetCurrentProcessId",
    "GetCurrentThreadId",
    "CreateMenu",
    "GetSystemMetrics",
    "PostThreadMessageA",
    "RegisterWindowMessageA",
    "WaitMessage",
];

/// The `.idata` section image plus the RVAs needed to reference it. Layout
/// (relative to its base RVA): `descriptors | ILT | IAT | hint/name | dll`.
struct Idata {
    image: Vec<u8>,
    iat_rva: u32,
    iat_size: u32,
    import_dir_rva: u32,
    import_dir_size: u32,
    /// Import name -> RVA of its IAT slot (the cell `call [rip+d]` targets).
    iat_slot: HashMap<String, u32>,
}

/// Deterministically scan the module's `RipRef::Import`s and validate every
/// imported symbol is known. Returns the set of DLLs actually needed, in
/// `WIN32_IMPORTS` table order (so emitted bytes never depend on HashMap
/// iteration). `KERNEL32.dll` is always included — the entry stub itself calls
/// `ExitProcess` (`STUB_DLL`) even for a program with no `RipRef::Import`. An
/// imported symbol absent from `WIN32_IMPORTS` is a hard error (never silently
/// wrong). For C1a this is wired and validated but the descriptor stays
/// KERNEL32-only; C1b consumes the per-DLL grouping for multi-descriptor
/// `.idata`.
fn used_dlls(module: &Module) -> Result<Vec<&'static str>, CodegenError> {
    for f in &module.funcs {
        for r in &f.riprefs {
            if let crate::codegen::RipRef::Import(name) = &r.target
                && !WIN32_IMPORTS.iter().any(|(s, _)| s == name)
            {
                return Err(CodegenError(format!("import '{name}' has no known DLL")));
            }
        }
    }
    // DLL order = first appearance in the table (deterministic). KERNEL32 is
    // always present via the stub, so for C1a (KERNEL32-only table) this is
    // exactly `["KERNEL32.dll"]` — the byte-identical console path.
    let mut dlls: Vec<&'static str> = Vec::new();
    for (_, dll) in WIN32_IMPORTS {
        if (*dll == STUB_DLL || used_symbol(module, dll)) && !dlls.contains(dll) {
            dlls.push(dll);
        }
    }
    Ok(dlls)
}

/// Whether any `RipRef::Import` in the module names a symbol that the table
/// maps to `dll`. Deterministic; used only to decide DLL membership.
fn used_symbol(module: &Module, dll: &str) -> bool {
    module.funcs.iter().any(|f| {
        f.riprefs.iter().any(|r| {
            if let crate::codegen::RipRef::Import(name) = &r.target {
                WIN32_IMPORTS.iter().any(|(s, d)| s == name && *d == dll)
            } else {
                false
            }
        })
    })
}

/// Whether the module imports `name` specifically (any `RipRef::Import(name)`).
/// Per-symbol analogue of [`used_symbol`]; gates [`EXTENDED_ON_DEMAND`] entries
/// in the Module-driven [`grouped_imports`] path (the object-link path uses its
/// own `used` set).
fn used_symbol_named(module: &Module, name: &str) -> bool {
    module.funcs.iter().any(|f| {
        f.riprefs
            .iter()
            .any(|r| matches!(&r.target, crate::codegen::RipRef::Import(n) if n == name))
    })
}

/// One DLL's contribution to `.idata`: its name and the table-ordered symbols
/// imported from it. Built in `WIN32_IMPORTS` order (across DLLs and within a
/// DLL) so the emitted bytes never depend on HashMap iteration.
struct DllImports<'a> {
    name: &'a str,
    symbols: Vec<&'a str>,
}

/// Group the used DLLs (already in deterministic table order) with the full
/// table-ordered symbol set for each. Per-symbol pruning is deliberately *not*
/// done here (deferred optimization): every `WIN32_IMPORTS` symbol whose DLL is
/// in the used set is emitted. For the KERNEL32-only table this yields exactly
/// one group of the historical six symbols ⇒ the console `.idata` is
/// byte-identical.
fn grouped_imports(module: &Module) -> Result<Vec<DllImports<'static>>, CodegenError> {
    let dlls = used_dlls(module)?;
    Ok(dlls
        .into_iter()
        .map(|dll| DllImports {
            name: dll,
            symbols: WIN32_IMPORTS
                .iter()
                .filter(|(_, d)| *d == dll)
                // S2e: x86-only symbols (e.g. `RtlUnwind`) never appear in a
                // PE32+ image — excluding them here keeps the KERNEL32 golden
                // + 88 SipHash baselines byte-identical.
                .filter(|(s, _)| !WIN32_IMPORTS_X64_EXCLUDE.contains(s))
                // S6: EXTENDED_ON_DEMAND imports emitted only when referenced
                // (mirrors the object-link path), so non-callers stay byte-
                // identical on this non-pruning x64 Module path too.
                .filter(|(s, _)| !EXTENDED_ON_DEMAND.contains(s) || used_symbol_named(module, s))
                .map(|(s, _)| *s)
                .collect(),
        })
        .collect())
}

/// Serialize the `.idata` section for an already-resolved, deterministically
/// ordered set of DLL groups (the pure layout core; `build_idata` is the
/// module-driven wrapper, exactly as `func_offsets` mirrors `build_text`'s
/// cursor). Splitting this out lets the multi-DLL layout be tested directly
/// without populating `WIN32_IMPORTS` with a second DLL (USER32 is C3, not
/// C1b). With `groups == [KERNEL32(six)]` every byte is identical to the
/// pre-C1b single-descriptor layout (the C1a golden lock proves this).
fn emit_idata(groups: &[DllImports], idata_rva: u32) -> Idata {
    // Historical PE32+ layout uses 8-byte thunks. The width-parameterised
    // version below is shared with the PE32 (x86) writer via 4-byte thunks.
    emit_idata_with_thunk(groups, idata_rva, 8)
}

/// Width-parameterised variant of `emit_idata`. `thunk_bytes` is 8 for
/// PE32+ (x64) and 4 for PE32 (x86); it controls the ILT/IAT thunk size
/// and the IAT slot stride. All other layout is identical.
fn emit_idata_with_thunk(groups: &[DllImports], idata_rva: u32, thunk_bytes: u32) -> Idata {
    debug_assert!(thunk_bytes == 4 || thunk_bytes == 8);
    // Layout: `descriptors | per-DLL ILT | per-DLL IAT | hint/name | dll names`.
    // Each DLL gets its own null-terminated ILT and IAT sub-array; hint/name
    // entries and DLL-name strings are emitted in group then table order. For
    // k == 1 this collapses to exactly the C1a layout (desc_size == 2*20, one
    // ILT/IAT of n+1 thunks, the hint/names then a single dll string).
    let k = groups.len() as u32;
    let desc_off = 0u32;
    let desc_size = (k + 1) * 20; // k descriptors + null terminator

    // Per-DLL ILT/IAT sub-array offsets (each `symbols.len() + 1` thunks).
    let mut ilt_off = Vec::with_capacity(groups.len());
    let mut cur = desc_off + desc_size;
    for g in groups {
        ilt_off.push(cur);
        cur += (g.symbols.len() as u32 + 1) * thunk_bytes;
    }
    let iat_block_off = cur;
    let mut iat_off = Vec::with_capacity(groups.len());
    for g in groups {
        iat_off.push(cur);
        cur += (g.symbols.len() as u32 + 1) * thunk_bytes;
    }
    let iat_size = cur - iat_block_off;

    // Hint/name entries, group then table order (hint u16 + name + NUL,
    // padded to an even length so thunks stay 2-aligned).
    let mut hn_off: Vec<Vec<u32>> = Vec::with_capacity(groups.len());
    for g in groups {
        let mut offs = Vec::with_capacity(g.symbols.len());
        for name in &g.symbols {
            offs.push(cur);
            let mut len = 2 + name.len() as u32 + 1;
            if !len.is_multiple_of(2) {
                len += 1;
            }
            cur += len;
        }
        hn_off.push(offs);
    }
    // DLL name strings, in group order.
    let mut dll_off = Vec::with_capacity(groups.len());
    for g in groups {
        dll_off.push(cur);
        cur += g.name.len() as u32 + 1;
    }

    let rva = |off: u32| idata_rva + off;
    let mut b = Buf::new();

    // One IMAGE_IMPORT_DESCRIPTOR per DLL (table order) + null terminator.
    for (gi, _g) in groups.iter().enumerate() {
        b.u32(rva(ilt_off[gi])); // OriginalFirstThunk
        b.u32(0); // TimeDateStamp
        b.u32(0); // ForwarderChain
        b.u32(rva(dll_off[gi])); // Name
        b.u32(rva(iat_off[gi])); // FirstThunk (IAT)
    }
    for _ in 0..5 {
        b.u32(0); // null descriptor
    }
    // Per-DLL ILTs: by-name thunks (high bit == 0), each null-terminated.
    // PE32+ uses 8-byte thunks (bit 63 = 0); PE32 uses 4-byte thunks
    // (bit 31 = 0). In both cases the thunk value is the RVA of the
    // hint/name entry.
    for (gi, _g) in groups.iter().enumerate() {
        for &h in &hn_off[gi] {
            if thunk_bytes == 8 {
                b.u64(u64::from(rva(h)));
            } else {
                b.u32(rva(h));
            }
        }
        if thunk_bytes == 8 {
            b.u64(0);
        } else {
            b.u32(0);
        }
    }
    // Per-DLL IATs: identical by-name thunks, each null-terminated.
    for (gi, _g) in groups.iter().enumerate() {
        for &h in &hn_off[gi] {
            if thunk_bytes == 8 {
                b.u64(u64::from(rva(h)));
            } else {
                b.u32(rva(h));
            }
        }
        if thunk_bytes == 8 {
            b.u64(0);
        } else {
            b.u32(0);
        }
    }
    // Hint/Name entries (group then table order).
    for (gi, g) in groups.iter().enumerate() {
        for (i, name) in g.symbols.iter().enumerate() {
            debug_assert_eq!(b.len() as u32, hn_off[gi][i]);
            b.u16(0); // hint
            b.bytes(name.as_bytes());
            b.u8(0);
            if !b.len().is_multiple_of(2) {
                b.u8(0);
            }
        }
    }
    // DLL name strings (group order).
    for (gi, g) in groups.iter().enumerate() {
        debug_assert_eq!(b.len() as u32, dll_off[gi]);
        b.bytes(g.name.as_bytes());
        b.u8(0);
    }

    // Every used symbol -> its IAT-slot RVA (unchanged contract: build_text
    // resolves `RipRef::Import` through this). Slots are distinct: each DLL's
    // IAT sub-array is a disjoint contiguous block.
    let mut iat_slot = HashMap::new();
    for (gi, g) in groups.iter().enumerate() {
        for (i, name) in g.symbols.iter().enumerate() {
            iat_slot.insert(
                (*name).to_string(),
                rva(iat_off[gi]) + i as u32 * thunk_bytes,
            );
        }
    }

    Idata {
        image: b.0,
        iat_rva: rva(iat_block_off),
        iat_size,
        import_dir_rva: rva(desc_off),
        import_dir_size: desc_size,
        iat_slot,
    }
}

/// Module-driven `.idata`: scan + validate the used imports (hard error on an
/// unknown symbol), group one entry per used DLL in deterministic
/// `WIN32_IMPORTS` order, then serialize. With today's KERNEL32-only table the
/// group set is exactly one KERNEL32 group of the historical six symbols, so
/// `emit_idata` produces a byte-identical single-descriptor `.idata` (the C1a
/// golden lock proves this).
fn build_idata(module: &Module, idata_rva: u32) -> Result<Idata, CodegenError> {
    let groups = grouped_imports(module)?;
    Ok(emit_idata(&groups, idata_rva))
}

/// Build the `.rdata` image (all string literals, each NUL-terminated) and,
/// for each function (in module order), the *offset within `.rdata`* of each
/// of its strings. The caller rebases these by the section's base RVA once
/// the layout is known.
fn build_rdata(module: &Module) -> (Vec<u8>, Vec<Vec<u32>>) {
    let mut image = Vec::new();
    let mut per_fn = Vec::with_capacity(module.funcs.len());
    for f in &module.funcs {
        let mut offs = Vec::with_capacity(f.strings.len());
        for s in &f.strings {
            offs.push(image.len() as u32);
            image.extend_from_slice(s);
            image.push(0);
        }
        per_fn.push(offs);
    }
    (image, per_fn)
}

/// Build the writable `.data` image (file-scope globals) and each global's
/// *offset within `.data`*. Pointer-to-string globals get their string
/// appended to `rdata` and their slot filled with its absolute address
/// (valid: fixed `ImageBase`, and `rdata_rva` is pinned before this appends).
fn build_data(module: &Module, rdata: &mut Vec<u8>, rdata_rva: u32) -> (Vec<u8>, Vec<u32>) {
    let mut image = Vec::new();
    let mut offs = Vec::with_capacity(module.globals.len());
    for g in &module.globals {
        while image.len() % 8 != 0 {
            image.push(0);
        }
        offs.push(image.len() as u32);
        if let Some(s) = &g.ptr_str {
            let str_rva = rdata_rva + rdata.len() as u32;
            rdata.extend_from_slice(s);
            let abs = IMAGE_BASE + str_rva as u64;
            image.extend_from_slice(&abs.to_le_bytes());
        } else {
            image.extend_from_slice(&g.bytes);
        }
    }
    (image, offs)
}

/// Function text offsets (mirrors the cursor loop in `build_text`; offsets
/// depend only on code lengths, never on relocations — safe to precompute so
/// vtable slots can bake absolute function addresses before `.text` exists).
fn func_offsets(module: &Module) -> Result<HashMap<&str, usize>, CodegenError> {
    let mut offsets = HashMap::new();
    let mut cursor = stub_len(module.entry);
    for f in &module.funcs {
        if offsets.insert(f.name.as_str(), cursor).is_some() {
            return Err(CodegenError(format!("duplicate function '{}'", f.name)));
        }
        cursor += f.code.len();
    }
    Ok(offsets)
}

/// Append each polymorphic class's vtable to `.rdata` (read-only). Slot `i`
/// holds the absolute address of its function — bakeable because `ImageBase`
/// is fixed (the same trick as `ptr_str`). A pure slot (empty sym) is 0 and
/// is provably never dispatched (an abstract class cannot be instantiated).
/// Returns the vtable RVA per record id (0 ⇒ that record has no vtable).
fn build_vtables(
    module: &Module,
    rdata: &mut Vec<u8>,
    rdata_rva: u32,
    text_rva: u32,
    offsets: &HashMap<&str, usize>,
) -> Result<Vec<u32>, CodegenError> {
    let mut rvas = vec![0u32; module.record_count];
    let mut base_link_offsets: Vec<Option<usize>> = Vec::with_capacity(module.vtables.len());
    for vt in &module.vtables {
        while !rdata.len().is_multiple_of(8) {
            rdata.push(0);
        }
        // Keep the two-word RTTI prefix on every vtable. The vtable symbol
        // still points at the first slot; the prefix makes weak-folded vtables
        // ABI-compatible across TUs regardless of which TU uses dynamic_cast.
        rdata.extend_from_slice(&(vt.this_adjust as i64).to_le_bytes());
        base_link_offsets.push(Some(rdata.len()));
        rdata.extend_from_slice(&0u64.to_le_bytes());
        rvas[vt.id] = rdata_rva + rdata.len() as u32;
        for sym in &vt.slots {
            let abs: u64 = if sym.is_empty() {
                0
            } else {
                let off = *offsets.get(sym.as_str()).ok_or_else(|| {
                    CodegenError(format!(
                        "vtable slot '{sym}' refers to an undefined function"
                    ))
                })?;
                IMAGE_BASE + text_rva as u64 + off as u64
            };
            rdata.extend_from_slice(&abs.to_le_bytes());
        }
    }
    for (vt, base_link_off) in module.vtables.iter().zip(base_link_offsets) {
        if let (Some(base_id), Some(off)) = (vt.base_id, base_link_off)
            && let Some(base_rva) = rvas.get(base_id).copied().filter(|r| *r != 0)
        {
            let abs = IMAGE_BASE + base_rva as u64;
            rdata[off..off + 8].copy_from_slice(&abs.to_le_bytes());
        }
    }
    Ok(rvas)
}

/// Phase H4b: append the per-polymorphic-class type-info table to
/// `.rdata` so the personality function can walk the class hierarchy
/// (derived → base) when matching a class catch. Each entry is two
/// `u32`s:
///   `class_rva  base_rva`
/// where `base_rva == 0` marks a root class. Emitted in `Module.typeinfo`
/// declaration order; the personality function does a linear scan
/// (modules carry tens of classes at most, so binary search is overkill).
///
/// Returns `(rva, count)`. Both are `0` when no entries are emitted
/// (the int-only / non-class-throwing path): the personality function
/// short-circuits the walk on `tyinf_count == 0`. Polymorphic records
/// without a registered base record (`Record::base == None`) write
/// `0` for the base_rva field.
fn build_typeinfo(
    module: &Module,
    rdata: &mut Vec<u8>,
    rdata_rva: u32,
    vtable_rvas: &[u32],
) -> Result<(u32, u32), CodegenError> {
    if module.typeinfo.is_empty() {
        return Ok((0, 0));
    }
    // 4-byte align (each entry is two u32 — natural alignment).
    while !rdata.len().is_multiple_of(4) {
        rdata.push(0);
    }
    let base_rva = rdata_rva + rdata.len() as u32;
    let count = module.typeinfo.len() as u32;
    for entry in &module.typeinfo {
        let class_rva = *vtable_rvas
            .get(entry.class_record_id)
            .filter(|&&r| r != 0)
            .ok_or_else(|| {
                CodegenError(format!(
                    "typeinfo: record {} has no vtable RVA (must be \
                 polymorphic)",
                    entry.class_record_id,
                ))
            })?;
        let base_rva_entry = match entry.base_record_id {
            None => 0,
            Some(id) => *vtable_rvas.get(id).filter(|&&r| r != 0).unwrap_or(&0),
        };
        rdata.extend_from_slice(&class_rva.to_le_bytes());
        rdata.extend_from_slice(&base_rva_entry.to_le_bytes());
    }
    Ok((base_rva, count))
}

/// Link the module into a `.text` image: an entry stub followed by every
/// function, with the stub's relative operands and all intra-unit `call`
/// displacements resolved. The console (`main`) entry stub is:
/// ```text
///   00: 48 83 EC 28          sub rsp, 0x28
///   04: E8 <rel32>           call main
///   09: 89 C1                mov ecx, eax
///   0B: FF 15 <disp32>       call qword ptr [rip+disp]   ; ExitProcess
///   11: F4                   hlt                          ; unreachable
/// ```
const STUB_LEN: usize = 0x12;

/// x86 console stub length (PE32). Sequence:
///   `E8 <rel32>`  call main         (5 bytes)
///   `50`          push eax          (1 byte) — eax = return value
///   `FF 15 <addr32>` call [ExitProcess]  (6 bytes)
///   `F4`          hlt               (1 byte)
/// Total: 13 bytes. cdecl convention: caller pushes args right-to-left,
/// no shadow space; arg = main's return value in EAX.
const STUB_LEN_X86: usize = 13;

/// x86 GUI stub length (PE32). The minimal `WinMainCRTStartup` for i386.
/// Sequence (args pushed right-to-left so WinMain sees hInstance, hPrev,
/// lpCmdLine, nCmdShow):
///   `6A 01`       push 1   — nCmdShow = SW_SHOWNORMAL (NOT 0/SW_HIDE!)  (2)
///   `6A 00`       push 0   — lpCmdLine = NULL                          (2)
///   `6A 00`       push 0   — hPrevInstance = NULL                      (2)
///   `68 <imm32>`  push ImageBase — hInstance = module base            (5)
///   `E8 <rel32>`  call WinMain                                         (5)
///   `83 C4 10`    add esp, 16   — reclaim the pushed args             (3)
///   `50`          push eax      — WinMain's return → ExitProcess       (1)
///   `FF 15 <addr32>` call [ExitProcess]                               (6)
///   `F4`          hlt                                                  (1)
/// Total: 27 bytes. Two values are LOAD-BEARING for a real OWL app (railc):
///   * nCmdShow MUST be >=1 — OWL `TApplication::Run` does
///     `MainWindow->Show(nCmdShow)`, so 0 (SW_HIDE) hides the main window.
///   * hInstance MUST be the module handle — railc's WinMain passes it to
///     Ctl3dRegister and stores it in TApplication for every EXE-bound
///     resource load (LoadIcon/LoadString/LoadBitmap/FindResource). The PE
///     is RELOCS_STRIPPED at the fixed ImageBase, so `push IMAGE_BASE_PE32`
///     == GetModuleHandle(NULL) at runtime — no GetModuleHandleA import.
///
/// WinMain is actually `__stdcall` (`ret 0x10`); the `add esp,16` is then
/// redundant but harmless (ExitProcess never returns, so the post-call esp
/// balance is never observed).
const GUI_STUB_LEN_X86: usize = 27;

/// The GUI (`WinMain`) entry stub (Phase C / C2). Synthesises the minimal
/// `WinMainCRTStartup`: it loads the four `WinMain` arguments per the Win64
/// ABI then tail-calls `WinMain` and exits with its return value. `hInstance`
/// is `IMAGE_BASE` baked as a 64-bit immediate — the EXE's module handle *is*
/// its image base, and `ImageBase` is fixed in this writer (no ASLR, no
/// `.reloc`), the same fact `ptr_str`/vtables already exploit; this avoids a
/// `GetModuleHandleA` import so `.idata` stays byte-identical for GUI too.
/// `hPrevInstance`/`lpCmdLine` are NULL (real argv is deferred per the HLD);
/// `nCmdShow` is `SW_SHOWNORMAL` (1). Stack discipline is identical to the
/// console stub (`sub rsp,0x28` — 32-byte shadow + the 8 that re-aligns RSP
/// to 16 at the callee after the `call` pushes the return address).
/// ```text
///   00: 48 83 EC 28          sub rsp, 0x28
///   04: 48 B9 <imm64>        mov rcx, IMAGE_BASE          ; hInstance
///   0E: 48 31 D2             xor rdx, rdx                 ; hPrevInstance=0
///   11: 4D 31 C0             xor r8, r8                   ; lpCmdLine=NULL
///   14: 41 B9 01 00 00 00    mov r9d, 1                   ; nCmdShow=SW_SHOWNORMAL
///   1A: E8 <rel32>           call WinMain
///   1F: 89 C1                mov ecx, eax
///   21: FF 15 <disp32>       call qword ptr [rip+disp]    ; ExitProcess
///   27: F4                   hlt                          ; unreachable
/// ```
const GUI_STUB_LEN: usize = 0x28;

/// The selected entry-stub length. `ConsoleMain` is the literal historical
/// `STUB_LEN` (so every console program is byte-identical); `GuiWinMain` is
/// the larger `GUI_STUB_LEN`. Used by the `.text` vsize pre-pass,
/// `func_offsets` and `build_text` so all three agree (the always-on
/// size-divergence hard error in `write_pe` fails loudly if they ever do not).
fn stub_len(entry: crate::codegen::Entry) -> usize {
    match entry {
        crate::codegen::Entry::ConsoleMain => STUB_LEN,
        crate::codegen::Entry::GuiWinMain => GUI_STUB_LEN,
        // S4.2s: rejected by `write_pe_with_rsrc` before any PE emission.
        crate::codegen::Entry::None => 0,
    }
}

fn build_text(
    module: &Module,
    idata: &Idata,
    str_rvas: &[Vec<u32>],
    data_rvas: &[u32],
    vtable_rvas: &[u32],
    text_rva: u32,
) -> Result<Vec<u8>, CodegenError> {
    // Lay functions out after the stub and record each one's text offset.
    let mut offsets: HashMap<&str, usize> = HashMap::new();
    let mut cursor = stub_len(module.entry);
    for f in &module.funcs {
        if offsets.insert(f.name.as_str(), cursor).is_some() {
            return Err(CodegenError(format!("duplicate function '{}'", f.name)));
        }
        cursor += f.code.len();
    }
    let exit_rva = idata.iat_slot["ExitProcess"];

    let mut t = Vec::with_capacity(cursor);
    // --- entry stub (selected by entry mode; console path byte-identical) ---
    match module.entry {
        crate::codegen::Entry::ConsoleMain => {
            let main_off = *offsets
                .get("main")
                .ok_or_else(|| CodegenError("no 'main' function defined".into()))?;
            t.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp,0x28
            t.push(0xE8);
            let call_rel = main_off as i64 - 0x09; // next insn at text 0x09
            t.extend_from_slice(&(call_rel as i32).to_le_bytes()); // call main
            t.extend_from_slice(&[0x89, 0xC1]); // mov ecx,eax
            t.extend_from_slice(&[0xFF, 0x15]);
            let disp = exit_rva as i64 - (text_rva as i64 + 0x11); // RIP=next
            t.extend_from_slice(&(disp as i32).to_le_bytes()); // call [rip+d]
            t.push(0xF4); // hlt
            debug_assert_eq!(t.len(), STUB_LEN);
        }
        crate::codegen::Entry::GuiWinMain => {
            let wm_off = *offsets
                .get("WinMain")
                .ok_or_else(|| CodegenError("no 'WinMain' function defined".into()))?;
            t.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp,0x28
            // hInstance = IMAGE_BASE (module handle == image base; fixed).
            t.extend_from_slice(&[0x48, 0xB9]); // mov rcx, imm64
            t.extend_from_slice(&IMAGE_BASE.to_le_bytes());
            t.extend_from_slice(&[0x48, 0x31, 0xD2]); // xor rdx,rdx (hPrev=0)
            t.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8,r8 (lpCmdLine=0)
            // nCmdShow = SW_SHOWNORMAL (1); r9d zero-extends into r9.
            t.extend_from_slice(&[0x41, 0xB9, 0x01, 0x00, 0x00, 0x00]); // mov r9d,1
            t.push(0xE8);
            let call_rel = wm_off as i64 - 0x1F; // next insn at text 0x1F
            t.extend_from_slice(&(call_rel as i32).to_le_bytes()); // call WinMain
            t.extend_from_slice(&[0x89, 0xC1]); // mov ecx,eax
            t.extend_from_slice(&[0xFF, 0x15]);
            let disp = exit_rva as i64 - (text_rva as i64 + 0x27); // RIP=next
            t.extend_from_slice(&(disp as i32).to_le_bytes()); // call [rip+d]
            t.push(0xF4); // hlt
            debug_assert_eq!(t.len(), GUI_STUB_LEN);
        }
        // S4.2s: rejected by `write_pe_with_rsrc` before any PE emission.
        crate::codegen::Entry::None => {}
    }

    // --- function bodies, with all relocations resolved ---
    for (fi, f) in module.funcs.iter().enumerate() {
        let base = t.len();
        t.extend_from_slice(&f.code);

        // `E8` relative calls to other unit functions.
        for cs in &f.calls {
            let target = *offsets.get(cs.callee.as_str()).ok_or_else(|| {
                // J-8b (tick 74): prefix the diagnostic with the call's
                // source position when one was recorded by codegen — the
                // user sees "<line>:<col>: call to undefined function ..."
                // instead of having to grep for the name.
                let msg = format!("call to undefined function '{}'", cs.callee);
                if cs.loc.is_synthetic() {
                    CodegenError(msg)
                } else {
                    CodegenError(format!("{}:{}: {}", cs.loc.line, cs.loc.col, msg))
                }
            })?;
            let site = base + cs.at;
            let rel = target as i64 - (site as i64 + 4);
            t[site..site + 4].copy_from_slice(&(rel as i32).to_le_bytes());
        }

        // RIP-relative refs to imports (IAT) and string literals (.rdata).
        for r in &f.riprefs {
            let target_rva = match &r.target {
                crate::codegen::RipRef::Import(name) => *idata
                    .iat_slot
                    .get(name.as_str())
                    .ok_or_else(|| CodegenError(format!("unknown import '{name}'")))?,
                crate::codegen::RipRef::Str(idx) => str_rvas[fi][*idx],
                crate::codegen::RipRef::Data(idx) => *data_rvas
                    .get(*idx)
                    .ok_or_else(|| CodegenError("global reference out of range".into()))?,
                crate::codegen::RipRef::Func(name) => {
                    let off = *offsets.get(name.as_str()).ok_or_else(|| {
                        CodegenError(format!("address of undefined function '{name}'"))
                    })?;
                    text_rva + off as u32
                }
                crate::codegen::RipRef::Vtable(id) => {
                    *vtable_rvas.get(*id).filter(|&&r| r != 0).ok_or_else(|| {
                        CodegenError(format!("vtable for record {id} was not emitted"))
                    })?
                }
            };
            let site = base + r.at;
            let next_rva = text_rva as i64 + site as i64 + 4;
            let disp = target_rva as i64 - next_rva;
            t[site..site + 4].copy_from_slice(&(disp as i32).to_le_bytes());
        }
    }
    Ok(t)
}

/// Phase H4a: whether the module needs Win64 SEH plumbing
/// (`.pdata` + `.xdata`). True iff at least one user function carries a
/// `try` scope (the synthesised personality function added by
/// `compile_module` itself carries none). Programs without `try` skip
/// `.pdata` + `.xdata` emission, so the `.exe` is structurally identical
/// in shape to a pre-H4a build except for the dormant `RaiseException`
/// and `RtlUnwindEx` entries in `.idata` (the `pe_imports` golden was
/// re-blessed for that — the only IAT shift, byte-for-byte).
fn needs_seh(module: &Module) -> bool {
    module.funcs.iter().any(|f| !f.try_scopes.is_empty())
}

/// Phase H4a: layout invariant for a Win64 mdbcc prologue. EVERY function
/// `Gen::run` emits begins with the literal three instructions
/// `push rbp; mov rbp,rsp; sub rsp, imm32`. The UNWIND_INFO opcodes below
/// describe exactly that shape; any future codegen change to the prologue
/// MUST update these constants in lockstep (and the size pre-pass check
/// would catch the byte-count drift first anyway).
///
/// Layout (offsets are the CodeOffset values the unwind opcodes carry —
/// they are the byte after the instruction that performed the action):
/// ```text
///   00..01:  push rbp        — 1-byte opcode 0x55
///   01..04:  mov rbp, rsp    — 3-byte REX.W mov (does NOT shrink rsp)
///   04..0B:  sub rsp, imm32  — 7-byte REX.W sub-with-imm32
///   0B:      <function body begins>
/// ```
///
/// `mov rbp, rsp` does not move the stack pointer ⇒ no UNWIND_CODE entry
/// is recorded for it (the unwinder's rsp-relative recovery is what we
/// rely on, NOT a SET_FPREG frame pointer — see the comment block on
/// `build_xdata_unwind_info`). The two opcodes recorded are:
///
/// * `UWOP_ALLOC_LARGE/SMALL` at CodeOffset 0x0B (just after `sub rsp`),
/// * `UWOP_PUSH_NONVOL` rbp at CodeOffset 0x01 (just after `push rbp`).
///
/// Listed in DESCENDING CodeOffset order, as Win64 requires (the unwinder
/// iterates them as it reverses the prologue).
const MDBCC_PROLOG_SIZE: u8 = 0x0B;
const MDBCC_PROLOG_PUSH_RBP_OFFSET: u8 = 0x01;
const MDBCC_PROLOG_SUB_RSP_OFFSET: u8 = 0x0B;
const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_OPINFO_RBP: u8 = 5; // register encoding 5 == rbp
const UNW_FLAG_EHANDLER: u8 = 1;

/// Recover the prologue's `sub rsp, imm32` immediate from the emitted
/// function bytes. The mdbcc prologue is FIXED — 11 bytes, identical
/// shape across every function (the size pre-pass in `write_pe` already
/// asserts each function reports the right vsize). The unwind opcodes
/// must match this allocation exactly: if codegen ever changes the
/// prologue shape, this fn picks up the new value automatically;
/// `read_prolog_alloc` is the single source of truth for the value the
/// unwinder will see.
///
/// Returns the byte count `sub rsp` removed (codegen sets it to the
/// `Gen.frame` field after the body has been emitted). Bytes are
/// `48 81 EC ll ll ll ll`; the imm32 is little-endian starting at
/// offset 4 of the prologue.
fn read_prolog_alloc(code: &[u8]) -> Result<u32, CodegenError> {
    if code.len() < MDBCC_PROLOG_SIZE as usize {
        return Err(CodegenError(
            "internal error: function code shorter than the mdbcc \
             prologue (Phase H4a unwind info cannot describe it)"
                .into(),
        ));
    }
    // Validate the literal prologue bytes — fail-loud rather than emit
    // an UNWIND_INFO that lies about the prologue shape (the #1 cause
    // of STATUS_BAD_FUNCTION_TABLE per the HLD risk register).
    if code[0] != 0x55 || code[1..4] != [0x48, 0x89, 0xE5] || code[4..7] != [0x48, 0x81, 0xEC] {
        return Err(CodegenError(
            "internal error: function prologue does not match the \
             expected `push rbp; mov rbp, rsp; sub rsp, imm32` \
             shape (Phase H4a UNWIND_INFO requires the historical \
             mdbcc prologue)"
                .into(),
        ));
    }
    Ok(u32::from_le_bytes(code[7..11].try_into().unwrap()))
}

fn is_unwindless_thunk(f: &CompiledFn) -> bool {
    f.name.starts_with("$thunk$")
}

/// Phase H4a: build the `.pdata` section image (an array of
/// `RUNTIME_FUNCTION` structs, 12 bytes each).
///
/// One entry per unwindable function in the module (the OS expects the table
/// to cover frame-using functions, not leaf tail-jump thunks).
/// Entries are sorted ascending by `BeginAddress` — same order as
/// `func_offsets` produces, which is module-declaration order, but the
/// PE writer iterates `module.funcs` linearly so sort is implicit.
///
/// Each entry points to that function's UNWIND_INFO in `.xdata` via
/// `UnwindInfoAddress`. The synthetic personality function (the last
/// element of `module.funcs` when SEH is active) is NOT skipped — the
/// OS must be able to unwind through it too, even though its body is
/// a leaf with no frame and no own scope table.
fn build_pdata(
    module: &Module,
    text_rva: u32,
    xdata_rva: u32,
    xdata_offsets: &[Option<u32>],
) -> Result<Vec<u8>, CodegenError> {
    let mut b = Buf::new();
    let mut cursor = stub_len(module.entry) as u32;
    for (i, f) in module.funcs.iter().enumerate() {
        let Some(xdata_offset) = xdata_offsets[i] else {
            cursor += f.code.len() as u32;
            continue;
        };
        let begin = text_rva + cursor;
        let end = begin + f.code.len() as u32;
        let unwind = xdata_rva + xdata_offset;
        b.u32(begin);
        b.u32(end);
        b.u32(unwind);
        cursor += f.code.len() as u32;
    }
    Ok(b.0)
}

/// Phase H4a/H4b: build the `.xdata` section image (variable-length
/// `UNWIND_INFO` blobs concatenated).
///
/// Two flavours per function:
///   * **try-bearing**: `UNW_FLAG_EHANDLER`-set UNWIND_INFO + trailing
///     `ExceptionHandler` RVA + scope-table records (see the inline
///     comment for the H4b extended scope-table layout — header +
///     20-byte entries).
///   * **plain** (no try): minimal UNWIND_INFO with just the standard
///     prologue opcodes describing `push rbp; sub rsp, N`. No EHANDLER,
///     no scope table. The synthetic personality function falls into
///     this case (and additionally is a true leaf — see below).
///
/// `vtable_rvas` / `tyinf_rva` / `tyinf_count` (H4b) are baked into the
/// scope-table header so the personality function can locate the
/// module-wide class-hierarchy table at exception-dispatch time.
///
/// Returns the per-function `xdata` offset (so the caller can compute
/// `UnwindInfoAddress` for `.pdata`) plus the concatenated image. A None
/// offset means the function is a leaf tail-jump thunk with no unwind entry.
fn build_xdata(
    module: &Module,
    text_rva: u32,
    personality_rva: u32,
    vtable_rvas: &[u32],
    tyinf_rva: u32,
    tyinf_count: u32,
) -> Result<(Vec<u8>, Vec<Option<u32>>), CodegenError> {
    let mut image = Vec::new();
    let mut offsets = vec![None; module.funcs.len()];
    let mut cursor = stub_len(module.entry) as u32;
    for (i, f) in module.funcs.iter().enumerate() {
        if is_unwindless_thunk(f) {
            if !f.try_scopes.is_empty() {
                return Err(CodegenError(format!(
                    "internal error: thunk '{}' unexpectedly carries try scopes",
                    f.name
                )));
            }
            cursor += f.code.len() as u32;
            continue;
        }
        // 8-byte align each UNWIND_INFO blob. The Win64 spec only
        // requires 4-byte alignment (UNWIND_INFO is DWORD-streamed), but
        // 8 keeps the trailing ExceptionHandler RVA + scope-table u32s
        // naturally aligned, which is what cl /O2 does too.
        while image.len() % 4 != 0 {
            image.push(0);
        }
        offsets[i] = Some(image.len() as u32);

        let func_text_rva = text_rva + cursor;
        let has_try = !f.try_scopes.is_empty();

        {
            // Standard mdbcc function: validate the prologue + describe
            // it with `UWOP_PUSH_NONVOL rbp` + `UWOP_ALLOC_*` (the latter
            // sized to the `sub rsp, imm32` immediate).
            let alloc = read_prolog_alloc(&f.code)?;
            // UNWIND_CODE encoding for the allocation:
            //   ALLOC_SMALL: alloc <= 128 and alloc % 8 == 0
            //       → 1 unwind code: (CodeOffset=0x0B, OpInfo=(alloc/8)-1)
            //   ALLOC_LARGE (small variant): alloc < 512 KB and alloc % 8 == 0
            //       → 2 unwind codes: header + u16(alloc/8)
            //   ALLOC_LARGE (large variant): alloc < 4 GB
            //       → 3 unwind codes: header + u32(alloc)
            // mdbcc frames are always 8-byte multiples (16-aligned even,
            // see `Gen::run`'s `(frame_fixed + io_out + 15) & !15`), so
            // we never need the rare-alloc shapes. The 4 KB pe-layout
            // fix lifted the practical cap; we still gate `alloc < 4 GB`
            // explicitly — anything that overflows that is a bug long
            // before unwinding cares.
            if alloc == 0 || alloc % 8 != 0 {
                return Err(CodegenError(format!(
                    "internal error: function '{}' prologue allocates \
                     {alloc} bytes — must be a non-zero multiple of 8 \
                     for Win64 UNWIND_INFO",
                    f.name
                )));
            }
            let (alloc_codes, alloc_extra): (u8, Vec<u8>) = if alloc <= 128 {
                let opinfo = ((alloc / 8) - 1) as u8;
                let code = [
                    MDBCC_PROLOG_SUB_RSP_OFFSET,
                    (opinfo << 4) | UWOP_ALLOC_SMALL,
                ];
                (1, code.to_vec())
            } else if alloc < 512 * 1024 {
                // ALLOC_LARGE "small" form: 2 unwind codes; second slot
                // is a u16 of (alloc / 8).
                let scaled = (alloc / 8) as u16;
                let header = [MDBCC_PROLOG_SUB_RSP_OFFSET, UWOP_ALLOC_LARGE]; // OpInfo=0
                let mut buf = header.to_vec();
                buf.extend_from_slice(&scaled.to_le_bytes());
                (2, buf)
            } else {
                // ALLOC_LARGE "large" form: 3 unwind codes; next two
                // slots are a u32 of alloc (NOT scaled).
                let header = [MDBCC_PROLOG_SUB_RSP_OFFSET, (1 << 4) | UWOP_ALLOC_LARGE]; // OpInfo=1
                let mut buf = header.to_vec();
                buf.extend_from_slice(&alloc.to_le_bytes());
                (3, buf)
            };
            // UWOP_PUSH_NONVOL rbp at CodeOffset 0x01 — always 1 unwind
            // code (2 bytes).
            let push_rbp = [
                MDBCC_PROLOG_PUSH_RBP_OFFSET,
                (UWOP_OPINFO_RBP << 4) | UWOP_PUSH_NONVOL,
            ];

            let count = alloc_codes + 1;
            let flags = if has_try { UNW_FLAG_EHANDLER } else { 0 };
            // ver:3 (=1) in low 3 bits, flags:5 in high 5 bits.
            image.push(1 | (flags << 3));
            image.push(MDBCC_PROLOG_SIZE);
            image.push(count);
            image.push(0); // FrameRegister=0, FrameOffset=0

            // Unwind codes — most recent FIRST (the alloc, then the push).
            image.extend_from_slice(&alloc_extra);
            image.extend_from_slice(&push_rbp);
            // UNWIND_CODEs are DWORD-streamed; if the total opcode count
            // is odd, the array is padded with one extra 2-byte zero
            // slot so the trailing ExceptionHandler RVA starts on a
            // DWORD boundary.
            if count % 2 != 0 {
                image.push(0);
                image.push(0);
            }

            if has_try {
                // ExceptionHandler RVA — points at the synthesised
                // personality function in `.text`.
                image.extend_from_slice(&personality_rva.to_le_bytes());
                // Language-specific data: our scope table. Format is
                // private to the personality function; the OS does not
                // interpret it.
                //
                // Phase H4b layout (extends H4a):
                //   u32 scope_count      N
                //   u32 tyinf_rva        Module-wide type-info table (0 if
                //                        no polymorphic class).
                //   u32 tyinf_count      Number of TypeInfoEntry records.
                //   N × {
                //     u32 try_begin_rva
                //     u32 try_end_rva
                //     u32 handler_rva
                //     u32 catch_kind     0=int, 1=class-by-ref, 2=class-by-ptr
                //     u32 catch_type_rva 0 for int; vtable RVA for class
                //   }                       (20 B per entry; total 12 + 20·N)
                let scope_count = f.try_scopes.len() as u32;
                image.extend_from_slice(&scope_count.to_le_bytes());
                image.extend_from_slice(&tyinf_rva.to_le_bytes());
                image.extend_from_slice(&tyinf_count.to_le_bytes());
                for s in &f.try_scopes {
                    image.extend_from_slice(&(func_text_rva + s.try_begin).to_le_bytes());
                    image.extend_from_slice(&(func_text_rva + s.try_end).to_le_bytes());
                    image.extend_from_slice(&(func_text_rva + s.handler).to_le_bytes());
                    let (kind, type_rva) = match s.policy {
                        crate::eh::CatchPolicy::Int => (0u32, 0u32),
                        crate::eh::CatchPolicy::ByRef { class_record_id } => {
                            let vt = *vtable_rvas
                                .get(class_record_id)
                                .filter(|&&r| r != 0)
                                .ok_or_else(|| {
                                    CodegenError(format!(
                                        "catch (Tag&) record {class_record_id} \
                                     has no vtable RVA (class must be \
                                     polymorphic for class-typed catch)"
                                    ))
                                })?;
                            (1u32, vt)
                        }
                        crate::eh::CatchPolicy::ByPtr { class_record_id } => {
                            let vt = *vtable_rvas
                                .get(class_record_id)
                                .filter(|&&r| r != 0)
                                .ok_or_else(|| {
                                    CodegenError(format!(
                                        "catch (Tag*) record {class_record_id} \
                                     has no vtable RVA (class must be \
                                     polymorphic for class-typed catch)"
                                    ))
                                })?;
                            (2u32, vt)
                        }
                        // Tick 69 (J-11b / J-15b): cleanup scope — the
                        // personality function runs the handler RVA's
                        // landing pad unconditionally for any in-range
                        // exception (only the two custom mdbcc codes get
                        // past the top-of-function code dispatch). No
                        // type tag.
                        crate::eh::CatchPolicy::Cleanup => (3u32, 0u32),
                        // S6: catch-all — match any in-range exception, no type tag.
                        crate::eh::CatchPolicy::CatchAll => (4u32, 0u32),
                    };
                    image.extend_from_slice(&kind.to_le_bytes());
                    image.extend_from_slice(&type_rva.to_le_bytes());
                }
            }
        }

        cursor += f.code.len() as u32;
    }
    Ok((image, offsets))
}

/// Build the PE `.rsrc` section image for an [`RcUnit`].
///
/// Layout (Win32-canonical three-level resource directory tree, plus a
/// trailing block of raw payload data):
/// ```text
///   ROOT directory (16 B)              IMAGE_RESOURCE_DIRECTORY
///   ROOT entries  (8 B each)           one IMAGE_RESOURCE_DIRECTORY_ENTRY
///                                      per distinct resource Type (RT_MENU=4,
///                                      RT_STRING=6, RT_ACCELERATOR=9, sorted
///                                      ascending). OffsetToData top-bit-set
///                                      = subdirectory.
///   TYPE directories (16 B each)       one per type (one IMAGE_RESOURCE_DIRECTORY
///                                      per type, with NumberOfIdEntries equal
///                                      to the number of distinct Names under
///                                      that type — STRINGTABLE bundle ids /
///                                      MENU ids / ACCEL ids).
///   TYPE entries  (8 B each)           one entry per (type, name) pair
///                                      (Name = bundle_id / menu_id / accel_id).
///   NAME directories (16 B each)       one IMAGE_RESOURCE_DIRECTORY per
///                                      (type, name) pair, NumberOfIdEntries = 1
///                                      (the single language).
///   NAME entries (8 B each)            one entry per (type, name). Name = lang id;
///                                      OffsetToData top-bit-CLEAR = leaf
///                                      IMAGE_RESOURCE_DATA_ENTRY.
///   DATA entries (16 B each)           IMAGE_RESOURCE_DATA_ENTRY per resource.
///                                      OffsetToData is an **RVA** (relative
///                                      to ImageBase), not a section offset.
///   payload blobs (DWORD-aligned)      raw resource bytes (UTF-16LE 16-slot
///                                      bundles / MENU MenuHeader+items /
///                                      ACCEL ACCELTABLEENTRYs).
/// ```
///
/// **Two different offset conventions in the same section** are the #1
/// source of `.rsrc` bugs: every `IMAGE_RESOURCE_DIRECTORY_ENTRY.OffsetToData`
/// is **relative to the start of the .rsrc section**, while every
/// `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` is an **RVA** (relative to
/// ImageBase). The caller passes `sect_base_rva` so the leaf RVAs can be
/// computed. DIALOG (G5) reuses the same directory skeleton — only the
/// leaf payload differs.
pub fn build_rsrc(unit: &RcUnit, sect_base_rva: u32) -> Vec<u8> {
    let res = write_res(unit);
    let entries = parse_res_entries(&res, "RcUnit")
        .expect("internal RC writer produced malformed .res bytes");
    build_rsrc_entries(entries, sect_base_rva)
}

/// Build an `.rsrc` section payload from an on-disk `.res` stream.
///
/// The `.res` envelope carries type, name, language, and raw payload bytes.
/// The PE directory tree re-sorts those records into the Win32 loader's
/// canonical directory order; payload bytes are copied verbatim.
pub fn build_rsrc_from_res(
    res: &[u8],
    sect_base_rva: u32,
    name: &str,
) -> Result<Vec<u8>, LinkError> {
    let entries = parse_res_entries(res, name)?;
    Ok(build_rsrc_entries(entries, sect_base_rva))
}

fn build_rsrc_entries(mut entries: Vec<RsrcEntry>, sect_base_rva: u32) -> Vec<u8> {
    if entries.is_empty() {
        // The caller is responsible for the empty-unit gate; reaching here
        // would mean a degenerate `.rsrc` with no data entries (legal per
        // the Win32 loader but a needless burn — short-circuit).
        return Vec::new();
    }
    entries.sort_by(|a, b| {
        cmp_rsrc_name(&a.type_name, &b.type_name)
            .then_with(|| cmp_rsrc_name(&a.name, &b.name))
            .then_with(|| a.language.cmp(&b.language))
    });
    emit_rsrc(&entries, sect_base_rva)
}

/// A flat (type, name, language, payload) tuple — the input to the
/// generalised 3-level directory emitter.
#[derive(Debug, Clone)]
struct RsrcEntry {
    type_name: RsrcName,
    name: RsrcName,
    language: u16,
    data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RsrcName {
    Id(u16),
    Name(String),
}

#[derive(Debug)]
struct RsrcTypeGroup {
    name: RsrcName,
    name_groups: Vec<RsrcNameGroup>,
}

#[derive(Debug)]
struct RsrcNameGroup {
    name: RsrcName,
    entries: std::ops::Range<usize>,
}

fn parse_res_entries(res: &[u8], source: &str) -> Result<Vec<RsrcEntry>, LinkError> {
    let mut entries = Vec::new();
    let mut off = 0usize;

    while off < res.len() {
        let rec_start = off;
        let data_size = read_res_u32(res, off, source, "data size")? as usize;
        off += 4;
        let header_size = read_res_u32(res, off, source, "header size")? as usize;
        off += 4;
        let header_end = rec_start
            .checked_add(header_size)
            .ok_or_else(|| malformed_res(source, rec_start, "header size overflows usize"))?;
        if header_end > res.len() {
            return Err(malformed_res(
                source,
                rec_start,
                "record header extends past end of file",
            ));
        }

        let (type_name, next) = read_res_name(res, off, source)?;
        off = next;
        let (name, next) = read_res_name(res, off, source)?;
        off = align_up_usize(next, 4);
        if off + 16 > header_end {
            return Err(malformed_res(
                source,
                rec_start,
                "record header is too short for fixed fields",
            ));
        }

        let language = read_res_u16(res, off + 6, source, "language id")?;
        let data_end = header_end
            .checked_add(data_size)
            .ok_or_else(|| malformed_res(source, rec_start, "data size overflows usize"))?;
        if data_end > res.len() {
            return Err(malformed_res(
                source,
                rec_start,
                "record data extends past end of file",
            ));
        }

        let is_null_header = data_size == 0
            && matches!(&type_name, RsrcName::Id(0))
            && matches!(&name, RsrcName::Id(0));
        if !is_null_header {
            entries.push(RsrcEntry {
                type_name,
                name,
                language,
                data: res[header_end..data_end].to_vec(),
            });
        }

        let next = align_up_usize(data_end, 4);
        off = if next <= res.len() { next } else { data_end };
    }

    Ok(entries)
}

fn read_res_name(res: &[u8], mut off: usize, source: &str) -> Result<(RsrcName, usize), LinkError> {
    let first = read_res_u16(res, off, source, "resource name/type")?;
    off += 2;
    if first == 0xFFFF {
        let id = read_res_u16(res, off, source, "resource ordinal")?;
        return Ok((RsrcName::Id(id), off + 2));
    }
    if first == 0 {
        return Ok((RsrcName::Name(String::new()), off));
    }

    let mut units = vec![first];
    loop {
        let ch = read_res_u16(res, off, source, "resource name string")?;
        off += 2;
        if ch == 0 {
            break;
        }
        units.push(ch);
    }

    let name = String::from_utf16(&units)
        .map_err(|_| malformed_res(source, off, "resource name is not valid UTF-16"))?;
    Ok((RsrcName::Name(name), off))
}

fn read_res_u16(res: &[u8], off: usize, source: &str, what: &str) -> Result<u16, LinkError> {
    let bytes = res
        .get(off..off + 2)
        .ok_or_else(|| malformed_res(source, off, what))?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_res_u32(res: &[u8], off: usize, source: &str, what: &str) -> Result<u32, LinkError> {
    let bytes = res
        .get(off..off + 4)
        .ok_or_else(|| malformed_res(source, off, what))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn malformed_res(source: &str, off: usize, what: &str) -> LinkError {
    LinkError::Internal(format!(
        "{source}: malformed .res at offset 0x{off:x}: {what}"
    ))
}

fn align_up_usize(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

fn group_rsrc_entries(entries: &[RsrcEntry]) -> Vec<RsrcTypeGroup> {
    let mut groups = Vec::new();
    let mut i = 0usize;
    while i < entries.len() {
        let type_name = entries[i].type_name.clone();
        let mut name_groups = Vec::new();
        while i < entries.len() && entries[i].type_name == type_name {
            let name = entries[i].name.clone();
            let start = i;
            while i < entries.len() && entries[i].type_name == type_name && entries[i].name == name
            {
                i += 1;
            }
            name_groups.push(RsrcNameGroup {
                name,
                entries: start..i,
            });
        }
        groups.push(RsrcTypeGroup {
            name: type_name,
            name_groups,
        });
    }
    groups
}

fn cmp_rsrc_name(a: &RsrcName, b: &RsrcName) -> std::cmp::Ordering {
    match (a, b) {
        (RsrcName::Name(a), RsrcName::Name(b)) => {
            let a: Vec<u16> = a.encode_utf16().collect();
            let b: Vec<u16> = b.encode_utf16().collect();
            a.cmp(&b)
        }
        (RsrcName::Name(_), RsrcName::Id(_)) => std::cmp::Ordering::Less,
        (RsrcName::Id(_), RsrcName::Name(_)) => std::cmp::Ordering::Greater,
        (RsrcName::Id(a), RsrcName::Id(b)) => a.cmp(b),
    }
}

fn named_count<'a>(names: impl Iterator<Item = &'a RsrcName>) -> u16 {
    let count = names.filter(|n| matches!(n, RsrcName::Name(_))).count();
    u16::try_from(count).expect("more than u16::MAX named resource entries")
}

fn id_count(total: usize, named: u16) -> u16 {
    let ids = total
        .checked_sub(usize::from(named))
        .expect("named count cannot exceed total");
    u16::try_from(ids).expect("more than u16::MAX resource id entries")
}

fn add_name_string(name: &RsrcName, pool: &mut Vec<(String, u32)>, cursor: &mut u32) {
    let RsrcName::Name(s) = name else {
        return;
    };
    if pool.iter().any(|(existing, _)| existing == s) {
        return;
    }
    let utf16_len = u32::try_from(s.encode_utf16().count()).expect("resource name too long");
    pool.push((s.clone(), *cursor));
    *cursor += 2 + utf16_len * 2;
}

fn name_entry_value(name: &RsrcName, pool: &[(String, u32)]) -> u32 {
    match name {
        RsrcName::Id(id) => u32::from(*id),
        RsrcName::Name(s) => {
            let off = pool
                .iter()
                .find_map(|(existing, off)| (existing == s).then_some(*off))
                .expect("resource name string offset must be precomputed");
            0x8000_0000 | off
        }
    }
}

/// Pure layout core: deterministic byte assembly given a pre-sorted, non-empty
/// resource list + the section's base RVA.
///
/// The 3-level directory tree is generalised for multiple types: ROOT has one
/// entry per distinct type; each TYPE subdirectory has one entry per distinct
/// name carrying that type; each NAME subdirectory has one LANGUAGE entry per
/// translation.
///
/// **Byte-identical to the G3 single-type RT_STRING emitter** when the input
/// list carries only RT_STRING entries: the same tier ordering (ROOT entries,
/// then TYPE dir+entries, then per-NAME dir+entries, then zero-length string
/// pool, then DATA_ENTRY leaves, then payload blobs) and the same offset
/// arithmetic. This is the leave-it-green invariant for the G3 PE-`.rsrc`
/// golden test in `tests/pe_rsrc.rs::build_rsrc_byte_exact_for_one_entry_hi`.
fn emit_rsrc(entries: &[RsrcEntry], sect_base_rva: u32) -> Vec<u8> {
    // Layout constants — Win32 IMAGE_RESOURCE_{DIRECTORY,DIRECTORY_ENTRY,DATA_ENTRY}.
    const RES_DIR: u32 = 16;
    const RES_DIR_ENTRY: u32 = 8;
    const RES_DATA_ENTRY: u32 = 16;
    const SUBDIR_FLAG: u32 = 0x8000_0000;

    let type_groups = group_rsrc_entries(entries);
    let n_types = u16::try_from(type_groups.len()).expect("more than u16::MAX resource types");
    let n_entries = u32::try_from(entries.len()).expect("more than u32::MAX resource entries");

    // ---- Compute section-relative offsets ----
    //
    // Tier 1 (ROOT): one IMAGE_RESOURCE_DIRECTORY header + one entry per type.
    let root_dir_off = 0u32;
    let root_entries_off = root_dir_off + RES_DIR;

    // Tier 2 (per-TYPE dirs): immediately after the ROOT entries.
    // Each type dir is 16 B + 8 B × (entries-in-type).
    let mut type_dir_offs: Vec<u32> = Vec::with_capacity(type_groups.len());
    let mut cursor = root_entries_off + RES_DIR_ENTRY * u32::from(n_types);
    for group in &type_groups {
        type_dir_offs.push(cursor);
        cursor += RES_DIR + RES_DIR_ENTRY * (group.name_groups.len() as u32);
    }

    // Tier 3 (per-NAME dirs): one per (type, name) pair. Each name dir is
    // 16 B + 8 B per language translation.
    let mut name_dir_offs: Vec<Vec<u32>> = Vec::with_capacity(type_groups.len());
    for group in &type_groups {
        let mut offs = Vec::with_capacity(group.name_groups.len());
        for name_group in &group.name_groups {
            offs.push(cursor);
            cursor += RES_DIR + RES_DIR_ENTRY * (name_group.entries.len() as u32);
        }
        name_dir_offs.push(offs);
    }

    // Tier 4 (string names): IMAGE_RESOURCE_DIR_STRING_U blobs used by any
    // named ROOT or TYPE entry. Id-only resources add no bytes, preserving the
    // old byte-exact layout.
    let string_pool_off = cursor;
    let mut string_pool: Vec<(String, u32)> = Vec::new();
    for group in &type_groups {
        add_name_string(&group.name, &mut string_pool, &mut cursor);
        for name_group in &group.name_groups {
            add_name_string(&name_group.name, &mut string_pool, &mut cursor);
        }
    }
    cursor = align_up(cursor, 4);

    // Tier 5 (DATA_ENTRY leaves): 16 B each.
    let data_entries_off = cursor;
    cursor += RES_DATA_ENTRY * n_entries;

    // Trailing payload blobs, each DWORD-aligned.
    let mut per_entry_payload_off: Vec<u32> = Vec::with_capacity(entries.len());
    for e in entries {
        per_entry_payload_off.push(cursor);
        cursor += align_up(e.data.len() as u32, 4);
    }
    let total_size = cursor;

    // ---- Emit bytes ----
    let mut buf = Buf::new();

    // Tier 1: ROOT directory header + entries.
    let root_named = named_count(type_groups.iter().map(|g| &g.name));
    write_resource_directory(
        &mut buf,
        root_named,
        id_count(type_groups.len(), root_named),
    );
    // ROOT entries: one per distinct type, sorted ascending.
    for (g, group) in type_groups.iter().enumerate() {
        buf.u32(name_entry_value(&group.name, &string_pool));
        buf.u32(SUBDIR_FLAG | type_dir_offs[g]);
    }

    // Tier 2: per-TYPE directories + name entries. Each type's name entries
    // point at this name's per-name directory in tier 3.
    for (g, group) in type_groups.iter().enumerate() {
        debug_assert_eq!(buf.len() as u32, type_dir_offs[g]);
        let type_named = named_count(group.name_groups.iter().map(|ng| &ng.name));
        write_resource_directory(
            &mut buf,
            type_named,
            id_count(group.name_groups.len(), type_named),
        );
        for (ng, name_group) in group.name_groups.iter().enumerate() {
            let name_dir = name_dir_offs[g][ng];
            buf.u32(name_entry_value(&name_group.name, &string_pool));
            buf.u32(SUBDIR_FLAG | name_dir);
        }
    }

    // Tier 3: per-NAME directories. Each has exactly one LANGUAGE entry
    // pointing at the corresponding DATA_ENTRY leaf.
    for (g, group) in type_groups.iter().enumerate() {
        for (ng, name_group) in group.name_groups.iter().enumerate() {
            debug_assert_eq!(buf.len() as u32, name_dir_offs[g][ng]);
            write_resource_directory(
                &mut buf,
                0,
                u16::try_from(name_group.entries.len())
                    .expect("more than u16::MAX language entries"),
            );
            for entry_idx in name_group.entries.clone() {
                let leaf_off = data_entries_off + RES_DATA_ENTRY * entry_idx as u32;
                buf.u32(u32::from(entries[entry_idx].language));
                buf.u32(leaf_off);
            }
        }
    }

    // Tier 4: IMAGE_RESOURCE_DIR_STRING_U blobs, if any.
    debug_assert_eq!(buf.len() as u32, string_pool_off);
    for (s, string_off) in &string_pool {
        debug_assert_eq!(buf.len() as u32, *string_off);
        let units: Vec<u16> = s.encode_utf16().collect();
        buf.u16(u16::try_from(units.len()).expect("resource name too long"));
        for unit in units {
            buf.u16(unit);
        }
    }
    while !buf.len().is_multiple_of(4) {
        buf.u8(0);
    }

    // Tier 5: IMAGE_RESOURCE_DATA_ENTRY leaves. OffsetToData is an RVA.
    debug_assert_eq!(buf.len() as u32, data_entries_off);
    for (i, e) in entries.iter().enumerate() {
        let payload_rva = sect_base_rva + per_entry_payload_off[i];
        buf.u32(payload_rva);
        buf.u32(e.data.len() as u32);
        buf.u32(0); // CodePage (neutral)
        buf.u32(0); // Reserved
    }

    // Trailing payload blobs, each DWORD-aligned.
    for e in entries {
        buf.bytes(&e.data);
        while !buf.len().is_multiple_of(4) {
            buf.u8(0);
        }
    }

    debug_assert_eq!(buf.len() as u32, total_size);
    buf.0
}

/// Write one `IMAGE_RESOURCE_DIRECTORY` header (16 bytes). v1 emits
/// `Characteristics`/`TimeDateStamp`/`Major`/`Minor` all zero — every
/// `link.exe`-produced `.rsrc` I have inspected does the same, and the
/// Win32 loader ignores these for resource lookup. v1 supports id entries
/// only (NumberOfNamedEntries = 0).
fn write_resource_directory(b: &mut Buf, named: u16, ids: u16) {
    b.u32(0); // Characteristics
    b.u32(0); // TimeDateStamp
    b.u16(0); // MajorVersion
    b.u16(0); // MinorVersion
    b.u16(named); // NumberOfNamedEntries
    b.u16(ids); // NumberOfIdEntries
}

/// Classic MZ header + DOS stub, occupying bytes `0..PE_OFF`.
fn write_dos_header(b: &mut Buf) {
    b.bytes(b"MZ");
    b.u16(0x90); // e_cblp
    b.u16(0x03); // e_cp
    b.u16(0); // e_crlc
    b.u16(0x04); // e_cparhdr
    b.u16(0); // e_minalloc
    b.u16(0xFFFF); // e_maxalloc
    b.u16(0); // e_ss
    b.u16(0xB8); // e_sp
    b.u16(0); // e_csum
    b.u16(0); // e_ip
    b.u16(0); // e_cs
    b.u16(0x40); // e_lfarlc
    b.u16(0); // e_ovno
    for _ in 0..4 {
        b.u16(0); // e_res
    }
    b.u16(0); // e_oemid
    b.u16(0); // e_oeminfo
    for _ in 0..10 {
        b.u16(0); // e_res2
    }
    b.u32(PE_OFF as u32); // e_lfanew
    // DOS stub program: prints the classic message and exits.
    b.bytes(&[
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
    ]);
    b.bytes(b"This program cannot be run in DOS mode.\r\r\n$");
    b.pad_to(PE_OFF);
}

/// Assemble a complete PE32+ executable from generated `main` code. The
/// **no-resource** entry point: byte-identical to the pre-G3 writer for every
/// existing program (`tests/end_to_end.rs`'s 88 e2e tests prove this). When
/// the caller has parsed a sibling `.rc` file, use [`write_pe_with_rsrc`]
/// instead.
pub fn write_pe(module: &Module) -> Result<Vec<u8>, CodegenError> {
    write_pe_with_rsrc(module, None)
}

/// Assemble a complete PE32+ executable with an optional embedded `.rsrc`
/// section. When `rc_unit` is `None` the produced bytes are byte-identical
/// to the pre-G3 writer for the same module (the leave-it-green contract).
/// When `Some` and the unit carries at least one STRINGTABLE entry, the
/// writer appends a fifth section `.rsrc` after `.data`, fills
/// `DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE = 2]`, and bumps
/// `NumberOfSections` from 4 to 5; all other bytes are still identical
/// (`.rsrc` is structurally appended; nothing it touches shifts an
/// earlier-section RVA).
pub fn write_pe_with_rsrc(
    module: &Module,
    rc_unit: Option<&RcUnit>,
) -> Result<Vec<u8>, CodegenError> {
    // S4.2s: an executable needs an entry point. A TU with no main/WinMain
    // (`Entry::None` — e.g. a real OWL app's `OwlMain` object) is a valid OBJECT
    // but cannot be a standalone PE; it must be linked with an object/lib that
    // defines the entry (the OWL runtime supplies `main`/`WinMain`).
    if module.entry == crate::codegen::Entry::None {
        return Err(CodegenError(
            "cannot produce an executable: no 'main'/'WinMain' entry point \
             (link this object with one that defines an entry)"
                .into(),
        ));
    }
    // Linear layout pass: each section's base RVA is fixed from the prior
    // section's real size, so no section overlaps the next regardless of
    // size. Programs that fit the historical 4 KB budget reproduce the old
    // fixed RVAs (0x1000/0x2000/0x3000/0x4000) byte-for-byte.

    // Cheap pre-pass: `.text` virtual size without building it (mirrors the
    // cursor loop in `build_text`). An always-on check below proves the two
    // never drift (a release-safe hard error if they ever do).
    let text_vsize = stub_len(module.entry) as u32
        + module
            .funcs
            .iter()
            .map(|f| f.code.len() as u32)
            .sum::<u32>();

    let text_rva = align_up(HEADERS_SIZE, SECT_ALIGN);
    let idata_rva = align_up(text_rva + text_vsize, SECT_ALIGN);
    let idata = build_idata(module, idata_rva)?;
    let idata_vsize = idata.image.len() as u32;

    let rdata_rva = align_up(idata_rva + idata_vsize, SECT_ALIGN);
    let (mut rdata, str_offs) = build_rdata(module);
    // `build_data` may append pointed-to strings to `.rdata`; its absolute
    // addresses are valid because `rdata_rva` is already pinned.
    let (mut data, data_offs) = build_data(module, &mut rdata, rdata_rva);
    // Phase B: append vtables to `.rdata` (after strings; their absolute
    // function-address slots are valid because `text_rva` is pinned and
    // function offsets depend only on code lengths). Empty pre-Phase-B /
    // for programs with no virtual functions ⇒ no bytes, no RVA drift.
    let foffsets = func_offsets(module)?;
    let vtable_rvas = build_vtables(module, &mut rdata, rdata_rva, text_rva, &foffsets)?;
    // Phase H4b: append the typeinfo table (class hierarchy walk source).
    // Empty for any TU without `try`/`throw` (Module.typeinfo is empty),
    // so int-only and non-throwing TUs see no `.rdata` growth — gates the
    // O1 88 e2e byte-identity contract.
    let (tyinf_rva, tyinf_count) = build_typeinfo(module, &mut rdata, rdata_rva, &vtable_rvas)?;
    if rdata.is_empty() {
        rdata.push(0); // keep the section non-degenerate
    }
    if data.is_empty() {
        data.push(0);
    }
    // `.data` RVA depends on the *final* `.rdata` size (after `build_data`
    // appended any strings and the empty-section guard ran).
    let data_rva = align_up(rdata_rva + rdata.len() as u32, SECT_ALIGN);
    // Rebase the section-relative offsets to absolute RVAs.
    let str_rvas: Vec<Vec<u32>> = str_offs
        .iter()
        .map(|v| v.iter().map(|&o| o + rdata_rva).collect())
        .collect();
    let data_rvas: Vec<u32> = data_offs.iter().map(|&o| o + data_rva).collect();

    // S5 #45: fill each `T *g = &other;` slot with the TARGET global's absolute
    // address — the standalone-PE analogue of the object writer's Addr64 reloc.
    // `data_rvas` is now known, and `build_data` reserved the 8-byte slot as
    // zeros (a ptr_global global carries `ptr_bytes` zero bytes). The target was
    // validated as a real data global at codegen time, so the lookup always hits.
    for (i, g) in module.globals.iter().enumerate() {
        if let Some(target) = &g.ptr_global {
            let tgt = module
                .globals
                .iter()
                .position(|x| &x.name == target)
                .expect("ptr_global target missing from module.globals");
            let abs = IMAGE_BASE + data_rvas[tgt] as u64;
            let off = data_offs[i] as usize;
            data[off..off + 8].copy_from_slice(&abs.to_le_bytes());
        }
    }

    let text = build_text(
        module,
        &idata,
        &str_rvas,
        &data_rvas,
        &vtable_rvas,
        text_rva,
    )?;
    // Always-on (release included): if the cheap pre-pass ever diverged from
    // the real `build_text` output, every size/RVA below is wrong and the PE
    // would be silently unloadable. Fail loudly instead.
    if text.len() as u32 != text_vsize {
        return Err(CodegenError(format!(
            "internal error: .text size pre-pass ({}) diverged from emitted code ({})",
            text_vsize,
            text.len()
        )));
    }

    let rdata_vsize = rdata.len() as u32;
    let data_vsize = data.len() as u32;
    let text_raw = align_up(text_vsize, FILE_ALIGN);
    let idata_raw = align_up(idata_vsize, FILE_ALIGN);
    let rdata_raw = align_up(rdata_vsize, FILE_ALIGN);
    let data_raw = align_up(data_vsize, FILE_ALIGN);

    let text_file_off = HEADERS_SIZE;
    let idata_file_off = text_file_off + text_raw;
    let rdata_file_off = idata_file_off + idata_raw;
    let data_file_off = rdata_file_off + rdata_raw;
    // Phase H4a: `.pdata` + `.xdata` file offsets are pinned now even
    // though their raw sizes are unknown until after the SEH layout
    // computation below — they are 0 when SEH is inactive, so the
    // arithmetic is correct for that case too (both file offsets equal
    // `data_file_off + data_raw`, never used). Computed early so the
    // `.rsrc` file offset below can chain off whichever section
    // actually precedes it.

    // ---- Optional `.pdata` / `.xdata` (Phase H / H4a) ----
    //
    // Win64 SEH unwind metadata. Gated on `needs_seh(module)` — true iff
    // at least one user function carries a `try` scope (the synthesised
    // personality function never sets the flag). Programs without
    // `try`/`throw` skip BOTH sections ⇒ `NumberOfSections` stays at 4
    // and `DataDirectory[3]` stays `(0,0)` ⇒ the only structural change
    // for a non-throwing program vs pre-H4a is the IAT shift caused by
    // adding `RaiseException`/`RtlUnwindEx` to `WIN32_IMPORTS` (the
    // explicitly re-blessed `pe_imports` golden).
    //
    // Section order: `.pdata` → `.xdata`, after `.data`, before `.rsrc`
    // (`.rsrc` is always trailing per Win32 convention; `.pdata` /
    // `.xdata` typically sit before it, between `.data` and `.rsrc`).
    // Both sections are read-only INITIALIZED_DATA.
    //
    // `.pdata` references `.xdata` (`UnwindInfoAddress` in each
    // `RUNTIME_FUNCTION` is an RVA into `.xdata`); its layout is fixed
    // once we know `.xdata`'s base RVA. `.xdata` in turn references the
    // synthesised personality function's RVA in `.text` (every
    // try-bearing function's `UNWIND_INFO.ExceptionHandler`), which
    // we recovered via `func_offsets` above.
    let has_seh = needs_seh(module);
    let pdata_rva = align_up(data_rva + data_vsize, SECT_ALIGN);
    let pdata_vsize: u32 = if has_seh {
        // 12 bytes per unwindable function (one RUNTIME_FUNCTION each).
        12 * module
            .funcs
            .iter()
            .filter(|f| !is_unwindless_thunk(f))
            .count() as u32
    } else {
        0
    };
    let xdata_rva = align_up(pdata_rva + pdata_vsize, SECT_ALIGN);
    let (xdata_bytes, xdata_offsets, pdata_bytes) = if has_seh {
        let personality_off = *foffsets
            .get(crate::eh::PERSONALITY_FN_NAME)
            .ok_or_else(|| {
                CodegenError(
                    "internal error: SEH module missing the synthesised \
                 personality function"
                        .into(),
                )
            })?;
        let personality_rva = text_rva + personality_off as u32;
        let (xb, xo) = build_xdata(
            module,
            text_rva,
            personality_rva,
            &vtable_rvas,
            tyinf_rva,
            tyinf_count,
        )?;
        let pb = build_pdata(module, text_rva, xdata_rva, &xo)?;
        (xb, xo, pb)
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    let _ = xdata_offsets; // (offsets are baked into pdata; kept named for clarity)
    let xdata_vsize = xdata_bytes.len() as u32;
    let pdata_raw = align_up(pdata_vsize, FILE_ALIGN);
    let xdata_raw = align_up(xdata_vsize, FILE_ALIGN);

    // ---- Optional `.rsrc` (Phase G / G3) ----
    //
    // The `.rsrc` section is appended **after** `.data` (last section in the
    // image), characteristics = INITIALIZED_DATA | READ. Section index 4 (the
    // 5th section). Gated on `rc_unit.is_some_and(non_empty)`: when no `.rc`
    // is present we never emit a `.rsrc` ⇒ `NumberOfSections` stays 4 ⇒ the
    // 88-program e2e corpus stays byte-identical (the leave-it-green
    // contract; the `Option::None` short-circuit at the call site is the
    // executable proof).
    //
    // RVA / file-offset arithmetic mirrors the four existing sections:
    // section-aligned RVA, file-aligned raw size; `.rsrc` raw data follows
    // `.data`'s padded raw block in the file. No earlier section's RVA or
    // raw offset shifts — only the trailing `.rsrc` is new, plus the
    // section-table grows by one 40-byte entry (still well within
    // HEADERS_SIZE = 0x400).
    let rsrc_rva = align_up(xdata_rva + xdata_vsize, SECT_ALIGN);
    let rsrc_bytes: Vec<u8> = rc_unit.map(|u| build_rsrc(u, rsrc_rva)).unwrap_or_default();
    let has_rsrc = !rsrc_bytes.is_empty();
    let rsrc_vsize = rsrc_bytes.len() as u32;
    let rsrc_raw = align_up(rsrc_vsize, FILE_ALIGN);
    let mut n_sections: u16 = 4;
    if has_seh {
        n_sections += 2; // .pdata + .xdata
    }
    if has_rsrc {
        n_sections += 1;
    }
    let size_of_image = if has_rsrc {
        align_up(rsrc_rva + rsrc_vsize, SECT_ALIGN)
    } else if has_seh {
        align_up(xdata_rva + xdata_vsize, SECT_ALIGN)
    } else {
        align_up(data_rva + data_vsize, SECT_ALIGN)
    };

    // File offsets: each section's raw block follows the previous
    // section's padded raw block. When `.pdata` / `.xdata` are absent
    // (`has_seh == false`) their offsets land where `.rsrc` (or
    // nothing) would naturally start, and `pdata_raw + xdata_raw` is 0
    // ⇒ the next section's file offset is unchanged from the pre-H4a
    // layout (the 88-program e2e corpus does not regress).
    let pdata_file_off = data_file_off + data_raw;
    let xdata_file_off = pdata_file_off + pdata_raw;
    let rsrc_file_off = xdata_file_off + xdata_raw;

    let mut b = Buf::new();
    write_dos_header(&mut b);
    debug_assert_eq!(b.len(), PE_OFF);

    // ---- PE signature + COFF file header ----
    b.bytes(b"PE\0\0");
    b.u16(0x8664); // Machine = AMD64
    // NumberOfSections (.text, .idata, .rdata, .data, +.rsrc when present).
    // Stays at 4 for any TU without resources — the 88-program e2e corpus
    // is byte-identical because every other field in the PE depends only
    // on the four-section layout for that path (Phase G / G3 gate).
    b.u16(n_sections);
    b.u32(0); // TimeDateStamp (0 => deterministic build)
    b.u32(0); // PointerToSymbolTable
    b.u32(0); // NumberOfSymbols
    b.u16(0xF0); // SizeOfOptionalHeader (PE32+: 112 + 16*8)
    b.u16(0x0022); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // ---- Optional header (PE32+) ----
    b.u16(0x020B); // Magic = PE32+
    b.u8(14); // MajorLinkerVersion
    b.u8(0); // MinorLinkerVersion
    b.u32(text_raw); // SizeOfCode
    b.u32(idata_raw + rdata_raw + data_raw + rsrc_raw); // SizeOfInitializedData (+.rsrc when present; 0 otherwise — byte-identical)
    b.u32(0); // SizeOfUninitializedData
    b.u32(text_rva); // AddressOfEntryPoint (entry stub)
    b.u32(text_rva); // BaseOfCode
    b.u64(IMAGE_BASE); // ImageBase
    b.u32(SECT_ALIGN); // SectionAlignment
    b.u32(FILE_ALIGN); // FileAlignment
    b.u16(6); // MajorOperatingSystemVersion
    b.u16(0); // MinorOperatingSystemVersion
    b.u16(0); // MajorImageVersion
    b.u16(0); // MinorImageVersion
    b.u16(6); // MajorSubsystemVersion
    b.u16(0); // MinorSubsystemVersion
    b.u32(0); // Win32VersionValue
    b.u32(size_of_image); // SizeOfImage
    b.u32(HEADERS_SIZE); // SizeOfHeaders
    b.u32(0); // CheckSum
    // Subsystem: console (`main`) ⇒ 3 (WINDOWS_CUI) — byte-identical to the
    // historical literal; GUI (`WinMain`) ⇒ 2 (WINDOWS_GUI). Phase C / C2.
    b.u16(match module.entry {
        crate::codegen::Entry::ConsoleMain => 3,
        crate::codegen::Entry::GuiWinMain => 2,
        crate::codegen::Entry::None => 3, // rejected earlier; console default
    });
    b.u16(0); // DllCharacteristics (no ASLR; fixed ImageBase, no relocs)
    b.u64(0x100000); // SizeOfStackReserve
    b.u64(0x1000); // SizeOfStackCommit
    b.u64(0x100000); // SizeOfHeapReserve
    b.u64(0x1000); // SizeOfHeapCommit
    b.u32(0); // LoaderFlags
    b.u32(16); // NumberOfRvaAndSizes

    // Data directories (16). Import (1) and IAT (12) are always used;
    // Resource (2) is non-zero iff a `.rsrc` was emitted (Phase G / G3);
    // Exception (3) is non-zero iff `.pdata` was emitted (Phase H / H4a).
    // For a TU with no resources and no `try` blocks `dirs[2]` and
    // `dirs[3]` stay `(0, 0)`.
    let mut dirs = [(0u32, 0u32); 16];
    dirs[1] = (idata.import_dir_rva, idata.import_dir_size);
    dirs[12] = (idata.iat_rva, idata.iat_size);
    if has_rsrc {
        dirs[2] = (rsrc_rva, rsrc_vsize);
    }
    if has_seh {
        dirs[3] = (pdata_rva, pdata_vsize);
    }
    for (rva, size) in dirs {
        b.u32(rva);
        b.u32(size);
    }

    // ---- Section headers ----
    write_section_header(
        &mut b,
        b".text",
        text_vsize,
        text_rva,
        text_raw,
        text_file_off,
        0x6000_0020, // CODE | EXECUTE | READ
    );
    write_section_header(
        &mut b,
        b".idata",
        idata_vsize,
        idata_rva,
        idata_raw,
        idata_file_off,
        0xC000_0040, // INITIALIZED_DATA | READ | WRITE
    );
    write_section_header(
        &mut b,
        b".rdata",
        rdata_vsize,
        rdata_rva,
        rdata_raw,
        rdata_file_off,
        0x4000_0040, // INITIALIZED_DATA | READ
    );
    write_section_header(
        &mut b,
        b".data",
        data_vsize,
        data_rva,
        data_raw,
        data_file_off,
        0xC000_0040, // INITIALIZED_DATA | READ | WRITE
    );
    // Phase H4a: `.pdata` + `.xdata` are appended between `.data` and
    // `.rsrc`, both read-only INITIALIZED_DATA. Gated on `has_seh` so
    // a non-throwing TU still has exactly 4 sections (no header drift).
    if has_seh {
        write_section_header(
            &mut b,
            b".pdata",
            pdata_vsize,
            pdata_rva,
            pdata_raw,
            pdata_file_off,
            0x4000_0040, // INITIALIZED_DATA | READ
        );
        write_section_header(
            &mut b,
            b".xdata",
            xdata_vsize,
            xdata_rva,
            xdata_raw,
            xdata_file_off,
            0x4000_0040, // INITIALIZED_DATA | READ
        );
    }
    // The last section, when present (Phase G / G3): `.rsrc` is read-only
    // INITIALIZED_DATA. For a TU without resources this header is NOT
    // emitted ⇒ no header drift.
    if has_rsrc {
        write_section_header(
            &mut b,
            b".rsrc",
            rsrc_vsize,
            rsrc_rva,
            rsrc_raw,
            rsrc_file_off,
            0x4000_0040, // INITIALIZED_DATA | READ
        );
    }

    // ---- Section data ----
    b.pad_to(text_file_off as usize);
    b.bytes(&text);
    b.pad_to(idata_file_off as usize);
    b.bytes(&idata.image);
    b.pad_to(rdata_file_off as usize);
    b.bytes(&rdata);
    b.pad_to(data_file_off as usize);
    b.bytes(&data);
    b.pad_to((data_file_off + data_raw) as usize);
    // Phase H4a: `.pdata` and `.xdata` come between `.data` and `.rsrc`
    // when present. Each pads up to its file_off, writes its bytes,
    // then pads to its raw-aligned end.
    if has_seh {
        b.pad_to(pdata_file_off as usize);
        b.bytes(&pdata_bytes);
        b.pad_to((pdata_file_off + pdata_raw) as usize);
        b.pad_to(xdata_file_off as usize);
        b.bytes(&xdata_bytes);
        b.pad_to((xdata_file_off + xdata_raw) as usize);
    }
    if has_rsrc {
        b.pad_to(rsrc_file_off as usize);
        b.bytes(&rsrc_bytes);
        b.pad_to((rsrc_file_off + rsrc_raw) as usize);
    }

    Ok(b.0)
}

#[allow(clippy::too_many_arguments)]
fn write_section_header(
    b: &mut Buf,
    name: &[u8],
    vsize: u32,
    rva: u32,
    raw_size: u32,
    raw_ptr: u32,
    characteristics: u32,
) {
    let mut n = [0u8; 8];
    n[..name.len()].copy_from_slice(name);
    b.bytes(&n);
    b.u32(vsize); // VirtualSize
    b.u32(rva); // VirtualAddress
    b.u32(raw_size); // SizeOfRawData
    b.u32(raw_ptr); // PointerToRawData
    b.u32(0); // PointerToRelocations
    b.u32(0); // PointerToLinenumbers
    b.u16(0); // NumberOfRelocations
    b.u16(0); // NumberOfLinenumbers
    b.u32(characteristics);
}

// ---------------------------------------------------------------------------
// S1c.3 — Object-consuming PE writer
// ---------------------------------------------------------------------------
//
// This is the new pipeline endpoint per HLD §1.3: `compile_to_pe_with_rc`
// now goes Module → Object → PE rather than Module → PE. The legacy
// `write_pe_with_rsrc` (Module-consuming) stays for one tick (per HLD §9
// row S1c.3); deletion is S1c.4 or later.
//
// PE bytes WILL shift from the legacy path because:
// 1. The Object's `.text` pads each function up to 16-byte alignment with
//    0xCC (int3) — the legacy path packs functions back-to-back.
// 2. Module-wide string dedup in the Object — the legacy path emits each
//    function's strings without cross-function dedup (so duplicate strings
//    occupied independent .rdata bytes).
// 3. Globals that carry pointer-to-string init (`ptr_str`) appear in `.data`
//    as 8 zero bytes patched by an Addr64 reloc (same RVA semantics).
//
// Acceptable per HLD R19: deterministic, semantic-equivalent changes
// (function entry points still resolve to function starts; padding is 0xCC
// which traps cleanly; shared strings save space without changing
// behaviour).

/// Section kinds the linker tracks during merge / RVA assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutKind {
    Text,
    Data,
    Rdata,
    Pdata,
    Xdata,
}

impl OutKind {
    fn from_section_name(name: &SectionName) -> Option<Self> {
        match name {
            SectionName::Text | SectionName::TextComdat(_) => Some(OutKind::Text),
            SectionName::Data => Some(OutKind::Data),
            SectionName::Rdata | SectionName::RdataComdat(_) => Some(OutKind::Rdata),
            SectionName::Pdata | SectionName::PdataComdat(_) => Some(OutKind::Pdata),
            SectionName::Xdata | SectionName::XdataComdat(_) => Some(OutKind::Xdata),
            _ => None,
        }
    }
}

/// Per-input-section placement within the merged output image.
#[derive(Debug, Clone, Copy)]
struct SectionPlace {
    /// Which output section this input section belongs to.
    out: OutKind,
    /// Final RVA where this section's first byte lands.
    rva: u32,
    /// Byte offset within the output section (used to compute final
    /// reloc target addresses for symbols defined here).
    out_offset: u32,
}

/// Resolved address for one Object symbol.
#[derive(Debug, Clone, Copy)]
enum ResolvedSym {
    /// Symbol points at a defined RVA inside the image (function, global,
    /// vtable, etc.). Value already includes `IMAGE_BASE` offset semantics
    /// where appropriate (i.e. this is the section-relative RVA, NOT VA).
    Rva(u32),
    /// Symbol is an `__imp_<name>` import — value is the IAT slot RVA.
    ImportSlot(u32),
}

/// Translate one Object into a PE image. Per HLD §1.2 this is the
/// single-input shortcut behind [`crate::link::link_single`].
///
/// Thin wrapper over [`write_pe_from_objects`] (which handles both the
/// single-input and multi-input cases). For input count == 1 the multi-
/// input pipeline collapses to the same data structures and the same
/// output byte sequence as the original S1c.3 single-Object code —
/// verified by `tests/two_file_link.rs::single_object_through_link_matches_link_single`
/// (R19 byte-identity).
pub fn write_pe_from_object(obj: &coff::Object, opts: &LinkOpts) -> Result<Vec<u8>, LinkError> {
    write_pe_from_objects(&[obj], opts)
}

/// Translate one-or-more Objects into a PE image (PE32+ for AMD64, PE32
/// for I386). Per HLD §1.2 / §2 this is the multi-input entry behind
/// [`crate::link::link`].
///
/// **Decision-1c.1** (2026-05-28 supervisor session): the HLD §5.6 spec
/// recommended two parallel functions (`write_pe32plus_from_objects` +
/// `write_pe32_from_objects`) but inspection of the actual writer shows
/// the divergence between PE32 and PE32+ is bounded to ~30 lines of
/// optional-header emission (HLD §5.1). Parametrising over machine
/// width inside one function (~30 lines of `if` branches) is far less
/// duplicated code than the ~1200-line copy-paste two parallel
/// functions would produce, and removes drift risk between the two
/// writers. The HLD recommendation is overridden by the actual code
/// shape; rationale recorded in
/// `wrk_journals/2026.05.27 - JRN - S2 drive (32-bit x86 backend).md`
/// §1c.
///
/// The 7-pass pipeline (HLD §2):
/// 1. **Ingest**: walk every input's sections; concatenate into per-OutKind
///    buffers in `(obj_ix, sec_ix)` order. The entry stub owns the first
///    `STUB_LEN` (or `GUI_STUB_LEN`) bytes of `.text`.
/// 2. **Symbol resolution**: build a global symbol table keyed by name.
///    Defined-once externals enter the table; duplicates of plain
///    externals raise `DuplicateSymbol`. Undefined references that
///    survive lookup collect into a single batched
///    `UnresolvedExternals` error.
/// 3. **RVA assignment**: section RVAs are computed in the legacy order
///    (`.text → .idata → .rdata → .data → .pdata → .xdata`); per-input-
///    section placements are derived from the merged-section cursor.
/// 4. **Reloc application**: for each input section's relocations, look
///    up the target symbol in the **owning input's** symbol table, then
///    (if undefined) resolve via the global table to the defining
///    input's `(section, offset)` and convert to its final RVA.
/// 5. **Entry stub**: synthesised at offset 0 of `.text`. Calls
///    `main`/`WinMain` via the resolved symbol RVA.
/// 6. **Data directories + headers**: identical to single-Object — the
///    merged image is just structurally larger.
///
/// For input count == 1 every Vec-of-Vec collapses to a single inner Vec
/// and the function emits the same bytes as the legacy S1c.3
/// single-Object path.
pub fn write_pe_from_objects(
    objects: &[&coff::Object],
    opts: &LinkOpts,
) -> Result<Vec<u8>, LinkError> {
    let is_pe32 = match opts.machine {
        coff::Machine::Amd64 => false,
        coff::Machine::I386 => true,
    };
    if objects.is_empty() {
        return Err(LinkError::Internal(
            "link requires at least one input".into(),
        ));
    }

    // ---- Pass 1: ingest — collect input sections per output kind --------
    //
    // For each input object we record a per-section `SectionPlace` (which
    // output kind it joins and the offset within that output buffer where
    // its bytes land). Walked in (obj_ix, sec_ix) order; for a single
    // object this collapses to the same iteration as the S1c.3 path.
    let mut place: Vec<Vec<Option<SectionPlace>>> = objects
        .iter()
        .map(|o| vec![None; o.sections.len()])
        .collect();

    let mut text_bytes: Vec<u8> = Vec::new();
    let mut data_bytes: Vec<u8> = Vec::new();
    let mut rdata_bytes: Vec<u8> = Vec::new();
    let mut pdata_bytes: Vec<u8> = Vec::new();
    let mut xdata_bytes: Vec<u8> = Vec::new();

    let subsystem = opts.subsystem;
    // #20 PART 2b: file-scope C++ objects with constructors in a main-LESS TU
    // (an OWL/RTL library `.obj`) are constructed before user code by a CRT
    // static-init pass. bcc emits one parameterless thunk per such object,
    // named with the reserved `.mdbcc_ctor.` prefix (no C identifier can begin
    // with `.`, like the existing `.flit.` convention), and registers it as a
    // root so it is never pruned. The linker collects every such thunk across
    // all inputs (deterministic input-then-symbol order) and CALLS each, in
    // order, immediately before `main`. Absent any thunk this is empty ⇒ a
    // ctor-free link is byte-for-byte unchanged. (For a single-TU program that
    // DEFINES `main`, bcc instead injects the calls into main's prologue —
    // PART 2a — so the two paths never double-construct.)
    let ctor_thunks = collect_ctor_thunks(objects);
    // Self-contained prologue prepended to the entry stub. x64: `sub rsp,0x28`
    // (reserve callee shadow space) + one `call rel32` per thunk + `add
    // rsp,0x28`. x86 (cdecl, no shadow space, parameterless thunks): just the
    // `call rel32` run. Each `call rel32` is 5 bytes; the encoding is identical
    // on both targets.
    let ctor_block_len: u32 = if ctor_thunks.is_empty() {
        0
    } else if is_pe32 {
        (ctor_thunks.len() * 5) as u32
    } else {
        (8 + ctor_thunks.len() * 5) as u32
    };
    // Stub length depends on both subsystem AND target arch. PE32+ uses
    // the historical x64 stubs; PE32 uses smaller x86 stubs (no shadow-
    // space reservation, push-based arg passing). The i386 GUI stub
    // (`WinMainCRTStartup`) pushes 4 zero args, calls WinMain, reclaims
    // them, and exits with the return value (see `GUI_STUB_LEN_X86`).
    let base_stub_len = if is_pe32 {
        match subsystem {
            Subsystem::Console => STUB_LEN_X86 as u32,
            Subsystem::Gui => GUI_STUB_LEN_X86 as u32,
        }
    } else {
        match subsystem {
            Subsystem::Console => STUB_LEN as u32,
            Subsystem::Gui => GUI_STUB_LEN as u32,
        }
    };
    // The CRT static-init block (if any) precedes the real entry stub.
    let stub_bytes_len = base_stub_len + ctor_block_len;

    // Reserve the entry-stub slot at the head of `.text`; per-object text
    // contributions append after.
    text_bytes.resize(stub_bytes_len as usize, 0u8);
    for (obj_ix, obj) in objects.iter().enumerate() {
        for (sec_ix, sec) in obj.sections.iter().enumerate() {
            let kind = match OutKind::from_section_name(&sec.name) {
                Some(k) => k,
                None => continue, // ignore .drectve etc.
            };
            let (buf, out): (&mut Vec<u8>, OutKind) = match kind {
                OutKind::Text => (&mut text_bytes, OutKind::Text),
                OutKind::Data => (&mut data_bytes, OutKind::Data),
                OutKind::Rdata => (&mut rdata_bytes, OutKind::Rdata),
                OutKind::Pdata => (&mut pdata_bytes, OutKind::Pdata),
                OutKind::Xdata => (&mut xdata_bytes, OutKind::Xdata),
            };
            let out_offset = buf.len() as u32;
            if sec.bss_size > 0 && sec.data.is_empty() {
                buf.resize(buf.len() + sec.bss_size as usize, 0);
            } else {
                buf.extend_from_slice(&sec.data);
            }
            place[obj_ix][sec_ix] = Some(SectionPlace {
                out,
                rva: 0, // patched below
                out_offset,
            });
        }
    }

    // ---- Pass 2 (RVA): assign final RVAs to each output section ---------
    let text_vsize = text_bytes.len() as u32;
    let text_rva = align_up(HEADERS_SIZE, SECT_ALIGN);

    let idata_rva = align_up(text_rva + text_vsize, SECT_ALIGN);
    let thunk_bytes = if is_pe32 { 4 } else { 8 };
    let idata = build_idata_from_objects(objects, idata_rva, thunk_bytes)?;
    let idata_vsize = idata.image.len() as u32;

    let rdata_rva = align_up(idata_rva + idata_vsize, SECT_ALIGN);
    let rdata_vsize_pre = rdata_bytes.len() as u32;
    let data_rva = align_up(rdata_rva + rdata_vsize_pre.max(1), SECT_ALIGN);
    let data_vsize = data_bytes.len() as u32;
    let pdata_rva = align_up(data_rva + data_vsize.max(1), SECT_ALIGN);
    let pdata_vsize = pdata_bytes.len() as u32;
    let xdata_rva = align_up(pdata_rva + pdata_vsize, SECT_ALIGN);
    let xdata_vsize = xdata_bytes.len() as u32;

    // Pad empty .rdata / .data with a single zero byte (matches legacy
    // writer). Done AFTER the RVA pass so cursors don't shift.
    if rdata_bytes.is_empty() {
        rdata_bytes.push(0);
    }
    if data_bytes.is_empty() {
        data_bytes.push(0);
    }

    // Patch each section's `rva` field based on its OutKind and
    // accumulated `out_offset`. Walk in the same (obj_ix, sec_ix) order
    // as Pass 1 so the cursor arithmetic matches the buffer layout.
    {
        let mut text_cursor = stub_bytes_len;
        let mut data_cursor = 0u32;
        let mut rdata_cursor = 0u32;
        let mut pdata_cursor = 0u32;
        let mut xdata_cursor = 0u32;
        for (obj_ix, obj) in objects.iter().enumerate() {
            for (sec_ix, sec) in obj.sections.iter().enumerate() {
                let Some(p) = place[obj_ix][sec_ix].as_mut() else {
                    continue;
                };
                let (rva_base, cursor) = match p.out {
                    OutKind::Text => (text_rva, &mut text_cursor),
                    OutKind::Data => (data_rva, &mut data_cursor),
                    OutKind::Rdata => (rdata_rva, &mut rdata_cursor),
                    OutKind::Pdata => (pdata_rva, &mut pdata_cursor),
                    OutKind::Xdata => (xdata_rva, &mut xdata_cursor),
                };
                p.rva = rva_base + *cursor;
                let size = if sec.bss_size > 0 && sec.data.is_empty() {
                    sec.bss_size
                } else {
                    sec.data.len() as u32
                };
                *cursor += size;
            }
        }
    }

    // ---- Pass 3: build per-object resolved symbol tables ----------------
    //
    // First pass: walk every input's symbol table, populate the per-object
    // `resolved` array for section-defined and absolute symbols. Section-
    // defined symbols always carry their owning section's RVA + symbol
    // offset. The global definition table is built simultaneously so we
    // can detect duplicates and resolve cross-object externals.
    let mut resolved: Vec<Vec<Option<ResolvedSym>>> = objects
        .iter()
        .map(|o| vec![None; o.symbols.len()])
        .collect();

    // Global table: name → (defining_obj_ix, defining_sym_ix). Built only
    // for EXTERNAL definitions (i.e. SectionRef::Section(_) symbols whose
    // storage is External, plus Absolute External symbols). Used by Pass
    // 3b to resolve undefined externals across inputs. BTreeMap keeps the
    // duplicate-detection iteration order deterministic.
    let mut global: std::collections::BTreeMap<String, (usize, usize)> =
        std::collections::BTreeMap::new();
    let mut duplicates: Vec<String> = Vec::new();

    for (obj_ix, obj) in objects.iter().enumerate() {
        for (sym_ix, sym) in obj.symbols.iter().enumerate() {
            let name = symbol_name_string(sym, &obj.strtab);
            match sym.section {
                SectionRef::Section(n) => {
                    let idx = (n as usize).saturating_sub(1);
                    if let Some(p) = place[obj_ix].get(idx).and_then(|p| *p) {
                        let final_rva = p.rva + sym.value;
                        resolved[obj_ix][sym_ix] = Some(ResolvedSym::Rva(final_rva));
                    }
                    // External + WeakExternal section-defined symbols enter
                    // the global table for cross-object resolution. STATIC
                    // symbols (section symbols + per-TU statics) are local to
                    // their input and never participate.
                    //
                    // S4.2af (COMDAT folding): a WeakExternal symbol marks an
                    // inline-emitted definition (header member/operator/
                    // template body) that EVERY using TU emits identically.
                    // On a cross-object duplicate:
                    //   * new WEAK            → FOLD: keep the first definition
                    //     (by-name refs resolve to it; this TU's own identical
                    //     copy still serves its intra-TU refs);
                    //   * new STRONG over WEAK → the strong definition wins;
                    //   * two STRONG          → a real `DuplicateSymbol`.
                    let is_def = matches!(
                        sym.storage,
                        StorageClass::External | StorageClass::WeakExternal
                    );
                    if is_def && !name.is_empty() {
                        if let Some(&(prev_obj, prev_sym)) = global.get(&name) {
                            if (prev_obj, prev_sym) != (obj_ix, sym_ix) {
                                let prev_weak = objects[prev_obj].symbols[prev_sym].storage
                                    == StorageClass::WeakExternal;
                                let new_weak = sym.storage == StorageClass::WeakExternal;
                                // W5: a strong duplicate where EITHER side comes
                                // from an archive-pulled member FOLDS (first
                                // definition wins, library order) instead of
                                // erroring — tlink/link.exe semantics: a library
                                // member's already-satisfied PUBDEF is ignored,
                                // only two EXPLICIT object files conflict. Borland
                                // ships TRect::Inflate strong in BOTH owl.lib and
                                // bids.lib; both members get pulled (for OTHER
                                // symbols), so the second copy must fold.
                                //
                                // Strong-over-weak still takes priority over
                                // library folding: archive-pulled inline wrappers
                                // must not hide the real out-of-line RTL body.
                                let lib_involved = opts
                                    .archive_origin
                                    .get(obj_ix)
                                    .copied()
                                    .unwrap_or(false)
                                    || opts.archive_origin.get(prev_obj).copied().unwrap_or(false);
                                if new_weak {
                                    // fold: keep the existing definition.
                                } else if prev_weak {
                                    global.insert(name, (obj_ix, sym_ix));
                                } else if lib_involved {
                                    // fold: keep the existing definition.
                                } else {
                                    duplicates.push(name);
                                }
                            }
                        } else {
                            global.insert(name, (obj_ix, sym_ix));
                        }
                    }
                }
                SectionRef::Absolute | SectionRef::Debug => {
                    resolved[obj_ix][sym_ix] = Some(ResolvedSym::Rva(sym.value));
                    if sym.storage == StorageClass::External
                        && matches!(sym.section, SectionRef::Absolute)
                        && !name.is_empty()
                    {
                        if let Some(&(prev_obj, prev_sym)) = global.get(&name) {
                            if (prev_obj, prev_sym) != (obj_ix, sym_ix) {
                                duplicates.push(name);
                            }
                        } else {
                            global.insert(name, (obj_ix, sym_ix));
                        }
                    }
                }
                SectionRef::Undefined => { /* resolved below in Pass 3b */ }
            }
        }
    }

    if !duplicates.is_empty() {
        duplicates.sort();
        duplicates.dedup();
        // The HLD error variant currently carries a single name; report
        // the first duplicate (alphabetical) — subsequent duplicates are
        // listed in the Display impl if we ever extend the variant.
        let name = duplicates.remove(0);
        return Err(LinkError::DuplicateSymbol { name });
    }

    // W6 (G54): TRUE COMDAT-any folding for WeakExternal definitions — a
    // WeakExternal copy that LOST the global-table fold redirects its OWN
    // resolution to the winner, so even INTRA-TU relocations land on the
    // single canonical copy. For inline functions this is behaviour-
    // preserving (the copies are identical); for the G54 EH identity
    // symbols (`@Tag@3` vtables, `@$xt$…` typeinfo) it is the semantics:
    // the personality compares type tags BY ADDRESS, so a class thrown in
    // one TU only matches a `catch` in another if both TUs' tags resolve
    // to the SAME RVA. Single-definition links are untouched (the winner
    // is the only copy).
    for (obj_ix, obj) in objects.iter().enumerate() {
        for (sym_ix, sym) in obj.symbols.iter().enumerate() {
            if sym.storage != StorageClass::WeakExternal
                || !matches!(sym.section, SectionRef::Section(_))
            {
                continue;
            }
            let name = symbol_name_string(sym, &obj.strtab);
            if let Some(&(def_obj, def_sym)) = global.get(&name)
                && (def_obj, def_sym) != (obj_ix, sym_ix)
                && let Some(rs) = resolved[def_obj][def_sym]
            {
                resolved[obj_ix][sym_ix] = Some(rs);
            }
        }
    }

    // Pass 3b: resolve undefined externals via the global table or the
    // import map. Unresolved-and-not-imported externals are tentative
    // (they may not be relocation-referenced); they only become hard
    // errors if a reloc actually targets them (caught in Pass 4 via
    // `apply_one_reloc`'s `target.ok_or_else`).
    let mut unresolved: Vec<(String, Option<(u32, u32)>)> = Vec::new();
    for (obj_ix, obj) in objects.iter().enumerate() {
        for (sym_ix, sym) in obj.symbols.iter().enumerate() {
            if !matches!(sym.section, SectionRef::Undefined) {
                continue;
            }
            if sym.storage != StorageClass::External && sym.storage != StorageClass::WeakExternal {
                continue;
            }
            let name = symbol_name_string(sym, &obj.strtab);
            if let Some(stripped) = name.strip_prefix("__imp_") {
                // Import: resolve via the IAT slot map.
                if let Some(&slot) = idata.iat_slot.get(stripped) {
                    resolved[obj_ix][sym_ix] = Some(ResolvedSym::ImportSlot(slot));
                } else {
                    let loc = obj.symbol_source_locs.get(sym_ix).copied().flatten();
                    unresolved.push((name.clone(), loc));
                }
            } else if let Some(&(def_obj, def_sym)) = global.get(&name) {
                // Cross-object resolution: inherit the defining object's
                // resolved RVA (a Section-defined symbol there).
                if let Some(rs) = resolved[def_obj][def_sym] {
                    resolved[obj_ix][sym_ix] = Some(rs);
                }
                // else: defining symbol's section was dropped (unlikely
                // for an External — leaves resolved[obj_ix][sym_ix] None
                // so a reloc against it fails loud in Pass 4).
            } else {
                // Truly undefined external. Marker stays None;
                // `apply_one_reloc` fails loud if a reloc targets it.
                // Symbols not referenced by any reloc (e.g. S1b.7
                // `extern_refs`) silently pass — matches legacy behaviour.
            }
        }
    }

    if !unresolved.is_empty() {
        unresolved.sort_by(|a, b| a.0.cmp(&b.0));
        unresolved.dedup_by(|a, b| a.0 == b.0);
        return Err(LinkError::UnresolvedExternals(unresolved));
    }

    // W6 (debugging aid): optional linker map — every GLOBAL definition's
    // final VA, sorted, written as plain text. A pure side effect (the PE
    // bytes are identical with or without it); failures to write are
    // surfaced on stderr but never fail the link.
    if let Some(map_path) = &opts.map {
        let map_base = if is_pe32 {
            IMAGE_BASE_PE32 as u64
        } else {
            IMAGE_BASE
        };
        let mut lines: Vec<(u64, String)> = global
            .iter()
            .filter_map(|(name, &(obj_ix, sym_ix))| match resolved[obj_ix][sym_ix] {
                Some(ResolvedSym::Rva(rva)) => Some((map_base + rva as u64, name.clone())),
                _ => None,
            })
            .collect();
        lines.sort();
        let mut text = String::with_capacity(lines.len() * 48);
        for (va, name) in &lines {
            use std::fmt::Write as _;
            let _ = writeln!(text, "{va:#010x} {name}");
        }
        if let Err(e) = std::fs::write(map_path, text) {
            eprintln!(
                "mdlink: warning: cannot write map '{}': {e}",
                map_path.display()
            );
        }
    }

    // ---- Pass 4: apply relocations --------------------------------------
    //
    // S2b.2d: absolute relocs (Addr32/DIR32 on i386) resolve to
    // `image_base + target_rva`, so they must use the SAME base the PE
    // header advertises. PE32 fixes the base at `IMAGE_BASE_PE32`
    // (0x00400000); PE32+ at `IMAGE_BASE` (0x1_4000_0000). The header
    // already writes the per-target base (see Pass 6); previously the
    // x64 `IMAGE_BASE` const was passed unconditionally here, which only
    // surfaced now that i386 grew its first absolute data reference (the
    // x64 path is REL32-only for `.text`, so its abs base is exercised
    // solely by Addr64 in `.data`/`.rdata`, where `IMAGE_BASE` is right).
    let reloc_image_base = if is_pe32 {
        IMAGE_BASE_PE32 as u64
    } else {
        IMAGE_BASE
    };
    // W5 dead-strip: compute relocations in unreachable archive units so the
    // resolver ignores their undefined references (linker-level GC; see
    // `compute_dead_relocs`). Empty when all objects are explicit.
    let dead_relocs = compute_dead_relocs(objects, &opts.archive_origin, &global);
    apply_relocs_multi(
        objects,
        &place,
        &resolved,
        &global,
        &idata,
        reloc_image_base,
        &dead_relocs,
        &mut text_bytes,
        &mut data_bytes,
        &mut rdata_bytes,
        &mut pdata_bytes,
        &mut xdata_bytes,
    )?;

    // ---- Pass 5: synthesise the entry stub ------------------------------
    let entry_name: &str = match (opts.entry.as_deref(), subsystem) {
        (Some(n), _) => n,
        (None, Subsystem::Console) => "main",
        (None, Subsystem::Gui) => "WinMain",
    };
    let entry_rva = resolved_symbol_rva_multi(objects, &resolved, entry_name).ok_or_else(|| {
        LinkError::Internal(format!(
            "no '{entry_name}' function defined (entry symbol not \
             found in any input)"
        ))
    })?;
    let exit_slot = idata
        .iat_slot
        .get("ExitProcess")
        .copied()
        .ok_or_else(|| LinkError::Internal("ExitProcess IAT slot missing".into()))?;

    // #20 PART 2b: emit the CRT static-init call block (if any) at the head of
    // .text, then the real entry stub immediately after it. The stub's RIP-
    // relative offsets are computed against its shifted base (text_rva +
    // ctor_block_len), so a subslice + adjusted base needs no change to
    // write_entry_stub itself; ctor_block_len == 0 ⇒ byte-identical.
    if ctor_block_len > 0 {
        emit_ctor_init_block(
            &mut text_bytes[..ctor_block_len as usize],
            &ctor_thunks,
            objects,
            &resolved,
            is_pe32,
            text_rva,
        )?;
    }
    write_entry_stub(
        &mut text_bytes[ctor_block_len as usize..],
        subsystem,
        is_pe32,
        entry_rva,
        text_rva + ctor_block_len,
        exit_slot,
    );

    // ---- Pass 6: data directories, headers, layout finalisation ---------
    let rdata_vsize_final = rdata_bytes.len() as u32;
    let data_vsize_final = data_bytes.len() as u32;

    let text_raw = align_up(text_vsize, FILE_ALIGN);
    let idata_raw = align_up(idata_vsize, FILE_ALIGN);
    let rdata_raw = align_up(rdata_vsize_final, FILE_ALIGN);
    let data_raw = align_up(data_vsize_final, FILE_ALIGN);
    let pdata_raw = align_up(pdata_vsize, FILE_ALIGN);
    let xdata_raw = align_up(xdata_vsize, FILE_ALIGN);

    let text_file_off = HEADERS_SIZE;
    let idata_file_off = text_file_off + text_raw;
    let rdata_file_off = idata_file_off + idata_raw;
    let data_file_off = rdata_file_off + rdata_raw;
    let pdata_file_off = data_file_off + data_raw;
    let xdata_file_off = pdata_file_off + pdata_raw;

    let has_seh = pdata_vsize > 0 || xdata_vsize > 0;
    // PE32 carries NO .pdata/.xdata: x86 SEH is fs:[0]-based, lowered inline
    // into .text by the codegen (S2e — per-function EXCEPTION_REGISTRATION
    // prologue/epilogue + the module-wide `.mdbcc_seh3_handler`; HLD §5.3 /
    // §7). The COFF converter gates `.pdata`/`.xdata` emission on Win64
    // (`object.rs::needs_eh`), so a PE32 Object should never present them.
    // This stays as a defensive backstop: if a future change reintroduces
    // table-based SEH for i386, fail loudly rather than emit a malformed PE32.
    if is_pe32 && has_seh {
        return Err(LinkError::Internal(
            "PE32 with table-based SEH (.pdata/.xdata) — i386 must use the \
             fs:[0] chain (lowered inline into .text), not exception tables"
                .into(),
        ));
    }
    let mut n_sections: u16 = 4;
    if has_seh {
        n_sections += 2;
    }
    let size_of_image = if has_seh {
        align_up(xdata_rva + xdata_vsize, SECT_ALIGN)
    } else {
        align_up(data_rva + data_vsize_final, SECT_ALIGN)
    };

    let mut b = Buf::new();
    write_dos_header(&mut b);
    debug_assert_eq!(b.len(), PE_OFF);

    // PE signature + COFF file header. (HLD §5.1 — Magic/SizeOfOptHdr
    // diverge between PE32+ and PE32; everything else here is shared.)
    b.bytes(b"PE\0\0");
    b.u16(if is_pe32 { 0x014C } else { 0x8664 });
    b.u16(n_sections);
    b.u32(0);
    b.u32(0);
    b.u32(0);
    b.u16(if is_pe32 { 0xE0 } else { 0xF0 });
    // Characteristics. PE32+: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE.
    // PE32: EXECUTABLE_IMAGE | 32BIT_MACHINE | RELOCS_STRIPPED
    // (per Q-Reloc — fixed ImageBase, no .reloc section).
    b.u16(if is_pe32 { 0x0103 } else { 0x0022 });

    // Optional header. Layout diverges per HLD §5.1:
    //   PE32+ : Magic | LinkerVer | SizeOfCode | SizeOfInitData |
    //           SizeOfUninit | EntryPoint | BaseOfCode | ImageBase(u64)
    //           | SectAlign | FileAlign | OS | ... | Stack/Heap(u64) | ...
    //   PE32  : Magic | LinkerVer | SizeOfCode | SizeOfInitData |
    //           SizeOfUninit | EntryPoint | BaseOfCode | BaseOfData(u32)
    //           | ImageBase(u32) | SectAlign | FileAlign | OS | ... |
    //           Stack/Heap(u32) | ...
    // The two have the SAME size up to ImageBase (PE32 inserts
    // BaseOfData; PE32+ widens ImageBase to u64). The 16-byte size
    // difference comes from the four Stack/Heap fields (u32 vs u64).
    b.u16(if is_pe32 { 0x010B } else { 0x020B });
    // PE32 targets old Borland/OWL-era Win32 programs. Match the BC4.5
    // linker metadata because Windows still uses these fields for legacy
    // app-compat decisions that affect dialog font/base-unit sizing.
    b.u8(if is_pe32 { 2 } else { 14 });
    b.u8(if is_pe32 { 25 } else { 0 });
    b.u32(text_raw);
    b.u32(idata_raw + rdata_raw + data_raw + pdata_raw + xdata_raw);
    b.u32(0);
    b.u32(text_rva);
    b.u32(text_rva);
    if is_pe32 {
        b.u32(rdata_rva); // BaseOfData (PE32-only field — RVA of first
        // initialized-data section, conventionally the
        // start of `.rdata`).
        b.u32(IMAGE_BASE_PE32); // ImageBase (u32) = 0x00400000.
    } else {
        b.u64(IMAGE_BASE); // ImageBase (u64) = 0x0000_0001_4000_0000.
    }
    b.u32(SECT_ALIGN);
    b.u32(FILE_ALIGN);
    b.u16(OS_VERSION.0); // MajorOSVersion
    b.u16(OS_VERSION.1);
    b.u16(0);
    b.u16(0);
    b.u16(SUBSYSTEM_VERSION.0); // MajorSubsystemVersion
    b.u16(SUBSYSTEM_VERSION.1); // MinorSubsystemVersion
    b.u32(0);
    b.u32(size_of_image);
    b.u32(HEADERS_SIZE);
    b.u32(0);
    b.u16(match subsystem {
        Subsystem::Console => 3,
        Subsystem::Gui => 2,
    });
    b.u16(0);
    if is_pe32 {
        b.u32(opts.stack_reserve as u32);
        b.u32(opts.stack_commit as u32);
        b.u32(opts.heap_reserve as u32);
        b.u32(opts.heap_commit as u32);
    } else {
        b.u64(opts.stack_reserve);
        b.u64(opts.stack_commit);
        b.u64(opts.heap_reserve);
        b.u64(opts.heap_commit);
    }
    b.u32(0);
    b.u32(16);

    let mut dirs = [(0u32, 0u32); 16];
    dirs[1] = (idata.import_dir_rva, idata.import_dir_size);
    dirs[12] = (idata.iat_rva, idata.iat_size);
    if has_seh {
        dirs[3] = (pdata_rva, pdata_vsize);
    }
    for (rva, size) in dirs {
        b.u32(rva);
        b.u32(size);
    }

    // Section headers.
    write_section_header(
        &mut b,
        b".text",
        text_vsize,
        text_rva,
        text_raw,
        text_file_off,
        0x6000_0020,
    );
    write_section_header(
        &mut b,
        b".idata",
        idata_vsize,
        idata_rva,
        idata_raw,
        idata_file_off,
        0xC000_0040,
    );
    write_section_header(
        &mut b,
        b".rdata",
        rdata_vsize_final,
        rdata_rva,
        rdata_raw,
        rdata_file_off,
        0x4000_0040,
    );
    write_section_header(
        &mut b,
        b".data",
        data_vsize_final,
        data_rva,
        data_raw,
        data_file_off,
        0xC000_0040,
    );
    if has_seh {
        write_section_header(
            &mut b,
            b".pdata",
            pdata_vsize,
            pdata_rva,
            pdata_raw,
            pdata_file_off,
            0x4000_0040,
        );
        write_section_header(
            &mut b,
            b".xdata",
            xdata_vsize,
            xdata_rva,
            xdata_raw,
            xdata_file_off,
            0x4000_0040,
        );
    }

    // Section data.
    b.pad_to(text_file_off as usize);
    b.bytes(&text_bytes);
    b.pad_to(idata_file_off as usize);
    b.bytes(&idata.image);
    b.pad_to(rdata_file_off as usize);
    b.bytes(&rdata_bytes);
    b.pad_to(data_file_off as usize);
    b.bytes(&data_bytes);
    b.pad_to((data_file_off + data_raw) as usize);
    if has_seh {
        b.pad_to(pdata_file_off as usize);
        b.bytes(&pdata_bytes);
        b.pad_to((pdata_file_off + pdata_raw) as usize);
        b.pad_to(xdata_file_off as usize);
        b.bytes(&xdata_bytes);
        b.pad_to((xdata_file_off + xdata_raw) as usize);
    }

    Ok(b.0)
}

/// #20 PART 2b: collect every CRT static-init thunk across all inputs, in
/// deterministic input-then-symbol order. A thunk is a DEFINED external symbol
/// whose name carries the reserved `.mdbcc_ctor.` prefix (bcc emits one per
/// constructor-initialised file-scope object in a main-less TU). Duplicates
/// (COMDAT-folded across TUs) are de-duplicated, first occurrence wins — so the
/// object is constructed exactly once.
fn collect_ctor_thunks(objects: &[&coff::Object]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for obj in objects {
        for sym in &obj.symbols {
            if matches!(sym.section, SectionRef::Undefined) {
                continue;
            }
            if sym.storage != StorageClass::External {
                continue;
            }
            let name = symbol_name_string(sym, &obj.strtab);
            if name.starts_with(".mdbcc_ctor.") && seen.insert(name.clone()) {
                out.push(name);
            }
        }
    }
    // W6 (G48): `#pragma startup` thunks (`.mdbcc_ctor.$startup$NNN$<fn>`,
    // NNN = zero-padded priority) run FIRST, ascending NNN — Borland's
    // INIT-record order, where the RTL's 0–63 priorities (heap 2, argv 3,
    // handles 4, streams 5, cvt 10, iostream 16) precede every C++ static
    // ctor. Plain ctor thunks keep their historical first-seen object order
    // after them (stable sort on the bucket key only). A TU with no startup
    // pragma produces no `$startup$` names ⇒ order byte-identical.
    out.sort_by(|a, b| {
        const P: &str = ".mdbcc_ctor.$startup$";
        match (a.strip_prefix(P), b.strip_prefix(P)) {
            (Some(x), Some(y)) => x.cmp(y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
    out
}

/// #20 PART 2b: emit the CRT static-init call block at the head of `.text`.
/// x64: `sub rsp,0x28` (reserve callee shadow space) + one `call rel32` per
/// thunk (in `thunks` order) + `add rsp,0x28`. x86: just the `call rel32` run
/// (cdecl, parameterless thunks need no shadow space or stack cleanup). The
/// block sits at offset 0, so a call at block offset `off` has RIP-next
/// `text_rva + off + 5`. `block.len()` was sized by the same arithmetic in
/// `write_pe_from_objects`, so the writes land exactly.
fn emit_ctor_init_block(
    block: &mut [u8],
    thunks: &[String],
    objects: &[&coff::Object],
    resolved: &[Vec<Option<ResolvedSym>>],
    is_pe32: bool,
    text_rva: u32,
) -> Result<(), LinkError> {
    let mut off: usize = 0;
    if !is_pe32 {
        block[0..4].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp,0x28
        off = 4;
    }
    for name in thunks {
        let target = resolved_symbol_rva_multi(objects, resolved, name).ok_or_else(|| {
            LinkError::Internal(format!(
                "CRT static-init thunk '{name}' not found in any input"
            ))
        })?;
        block[off] = 0xE8; // call rel32
        let rel = target as i64 - (text_rva as i64 + off as i64 + 5);
        block[off + 1..off + 5].copy_from_slice(&(rel as i32).to_le_bytes());
        off += 5;
    }
    if !is_pe32 {
        block[off..off + 4].copy_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp,0x28
    }
    Ok(())
}

/// Helper: extract a symbol's name as a `String` (handles both Short and
/// Long forms).
fn symbol_name_string(sym: &coff::Symbol, strtab: &coff::StringTable) -> String {
    match &sym.name {
        coff::SymName::Short(arr) => {
            let end = arr.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&arr[..end]).into_owned()
        }
        coff::SymName::Long(off) => strtab
            .get_str(*off)
            .map(|s| s.to_string())
            .unwrap_or_default(),
    }
}

/// Helper: look up a defined symbol's RVA across all inputs by name.
/// Walks objects in input order; first match wins. Used by Pass 5 to
/// locate the entry-point symbol (`main` / `WinMain`) in the merged
/// image.
fn resolved_symbol_rva_multi(
    objects: &[&coff::Object],
    resolved: &[Vec<Option<ResolvedSym>>],
    name: &str,
) -> Option<u32> {
    for (obj_ix, obj) in objects.iter().enumerate() {
        for (i, sym) in obj.symbols.iter().enumerate() {
            // External + Static (the converter emits the user's main /
            // WinMain as External; some converters / libs use Static for
            // similar effect — accept both, matching legacy single-obj
            // behaviour).
            if sym.storage != StorageClass::External && sym.storage != StorageClass::Static {
                continue;
            }
            let s = symbol_name_string(sym, &obj.strtab);
            if s != name {
                continue;
            }
            if let Some(ResolvedSym::Rva(rva)) = resolved[obj_ix][i] {
                return Some(rva);
            }
        }
    }
    None
}

/// Synthesise the entry stub at offset 0 of `.text`. Four variants:
/// x64 console, x64 GUI (both = legacy `build_text` byte-for-byte), x86
/// console (PE32, 13 bytes), and x86 GUI (PE32, 24 bytes).
fn write_entry_stub(
    text: &mut [u8],
    subsystem: Subsystem,
    is_pe32: bool,
    entry_rva: u32,
    text_rva: u32,
    exit_slot_rva: u32,
) {
    if is_pe32 {
        match subsystem {
            Subsystem::Console => {
                // x86 console stub (PE32, 13 bytes):
                //   E8 <rel32>      call main          ; eax = return value
                //   50              push eax           ; arg to ExitProcess
                //   FF 15 <addr32>  call [ExitProcess] ; absolute addr (cdecl)
                //   F4              hlt                ; defensive
                // The stub occupies the reserved PREFIX of `.text`; user code
                // is appended after it (see `text_bytes.resize(stub_bytes_len)`
                // in `write_pe_from_objects`), so assert the buffer is at least
                // stub-sized — NOT exactly (the x64 paths below do the same).
                debug_assert!(text.len() >= STUB_LEN_X86);
                text[0] = 0xE8;
                // rel32 measured from the byte AFTER the call (offset 5).
                let call_rel = entry_rva as i64 - (text_rva as i64 + 5);
                text[1..5].copy_from_slice(&(call_rel as i32).to_le_bytes());
                text[5] = 0x50; // push eax
                text[6] = 0xFF;
                text[7] = 0x15;
                // Absolute 32-bit address of the IAT slot: ImageBase + slot RVA.
                let abs = IMAGE_BASE_PE32 + exit_slot_rva;
                text[8..12].copy_from_slice(&abs.to_le_bytes());
                text[12] = 0xF4; // hlt
            }
            Subsystem::Gui => {
                // x86 GUI stub (PE32, 27 bytes) — `WinMainCRTStartup`. Push the
                // four WinMain args right-to-left so they sit at [esp+0]=hInstance
                // .. [esp+12]=nCmdShow, call WinMain, reclaim the 16 arg bytes,
                // then exit with the return value. Two args are LOAD-BEARING for
                // a real OWL app (see GUI_STUB_LEN_X86 doc): nCmdShow=1 (else the
                // main window is SW_HIDE), hInstance=ImageBase (else every
                // EXE-resource load / Ctl3dRegister gets a NULL module handle).
                //   6A 01          push 1            ; nCmdShow = SW_SHOWNORMAL
                //   6A 00          push 0            ; lpCmdLine = NULL
                //   6A 00          push 0            ; hPrevInstance = NULL
                //   68 <imm32>     push ImageBase    ; hInstance = module base
                //   E8 <rel32>     call WinMain
                //   83 C4 10       add esp, 16
                //   50             push eax          ; arg to ExitProcess
                //   FF 15 <addr32> call [ExitProcess]
                //   F4             hlt               ; defensive
                // Stub occupies the reserved PREFIX of `.text`; user code is
                // appended after it — assert at-least-stub-sized, matching the
                // x64 paths (which write into `text[0..N]` of a larger buffer).
                debug_assert!(text.len() >= GUI_STUB_LEN_X86);
                // push nCmdShow=1, lpCmdLine=NULL, hPrevInstance=NULL
                text[0..6].copy_from_slice(&[0x6A, 0x01, 0x6A, 0x00, 0x6A, 0x00]);
                // push hInstance = ImageBase (fixed base, no .reloc => == module handle)
                text[6] = 0x68;
                text[7..11].copy_from_slice(&IMAGE_BASE_PE32.to_le_bytes());
                text[11] = 0xE8; // call WinMain
                // rel32 measured from the byte AFTER the call (offset 16).
                let call_rel = entry_rva as i64 - (text_rva as i64 + 16);
                text[12..16].copy_from_slice(&(call_rel as i32).to_le_bytes());
                text[16..19].copy_from_slice(&[0x83, 0xC4, 0x10]); // add esp, 16
                text[19] = 0x50; // push eax
                text[20] = 0xFF;
                text[21] = 0x15;
                let abs = IMAGE_BASE_PE32 + exit_slot_rva;
                text[22..26].copy_from_slice(&abs.to_le_bytes());
                text[26] = 0xF4; // hlt
            }
        }
        return;
    }
    match subsystem {
        Subsystem::Console => {
            // sub rsp, 0x28
            text[0..4].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
            // call entry (E8 + rel32 from offset 5 to 9)
            text[4] = 0xE8;
            let call_rel = entry_rva as i64 - (text_rva as i64 + 0x09);
            text[5..9].copy_from_slice(&(call_rel as i32).to_le_bytes());
            // mov ecx, eax
            text[9] = 0x89;
            text[10] = 0xC1;
            // call qword ptr [rip+disp] -> ExitProcess
            text[11] = 0xFF;
            text[12] = 0x15;
            let disp = exit_slot_rva as i64 - (text_rva as i64 + 0x11);
            text[13..17].copy_from_slice(&(disp as i32).to_le_bytes());
            // hlt
            text[17] = 0xF4;
        }
        Subsystem::Gui => {
            // sub rsp, 0x28
            text[0..4].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
            // mov rcx, IMAGE_BASE
            text[4] = 0x48;
            text[5] = 0xB9;
            text[6..14].copy_from_slice(&IMAGE_BASE.to_le_bytes());
            // xor rdx, rdx
            text[14..17].copy_from_slice(&[0x48, 0x31, 0xD2]);
            // xor r8, r8
            text[17..20].copy_from_slice(&[0x4D, 0x31, 0xC0]);
            // mov r9d, 1
            text[20..26].copy_from_slice(&[0x41, 0xB9, 0x01, 0x00, 0x00, 0x00]);
            // call WinMain
            text[26] = 0xE8;
            let call_rel = entry_rva as i64 - (text_rva as i64 + 0x1F);
            text[27..31].copy_from_slice(&(call_rel as i32).to_le_bytes());
            // mov ecx, eax
            text[31] = 0x89;
            text[32] = 0xC1;
            // call qword ptr [rip+disp]
            text[33] = 0xFF;
            text[34] = 0x15;
            let disp = exit_slot_rva as i64 - (text_rva as i64 + 0x27);
            text[35..39].copy_from_slice(&(disp as i32).to_le_bytes());
            // hlt
            text[39] = 0xF4;
        }
    }
}

/// Build the `.idata` image from the union of every input Object's
/// UNDEFINED EXTERNAL `__imp_*` symbols. Reuses the existing `emit_idata`
/// machinery; the only difference from the Module-driven `build_idata` is
/// the multi-input symbol-source walk.
///
/// Same hard-error semantics as the single-object path: an import name
/// absent from `WIN32_IMPORTS` is a `LinkError::UnresolvedExternals`.
/// For single-input the byte output is byte-identical to the previous
/// `build_idata_from_object` because `BTreeSet`'s deterministic
/// iteration and the `WIN32_IMPORTS`-ordered DLL grouping are unchanged.
///
/// `thunk_bytes` selects the ILT/IAT thunk width — 8 for PE32+ (x64), 4 for
/// PE32 (x86). The loader walks the thunk arrays at the image's native
/// pointer width, so a PE32 image MUST use 4-byte thunks; using 8 leaves a
/// zero high-DWORD after the first thunk that the loader reads as the array
/// terminator, silently dropping every import after the first (S2b.2e: this
/// only surfaced once a TU imported more than ExitProcess).
fn build_idata_from_objects(
    objects: &[&coff::Object],
    idata_rva: u32,
    thunk_bytes: u32,
) -> Result<Idata, LinkError> {
    let mut used: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for obj in objects {
        for sym in &obj.symbols {
            if !matches!(sym.section, SectionRef::Undefined) {
                continue;
            }
            if sym.storage != StorageClass::External && sym.storage != StorageClass::WeakExternal {
                continue;
            }
            let name = symbol_name_string(sym, &obj.strtab);
            if let Some(stripped) = name.strip_prefix("__imp_") {
                used.insert(stripped.to_string());
            }
        }
    }

    let mut bad: Vec<(String, Option<(u32, u32)>)> = Vec::new();
    for name in &used {
        if !WIN32_IMPORTS.iter().any(|(s, _)| *s == name.as_str()) {
            bad.push((format!("__imp_{name}"), None));
        }
    }
    if !bad.is_empty() {
        return Err(LinkError::UnresolvedExternals(bad));
    }

    let mut dlls: Vec<&'static str> = Vec::new();
    for (sym_name, dll) in WIN32_IMPORTS {
        let is_used = *dll == STUB_DLL || used.contains(*sym_name);
        if is_used && !dlls.contains(dll) {
            dlls.push(dll);
        }
    }
    // PE32 (x86) MUST prune to the symbols actually referenced. The x64
    // table maps `RtlUnwindEx` to KERNEL32 (correct on 64-bit Windows, where
    // it is a kernel32 forwarder), but the 32-bit `SysWOW64\kernel32.dll`
    // does NOT export it (it lives in 32-bit ntdll). The historical x64
    // "import every WIN32_IMPORTS symbol of a used DLL" aggregation would
    // therefore drag `RtlUnwindEx` into a plain `puts` program's i386 IAT
    // and the loader would reject the image (STATUS_ENTRYPOINT_NOT_FOUND).
    // Per-symbol pruning fixes this and is correct in general (the comment on
    // the x64 path already flags it as a deferred optimization). We gate it on
    // PE32 so the x64 `.idata` — and every golden lock in `tests/pe_imports.rs`
    // — stays byte-for-byte unchanged. `ExitProcess` (the entry-stub call) is
    // always kept even when the program never names it.
    let prune = thunk_bytes == 4;
    let groups: Vec<DllImports<'static>> = dlls
        .into_iter()
        .map(|dll| DllImports {
            name: dll,
            symbols: WIN32_IMPORTS
                .iter()
                .filter(|(_, d)| *d == dll)
                // S2e: x86-only symbols never enter a PE32+ (x64) image. On
                // PE32 (`prune`) they ride the per-symbol `used` filter; on
                // x64 (non-pruning) they must be excluded so the x64 idata
                // stays byte-identical.
                .filter(|(s, _)| prune || !WIN32_IMPORTS_X64_EXCLUDE.contains(s))
                .filter(|(s, _)| {
                    // S6: EXTENDED_ON_DEMAND imports are per-symbol-pruned on
                    // BOTH targets (emitted only when actually referenced), so a
                    // program that does not call one stays byte-identical even on
                    // the non-pruning x64 path. The historical group keeps its
                    // always-emit-on-x64 behaviour (locked by the goldens).
                    if EXTENDED_ON_DEMAND.contains(s) {
                        used.contains(*s)
                    } else {
                        !prune || used.contains(*s) || (dll == STUB_DLL && *s == "ExitProcess")
                    }
                })
                .map(|(s, _)| *s)
                .collect(),
        })
        .collect();

    Ok(emit_idata_with_thunk(&groups, idata_rva, thunk_bytes))
}

/// W5 dead-strip (linker-level garbage collection). Returns the set of
/// relocations — keyed `(obj_ix, sec_ix, reloc_offset)` — that live in an
/// UNREACHABLE function/data unit of an ARCHIVE-pulled object, so the resolver
/// can ignore their undefined references. This matches what tlink32 + a
/// fine-grained static library do: only the code transitively reached from the
/// explicit objects is linked.
///
/// ## Why this exists (railc closure root cause)
///
/// mdbcc compiles one coarse `.o` per `.CPP` (all of a class's methods in one
/// object). A COFF/lib link pulls WHOLE objects to satisfy any one symbol, so
/// pulling `APPLICAT.o` for `TApplication`'s ctor (which railc references) drags
/// in TApplication's DEAD doc-manager methods, whose references to `TDocManager`
/// then cascade the entire unused doc/view framework into the closure. tlink32 +
/// the fine-grained `OWLWF.LIB` avoid this; the golden railc.exe contains none
/// of it (`TDocument`/`TView` appear zero times). Per-function reachability GC
/// reproduces that pruning WITHOUT changing the `.o` layout (so the `.obj`↔bcc32
/// byte-identity oracle is preserved) — it is a pure linker analysis.
///
/// ## Algorithm
///
/// A "unit" is the code/data owned by one defined symbol: the byte range from
/// that symbol's value (offset) up to the next defined symbol in the same
/// section. Roots are every unit of every EXPLICIT (non-archive) object —
/// railc's own objects link whole; only archive members are GC'd. Edges follow
/// each relocation to the unit defining its target (intra-object `Section`
/// symbols directly; cross-object externals via `global`). Reachability is the
/// BFS closure; a relocation in a non-reachable archive unit is "dead".
///
/// When every object is explicit (single-object links / empty `archive_origin`)
/// the result is empty and resolution is unchanged.
fn compute_dead_relocs(
    objects: &[&coff::Object],
    archive_origin: &[bool],
    global: &std::collections::BTreeMap<String, (usize, usize)>,
) -> std::collections::HashSet<(usize, usize, u32)> {
    use std::collections::HashSet;
    let explicit = |oi: usize| !archive_origin.get(oi).copied().unwrap_or(false);

    // Per (obj, sec): sorted distinct unit-start offsets — every section-defined
    // symbol's value, plus 0 so leading bytes always belong to some unit.
    let mut starts: Vec<Vec<Vec<u32>>> = objects
        .iter()
        .map(|o| o.sections.iter().map(|_| vec![0u32]).collect())
        .collect();
    for (oi, obj) in objects.iter().enumerate() {
        for sym in &obj.symbols {
            if let SectionRef::Section(n) = sym.section {
                let si = (n as usize).saturating_sub(1);
                if let Some(v) = starts[oi].get_mut(si) {
                    v.push(sym.value);
                }
            }
        }
    }
    for o in &mut starts {
        for s in o {
            s.sort_unstable();
            s.dedup();
        }
    }
    let unit_of = |oi: usize, si: usize, off: u32| -> usize {
        starts[oi][si]
            .partition_point(|&x| x <= off)
            .saturating_sub(1)
    };

    // BFS over units; seed with every unit of every explicit object.
    let mut reachable: HashSet<(usize, usize, usize)> = HashSet::new();
    let mut work: Vec<(usize, usize, usize)> = Vec::new();
    for (oi, obj_starts) in starts.iter().enumerate() {
        if !explicit(oi) {
            continue;
        }
        for (si, sec_starts) in obj_starts.iter().enumerate() {
            for ui in 0..sec_starts.len() {
                if reachable.insert((oi, si, ui)) {
                    work.push((oi, si, ui));
                }
            }
        }
    }
    // W6: CRT static-init thunks (`.mdbcc_ctor.*`) are CALLED unconditionally
    // by the synthesized entry stub (collect_ctor_thunks gathers them from
    // EVERY input, archive members included), so they are reachability ROOTS
    // exactly like explicit objects. Without this, an unresolved external
    // reachable ONLY through an archive member's ctor thunk was misclassified
    // dead — its reloc skipped, leaving a silent zero-displacement `call`
    // (OBJSTRM.o's TStreamableTypes ctor never constructed its vector; the
    // first streamable registration then dispatched through a garbage vptr).
    for (oi, obj) in objects.iter().enumerate() {
        if explicit(oi) {
            continue; // already fully seeded
        }
        for sym in &obj.symbols {
            let SectionRef::Section(n) = sym.section else {
                continue;
            };
            let name = symbol_name_string(sym, &obj.strtab);
            if !name.starts_with(".mdbcc_ctor.") {
                continue;
            }
            let si = (n as usize).saturating_sub(1);
            if si >= starts[oi].len() {
                continue;
            }
            let ui = unit_of(oi, si, sym.value);
            if reachable.insert((oi, si, ui)) {
                work.push((oi, si, ui));
            }
        }
    }
    while let Some((oi, si, ui)) = work.pop() {
        let start = starts[oi][si][ui];
        let end = starts[oi][si].get(ui + 1).copied().unwrap_or(u32::MAX);
        for r in &objects[oi].sections[si].relocs {
            if r.offset < start || r.offset >= end {
                continue;
            }
            let Some(tsym) = objects[oi].symbols.get(r.symbol as usize) else {
                continue;
            };
            let (toi, tsi, tval) = match tsym.section {
                SectionRef::Section(n) => (oi, (n as usize).saturating_sub(1), tsym.value),
                SectionRef::Undefined => {
                    let name = symbol_name_string(tsym, &objects[oi].strtab);
                    match global.get(&name) {
                        Some(&(doi, dsi)) => {
                            let dsym = &objects[doi].symbols[dsi];
                            if let SectionRef::Section(n) = dsym.section {
                                (doi, (n as usize).saturating_sub(1), dsym.value)
                            } else {
                                continue;
                            }
                        }
                        None => continue,
                    }
                }
                _ => continue,
            };
            if tsi >= starts[toi].len() {
                continue;
            }
            let tui = unit_of(toi, tsi, tval);
            if reachable.insert((toi, tsi, tui)) {
                work.push((toi, tsi, tui));
            }
        }
    }

    // Dead relocs: archive-object relocs whose owning unit was never reached.
    // (Explicit objects are linked whole — their refs are never stripped.)
    let mut dead: HashSet<(usize, usize, u32)> = HashSet::new();
    for (oi, obj) in objects.iter().enumerate() {
        if explicit(oi) {
            continue;
        }
        for (si, sec) in obj.sections.iter().enumerate() {
            for r in &sec.relocs {
                let ui = unit_of(oi, si, r.offset);
                if !reachable.contains(&(oi, si, ui)) {
                    dead.insert((oi, si, r.offset));
                }
            }
        }
    }
    dead
}

/// Apply every relocation from every input section across every input
/// Object to its containing output buffer.
///
/// Each `RelocKind` patches the appropriate field width per AMD64 semantics:
/// - `Addr64`: write `image_base + target_rva` at `bytes[off..off+8]`.
/// - `Addr32`: write low 32 bits of `image_base + target_rva` at off..off+4.
/// - `Addr32nb`: write `target_rva + addend` (addend = current 4 bytes).
/// - `Rel32`: write `target_rva - (reloc_site_rva + 4 + addend)`.
/// - `SectionIx` / `SecRel32`: not emitted by current mdbcc / not
///   linker-relevant for the EXE shape we ship; rejected.
///
/// Multi-input note: `r.symbol` is per-object (the symbol index in the
/// owning Object's symbol table). For Section-defined symbols the lookup
/// is local. For undefined externals we consult the global table to
/// inherit the defining input's resolved RVA. The `__imp_*` import
/// short-circuit (resolved in Pass 3b) writes the IAT slot RVA directly.
#[allow(clippy::too_many_arguments)] // 5 mutable section buffers + bookkeeping; bundling adds layers without semantic clarity.
fn apply_relocs_multi(
    objects: &[&coff::Object],
    place: &[Vec<Option<SectionPlace>>],
    resolved: &[Vec<Option<ResolvedSym>>],
    global: &std::collections::BTreeMap<String, (usize, usize)>,
    idata: &Idata,
    image_base: u64,
    dead: &std::collections::HashSet<(usize, usize, u32)>,
    text: &mut [u8],
    data: &mut [u8],
    rdata: &mut [u8],
    pdata: &mut [u8],
    xdata: &mut [u8],
) -> Result<(), LinkError> {
    // S5: accumulate EVERY reloc-referenced unresolved target into one batch
    // (was: bail at the first via `apply_one_reloc`'s `?`). The single-symbol
    // failure masked the true closure — a bisection oracle saw "1 unresolved"
    // when hundreds were missing. Reporting all at once makes the link the
    // honest closure oracle the GOAL's bisection step relies on. (A reloc-
    // UNREFERENCED undefined external still passes silently — a declared-but-
    // uncalled extern emits no code, matching legacy behaviour.)
    let mut unresolved: Vec<(String, Option<(u32, u32)>)> = Vec::new();
    for (obj_ix, obj) in objects.iter().enumerate() {
        for (sec_ix, sec) in obj.sections.iter().enumerate() {
            let Some(sec_place) = place[obj_ix][sec_ix] else {
                continue;
            };
            // The output buffer for this section's contribution.
            let buf: &mut [u8] = match sec_place.out {
                OutKind::Text => text,
                OutKind::Data => data,
                OutKind::Rdata => rdata,
                OutKind::Pdata => pdata,
                OutKind::Xdata => xdata,
            };
            for r in &sec.relocs {
                let in_buf_off = (sec_place.out_offset + r.offset) as usize;
                // Look up the target symbol's resolved RVA. For
                // Section-defined symbols the entry was filled in Pass 3.
                // For undefined externals, Pass 3b populated `resolved`
                // for `__imp_*` imports; for plain externals we fall
                // through to the global table here so a reloc against an
                // unresolved-tentative symbol can still find the cross-
                // object definer.
                let mut target = resolved[obj_ix].get(r.symbol as usize).and_then(|x| *x);
                if target.is_none() {
                    let sym = obj.symbols.get(r.symbol as usize);
                    if let Some(sym) = sym
                        && matches!(sym.section, SectionRef::Undefined)
                    {
                        let name = symbol_name_string(sym, &obj.strtab);
                        if let Some(&(def_obj, def_sym)) = global.get(&name)
                            && let Some(rs) = resolved[def_obj][def_sym]
                        {
                            target = Some(rs);
                        }
                    }
                }
                if target.is_none() {
                    // W5 dead-strip: an undefined reference from an UNREACHABLE
                    // (dead) archive unit does not demand resolution — tlink32 +
                    // a fine-grained lib never pull it. Only live refs (reachable
                    // from the explicit objects) are real unresolved externals.
                    if dead.contains(&(obj_ix, sec_ix, r.offset)) {
                        continue;
                    }
                    let name = obj
                        .symbols
                        .get(r.symbol as usize)
                        .map(|s| symbol_name_string(s, &obj.strtab))
                        .unwrap_or_else(|| format!("<sym#{}>", r.symbol));
                    let loc = obj
                        .symbol_source_locs
                        .get(r.symbol as usize)
                        .copied()
                        .flatten();
                    unresolved.push((name, loc));
                    continue;
                }
                let site_rva = sec_place.rva + r.offset;
                apply_one_reloc(
                    obj, buf, in_buf_off, r.kind, target, site_rva, image_base, r.symbol,
                )?;
            }
        }
    }
    if !unresolved.is_empty() {
        unresolved.sort_by(|a, b| a.0.cmp(&b.0));
        unresolved.dedup_by(|a, b| a.0 == b.0);
        return Err(LinkError::UnresolvedExternals(unresolved));
    }
    // Silence "unused" warnings for the idata parameter — it's reserved
    // for the future "imports-via-archive" path where resolution needs to
    // dispatch by name into idata's slot map post-Pass-3b.
    let _ = idata;
    Ok(())
}

#[allow(clippy::too_many_arguments)] // mirrors apply_relocs; bundling fields adds layers without semantic clarity.
fn apply_one_reloc(
    obj: &coff::Object,
    buf: &mut [u8],
    off: usize,
    kind: RelocKind,
    target: Option<ResolvedSym>,
    site_rva: u32,
    image_base: u64,
    sym_ix: u32,
) -> Result<(), LinkError> {
    // An unresolved target at relocation time is fatal — it means a reloc
    // points at a symbol we couldn't pin down (defined nowhere in the TU,
    // and not an `__imp_*` import). Surface the symbol name so the error
    // is actionable.
    let resolved = target.ok_or_else(|| {
        let name = obj
            .symbols
            .get(sym_ix as usize)
            .map(|s| symbol_name_string(s, &obj.strtab))
            .unwrap_or_else(|| format!("<sym#{sym_ix}>"));
        // J-8b: look up the call-site source location threaded through the
        // Object IR (codegen/object.rs::symbol_source_locs). When present,
        // the Display impl renders `"line:col: unresolved external function"`.
        let loc = obj
            .symbol_source_locs
            .get(sym_ix as usize)
            .copied()
            .flatten();
        LinkError::UnresolvedExternals(vec![(name, loc)])
    })?;
    let target_rva = match resolved {
        ResolvedSym::Rva(r) => r,
        ResolvedSym::ImportSlot(r) => r,
    };
    match kind {
        RelocKind::Addr64 => {
            if off + 8 > buf.len() {
                return Err(LinkError::PeOverflow {
                    what: "Addr64 reloc out of range",
                });
            }
            // Addr64 carries an "addend" in the section bytes; preserve it.
            let addend = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            let abs = image_base + target_rva as u64 + addend;
            buf[off..off + 8].copy_from_slice(&abs.to_le_bytes());
        }
        RelocKind::Addr32 => {
            if off + 4 > buf.len() {
                return Err(LinkError::PeOverflow {
                    what: "Addr32 reloc out of range",
                });
            }
            let addend = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            let abs = (image_base + target_rva as u64 + addend as u64) as u32;
            buf[off..off + 4].copy_from_slice(&abs.to_le_bytes());
        }
        RelocKind::Addr32nb => {
            if off + 4 > buf.len() {
                return Err(LinkError::PeOverflow {
                    what: "Addr32nb reloc out of range",
                });
            }
            // Addr32nb is RVA + addend; the addend was written into the
            // 4-byte slot by the converter (e.g. .pdata's EndAddress is
            // begin_sym_rva + code_len, encoded as `Addr32nb against the
            // function symbol with addend = code_len`).
            let addend = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            let val = target_rva.wrapping_add(addend);
            buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
        RelocKind::Rel32 => {
            if off + 4 > buf.len() {
                return Err(LinkError::PeOverflow {
                    what: "Rel32 reloc out of range",
                });
            }
            // Rel32 from x86_64 perspective: `next_instruction_rva = site_rva + 4`
            // (the disp32 follows the opcode; we ignore the addend per MS
            // PE/COFF spec — the converter never writes one).
            let disp = target_rva as i64 - (site_rva as i64 + 4);
            buf[off..off + 4].copy_from_slice(&(disp as i32).to_le_bytes());
        }
        RelocKind::SectionIx | RelocKind::SecRel32 => {
            return Err(LinkError::Internal(format!(
                "S1c.3: reloc kind {kind:?} not supported by the PE writer"
            )));
        }
    }
    Ok(())
}

/// Wrapper: merge an in-memory [`RcUnit`] into an already-built PE. The
/// implementation re-uses the legacy `build_rsrc` + section-appending
/// logic but operates on the already-assembled PE byte image.
///
/// S1c.3 keeps the simple "append .rsrc" path that the legacy writer
/// uses today — full multi-input merge is S1c.4+. The function is a thin
/// wrapper around the existing `write_pe_with_rsrc` rsrc-handling code,
/// invoked AFTER `link_single` so .rsrc layout is computed against the
/// linked image's actual size.
pub fn merge_rsrc_into_pe(pe: Vec<u8>, rc: &RcUnit) -> Result<Vec<u8>, LinkError> {
    // Read the produced PE's existing section table to find where the
    // last section ends, then append a fifth section .rsrc with the
    // resource bytes. This is structurally additive — earlier sections'
    // RVAs and bytes are unchanged.
    //
    // S1c.3 limitation: the legacy `write_pe_with_rsrc(module, Some(rc))`
    // path was an integrated emit (rsrc bytes flowed through the same
    // optional-header arithmetic as the other sections). To preserve
    // bytes precisely, this wrapper PARSES the existing PE, rebuilds the
    // headers with the .rsrc section appended, and re-emits. A future
    // tick (S1c.4+) can replace this with a single-pass linker call that
    // produces the .rsrc inline.
    if rc.resources.is_empty() {
        return Ok(pe); // empty unit: no-op
    }
    append_rsrc_to_pe(pe, rc)
}

/// Merge one or more on-disk `.res` files into an already-built PE image.
/// Records from all files are combined into one `.rsrc` section and then
/// sorted into the Win32 resource-directory order.
pub fn merge_res_files_into_pe(
    pe: Vec<u8>,
    res_files: &[(&str, &[u8])],
) -> Result<Vec<u8>, LinkError> {
    let mut entries = Vec::new();
    for (name, bytes) in res_files {
        entries.extend(parse_res_entries(bytes, name)?);
    }
    if entries.is_empty() {
        return Ok(pe);
    }
    append_rsrc_entries_to_pe(pe, entries)
}

/// Internal: given a built PE without .rsrc and an RcUnit, append a
/// `.rsrc` section. Reads the existing section table, computes the new
/// section's placement (RVA + file offset), rebuilds the COFF header
/// (NumberOfSections++), the optional header (SizeOfInitializedData,
/// SizeOfImage, DataDirectory[2]), appends the section header and the
/// resource bytes.
fn append_rsrc_to_pe(pe: Vec<u8>, rc: &RcUnit) -> Result<Vec<u8>, LinkError> {
    let res = write_res(rc);
    let entries = parse_res_entries(&res, "RcUnit")?;
    if entries.is_empty() {
        return Ok(pe);
    }
    append_rsrc_entries_to_pe(pe, entries)
}

fn append_rsrc_entries_to_pe(pe: Vec<u8>, entries: Vec<RsrcEntry>) -> Result<Vec<u8>, LinkError> {
    const NUM_SECT_OFF_FROM_COFF: usize = 2; // offset of NumberOfSections in COFF header
    const SIZEOF_OPT_HDR_OFF_FROM_COFF: usize = 16;

    let mut pe = pe;
    let coff = PE_OFF + 4;
    let n_sections = u16::from_le_bytes([
        pe[coff + NUM_SECT_OFF_FROM_COFF],
        pe[coff + NUM_SECT_OFF_FROM_COFF + 1],
    ]) as usize;
    let opt_hdr_off = coff + 20;
    let sizeof_opt = u16::from_le_bytes([
        pe[coff + SIZEOF_OPT_HDR_OFF_FROM_COFF],
        pe[coff + SIZEOF_OPT_HDR_OFF_FROM_COFF + 1],
    ]) as usize;
    let sect_tbl_off = opt_hdr_off + sizeof_opt;

    // Find the last section's end RVA + file offset.
    let mut last_rva_end = 0u32;
    let mut last_file_end = 0u32;
    for i in 0..n_sections {
        let h = sect_tbl_off + i * 40;
        let vsize = u32::from_le_bytes(pe[h + 8..h + 12].try_into().unwrap());
        let va = u32::from_le_bytes(pe[h + 12..h + 16].try_into().unwrap());
        let raw_size = u32::from_le_bytes(pe[h + 16..h + 20].try_into().unwrap());
        let raw_ptr = u32::from_le_bytes(pe[h + 20..h + 24].try_into().unwrap());
        let _ = vsize;
        let end_rva = align_up(va + vsize, SECT_ALIGN);
        let end_file = raw_ptr + raw_size;
        if end_rva > last_rva_end {
            last_rva_end = end_rva;
        }
        if end_file > last_file_end {
            last_file_end = end_file;
        }
    }
    let rsrc_rva = last_rva_end; // already aligned by `align_up`
    let rsrc_bytes = build_rsrc_entries(entries, rsrc_rva);
    let rsrc_vsize = rsrc_bytes.len() as u32;
    let rsrc_raw = align_up(rsrc_vsize, FILE_ALIGN);
    let rsrc_file_off = last_file_end;

    // Patch the COFF header's NumberOfSections.
    let new_n = (n_sections + 1) as u16;
    pe[coff + NUM_SECT_OFF_FROM_COFF..coff + NUM_SECT_OFF_FROM_COFF + 2]
        .copy_from_slice(&new_n.to_le_bytes());

    // Patch optional header: SizeOfInitializedData, SizeOfImage,
    // DataDirectory[2] (Resource).
    let sid_off = opt_hdr_off + 8; // SizeOfInitializedData (offset 8 of opt hdr after Magic+Linker)
    // Optional header layout (PE32+):
    //   u16 Magic | u8 MajLink | u8 MinLink | u32 SizeOfCode |
    //   u32 SizeOfInitializedData | ...
    // SizeOfInitializedData is at offset 8 from opt_hdr_off.
    let current_sid = u32::from_le_bytes(pe[sid_off..sid_off + 4].try_into().unwrap());
    let new_sid = current_sid + rsrc_raw;
    pe[sid_off..sid_off + 4].copy_from_slice(&new_sid.to_le_bytes());

    // SizeOfImage is at offset 56 of opt hdr (PE32+).
    let soi_off = opt_hdr_off + 56;
    let new_size_of_image = align_up(rsrc_rva + rsrc_vsize, SECT_ALIGN);
    pe[soi_off..soi_off + 4].copy_from_slice(&new_size_of_image.to_le_bytes());

    // DataDirectory[2] (Resource). W5 (rc gap 1): the directory BASE depends
    // on the optional-header Magic — PE32 (0x10B) directories start at
    // opt+96, PE32+ (0x20B) at opt+112. The old hardcoded 112 wrote a PE32's
    // Resource entry onto DataDirectory[4] (Certificate Table): the .rsrc
    // section appended fine but the loader never saw it (LoadIcon/LoadMenu
    // returned NULL) AND the security dir was corrupted. SizeOfImage (+56)
    // and SizeOfInitializedData (+8) are coincidentally identical in both
    // formats, so this base is the only magic-dependent patch.
    let magic = u16::from_le_bytes(pe[opt_hdr_off..opt_hdr_off + 2].try_into().unwrap());
    let dd_base = if magic == 0x10B { 96 } else { 112 };
    let dd_off = opt_hdr_off + dd_base + 2 * 8;
    pe[dd_off..dd_off + 4].copy_from_slice(&rsrc_rva.to_le_bytes());
    pe[dd_off + 4..dd_off + 8].copy_from_slice(&rsrc_vsize.to_le_bytes());

    // Append the section header at the end of the existing section-table
    // entries. The section table sits within HEADERS_SIZE (0x400 bytes);
    // 4 existing sections × 40 = 160 bytes, + opt hdr (0xF0) + COFF (20)
    // + signature (4) + DOS (0x80) = 0x224, comfortably below 0x400.
    let new_hdr_off = sect_tbl_off + n_sections * 40;
    // Use a transient Buf to render the section header bytes.
    let mut hdr_buf = Buf::new();
    write_section_header(
        &mut hdr_buf,
        b".rsrc",
        rsrc_vsize,
        rsrc_rva,
        rsrc_raw,
        rsrc_file_off,
        0x4000_0040,
    );
    pe[new_hdr_off..new_hdr_off + 40].copy_from_slice(&hdr_buf.0[..40]);

    // Append the resource bytes (padded to FILE_ALIGN) at rsrc_file_off.
    // The current PE already ends at last_file_end (rsrc_file_off), so we
    // simply extend the Vec.
    debug_assert_eq!(pe.len() as u32, rsrc_file_off);
    pe.extend_from_slice(&rsrc_bytes);
    while !pe.len().is_multiple_of(FILE_ALIGN as usize) {
        pe.push(0);
    }

    Ok(pe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::{CompiledFn, compile_module};
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    fn pe_of(src: &str) -> Vec<u8> {
        let toks = Lexer::tokenize(src.as_bytes()).unwrap();
        let tu = Parser::parse(&toks).unwrap();
        let m = compile_module(&tu).unwrap();
        write_pe(&m).unwrap()
    }

    fn parse_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn has_mz_and_pe_signatures() {
        let pe = pe_of("int main(void){ return 42; }");
        assert_eq!(&pe[0..2], b"MZ");
        assert_eq!(parse_u32(&pe, 0x3C) as usize, PE_OFF);
        assert_eq!(&pe[PE_OFF..PE_OFF + 4], b"PE\0\0");
    }

    #[test]
    fn machine_is_amd64_and_four_sections() {
        let pe = pe_of("int main(void){ return 0; }");
        let coff = PE_OFF + 4;
        assert_eq!(u16::from_le_bytes([pe[coff], pe[coff + 1]]), 0x8664);
        assert_eq!(u16::from_le_bytes([pe[coff + 2], pe[coff + 3]]), 4);
    }

    #[test]
    fn entry_point_is_text_rva_and_subsystem_is_console() {
        let pe = pe_of("int main(void){ return 0; }");
        let opt = PE_OFF + 4 + 20;
        assert_eq!(u16::from_le_bytes([pe[opt], pe[opt + 1]]), 0x020B);
        let entry = parse_u32(&pe, opt + 16); // AddressOfEntryPoint
        // Entry == the (now dynamically-placed) `.text` VirtualAddress; for a
        // program this small that is still the historical 0x1000.
        let text_va = parse_u32(&pe, opt + 0xF0 + 12);
        assert_eq!(entry, text_va);
        assert_eq!(entry, 0x1000);
        let subsystem_off = opt + 68;
        assert_eq!(
            u16::from_le_bytes([pe[subsystem_off], pe[subsystem_off + 1]]),
            3
        );
    }

    #[test]
    fn file_is_section_padded() {
        let pe = pe_of("int main(void){ return 0; }");
        assert_eq!(pe.len() % FILE_ALIGN as usize, 0);
        assert!(pe.len() >= (HEADERS_SIZE + 2 * FILE_ALIGN) as usize);
    }

    #[test]
    fn undefined_callee_is_link_error() {
        let toks = Lexer::tokenize(b"int main(void){ return missing(); }").unwrap();
        let tu = Parser::parse(&toks).unwrap();
        let m = compile_module(&tu).unwrap();
        let e = write_pe(&m).unwrap_err();
        assert!(e.0.contains("undefined function"), "{}", e.0);
    }

    /// A synthetic `main` whose machine code is `body_len` filler bytes. The
    /// content is irrelevant to *layout* (no calls/riprefs/strings, never
    /// executed by this test); only `code.len()` drives `text_vsize`, which
    /// the writer computes as `STUB_LEN + Σ f.code.len()`. Constructing the
    /// `Module` directly lets us hit an *exact* `SECT_ALIGN` multiple with no
    /// C frontend or guesswork.
    fn pe_with_text_body(body_len: usize) -> Vec<u8> {
        let m = Module {
            funcs: vec![CompiledFn {
                name: "main".into(),
                code: vec![0x90; body_len], // NOP filler; placement-only
                calls: Vec::new(),
                riprefs: Vec::new(),
                strings: Vec::new(),
                fp_literals: Vec::new(),
                try_scopes: Vec::new(),
                extern_refs: Vec::new(),
                inline: false,
            }],
            globals: Vec::new(),
            vtables: Vec::new(),
            has_dynamic_cast: false,
            record_count: 0,
            entry: crate::codegen::Entry::ConsoleMain,
            typeinfo: Vec::new(),
            eh_buffer_size: 0,
            target: crate::codegen::target::TargetKind::Win64,
        };
        write_pe(&m).unwrap()
    }

    /// Read the four section headers as `(virtual_size, virtual_address)`.
    fn sections(pe: &[u8]) -> Vec<(u32, u32)> {
        let opt = PE_OFF + 4 + 20;
        let tbl = opt + 0xF0; // SizeOfOptionalHeader (PE32+: 0xF0)
        (0..4)
            .map(|i| {
                let h = tbl + i * 40; // each section header is 40 bytes
                (parse_u32(pe, h + 8), parse_u32(pe, h + 12)) // VSize, VA
            })
            .collect()
    }

    /// Locks the exact-`SECT_ALIGN`-multiple boundary: when `.text`'s virtual
    /// size is *exactly* one or two pages, `align_up` must NOT add a spurious
    /// extra page. We pick `body_len` so `text_vsize == STUB_LEN + body_len`
    /// equals exactly `0x1000` then exactly `0x2000`, assert that fact (the
    /// test cannot silently degrade into a non-boundary case), then assert the
    /// full layout invariants on the produced PE bytes.
    ///
    /// A regression that made `align_up` add a page at exact multiples (e.g.
    /// `v / a * a + a`, or `(v + a) & !(a - 1)`) would push `.idata` to
    /// `text_rva + text_vsize + 0x1000`, breaking `idata_rva == text_rva +
    /// text_vsize`; an off-by-one that *under*-aligned would overlap the
    /// previous section. Both are caught below, and `SizeOfImage` is pinned.
    #[test]
    fn exact_sect_align_boundary_no_spurious_page() {
        for &want_text_vsize in &[SECT_ALIGN, 2 * SECT_ALIGN] {
            // Cannot underflow: both operands are compile-time constants and
            // the chosen boundary sizes (0x1000 / 0x2000 == SECT_ALIGN /
            // 2*SECT_ALIGN) far exceed STUB_LEN (0x12).
            let body_len = want_text_vsize as usize - STUB_LEN;
            let pe = pe_with_text_body(body_len);

            let opt = PE_OFF + 4 + 20;
            let secs = sections(&pe); // [.text, .idata, .rdata, .data]
            let (text_vsize, text_rva) = secs[0];

            // The case must actually exercise the exact-multiple edge.
            assert_eq!(
                text_vsize, want_text_vsize,
                "test no longer hits the intended .text vsize"
            );
            assert_eq!(
                text_vsize % SECT_ALIGN,
                0,
                "boundary test degraded into a non-exact-multiple case \
                 (text_vsize={text_vsize:#x})"
            );

            // No spurious page: `.idata` sits exactly at the end of `.text`,
            // not a page beyond it.
            let (_, idata_rva) = secs[1];
            assert_eq!(
                idata_rva,
                text_rva + text_vsize,
                "spurious extra page at exact SECT_ALIGN multiple \
                 (text_vsize={text_vsize:#x})"
            );

            // Every section base is `align_up(prev_end, SECT_ALIGN)` and no
            // two `[va, va+vsize)` ranges overlap.
            for w in secs.windows(2) {
                let (pv, pa) = w[0];
                let (_, na) = w[1];
                assert_eq!(
                    na,
                    align_up(pa + pv, SECT_ALIGN),
                    "section base not align_up(prev_end) \
                     (text_vsize={text_vsize:#x})"
                );
                assert!(
                    na >= pa + pv,
                    "section overlap (text_vsize={text_vsize:#x})"
                );
            }

            // SizeOfImage is the exact aligned end of the last section.
            let (lv, la) = *secs.last().unwrap();
            let size_of_image = parse_u32(&pe, opt + 56);
            assert_eq!(
                size_of_image,
                align_up(la + lv, SECT_ALIGN),
                "SizeOfImage not exact (text_vsize={text_vsize:#x})"
            );
        }
    }

    fn rva_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn rva_u64(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    /// C1b multi-descriptor `.idata`: drive `emit_idata` directly with a
    /// synthetic *two-DLL* group set (KERNEL32-style + a second fictitious DLL
    /// — deliberately NOT USER32/MessageBoxA, which is C3; this proves the
    /// multi-descriptor path without populating `WIN32_IMPORTS`). Asserts the
    /// section has exactly two well-formed `IMAGE_IMPORT_DESCRIPTOR`s + a null
    /// terminator, each pointing at its own null-terminated ILT/IAT and DLL
    /// name, the hint/name blob is correct, and every symbol's `iat_slot` RVA
    /// is distinct and points at the right per-DLL IAT cell. Deterministic:
    /// the group order is fixed by the caller (no HashMap into bytes).
    #[test]
    fn multi_dll_idata_has_two_well_formed_descriptors() {
        let base = 0x2000u32;
        let groups = [
            DllImports {
                name: "ADLL.dll",
                symbols: vec!["AlphaOne", "AlphaTwo"],
            },
            DllImports {
                name: "BDLL.dll",
                symbols: vec!["BetaOnly"],
            },
        ];
        let idata = emit_idata(&groups, base);
        let img = &idata.image;
        let off = |rva: u32| (rva - base) as usize; // section-relative

        // --- descriptor array: 2 real + 1 null terminator (3 * 20 bytes) ---
        assert_eq!(idata.import_dir_rva, base);
        assert_eq!(idata.import_dir_size, 3 * 20);
        // Descriptor 0 (ADLL): OFT/Name/FT non-zero & inside the section.
        let d0_oft = rva_u32(img, 0);
        let d0_name = rva_u32(img, 12);
        let d0_ft = rva_u32(img, 16);
        // Descriptor 1 (BDLL).
        let d1_oft = rva_u32(img, 20);
        let d1_name = rva_u32(img, 32);
        let d1_ft = rva_u32(img, 36);
        // Null terminator: a fully-zero 20-byte descriptor at index 2.
        assert!(
            img[40..60].iter().all(|&x| x == 0),
            "third descriptor must be the null terminator"
        );

        // --- DLL name strings the `Name` fields point at ---
        assert_eq!(&img[off(d0_name)..off(d0_name) + 9], b"ADLL.dll\0");
        assert_eq!(&img[off(d1_name)..off(d1_name) + 9], b"BDLL.dll\0");

        // --- per-DLL ILT == IAT (by-name thunks), each null-terminated ---
        // ADLL: 2 symbols + null; BDLL: 1 symbol + null.
        for k in 0..2 {
            assert_eq!(
                rva_u64(img, off(d0_oft) + k * 8),
                rva_u64(img, off(d0_ft) + k * 8),
                "ADLL ILT/IAT thunk {k} must match"
            );
            assert_ne!(rva_u64(img, off(d0_oft) + k * 8), 0);
        }
        assert_eq!(rva_u64(img, off(d0_oft) + 2 * 8), 0, "ADLL ILT terminator");
        assert_eq!(rva_u64(img, off(d0_ft) + 2 * 8), 0, "ADLL IAT terminator");
        assert_eq!(
            rva_u64(img, off(d1_oft)),
            rva_u64(img, off(d1_ft)),
            "BDLL ILT/IAT thunk 0 must match"
        );
        assert_eq!(rva_u64(img, off(d1_oft) + 8), 0, "BDLL ILT terminator");
        assert_eq!(rva_u64(img, off(d1_ft) + 8), 0, "BDLL IAT terminator");

        // --- hint/name: each thunk points at <hint u16=0><name><NUL> ---
        let check_hn = |thunk_rva: u32, want: &str| {
            let o = off(thunk_rva);
            assert_eq!(&img[o..o + 2], &[0, 0], "hint must be 0");
            let s = &img[o + 2..o + 2 + want.len()];
            assert_eq!(s, want.as_bytes(), "hint/name symbol");
            assert_eq!(img[o + 2 + want.len()], 0, "name NUL terminator");
        };
        check_hn(rva_u32(img, off(d0_oft)) as u32, "AlphaOne");
        check_hn(rva_u32(img, off(d0_oft) + 8) as u32, "AlphaTwo");
        check_hn(rva_u32(img, off(d1_oft)) as u32, "BetaOnly");

        // --- iat_slot: every symbol -> its OWN per-DLL IAT cell, distinct ---
        let s_a1 = idata.iat_slot["AlphaOne"];
        let s_a2 = idata.iat_slot["AlphaTwo"];
        let s_b = idata.iat_slot["BetaOnly"];
        assert_eq!(s_a1, d0_ft, "AlphaOne -> ADLL IAT slot 0");
        assert_eq!(s_a2, d0_ft + 8, "AlphaTwo -> ADLL IAT slot 1");
        assert_eq!(s_b, d1_ft, "BetaOnly -> BDLL IAT slot 0");
        // All three slot RVAs distinct (no aliasing across DLLs).
        assert_ne!(s_a1, s_a2);
        assert_ne!(s_a1, s_b);
        assert_ne!(s_a2, s_b);

        // --- IAT data directory spans both DLLs' contiguous IAT sub-arrays ---
        // ADLL IAT (3*8) + BDLL IAT (2*8) == 40 bytes, starting at d0_ft.
        assert_eq!(idata.iat_rva, d0_ft);
        assert_eq!(idata.iat_size, (3 + 2) * 8);
        assert_eq!(d1_ft, d0_ft + 3 * 8, "IAT sub-arrays must be contiguous");

        // Determinism: same groups -> identical bytes (no HashMap into image).
        assert_eq!(emit_idata(&groups, base).image, *img);
    }

    #[test]
    fn object_link_x64_emits_live_hellowin_style_imports() {
        let mut obj = coff::Object {
            machine: coff::Machine::Amd64,
            ..Default::default()
        };
        for name in [
            "__imp_GetClientRect",
            "__imp_DrawTextA",
            "__imp_GetStockObject",
            "__imp_CreatePalette",
            "__imp_GetPaletteEntries",
            "__imp_lstrlenA",
            "__imp_lstrcmpA",
            "__imp_lstrcmpiA",
        ] {
            obj.symbols.push(coff::Symbol {
                name: coff::SymName::from_str(name, &mut obj.strtab),
                value: 0,
                section: SectionRef::Undefined,
                kind: coff::SymKind::Notype,
                storage: StorageClass::External,
                aux: Vec::new(),
            });
        }

        let idata =
            build_idata_from_objects(&[&obj], 0x2000, 8).expect("x64 imports should resolve");
        for name in [
            "GetClientRect",
            "DrawTextA",
            "GetStockObject",
            "CreatePalette",
            "GetPaletteEntries",
            "lstrlenA",
            "lstrcmpA",
            "lstrcmpiA",
        ] {
            assert!(
                idata.iat_slot.contains_key(name),
                "missing IAT slot for {name}"
            );
        }
    }

    /// Scope/regression lock for C1b: with today's KERNEL32-only
    /// `WIN32_IMPORTS`, the module-driven grouping yields **exactly one**
    /// KERNEL32 group containing the table-ordered symbols — no per-symbol
    /// pruning (deferred), no extra DLL. This is what keeps the console
    /// `.idata` single-descriptor.
    ///
    /// Phase H4a added `RaiseException` + `RtlUnwindEx` (the SEH runtime
    /// pair) to KERNEL32, so the historical six grew to eight. Per-symbol
    /// pruning is still deferred, so the SEH pair is dormant in every
    /// non-throwing TU — only present in `.idata` because some OTHER
    /// KERNEL32 symbol is referenced via the entry stub. Listed in
    /// `WIN32_IMPORTS` declaration order (which is also `groups[0].symbols`
    /// emission order).
    #[test]
    fn console_grouping_is_single_kernel32_group_of_eight() {
        // Direct lexer+parser (these in-crate tests bypass the preprocessor);
        // `printf` and `new`/`delete` are codegen intrinsics needing no
        // declaration, and together emit the full KERNEL32 six. The SEH
        // pair joins automatically because they share the KERNEL32 DLL.
        let toks = Lexer::tokenize(
            b"int main(void){int*p=new int;*p=1;printf(\"%d\",*p);delete p;return 0;}",
        )
        .unwrap();
        let tu = Parser::parse(&toks).unwrap();
        let m = compile_module(&tu).unwrap();
        let groups = grouped_imports(&m).unwrap();
        assert_eq!(groups.len(), 1, "console program must use exactly one DLL");
        assert_eq!(groups[0].name, "KERNEL32.dll");
        assert_eq!(
            groups[0].symbols,
            vec![
                "ExitProcess",
                "GetStdHandle",
                "WriteFile",
                "GetProcessHeap",
                "HeapAlloc",
                "HeapFree",
                "RaiseException",
                "RtlUnwindEx",
            ],
            "the full table-ordered KERNEL32 eight (no per-symbol pruning \
             — that is a deferred C1b optimization; H4a appended the two \
             SEH runtime symbols, dormant in this non-throwing TU)"
        );
    }
}
