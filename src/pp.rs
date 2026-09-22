//! The C preprocessor (translation phase 4): a [`Token`]-stream transformer
//! sitting between the lexer and the parser.
//!
//! Supports `#define`/`#undef` (object- and function-like macros, `#`
//! stringize, `##` paste, `__VA_ARGS__`), `#include` (`"..."` and `<...>` via
//! a pluggable resolver), the full conditional family (`#if`/`#ifdef`/
//! `#ifndef`/`#elif`/`#else`/`#endif` with `defined` and a constant-expression
//! evaluator), `#error`, and ignored `#pragma`/`#line`. Predefined: `__LINE__`,
//! `__FILE__`, `__STDC__`, `__DATE__`, `__TIME__`, `__MDBCC__`.
//!
//! Recursion is bounded with a name guard (the classic "blue paint"); this
//! handles real-world code, with rare standard re-expansion corner cases
//! deliberately out of scope (noted in the scratchpad).

use std::collections::{HashMap, HashSet};

use crate::lexer::{Keyword, Lexer, Punct, Token, TokenKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PpError {
    pub message: String,
    pub line: u32,
    pub col: u32,
}

impl std::fmt::Display for PpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: error: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for PpError {}

/// Resolves `#include` targets to source bytes. `system` is true for the
/// `<...>` form, false for `"..."`.
pub trait IncludeResolver {
    fn resolve(&self, name: &str, system: bool) -> Option<Vec<u8>>;
}

/// The intrinsic `<windows.h>` body (Phase C / C3 + Phase D / D1). C libc
/// headers stub to *empty* because libc names are recognised in codegen;
/// Win32 *types*, however, are type names the *parser* needs (an unknown
/// type name is a hard parse error). So `<windows.h>` resolves — uniquely
/// among system headers — to this small fixed body of typedefs, structs
/// and object macros, every construct of which is already supported by
/// the existing typedef/struct/macro machinery. Sizes are the Win64 ABI
/// ones the parser already models: opaque handles are `void*` (8);
/// `WPARAM`/`LPARAM`/`LRESULT` are `__int64` (8; `long` is LLP64 32-bit
/// so it is NOT used for those); `WINAPI`/`CALLBACK`/`WINAPIV` are empty
/// (we have exactly one Win64 ABI — no `@N` decoration in x64). `LPCSTR`
/// is `const char *`; the parser treats `const` as a no-op qualifier, so
/// it decays to `char *` exactly as a real header's would. `MessageBoxA`
/// and the new Phase-D USER32 functions themselves need **no**
/// declaration — like libc, calls are recognised by name in codegen via
/// `WIN32_IMPORTS`; this body is only for the *types* a basic GUI app
/// names.
///
/// Phase D / D1 (per `wrk_docs/2026.05.18 - HLD - Phase D (minimal OWL
/// runtime).md` §D-a (2)) adds **only** what the hello-window OWL source
/// literally names: the handle typedefs `HICON`/`HCURSOR`/`HBRUSH`/`HDC`
/// (all `void*`); `LONG`/`LONG_PTR`; the `WNDPROC` function-pointer
/// typedef (CALLBACK is empty, so this is exactly Phase-A's `Type::Func`
/// form); the structs `POINT`/`RECT`/`MSG`/`WNDCLASSEXA`/`CREATESTRUCTA`
/// (Win64 member layout — pointers passed by `&`, never by value); and
/// the `WM_*`, `WS_*`, `CS_*`, `CW_USEDEFAULT`, `SW_*`, `IDC_ARROW`,
/// `GWLP_USERDATA`, `COLOR_WINDOW` constants. No `WM_PAINT`/menu/dialog/
/// `WS_CHILD` (Phase E/G). `CW_USEDEFAULT` is `0x80000000` (the
/// documented Win32 value), passed as the `int` arg the existing int ABI
/// handles.
const WINDOWS_H: &[u8] = b"\
typedef unsigned int UINT;\n\
typedef unsigned int DWORD;\n\
typedef int BOOL;\n\
typedef long LONG;\n\
typedef __int64 LONG_PTR;\n\
typedef unsigned char BYTE;\n\
typedef unsigned short WORD;\n\
typedef void *HANDLE;\n\
typedef void *HWND;\n\
typedef void *HINSTANCE;\n\
typedef void *HMODULE;\n\
typedef void *HMENU;\n\
typedef void *HICON;\n\
typedef void *HCURSOR;\n\
typedef void *HBRUSH;\n\
typedef void *HDC;\n\
typedef char *LPSTR;\n\
typedef const char *LPCSTR;\n\
typedef unsigned __int64 WPARAM;\n\
typedef __int64 LPARAM;\n\
typedef __int64 LRESULT;\n\
#define WINAPI\n\
#define CALLBACK\n\
#define WINAPIV\n\
#define PASCAL\n\
#define _PASCAL\n\
#define __pascal\n\
#define CONST const\n\
#define NULL 0\n\
#define FALSE 0\n\
#define TRUE 1\n\
typedef LRESULT (CALLBACK *WNDPROC)(HWND, UINT, WPARAM, LPARAM);\n\
struct tagPOINT { LONG x; LONG y; };\n\
typedef struct tagPOINT POINT;\n\
struct tagRECT { LONG left; LONG top; LONG right; LONG bottom; };\n\
typedef struct tagRECT RECT;\n\
typedef struct tagRECT *LPRECT;\n\
struct tagMSG {\n\
    HWND hwnd;\n\
    UINT message;\n\
    WPARAM wParam;\n\
    LPARAM lParam;\n\
    DWORD time;\n\
    POINT pt;\n\
};\n\
typedef struct tagMSG MSG;\n\
struct tagWNDCLASSEXA {\n\
    UINT cbSize;\n\
    UINT style;\n\
    WNDPROC lpfnWndProc;\n\
    int cbClsExtra;\n\
    int cbWndExtra;\n\
    HINSTANCE hInstance;\n\
    HICON hIcon;\n\
    HCURSOR hCursor;\n\
    HBRUSH hbrBackground;\n\
    LPCSTR lpszMenuName;\n\
    LPCSTR lpszClassName;\n\
    HICON hIconSm;\n\
};\n\
typedef struct tagWNDCLASSEXA WNDCLASSEXA;\n\
struct tagWNDCLASSA {\n\
    UINT style;\n\
    WNDPROC lpfnWndProc;\n\
    int cbClsExtra;\n\
    int cbWndExtra;\n\
    HINSTANCE hInstance;\n\
    HICON hIcon;\n\
    HCURSOR hCursor;\n\
    HBRUSH hbrBackground;\n\
    LPCSTR lpszMenuName;\n\
    LPCSTR lpszClassName;\n\
};\n\
typedef struct tagWNDCLASSA WNDCLASSA;\n\
typedef struct tagWNDCLASSA WNDCLASS;\n\
struct tagCREATESTRUCTA {\n\
    void *lpCreateParams;\n\
    HINSTANCE hInstance;\n\
    HMENU hMenu;\n\
    HWND hwndParent;\n\
    int cy;\n\
    int cx;\n\
    int y;\n\
    int x;\n\
    LONG style;\n\
    LPCSTR lpszName;\n\
    LPCSTR lpszClass;\n\
    DWORD dwExStyle;\n\
};\n\
typedef struct tagCREATESTRUCTA CREATESTRUCTA;\n\
struct tagPAINTSTRUCT {\n\
    HDC hdc;\n\
    BOOL fErase;\n\
    RECT rcPaint;\n\
    BOOL fRestore;\n\
    BOOL fIncUpdate;\n\
    BYTE rgbReserved[32];\n\
};\n\
typedef struct tagPAINTSTRUCT PAINTSTRUCT;\n\
#define MB_OK 0\n\
#define MB_OKCANCEL 1\n\
#define MB_ICONERROR 0x10\n\
#define MB_ICONINFORMATION 0x40\n\
#define WM_FIRST 0\n\
#define WM_CREATE 0x0001\n\
#define WM_DESTROY 0x0002\n\
#define WM_RBUTTONDOWN 0x0204\n\
#define WM_RBUTTONUP 0x0205\n\
#define WM_CLOSE 0x0010\n\
#define WM_QUIT 0x0012\n\
#define WM_PAINT 0x000F\n\
#define WM_KEYDOWN 0x0100\n\
#define WM_COMMAND 0x0111\n\
#define WM_MOUSEMOVE 0x0200\n\
#define WM_LBUTTONDOWN 0x0201\n\
#define WM_LBUTTONUP 0x0202\n\
#define MK_LBUTTON 0x0001\n\
#define MK_RBUTTON 0x0002\n\
#define MK_SHIFT 0x0004\n\
#define MK_CONTROL 0x0008\n\
#define MK_MBUTTON 0x0010\n\
#define WM_NCCREATE 0x0081\n\
#define WS_OVERLAPPED 0\n\
#define WS_VISIBLE 0x10000000\n\
#define WS_CAPTION 0x00C00000\n\
#define WS_SYSMENU 0x00080000\n\
#define WS_THICKFRAME 0x00040000\n\
#define WS_MINIMIZEBOX 0x00020000\n\
#define WS_MAXIMIZEBOX 0x00010000\n\
#define WS_OVERLAPPEDWINDOW 0x00CF0000\n\
#define WS_CHILD 0x40000000\n\
#define SS_LEFT 0x00000000\n\
#define SS_CENTER 0x00000001\n\
#define SS_RIGHT 0x00000002\n\
#define SS_BLACKRECT 0x00000004\n\
#define SS_GRAYRECT 0x00000005\n\
#define SS_BLACKFRAME 0x00000007\n\
#define SS_GRAYFRAME 0x00000008\n\
#define SS_SIMPLE 0x0000000B\n\
#define SS_NOPREFIX 0x00000080\n\
#define CW_USEDEFAULT 0x80000000\n\
#define SW_SHOWNORMAL 1\n\
#define SW_SHOW 5\n\
#define GWLP_USERDATA -21\n\
#define CS_VREDRAW 0x0001\n\
#define CS_HREDRAW 0x0002\n\
#define IDC_ARROW 32512\n\
#define IDC_IBEAM 32513\n\
#define MoveTo(h,x,y) MoveToEx(h,x,y,0)\n\
#define LoadCursor LoadCursorA\n\
#define COLOR_WINDOW 5\n";

/// The intrinsic OWL runtime (Phase D / D4). Every `<owl/...>` system
/// include resolves to **this single body**, idempotent via the
/// `_OWL_RUNTIME_INCLUDED` include guard so a TU may freely `#include
/// <owl/applicat.h>` AND `<owl/framewin.h>` (the canonical Borland
/// idiom) without redefining classes. Per `wrk_docs/2026.05.18 - HLD -
/// Phase D (minimal OWL runtime).md` §D-b this is the "intrinsic OWL
/// implementation TU prepended to the user's source" — except mdbcc is
/// already single-TU, so we realise it more cleanly as a self-contained
/// header that carries both the class declarations AND the runtime
/// implementations (the OWL bodies are plain Borland-dialect C++ in the
/// Phase-A/B subset mdbcc compiles; no linker, no separate `owl.lib`,
/// no global ctors). Dormant for any TU that does not `#include
/// <owl/*.h>` ⇒ a console program still emits zero new bytes (the
/// `WIN32_IMPORTS` dormancy invariant already byte-locked by
/// `tests/pe_imports.rs`).
///
/// **Public API (the MINIMAL faithful subset; HLD §D-b, D-2 non-template
/// OWL 2.5).** Only what a hello-OWL window needs:
///   - `TModule` (base of TApplication; holds `HINSTANCE hInstance`).
///   - `TApplication : public TModule` (`TWindow* MainWindow`,
///     `virtual InitMainWindow()`, `SetMainWindow`, `virtual Run()`
///     drives `GetMessageA`/`TranslateMessage`/`DispatchMessageA`).
///   - `TWindow` (HWND, parent, title; ctor; virtual dtor; virtual
///     `WindowProc`; `Create()` registers the class + `CreateWindowExA`
///     passing `this` as `lpCreateParams`; `Show()`).
///   - `TFrameWindow : public TWindow` (thin alias for v1).
///   - `OwlMain(int, char**)` — Borland's OWL entry; the user writes
///     this, the runtime owns `WinMain` and calls it.
///
/// **WinMain↔OwlMain glue (HLD §D-b).** The runtime supplies
/// `int WinMain(HINSTANCE, HINSTANCE, LPSTR, int)` so Phase-C's
/// `Entry::GuiWinMain` detection (`src/codegen.rs:347`) fires ⇒ PE
/// subsystem 2 + the GUI stub *reused unchanged*. WinMain's body sets a
/// process-global `_OwlHInstance` from its `hI` parameter (Phase-C stub
/// passes `hInstance == IMAGE_BASE`, which equals
/// `GetModuleHandle(NULL)` for a no-resource EXE) and then calls
/// `OwlMain(0, 0)` (real `argc`/`argv` deferred — same boundary as
/// Phase C's NULL `lpCmdLine`). No global constructors anywhere — the
/// one process-global is a constant-initialised null pointer
/// (`HINSTANCE _OwlHInstance = 0`), set by the first executed
/// statement of WinMain (HLD §D-c crux risk "closed by construction").
///
/// **Phase E / E1 (per `wrk_docs/2026.05.18 - HLD - Phase E (OWL event
/// handling).md` §E-a/§E-b)** grows this header with the response-table
/// machinery: eight per-event `EvX` virtual no-op slots on `TWindow`
/// (`EvPaint`, `EvDestroy`, `EvLButtonDown/Up`, `EvMouseMove`,
/// `EvCommand`, `EvKeyDown`, `EvCreate`); a non-virtual `base_WindowProc`
/// helper that calls `DefWindowProcA(HWindow, m, w, l)` — the
/// parent-class link `END_RESPONSE_TABLE` resolves to (HLD §E-b decision
/// 1: qualified-call syntax `TFrameWindow::WindowProc(...)` is not in
/// mdbcc's expression-position grammar, so a same-class helper
/// short-circuits to `DefWindowProcA` directly; identical observable
/// behaviour in v1 because `TFrameWindow` does not override
/// `WindowProc`); the `DECLARE_RESPONSE_TABLE(cls)` /
/// `DEFINE_RESPONSE_TABLE1(cls, base)` / `END_RESPONSE_TABLE` /
/// `EV_WM_*` (the eight v1 messages) preprocessor macros. Each
/// `EV_WM_*` expands to an `if (msg == X) { ...; return 0; }` block —
/// an **if-chain**, NOT `switch`/`case` (the parser does not yet support
/// `switch`; HLD §E-a, Phase-D Tick 11 finding). The chosen mechanism
/// is the **virtual-dispatch lowering** (HLD §E-a Option (b)), not the
/// authentic OWL member-fn-ptr table (Option (a)) — chosen because
/// mdbcc does not have member function pointers and Option (b) needs
/// zero new codegen. Cracking signatures use `int x, int y` rather than
/// `TPoint& pt` for v1 (the no-`TPoint` simplification; sign-extending
/// `(int)(short)(l & 0xFFFF)` casts preserve Win32's signed-coordinate
/// semantics).
///
/// **The static thunk (HLD §D-c).** `OwlStaticWndProc` is a plain
/// free-function whose mdbcc Win64 emission *is* a conformant Win64
/// `WNDPROC` (CALLBACK is empty — no name decoration in x64). It uses
/// `lpCreateParams` (last arg of `CreateWindowExA`) ⇒ `WM_NCCREATE`
/// stores the `TWindow*` into `GWLP_USERDATA`; later messages
/// `GetWindowLongPtrA` it back and virtual-dispatch to `WindowProc`
/// (Phase B vtable across the Win32 callback boundary — proven by D3's
/// PROG_D3_THUNK). The pre-`WM_NCCREATE` null-self case falls through
/// to `DefWindowProcA` (never a null deref — the standard OWL behaviour).
const OWL_RUNTIME_H: &[u8] = b"\
#ifndef _OWL_RUNTIME_INCLUDED\n\
#define _OWL_RUNTIME_INCLUDED\n\
#include <windows.h>\n\
\n\
class TWindow;\n\
typedef TWindow *PTWindowsObject;\n\
\n\
/* OWL 1.x dynamic-dispatch message packet. A DDVT handler\n\
   'void WMxxx(RTMessage) = [WM_FIRST + WM_xxx];' receives the incoming\n\
   message packaged here; LP.Lo/LP.Hi are LOWORD/HIWORD of LParam (e.g. the\n\
   mouse x,y for the button/move messages). Passed BY VALUE (RTMessage is a\n\
   value typedef here) -- the 1992 samples only READ the packet. */\n\
struct TMessage {\n\
    HWND Receiver;\n\
    WPARAM WParam;\n\
    LPARAM LParam;\n\
    struct { WORD Lo; WORD Hi; } LP;\n\
    LRESULT Result;\n\
};\n\
typedef struct TMessage RTMessage;\n\
\n\
/* OWL window attributes (position/size/style/id), set before Create. Default =\n\
   an overlapped window at CW_USEDEFAULT (byte-identical to pre-Attr); a control\n\
   or positioned window overrides the fields. */\n\
struct TWindowAttr {\n\
    int X;\n\
    int Y;\n\
    int W;\n\
    int H;\n\
    DWORD Style;\n\
    int Id;\n\
};\n\
\n\
class TModule {\n\
public:\n\
    HINSTANCE hInstance;\n\
    TModule() { hInstance = 0; }\n\
    virtual ~TModule() {}\n\
    HINSTANCE GetInstance() { return hInstance; }\n\
};\n\
\n\
class TApplication : public TModule {\n\
public:\n\
    TWindow *MainWindow;\n\
    int Status;\n\
    const char *Name;\n\
    TApplication();\n\
    TApplication(LPSTR AName, HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdLine, int cmdShow);\n\
    virtual ~TApplication() {}\n\
    virtual void InitApplication() {}\n\
    virtual void InitInstance();\n\
    virtual void InitMainWindow() {}\n\
    void SetMainWindow(TWindow *w) { MainWindow = w; }\n\
    virtual int Run();\n\
};\n\
\n\
class TWindow {\n\
public:\n\
    HWND HWindow;\n\
    TWindow *Parent;\n\
    const char *Title;\n\
    TWindowAttr Attr;\n\
    TWindow *Children[64];\n\
    int ChildCount;\n\
    TWindow(TWindow *parent, const char *title);\n\
    void AddChild(TWindow *c) { if (ChildCount < 64) { Children[ChildCount] = c; ChildCount = ChildCount + 1; } }\n\
    void CreateChildren() { int i; for (i = 0; i < ChildCount; i = i + 1) { Children[i]->Create(); } }\n\
    virtual ~TWindow() {}\n\
    virtual const char *GetClassName() { return \"OWLWindow\"; }\n\
    virtual void GetWindowClass(WNDCLASS& wc);\n\
    virtual BOOL Create();\n\
    void Show(int cmd);\n\
    virtual LRESULT WindowProc(UINT msg, WPARAM w, LPARAM l);\n\
    virtual void EvPaint() {}\n\
    virtual void EvDestroy() {}\n\
    virtual void EvLButtonDown(UINT modKeys, int x, int y) {}\n\
    virtual void EvLButtonUp(UINT modKeys, int x, int y) {}\n\
    virtual void EvMouseMove(UINT modKeys, int x, int y) {}\n\
    virtual void EvCommand(UINT cmdId, HWND ctrl, UINT notify) {}\n\
    virtual void EvKeyDown(UINT key, UINT repeat, UINT flags) {}\n\
    virtual int EvCreate(CREATESTRUCTA *cs) { return 0; }\n\
    LRESULT base_WindowProc(UINT m, WPARAM w, LPARAM l) { return DefWindowProcA(HWindow, m, w, l); }\n\
};\n\
\n\
class TFrameWindow : public TWindow {\n\
public:\n\
    TFrameWindow(TWindow *parent, const char *title) : TWindow(parent, title) {}\n\
    virtual ~TFrameWindow() {}\n\
};\n\
\n\
/* OWL static-text control: a child of the system \"STATIC\" class (no\n\
   RegisterClass); registered with its parent in the ctor and created after\n\
   the parent's HWND exists, via TWindow::CreateChildren. */\n\
class TStatic : public TWindow {\n\
public:\n\
    TStatic(PTWindowsObject parent, int id, const char *text, int x, int y, int w, int h, int textlen);\n\
    virtual ~TStatic() {}\n\
    virtual const char *GetClassName() { return \"STATIC\"; }\n\
    virtual BOOL Create();\n\
};\n\
\n\
class TPaintDC {\n\
public:\n\
    HDC hdc;\n\
    PAINTSTRUCT ps;\n\
    HWND hwnd;\n\
    TPaintDC(TWindow& win) { hwnd = win.HWindow; hdc = BeginPaint(hwnd, &ps); }\n\
    virtual ~TPaintDC() { EndPaint(hwnd, &ps); }\n\
    void TextOut(int x, int y, LPCSTR text) { TextOutA(hdc, x, y, text, strlen(text)); }\n\
};\n\
\n\
HINSTANCE _OwlHInstance = 0;\n\
TApplication *_OwlApp = 0;\n\
int OwlMain(int argc, char **argv);\n\
LRESULT CALLBACK OwlStaticWndProc(HWND h, UINT m, WPARAM w, LPARAM l);\n\
\n\
TApplication::TApplication() {\n\
    MainWindow = 0;\n\
    Status = 0;\n\
    Name = 0;\n\
    hInstance = _OwlHInstance;\n\
    _OwlApp = this;\n\
}\n\
\n\
TApplication::TApplication(LPSTR AName, HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdLine, int cmdShow) {\n\
    MainWindow = 0;\n\
    Status = 0;\n\
    Name = AName;\n\
    _OwlHInstance = hInst;\n\
    hInstance = hInst;\n\
    _OwlApp = this;\n\
}\n\
\n\
void TApplication::InitInstance() {\n\
    InitMainWindow();\n\
    if (MainWindow != 0) {\n\
        MainWindow->Create();\n\
        MainWindow->Show(SW_SHOWNORMAL);\n\
    }\n\
}\n\
\n\
int TApplication::Run() {\n\
    /* OWL app-init lifecycle. On Win32 hPrevInstance is always NULL, so every\n\
       instance is the \"first\" => InitApplication() always runs (matches bcc32).\n\
       InitInstance() does the per-instance InitMainWindow + Create + Show. */\n\
    InitApplication();\n\
    InitInstance();\n\
    MSG msg;\n\
    msg.wParam = 0;\n\
    while (GetMessageA(&msg, 0, 0, 0) > 0) {\n\
        TranslateMessage(&msg);\n\
        DispatchMessageA(&msg);\n\
    }\n\
    Status = (int)msg.wParam;\n\
    return Status;\n\
}\n\
\n\
TWindow::TWindow(TWindow *parent, const char *title) {\n\
    HWindow = 0;\n\
    Parent = parent;\n\
    Title = title;\n\
    ChildCount = 0;\n\
    Attr.X = (int)CW_USEDEFAULT;\n\
    Attr.Y = (int)CW_USEDEFAULT;\n\
    Attr.W = (int)CW_USEDEFAULT;\n\
    Attr.H = (int)CW_USEDEFAULT;\n\
    Attr.Style = WS_OVERLAPPEDWINDOW;\n\
    Attr.Id = 0;\n\
}\n\
\n\
void TWindow::GetWindowClass(WNDCLASS& wc) {\n\
    /* Fill the window-class defaults. OWL apps override this hook to tweak\n\
       the class before registration (CURSAPP sets a custom hCursor); the\n\
       default registers the standard OWL window class. */\n\
    wc.style = CS_HREDRAW | CS_VREDRAW;\n\
    wc.lpfnWndProc = OwlStaticWndProc;\n\
    wc.cbClsExtra = 0;\n\
    wc.cbWndExtra = 0;\n\
    wc.hInstance = _OwlHInstance;\n\
    wc.hIcon = 0;\n\
    wc.hCursor = LoadCursorA(0, (LPCSTR)IDC_ARROW);\n\
    wc.hbrBackground = (HBRUSH)(LONG_PTR)(COLOR_WINDOW + 1);\n\
    wc.lpszMenuName = 0;\n\
    wc.lpszClassName = GetClassName();\n\
}\n\
\n\
BOOL TWindow::Create() {\n\
    WNDCLASS wc;\n\
    GetWindowClass(wc);\n\
    /* B-7 (Phase E / E2 fold-in): surface RegisterClassA failure. A zero\n\
       return means the class registration failed (USER32 sets last-error);\n\
       Create() must NOT then call CreateWindowExA with an unregistered\n\
       class. The happy path is unaffected (a freshly constructed app always\n\
       succeeds); the BOOL return reports failure honestly (TApplication::Run\n\
       already trusts it). The GetWindowClass(WNDCLASS&) hook lets a derived\n\
       class customise the registration (e.g. CURSAPP's I-beam cursor). */\n\
    if (RegisterClassA(&wc) == 0) { return 0; }\n\
    HWND parent_hwnd;\n\
    if (Parent != 0) {\n\
        parent_hwnd = Parent->HWindow;\n\
    } else {\n\
        parent_hwnd = 0;\n\
    }\n\
    HWindow = CreateWindowExA(\n\
        0, GetClassName(), Title,\n\
        Attr.Style,\n\
        Attr.X, Attr.Y, Attr.W, Attr.H,\n\
        parent_hwnd, 0, _OwlHInstance, this);\n\
    if (HWindow == 0) { return 0; }\n\
    /* Create registered child controls now that the parent HWND exists (OWL\n\
       creates children after the parent). A plain TWindow with no children\n\
       skips the loop -- unchanged. */\n\
    CreateChildren();\n\
    return 1;\n\
}\n\
\n\
void TWindow::Show(int cmd) {\n\
    ShowWindow(HWindow, cmd);\n\
    UpdateWindow(HWindow);\n\
}\n\
\n\
TStatic::TStatic(PTWindowsObject parent, int id, const char *text, int x, int y, int w, int h, int textlen) : TWindow(parent, text) {\n\
    Attr.X = x;\n\
    Attr.Y = y;\n\
    Attr.W = w;\n\
    Attr.H = h;\n\
    Attr.Id = id;\n\
    Attr.Style = WS_CHILD | WS_VISIBLE | SS_LEFT;\n\
    if (parent != 0) { parent->AddChild(this); }\n\
}\n\
\n\
BOOL TStatic::Create() {\n\
    HWND ph;\n\
    if (Parent != 0) { ph = Parent->HWindow; } else { ph = 0; }\n\
    /* System \"STATIC\" class -- no RegisterClass; just create the child. */\n\
    HWindow = CreateWindowExA(0, \"STATIC\", Title, Attr.Style,\n\
        Attr.X, Attr.Y, Attr.W, Attr.H, ph, (HMENU)(LONG_PTR)Attr.Id, _OwlHInstance, 0);\n\
    return HWindow != 0;\n\
}\n\
\n\
LRESULT TWindow::WindowProc(UINT msg, WPARAM w, LPARAM l) {\n\
    if (msg == WM_DESTROY) {\n\
        PostQuitMessage(0);\n\
        return 0;\n\
    }\n\
    return DefWindowProcA(HWindow, msg, w, l);\n\
}\n\
\n\
LRESULT CALLBACK OwlStaticWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {\n\
    TWindow *self = 0;\n\
    if (m == WM_NCCREATE) {\n\
        CREATESTRUCTA *cs;\n\
        cs = (CREATESTRUCTA *)l;\n\
        self = (TWindow *)cs->lpCreateParams;\n\
        self->HWindow = h;\n\
        SetWindowLongPtrA(h, GWLP_USERDATA, (LONG_PTR)self);\n\
    }\n\
    self = (TWindow *)GetWindowLongPtrA(h, GWLP_USERDATA);\n\
    if (self != 0) {\n\
        return self->WindowProc(m, w, l);\n\
    }\n\
    return DefWindowProcA(h, m, w, l);\n\
}\n\
\n\
int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR cmd, int show) {\n\
    _OwlHInstance = hI;\n\
    return OwlMain(0, 0);\n\
}\n\
\n\
#define DECLARE_RESPONSE_TABLE(cls) virtual LRESULT WindowProc(UINT msg, WPARAM w, LPARAM l)\n\
#define DEFINE_RESPONSE_TABLE1(cls, base) LRESULT cls::WindowProc(UINT msg, WPARAM w, LPARAM l) {\n\
#define END_RESPONSE_TABLE return this->base_WindowProc(msg, w, l); }\n\
#define EV_WM_PAINT if (msg == WM_PAINT) { this->EvPaint(); return 0; }\n\
#define EV_WM_DESTROY if (msg == WM_DESTROY) { this->EvDestroy(); PostQuitMessage(0); return 0; }\n\
#define EV_WM_LBUTTONDOWN if (msg == WM_LBUTTONDOWN) { this->EvLButtonDown((UINT)w, (int)(short)(l & 0xFFFF), (int)(short)((l >> 16) & 0xFFFF)); return 0; }\n\
#define EV_WM_LBUTTONUP if (msg == WM_LBUTTONUP) { this->EvLButtonUp((UINT)w, (int)(short)(l & 0xFFFF), (int)(short)((l >> 16) & 0xFFFF)); return 0; }\n\
#define EV_WM_MOUSEMOVE if (msg == WM_MOUSEMOVE) { this->EvMouseMove((UINT)w, (int)(short)(l & 0xFFFF), (int)(short)((l >> 16) & 0xFFFF)); return 0; }\n\
#define EV_WM_COMMAND if (msg == WM_COMMAND) { this->EvCommand((UINT)(w & 0xFFFF), (HWND)l, (UINT)(w >> 16)); return 0; }\n\
#define EV_WM_KEYDOWN if (msg == WM_KEYDOWN) { this->EvKeyDown((UINT)w, (UINT)(l & 0xFFFF), (UINT)(l >> 16)); return 0; }\n\
#define EV_WM_CREATE if (msg == WM_CREATE) { CREATESTRUCTA *cs_; cs_ = (CREATESTRUCTA *)l; return (LRESULT)this->EvCreate(cs_); }\n\
\n\
#endif\n";

/// Tick 64 (J-13 v1): the intrinsic `<stdarg.h>` body. Win64's `va_list` is
/// a bare `char*` — the va_arg machinery walks a contiguous array of 8-byte
/// slots in the caller's home/argument space. The macros `va_start`,
/// `va_arg`, and `va_end` are compiler intrinsics (recognised in the
/// parser; see `parser.rs::primary`'s `va_start`/`va_arg`/`va_end` arms)
/// rather than preprocessor expansions, because `va_arg`'s second
/// argument is a *type-id* and mdbcc's preprocessor has no comma-
/// expression-with-side-effects to express the increment-and-load
/// idiom cleanly. So this header just declares the type.
const STDARG_H: &[u8] = b"\
typedef char *va_list;\n";

/// Default resolver: real files for `"..."` (relative to a base dir), and
/// empty stubs for known C system headers (our `printf`/`puts` are intrinsic,
/// so the declarations are not needed yet). `<windows.h>` is the one
/// exception: it resolves to the [`WINDOWS_H`] intrinsic typedef/macro body
/// (Phase C / C3 — Win32 *types* are needed by the parser, unlike intrinsic
/// libc *names*). Phase D / D4 adds the `<owl/*>` umbrella: any system
/// include whose path starts `owl/` resolves to the single
/// [`OWL_RUNTIME_H`] body — the OWL public API + runtime impls in one TU
/// (HLD §D-b "intrinsic OWL implementation TU prepended to the user's
/// source", realised more cleanly as a self-contained intrinsic header
/// guarded with `_OWL_RUNTIME_INCLUDED` so multiple `owl/*` includes are
/// idempotent). Dormant for any TU that does not `#include <owl/*.h>` —
/// the `owl/` prefix gate is the same shape as the literal-`windows.h`
/// gate, so a console program emits zero new bytes (`tests/pe_imports.rs`
/// is the byte-identical executable proof).
pub struct DefaultResolver {
    pub base_dir: std::path::PathBuf,
}

impl IncludeResolver for DefaultResolver {
    fn resolve(&self, name: &str, system: bool) -> Option<Vec<u8>> {
        if system {
            if name == "windows.h" {
                return Some(WINDOWS_H.to_vec());
            }
            // Tick 64 (J-13 v1): `<stdarg.h>` declares `va_list`; the
            // three macros are codegen intrinsics (see `STDARG_H` doc).
            if name == "stdarg.h" {
                return Some(STDARG_H.to_vec());
            }
            // Phase D / D4: any `<owl/...>` header resolves to the single
            // intrinsic OWL runtime body (idempotent via include guard).
            // The `owl/` prefix gate keeps every byte dormant for non-OWL
            // TUs (a console program never includes it ⇒ zero new bytes).
            if name.starts_with("owl/") || name == "owl.h" {
                return Some(OWL_RUNTIME_H.to_vec());
            }
            const KNOWN: &[&str] = &[
                "stdio.h", "stdlib.h", "string.h", "stddef.h", "ctype.h", "math.h", "limits.h",
                "assert.h", "conio.h", "dos.h", "io.h", "time.h", "errno.h", "float.h",
            ];
            if KNOWN.contains(&name) {
                return Some(Vec::new());
            }
            // Unknown system headers: also stub to empty (lenient, era-typical).
            return Some(Vec::new());
        }
        // Quoted include (`#include "..."`): search the local directory first,
        // then fall back to the intrinsic system headers — the standard C
        // lookup order (`""` searches local, then the system path). This lets a
        // sample written with `#include "owl.h"` / `"windows.h"` reach the
        // intrinsic runtime exactly as `<owl.h>` does (CURSAPP/SCRIBAPP use the
        // quoted form). Only `DefaultResolver` (the no-`-I` path) is affected;
        // the `-I` `SearchPathResolver` keeps its own real-file search.
        if let Ok(bytes) = std::fs::read(self.base_dir.join(name)) {
            return Some(bytes);
        }
        self.resolve(name, true)
    }
}

/// S3: a resolver that searches real `-I` include directories before falling
/// back to [`DefaultResolver`]'s era-typical stubbing.
///
/// `resolve(name, system)`:
///   - For `system` (`<...>`): search every `dirs` entry in order for a file
///     named `name`, **case-insensitively** on the final path component (the
///     Borland headers are UPPERCASE — `STDIO.H` — but C source spells the
///     include lowercase: `<stdio.h>`). Subdirectory names work too
///     (`<sys/stat.h>` → `<dir>/SYS/STAT.H`): each path component is matched
///     case-insensitively against the real directory entries. If no `-I` dir
///     has the file, fall through to `self.fallback.resolve(name, true)` so an
///     unknown header still stubs to empty (lenient, period-typical).
///   - For `"..."` (`system == false`): the fallback (`DefaultResolver`)
///     already searches the TU's `base_dir`; try that first, then — only if it
///     misses — search the `-I` dirs (quote-includes fall back to the system
///     search path, as Borland's `bcc` does).
///
/// With NO `-I` dirs this is behaviourally identical to using `DefaultResolver`
/// directly (the `dirs` loop is empty), so the driver only constructs this when
/// at least one `-I` is given — existing no-`-I` callers/tests are unaffected.
pub struct SearchPathResolver {
    pub dirs: Vec<std::path::PathBuf>,
    pub fallback: DefaultResolver,
}

impl SearchPathResolver {
    /// Search `dirs` in order for `name`, matching each path component
    /// case-insensitively against the real on-disk entries. Returns the file
    /// bytes of the first match.
    fn search_dirs(&self, name: &str) -> Option<Vec<u8>> {
        for dir in &self.dirs {
            if let Some(bytes) = read_case_insensitive(dir, name) {
                return Some(bytes);
            }
        }
        None
    }
}

impl IncludeResolver for SearchPathResolver {
    fn resolve(&self, name: &str, system: bool) -> Option<Vec<u8>> {
        if system {
            // System include: real `-I` dirs first, then stub fallback.
            if let Some(bytes) = self.search_dirs(name) {
                return Some(bytes);
            }
            return self.fallback.resolve(name, true);
        }
        // Quote include: a REAL local file (the TU base dir) first, then REAL
        // `-I` dirs, and ONLY if neither exists fall back to the intrinsic/era
        // stub. The fallback's `resolve` stubs every unknown header to empty (it
        // NEVER returns `None`), so it MUST be tried LAST — otherwise a quoted
        // include of a real `-I` header (Borland's `#include "classlib\vectimp.h"`,
        // STREAMBL.H et al.) is shadowed by that empty stub and silently yields
        // no declarations: the file appears included but contributes nothing,
        // with not even a "cannot open" diagnostic — a silent-miscompile hazard.
        // This mirrors the `<...>` (system) arm above, which already searches
        // real `-I` files before stubbing.
        if let Ok(bytes) = std::fs::read(self.fallback.base_dir.join(name)) {
            return Some(bytes);
        }
        if let Some(bytes) = self.search_dirs(name) {
            return Some(bytes);
        }
        self.fallback.resolve(name, false)
    }
}

/// Read the file `rel` (which may contain `/` or `\` subdirectory separators)
/// under `dir`, matching every path component case-insensitively against the
/// real directory entries. Returns the file bytes, or `None` if any component
/// fails to resolve. A fast path tries the literal join first (the common case
/// on case-insensitive Windows filesystems); only on miss do we enumerate.
fn read_case_insensitive(dir: &std::path::Path, rel: &str) -> Option<Vec<u8>> {
    // Fast path: Windows is case-insensitive, so the literal join usually hits
    // even when the on-disk name is `STDIO.H` and `rel` is `stdio.h`.
    let direct = dir.join(rel);
    if let Ok(bytes) = std::fs::read(&direct) {
        return Some(bytes);
    }
    // Slow path: walk the components, matching each against real entries
    // case-insensitively. Handles case-sensitive filesystems and lets the
    // resolver be exercised portably.
    let mut cur = dir.to_path_buf();
    let components: Vec<&str> = rel.split(['/', '\\']).filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return None;
    }
    for (idx, comp) in components.iter().enumerate() {
        let last = idx + 1 == components.len();
        let matched = match_entry(&cur, comp)?;
        cur = matched;
        if last {
            return std::fs::read(&cur).ok();
        }
        if !cur.is_dir() {
            return None;
        }
    }
    None
}

/// Find a directory entry of `dir` whose name equals `want` ignoring ASCII
/// case. Returns the full path of the match.
fn match_entry(dir: &std::path::Path, want: &str) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str()
            && name.eq_ignore_ascii_case(want)
        {
            return Some(entry.path());
        }
    }
    None
}

/// A resolver that knows nothing (used by unit tests with no `#include`).
pub struct NoIncludes;
impl IncludeResolver for NoIncludes {
    fn resolve(&self, _: &str, system: bool) -> Option<Vec<u8>> {
        if system { Some(Vec::new()) } else { None }
    }
}

#[derive(Clone)]
enum Macro {
    Object(Vec<Token>),
    Func {
        params: Vec<String>,
        variadic: bool,
        body: Vec<Token>,
    },
}

/// Preprocess `tokens` (one lexed translation unit, ending in `Eof`).
///
/// `cplusplus` selects the source-language dialect: when `true`, the
/// compiler-predefined macros `__cplusplus` (= 1, the bcc32 4.52 value) and
/// `__BCPLUSPLUS__` (= 0x0340) are visible, so headers guarded by
/// `#if !defined(__cplusplus)` (the `#error "Must use C++"` family) accept and
/// their `extern "C" { }` blocks switch on. When `false` (the C-mode default
/// the *compile* path always passes), neither is defined and `#ifdef
/// __cplusplus` stays false — byte-for-byte the historical behaviour.
pub fn preprocess(
    tokens: Vec<Token>,
    file_name: &str,
    resolver: &dyn IncludeResolver,
    cplusplus: bool,
) -> Result<Vec<Token>, PpError> {
    preprocess_with_defines(tokens, file_name, resolver, cplusplus, &[])
}

/// As [`preprocess`] but seeds command-line object-macro definitions (the
/// `bcc -D<name>[=<value>]` flag) before running. Each `(name, body)` is
/// inserted exactly as an object-like `#define` at the very top of the TU, so
/// `#ifdef`/`#if defined(name)` see it and the body expands at use sites. A
/// later `#define name ...` in the source overrides it (last definition wins),
/// matching the "defines at the start of the unit" model. The bodies are
/// pre-tokenized by the caller (compile.rs, where the `Lexer` lives) so this
/// module needs no lexer dependency. `preprocess` delegates here with `&[]`,
/// so every existing call site — and the 88 byte-identity baselines — is
/// unchanged.
pub fn preprocess_with_defines(
    tokens: Vec<Token>,
    file_name: &str,
    resolver: &dyn IncludeResolver,
    cplusplus: bool,
    defines: &[(String, Vec<Token>)],
) -> Result<Vec<Token>, PpError> {
    let mut pp = Pp::new(file_name, resolver, cplusplus);
    for (name, body) in defines {
        pp.macros.insert(name.clone(), Macro::Object(body.clone()));
    }
    let mut out = pp.run(tokens)?;
    if out.last().map(|t| &t.kind) != Some(&TokenKind::Eof) {
        out.push(Token::new_eof());
    }
    Ok(out)
}

impl Token {
    fn new_eof() -> Token {
        Token {
            kind: TokenKind::Eof,
            line: 0,
            col: 0,
            start_of_line: true,
        }
    }
}

struct Pp<'r> {
    macros: HashMap<String, Macro>,
    resolver: &'r dyn IncludeResolver,
    file: String,
    include_depth: u32,
    /// Source-language dialect: `true` for C++ (`__cplusplus`/`__BCPLUSPLUS__`
    /// predefined), `false` for C (the compile-path default).
    cplusplus: bool,
}

/// One frame of `#if` nesting.
#[derive(Clone, Copy)]
struct Cond {
    /// Tokens in this branch are emitted.
    active: bool,
    /// Some branch (this or an earlier `#elif`/`#else`) has been taken.
    taken: bool,
    /// The enclosing context was emitting (so `#elif` can re-activate).
    parent_active: bool,
    seen_else: bool,
}

impl<'r> Pp<'r> {
    fn new(file: &str, resolver: &'r dyn IncludeResolver, cplusplus: bool) -> Self {
        let mut macros = HashMap::new();
        // `__rtti` is a Borland RTTI class/function qualifier — TYPEINFO.H
        // declares `class __rtti typeinfo`, and OWL classes use it. mdbcc carries
        // no RTTI semantics, so it expands to NOTHING (an empty object-macro):
        // `class __rtti typeinfo` becomes `class typeinfo`. Reserved spelling, so
        // this can't shadow a user identifier; a header never `#define`s it.
        macros.insert("__rtti".to_string(), Macro::Object(Vec::new()));
        // Borland 16-bit SEGMENT pointer modifiers `_seg` / `__seg` — a no-op
        // on the flat (Win32/Win64) target, exactly like `near`/`far`/`huge`
        // (which are lexer keywords). These spellings are NOT lexer keywords,
        // so they reach the parser as identifiers and would be misread as a
        // declarator name (`(void _seg *)` ⇒ "expected ')'"). dos.h's `MK_FP`
        // macro — `((void _seg *)(seg) + (void near *)(ofs))` — pulls this into
        // OWL via WINDOBJ.H → OBJSTRM.H → dos.h. Expand to NOTHING so
        // `(void _seg *)` becomes `(void *)`. Reserved spellings; no portable
        // program (and none of the byte-identity baselines) uses them as names.
        macros.insert("_seg".to_string(), Macro::Object(Vec::new()));
        macros.insert("__seg".to_string(), Macro::Object(Vec::new()));
        Pp {
            macros,
            resolver,
            file: file.to_string(),
            include_depth: 0,
            cplusplus,
        }
    }

    fn err<T>(&self, msg: impl Into<String>, t: &Token) -> Result<T, PpError> {
        Err(PpError {
            message: msg.into(),
            line: t.line,
            col: t.col,
        })
    }

    fn run(&mut self, tokens: Vec<Token>) -> Result<Vec<Token>, PpError> {
        let mut out = Vec::new();
        let mut conds: Vec<Cond> = Vec::new();
        let active = |c: &[Cond]| c.last().map(|x| x.active).unwrap_or(true);

        let mut i = 0;
        while i < tokens.len() {
            let t = &tokens[i];
            if t.kind == TokenKind::Eof {
                break;
            }
            // A directive: `#` first on a logical line.
            if t.start_of_line && t.kind == TokenKind::Punct(Punct::Hash) {
                let (line_toks, next) = take_logical_line(&tokens, i);
                i = next;
                self.directive(&line_toks, &mut conds, &mut out)?;
                continue;
            }
            // Ordinary text: gather a maximal run of CONSECUTIVE
            // non-directive logical lines and expand them as one unit, so a
            // function-like macro invocation whose `(...)` spans line
            // boundaries is fully visible to the expander (C99 §6.10.3 — a
            // macro call may cross newlines; its argument list cannot contain
            // a preprocessing directive, so stopping at the next `#`-line is
            // correct). `active` is constant across a directive-free run, so
            // this does not perturb conditional compilation. For text with no
            // cross-line macro call, expanding the concatenated run yields the
            // same tokens as expanding each line separately ⇒ the 88 O1
            // byte-identity baselines are unchanged.
            let start = i;
            while i < tokens.len() {
                let tk = &tokens[i];
                if tk.kind == TokenKind::Eof {
                    break;
                }
                if tk.start_of_line && tk.kind == TokenKind::Punct(Punct::Hash) {
                    break;
                }
                let (_, next) = take_logical_line(&tokens, i);
                i = next;
            }
            if active(&conds) {
                let expanded = self.expand(tokens[start..i].to_vec())?;
                out.extend(expanded);
            }
        }
        if let Some(c) = conds.first() {
            let _ = c;
            return Err(PpError {
                message: "unterminated #if".into(),
                line: 0,
                col: 0,
            });
        }
        out.push(Token::new_eof());
        Ok(out)
    }

    // ---- directives -------------------------------------------------------

    fn directive(
        &mut self,
        line: &[Token],
        conds: &mut Vec<Cond>,
        out: &mut Vec<Token>,
    ) -> Result<(), PpError> {
        // line[0] == '#'. Null directive (`#` alone) is a no-op.
        let name_tok = match line.get(1) {
            None => return Ok(()),
            Some(t) => t,
        };
        let name = spelling(&name_tok.kind).unwrap_or_default();
        let rest = &line[2..];
        let active = conds.last().map(|c| c.active).unwrap_or(true);

        match name.as_str() {
            "ifdef" | "ifndef" => {
                let cond = if active {
                    let id = rest
                        .first()
                        .and_then(|t| spelling(&t.kind))
                        .ok_or_else(|| PpError {
                            message: format!("#{name} expects an identifier"),
                            line: name_tok.line,
                            col: name_tok.col,
                        })?;
                    let def = self.is_defined(&id);
                    if name == "ifdef" { def } else { !def }
                } else {
                    false
                };
                conds.push(Cond {
                    active: active && cond,
                    taken: cond,
                    parent_active: active,
                    seen_else: false,
                });
            }
            "if" => {
                let cond = if active {
                    self.eval_cond(rest, name_tok)?
                } else {
                    false
                };
                conds.push(Cond {
                    active: active && cond,
                    taken: cond,
                    parent_active: active,
                    seen_else: false,
                });
            }
            "elif" => {
                let c = conds.last_mut().ok_or_else(|| PpError {
                    message: "#elif without #if".into(),
                    line: name_tok.line,
                    col: name_tok.col,
                })?;
                if c.seen_else {
                    return self.err("#elif after #else", name_tok);
                }
                let parent = c.parent_active;
                let already = c.taken;
                if parent && !already {
                    let v = self.eval_cond(rest, name_tok)?;
                    let c = conds.last_mut().unwrap();
                    c.active = v;
                    c.taken = v;
                } else {
                    conds.last_mut().unwrap().active = false;
                }
            }
            "else" => {
                let c = conds.last_mut().ok_or_else(|| PpError {
                    message: "#else without #if".into(),
                    line: name_tok.line,
                    col: name_tok.col,
                })?;
                if c.seen_else {
                    return self.err("multiple #else", name_tok);
                }
                c.seen_else = true;
                c.active = c.parent_active && !c.taken;
                c.taken = true;
            }
            "endif" => {
                if conds.pop().is_none() {
                    return self.err("#endif without #if", name_tok);
                }
            }
            _ if !active => {} // skip every other directive in a dead branch
            "define" => self.do_define(rest, name_tok)?,
            "undef" => {
                if let Some(id) = rest.first().and_then(|t| spelling(&t.kind)) {
                    self.macros.remove(&id);
                }
            }
            "include" => self.do_include(rest, name_tok, conds, out)?,
            "error" => {
                let msg: String = rest
                    .iter()
                    .map(|t| spelling(&t.kind).unwrap_or_else(|| "?".into()))
                    .collect::<Vec<_>>()
                    .join(" ");
                return self.err(format!("#error {msg}"), name_tok);
            }
            "pragma" => {
                // W6 (G48): `#pragma startup <fn> [<priority>]` — Borland's
                // INIT-record registration (run `<fn>` before main/WinMain,
                // ascending priority, default 100). The RTL heap/stdio/cvt
                // init path is built on it (HEAP.C `_init_heap` 2, FILES.C
                // `_init_streams` 5, …). Splice the reserved-identifier form
                //   `__mdbcc_startup__ <fn> <prio> ;`
                // into the token stream; the parser records it on the TU and
                // codegen emits an ordered `.mdbcc_ctor.$startup$…` thunk.
                // (`\u{1}`-style reserved names can't pass the lexer, and no
                // C identifier may collide with the double-underscore form
                // only the pp emits.) Every other pragma stays ignored.
                if active
                    && rest.first().and_then(|t| spelling(&t.kind)).as_deref() == Some("startup")
                    && let Some(fn_tok) = rest.get(1)
                    && matches!(fn_tok.kind, TokenKind::Ident(_))
                {
                    let prio = match rest.get(2).map(|t| &t.kind) {
                        Some(TokenKind::Int { value, .. }) => *value,
                        _ => 100, // Borland default user priority
                    };
                    let mk = |kind: TokenKind| Token {
                        kind,
                        line: name_tok.line,
                        col: name_tok.col,
                        start_of_line: false,
                    };
                    out.push(mk(TokenKind::Ident("__mdbcc_startup__".into())));
                    out.push(fn_tok.clone());
                    out.push(mk(TokenKind::Int {
                        value: prio,
                        unsigned: false,
                        long: false,
                        longlong: false,
                    }));
                    out.push(mk(TokenKind::Punct(Punct::Semi)));
                }
            }
            "line" => {} // accepted and ignored
            "" => {}     // `#` then non-name: treat as null
            other => {
                return self.err(format!("unknown directive #{other}"), name_tok);
            }
        }
        Ok(())
    }

    fn is_defined(&self, name: &str) -> bool {
        self.macros.contains_key(name)
            || matches!(
                name,
                "__LINE__" | "__FILE__" | "__DATE__"
                    | "__TIME__" | "__MDBCC__"
                    // Borland bcc32 4.52 compiler-predefined (see `predefined`).
                    | "__BORLANDC__" | "__TURBOC__" | "__WIN32__" | "__FLAT__"
                    | "__CONSOLE__" | "__TLS__" | "_Windows"
            )
            // C++-mode predefined: visible to `defined()` / `#ifdef` only when
            // preprocessing in C++ mode (matches `predefined`). In C mode both
            // are absent so `#ifdef __cplusplus` is false.
            || (self.cplusplus && matches!(name, "__cplusplus" | "__BCPLUSPLUS__"))
    }

    fn do_define(&mut self, rest: &[Token], at: &Token) -> Result<(), PpError> {
        let name = rest
            .first()
            .and_then(|t| spelling(&t.kind))
            .ok_or_else(|| PpError {
                message: "#define expects a name".into(),
                line: at.line,
                col: at.col,
            })?;
        // Function-like only if `(` immediately follows the name (no space).
        let is_func = rest.get(1).is_some_and(|t| {
            t.kind == TokenKind::Punct(Punct::LParen) && !t.start_of_line && adjacent(&rest[0], t)
        });
        if is_func {
            let mut params = Vec::new();
            let mut variadic = false;
            let mut k = 2; // past name and '('
            if rest.get(k).map(|t| &t.kind) != Some(&TokenKind::Punct(Punct::RParen)) {
                loop {
                    let tk = rest.get(k).ok_or_else(|| PpError {
                        message: "unterminated macro parameter list".into(),
                        line: at.line,
                        col: at.col,
                    })?;
                    if tk.kind == TokenKind::Punct(Punct::Ellipsis) {
                        variadic = true;
                        k += 1;
                        break;
                    }
                    let p = spelling(&tk.kind).ok_or_else(|| PpError {
                        message: "bad macro parameter".into(),
                        line: tk.line,
                        col: tk.col,
                    })?;
                    params.push(p);
                    k += 1;
                    match rest.get(k).map(|t| &t.kind) {
                        Some(TokenKind::Punct(Punct::Comma)) => k += 1,
                        Some(TokenKind::Punct(Punct::RParen)) => break,
                        _ => {
                            return self.err("expected ',' or ')' in macro params", tk);
                        }
                    }
                }
            }
            if rest.get(k).map(|t| &t.kind) != Some(&TokenKind::Punct(Punct::RParen)) {
                return self.err("expected ')' in macro definition", at);
            }
            let body = rest[k + 1..].to_vec();
            self.macros.insert(
                name,
                Macro::Func {
                    params,
                    variadic,
                    body,
                },
            );
        } else {
            self.macros.insert(name, Macro::Object(rest[1..].to_vec()));
        }
        Ok(())
    }

    fn do_include(
        &mut self,
        rest: &[Token],
        at: &Token,
        conds: &mut [Cond],
        out: &mut Vec<Token>,
    ) -> Result<(), PpError> {
        let _ = conds;
        // Header-name token: `"name"` (quoted, local) or `<name>` (angle,
        // system) — both lexed VERBATIM by the lexer, distinguished by `wide`
        // (S4.2r: `true` ⇒ the `<...>` system form). The `Lt`-reconstruction
        // branch below is a defensive fallback (the lexer now emits a single
        // header-name token for both forms).
        let (name, system) =
            if let Some(TokenKind::Str { bytes, wide }) = rest.first().map(|t| &t.kind) {
                (String::from_utf8_lossy(bytes).into_owned(), *wide)
            } else if rest.first().map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::Lt)) {
                let mut s = String::new();
                for t in &rest[1..] {
                    if t.kind == TokenKind::Punct(Punct::Gt) {
                        break;
                    }
                    s.push_str(&spelling(&t.kind).unwrap_or_default());
                }
                (s, true)
            } else {
                return self.err("#include expects \"file\" or <file>", at);
            };

        let bytes = match self.resolver.resolve(&name, system) {
            Some(b) => b,
            None => {
                return self.err(format!("cannot open include file '{name}'"), at);
            }
        };
        if self.include_depth > 64 {
            return self.err("#include nested too deeply", at);
        }
        let toks = Lexer::tokenize(&bytes).map_err(|e| PpError {
            message: format!("in {name}: {}", e.message),
            line: at.line,
            col: at.col,
        })?;
        self.include_depth += 1;
        let processed = self.run(toks)?; // shares macro table (include guards work)
        self.include_depth -= 1;
        out.extend(processed.into_iter().filter(|t| t.kind != TokenKind::Eof));
        Ok(())
    }

    // ---- conditional-expression evaluation -------------------------------

    fn eval_cond(&mut self, toks: &[Token], at: &Token) -> Result<bool, PpError> {
        // 1. Resolve `defined X` / `defined(X)` before macro expansion.
        let mut pre = Vec::new();
        let mut j = 0;
        while j < toks.len() {
            let t = &toks[j];
            if spelling(&t.kind).as_deref() == Some("defined") {
                let (id, adv) = match toks.get(j + 1).map(|x| &x.kind) {
                    Some(TokenKind::Punct(Punct::LParen)) => {
                        let id = toks.get(j + 2).and_then(|x| spelling(&x.kind));
                        if toks.get(j + 3).map(|x| &x.kind)
                            != Some(&TokenKind::Punct(Punct::RParen))
                        {
                            return self.err("expected ')' after defined", t);
                        }
                        (id, 4)
                    }
                    _ => (toks.get(j + 1).and_then(|x| spelling(&x.kind)), 2),
                };
                let id = id.ok_or_else(|| PpError {
                    message: "operator 'defined' needs an identifier".into(),
                    line: t.line,
                    col: t.col,
                })?;
                pre.push(int_tok(if self.is_defined(&id) { 1 } else { 0 }, t));
                j += adv;
            } else {
                pre.push(t.clone());
                j += 1;
            }
        }
        // 2. Macro-expand, then 3. remaining identifiers -> 0.
        let expanded = self.expand(pre)?;
        // 2.5 (S5): the Borland pp extension `sizeof(type)` inside `#if` — the
        // RTL guards `#if ( sizeof( wchar_t ) == 1 ) #error …` (LOCALE/
        // MBYTE1.C); bcc32 4.52 evaluates sizeof of builtin scalar types in pp
        // conditionals. Resolve `sizeof ( <builtin-type run> )` to its Borland
        // Win32 size; an unrecognized operand (pointers, tags, expressions) is
        // left untouched and falls into the historical ident→0 path (a loud
        // eval error, never a silent wrong value).
        let expanded = resolve_pp_sizeof(expanded);
        let mut ev: Vec<Token> = expanded
            .into_iter()
            .filter(|t| t.kind != TokenKind::Eof)
            .map(|t| match &t.kind {
                TokenKind::Ident(_) | TokenKind::Keyword(_) => int_tok(0, &t),
                _ => t,
            })
            .collect();
        if ev.is_empty() {
            return self.err("#if with no expression", at);
        }
        let mut p = CondEval { toks: &ev, pos: 0 };
        let v = p.expr(0)?;
        // touch ev to satisfy borrow lifetime clarity
        ev.clear();
        Ok(v != 0)
    }

    // ---- macro expansion --------------------------------------------------

    fn expand(&self, toks: Vec<Token>) -> Result<Vec<Token>, PpError> {
        let mut hide = HashSet::new();
        self.expand_inner(toks, &mut hide)
    }

    /// §6.10.3.1: macro-expand each function-like-macro argument independently
    /// (used for substitution into PLAIN parameters; `#`/`##` operands keep the
    /// raw argument). The current `hide` set is cloned per argument so the
    /// expansion sees the same already-hidden macros but cannot leak changes —
    /// and, crucially, the macro being invoked is not yet in `hide`, so a nested
    /// call to the same macro inside an argument expands.
    fn expand_args(
        &self,
        args: &[Vec<Token>],
        hide: &HashSet<String>,
    ) -> Result<Vec<Vec<Token>>, PpError> {
        args.iter()
            .map(|a| self.expand_inner(a.clone(), &mut hide.clone()))
            .collect()
    }

    fn expand_inner(
        &self,
        toks: Vec<Token>,
        hide: &mut HashSet<String>,
    ) -> Result<Vec<Token>, PpError> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < toks.len() {
            let t = toks[i].clone();
            let name = match spelling(&t.kind) {
                Some(s) if matches!(t.kind, TokenKind::Ident(_) | TokenKind::Keyword(_)) => s,
                _ => {
                    out.push(t);
                    i += 1;
                    continue;
                }
            };

            if let Some(builtin) = self.predefined(&name, &t) {
                out.push(builtin);
                i += 1;
                continue;
            }
            if hide.contains(&name) {
                out.push(t);
                i += 1;
                continue;
            }
            match self.macros.get(&name) {
                Some(Macro::Object(body)) => {
                    // Object macro: no parameters, so both maps are empty.
                    let sub = substitute(body, &HashMap::new(), &HashMap::new(), false, &[], &t);
                    hide.insert(name.clone());
                    let mut ex = self.expand_inner(sub, hide)?;
                    hide.remove(&name);
                    i += 1;
                    // §6.10.3.4: an object macro whose expansion ends in a
                    // function-like macro NAME forms a call with the source
                    // `(...)` that follows (e.g. `#define MAKEINTRESOURCE
                    // MAKEINTRESOURCEA` then `MAKEINTRESOURCE(32512)`).
                    self.rescan_boundary_call(&mut ex, &toks, &mut i, hide)?;
                    out.append(&mut ex);
                }
                Some(Macro::Func {
                    params,
                    variadic,
                    body,
                }) => {
                    // Needs a '(' (possibly later) to invoke.
                    let mut k = i + 1;
                    if k < toks.len() && toks[k].kind == TokenKind::Punct(Punct::LParen) {
                        let (args, end) = collect_args(&toks, k, &t, self)?;
                        k = end;
                        let raw_map = bind_args(params, *variadic, &args, &t, self)?;
                        // §6.10.3.1: pre-expand each argument (the outer macro is
                        // NOT yet hidden, so a nested call to the SAME macro in an
                        // argument expands — `SC(int*, SC(void*, p))`).
                        let exp_args = self.expand_args(&args, hide)?;
                        let exp_map = bind_args(params, *variadic, &exp_args, &t, self)?;
                        let sub = substitute(body, &raw_map, &exp_map, *variadic, params, &t);
                        hide.insert(name.clone());
                        let mut ex = self.expand_inner(sub, hide)?;
                        hide.remove(&name);
                        i = k;
                        // §6.10.3.4: same boundary rescan if this expansion
                        // itself ends in a pending function-like call.
                        self.rescan_boundary_call(&mut ex, &toks, &mut i, hide)?;
                        out.append(&mut ex);
                    } else {
                        out.push(t);
                        i += 1;
                    }
                }
                None => {
                    out.push(t);
                    i += 1;
                }
            }
        }
        Ok(out)
    }

    /// §6.10.3.4 cross-boundary rescan. After producing a macro expansion
    /// `ex`, if its FINAL token is a function-like macro name (not currently
    /// hidden) and the next *source* token (`toks[*i]`) is `(`, the macro
    /// call spans the replacement/source boundary — expand it now, consuming
    /// the source argument list and advancing `*i` past it. Loops so a chain
    /// (`A` → `B` → `C(...)`) resolves fully.
    ///
    /// This is a **no-op** for any expansion that does not end in such a
    /// pending call: `ex` and `*i` are returned unchanged. Every program in
    /// the O1 byte-identity corpus is non-boundary, so its preprocessed
    /// token stream — and thus its codegen — is byte-for-byte unchanged.
    /// What it fixes: real `<windows.h>` chains like
    /// `#define MAKEINTRESOURCE MAKEINTRESOURCEA` →
    /// `IDC_ARROW` = `MAKEINTRESOURCE(32512)`, which previously left a bare
    /// `MAKEINTRESOURCEA` identifier that codegen saw as an unresolved call.
    fn rescan_boundary_call(
        &self,
        ex: &mut Vec<Token>,
        toks: &[Token],
        i: &mut usize,
        hide: &mut HashSet<String>,
    ) -> Result<(), PpError> {
        loop {
            let Some(last) = ex.last() else { return Ok(()) };
            if !matches!(last.kind, TokenKind::Ident(_) | TokenKind::Keyword(_)) {
                return Ok(());
            }
            let lname = match spelling(&last.kind) {
                Some(s) => s,
                None => return Ok(()),
            };
            if hide.contains(&lname) {
                return Ok(());
            }
            // The tail must be a function-like macro, and the next *source*
            // token must be its opening `(`.
            let (params, variadic, body) = match self.macros.get(&lname) {
                Some(Macro::Func {
                    params,
                    variadic,
                    body,
                }) => (params.clone(), *variadic, body.clone()),
                _ => return Ok(()),
            };
            if *i >= toks.len() || toks[*i].kind != TokenKind::Punct(Punct::LParen) {
                return Ok(());
            }
            let nametok = last.clone();
            let (args, end) = collect_args(toks, *i, &nametok, self)?;
            *i = end;
            let raw_map = bind_args(&params, variadic, &args, &nametok, self)?;
            let exp_args = self.expand_args(&args, hide)?;
            let exp_map = bind_args(&params, variadic, &exp_args, &nametok, self)?;
            let sub = substitute(&body, &raw_map, &exp_map, variadic, &params, &nametok);
            hide.insert(lname.clone());
            let exsub = self.expand_inner(sub, hide)?;
            hide.remove(&lname);
            ex.pop(); // drop the function-like macro NAME we just consumed
            ex.extend(exsub);
            // Loop: the freshly appended tail may itself be another pending
            // boundary call (`A`→`B`→`C(...)`).
        }
    }

    fn predefined(&self, name: &str, at: &Token) -> Option<Token> {
        match name {
            "__LINE__" => Some(int_tok(at.line as i64, at)),
            // S4.2b15: `__STDC__` is DELIBERATELY NOT predefined. It signals
            // strict ISO C (no extensions); mdbcc accepts Borland extensions
            // (`far`, `_import`, templates in C headers, …), so — like bcc32 in
            // its default non-strict mode — `__STDC__` must be UNDEFINED. The
            // RTL/Win32 headers gate their extension blocks on `#if
            // !defined(__STDC__)` (e.g. STDLIB.H's `min`/`max` templates,
            // STDLIB.H:526); defining it skipped those blocks entirely (the
            // STRING RTL's `min` was left undeclared → unresolved at link).
            "__MDBCC__" => Some(int_tok(1, at)),
            // --- Borland bcc32 4.52 compiler-predefined macros (probed from
            // the real bcc32). `__BORLANDC__`/`__TURBOC__` are 0x0460 for BC
            // 4.52 (NOT 0x0452). The Win32/flat-model quartet identifies the
            // 32-bit console target so the headers route into their Win32
            // branches. Deliberately NOT defined here: `_WIN32`, `_M_IX86`,
            // `__MSDOS__` (bcc32 4.52 does not predefine these compiler-side —
            // `windef.h` derives `_WIN32` from `__BORLANDC__ < 0x500`).
            "__BORLANDC__" | "__TURBOC__" => Some(int_tok(0x0460, at)),
            "__WIN32__" | "__FLAT__" | "__CONSOLE__" | "__TLS__" | "_Windows" => {
                Some(int_tok(1, at))
            }
            // C++-mode only (probed from bcc32 4.52 compiling a `.cpp` TU):
            // `__cplusplus` == 1 and `__BCPLUSPLUS__` == 0x0340. Gated on
            // `cplusplus` so the C-mode compile path leaves both undefined
            // (and `#ifdef __cplusplus` false) — this is what flips on the
            // C++-only headers' `extern "C" {` blocks in the O15 oracle.
            "__cplusplus" if self.cplusplus => Some(int_tok(1, at)),
            "__BCPLUSPLUS__" if self.cplusplus => Some(int_tok(0x0340, at)),
            "__FILE__" => Some(Token {
                kind: TokenKind::Str {
                    bytes: self.file.clone().into_bytes(),
                    wide: false,
                },
                line: at.line,
                col: at.col,
                start_of_line: false,
            }),
            "__DATE__" => Some(str_tok("Jan  1 2026", at)),
            "__TIME__" => Some(str_tok("00:00:00", at)),
            _ => None,
        }
    }
}

// ---- free helpers --------------------------------------------------------

/// True iff `b` immediately follows `a` in the source with NO intervening
/// whitespace — i.e. `b` begins exactly where `a`'s spelling ends. This is
/// what distinguishes a **function-like** macro `NAME(args)` from an
/// **object-like** macro whose replacement list merely starts with `(`,
/// e.g. `#define EOF (-1)` (X3J11 §6.10.3): the `(` is part of the
/// definition's *parameter list* only when it directly abuts the name.
///
/// The previous heuristic (`b.col > a.col`) treated ANY same-line `(` after
/// the name as function-like, so every spaced object-macro like `(-1)` was
/// mis-parsed — the single biggest source of real-header `#define` rejects.
/// `a` is always the macro-name identifier here, whose source width equals
/// its spelling length (identifiers carry no escapes), so col-adjacency is
/// exact.
fn adjacent(a: &Token, b: &Token) -> bool {
    a.line == b.line && spelling(&a.kind).is_some_and(|s| b.col == a.col + s.len() as u32)
}

/// Collect tokens of one logical line starting at `start`; returns the line
/// (without the trailing newline) and the index just past it.
fn take_logical_line(toks: &[Token], start: usize) -> (Vec<Token>, usize) {
    let mut i = start + 1;
    while i < toks.len() && toks[i].kind != TokenKind::Eof && !toks[i].start_of_line {
        i += 1;
    }
    (toks[start..i].to_vec(), i)
}

/// S5: resolve the Borland pp extension `sizeof ( <builtin-type run> )` inside
/// an `#if` expression to an integer token carrying the type's Borland Win32
/// size (`sizeof(wchar_t)` = 2, `sizeof(long double)` = 10, …). Only a flat
/// run of builtin type keywords (plus the `wchar_t` typedef-ident) up to the
/// closing `)` is resolved; anything else (a `*`, a tag, an expression) leaves
/// the tokens untouched so the historical ident→0 mapping surfaces a loud
/// evaluation error rather than a silent wrong value.
fn resolve_pp_sizeof(toks: Vec<Token>) -> Vec<Token> {
    let mut out: Vec<Token> = Vec::with_capacity(toks.len());
    let mut i = 0;
    while i < toks.len() {
        if matches!(toks[i].kind, TokenKind::Keyword(Keyword::Sizeof))
            && toks.get(i + 1).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::LParen))
        {
            let mut j = i + 2;
            let (mut c_char, mut c_short, mut c_int, mut c_float, mut c_double) =
                (false, false, false, false, false);
            let (mut c_wchar, mut c_sign, mut other) = (false, false, false);
            let mut n_long = 0usize;
            while let Some(t) = toks.get(j) {
                match &t.kind {
                    TokenKind::Punct(Punct::RParen) => break,
                    TokenKind::Ident(s) if s == "wchar_t" => c_wchar = true,
                    TokenKind::Keyword(Keyword::Char) => c_char = true,
                    TokenKind::Keyword(Keyword::Short) => c_short = true,
                    TokenKind::Keyword(Keyword::Int) => c_int = true,
                    TokenKind::Keyword(Keyword::Long) => n_long += 1,
                    TokenKind::Keyword(Keyword::Float) => c_float = true,
                    TokenKind::Keyword(Keyword::Double) => c_double = true,
                    TokenKind::Keyword(Keyword::Signed | Keyword::Unsigned) => {
                        c_sign = true;
                    }
                    _ => {
                        other = true;
                        break;
                    }
                }
                j += 1;
            }
            let closed = toks.get(j).map(|t| &t.kind) == Some(&TokenKind::Punct(Punct::RParen));
            let size: Option<i64> = if other || !closed {
                None
            } else if c_wchar && !(c_char || c_short || c_int || c_float || c_double || n_long > 0)
            {
                Some(2) // Borland Win32 wchar_t (unsigned short)
            } else if c_double {
                Some(if n_long > 0 { 10 } else { 8 }) // Borland long double = 10
            } else if c_float {
                Some(4)
            } else if c_char {
                Some(1)
            } else if c_short {
                Some(2)
            } else if n_long == 2 {
                Some(8)
            } else if n_long == 1 || c_int || c_sign {
                Some(4)
            } else {
                None
            };
            if let Some(sz) = size {
                out.push(int_tok(sz, &toks[i]));
                i = j + 1; // past the closing `)`
                continue;
            }
        }
        out.push(toks[i].clone());
        i += 1;
    }
    out
}

fn int_tok(v: i64, at: &Token) -> Token {
    Token {
        kind: TokenKind::Int {
            value: v.unsigned_abs() as u128,
            unsigned: false,
            long: false,
            longlong: false,
        },
        line: at.line,
        col: at.col,
        start_of_line: false,
    }
}

fn str_tok(s: &str, at: &Token) -> Token {
    Token {
        kind: TokenKind::Str {
            bytes: s.as_bytes().to_vec(),
            wide: false,
        },
        line: at.line,
        col: at.col,
        start_of_line: false,
    }
}

/// Collect the argument token lists of a function-macro invocation. `lp` is
/// the index of `(`. Returns (args, index-past-`)`).
fn collect_args(
    toks: &[Token],
    lp: usize,
    at: &Token,
    pp: &Pp,
) -> Result<(Vec<Vec<Token>>, usize), PpError> {
    let mut args: Vec<Vec<Token>> = vec![Vec::new()];
    let mut depth = 0i32;
    let mut i = lp;
    loop {
        let t = toks.get(i).ok_or_else(|| PpError {
            message: "unterminated macro argument list".into(),
            line: at.line,
            col: at.col,
        })?;
        match &t.kind {
            TokenKind::Punct(Punct::LParen) => {
                depth += 1;
                if depth > 1 {
                    args.last_mut().unwrap().push(t.clone());
                }
            }
            TokenKind::Punct(Punct::RParen) => {
                depth -= 1;
                if depth == 0 {
                    let _ = pp;
                    return Ok((args, i + 1));
                }
                args.last_mut().unwrap().push(t.clone());
            }
            TokenKind::Punct(Punct::Comma) if depth == 1 => args.push(Vec::new()),
            _ => args.last_mut().unwrap().push(t.clone()),
        }
        i += 1;
    }
}

fn bind_args(
    params: &[String],
    variadic: bool,
    args: &[Vec<Token>],
    at: &Token,
    pp: &Pp,
) -> Result<HashMap<String, Vec<Token>>, PpError> {
    // A single empty arg means "no arguments".
    let args: Vec<Vec<Token>> =
        if args.len() == 1 && args[0].is_empty() && params.is_empty() && !variadic {
            Vec::new()
        } else {
            args.to_vec()
        };
    if !variadic && args.len() != params.len() {
        return Err(PpError {
            message: format!(
                "macro expects {} argument(s), got {}",
                params.len(),
                args.len()
            ),
            line: at.line,
            col: at.col,
        });
    }
    if variadic && args.len() < params.len() {
        return Err(PpError {
            message: "too few arguments for variadic macro".into(),
            line: at.line,
            col: at.col,
        });
    }
    let mut map = HashMap::new();
    for (i, p) in params.iter().enumerate() {
        map.insert(p.clone(), args[i].clone());
    }
    if variadic {
        let mut va: Vec<Token> = Vec::new();
        for (k, a) in args.iter().enumerate().skip(params.len()) {
            if k > params.len() {
                va.push(comma_tok(at));
            }
            va.extend(a.clone());
        }
        map.insert("__VA_ARGS__".to_string(), va);
    }
    let _ = pp;
    Ok(map)
}

fn comma_tok(at: &Token) -> Token {
    Token {
        kind: TokenKind::Punct(Punct::Comma),
        line: at.line,
        col: at.col,
        start_of_line: false,
    }
}

/// Substitute parameters into a macro body. §6.10.3.1: a plain parameter is
/// replaced by its fully MACRO-EXPANDED argument (`exp`), whereas the operand of
/// `#` (stringize) or `##` (paste) uses the RAW, unexpanded argument (`raw`).
fn substitute(
    body: &[Token],
    raw: &HashMap<String, Vec<Token>>,
    exp: &HashMap<String, Vec<Token>>,
    _variadic: bool,
    _params: &[String],
    at: &Token,
) -> Vec<Token> {
    let mut out: Vec<Token> = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let t = &body[i];
        // Stringize: # param
        if t.kind == TokenKind::Punct(Punct::Hash)
            && let Some(nm) = body.get(i + 1).and_then(|x| spelling(&x.kind))
            && let Some(arg) = raw.get(&nm)
        {
            out.push(str_tok(&stringize(arg), at));
            i += 2;
            continue;
        }
        // Paste: lhs ## rhs
        if body.get(i + 1).map(|x| &x.kind) == Some(&TokenKind::Punct(Punct::HashHash)) {
            let mut lhs: Vec<Token> = arg_or_self(t, raw);
            let mut j = i;
            while body.get(j + 1).map(|x| &x.kind) == Some(&TokenKind::Punct(Punct::HashHash)) {
                let rhs_tok = &body[j + 2];
                let rhs = arg_or_self(rhs_tok, raw);
                let l = lhs.pop();
                let r = rhs.first().cloned();
                if let (Some(l), Some(r)) = (l.clone(), r.clone()) {
                    lhs.push(paste(&l, &r, at));
                    lhs.extend(rhs.into_iter().skip(1));
                } else {
                    if let Some(l) = l {
                        lhs.push(l);
                    }
                    lhs.extend(rhs);
                }
                j += 2;
            }
            out.extend(lhs);
            i = j + 1;
            continue;
        }
        // Plain parameter -> its fully macro-EXPANDED argument tokens.
        if let Some(nm) = spelling(&t.kind)
            && let Some(arg) = exp.get(&nm)
        {
            out.extend(arg.clone());
            i += 1;
            continue;
        }
        out.push(t.clone());
        i += 1;
    }
    out
}

fn arg_or_self(t: &Token, args: &HashMap<String, Vec<Token>>) -> Vec<Token> {
    if let Some(nm) = spelling(&t.kind)
        && let Some(a) = args.get(&nm)
    {
        return a.clone();
    }
    vec![t.clone()]
}

fn stringize(toks: &[Token]) -> String {
    let mut s = String::new();
    for (i, t) in toks.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&spelling(&t.kind).unwrap_or_default());
    }
    s
}

/// Concatenate two tokens' spellings and re-lex into one token.
fn paste(a: &Token, b: &Token, at: &Token) -> Token {
    let mut s = spelling(&a.kind).unwrap_or_default();
    s.push_str(&spelling(&b.kind).unwrap_or_default());
    match Lexer::tokenize(s.as_bytes()) {
        Ok(mut v) if v.len() == 2 => {
            let mut tk = v.remove(0);
            tk.line = at.line;
            tk.col = at.col;
            tk
        }
        // If it does not form a single token, keep the left (lenient).
        _ => a.clone(),
    }
}

/// Spelling of a token for stringize/paste/name lookup. Covers the cases the
/// preprocessor needs.
pub fn spelling(k: &TokenKind) -> Option<String> {
    Some(match k {
        TokenKind::Ident(s) => s.clone(),
        TokenKind::Keyword(kw) => keyword_str(*kw).to_string(),
        TokenKind::Int { value, .. } => value.to_string(),
        TokenKind::Str { bytes, .. } => {
            format!("\"{}\"", String::from_utf8_lossy(bytes))
        }
        TokenKind::Char { value, .. } => format!("'{}'", (*value as u8) as char),
        TokenKind::Float(s) => s.clone(),
        TokenKind::Punct(p) => punct_str(*p).to_string(),
        // A lone non-white-space byte (e.g. the `'` in `#error Can't ...`).
        // Spells as that single character so directive free-text round-trips.
        TokenKind::Other(b) => (*b as char).to_string(),
        TokenKind::Eof => return None,
    })
}

fn punct_str(p: Punct) -> &'static str {
    use Punct::*;
    match p {
        LParen => "(",
        RParen => ")",
        LBrace => "{",
        RBrace => "}",
        LBracket => "[",
        RBracket => "]",
        Semi => ";",
        Comma => ",",
        Dot => ".",
        Arrow => "->",
        Ellipsis => "...",
        Plus => "+",
        Minus => "-",
        Star => "*",
        Slash => "/",
        Percent => "%",
        Inc => "++",
        Dec => "--",
        Amp => "&",
        Pipe => "|",
        Caret => "^",
        Tilde => "~",
        Bang => "!",
        Shl => "<<",
        Shr => ">>",
        Lt => "<",
        Gt => ">",
        Le => "<=",
        Ge => ">=",
        EqEq => "==",
        Ne => "!=",
        AndAnd => "&&",
        OrOr => "||",
        Assign => "=",
        PlusEq => "+=",
        MinusEq => "-=",
        StarEq => "*=",
        SlashEq => "/=",
        PercentEq => "%=",
        AmpEq => "&=",
        PipeEq => "|=",
        CaretEq => "^=",
        ShlEq => "<<=",
        ShrEq => ">>=",
        Question => "?",
        Colon => ":",
        ColonColon => "::",
        DotStar => ".*",
        ArrowStar => "->*",
        Hash => "#",
        HashHash => "##",
    }
}

fn keyword_str(k: Keyword) -> &'static str {
    use Keyword::*;
    match k {
        Auto => "auto",
        Break => "break",
        Case => "case",
        Char => "char",
        Const => "const",
        Continue => "continue",
        Default => "default",
        Do => "do",
        Double => "double",
        Else => "else",
        Enum => "enum",
        Extern => "extern",
        Float => "float",
        For => "for",
        Goto => "goto",
        If => "if",
        Int => "int",
        Long => "long",
        Register => "register",
        Return => "return",
        Short => "short",
        Signed => "signed",
        Sizeof => "sizeof",
        Static => "static",
        Struct => "struct",
        Switch => "switch",
        Typedef => "typedef",
        Union => "union",
        Unsigned => "unsigned",
        Void => "void",
        Volatile => "volatile",
        While => "while",
        Asm => "asm",
        Catch => "catch",
        Class => "class",
        ConstCast => "const_cast",
        Delete => "delete",
        DynamicCast => "dynamic_cast",
        Explicit => "explicit",
        Friend => "friend",
        Inline => "inline",
        Namespace => "namespace",
        New => "new",
        Operator => "operator",
        Private => "private",
        Protected => "protected",
        Public => "public",
        ReinterpretCast => "reinterpret_cast",
        StaticCast => "static_cast",
        Template => "template",
        This => "this",
        Throw => "throw",
        Try => "try",
        Typeid => "typeid",
        Typename => "typename",
        Using => "using",
        Virtual => "virtual",
        Near => "near",
        Far => "far",
        Huge => "huge",
        Cdecl => "cdecl",
        Pascal => "pascal",
        Interrupt => "interrupt",
        Fastcall => "_fastcall",
        Stdcall => "_stdcall",
        Export => "_export",
        Import => "_import",
        Asm2 => "__asm",
        Declspec => "__declspec",
        Int8 => "__int8",
        Int16 => "__int16",
        Int32 => "__int32",
        Int64 => "__int64",
    }
}

/// Pratt evaluator for `#if` constant expressions over `int`s (`i64`).
struct CondEval<'a> {
    toks: &'a [Token],
    pos: usize,
}

impl CondEval<'_> {
    fn peek(&self) -> Option<&TokenKind> {
        self.toks.get(self.pos).map(|t| &t.kind)
    }

    fn unary(&mut self) -> Result<i64, PpError> {
        match self.peek().cloned() {
            Some(TokenKind::Punct(Punct::Minus)) => {
                self.pos += 1;
                Ok(-self.unary()?)
            }
            Some(TokenKind::Punct(Punct::Plus)) => {
                self.pos += 1;
                self.unary()
            }
            Some(TokenKind::Punct(Punct::Bang)) => {
                self.pos += 1;
                Ok((self.unary()? == 0) as i64)
            }
            Some(TokenKind::Punct(Punct::Tilde)) => {
                self.pos += 1;
                Ok(!self.unary()?)
            }
            Some(TokenKind::Punct(Punct::LParen)) => {
                self.pos += 1;
                let v = self.expr(0)?;
                if self.peek() != Some(&TokenKind::Punct(Punct::RParen)) {
                    return Err(self.oops("expected ')'"));
                }
                self.pos += 1;
                Ok(v)
            }
            Some(TokenKind::Int { value, .. }) => {
                self.pos += 1;
                Ok(value as i64)
            }
            Some(TokenKind::Char { value, .. }) => {
                self.pos += 1;
                Ok(value)
            }
            _ => Err(self.oops("expected a value in #if expression")),
        }
    }

    /// Precedence-climbing for binary and `?:` operators.
    fn expr(&mut self, min_bp: u8) -> Result<i64, PpError> {
        let mut lhs = self.unary()?;
        while let Some(&TokenKind::Punct(p)) = self.peek() {
            let Some((op, lbp, rbp)) = bin_bp(p) else {
                break;
            };
            if lbp < min_bp {
                break;
            }
            // Ternary: lhs ? a : b
            if op == Punct::Question {
                self.pos += 1;
                let a = self.expr(0)?;
                if self.peek() != Some(&TokenKind::Punct(Punct::Colon)) {
                    return Err(self.oops("expected ':' in ?: "));
                }
                self.pos += 1;
                let b = self.expr(rbp)?;
                lhs = if lhs != 0 { a } else { b };
                continue;
            }
            self.pos += 1;
            let rhs = self.expr(rbp)?;
            lhs = apply(op, lhs, rhs);
        }
        Ok(lhs)
    }

    fn oops(&self, m: &str) -> PpError {
        let t = self.toks.get(self.pos).or_else(|| self.toks.last());
        PpError {
            message: m.into(),
            line: t.map(|x| x.line).unwrap_or(0),
            col: t.map(|x| x.col).unwrap_or(0),
        }
    }
}

fn bin_bp(p: Punct) -> Option<(Punct, u8, u8)> {
    use Punct::*;
    // (operator, left binding power, right binding power)
    Some(match p {
        Star | Slash | Percent => (p, 20, 21),
        Plus | Minus => (p, 18, 19),
        Shl | Shr => (p, 16, 17),
        Lt | Le | Gt | Ge => (p, 14, 15),
        EqEq | Ne => (p, 12, 13),
        Amp => (p, 10, 11),
        Caret => (p, 8, 9),
        Pipe => (p, 6, 7),
        AndAnd => (p, 4, 5),
        OrOr => (p, 2, 3),
        Question => (p, 1, 0), // right-assoc ternary
        _ => return None,
    })
}

fn apply(op: Punct, a: i64, b: i64) -> i64 {
    use Punct::*;
    match op {
        Star => a.wrapping_mul(b),
        Slash => {
            if b == 0 {
                0
            } else {
                a.wrapping_div(b)
            }
        }
        Percent => {
            if b == 0 {
                0
            } else {
                a.wrapping_rem(b)
            }
        }
        Plus => a.wrapping_add(b),
        Minus => a.wrapping_sub(b),
        Shl => a.wrapping_shl(b as u32),
        Shr => a.wrapping_shr(b as u32),
        Lt => (a < b) as i64,
        Le => (a <= b) as i64,
        Gt => (a > b) as i64,
        Ge => (a >= b) as i64,
        EqEq => (a == b) as i64,
        Ne => (a != b) as i64,
        Amp => a & b,
        Caret => a ^ b,
        Pipe => a | b,
        AndAnd => ((a != 0) && (b != 0)) as i64,
        OrOr => ((a != 0) || (b != 0)) as i64,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Preprocess a string in C mode and return the non-Eof tokens' spellings.
    fn pp(src: &str) -> Vec<String> {
        pp_mode(src, false)
    }

    /// As [`pp`] but with an explicit `cplusplus` dialect flag.
    fn pp_mode(src: &str, cplusplus: bool) -> Vec<String> {
        let toks = Lexer::tokenize(src.as_bytes()).expect("lex");
        let out = preprocess(toks, "test.c", &NoIncludes, cplusplus).expect("pp ok");
        out.into_iter()
            .filter(|t| t.kind != TokenKind::Eof)
            .map(|t| spelling(&t.kind).unwrap_or_default())
            .collect()
    }

    fn pp_err(src: &str) -> PpError {
        let toks = Lexer::tokenize(src.as_bytes()).expect("lex");
        preprocess(toks, "t.c", &NoIncludes, false).unwrap_err()
    }

    #[test]
    fn object_macro() {
        assert_eq!(pp("#define N 42\nint x = N;"), ["int", "x", "=", "42", ";"]);
    }

    /// Preprocess with command-line `-D` defines (each value already lexed).
    fn pp_def(src: &str, defines: &[(&str, &str)]) -> Vec<String> {
        let toks = Lexer::tokenize(src.as_bytes()).expect("lex");
        let defs: Vec<(String, Vec<Token>)> = defines
            .iter()
            .map(|(n, v)| {
                let mut vt = Lexer::tokenize(v.as_bytes()).expect("lex value");
                vt.retain(|t| t.kind != TokenKind::Eof);
                (n.to_string(), vt)
            })
            .collect();
        let out =
            preprocess_with_defines(toks, "test.c", &NoIncludes, false, &defs).expect("pp ok");
        out.into_iter()
            .filter(|t| t.kind != TokenKind::Eof)
            .map(|t| spelling(&t.kind).unwrap_or_default())
            .collect()
    }

    #[test]
    fn cli_define_satisfies_ifdef_and_expands() {
        // `-DWIN31` (value "1"): `#ifdef WIN31` branch taken; bare `WIN31` use
        // expands to the body. Mirrors how OWL's APPLICAT.H guards on WIN31.
        assert_eq!(
            pp_def(
                "#ifdef WIN31\nok\n#else\n#error nope\n#endif\nint v = WIN31;",
                &[("WIN31", "1")]
            ),
            ["ok", "int", "v", "=", "1", ";"]
        );
        // `-DFOO=bar` defines an object macro with a token body.
        assert_eq!(pp_def("FOO", &[("FOO", "bar")]), ["bar"]);
        // No defines ⇒ identical to plain `preprocess` (the delegation path).
        assert_eq!(pp_def("int x;", &[]), ["int", "x", ";"]);
    }

    #[test]
    fn object_macro_recursive_and_nested() {
        assert_eq!(pp("#define A B\n#define B 7\nA"), ["7"]);
        // Self-reference must not loop.
        assert_eq!(pp("#define X X\nX"), ["X"]);
    }

    #[test]
    fn function_macro_and_args() {
        assert_eq!(
            pp("#define ADD(a,b) ((a)+(b))\nADD(1,2*3)"),
            ["(", "(", "1", ")", "+", "(", "2", "*", "3", ")", ")"]
        );
    }

    #[test]
    fn function_macro_argument_prescan() {
        // §6.10.3.1: an argument is macro-expanded BEFORE substitution into a
        // plain parameter — including a nested call to the SAME macro
        // (CLASSLIB's `STATIC_CAST(T*, STATIC_CAST(void*, x))`).
        assert_eq!(
            pp("#define SC(t,e) static_cast<t>(e)\nSC(int*, SC(void*, p))"),
            [
                "static_cast",
                "<",
                "int",
                "*",
                ">",
                "(",
                "static_cast",
                "<",
                "void",
                "*",
                ">",
                "(",
                "p",
                ")",
                ")"
            ]
        );
        // A different inner macro as an argument also pre-expands.
        assert_eq!(
            pp("#define ID(x) x\n#define F(a) [a]\nF(ID(9))"),
            ["[", "9", "]"]
        );
        // But the operand of `#` keeps the RAW (unexpanded) argument (mdbcc's
        // stringize single-spaces tokens, so `ID(9)` → `"ID ( 9 )"` — the point
        // is it is NOT pre-expanded to `9`).
        assert_eq!(
            pp("#define ID(x) x\n#define STR(s) #s\nSTR(ID(9))"),
            ["\"ID ( 9 )\""]
        );
    }

    #[test]
    fn stringize_and_paste() {
        assert_eq!(
            pp("#define STR(x) #x\nSTR(hello world)"),
            ["\"hello world\""]
        );
        assert_eq!(pp("#define CAT(a,b) a##b\nCAT(foo,bar)"), ["foobar"]);
        assert_eq!(
            pp("#define CAT(a,b) a##b\nint CAT(v,1) ;"),
            ["int", "v1", ";"]
        );
    }

    #[test]
    fn variadic_macro() {
        assert_eq!(
            pp("#define P(...) f(__VA_ARGS__)\nP(1,2,3)"),
            ["f", "(", "1", ",", "2", ",", "3", ")"]
        );
    }

    /// A recording resolver — captures the (name, system) of every `#include`
    /// and resolves each to an empty header so preprocessing succeeds.
    struct Recorder(std::cell::RefCell<Vec<(String, bool)>>);
    impl IncludeResolver for Recorder {
        fn resolve(&self, name: &str, system: bool) -> Option<Vec<u8>> {
            self.0.borrow_mut().push((name.to_string(), system));
            Some(Vec::new())
        }
    }
    fn record_includes(src: &str) -> Vec<(String, bool)> {
        let rec = Recorder(std::cell::RefCell::new(Vec::new()));
        let toks = Lexer::tokenize(src.as_bytes()).expect("lex");
        preprocess(toks, "t.c", &rec, false).expect("pp ok");
        rec.0.into_inner()
    }

    /// The header-name of a quoted `#include "..."` is LITERAL: a backslash is a
    /// path separator, not a string escape. Borland's `STREAMBL.H` writes
    /// `#include "classlib\vectimp.h"`; before the header-name lexer this lost
    /// `\v` to a vertical-tab escape, producing `classlib<VT>ectimp.h`.
    #[test]
    fn include_quoted_header_name_is_literal_no_escape() {
        // Rust source `\\v` is the two bytes `\` `v`; `\\t` is `\` `t`.
        assert_eq!(
            record_includes("#include \"classlib\\vectimp.h\"\n"),
            [("classlib\\vectimp.h".to_string(), false)]
        );
        // `\t`, `\b`, `\a` etc. would all corrupt under escape processing too.
        assert_eq!(
            record_includes("#  include \"sys\\types.h\"\n"),
            [("sys\\types.h".to_string(), false)]
        );
    }

    /// The angle form `<...>` is a literal header-name (S4.2r); a forward-slash
    /// system path is unchanged (still `system == true`).
    #[test]
    fn include_angle_forward_slash_unchanged() {
        assert_eq!(
            record_includes("#include <classlib/vectimp.h>\n"),
            [("classlib/vectimp.h".to_string(), true)]
        );
    }

    /// S4.2r: a BACKSLASH path in an angle `#include <...>` is verbatim and stays
    /// a system header — `#include <owl\owlpch.h>` is the form every OWL sample
    /// app and OBSOLETE header uses. Before the angle header-name lexer this
    /// failed with "unexpected character '\\'".
    #[test]
    fn include_angle_backslash_header_name_is_literal_system() {
        assert_eq!(
            record_includes("#include <owl\\owlpch.h>\n"),
            [("owl\\owlpch.h".to_string(), true)]
        );
        assert_eq!(
            record_includes("#include <owl\\applicat.h>\n"),
            [("owl\\applicat.h".to_string(), true)]
        );
    }

    /// S5: a quoted `#include "dir\\file.h"` whose target lives in a `-I`
    /// directory (NOT the TU's base dir) must resolve to the REAL file, not be
    /// shadowed by the fallback's empty stub. Borland's STREAMBL.H writes
    /// `#include "classlib\vectimp.h"`; before this fix `SearchPathResolver`
    /// tried the stubbing fallback FIRST for quote includes, and that fallback
    /// stubs every unknown header to empty (never `None`) — so the real `-I`
    /// header was silently replaced by an empty body (no declarations, no
    /// diagnostic), and the include chain that registers `TISVectorImp`
    /// vanished. Both slash forms must hit the real file; a genuinely-absent
    /// header must still stub (the era-typical leniency is preserved).
    #[test]
    fn quote_include_of_dash_i_header_finds_real_file_not_stub() {
        let root = std::env::temp_dir().join(format!("mdbcc_pp_quote_inc_{}", std::process::id()));
        let sub = root.join("classlib");
        std::fs::create_dir_all(&sub).expect("mkdir temp include tree");
        let marker = b"int MDBCC_QUOTE_INCLUDE_MARKER;\n";
        std::fs::write(sub.join("vectimp.h"), marker).expect("write header");
        let base = root.join("tu"); // empty TU dir — does NOT contain classlib/
        std::fs::create_dir_all(&base).expect("mkdir base");

        let resolver = SearchPathResolver {
            dirs: vec![root.clone()],
            fallback: DefaultResolver { base_dir: base },
        };
        // Backslash quote form (exactly Borland's STREAMBL.H spelling).
        assert_eq!(
            resolver.resolve("classlib\\vectimp.h", false).as_deref(),
            Some(&marker[..]),
            "backslash quote include must resolve to the real -I file, not an empty stub"
        );
        // Forward-slash quote form resolves to the same real file.
        assert_eq!(
            resolver.resolve("classlib/vectimp.h", false).as_deref(),
            Some(&marker[..]),
            "forward-slash quote include must also resolve to the real -I file"
        );
        // A genuinely-absent quoted header still stubs to empty (unchanged).
        assert_eq!(
            resolver.resolve("classlib\\nope.h", false).as_deref(),
            Some(&b""[..]),
            "an absent quote include still stubs to empty (era-typical leniency)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An ordinary string literal (NOT an include header-name) still decodes
    /// escapes — `\v` is a vertical tab. Guards that the header-name state
    /// machine doesn't leak into normal string lexing.
    #[test]
    fn ordinary_string_literal_still_escapes() {
        let toks = Lexer::tokenize(b"char *s = \"a\\vb\";").expect("lex");
        let s = toks
            .iter()
            .find_map(|t| match &t.kind {
                TokenKind::Str { bytes, .. } => Some(bytes.clone()),
                _ => None,
            })
            .expect("a string token");
        assert_eq!(s, vec![b'a', 0x0b, b'b']);
    }

    #[test]
    fn ifdef_ifndef_else() {
        assert_eq!(pp("#define A\n#ifdef A\n1\n#else\n2\n#endif"), ["1"]);
        assert_eq!(pp("#ifndef A\n1\n#else\n2\n#endif"), ["1"]);
        assert_eq!(pp("#ifdef NOPE\n1\n#endif\n9"), ["9"]);
    }

    #[test]
    fn if_elif_else_expr() {
        let s = "#define V 3\n#if V == 1\na\n#elif V == 3\nb\n#else\nc\n#endif";
        assert_eq!(pp(s), ["b"]);
        assert_eq!(pp("#if 2+3*2 > 7\nyes\n#endif"), ["yes"]);
        assert_eq!(pp("#if defined(X) || !defined(Y)\nok\n#endif"), ["ok"]);
        assert_eq!(pp("#if 1 ? 0 : 1\nx\n#else\ny\n#endif"), ["y"]);
    }

    #[test]
    fn nested_conditionals() {
        let s = "#if 1\n#if 0\na\n#else\nb\n#endif\n#endif";
        assert_eq!(pp(s), ["b"]);
    }

    #[test]
    fn undef_works() {
        assert_eq!(
            pp("#define A 1\n#undef A\n#ifdef A\nx\n#else\ny\n#endif"),
            ["y"]
        );
    }

    #[test]
    fn predefined_line_and_stdc() {
        // __LINE__ on line 1.
        assert_eq!(pp("__LINE__"), ["1"]);
        // S4.2b15: `__STDC__` is NOT predefined (mdbcc accepts Borland
        // extensions ⇒ not strict ISO C, matching bcc32's default). So
        // `#if __STDC__` is 0 and `#if !defined(__STDC__)` is taken — the
        // condition the RTL/Win32 headers use to enable their extension blocks
        // (STDLIB.H's `min`/`max` templates etc.).
        assert_eq!(pp("#if __STDC__\nyes\n#else\nno\n#endif"), ["no"]);
        assert_eq!(pp("#if !defined(__STDC__)\nok\n#endif"), ["ok"]);
    }

    #[test]
    fn borland_predefined_macros() {
        // bcc32 4.52's `__BORLANDC__` is 0x0460 == 1120 (NOT 0x0452); object-
        // like expansion yields that literal.
        assert_eq!(pp("__BORLANDC__"), ["1120"]);
        assert_eq!(pp("__TURBOC__"), ["1120"]);
        // `defined(__BORLANDC__)` is true, and the 32-bit-target quartet is 1.
        assert_eq!(pp("#if defined(__BORLANDC__)\nok\n#endif"), ["ok"]);
        assert_eq!(
            pp("#if __WIN32__ && __FLAT__ && __CONSOLE__ && __TLS__ && _Windows\ny\n#endif"),
            ["y"]
        );
        // The version guard real Borland headers use must take the modern branch.
        assert_eq!(
            pp("#if __BORLANDC__ >= 0x0410\nmodern\n#else\nold\n#endif"),
            ["modern"]
        );
        // Deliberately NOT predefined (Win32 / version-derived): these stay 0.
        assert_eq!(pp("#if defined(_WIN32)\nx\n#else\ny\n#endif"), ["y"]);
        assert_eq!(pp("#if defined(__cplusplus)\nx\n#else\ny\n#endif"), ["y"]);
    }

    #[test]
    fn cplusplus_mode_predefines_cplusplus_macros() {
        // C++ mode: `__cplusplus` and `__BCPLUSPLUS__` are defined (the bcc32
        // 4.52 values 1 and 0x0340), `#ifdef __cplusplus` is taken, and the
        // `#error "Must use C++"` guard pattern passes (the not-`!`-branch).
        assert_eq!(pp_mode("__cplusplus", true), ["1"]);
        assert_eq!(pp_mode("__BCPLUSPLUS__", true), ["832"]); // 0x0340
        assert_eq!(
            pp_mode("#ifdef __cplusplus\ncpp\n#else\nc\n#endif", true),
            ["cpp"]
        );
        assert_eq!(
            pp_mode("#if defined(__cplusplus)\ncpp\n#else\nc\n#endif", true),
            ["cpp"]
        );
        // The real-header guard: `#if !defined(__cplusplus)` -> `#error` must
        // NOT fire in C++ mode (the block is skipped).
        assert_eq!(
            pp_mode(
                "#if !defined(__cplusplus)\n#error Must use C++\n#endif\nok",
                true
            ),
            ["ok"]
        );

        // C mode (default): neither macro is defined, `#ifdef __cplusplus` is
        // not taken, and `#if !defined(__cplusplus)` IS taken.
        assert_eq!(
            pp_mode("#ifdef __cplusplus\ncpp\n#else\nc\n#endif", false),
            ["c"]
        );
        assert_eq!(
            pp_mode("#ifndef __BCPLUSPLUS__\nnobc\n#endif", false),
            ["nobc"]
        );
    }

    #[test]
    fn lone_quote_in_skipped_error_block_round_trips() {
        // A real-header pattern: `#error Can't ...` inside a not-taken guard.
        // The lone `'` must lex as ordinary directive text (not a hard lexer
        // error), and the whole TU must preprocess cleanly because the block
        // is skipped.
        assert_eq!(pp("#ifdef NOPE\n#error Can't do that\n#endif\nok"), ["ok"]);
        // When the `#error` IS reached, its message carries the `'` as a token
        // (the directive-text join inserts spaces between tokens, so the lone
        // `'` round-trips as `Can ' t`). The point is that the `'` survives and
        // does not abort lexing.
        let msg = pp_err("#error Can't do that").message;
        assert!(msg.contains('\''), "message lost the stray quote: {msg}");
        assert!(msg.contains("Can") && msg.contains("do that"), "msg: {msg}");
    }

    #[test]
    fn line_continuation_in_define() {
        assert_eq!(pp("#define LONG 1 + \\\n2\nLONG"), ["1", "+", "2"]);
    }

    #[test]
    fn error_directive() {
        assert!(pp_err("#error nope").message.contains("#error nope"));
    }

    #[test]
    fn unterminated_if_is_error() {
        assert!(pp_err("#if 1\nx").message.contains("unterminated"));
    }

    #[test]
    fn pragma_and_unknown_system_include_are_ignored() {
        assert_eq!(
            pp("#pragma warn -rvl\n#include <stdio.h>\nint a;"),
            ["int", "a", ";"]
        );
    }

    /// S5: the Borland pp extension `sizeof(type)` inside `#if` — the RTL
    /// guards `#if ( sizeof( wchar_t ) == 1 ) #error …` (LOCALE/MBYTE1.C).
    /// wchar_t = 2, long double = 10 (Borland), unsigned long = 4.
    #[test]
    fn sizeof_builtin_type_in_if_condition() {
        assert_eq!(
            pp("#if ( sizeof( wchar_t ) == 1 )\nbad\n#else\ngood\n#endif"),
            ["good"]
        );
        assert_eq!(pp("#if sizeof(long double) == 10\nld10\n#endif"), ["ld10"]);
        assert_eq!(pp("#if sizeof(unsigned long) == 4\nul4\n#endif"), ["ul4"]);
    }

    /// An unrecognized `sizeof` operand inside `#if` (a POINTER type — its
    /// size is target-dependent, which the pp does not know) is NOT resolved:
    /// it falls into the historical ident→0 mapping, which must never make the
    /// condition silently TRUE (the guarded text stays suppressed).
    #[test]
    fn sizeof_unrecognized_operand_in_if_stays_falsy() {
        assert_eq!(
            pp("#if sizeof(char *) == 4\nx\n#endif"),
            Vec::<String>::new()
        );
    }
}
