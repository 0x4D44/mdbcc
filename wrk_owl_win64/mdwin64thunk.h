/* mdwin64thunk.h — Win64 OWL window-bootstrap shim (MDBCC-01).
 *
 * ADDITIVE ONLY. Supplies the pointer-width primitives the BC++ 4.52 (1995)
 * headers predate: LONG_PTR / UINT_PTR and the GWLP_WNDPROC / GWLP_USERDATA
 * window-long indices. It never shadows or re-includes an oracle header, so the
 * first-match-wins include-recursion hazard cannot arise. Include this AFTER the
 * oracle <owl/*.h> includes (so HWND/int are already defined).
 *
 * WPARAM/LPARAM/LRESULT are intentionally LEFT at the oracle's 32-bit width
 * (HLD D2): widening them in only these two TUs would change the mangled names
 * of the non-virtual, cross-TU-inlined TWindow::ReceiveMessage/HandleMessage and
 * break the link. The int32 message-dispatch layer is the deferred wall 2.
 *
 * Prototypes for SetWindowLongPtrA / GetWindowLongPtrA ARE declared here (LONG_PTR return):
 * without a prototype, mdbcc treats the call as implicit-int and TRUNCATES the *return* to a
 * signed 32 bits. That is harmless for the install calls (return ignored), but fatal for
 * TWindow::SubclassWindowFunction, which captures the RETURN as DefaultProc (the prior window
 * proc of a subclassed predefined control). A truncated+sign-extended USER32 proc address
 * (0xFFFFFFFF_xxxxxxxx) then makes ::CallWindowProc(DefaultProc, …) fault — the wall-2 crash
 * seen opening dialogs with OWL child controls (TConfigur's radios/checkboxes).
 */
#ifndef MDBCC_WIN64_THUNK_H
#define MDBCC_WIN64_THUNK_H

typedef __int64          LONG_PTR;
typedef unsigned __int64 UINT_PTR;

#define GWLP_WNDPROC  (-4)
#define GWLP_USERDATA (-21)

extern "C" LONG_PTR __stdcall SetWindowLongPtrA(HWND, int, LONG_PTR);
extern "C" LONG_PTR __stdcall GetWindowLongPtrA(HWND, int);

#endif /* MDBCC_WIN64_THUNK_H */
