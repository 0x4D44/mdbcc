// oracle: lang cpp
// C++ corpus: i386 fs:[0] structured exception handling (S2e). The
// differential harness compiles this as C++ (bcc32 -P + t.cpp); mdbcc
// compiles the C++ subset in-process. Also locked by tests/i386_run.rs
// (the three bcc32-diffed EH acceptance cases) and tests/cpp_exceptions.rs
// (the x64 stripe). Minimal int-catch only — class throws / nested try /
// rethrow are follow-on ticks, so this fixture stays within that subset.
/* Portable C++: a `throw <int>` caught by `catch (int)`, plus a `try` that
   does NOT throw (falls through). Deterministic stdout, no pointer-size
   output — bcc32 4.52 is the oracle. Expected stdout:
       caught 42
       no throw: 7
   The first line proves the thrown int reaches the catch parameter and the
   catch body's printf runs on a sane stack; the second proves a non-throwing
   try installs and cleanly pops its fs:[0] record. */
#include <stdio.h>

int catch_one(int v) {
    try {
        throw v;
    } catch (int e) {
        return e;
    }
    return -1;
}

int main(void) {
    printf("caught %d\n", catch_one(42));

    int r = 0;
    try {
        r = 7;
    } catch (int e) {
        r = 99;
    }
    printf("no throw: %d\n", r);
    return 0;
}
