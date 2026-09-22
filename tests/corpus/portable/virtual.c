// oracle: lang cpp
// C++ corpus: the differential harness compiles this as C++ (cl /TP +
// t.cpp, bcc32 -P + t.cpp) — backlog B-4 / Phase C C5. mdbcc compiles
// the C++ subset in-process; Phase B is also O1-validated by
// tests/virtual.rs (11 hand-computed, position-observable).
/* Portable C++: virtual dispatch through a base pointer, an inherited
   (non-overridden) slot, and a virtual destructor's derived->base
   ordering. Deterministic stdout, no pointer-size output — three-way
   O2 (cl) + O3 (bcc32 5.5.1) agreement with mdbcc. */
#include <stdio.h>

class Shape {
public:
    virtual int area() { return 0; }
    virtual ~Shape() { printf("~Shape\n"); }
};

class Square : public Shape {
    int s;
public:
    Square(int x) { s = x; }
    virtual int area() { return s * s; }
    ~Square() { printf("~Square\n"); }
};

class Rect : public Shape {
    int w;
    int h;
public:
    Rect(int a, int b) { w = a; h = b; }
    virtual int area() { return w * h; }
    /* no ~Rect: inherits the (virtual) ~Shape slot */
};

int main(void) {
    Square sq(3);
    Rect rc(4, 5);
    Shape *p;

    p = &sq;
    printf("%d\n", p->area());          /* 9  (Square::area) */
    p = &rc;
    printf("%d\n", p->area());          /* 20 (Rect::area)   */

    p = new Square(7);
    printf("%d\n", p->area());          /* 49 */
    delete p;                           /* ~Square then ~Shape */

    p = new Rect(2, 6);
    printf("%d\n", p->area());          /* 12 */
    delete p;                           /* ~Shape (Rect has no own dtor) */
    return 0;
}
