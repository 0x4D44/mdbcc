/* Phase F-4: printf %f three-way differential (mdbcc ≡ cl /O2 ≡ bcc32 5.5.1).
   Every input is dyadic-rational at the chosen precision (powers of 2 or
   finite sums; or 3.14 / 0.125 whose representation rounds identically at
   the requested precision across all three compilers). Specials (inf/nan)
   live in tests/printf_format.rs only — bcc32 prints "1.#INF"/"1.#NAN" not
   "inf"/"nan", a known vendor-divergence on Windows. Strict C89. */
#include <stdio.h>
int main(void){
    printf("[%f]\n", 0.5);
    printf("[%f]\n", 1.5);
    printf("[%f]\n", 3.14);
    printf("[%f]\n", -3.5);
    printf("[%.0f]\n", 7.0);
    printf("[%.3f]\n", 3.14);
    printf("[%.3f]\n", 0.125);
    printf("[%.10f]\n", 0.5);
    printf("[%10.2f]\n", 1.5);
    printf("[%-10.2f]\n", 1.5);
    printf("[%010.2f]\n", 1.5);
    printf("[%010.2f]\n", -1.5);
    return 0;
}
