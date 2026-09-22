/* Loops / if / while. Strict C89: declarations precede statements. */
#include <stdio.h>
int main(void){
    int i, f, a, b, s, n;
    f = 1;
    for (i = 1; i <= 6; i++) f *= i;
    printf("%d\n", f);                   /* 720  */
    a = 48; b = 18;
    while (b) { int t; t = a % b; a = b; b = t; }
    printf("%d\n", a);                   /* 6    */
    s = 0; n = 100;
    for (i = 1; i <= n; i++) s += i;
    printf("%d\n", s);                   /* 5050 */
    return 0;
}
