/* Recursion & mutual-ish recursion. Strict C89. */
#include <stdio.h>
int fib(int n){ if (n < 2) return n; return fib(n-1) + fib(n-2); }
int gcd(int a, int b){ if (b == 0) return a; return gcd(b, a % b); }
int main(void){
    int i, s;
    s = 0;
    for (i = 0; i < 12; i++) s += fib(i);
    printf("%d\n", s);                   /* 232 */
    printf("%d\n", gcd(1071, 462));      /* 21  */
    return 0;
}
