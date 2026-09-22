/* Pointers, arrays, pointer write-through. Strict C89, UB-free. */
#include <stdio.h>
int sum(int *p, int n){
    int i, s;
    s = 0;
    for (i = 0; i < n; i++) s += p[i];
    return s;
}
int main(void){
    int a[5];
    int i, *p;
    for (i = 0; i < 5; i++) a[i] = i * i;
    p = a;
    *p = 100;
    p[4] = 7;
    printf("%d\n", sum(a, 5));   /* 100+1+4+9+7 = 121 */
    printf("%d\n", a[0] + a[4]); /* 107 */
    return 0;
}
