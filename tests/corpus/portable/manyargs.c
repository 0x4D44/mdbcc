/* More than four arguments (Win64 stack-arg ABI). Strict C89,
   deterministic, pointer-size-agnostic. Weighted sums make every
   argument position observable. Three-way: mdbcc / cl / bcc32. */
#include <stdio.h>

int f5(int a, int b, int c, int d, int e){
    return a + b*2 + c*3 + d*4 + e*5;
}
int f8(int a, int b, int c, int d, int e, int f, int g, int h){
    return a + b*2 + c*3 + d*4 + e*5 + f*6 + g*7 + h*8;
}
int g1(int x){ return f8(x, x+1, x+2, x+3, x+4, x+5, x+6, x+7); }

int main(void){
    printf("%d\n", f5(2,3,4,5,6));            /* 70   */
    printf("%d\n", f8(1,2,3,4,5,6,7,8));      /* 204  */
    printf("%d\n", g1(1));                    /* f8(1..8)=204 */
    printf("%d\n", f8(10,20,30,40,50,60,70,80)); /* 2040 */
    return 0;
}
