/* Function pointers: variable, callback parameter, array dispatch, and
   a >4-arg indirect call (A2 reuses the A1 stack-arg ABI). Strict C89,
   deterministic, pointer-size-agnostic. Three-way: mdbcc / cl / bcc32. */
#include <stdio.h>

int dbl(int x){ return x*2; }
int inc(int x){ return x+1; }
int apply(int (*f)(int), int v){ return f(v); }

int add(int a, int b){ return a+b; }
int sub(int a, int b){ return a-b; }
int mul(int a, int b){ return a*b; }

int f6(int a, int b, int c, int d, int e, int f){
    return a + b*2 + c*3 + d*4 + e*5 + f*6;
}

int main(void){
    int (*fp)(int);
    int (*ops[3])(int,int);
    int (*p6)(int,int,int,int,int,int);

    fp = dbl;
    printf("%d\n", fp(21));            /* 42  */
    printf("%d\n", apply(inc, 100));   /* 101 */

    ops[0] = add; ops[1] = sub; ops[2] = mul;
    printf("%d\n", ops[0](6,4));       /* 10  */
    printf("%d\n", ops[1](6,4));       /* 2   */
    printf("%d\n", ops[2](6,4));       /* 24  */

    p6 = f6;
    printf("%d\n", p6(1,2,3,4,5,6));   /* 91  */
    return 0;
}
