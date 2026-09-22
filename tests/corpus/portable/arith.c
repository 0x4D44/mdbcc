/* Integer arithmetic & precedence. Strict C89; mdbcc INT MSVC INT bcc32. */
#include <stdio.h>
int main(void){
    int a, b;
    a = 7; b = 3;
    printf("%d\n", a + b * 2 - (a - b)); /* 9  */
    printf("%d\n", (a*a + b*b) % 13);    /* 6  */
    printf("%d\n", a / b);               /* 2  */
    printf("%d\n", 100 - 7 * 9);         /* 37 */
    printf("%d\n", (a > b) ? a : b);     /* 7  */
    return 0;
}
