/* libc string builtins. Strict C89. */
#include <stdio.h>
#include <string.h>
int main(void){
    char buf[16];
    strcpy(buf, "borland");
    printf("%d\n", (int)strlen(buf));        /* 7 */
    printf("%d\n", strcmp(buf, "borland"));  /* 0 */
    printf("%d\n", strcmp("a", "b") < 0);    /* 1 */
    printf("%s\n", buf);                     /* borland */
    return 0;
}
