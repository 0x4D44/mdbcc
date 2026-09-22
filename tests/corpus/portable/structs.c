/* struct via pointer (no by-value param/return). Strict C89. */
#include <stdio.h>
struct Point { int x; int y; };
int norm2(struct Point *p){ return p->x * p->x + p->y * p->y; }
int main(void){
    struct Point a;
    struct Point *q;
    a.x = 3; a.y = 4;
    q = &a;
    q->y = 12;
    printf("%d\n", norm2(&a));   /* 9 + 144 = 153 */
    printf("%d\n", a.x + a.y);   /* 15 */
    return 0;
}
