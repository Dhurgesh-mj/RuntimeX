/*
 * RuntimeX target A: safe allocation demo.
 * Ordinary allocation, valid access, deallocation. Exits 0 on success.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    unsigned char *p;

    (void)free(NULL); /* exercised no-op; emits no event by contract */

    p = malloc(64);
    if (p == NULL) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    memset(p, 0xAB, 64);
    if (p[0] != 0xAB) {
        fprintf(stderr, "memory not usable\n");
        free(p);
        return 1;
    }
    free(p);

    /* A deliberately-huge size; volatile hides its value from gcc's
     * static allocation-size analysis. */
    {
        volatile size_t huge = (size_t)-1;
        if (malloc(huge) != NULL) {
            fprintf(stderr, "unexpected huge malloc success\n");
            return 1;
        }
    }

    puts("safe_demo done");
    return 0;
}
