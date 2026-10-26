/*
 * HeapSentry target B: reallocation demo.
 * Exercises successful realloc growth/contraction, realloc-failure
 * preservation, and zero-size behavior. Exits 0 on success.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    unsigned char *p, *q, *r;
    size_t i;

    p = malloc(32);
    if (p == NULL) return 1;
    memset(p, 0x11, 32);

    /* Successful grow: content prefix must survive. */
    q = realloc(p, 256);
    if (q == NULL) {
        fprintf(stderr, "realloc failed\n");
        free(p);
        return 1;
    }
    for (i = 0; i < 32; i++) {
        if (q[i] != 0x11) {
            fprintf(stderr, "realloc lost data\n");
            free(q);
            return 1;
        }
    }
    memset(q, 0x22, 256);

    /* Failed realloc must preserve the original allocation. */
    {
        volatile size_t huge = (size_t)-1;
        r = realloc(q, huge);
    }
    if (r != NULL) {
        fprintf(stderr, "unexpected huge realloc success\n");
        free(r != q ? r : q);
        return 1;
    }
    /* Original still valid */
    if (q[0] != 0x22 || q[255] != 0x22) {
        fprintf(stderr, "original block corrupted after failed realloc\n");
        free(q);
        return 1;
    }

    /* Shrink back down. */
    r = realloc(q, 16);
    if (r == NULL) {
        fprintf(stderr, "shrink realloc failed\n");
        free(q);
        return 1;
    }
    r[0] = 0x33;

    /* glibc semantics: zero-size realloc frees and returns NULL. */
    if (realloc(r, 0) != NULL) {
        fprintf(stderr, "unexpected zero-size realloc success\n");
        return 1;
    }

    puts("realloc_demo done");
    return 0;
}
