/*
 * RuntimeX test: allocation lifecycle under load (run under LD_PRELOAD).
 * Exercises malloc/free/free(NULL)/failed allocations in loops and
 * churns allocation-identity reuse with 32-byte pairs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ITERS 5000

/* Deliberately unsatisfiable size (deterministic failed allocation).
 * volatile hides the value from gcc's static allocation-size analysis. */
static volatile size_t fail_size = (size_t)-1;

int main(void)
{
    int i;
    int failures = 0;

    for (i = 0; i < ITERS; i++) {
        size_t sz = (size_t)(8 + (i % 512));
        unsigned char *p = malloc(sz);
        if (p == NULL) { failures++; break; }
        memset(p, 0x5A, sz);
        free(p);
    }

    (void)free(NULL);

    /* Deterministic failed allocation. */
    if (malloc(fail_size) != NULL)
        failures++;

    /* Many small alloc/free cycles to churn identity reuse. */
    for (i = 0; i < 200; i++) {
        void *a = malloc(32);
        void *b;
        if (!a) { failures++; break; }
        b = malloc(32);
        if (!b) { failures++; free(a); break; }
        free(a);
        free(b);
    }

    puts(failures ? "test_allocations FAILED" : "test_allocations done");
    return failures ? 1 : 0;
}
