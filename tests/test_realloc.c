/*
 * RuntimeX test: realloc semantics (run under LD_PRELOAD or standalone).
 * Data-level checks here; identity relationships in the event log are
 * verified by tests/test_event_schema.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deliberately unsatisfiable size (deterministic failed realloc).
 * volatile hides the value from gcc's static allocation-size analysis. */
static volatile size_t fail_size = (size_t)-1;

int main(void)
{
    unsigned char *p, *q;
    int failures = 0;

    p = malloc(100);
    if (!p) return 1;
    memset(p, 0x33, 100);

    q = realloc(p, 4000);
    if (!q) { failures++; } else {
        if (q[0] != 0x33 || q[99] != 0x33) failures++;
        free(q);
    }

    /* realloc(NULL, n) behaves like malloc(n) */
    p = realloc(NULL, 64);
    if (!p) { failures++; } else {
        memset(p, 0x44, 64);
        free(p);
    }

    /* realloc(p, 0): glibc frees and returns NULL */
    p = malloc(64);
    if (!p) failures++;
    else {
        void *r = realloc(p, 0);
        if (r != NULL) { failures++; free(r); }
    }

    /* Failed huge realloc preserves the original. free(p) below is valid
     * because realloc() preserves the block on failure; the pragma silences
     * gcc's impossible-to-prove use-after-free heuristic. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuse-after-free"
    p = malloc(48);
    if (!p) failures++;
    else {
        q = realloc(p, fail_size);
        if (q != NULL) { failures++; free(q); }
        free(p);
    }
#pragma GCC diagnostic pop

    puts(failures ? "test_realloc FAILED" : "test_realloc done");
    return failures ? 1 : 0;
}
