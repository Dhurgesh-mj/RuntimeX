/*
 * RuntimeX test: metadata exhaustion policy (run under LD_PRELOAD).
 * RUNTIMEX_TRACKED (see Makefile) lowers the tracking capacity so the
 * test can exhaust it quickly. Live allocations beyond capacity are still
 * real allocations (malloc must not fail); their later frees are events
 * with status "untracked" and the real allocator is still called.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LIVE 200   /* must exceed RUNTIMEX_TRACKED used in the Makefile */

int main(void)
{
    void *ptrs[LIVE];
    int i;
    int failures = 0;

    for (i = 0; i < LIVE; i++) {
        ptrs[i] = malloc(16);
        if (!ptrs[i]) {
            /* Exhaustion of the tracker must never fail the app. */
            failures++;
            break;
        }
        memset(ptrs[i], 0x0F, 16);
    }
    for (i = 0; i < LIVE; i++) {
        if (ptrs[i])
            free(ptrs[i]);
    }
    puts(failures ? "test_exhaustion FAILED" : "test_exhaustion done");
    return failures ? 1 : 0;
}
