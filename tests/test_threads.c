/*
 * RuntimeX test: threaded allocation (run under LD_PRELOAD).
 * Concurrent alloc/realloc/free across threads with distinct payloads;
 * checks data integrity of each thread's own blocks.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define THREADS 16
#define ITERS 500

static void *worker(void *arg)
{
    long n = (long)arg;
    int i;
    for (i = 0; i < ITERS; i++) {
        size_t sz = 32 + (size_t)((n * 13 + i * 5) % 512);
        unsigned char *p = malloc(sz);
        if (!p) return (void *)1;
        memset(p, (int)(0x40 + (n % 26)), sz);
        if (i % 2 == 0) {
            unsigned char *g = realloc(p, sz * 2);
            if (!g) { free(p); return (void *)1; }
            p = g;
        }
        if (p[sz / 2] != (unsigned char)(0x40 + (n % 26))) {
            free(p);
            return (void *)1;
        }
        free(p);
    }
    return NULL;
}

int main(void)
{
    pthread_t t[THREADS];
    long i;
    void *rv;
    int failures = 0;

    for (i = 0; i < THREADS; i++)
        if (pthread_create(&t[i], NULL, worker, (void *)i) != 0)
            return 1;
    for (i = 0; i < THREADS; i++) {
        if (pthread_join(t[i], &rv) != 0) return 1;
        if (rv != NULL) failures++;
    }
    puts(failures ? "test_threads FAILED" : "test_threads done");
    return failures ? 1 : 0;
}
