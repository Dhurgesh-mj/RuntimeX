/*
 * HeapSentry target C: multithreaded allocation demo.
 * Several threads allocate, touch, and free blocks concurrently.
 * Validates that tracking state survives concurrency (the assertion here
 * is that the thread job itself completes with valid data).
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define THREADS 8
#define ITERS 2000

static void *worker(void *arg)
{
    long n = (long)arg;
    int i;
    for (i = 0; i < ITERS; i++) {
        size_t sz = 16 + (size_t)((n * 7 + i) % 128);
        unsigned char *p = malloc(sz);
        if (p == NULL)
            return (void *)1;
        memset(p, (int)(n + 1), sz);
        if (i % 3 == 0 && sz >= 32) {
            unsigned char *g = realloc(p, sz + 64);
            if (g == NULL) { free(p); return (void *)1; }
            p = g;
        }
        if (p[0] != (unsigned char)(n + 1)) {
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
    int failed = 0;

    for (i = 0; i < THREADS; i++)
        if (pthread_create(&t[i], NULL, worker, (void *)i) != 0)
            return 1;
    for (i = 0; i < THREADS; i++) {
        if (pthread_join(t[i], &rv) != 0)
            return 1;
        if (rv != NULL)
            failed = 1;
    }
    puts(failed ? "threaded_demo FAILED" : "threaded_demo done");
    return failed;
}
