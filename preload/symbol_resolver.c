/*
 * HeapSentry Runtime Core — dynamic symbol resolution (Person 1).
 *
 * Resolves the real malloc/free/realloc with dlsym(RTLD_NEXT, ...).
 *
 * Known hazard: glibc's dlsym() may itself call calloc(). We do not wrap
 * calloc, so that call goes straight to libc and cannot recurse into us.
 * Any later free() of memory allocated by dlsym comes through our free()
 * wrapper as an untracked pointer and is forwarded to the real free(),
 * which is the correct owner, so ownership stays well-defined.
 */
#include "internal.h"

#include <dlfcn.h>
#include <string.h>

volatile rtx_malloc_fn  rtx_real_malloc  = NULL;
volatile rtx_free_fn    rtx_real_free    = NULL;
volatile rtx_realloc_fn rtx_real_realloc = NULL;

volatile int rtx_resolving = 0;

int rtx_resolve_symbols(void)
{
    const char *e;
    rtx_malloc_fn  m;
    rtx_free_fn    f;
    rtx_realloc_fn r;

    rtx_resolving = 1;

    dlerror();
    m = (rtx_malloc_fn)dlsym(RTLD_NEXT, "malloc");
    e = dlerror();
    if (e != NULL || m == NULL) {
        rtx_resolving = 0;
        return -1;
    }

    dlerror();
    f = (rtx_free_fn)dlsym(RTLD_NEXT, "free");
    e = dlerror();
    if (e != NULL || f == NULL) {
        rtx_resolving = 0;
        return -1;
    }

    dlerror();
    r = (rtx_realloc_fn)dlsym(RTLD_NEXT, "realloc");
    e = dlerror();
    if (e != NULL || r == NULL) {
        rtx_resolving = 0;
        return -1;
    }

    rtx_real_malloc  = m;
    rtx_real_free    = f;
    rtx_real_realloc = r;

    rtx_resolving = 0;
    return 0;
}
