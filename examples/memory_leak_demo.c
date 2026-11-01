/*
 * RuntimeX / HeapSentry Vulnerability Demo: Memory Leak
 *
 * Vulnerability Class: CWE-401 (Improper Release of Memory Before Removing Last Reference)
 * Severity: MEDIUM
 *
 * Description:
 *   Memory allocated via malloc() is not freed prior to function exit or
 *   process termination. Over time, memory leaks lead to performance degradation,
 *   out-of-memory (OOM) crashes, and resource exhaustion.
 *   HeapSentry tracks all live allocations in an internal open-addressing table
 *   and walks the table at exit (atexit) to report every leaked allocation,
 *   its base address, and requested size.
 *
 * Safe Alternative:
 *   Ensure every execution path (including error exits) has a matching free(),
 *   or adopt RAII / region-based allocation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int process_data(int condition) {
    char *header = (char *)malloc(128);
    char *payload = (char *)malloc(1024);

    if (!header || !payload) {
        return -1;
    }

    strcpy(header, "Content-Type: application/json");
    strcpy(payload, "{\"status\": \"ok\", \"data\": [1, 2, 3]}");
    printf("[+] Allocated header (%p, 128B) and payload (%p, 1024B)\n", (void *)header, (void *)payload);

    if (condition < 0) {
        printf("[!] Error path taken! Exiting early without freeing payload...\n");
        free(header);
        /* VULNERABILITY: payload is never freed */
        return -1;
    }

    free(header);
    free(payload);
    return 0;
}

int main(void) {
    printf("=== Memory Leak Demo ===\n");
    printf("[*] Running normal path...\n");
    process_data(1);

    printf("[*] Running flawed error-handling path...\n");
    process_data(-1);

    printf("[+] Exiting main — HeapSentry will walk the allocation table and detect leaks.\n");
    return 0;
}
