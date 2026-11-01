/*
 * RuntimeX / HeapSentry Vulnerability Demo: Use-After-Free (UAF) Write
 *
 * Vulnerability Class: CWE-416 (Use After Free)
 * Severity: HIGH
 *
 * Description:
 *   An object is allocated on the heap, deallocated via free(), and then
 *   subsequently written to via the dangling pointer.
 *   HeapSentry poisons freed memory with 0xDD bytes; subsequent writes
 *   or checks reveal heap corruption and dangling pointer usage.
 *
 * Safe Alternative:
 *   Always set pointers to NULL immediately after freeing (ptr = NULL),
 *   or use C++ smart pointers (std::unique_ptr) that enforce ownership.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    int role;
    char username[24];
} UserSession;

void trigger_use_after_free(void) {
    UserSession *session = (UserSession *)malloc(sizeof(UserSession));
    if (!session) {
        perror("malloc failed");
        exit(1);
    }

    session->id = 1001;
    session->role = 1; /* Normal user */
    strncpy(session->username, "alice", sizeof(session->username) - 1);
    printf("[+] Allocated UserSession (id=%d, role=%d) at %p\n", session->id, session->role, (void *)session);

    printf("[*] Deallocating session...\n");
    free(session);

    /* VULNERABILITY: Writing to freed memory (Dangling pointer) */
    printf("[!] Modifying session->role after free() (dangling pointer write)...\n");
    session->role = 999; /* Privilege escalation / heap corruption */

    printf("[+] Session role after UAF write: %d\n", session->role);
}

int main(void) {
    printf("=== Use-After-Free (UAF) Write Demo ===\n");
    trigger_use_after_free();
    printf("[+] Program completed.\n");
    return 0;
}
