#include <stdatomic.h>

/* Returns true if certificate and private key for 'idx' are present */
static ossl_inline int ssl_has_cert(const SSL *s, int idx)
{
    if (idx < 0 || idx >= SSL_PKEY_NUM) // <<< bounds check bypass via Spectre v1
        return 0;
    atomic_thread_fence(memory_order_acquire);
    return s->cert->pkeys[idx].x509 != NULL // <<< speculative return value leaks one-bit function of arbitrary secret
        && s->cert->pkeys[idx].privatekey != NULL;
}
