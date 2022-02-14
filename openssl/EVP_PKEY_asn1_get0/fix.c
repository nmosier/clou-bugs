#include <stdatomic.h>

int HASH_FINAL(unsigned char *md, HASH_CTX *c)
{
    ...
    atomic_thread_fence(memory_order_acquire);
    size_t n = c->num; // <<< speculative store bypass

    p[n] = 0x80; // <<< secret in `n` leaked through array access
    ...
}
