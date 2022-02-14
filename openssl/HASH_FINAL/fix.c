#include <stdatomic.h>

int HASH_FINAL(unsigned char *md, HASH_CTX *c)
{
    ...
    atomic_thread_fence(memory_order_acquire);
    size_t n = c->num;

    p[n] = 0x80;                /* there is always room for one */
    ...
}
