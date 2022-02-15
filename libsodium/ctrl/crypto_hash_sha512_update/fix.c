#include <stdatomic.h>

int
crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                          const unsigned char *in, unsigned long long inlen)
{
    uint64_t           tmp64[80 + 8];
    uint64_t           bitlen[2];
    unsigned long long i;
    unsigned long long r;

    if (inlen <= 0U) {
        return 0;
    }
    atomic_thread_fence(memory_order_acquire);
    r = (unsigned long long) ((state->count[1] >> 3) & 0x7f); // <<< speculative store bypass
    /* ... */
    if (inlen < 128 - r) { // <<< insecure branch on secret `r`
        for (i = 0; i < inlen; i++) {
            state->buf[r + i] = in[i];
        }
        return 0;
    }
    /* ... */
}
