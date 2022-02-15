#include <stdatomic.h>

static void
SHA256_Pad(crypto_hash_sha256_state *state, uint32_t tmp32[64 + 8])
{
    unsigned int r;
    unsigned int i;

    atomic_thread_fence(memory_order_acquire);
    r = (unsigned int) ((state->count >> 3) & 0x3f); // <<< speculative store bypass
    if (r < 56) {
        for (i = 0; i < 56 - r; i++) {
            state->buf[r + i] = PAD[i]; // <<< secret `r` used as index into state->buf[]
        }
    } else {
        for (i = 0; i < 64 - r; i++) {
            state->buf[r + i] = PAD[i]; // <<< secret `r` used as index into state->buf[]
        }
        SHA256_Transform(state->state, state->buf, &tmp32[0], &tmp32[64]);
        memset(&state->buf[0], 0, 56);
    }
    STORE64_BE(&state->buf[56], state->count);
    SHA256_Transform(state->state, state->buf, &tmp32[0], &tmp32[64]);
}
