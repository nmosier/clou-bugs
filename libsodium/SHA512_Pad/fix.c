#include <stdatomic.h>

static void
SHA512_Pad(crypto_hash_sha512_state *state, uint64_t tmp64[80 + 8])
{
    unsigned int r;
    unsigned int i;

    atomic_thread_fence(memory_order_acquire);
    r = (unsigned int) ((state->count[1] >> 3) & 0x7f);
    if (r < 112) {
        for (i = 0; i < 112 - r; i++) {
            state->buf[r + i] = PAD[i];
        }
    } else {
        for (i = 0; i < 128 - r; i++) {
            state->buf[r + i] = PAD[i];
        }
        SHA512_Transform(state->state, state->buf, &tmp64[0], &tmp64[80]);
        memset(&state->buf[0], 0, 112);
    }
    be64enc_vect(&state->buf[112], state->count, 16);
    SHA512_Transform(state->state, state->buf, &tmp64[0], &tmp64[80]);
}
