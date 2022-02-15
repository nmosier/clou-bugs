#include <stdatomic.h>

int
_crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                     const unsigned char *m,
                                     unsigned long long   mlen,
                                     const unsigned char *pk,
                                     int prehashed)
{
    crypto_hash_sha512_state hs;
    unsigned char            h[64];
    unsigned char            rcheck[32];
    ge25519_p3               A;
    ge25519_p2               R;

    atomic_thread_fence(memory_order_acquire);
#ifdef ED25519_COMPAT
    if (sig[63] & 224) { // <<< speculative store bypass of `sig` results in branch on secret
        return -1;
    }
#else
    if ((sig[63] & 240) != 0 && // <<< speculative store bypass of `sig` results in branch on secret
        sc25519_is_canonical(sig + 32) == 0) {
        return -1;
    }
    /* ... */
#endif
    /* ... */
}
