static void
SHA256_Pad(crypto_hash_sha256_state *state, uint32_t tmp32[64 + 8])
{
    unsigned int r;
    unsigned int i;

    r = (unsigned int) ((state->count >> 3) & 0x3f); // <<< speculative store bypass
    if (r < 56) { // <<< insecure branch on secret
        /* ... */
    } else {
        /* ... */
    }
    /* ... */
}
