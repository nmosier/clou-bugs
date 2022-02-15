## Spectre v4 Vulnerability (Variant B)

### Location
- Function: `SHA512_Pad`
- File: [crypto_hash/sha256/cp/hash_sha512_cp.c:178,181,185](https://github.com/jedisct1/libsodium/blob/d30251f03e646abd07b5399654f1f5dcea9a6b38/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L178)

### Code Snippet
```
static void
SHA512_Pad(crypto_hash_sha512_state *state, uint64_t tmp64[80 + 8])
{
    unsigned int r;
    unsigned int i;

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
```

### Explanation
The struct pointer parameter `state` is stored to the stack upon entry to the function.
The subsequent load of `state` on line 159 may read the stale value at that stack memory location via Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If that stale value is attacker-controlled, the struct member access `state->counter` on line 178 may read an arbitrary secret from memory, which is subsequently stored into index `r`.
Index `r` is then used to index into `state->buf[]` on lines 181 and 185, leaking the value of the secret in `r`.

This vulnerability may allow an attacker to leak arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 178 to ensure the store of parameter `state` cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
6a9
>     atomic_thread_fence(memory_order_acquire);
```
