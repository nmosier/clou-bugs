## Spectre v4 Vulnerability (Variant B)

### Location
- Function: `SHA256_Pad`
- File: [crypto_hash/sha256/cp/hash_sha256_cp.c:159,162,166](https://github.com/jedisct1/libsodium/blob/d30251f03e646abd07b5399654f1f5dcea9a6b38/src/libsodium/crypto_hash/sha256/cp/hash_sha256_cp.c#L159)

### Code Snippet
```
static void
SHA256_Pad(crypto_hash_sha256_state *state, uint32_t tmp32[64 + 8])
{
    unsigned int r;
    unsigned int i;

    r = (unsigned int) ((state->count >> 3) & 0x3f); // <<< speculative store bypass (L159)
    if (r < 56) {
        for (i = 0; i < 56 - r; i++) {
            state->buf[r + i] = PAD[i]; // <<< secret `r` used as index into state->buf[] (L162)
        }
    } else {
        for (i = 0; i < 64 - r; i++) {
            state->buf[r + i] = PAD[i]; // <<< secret `r` used as index into state->buf[] (L166)
        }
        SHA256_Transform(state->state, state->buf, &tmp32[0], &tmp32[64]);
        memset(&state->buf[0], 0, 56);
    }
    STORE64_BE(&state->buf[56], state->count);
    SHA256_Transform(state->state, state->buf, &tmp32[0], &tmp32[64]);
}
```

### Explanation
The struct pointer parameter `state` is stored to the stack upon entry to the function.
The subsequent load of `state` on line 159 may read the stale value at that stack memory location via Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If that stale value is attacker-controlled, the struct member access `state->counter` on line 159 may read an arbitrary secret from memory, which is subsequently stored into index `r`.
Index `r` is then used to index into `state->buf[]` on lines 162 and 166, leaking the value of the secret in `r`.

This vulnerability may allow an attacker to leak arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 159 to ensure the store of parameter `state` cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
6a9
>     atomic_thread_fence(memory_order_acquire);
```
