## Spectre v4 Vulnerability (Variant A')

### Location
- Function: `crypto_hash_sha512_update`
- File: [crypto_hash/sha512/cp/hash_sha512_cp.c:221](https://github.com/jedisct1/libsodium/blob/d30251f03e646abd07b5399654f1f5dcea9a6b38/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c#L221)

### Code Snippet
```
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
```

### Explanation
The struct pointer parameter `state` is stored to the stack upon entry to the function.
The subsequent loads of `state` on line 221 may read the stale value at that stack memory location via Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If that stale value is attacker-controlled, the array access `state->count` on line 221 may read an arbitrary secret from memory.
A 1-bit function of this secret leaks through the branch predicates on line 226.

This vulnerability may allow an attacker to leak one bit for arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 221 to ensure the store of parameter `sig` cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
12a15
>     atomic_thread_fence(memory_order_acquire);
```
