## Spectre v4 Vulnerability (Variant B')

### Location
- Function: `SHA256_Pad`
- File: [crypto_hash/sha256/cp/hash_sha256_cp.c:159](https://github.com/jedisct1/libsodium/blob/d30251f03e646abd07b5399654f1f5dcea9a6b38/src/libsodium/crypto_hash/sha256/cp/hash_sha256_cp.c#L159)

### Code Snippet
```
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
```

### Explanation
The struct pointer parameter `state` is stored to the stack upon entry to the function.
The subsequent loads of `state` on line 159 may read the stale value at that stack memory location via Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If that stale value is attacker-controlled, the array access `state->count` on line 159 may read an arbitrary secret from memory.
A 1-bit function of this secret leaks through the branch predicates on line 160.

This vulnerability may allow an attacker to leak one bit for arbitrary data in memory.


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
