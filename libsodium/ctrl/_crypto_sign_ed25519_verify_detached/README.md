## Spectre v4 Vulnerability (Variant A')

### Location
- Function: `_crypto_sign_ed25519_verify_detached`
- File: [crypto_sign/ed25519/ref10/open.c:27,31](https://github.com/jedisct1/libsodium/blob/d30251f03e646abd07b5399654f1f5dcea9a6b38/src/libsodium/crypto_sign/ed25519/ref10/open.c#L27)

### Code Snippet
```
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
```

### Explanation
The pointer parameter `sig` is stored to the stack upon entry to the function.
The subsequent loads of `sig` on lines 27 and 31 may read the stale value at that stack memory location via Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If that stale value is attacker-controlled, the array access `sig[63]` on lines 27 and 31 may read an arbitrary secret from memory.
A 1-bit function of this secret leaks through the branch predicates on lines 27 and 31.

This vulnerability may allow an attacker to leak one bit for arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 26 to ensure the store of parameter `sig` cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
13a16
>     atomic_thread_fence(memory_order_acquire);
```
