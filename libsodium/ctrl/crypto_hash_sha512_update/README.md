## Spectre v4 Vulnerability (Variant A')

### Location
- Function: `_crypto_sign_ed25519_verify_detached`
- File: [crypto_sign/ed25519/ref10/open.c:27,31](https://github.com/jedisct1/libsodium/blob/d30251f03e646abd07b5399654f1f5dcea9a6b38/src/libsodium/crypto_sign/ed25519/ref10/open.c#L27)

### Code Snippet
```
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
12a15
>     atomic_thread_fence(memory_order_acquire);
```
