## Spectre v1 Vulnerability (Variant B)

### Location
- Function: [`SSL_get_shared_sigalgs`](https://www.openssl.org/docs/man3.0/man3/SSL_get_shared_sigalgs.html)
- File: [ssl/t1_lib.c:2408](https://github.com/openssl/openssl/blob/3d27ac8d92ef89c202b518cf6c4e15477eb594b2/ssl/t1_lib.c#L2408)

### Code Snippet
```
int SSL_get_shared_sigalgs(SSL *s, int idx,
                           int *psign, int *phash, int *psignhash,
                           unsigned char *rsig, unsigned char *rhash)
{
    const SIGALG_LOOKUP *shsigalgs;
    if (s->shared_sigalgs == NULL
        || idx < 0
        || idx >= (int)s->shared_sigalgslen // <<< bypassed bounds check (Spectre v1)
        || s->shared_sigalgslen > INT_MAX)
        return 0;
    shsigalgs = s->shared_sigalgs[idx]; // <<< out-of-bounds array access using attacker-controlled index
    if (phash != NULL)
        *phash = shsigalgs->hash; // <<< tainted pointer access leaks secret into cache
    if (psign != NULL)
        *psign = shsigalgs->sig;
    if (psignhash != NULL)
        *psignhash = shsigalgs->sigandhash;
    if (rsig != NULL)
        *rsig = (unsigned char)(shsigalgs->sigalg & 0xff);
    if (rhash != NULL)
        *rhash = (unsigned char)((shsigalgs->sigalg >> 8) & 0xff);
    return (int)s->shared_sigalgslen;
}
```

### Explanation
The bounds check on attacker-controlled index `idx` on lines 2414 and 2415 may be speculatively bypassed via Bounds Check Bypass ([CVE-2017-5753](https://www.cve.org/CVERecord?id=CVE-2017-5753)), 
allowing the array access on line 2418 to an arbitrary secret from memory into pointer variable `shsigalgs`.
When the tainted pointer `shsigalgs` is accessed on line 2420, it leaks the secret into the cache.

This vulnerability may allow an attacker to leak arbitrary data in memory and appears to be highly exploitable,
since it is via a classic Spectre v1 gadget in the public API function [SSL_get_shared_sigalgs](https://www.openssl.org/docs/man3.0/man3/SSL_get_shared_sigalgs.html).


The struct pointer parameter `c` is stored to the stack upon entry to the function.
The subsequent load of `c` on line 145 may read the stale value at that stack memory location via Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If that stale value is attacker-controlled, the struct member access `c->num` on line 145 may read an arbitrary secret from memory, which is subsequently stored to the stack in index `n`.
Index `n` is then used in pointer arithmetic with `p` and then dereferenced by `memcpy()` on lines 150 and 164, leaking the value of the secret in `n`.

This vulnerability may allow an attacker to leak arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 145 to ensure the store of parameter `c` cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
10a13
>     atomic_thread_fence(memory_order_acquire);
```
