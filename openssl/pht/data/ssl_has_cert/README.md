## Spectre v1 Vulnerability (Variant B)

### Location
- Function: `ssl_has_cert`
- File: [ssl/ssl_local.h:2361](https://github.com/openssl/openssl/blob/3d27ac8d92ef89c202b518cf6c4e15477eb594b2/ssl/ssl_local.h#L2361)

### Code Snippet
```
/* Returns true if certificate and private key for 'idx' are present */
static ossl_inline int ssl_has_cert(const SSL *s, int idx)
{
    if (idx < 0 || idx >= SSL_PKEY_NUM) // <<< bounds check bypass via Spectre v1
        return 0;
    return s->cert->pkeys[idx].x509 != NULL // <<< speculative return value leaks one-bit function of arbitrary secret
        && s->cert->pkeys[idx].privatekey != NULL;
}
```

### Explanation
The bounds check on attacker-controlled index `idx` on line 2363 may be speculatively  bypassed via Bounds Check Bypass ([CVE-2017-5753](https://www.cve.org/CVERecord?id=CVE-2017-5753)), 
allowing the array accesses on lines 2365 and 2366 to load an arbitrary secret in memory and return whether it is zero. 
Subsequent code may branch on this tainted return value, leaking the one-bit function of the secret.

### Suggested Fix
Insert a fence right before line 2365 to ensure the bounds check resolves before accessing the array.
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
5a8
>     atomic_thread_fence(memory_order_acquire);
```
