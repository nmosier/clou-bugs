## Spectre v1 Vulnerability

### Location
- Function: `EVP_PKEY_asn1_get0`
- File: [crypto/asn1/ameth_lib.c:52](https://github.com/openssl/openssl/blob/065121ff198a84106023013420dedd57ac4ff53a/crypto/asn1/ameth_lib.c#L52)

### Code Snippet
```
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx)
{
    int num = OSSL_NELEM(standard_methods);
    if (idx < 0)
        return NULL;
    if (idx < num) // <<< speculative bounds check bypass
        return standard_methods[idx]; // <<< speculative out-of-bounds access returns secret
    idx -= num;
    return sk_EVP_PKEY_ASN1_METHOD_value(app_methods, idx);
}
```

### Explanation
Line 52 performs a bounds check on the attacker-controlled parameter `idx`.
If `idx` is out of bounds (`idx >= num`) but the processor predicts that `idx < num`, the body of the if-statement is executed, and the out-of-bounds load from the array `standard_methods[idx]` returns an arbitrary secret in memory, reinterpreted as a pointer.
The caller of `EVP_PKEY_asn1_get0` then reads from the tainted pointer, leaking the arbitrary secret.

This vulnerability may allow an attacker to leak arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 145 to ensure the store of parameter `c` cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
6c8,9
<     if (idx < num) // <<< speculative bounds check bypass
---
>     if (idx < num) { // <<< speculative bounds check bypass
>         atomic_thread_fence(memory_fence_acquire);
7a11
>     }
```
