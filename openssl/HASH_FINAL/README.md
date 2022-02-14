## Spectre v4 Vulnerability (Variant B)

### Location
- Function: `HASH_UPDATE`
- File: [include/crypto/md32_common.h:145](https://github.com/openssl/openssl/blob/065121ff198a84106023013420dedd57ac4ff53a/include/crypto/md32_common.h#L145)

### Code Snippet
```
int HASH_UPDATE(HASH_CTX *c, const void *data_, size_t len)
{
    ...
    size_t n;
    ...
    n = c->num; // <<< speculative store bypass
    if (n != 0) {
        p = (unsigned char *)c->data;

        if (len >= HASH_CBLOCK || len + n >= HASH_CBLOCK) {
            memcpy(p + n, data, HASH_CBLOCK - n); // <<< memcpy() dereferences secret-tainted pointer
            ...
        } else {
            memcpy(p + n, data, len); // <<< memcpy() dereferences secret-tainted pointer
            ...
        }
    }
    ...
}
```

### Explanation
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
5a8
>     atomic_thread_fence(memory_order_acquire);
```
