## Spectre v4 Vulnerability (Variant B)

### Location
- Function: `HASH_FINAL`
- File: [include/crypto/md32_common.h:191](https://github.com/openssl/openssl/blob/065121ff198a84106023013420dedd57ac4ff53a/include/crypto/md32_common.h#L191)

### Code Snippet
```
int HASH_FINAL(unsigned char *md, HASH_CTX *c)
{
    ...
    size_t n = c->num; // <<< speculative store bypass

    p[n] = 0x80; // <<< secret in `n` leaked through array access
    ...
}
```

### Explanation
The struct pointer parameter `c` is stored to the stack upon entry to the function.
The subsequent load of `c` on line 191 may read the stale value at that stack memory location via Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If that stale value is attacker-controlled, the struct member access `c->num` on line 145 may read an arbitrary secret from memory, which is subsequently stored to the stack in index `n`.
The index `n` is then used to access array `p` on line 196, leaking the value of the secret in `n`.

This vulnerability may allow an attacker to leak arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 191 to ensure the store of parameter `c` cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
3a6
>     atomic_thread_fence(memory_order_acquire);
```
