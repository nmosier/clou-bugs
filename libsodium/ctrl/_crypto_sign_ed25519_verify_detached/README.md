## Spectre v4 Vulnerability (Variant B')

### Location
- Function: `HASH_UPDATE`
- File: [include/crypto/md32_common.h:138](https://github.com/openssl/openssl/blob/065121ff198a84106023013420dedd57ac4ff53a/include/crypto/md32_common.h#L138)

### Code Snippet
```
int HASH_UPDATE(HASH_CTX *c, const void *data_, size_t len)
{
    /* ... */
    HASH_LONG l;
    /* ... */
    l = (c->Nl + (((HASH_LONG) len) << 3)) & 0xffffffffUL; // <<< speculative store bypass
    if (l < c->Nl) // <<< branch on secret
        c->Nh++;
    /* ... */
}
```

### Explanation
The struct pointer parameter `c` is stored to the stack upon entry to the function.
The subsequent load of `c` on line 138 may read the stale value at that stack memory location via Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If that stale value is attacker-controlled, the struct member access `c->Nl` on line 145 may read an arbitrary secret from memory, which is subsequently stored to the stack in variable `l`.
The if-statement on line 139 branches on `l`, which contains a secret, thereby a one-bit function of the secret.

This vulnerability may allow an attacker to leak one bit for arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 138 to ensure the store of parameter `c` cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
13a16
>     atomic_thread_fence(memory_order_acquire);
```
