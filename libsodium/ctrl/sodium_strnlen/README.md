## Spectre v4 Vulnerability (Variant A')

### Location
- Function: `sodium_strnlen`
- File: [crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c:60](https://github.com/jedisct1/libsodium/blob/d30251f03e646abd07b5399654f1f5dcea9a6b38/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c#L60)

### Code Snippet
```
static size_t
sodium_strnlen(const char *str, size_t maxlen)
{
    size_t i = 0U;

    while (i < maxlen && str[i] != 0) { // <<< speculative store bypass and insecure branch predicate
        i++;
    }
    return i;
}
```

### Explanation
The C string parameter `str` is stored to the stack upon entry to the function.
The subsequent load of `str` on line 60 may read the stale value at that stack memory location via Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639).
If that stale value is attacker-controlled, the array access `str[i]` on line 159 may read an arbitrary secret from memory.
A 1-bit function of this secret leaks through the while-loop predicate on line 159.

This vulnerability may allow an attacker to leak one bit for arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 159 to ensure the store of parameter `state` cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
5a8
>     atomic_thread_fence(memory_order_acquire);
```
