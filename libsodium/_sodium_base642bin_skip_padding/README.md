Spectre v4 Vulnerability (Variant A)

### Location
- Function: `_sodium_base642bin_skip_padding`
- File: [sodium/codecs.c:253](https://github.com/jedisct1/libsodium/blob/d30251f03e646abd07b5399654f1f5dcea9a6b38/src/libsodium/sodium/codecs.c#L253)

### Code Snippet
```
static int
_sodium_base642bin_skip_padding(const char * const b64, const size_t b64_len,
                                size_t * const b64_pos_p,
                                const char * const ignore, size_t padding_len)
{
    int c;

    while (padding_len > 0) {
        if (*b64_pos_p >= b64_len) {
            errno = ERANGE;
            return -1;
        }
        c = b64[*b64_pos_p]; // speculative store bypass
        if (c == '=') {
            padding_len--;
        } else if (ignore == NULL || strchr(ignore, c) == NULL) {
            errno = EINVAL;
            return -1;
        }
        (*b64_pos_p)++;
    }
    return 0;
}
```

### Explanation
The pointer parameter `b64_pos_p` is stored on the stack upon entry to the function.
The subsequent load of `b64_pos_p` may read the stale value at that stack memory location via Speculative Store Bypass ([CVE-2018-3639](https://cve.org/CVERecord?id=CVE-2018-3639)).
If that stale value is attacker-controlled, the pointer dereference `*b64_pos_p` may read an arbitrary secret from memory and then leak that secret by using it to index into the array `b64[]`.
This vulnerability may allow an attacker to leak arbitrary data in memory.

### Suggested Fix
Insert a fence right before the vulnerable line of C code. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
12a15
> 	atomic_memory_fence(memory_order_acquire);
```
