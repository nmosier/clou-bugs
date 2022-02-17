## Spectre v1 Vulnerability (Variant B)

### Location
- Function: `TXT_DB_create_index`
- File: [crypto/txt_db/txt_db.c:150](https://github.com/openssl/openssl/blob/3d27ac8d92ef89c202b518cf6c4e15477eb594b2/crypto/txt_db/txt_db.c#L150)

### Code Snippet
```
int TXT_DB_create_index(TXT_DB *db, int field, int (*qual) (OPENSSL_STRING *),
                        OPENSSL_LH_HASHFUNC hash, OPENSSL_LH_COMPFUNC cmp)
{
    LHASH_OF(OPENSSL_STRING) *idx;
    OPENSSL_STRING *r, *k;
    int i, n;

    if (field >= db->num_fields) { // <<< bypassed bounds check on `field`
        db->error = DB_ERROR_INDEX_OUT_OF_RANGE;
        return 0;
    }

    /* ... */
    
   	lh_OPENSSL_STRING_free(db->index[field]); // <<< array access reads arbirary secret that is leaked in function
    db->index[field] = idx;
    db->qual[field] = qual;
    return 1;
}
```

### Explanation
The bounds check on attacker-controlled value `field` on line 157 may be speculatively bypassed via Bounds Check Bypass ([CVE-2017-5753](https://www.cve.org/CVERecord?id=CVE-2017-5753)),
allowing the array access on line 184 to pass an arbitrary secret from memory to function `lh_OPENSSL_STRING_free` as a pointer.
The called function subsequently dereferences the tainted pointer, leaking the secret into the cache.

This vulnerability may allow an attacker to leak arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 161 to ensure the bounds check cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
11a14
>     atomic_thread_fence(memory_order_acquire);
```
