## Spectre v1 Vulnerability (Variant B)

### Location
- Function: `ts_check_status_info`
- File: [crypto/ts/ts_rsp_verify.c:351](https://github.com/openssl/openssl/blob/3d27ac8d92ef89c202b518cf6c4e15477eb594b2/crypto/ts/ts_rsp_verify.c#L351)

### Code Snippet
```
static int ts_check_status_info(TS_RESP *response)
{
    TS_STATUS_INFO *info = response->status_info;
    long status = ASN1_INTEGER_get(info->status);
    const char *status_text = NULL;
    char *embedded_status_text = NULL;
    char failure_text[TS_STATUS_BUF_SIZE] = "";

    if (status == 0 || status == 1)
        return 1;

    /* There was an error, get the description in status_text. */
    if (0 <= status && status < (long) OSSL_NELEM(ts_status_text)) // <<< bypassed bounds check
        status_text = ts_status_text[status]; // <<< attacker-controlled read of secret into status_text
    else
        status_text = "unknown code";

    /* ... */

    ERR_raise_data(ERR_LIB_TS, TS_R_NO_TIME_STAMP_TOKEN,
                   "status code: %s, status text: %s, failure codes: %s",
                   status_text, // <<< dereference of tainted pointer by called function leaks secret
                   embedded_status_text ? embedded_status_text : "unspecified",
                   failure_text);
    OPENSSL_free(embedded_status_text);

    return 0;
}
```

### Explanation
The bounds check on attacker-controlled value `status` on line 363 may be speculatively bypassed via Bounds Check Bypass ([CVE-2017-5753](https://www.cve.org/CVERecord?id=CVE-2017-5753)),
allowing the array access on line 364 to write an arbitrary secret from memory into C string variable `status_text`.
The called function `ERR_raise_data` subsequently dereferences the tainted C string pointer `status_text`, leaking the secret into the cache.

This vulnerability may allow an attacker to leak arbitrary data in memory.

### Suggested Fix
Insert a fence right before line 364 to ensure the bounds check cannot be bypassed. See [fix.c](fix.c).
```
$ diff bug.c fix.c
0a1,2
> #include <stdatomic.h>
> 
13c15,16
<     if (0 <= status && status < (long) OSSL_NELEM(ts_status_text)) // <<< bypassed bounds check
---
>     if (0 <= status && status < (long) OSSL_NELEM(ts_status_text)) { // <<< bypassed bounds check
>         atomic_thread_fence(memory_order_acquire);
15c18
<     else
---
>     } else
```
