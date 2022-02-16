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
