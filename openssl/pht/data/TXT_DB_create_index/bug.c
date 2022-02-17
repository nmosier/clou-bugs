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
