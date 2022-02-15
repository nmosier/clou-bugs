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
