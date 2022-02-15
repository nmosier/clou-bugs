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
