int HASH_FINAL(unsigned char *md, HASH_CTX *c)
{
    ...
    size_t n = c->num; // <<< speculative store bypass

    p[n] = 0x80; // <<< secret in `n` leaked through array access
    ...
}
