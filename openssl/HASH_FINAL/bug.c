int HASH_FINAL(unsigned char *md, HASH_CTX *c)
{
    ...
    size_t n = c->num;

    p[n] = 0x80;                /* there is always room for one */
    ...
}
