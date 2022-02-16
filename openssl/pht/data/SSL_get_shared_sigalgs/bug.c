int SSL_get_shared_sigalgs(SSL *s, int idx,
                           int *psign, int *phash, int *psignhash,
                           unsigned char *rsig, unsigned char *rhash)
{
    const SIGALG_LOOKUP *shsigalgs;
    if (s->shared_sigalgs == NULL
        || idx < 0
        || idx >= (int)s->shared_sigalgslen // <<< bypassed bounds check (Spectre v1)
        || s->shared_sigalgslen > INT_MAX)
        return 0;
    shsigalgs = s->shared_sigalgs[idx]; // <<< out-of-bounds array access using attacker-controlled index
    if (phash != NULL)
        *phash = shsigalgs->hash; // <<< tainted pointer access leaks secret into cache
    if (psign != NULL)
        *psign = shsigalgs->sig;
    if (psignhash != NULL)
        *psignhash = shsigalgs->sigandhash;
    if (rsig != NULL)
        *rsig = (unsigned char)(shsigalgs->sigalg & 0xff);
    if (rhash != NULL)
        *rhash = (unsigned char)((shsigalgs->sigalg >> 8) & 0xff);
    return (int)s->shared_sigalgslen;
}
