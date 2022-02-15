static size_t
sodium_strnlen(const char *str, size_t maxlen)
{
    size_t i = 0U;

    while (i < maxlen && str[i] != 0) { // <<< speculative store bypass and insecure branch predicate
        i++;
    }
    return i;
}
