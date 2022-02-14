static int
_sodium_base642bin_skip_padding(const char * const b64, const size_t b64_len,
                                size_t * const b64_pos_p,
                                const char * const ignore, size_t padding_len)
{
    int c;

    while (padding_len > 0) {
        if (*b64_pos_p >= b64_len) {
            errno = ERANGE;
            return -1;
        }
	atomic_memory_fence(memory_order_acquire);		
        c = b64[*b64_pos_p]; // speculative store bypass
        if (c == '=') {
            padding_len--;
        } else if (ignore == NULL || strchr(ignore, c) == NULL) {
            errno = EINVAL;
            return -1;
        }
        (*b64_pos_p)++;
    }
    return 0;
}
