#include <stdatomic.h>

static size_t
sodium_strnlen(const char *str, size_t maxlen)
{
    size_t i = 0U;

    atomic_thread_fence(memory_order_acquire);
    while (i < maxlen && str[i] != 0) { // <<< speculative store bypass and insecure branch predicate
        i++;
    }
    return i;
}
