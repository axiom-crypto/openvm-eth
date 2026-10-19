/* A C guest for tests/link.sh. It defines a weak memcpy, as Rust's compiler-builtins does, which
   must lose to the library's, and a static constructor (volatile, so that the compiler can't
   evaluate it at compile time). */
#include <stddef.h>
#include <stdint.h>

void read_input(const uint8_t **buf_ptr, size_t *buf_size);
void write_output(const uint8_t *output, size_t size);

void *decoy_memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = dest;
    const uint8_t *s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}
void *memcpy(void *dest, const void *src, size_t n) __attribute__((weak, alias("decoy_memcpy")));

static volatile int constructed;
__attribute__((constructor)) static void construct(void) { constructed = 1; }

int main(void) {
    const uint8_t *input;
    size_t size;
    uint8_t copy[64];
    read_input(&input, &size);
    if (size > sizeof copy) {
        size = sizeof copy;
    }
    memcpy(copy, input, size);
    write_output(copy, size);
    return constructed ? 0 : 1;
}
