/* A C guest for tests/link.sh. It defines a weak memcpy, as Rust's compiler-builtins does, which
   must lose to the library's, and a static constructor (volatile, so that the compiler can't
   evaluate it at compile time). It has a named read-only object, which must stay out of the
   executable segment, and an uninitialized .noinit buffer, which must stay below the program's
   heap, and it copies its input to its heap, which openvm.ld defines. */
#include <stddef.h>
#include <stdint.h>

void read_input(const uint8_t **buf_ptr, size_t *buf_size);
void write_output(const uint8_t *output, size_t size);

extern uint8_t _heap_start[], _heap_end[];

const uint8_t link_magic[8] = "openvm!";

/* .noinit as GNU as makes it, a NOBITS section. */
__asm__(".pushsection .noinit,\"aw\",@nobits\n"
        ".globl noinit_buf\n"
        "noinit_buf:\n"
        ".zero 64\n"
        ".popsection");
extern volatile uint8_t noinit_buf[64];

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
    noinit_buf[0] = 0x5a;
    read_input(&input, &size);
    if (size > (uintptr_t)_heap_end - (uintptr_t)_heap_start) {
        return 2;
    }
    memcpy(_heap_start, input, size);
    if (noinit_buf[0] != 0x5a || *(volatile const uint8_t *)link_magic != 'o') {
        return 3;
    }
    write_output(_heap_start, size);
    return constructed ? 0 : 1;
}
