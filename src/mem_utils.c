#include <stdint.h>
#include "app_mem_utils.h"
#include "mem_utils.h"

// Heap for the Address Book contact store and its transient UI buffers.
#define SIZE_MEM_BUFFER (1024 * 8)

static uint8_t mem_buffer[SIZE_MEM_BUFFER] __attribute__((aligned(sizeof(intmax_t))));

bool app_mem_init(void) {
    return mem_utils_init(mem_buffer, sizeof(mem_buffer));
}
