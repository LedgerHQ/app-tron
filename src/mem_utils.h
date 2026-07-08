#pragma once

#include <stdbool.h>

// Initialize the dynamic allocation heap. Must be called once at startup.
bool app_mem_init(void);
