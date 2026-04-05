#ifndef XENON_BOOTLOADER_H_
#define XENON_BOOTLOADER_H_

#include <stdint.h>
#include <stdbool.h>
#include "excrypt.h"

typedef struct _bootloader_compression_header {
    uint32_t window_size;
    uint32_t block_size;
    uint32_t compressed_size;
    uint32_t decompressed_size;
} bootloader_compression_header;

typedef struct _bootloader_compression_block {
    uint16_t compressed_size;
    uint16_t decompressed_size;
} bootloader_compression_block;

typedef struct _bootloader_delta_block {
    uint32_t old_addr;
    uint32_t new_addr;
    uint16_t decompressed_size;
    uint16_t compressed_size;
} bootloader_delta_block;

#endif
