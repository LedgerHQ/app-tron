/* SPDX-FileCopyrightText: © 2026 Ledger SAS */
/* SPDX-License-Identifier: Apache-2.0 */

#include <string.h>
#include "known_services.h"
#include "parse.h"
#include "os.h"

typedef struct {
    uint8_t address[ADDRESS_SIZE];
    const char *label;
} s_known_service;

/*
 * TUFXua1qzfCsFpcZEGXaU7oGFURqQ7RQpy - Tronify platformAddr, taken from the
 * uploadHash example in Tronify's API documentation.
 * TODO: have PTX confirm it against the commercial contract before release.
 */
static const s_known_service KNOWN_SERVICES[] = {
    {{0x41, 0xC8, 0x88, 0xB3, 0x6E, 0x17, 0x95, 0x8E, 0x39, 0x14, 0x00,
      0x51, 0xEB, 0x5D, 0x8C, 0xBC, 0x1B, 0x5C, 0x10, 0x9D, 0x6D},
     "Energy rental - Tronify"},
};

const char *get_known_service_label(const uint8_t *raw_address) {
    if (raw_address == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < ARRAYLEN(KNOWN_SERVICES); i++) {
        if (memcmp(raw_address, KNOWN_SERVICES[i].address, ADDRESS_SIZE) == 0) {
            return KNOWN_SERVICES[i].label;
        }
    }
    return NULL;
}
