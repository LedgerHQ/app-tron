/* SPDX-FileCopyrightText: © 2026 Ledger SAS */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file known_services.h
 * @brief Registry of well-known third-party service addresses.
 *
 * Entries are compiled into the application binary: they are trusted because
 * they ship with the signed app, not because the host provided them. The label
 * is only ever displayed in addition to the raw address, never in place of it.
 */

#pragma once

#include <stdint.h>

/**
 * @brief Look up a well-known service by its raw Tron address.
 *
 * @param[in] raw_address 21-byte 0x41-prefixed address, or NULL
 * @return the display label, or NULL if the address is not a known service
 */
const char *get_known_service_label(const uint8_t *raw_address);
