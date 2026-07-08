/* SPDX-FileCopyrightText: © 2026 Ledger SAS */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#if defined(HAVE_ADDRESS_BOOK)

#include <stdint.h>
#include <stdbool.h>
#include "identity.h"  // CONTACT_NAME_LENGTH, SCOPE_LENGTH
#include "lists.h"     // flist_node_t
#include "parse.h"     // ADDRESS_SIZE

// Type of a stored Address Book contact.
typedef enum {
    AB_CONTACT_IDENTITY,
    AB_CONTACT_LEDGER_ACCOUNT,
} ab_contact_type_e;

// A stored Address Book contact. _list must stay first for flist casts.
// Tron has a single network, so no chain_id is kept: the 21-byte 0x41-prefixed
// address is the unique key.
typedef struct {
    flist_node_t _list;
    ab_contact_type_e type;
    char contact_name[CONTACT_NAME_LENGTH];
    char scope[SCOPE_LENGTH];
    uint8_t identifier[ADDRESS_SIZE];  ///< 21-byte 0x41-prefixed address
} s_ab_contact;

void ab_contact_list_push(s_ab_contact *node);

const s_ab_contact *get_address_book_contact(const uint8_t *addr);

void address_book_contact_cleanup(void);

void update_contact_name(const char *old_name, const char *new_name);

void update_contact_identifier(const uint8_t *old_addr, const uint8_t *new_addr);

void update_contact_scope(const uint8_t *addr, const char *new_scope);

void update_ledger_account_contact_name(const uint8_t *addr, const char *new_name);

#endif  // HAVE_ADDRESS_BOOK
