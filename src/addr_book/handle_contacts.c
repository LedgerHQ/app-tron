/* SPDX-FileCopyrightText: © 2026 Ledger SAS */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file handle_contacts.c
 * @brief Address Book contact list (Identity + Ledger Account).
 *
 * Lookup key is the 21-byte 0x41-prefixed Tron address.
 */

#if defined(HAVE_ADDRESS_BOOK)

#include <string.h>
#include "handle_contacts.h"
#include "app_mem_utils.h"  // APP_MEM_FREE
#include "os.h"             // PRINTF

static s_ab_contact *g_ab_contact_list = NULL;

static void delete_contact(flist_node_t *node) {
    APP_MEM_FREE(node);
}

void ab_contact_list_push(s_ab_contact *node) {
    flist_push_back((flist_node_t **) &g_ab_contact_list, (flist_node_t *) node);
}

void address_book_contact_cleanup(void) {
    flist_clear((flist_node_t **) &g_ab_contact_list, &delete_contact);
}

const s_ab_contact *get_address_book_contact(const uint8_t *addr) {
    if (addr == NULL) {
        return NULL;
    }
    for (s_ab_contact *tmp = g_ab_contact_list; tmp != NULL;
         tmp = (s_ab_contact *) ((flist_node_t *) tmp)->next) {
        if (memcmp(tmp->identifier, addr, ADDRESS_SIZE) == 0) {
            return tmp;
        }
    }
    return NULL;
}

void update_contact_name(const char *old_name, const char *new_name) {
    if (old_name == NULL || new_name == NULL) {
        return;
    }
    for (s_ab_contact *node = g_ab_contact_list; node != NULL;
         node = (s_ab_contact *) ((flist_node_t *) node)->next) {
        if ((node->type == AB_CONTACT_IDENTITY) &&
            (strncmp(node->contact_name, old_name, CONTACT_NAME_LENGTH) == 0)) {
            strlcpy(node->contact_name, new_name, sizeof(node->contact_name));
        }
    }
}

void update_contact_identifier(const uint8_t *old_addr, const uint8_t *new_addr) {
    if (old_addr == NULL || new_addr == NULL) {
        return;
    }
    for (s_ab_contact *node = g_ab_contact_list; node != NULL;
         node = (s_ab_contact *) ((flist_node_t *) node)->next) {
        if ((node->type == AB_CONTACT_IDENTITY) &&
            (memcmp(node->identifier, old_addr, ADDRESS_SIZE) == 0)) {
            memcpy(node->identifier, new_addr, ADDRESS_SIZE);
            return;  // identifier is unique in the list
        }
    }
}

void update_contact_scope(const uint8_t *addr, const char *new_scope) {
    if (addr == NULL || new_scope == NULL) {
        return;
    }
    for (s_ab_contact *node = g_ab_contact_list; node != NULL;
         node = (s_ab_contact *) ((flist_node_t *) node)->next) {
        if ((node->type == AB_CONTACT_IDENTITY) &&
            (memcmp(node->identifier, addr, ADDRESS_SIZE) == 0)) {
            strlcpy(node->scope, new_scope, sizeof(node->scope));
            return;  // identifier is unique in the list
        }
    }
}

void update_ledger_account_contact_name(const uint8_t *addr, const char *new_name) {
    if (addr == NULL || new_name == NULL) {
        return;
    }
    for (s_ab_contact *node = g_ab_contact_list; node != NULL;
         node = (s_ab_contact *) ((flist_node_t *) node)->next) {
        if ((node->type == AB_CONTACT_LEDGER_ACCOUNT) &&
            (memcmp(node->identifier, addr, ADDRESS_SIZE) == 0)) {
            strlcpy(node->contact_name, new_name, sizeof(node->contact_name));
            return;  // address is unique in the list
        }
    }
}

#endif  // HAVE_ADDRESS_BOOK
