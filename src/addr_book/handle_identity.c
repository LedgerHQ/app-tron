/* SPDX-FileCopyrightText: © 2026 Ledger SAS */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file handle_identity.c
 * @brief Coin-app callbacks for Address Book Identity flows (Tron).
 *
 * The identifier is a 21-byte 0x41-prefixed Tron address, displayed as a
 * base58check "T..." string. Tron has a single network, so there is no chain_id.
 */

#if defined(HAVE_ADDRESS_BOOK)

#include <string.h>
#include "address_book_entrypoints.h"
#include "address_book_ctx.h"
#include "handle_contacts.h"
#include "helpers.h"
#include "parse.h"
#include "ui_idle_menu.h"
#include "app_mem_utils.h"
#include "os.h"

#define g_ctx g_ab_ctx.identity

// base58 "T..." string buffer size (including null terminator)
#define AB_ADDR_STR_SIZE (BASE58CHECK_ADDRESS_SIZE + 1)

// Validate a Tron identifier: 21-byte address with the mainnet 0x41 prefix.
static bool is_valid_tron_identifier(const identity_t *id) {
    if (id->blockchain_family != FAMILY_TRON) {
        PRINTF("Unsupported blockchain family: %d\n", id->blockchain_family);
        return false;
    }
    if (id->identifier_len != ADDRESS_SIZE) {
        PRINTF("Invalid identifier length: %d (expected %d)\n", id->identifier_len, ADDRESS_SIZE);
        return false;
    }
    if (id->identifier[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        PRINTF("Invalid address prefix: %02x\n", id->identifier[0]);
        return false;
    }
    return true;
}

/* ============================ Register Identity ========================= */

void finalize_ui_register_identity(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.register_identity.identifier_display);
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.register_identity.identity);
    ui_idle();
}

bool handle_check_register_identity(identity_t *params) {
    if (params == NULL || !is_valid_tron_identifier(params)) {
        return false;
    }
    if (APP_MEM_PERMANENT((void **) &g_ctx.register_identity.identity, sizeof(identity_t)) ==
        false) {
        PRINTF("Failed to allocate identity\n");
        return false;
    }
    memmove(g_ctx.register_identity.identity, params, sizeof(identity_t));
    return true;
}

nbgl_contentTagValue_t *get_register_identity_tagValue(uint8_t pairIndex) {
    memset(&g_ctx.current_pair, 0, sizeof(g_ctx.current_pair));
    switch (pairIndex) {
        case 0:
            g_ctx.current_pair.item = "Contact name";
            g_ctx.current_pair.value = g_ctx.register_identity.identity->contact_name;
            break;
        case 1:
            g_ctx.current_pair.item = "Address name";
            g_ctx.current_pair.value = g_ctx.register_identity.identity->scope;
            break;
        case 2:
            if (APP_MEM_PERMANENT((void **) &g_ctx.register_identity.identifier_display,
                                  AB_ADDR_STR_SIZE) == false) {
                PRINTF("Failed to allocate identifier display buffer\n");
                return NULL;
            }
            getBase58FromAddress(g_ctx.register_identity.identity->identifier,
                                 g_ctx.register_identity.identifier_display);
            g_ctx.current_pair.item = "Address";
            g_ctx.current_pair.value = g_ctx.register_identity.identifier_display;
            break;
        default:
            return NULL;
    }
    return &g_ctx.current_pair;
}

/* =================== Edit Contact Name / Edit Scope ==================== */
/* Display is handled entirely by the SDK; only cleanup is needed here.    */

void finalize_ui_edit_contact_name(void) {
    ui_idle();
}

void finalize_ui_edit_scope(void) {
    ui_idle();
}

/* ============================ Edit Identifier ========================== */

static void free_edit_identifier_buffers(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.edit_identifier.contact_name);
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.edit_identifier.scope);
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.edit_identifier.old_identifier);
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.edit_identifier.new_identifier);
}

void finalize_ui_edit_identifier(void) {
    free_edit_identifier_buffers();
    ui_idle();
}

bool handle_check_edit_identifier(const edit_identifier_t *params) {
    if (params == NULL || !is_valid_tron_identifier(&params->identity)) {
        return false;
    }
    if (params->old_identifier_len != ADDRESS_SIZE ||
        params->old_identifier[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        PRINTF("Invalid previous identifier\n");
        return false;
    }

    if (APP_MEM_PERMANENT((void **) &g_ctx.edit_identifier.contact_name, CONTACT_NAME_LENGTH) ==
            false ||
        APP_MEM_PERMANENT((void **) &g_ctx.edit_identifier.scope, SCOPE_LENGTH) == false ||
        APP_MEM_PERMANENT((void **) &g_ctx.edit_identifier.old_identifier, AB_ADDR_STR_SIZE) ==
            false ||
        APP_MEM_PERMANENT((void **) &g_ctx.edit_identifier.new_identifier, AB_ADDR_STR_SIZE) ==
            false) {
        PRINTF("Failed to allocate edit identifier buffers\n");
        free_edit_identifier_buffers();
        return false;
    }

    strlcpy(g_ctx.edit_identifier.contact_name, params->identity.contact_name, CONTACT_NAME_LENGTH);
    strlcpy(g_ctx.edit_identifier.scope, params->identity.scope, SCOPE_LENGTH);
    getBase58FromAddress(params->old_identifier, g_ctx.edit_identifier.old_identifier);
    getBase58FromAddress(params->identity.identifier, g_ctx.edit_identifier.new_identifier);
    return true;
}

nbgl_contentTagValue_t *get_edit_identifier_tagValue(uint8_t pairIndex) {
    memset(&g_ctx.current_pair, 0, sizeof(g_ctx.current_pair));
    switch (pairIndex) {
        case 0:
            g_ctx.current_pair.item = "Contact name";
            g_ctx.current_pair.value = g_ctx.edit_identifier.contact_name;
            break;
        case 1:
            g_ctx.current_pair.item = "Address name";
            g_ctx.current_pair.value = g_ctx.edit_identifier.scope;
            break;
        case 2:
            g_ctx.current_pair.item = "Old address";
            g_ctx.current_pair.value = g_ctx.edit_identifier.old_identifier;
            break;
        case 3:
            g_ctx.current_pair.item = "New address";
            g_ctx.current_pair.value = g_ctx.edit_identifier.new_identifier;
            break;
        default:
            return NULL;
    }
    return &g_ctx.current_pair;
}

/* ==================== Confirmed-edit cache updates ===================== */

void on_edit_contact_name_applied(const edit_contact_name_t *edit) {
    if (edit == NULL) {
        return;
    }
    update_contact_name(edit->old_contact_name, edit->contact_name);
}

void on_edit_identifier_applied(const edit_identifier_t *edit) {
    if (edit == NULL) {
        return;
    }
    update_contact_identifier(edit->old_identifier, edit->identity.identifier);
}

void on_edit_scope_applied(const edit_scope_t *edit) {
    if (edit == NULL) {
        return;
    }
    update_contact_scope(edit->identity.identifier, edit->identity.scope);
}

/* ============================ Provide Contact ========================== */

bool handle_provide_identity(const identity_t *contact) {
    s_ab_contact *node = NULL;

    if (contact == NULL || !is_valid_tron_identifier(contact)) {
        return false;
    }
    if (get_address_book_contact(contact->identifier) != NULL) {
        PRINTF("Contact already stored, ignoring\n");
        return true;
    }
    if (APP_MEM_PERMANENT((void **) &node, sizeof(*node)) == false) {
        PRINTF("Failed to allocate contact\n");
        return false;
    }
    node->type = AB_CONTACT_IDENTITY;
    strlcpy(node->contact_name, contact->contact_name, sizeof(node->contact_name));
    strlcpy(node->scope, contact->scope, sizeof(node->scope));
    memcpy(node->identifier, contact->identifier, ADDRESS_SIZE);
    ab_contact_list_push(node);
    PRINTF("Stored contact '%s'\n", node->contact_name);
    return true;
}

#endif  // HAVE_ADDRESS_BOOK
