/* SPDX-FileCopyrightText: © 2026 Ledger SAS */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file handle_ledger_account.c
 * @brief Coin-app callbacks for Address Book Ledger Account flows (Tron).
 *
 * A Ledger Account is identified by its BIP32 path; the address is derived on
 * device and displayed as a base58check "T..." string.
 */

#if defined(HAVE_ADDRESS_BOOK) && defined(HAVE_ADDRESS_BOOK_LEDGER_ACCOUNT)

#include <string.h>
#include "address_book_entrypoints.h"
#include "address_book_ctx.h"
#include "handle_contacts.h"
#include "helpers.h"
#include "parse.h"
#include "ui_idle_menu.h"
#include "ui_globals.h"  // APP_TRON_ICON
#include "app_mem_utils.h"
#include "os.h"
#include "crypto_helpers.h"
#include "nbgl_icons.h"

#define g_ctx g_ab_ctx.ledger_account

#define AB_ADDR_STR_SIZE (BASE58CHECK_ADDRESS_SIZE + 1)

// Derive the 21-byte 0x41-prefixed Tron address for a BIP32 path.
static bool derive_tron_address(const path_bip32_t *path, uint8_t address[ADDRESS_SIZE]) {
    uint8_t pubkey[PUBLIC_KEY_SIZE] = {0};
    bool ok = false;

    if (bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                    path->path,
                                    path->length,
                                    pubkey,
                                    NULL,
                                    CX_SHA512) == CX_OK) {
        getAddressFromPublicKey(pubkey, address);
        ok = true;
    }
    explicit_bzero(pubkey, sizeof(pubkey));
    return ok;
}

/* ======================= Register Ledger Account ======================= */

static void free_ledger_account_buffers(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.register_account.address_display);
    APP_MEM_FREE_AND_NULL((void **) &g_ctx.ledger_account);
}

void finalize_ui_ledger_account(void) {
    free_ledger_account_buffers();
    ui_idle();
}

bool handle_check_register_ledger_account(ledger_account_t *params) {
    uint8_t address[ADDRESS_SIZE] = {0};

    if (params == NULL) {
        return false;
    }
    if (params->blockchain_family != FAMILY_TRON) {
        PRINTF("Unsupported blockchain family: %d\n", params->blockchain_family);
        return false;
    }
    if (params->bip32_path.length == 0 || params->bip32_path.length > MAX_BIP32_PATH) {
        PRINTF("Invalid derivation path length: %d\n", params->bip32_path.length);
        return false;
    }

    if (APP_MEM_PERMANENT((void **) &g_ctx.register_account.address_display, AB_ADDR_STR_SIZE) ==
        false) {
        PRINTF("Failed to allocate address display buffer\n");
        return false;
    }
    if (!derive_tron_address(&params->bip32_path, address)) {
        PRINTF("Key derivation failed\n");
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.register_account.address_display);
        return false;
    }
    getBase58FromAddress(address, g_ctx.register_account.address_display);

    if (APP_MEM_PERMANENT((void **) &g_ctx.ledger_account, sizeof(ledger_account_t)) == false) {
        PRINTF("Failed to allocate ledger_account\n");
        APP_MEM_FREE_AND_NULL((void **) &g_ctx.register_account.address_display);
        return false;
    }
    memmove(g_ctx.ledger_account, params, sizeof(ledger_account_t));
    return true;
}

void display_register_ledger_account_review(nbgl_choiceCallback_t choice_callback) {
    register_ledger_account_ctx_t *ra = &g_ctx.register_account;

#ifdef SCREEN_SIZE_WALLET
    // Full address kept for the details modal (reached via the header info icon)
    ra->texts[0] = "Address";
    ra->subTexts[0] = ra->address_display;
    ra->details.title = g_ctx.ledger_account->account_name;
    ra->details.type = BAR_LIST_WARNING;
    ra->details.barList.nbBars = 1;
    ra->details.barList.texts = ra->texts;
    ra->details.barList.subTexts = ra->subTexts;

    // Middle-truncated address for the subMessage line: "TBoTZ...QL16"
    snprintf(ra->address_display_short,
             sizeof(ra->address_display_short),
             "%.*s...%s",
             1 + AB_ADDR_SHORT_LEN,
             ra->address_display,
             ra->address_display + BASE58CHECK_ADDRESS_SIZE - AB_ADDR_SHORT_LEN);

    nbgl_useCaseAdvancedChoiceWithDetails(&APP_TRON_ICON,
                                          &INFO_I_ICON,
                                          "Confirm name?",
                                          g_ctx.ledger_account->account_name,
                                          ra->address_display_short,
                                          "Confirm",
                                          "Cancel",
                                          &ra->details,
                                          choice_callback);
#else
    memset(ra->pairs, 0, sizeof(ra->pairs));
    memset(&ra->list, 0, sizeof(ra->list));
    ra->pairs[0].item = "Account name";
    ra->pairs[0].value = g_ctx.ledger_account->account_name;
    ra->pairs[1].item = "Address";
    ra->pairs[1].value = ra->address_display;
    ra->list.pairs = ra->pairs;
    ra->list.nbPairs = 2;

    nbgl_useCaseReview(TYPE_OPERATION | ADDRESS_BOOK_OPERATION,
                       &ra->list,
                       &APP_TRON_ICON,
                       "Review account name",
                       NULL,
                       "Confirm account name",
                       choice_callback);
#endif
}

/* ========================= Edit Ledger Account ========================= */

bool handle_check_edit_ledger_account(edit_ledger_account_t *params) {
    if (params == NULL) {
        return false;
    }
    // Reuse the Register check to validate and prepare the shared review context.
    if (!handle_check_register_ledger_account(&params->ledger_account)) {
        return false;
    }
    // Keep the raw address so on_edit_ledger_account_applied() can locate the entry.
    if (!derive_tron_address(&params->ledger_account.bip32_path, params->address)) {
        PRINTF("Key derivation failed\n");
        free_ledger_account_buffers();
        return false;
    }
    params->address_len = ADDRESS_SIZE;
    return true;
}

void on_edit_ledger_account_applied(const edit_ledger_account_t *edit) {
    if (edit == NULL) {
        return;
    }
    update_ledger_account_contact_name(edit->address, edit->ledger_account.account_name);
}

/* =================== Provide Ledger Account Contact ==================== */

bool handle_provide_ledger_account(const ledger_account_t *account) {
    uint8_t address[ADDRESS_SIZE] = {0};
    s_ab_contact *node = NULL;

    if (account == NULL) {
        return false;
    }
    if (account->blockchain_family != FAMILY_TRON) {
        PRINTF("Unsupported blockchain family: %d\n", account->blockchain_family);
        return false;
    }
    if (!derive_tron_address(&account->bip32_path, address)) {
        PRINTF("Key derivation failed\n");
        return false;
    }

    const s_ab_contact *existing = get_address_book_contact(address);
    if (existing != NULL && existing->type == AB_CONTACT_LEDGER_ACCOUNT) {
        PRINTF("Contact already stored, ignoring\n");
        return true;
    }

    if (APP_MEM_PERMANENT((void **) &node, sizeof(*node)) == false) {
        PRINTF("Failed to allocate contact\n");
        return false;
    }
    node->type = AB_CONTACT_LEDGER_ACCOUNT;
    strlcpy(node->contact_name, account->account_name, sizeof(node->contact_name));
    memcpy(node->identifier, address, ADDRESS_SIZE);
    // scope stays empty — Ledger Accounts have no external scope
    ab_contact_list_push(node);
    PRINTF("Stored ledger account '%s'\n", node->contact_name);
    return true;
}

#endif  // HAVE_ADDRESS_BOOK && HAVE_ADDRESS_BOOK_LEDGER_ACCOUNT
