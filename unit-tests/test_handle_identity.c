#include <string.h>

#include "unity.h"

#include "Mockhandle_contacts.h"
#include "Mockhelpers.h"
#include "Mockui_idle_menu.h"
#include "Mockapp_mem_utils.h"

#include "address_book_entrypoints.h"

static void make_identity(identity_t *id, uint8_t prefix, uint8_t len, blockchain_family_e family) {
    memset(id, 0, sizeof(*id));
    id->blockchain_family = family;
    id->identifier_len = len;
    memset(id->identifier, 0x11, len);
    id->identifier[0] = prefix;
}

static void make_edit_scope(edit_scope_t *edit,
                            uint8_t prefix,
                            uint8_t len,
                            blockchain_family_e family) {
    memset(edit, 0, sizeof(*edit));
    make_identity(&edit->identity, prefix, len, family);
    strlcpy(edit->old_scope, "Trx Address 1", sizeof(edit->old_scope));
    strlcpy(edit->identity.scope, "Trx Savings", sizeof(edit->identity.scope));
}

void setUp(void) {
    Mockhandle_contacts_Init();
    Mockhelpers_Init();
    Mockui_idle_menu_Init();
    Mockapp_mem_utils_Init();
}

void tearDown(void) {
    Mockhandle_contacts_Verify();
    Mockhelpers_Verify();
    Mockui_idle_menu_Verify();
    Mockapp_mem_utils_Verify();

    Mockhandle_contacts_Destroy();
    Mockhelpers_Destroy();
    Mockui_idle_menu_Destroy();
    Mockapp_mem_utils_Destroy();
}

void test_edit_scope_updates_cache_for_tron_address(void) {
    edit_scope_t edit;
    make_edit_scope(&edit, ADD_PRE_FIX_BYTE_MAINNET, ADDRESS_SIZE, FAMILY_TRON);

    update_contact_scope_Expect(edit.identity.gid,
                                edit.identity.identifier,
                                edit.old_scope,
                                edit.identity.scope);
    on_edit_scope_applied(&edit);
}

void test_edit_scope_ignores_wrong_address_prefix(void) {
    edit_scope_t edit;
    make_edit_scope(&edit, 0x42, ADDRESS_SIZE, FAMILY_TRON);
    on_edit_scope_applied(&edit);
}

void test_edit_scope_ignores_wrong_address_length(void) {
    edit_scope_t edit;
    make_edit_scope(&edit, ADD_PRE_FIX_BYTE_MAINNET, ADDRESS_SIZE - 1, FAMILY_TRON);
    on_edit_scope_applied(&edit);
}

void test_edit_scope_ignores_non_tron_family(void) {
    edit_scope_t edit;
    make_edit_scope(&edit, ADD_PRE_FIX_BYTE_MAINNET, ADDRESS_SIZE, FAMILY_ETHEREUM);
    on_edit_scope_applied(&edit);
}

void test_register_identity_rejects_wrong_address_prefix(void) {
    identity_t id;
    make_identity(&id, 0x42, ADDRESS_SIZE, FAMILY_TRON);
    TEST_ASSERT_FALSE(handle_check_register_identity(&id));
}

void test_provide_identity_rejects_wrong_address_prefix(void) {
    identity_t id;
    make_identity(&id, 0x42, ADDRESS_SIZE, FAMILY_TRON);
    TEST_ASSERT_FALSE(handle_provide_identity(&id));
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_edit_scope_updates_cache_for_tron_address);
    RUN_TEST(test_edit_scope_ignores_wrong_address_prefix);
    RUN_TEST(test_edit_scope_ignores_wrong_address_length);
    RUN_TEST(test_edit_scope_ignores_non_tron_family);
    RUN_TEST(test_register_identity_rejects_wrong_address_prefix);
    RUN_TEST(test_provide_identity_rejects_wrong_address_prefix);

    return UNITY_END();
}
