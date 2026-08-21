// handleSignByHash(): fixed p1/p2, the S_SIGN_BY_HASH settings gate (this *is*
// Tron's blind-signing path — must stay opt-in), BIP32/key-derivation error
// forwarding, the exact-HASH_SIZE length check, and the final hash stash +
// display prep + review screen.

#include <string.h>

#include "unity.h"

#include "Mockhelpers.h"
#include "Mockio.h"
#include "Mockui_review_menu.h"
#include "Mockparse.h"

#include "handlers.h"
#include "ui_globals.h"
#include "app_errors.h"

// Mirrors settings.h's N_storage_real/S_SIGN_BY_HASH without its `const`
// qualifier (see [[phase1-unit-tests]] Phase 2 notes) so tests can flip it.
#define S_SIGN_BY_HASH 2
uint8_t N_storage_real = 0;

transactionContext_t transactionContext;
char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];
char fullHash[HASH_SIZE * 2 + 1];
char fullContract[MAX_TOKEN_LENGTH];

static uint16_t g_captured_sw;

static int send_sw_cb(const buffer_t *rdatalist, size_t count, uint16_t sw, int n) {
    (void) rdatalist;
    (void) count;
    (void) n;
    g_captured_sw = sw;
    return 0;
}

void setUp(void) {
    Mockhelpers_Init();
    Mockio_Init();
    Mockui_review_menu_Init();
    Mockparse_Init();
    memset(&transactionContext, 0, sizeof(transactionContext));
    N_storage_real = (1 << S_SIGN_BY_HASH);
    g_captured_sw = 0;
    io_send_response_buffers_AddCallback(send_sw_cb);
}

void tearDown(void) {
    Mockhelpers_Verify();
    Mockio_Verify();
    Mockui_review_menu_Verify();
    Mockparse_Verify();

    Mockhelpers_Destroy();
    Mockio_Destroy();
    Mockui_review_menu_Destroy();
    Mockparse_Destroy();
}

void test_rejects_wrong_p1_p2(void) {
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignByHash(0x01, 0x00, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_rejects_when_sign_by_hash_setting_is_disabled(void) {
    N_storage_real = 0;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSignByHash(0x00, 0x00, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_MISSING_SETTING_SIGN_BY_HASH, g_captured_sw);
}

void test_forwards_bip32_path_error(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSignByHash(0x00, 0x00, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_BIP32_PATH, g_captured_sw);
}

void test_forwards_key_derivation_failure(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(5);
    initPublicKeyContext_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    uint8_t buf[5 + HASH_SIZE] = {0};
    handleSignByHash(0x00, 0x00, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_HEX16(E_SECURITY_STATUS_NOT_SATISFIED, g_captured_sw);
}

void test_rejects_hash_of_the_wrong_length(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(5);
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    uint8_t buf[5 + HASH_SIZE - 1] = {0};  // one byte short of a full hash
    handleSignByHash(0x00, 0x00, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_LENGTH, g_captured_sw);
}

void test_success_stashes_hash_and_displays_review(void) {
    uint8_t buf[5 + HASH_SIZE];
    memset(buf, 0, 5);
    for (int i = 0; i < HASH_SIZE; i++) {
        buf[5 + i] = (uint8_t) (i + 1);
    }

    read_bip32_path_ExpectAnyArgsAndReturn(5);
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    setContractType_ExpectAnyArgsAndReturn(true);
    ux_flow_display_Expect(APPROVAL_SIMPLE_TRANSACTION, false);

    int ret = handleSignByHash(0x00, 0x00, buf, sizeof(buf));

    TEST_ASSERT_EQUAL(0, ret);
    TEST_ASSERT_EQUAL_MEMORY(buf + 5, transactionContext.hash, HASH_SIZE);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_rejects_wrong_p1_p2);
    RUN_TEST(test_rejects_when_sign_by_hash_setting_is_disabled);
    RUN_TEST(test_forwards_bip32_path_error);
    RUN_TEST(test_forwards_key_derivation_failure);
    RUN_TEST(test_rejects_hash_of_the_wrong_length);
    RUN_TEST(test_success_stashes_hash_and_displays_review);

    return UNITY_END();
}
