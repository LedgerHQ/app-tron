// handleGetPublicKey(): p1/p2 validation, BIP32-path/key-derivation error
// forwarding, the toAddress cache copy, and the confirm-vs-non-confirm /
// swap-mode branching. helpers.c's own logic is covered by test_helpers.c;
// here it's mocked so this test isolates handleGetPublicKey()'s own branching.

#include <string.h>

#include "unity.h"

#include "Mockhelpers.h"
#include "Mockio.h"
#include "Mockui_review_menu.h"

#include "handlers.h"
#include "ui_globals.h"
#include "app_errors.h"
#include "swap.h"

publicKeyContext_t publicKeyContext;
char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
volatile bool G_called_from_swap;

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
    memset(&publicKeyContext, 0, sizeof(publicKeyContext));
    memset(toAddress, 0, sizeof(toAddress));
    G_called_from_swap = false;
    g_captured_sw = 0;
    io_send_response_buffers_AddCallback(send_sw_cb);
}

void tearDown(void) {
    Mockhelpers_Verify();
    Mockio_Verify();
    Mockui_review_menu_Verify();

    Mockhelpers_Destroy();
    Mockio_Destroy();
    Mockui_review_menu_Destroy();
}

void test_rejects_invalid_p1(void) {
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleGetPublicKey(0x77, P2_NO_CHAINCODE, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_rejects_invalid_p2_chain_bits(void) {
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleGetPublicKey(P1_CONFIRM, 0x02, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_forwards_bip32_path_error(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleGetPublicKey(P1_CONFIRM, P2_NO_CHAINCODE, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_BIP32_PATH, g_captured_sw);
}

void test_forwards_key_derivation_failure(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(1);
    initPublicKeyContext_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleGetPublicKey(P1_CONFIRM, P2_NO_CHAINCODE, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_SECURITY_STATUS_NOT_SATISFIED, g_captured_sw);
}

static int fake_address58_cb(bip32_path_t *path, char *address58, int n) {
    (void) path;
    (void) n;
    strcpy(address58, "TFakeAddress58");
    return 0;
}

void test_non_confirm_forwards_to_send_response_and_caches_toAddress(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(1);
    initPublicKeyContext_AddCallback(fake_address58_cb);
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    helper_send_response_pubkey_ExpectAndReturn(&publicKeyContext, 0x1234);

    int ret = handleGetPublicKey(P1_NON_CONFIRM, P2_NO_CHAINCODE, NULL, 0);

    TEST_ASSERT_EQUAL(0x1234, ret);
    TEST_ASSERT_EQUAL_STRING("TFakeAddress58", toAddress);
}

void test_p2_chaincode_bit_sets_getChaincode(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(1);
    initPublicKeyContext_AddCallback(fake_address58_cb);
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    helper_send_response_pubkey_ExpectAnyArgsAndReturn(0);

    handleGetPublicKey(P1_NON_CONFIRM, P2_CHAINCODE, NULL, 0);

    TEST_ASSERT_TRUE(publicKeyContext.getChaincode);
}

void test_p2_no_chaincode_bit_clears_getChaincode(void) {
    publicKeyContext.getChaincode = true;
    read_bip32_path_ExpectAnyArgsAndReturn(1);
    initPublicKeyContext_AddCallback(fake_address58_cb);
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    helper_send_response_pubkey_ExpectAnyArgsAndReturn(0);

    handleGetPublicKey(P1_NON_CONFIRM, P2_NO_CHAINCODE, NULL, 0);

    TEST_ASSERT_FALSE(publicKeyContext.getChaincode);
}

void test_confirm_triggers_the_address_review_screen(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(1);
    initPublicKeyContext_AddCallback(fake_address58_cb);
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    ux_flow_display_Expect(APPROVAL_VERIFY_ADDRESS, false);

    int ret = handleGetPublicKey(P1_CONFIRM, P2_NO_CHAINCODE, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);
}

void test_confirm_is_refused_when_called_from_swap(void) {
    G_called_from_swap = true;
    read_bip32_path_ExpectAnyArgsAndReturn(1);
    initPublicKeyContext_AddCallback(fake_address58_cb);
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleGetPublicKey(P1_CONFIRM, P2_NO_CHAINCODE, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_SWAP_CHECKING_FAIL, g_captured_sw);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_rejects_invalid_p1);
    RUN_TEST(test_rejects_invalid_p2_chain_bits);
    RUN_TEST(test_forwards_bip32_path_error);
    RUN_TEST(test_forwards_key_derivation_failure);
    RUN_TEST(test_non_confirm_forwards_to_send_response_and_caches_toAddress);
    RUN_TEST(test_p2_chaincode_bit_sets_getChaincode);
    RUN_TEST(test_p2_no_chaincode_bit_clears_getChaincode);
    RUN_TEST(test_confirm_triggers_the_address_review_screen);
    RUN_TEST(test_confirm_is_refused_when_called_from_swap);

    return UNITY_END();
}
