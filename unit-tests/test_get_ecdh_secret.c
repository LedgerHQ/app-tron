// handleECDHSecret(): fixed p1/p2, BIP32-path consumption, the exact-65-byte
// peer-pubkey length check, key-derivation error forwarding, and the final
// signature-buffer-as-scratch copy + base58 display address + review screen.

#include <string.h>

#include "unity.h"

#include "Mockhelpers.h"
#include "Mockio.h"
#include "Mockui_review_menu.h"

#include "handlers.h"
#include "ui_globals.h"
#include "app_errors.h"

transactionContext_t transactionContext;
char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];
char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];

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
    memset(&transactionContext, 0, sizeof(transactionContext));
    memset(fromAddress, 0, sizeof(fromAddress));
    memset(toAddress, 0, sizeof(toAddress));
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

void test_rejects_wrong_p1_p2(void) {
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleECDHSecret(0x01, 0x01, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);

    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleECDHSecret(0x00, 0x00, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_forwards_bip32_path_error(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleECDHSecret(0x00, 0x01, NULL, 70);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_BIP32_PATH, g_captured_sw);
}

void test_rejects_peer_pubkey_of_the_wrong_length(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(10);  // consumes 10 of 70 -> 60 left, not 65
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    uint8_t buf[70] = {0};
    handleECDHSecret(0x00, 0x01, buf, 70);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_LENGTH, g_captured_sw);
}

void test_forwards_key_derivation_failure(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(5);  // consumes 5 of 70 -> 65 left
    initPublicKeyContext_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    uint8_t buf[70] = {0};
    handleECDHSecret(0x00, 0x01, buf, 70);
    TEST_ASSERT_EQUAL_HEX16(E_SECURITY_STATUS_NOT_SATISFIED, g_captured_sw);
}

void test_success_stashes_peer_pubkey_and_displays_review(void) {
    uint8_t buf[70];
    for (int i = 0; i < 70; i++) {
        buf[i] = (uint8_t) i;
    }

    read_bip32_path_ExpectAnyArgsAndReturn(5);  // consumes 5 of 70 -> 65 (peer pubkey) left
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    getBase58FromPublicKey_ExpectAnyArgs();
    ux_flow_display_Expect(APPROVAL_SHARED_ECDH_SECRET, false);

    int ret = handleECDHSecret(0x00, 0x01, buf, 70);

    TEST_ASSERT_EQUAL(0, ret);
    TEST_ASSERT_EQUAL_MEMORY(buf + 5, transactionContext.signature, PUBLIC_KEY_SIZE);
}

static off_t path_b_cb(const uint8_t *buffer, size_t length, bip32_path_t *path, int n) {
    (void) buffer;
    (void) length;
    (void) n;
    path->length = 1;
    path->indices[0] = 0xB;
    return 5;
}

void test_malformed_request_keeps_the_signing_path(void) {
    transactionContext.bip32_path.length = 1;
    transactionContext.bip32_path.indices[0] = 0xA;
    read_bip32_path_Stub(path_b_cb);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    uint8_t buf[5] = {0};
    handleECDHSecret(0x00, 0x01, buf, sizeof(buf));

    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_LENGTH, g_captured_sw);
    TEST_ASSERT_EQUAL_HEX32(0xA, transactionContext.bip32_path.indices[0]);
}

void test_valid_request_commits_its_path(void) {
    read_bip32_path_Stub(path_b_cb);
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    getBase58FromPublicKey_ExpectAnyArgs();
    ux_flow_display_Expect(APPROVAL_SHARED_ECDH_SECRET, false);

    uint8_t buf[5 + PUBLIC_KEY_SIZE] = {0};
    handleECDHSecret(0x00, 0x01, buf, sizeof(buf));

    TEST_ASSERT_EQUAL_HEX32(0xB, transactionContext.bip32_path.indices[0]);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_rejects_wrong_p1_p2);
    RUN_TEST(test_forwards_bip32_path_error);
    RUN_TEST(test_rejects_peer_pubkey_of_the_wrong_length);
    RUN_TEST(test_forwards_key_derivation_failure);
    RUN_TEST(test_success_stashes_peer_pubkey_and_displays_review);
    RUN_TEST(test_malformed_request_keeps_the_signing_path);
    RUN_TEST(test_valid_request_commits_its_path);

    return UNITY_END();
}
