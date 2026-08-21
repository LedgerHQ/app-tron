// apdu_dispatcher(): CLA check, the g_review_pending anti-reentrancy lock, INS ->
// handler routing (forwarding p1/p2/data/lc and the handler's return value
// verbatim), the swap-mode INS allowlist, and the per-command contact reset.

#include <string.h>

#include "unity.h"

#include "Mockhandlers.h"
#include "Mockio.h"

#include "handlers.h"
#include "dispatcher.h"
#include "ui_globals.h"
#include "swap.h"
#include "app_errors.h"

bool g_review_pending;
const s_ab_contact *g_recipient_contact;
const s_ab_contact *g_sender_contact;
const char *g_recipient_service;
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
    Mockhandlers_Init();
    Mockio_Init();
    g_review_pending = false;
    g_recipient_contact = (const s_ab_contact *) 0x1234;
    g_sender_contact = (const s_ab_contact *) 0x1234;
    g_recipient_service = "stale";
    G_called_from_swap = false;
    g_captured_sw = 0;
    io_send_response_buffers_AddCallback(send_sw_cb);
}

void tearDown(void) {
    Mockhandlers_Verify();
    Mockio_Verify();

    Mockhandlers_Destroy();
    Mockio_Destroy();
}

void test_wrong_cla_is_rejected_without_dispatching(void) {
    uint8_t data[1] = {0};
    command_t cmd = {.cla = 0xFF, .ins = INS_GET_PUBLIC_KEY, .p1 = 0, .p2 = 0, .data = data, .lc = 1};

    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    apdu_dispatcher(&cmd);

    TEST_ASSERT_EQUAL_HEX16(E_CLA_NOT_SUPPORTED, g_captured_sw);
}

void test_review_pending_rejects_a_new_command(void) {
    g_review_pending = true;
    uint8_t data[1] = {0};
    command_t cmd = {.cla = CLA, .ins = INS_GET_PUBLIC_KEY, .p1 = 0, .p2 = 0, .data = data, .lc = 1};

    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    apdu_dispatcher(&cmd);

    TEST_ASSERT_EQUAL_HEX16(E_CONDITIONS_OF_USE_NOT_SATISFIED, g_captured_sw);
}

void test_get_public_key_is_routed_with_its_arguments_and_return_value(void) {
    uint8_t data[3] = {0xAA, 0xBB, 0xCC};
    command_t cmd = {.cla = CLA, .ins = INS_GET_PUBLIC_KEY, .p1 = 1, .p2 = 2, .data = data, .lc = 3};

    handleGetPublicKey_ExpectAndReturn(1, 2, data, 3, 0x4242);

    TEST_ASSERT_EQUAL(0x4242, apdu_dispatcher(&cmd));
}

void test_sign_is_routed_with_its_arguments_and_return_value(void) {
    uint8_t data[2] = {0x01, 0x02};
    command_t cmd = {.cla = CLA, .ins = INS_SIGN, .p1 = 0x90, .p2 = 0, .data = data, .lc = 2};

    handleSign_ExpectAndReturn(0x90, 0, data, 2, 0x4343);

    TEST_ASSERT_EQUAL(0x4343, apdu_dispatcher(&cmd));
}

void test_sign_txn_hash_is_routed(void) {
    uint8_t data[1] = {0};
    command_t cmd = {.cla = CLA, .ins = INS_SIGN_TXN_HASH, .p1 = 0, .p2 = 0, .data = data, .lc = 1};

    handleSignByHash_ExpectAndReturn(0, 0, data, 1, 7);

    TEST_ASSERT_EQUAL(7, apdu_dispatcher(&cmd));
}

void test_get_app_configuration_is_routed(void) {
    uint8_t data[1] = {0};
    command_t cmd = {
        .cla = CLA, .ins = INS_GET_APP_CONFIGURATION, .p1 = 0, .p2 = 0, .data = data, .lc = 0};

    handleGetAppConfiguration_ExpectAndReturn(0, 0, data, 0, 8);

    TEST_ASSERT_EQUAL(8, apdu_dispatcher(&cmd));
}

void test_get_ecdh_secret_is_routed(void) {
    uint8_t data[1] = {0};
    command_t cmd = {.cla = CLA, .ins = INS_GET_ECDH_SECRET, .p1 = 0, .p2 = 1, .data = data, .lc = 1};

    handleECDHSecret_ExpectAndReturn(0, 1, data, 1, 9);

    TEST_ASSERT_EQUAL(9, apdu_dispatcher(&cmd));
}

void test_sign_personal_message_is_routed(void) {
    uint8_t data[1] = {0};
    command_t cmd = {
        .cla = CLA, .ins = INS_SIGN_PERSONAL_MESSAGE, .p1 = 0, .p2 = 0, .data = data, .lc = 1};

    handleSignPersonalMessage_ExpectAndReturn(0, 0, data, 1, 10);

    TEST_ASSERT_EQUAL(10, apdu_dispatcher(&cmd));
}

void test_sign_tip712_message_is_routed(void) {
    uint8_t data[1] = {0};
    command_t cmd = {
        .cla = CLA, .ins = INS_SIGN_TIP_712_MESSAGE, .p1 = 0, .p2 = 0, .data = data, .lc = 1};

    handleSignTIP712Message_ExpectAndReturn(0, 0, data, 1, 11);

    TEST_ASSERT_EQUAL(11, apdu_dispatcher(&cmd));
}

void test_unknown_ins_is_rejected(void) {
    uint8_t data[1] = {0};
    command_t cmd = {.cla = CLA, .ins = 0x99, .p1 = 0, .p2 = 0, .data = data, .lc = 1};

    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    apdu_dispatcher(&cmd);

    TEST_ASSERT_EQUAL_HEX16(E_INS_NOT_SUPPORTED, g_captured_sw);
}

void test_swap_mode_rejects_ins_outside_the_allowlist(void) {
    G_called_from_swap = true;
    uint8_t data[1] = {0};
    command_t cmd = {
        .cla = CLA, .ins = INS_SIGN_PERSONAL_MESSAGE, .p1 = 0, .p2 = 0, .data = data, .lc = 1};

    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    apdu_dispatcher(&cmd);

    TEST_ASSERT_EQUAL_HEX16(E_SWAP_CHECKING_FAIL, g_captured_sw);
}

void test_swap_mode_allows_get_public_key_even_with_review_pending(void) {
    G_called_from_swap = true;
    g_review_pending = true;  // the reentrancy lock is bypassed while in swap mode
    uint8_t data[1] = {0};
    command_t cmd = {.cla = CLA, .ins = INS_GET_PUBLIC_KEY, .p1 = 0, .p2 = 0, .data = data, .lc = 1};

    handleGetPublicKey_ExpectAndReturn(0, 0, data, 1, 0);

    TEST_ASSERT_EQUAL(0, apdu_dispatcher(&cmd));
}

static int capture_contacts_and_return(uint8_t p1, uint8_t p2, uint8_t *data, uint16_t lc, int n) {
    (void) p1;
    (void) p2;
    (void) data;
    (void) lc;
    (void) n;
    TEST_ASSERT_NULL(g_recipient_contact);
    TEST_ASSERT_NULL(g_sender_contact);
    TEST_ASSERT_NULL(g_recipient_service);
    return 0;
}

void test_a_new_command_resets_stale_contact_pointers_before_dispatch(void) {
    uint8_t data[1] = {0};
    command_t cmd = {.cla = CLA, .ins = INS_GET_PUBLIC_KEY, .p1 = 0, .p2 = 0, .data = data, .lc = 1};

    handleGetPublicKey_AddCallback(capture_contacts_and_return);
    handleGetPublicKey_ExpectAndReturn(0, 0, data, 1, 0);

    apdu_dispatcher(&cmd);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_wrong_cla_is_rejected_without_dispatching);
    RUN_TEST(test_review_pending_rejects_a_new_command);
    RUN_TEST(test_get_public_key_is_routed_with_its_arguments_and_return_value);
    RUN_TEST(test_sign_is_routed_with_its_arguments_and_return_value);
    RUN_TEST(test_sign_txn_hash_is_routed);
    RUN_TEST(test_get_app_configuration_is_routed);
    RUN_TEST(test_get_ecdh_secret_is_routed);
    RUN_TEST(test_sign_personal_message_is_routed);
    RUN_TEST(test_sign_tip712_message_is_routed);
    RUN_TEST(test_unknown_ins_is_rejected);
    RUN_TEST(test_swap_mode_rejects_ins_outside_the_allowlist);
    RUN_TEST(test_swap_mode_allows_get_public_key_even_with_review_pending);
    RUN_TEST(test_a_new_command_resets_stale_contact_pointers_before_dispatch);

    return UNITY_END();
}
