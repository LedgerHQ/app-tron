// handleSignTIP712Message(): S_SIGN_BY_HASH gate, its own inline BIP32-path
// decode (distinct from helpers.c's read_bip32_path — same Tron-subtree
// restriction re-implemented here, worth checking independently), the fixed
// 64-byte domainHash||messageHash tail, and the address-book sender lookup.

#include <string.h>

#include "unity.h"

#include "Mockhelpers.h"
#include "Mockio.h"
#include "Mockui_review_menu.h"
#include "Mockhandle_contacts.h"

#include "handlers.h"
#include "ui_globals.h"
#include "app_errors.h"

#define S_SIGN_BY_HASH 2
uint8_t N_storage_real = (1 << S_SIGN_BY_HASH);

messageSigningContext712_t messageSigningContext712;
char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];
publicKeyContext_t publicKeyContext;
const s_ab_contact *g_sender_contact;

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
    Mockhandle_contacts_Init();
    N_storage_real = (1 << S_SIGN_BY_HASH);
    memset(&messageSigningContext712, 0, sizeof(messageSigningContext712));
    memset(&publicKeyContext, 0, sizeof(publicKeyContext));
    g_sender_contact = NULL;
    g_captured_sw = 0;
    io_send_response_buffers_AddCallback(send_sw_cb);
}

void tearDown(void) {
    Mockhelpers_Verify();
    Mockio_Verify();
    Mockui_review_menu_Verify();
    Mockhandle_contacts_Verify();

    Mockhelpers_Destroy();
    Mockio_Destroy();
    Mockui_review_menu_Destroy();
    Mockhandle_contacts_Destroy();
}

// [pathLength][4*pathLength BE indices][32-byte domainHash][32-byte messageHash]
static size_t build_payload(uint8_t *out, const uint32_t *path, uint8_t path_len,
                            const uint8_t *domain_hash, const uint8_t *message_hash) {
    size_t off = 0;
    out[off++] = path_len;
    for (uint8_t i = 0; i < path_len; i++) {
        out[off++] = (uint8_t) (path[i] >> 24);
        out[off++] = (uint8_t) (path[i] >> 16);
        out[off++] = (uint8_t) (path[i] >> 8);
        out[off++] = (uint8_t) path[i];
    }
    memcpy(out + off, domain_hash, 32);
    off += 32;
    memcpy(out + off, message_hash, 32);
    off += 32;
    return off;
}

static const uint32_t VALID_PATH[3] = {TRON_BIP32_PREFIX_0, TRON_BIP32_PREFIX_1, 0};
static const uint8_t DOMAIN_HASH[32] = {0x01, 0x02, 0x03};
static const uint8_t MESSAGE_HASH[32] = {0xAA, 0xBB, 0xCC};

void test_rejects_when_sign_by_hash_setting_is_disabled(void) {
    N_storage_real = 0;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignTIP712Message(0, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_MISSING_SETTING_SIGN_BY_HASH, g_captured_sw);
}

void test_rejects_wrong_p1_p2(void) {
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignTIP712Message(1, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_rejects_empty_payload(void) {
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignTIP712Message(0, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_rejects_zero_path_length(void) {
    uint8_t buf[1] = {0};
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignTIP712Message(0, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_rejects_path_length_above_max(void) {
    uint8_t buf[1] = {MAX_BIP32_PATH + 1};
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignTIP712Message(0, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_rejects_truncated_path_indices(void) {
    uint8_t buf[1 + 3] = {2, 0x80, 0x00, 0x00};  // claims 2 indices, only 3 bytes follow
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignTIP712Message(0, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_rejects_path_length_of_one(void) {
    uint32_t path[1] = {TRON_BIP32_PREFIX_0};
    uint8_t buf[1 + 4 + 64];
    size_t len = build_payload(buf, path, 1, DOMAIN_HASH, MESSAGE_HASH);

    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignTIP712Message(0, 0, buf, len);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_rejects_path_outside_tron_subtree(void) {
    uint32_t path[2] = {0x8000002C, 0x80000001};  // 44'/1' — not Tron's 195'
    uint8_t buf[1 + 8 + 64];
    size_t len = build_payload(buf, path, 2, DOMAIN_HASH, MESSAGE_HASH);

    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignTIP712Message(0, 0, buf, len);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_rejects_truncated_hash_tail(void) {
    uint8_t buf[1 + 8 + 63];  // one byte short of the 64-byte domain+message hash
    size_t len = build_payload(buf, VALID_PATH, 2, DOMAIN_HASH, MESSAGE_HASH) - 1;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignTIP712Message(0, 0, buf, len);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_forwards_key_derivation_failure(void) {
    uint8_t buf[1 + 8 + 64];
    size_t len = build_payload(buf, VALID_PATH, 2, DOMAIN_HASH, MESSAGE_HASH);

    initPublicKeyContext_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSignTIP712Message(0, 0, buf, len);
    TEST_ASSERT_EQUAL_HEX16(E_SECURITY_STATUS_NOT_SATISFIED, g_captured_sw);
}

void test_success_captures_hashes_and_resolves_sender_contact(void) {
    uint32_t path[3] = {TRON_BIP32_PREFIX_0, TRON_BIP32_PREFIX_1, 7};
    uint8_t buf[1 + 12 + 64];
    size_t len = build_payload(buf, path, 3, DOMAIN_HASH, MESSAGE_HASH);

    static const s_ab_contact FAKE_CONTACT;

    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    getAddressFromPublicKey_ExpectAnyArgs();
    get_address_book_contact_ExpectAnyArgsAndReturn(&FAKE_CONTACT);
    ux_flow_display_Expect(APPROVAL_SIGN_TIP72_TRANSACTION, false);

    int ret = handleSignTIP712Message(0, 0, buf, len);

    TEST_ASSERT_EQUAL(0, ret);
    TEST_ASSERT_EQUAL(3, messageSigningContext712.pathLength);
    TEST_ASSERT_EQUAL_UINT32(7, messageSigningContext712.bip32Path[2]);
    TEST_ASSERT_EQUAL_MEMORY(DOMAIN_HASH, messageSigningContext712.domainHash, 32);
    TEST_ASSERT_EQUAL_MEMORY(MESSAGE_HASH, messageSigningContext712.messageHash, 32);
    TEST_ASSERT_EQUAL_PTR(&FAKE_CONTACT, g_sender_contact);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_rejects_when_sign_by_hash_setting_is_disabled);
    RUN_TEST(test_rejects_wrong_p1_p2);
    RUN_TEST(test_rejects_empty_payload);
    RUN_TEST(test_rejects_zero_path_length);
    RUN_TEST(test_rejects_path_length_above_max);
    RUN_TEST(test_rejects_truncated_path_indices);
    RUN_TEST(test_rejects_path_length_of_one);
    RUN_TEST(test_rejects_path_outside_tron_subtree);
    RUN_TEST(test_rejects_truncated_hash_tail);
    RUN_TEST(test_forwards_key_derivation_failure);
    RUN_TEST(test_success_captures_hashes_and_resolves_sender_contact);

    return UNITY_END();
}
