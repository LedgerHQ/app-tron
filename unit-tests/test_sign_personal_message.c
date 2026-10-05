// handleSignPersonalMessage(): S_SIGN_BY_HASH gate, the P1_FIRST/P1_MORE/P1_SIGN
// chunking state machine (personal_msg_ctx is file-static and must persist across
// calls, and be wiped on every error exit), the declared-length vs actual-bytes
// bookkeeping, and the final hash/address/review-screen handoff.
//
// Ordering note: personal_msg_ctx has no reset hook, so
// test_p1_more_without_prior_first_is_rejected must run before any P1_FIRST call
// in this binary (see RUN_TEST order in main()) to observe its true zero-init state.

#include <string.h>

#include "unity.h"

#include "cx.h"
#include "Mocklcx_sha3.h"
#include "Mocklcx_hash.h"
#include "Mockhelpers.h"
#include "Mockio.h"
#include "Mockui_review_menu.h"
#include "Mockledger_assert_internals.h"

#include "handlers.h"
#include "ui_globals.h"
#include "app_errors.h"

#define S_SIGN_BY_HASH 2
uint8_t N_storage_real = (1 << S_SIGN_BY_HASH);

transactionContext_t transactionContext;
txContent_t txContent;
char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];
char fullContract[MAX_TOKEN_LENGTH];

static uint16_t g_captured_sw;

static int send_sw_cb(const buffer_t *rdatalist, size_t count, uint16_t sw, int n) {
    (void) rdatalist;
    (void) count;
    (void) n;
    g_captured_sw = sw;
    return 0;
}

static const uint8_t FAKE_DIGEST[32] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

static cx_err_t hash_cb(cx_hash_t *hash, uint32_t mode, const uint8_t *in, size_t len,
                        uint8_t *out, size_t out_len, int n) {
    (void) hash;
    (void) mode;
    (void) in;
    (void) len;
    (void) n;
    if (out_len == 32) {
        memcpy(out, FAKE_DIGEST, 32);
    }
    return CX_OK;
}

void setUp(void) {
    Mocklcx_sha3_Init();
    Mocklcx_hash_Init();
    Mockhelpers_Init();
    Mockio_Init();
    Mockui_review_menu_Init();
    Mockledger_assert_internals_Init();
    N_storage_real = (1 << S_SIGN_BY_HASH);
    memset(&transactionContext, 0, sizeof(transactionContext));
    memset(&txContent, 0, sizeof(txContent));
    g_captured_sw = 0;
    io_send_response_buffers_AddCallback(send_sw_cb);
    cx_hash_no_throw_AddCallback(hash_cb);
}

void tearDown(void) {
    Mocklcx_sha3_Verify();
    Mocklcx_hash_Verify();
    Mockhelpers_Verify();
    Mockio_Verify();
    Mockui_review_menu_Verify();
    Mockledger_assert_internals_Verify();

    Mocklcx_sha3_Destroy();
    Mocklcx_hash_Destroy();
    Mockhelpers_Destroy();
    Mockio_Destroy();
    Mockui_review_menu_Destroy();
    Mockledger_assert_internals_Destroy();
}

// Builds a P1_FIRST/P1_SIGN payload: bip32-path-consumed-bytes placeholder (the
// mocked read_bip32_path reports how many it "consumed") + 4-byte BE message
// length + message bytes.
static size_t build_first_chunk(uint8_t *out, uint32_t declared_len, const uint8_t *msg,
                                size_t msg_len) {
    size_t off = 0;
    out[off++] = (uint8_t) (declared_len >> 24);
    out[off++] = (uint8_t) (declared_len >> 16);
    out[off++] = (uint8_t) (declared_len >> 8);
    out[off++] = (uint8_t) declared_len;
    memcpy(out + off, msg, msg_len);
    off += msg_len;
    return off;
}

void test_p1_more_without_prior_first_is_rejected(void) {
    uint8_t buf[1] = {0};
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignPersonalMessage(P1_MORE, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_rejects_when_sign_by_hash_setting_is_disabled(void) {
    N_storage_real = 0;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSignPersonalMessage(P1_FIRST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_MISSING_SETTING_SIGN_BY_HASH, g_captured_sw);
}

void test_forwards_bip32_path_error(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSignPersonalMessage(P1_FIRST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_BIP32_PATH, g_captured_sw);
}

void test_rejects_declared_length_field_shorter_than_4_bytes(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(0);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    uint8_t buf[3] = {0};
    handleSignPersonalMessage(P1_FIRST, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_LENGTH, g_captured_sw);
}

void test_rejects_wrong_p2_after_wasting_the_header_hash(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(0);
    cx_keccak_init_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // magic
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // declared-length string
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    uint8_t buf[4];
    size_t len = build_first_chunk(buf, 5, (const uint8_t *) "", 0);
    handleSignPersonalMessage(P1_FIRST, 1, buf, len);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);

    // Unlike the bip32-path/length-check error paths, a p2 rejection does NOT
    // wipe personal_msg_ctx (no explicit_bzero on this branch): the hash state
    // and the declared dataBytes(5) from this aborted attempt are still live.
    // Not a security issue (nothing sensitive in a Keccak sponge over the
    // attacker's own declared length), but worth pinning down: a bare P1_MORE
    // is accepted right after, continuing the leftover state instead of being
    // rejected.
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSignPersonalMessage(P1_MORE, 0, buf, 0);
    TEST_ASSERT_EQUAL_HEX16(E_OK, g_captured_sw);
}

void test_rejects_a_first_chunk_longer_than_its_own_declared_length(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(0);
    cx_keccak_init_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // magic
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // declared-length string
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    const uint8_t msg[] = "too long for the declared length";
    uint8_t buf[64];
    size_t len = build_first_chunk(buf, 3, msg, sizeof(msg) - 1);  // declares only 3 bytes

    handleSignPersonalMessage(P1_FIRST, 0, buf, len);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_LENGTH, g_captured_sw);
}

void test_single_chunk_message_completes_immediately(void) {
    const uint8_t msg[] = "hello";
    uint8_t buf[64];
    size_t len = build_first_chunk(buf, sizeof(msg) - 1, msg, sizeof(msg) - 1);

    read_bip32_path_ExpectAnyArgsAndReturn(0);
    cx_keccak_init_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // magic
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // declared-length string
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // message bytes
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // CX_LAST finalize
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    ux_flow_display_Expect(APPROVAL_SIGN_PERSONAL_MESSAGE, false);

    int ret = handleSignPersonalMessage(P1_FIRST, 0, buf, len);

    TEST_ASSERT_EQUAL(0, ret);
    TEST_ASSERT_EQUAL_MEMORY(FAKE_DIGEST, transactionContext.hash, 32);
}

void test_message_split_across_first_and_more_chunks(void) {
    const uint8_t part1[] = "hello ";
    const uint8_t part2[] = "world";
    uint32_t total_len = (uint32_t) (sizeof(part1) - 1 + sizeof(part2) - 1);

    uint8_t buf1[64];
    size_t len1 = build_first_chunk(buf1, total_len, part1, sizeof(part1) - 1);

    read_bip32_path_ExpectAnyArgsAndReturn(0);
    cx_keccak_init_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // magic
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // declared-length string
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // part1 bytes
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    int ret1 = handleSignPersonalMessage(P1_FIRST, 0, buf1, len1);
    TEST_ASSERT_EQUAL(0, ret1);
    TEST_ASSERT_EQUAL_HEX16(E_OK, g_captured_sw);

    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // part2 bytes
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // CX_LAST finalize
    initPublicKeyContext_ExpectAnyArgsAndReturn(0);
    ux_flow_display_Expect(APPROVAL_SIGN_PERSONAL_MESSAGE, false);

    int ret2 = handleSignPersonalMessage(P1_MORE, 0, (uint8_t *) part2, sizeof(part2) - 1);
    TEST_ASSERT_EQUAL(0, ret2);
    TEST_ASSERT_EQUAL_MEMORY(FAKE_DIGEST, transactionContext.hash, 32);
}

void test_forwards_key_derivation_failure_on_the_finishing_chunk(void) {
    const uint8_t msg[] = "hi";
    uint8_t buf[64];
    size_t len = build_first_chunk(buf, sizeof(msg) - 1, msg, sizeof(msg) - 1);

    read_bip32_path_ExpectAnyArgsAndReturn(0);
    cx_keccak_init_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // magic
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // declared-length string
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // message bytes
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);  // CX_LAST finalize
    initPublicKeyContext_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSignPersonalMessage(P1_FIRST, 0, buf, len);
    TEST_ASSERT_EQUAL_HEX16(E_SECURITY_STATUS_NOT_SATISFIED, g_captured_sw);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_p1_more_without_prior_first_is_rejected);
    RUN_TEST(test_rejects_when_sign_by_hash_setting_is_disabled);
    RUN_TEST(test_forwards_bip32_path_error);
    RUN_TEST(test_rejects_declared_length_field_shorter_than_4_bytes);
    RUN_TEST(test_rejects_wrong_p2_after_wasting_the_header_hash);
    RUN_TEST(test_rejects_a_first_chunk_longer_than_its_own_declared_length);
    RUN_TEST(test_single_chunk_message_completes_immediately);
    RUN_TEST(test_message_split_across_first_and_more_chunks);
    RUN_TEST(test_forwards_key_derivation_failure_on_the_finishing_chunk);

    return UNITY_END();
}
