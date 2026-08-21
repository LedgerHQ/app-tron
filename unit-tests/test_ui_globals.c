// The UI approval callbacks: the last code that runs after the user approves
// a review screen, so this is where an actual signature gets produced and
// sent. format_signature_out() (DER r/s -> raw 64-byte r||s, incl. the
// 33-byte-leading-zero-padding case) is pure logic and gets independently
// derived byte-exact test vectors; the rest mock the crypto/IO calls.

#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "cx.h"
#include "Mockhelpers.h"
#include "Mockio.h"
#include "Mockui_idle_menu.h"
#include "Mockcrypto_helpers.h"
#include "Mocklcx_ecdh.h"
#include "Mocklcx_sha3.h"
#include "Mocklcx_hash.h"
#include "Mocklcx_ecdsa.h"

#include "ui_globals.h"
#include "app_errors.h"

unsigned char G_io_tx_buffer[OS_IO_BUFFER_SIZE + 1];

void io_seproxyhal_io_heartbeat(void) {
}

// io_exchange() is declared separately from io.h (os_io_legacy.h, which also
// pulls in bagl_element_t/NFC callback types CMock can't resolve here) — a
// plain override is simpler than mocking that whole header for one call.
unsigned short io_exchange(unsigned char channel_and_flags, unsigned short tx_len) {
    (void) channel_and_flags;
    (void) tx_len;
    return 0;
}

// cx_ecdomain_parameters_length() lives in ox_ec.h, a header CMock can't parse
// (a real parser bug on its cx_ecpoint_* declarations, unrelated to this
// function) — a plain deterministic override stands in for it. Only the
// success value (secp256k1's 32-byte parameter size) is exercised by any test
// here; its own failure path is a hardware-only branch, not data-driven.
cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length) {
    (void) cv;
    *length = 32;
    return CX_OK;
}

void format_signature_out(const uint8_t *signature);

static uint16_t g_captured_sw;
static uint8_t g_captured_resp[300];
static size_t g_captured_size;

static int send_cb(const buffer_t *rdatalist, size_t count, uint16_t sw, int n) {
    (void) count;
    (void) n;
    g_captured_sw = sw;
    if (rdatalist != NULL && rdatalist->ptr != NULL) {
        g_captured_size = rdatalist->size;
        memcpy(g_captured_resp, rdatalist->ptr, rdatalist->size);
    } else {
        g_captured_size = 0;
    }
    return 0;
}

void setUp(void) {
    Mockhelpers_Init();
    Mockio_Init();
    Mockui_idle_menu_Init();
    Mockcrypto_helpers_Init();
    Mocklcx_ecdh_Init();
    Mocklcx_sha3_Init();
    Mocklcx_hash_Init();
    Mocklcx_ecdsa_Init();

    memset(&transactionContext, 0, sizeof(transactionContext));
    memset(&publicKeyContext, 0, sizeof(publicKeyContext));
    memset(&messageSigningContext712, 0, sizeof(messageSigningContext712));
    g_review_pending = true;
    g_captured_sw = 0;
    g_captured_size = 0;
    memset(g_captured_resp, 0, sizeof(g_captured_resp));

    io_send_response_buffers_AddCallback(send_cb);
}

void tearDown(void) {
    Mockhelpers_Verify();
    Mockio_Verify();
    Mockui_idle_menu_Verify();
    Mockcrypto_helpers_Verify();
    Mocklcx_ecdh_Verify();
    Mocklcx_sha3_Verify();
    Mocklcx_hash_Verify();
    Mocklcx_ecdsa_Verify();

    Mockhelpers_Destroy();
    Mockio_Destroy();
    Mockui_idle_menu_Destroy();
    Mockcrypto_helpers_Destroy();
    Mocklcx_ecdh_Destroy();
    Mocklcx_sha3_Destroy();
    Mocklcx_hash_Destroy();
    Mocklcx_ecdsa_Destroy();
}

// --- ui_callback_address_ok ---

void test_address_ok_sends_pubkey_and_clears_review_pending(void) {
    helper_send_response_pubkey_ExpectAnyArgsAndReturn(0);

    bool ret = ui_callback_address_ok(false);

    TEST_ASSERT_TRUE(ret);
    TEST_ASSERT_FALSE(g_review_pending);
}

void test_address_ok_redisplays_idle_menu_when_asked(void) {
    helper_send_response_pubkey_ExpectAnyArgsAndReturn(0);
    ui_idle_Expect();

    ui_callback_address_ok(true);
}

// --- ui_callback_tx_ok / ui_callback_signMessage_ok (identical logic) ---

void test_tx_ok_sends_signature_on_success(void) {
    transactionContext.signatureLength = 65;
    signTransaction_ExpectAnyArgsAndReturn(0);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    bool ret = ui_callback_tx_ok(false);

    TEST_ASSERT_TRUE(ret);
    TEST_ASSERT_EQUAL_HEX16(E_OK, g_captured_sw);
    TEST_ASSERT_EQUAL_UINT32(65, g_captured_size);
}

void test_tx_ok_reports_security_error_on_signing_failure(void) {
    signTransaction_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    bool ret = ui_callback_tx_ok(false);

    TEST_ASSERT_FALSE(ret);
    TEST_ASSERT_EQUAL_HEX16(E_SECURITY_STATUS_NOT_SATISFIED, g_captured_sw);
}

void test_signMessage_ok_sends_signature_on_success(void) {
    transactionContext.signatureLength = 65;
    signTransaction_ExpectAnyArgsAndReturn(0);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    bool ret = ui_callback_signMessage_ok(false);

    TEST_ASSERT_TRUE(ret);
    TEST_ASSERT_EQUAL_HEX16(E_OK, g_captured_sw);
}

// --- ui_callback_tx_cancel ---

void test_tx_cancel_reports_conditions_not_satisfied(void) {
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    bool ret = ui_callback_tx_cancel(false);

    TEST_ASSERT_TRUE(ret);
    TEST_ASSERT_EQUAL_HEX16(E_CONDITIONS_OF_USE_NOT_SATISFIED, g_captured_sw);
    TEST_ASSERT_FALSE(g_review_pending);
}

// --- ui_callback_ecdh_ok ---

void test_ecdh_ok_reports_security_error_on_key_derivation_failure(void) {
    bip32_derive_with_seed_init_privkey_256_ExpectAnyArgsAndReturn(CX_INVALID_PARAMETER);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    bool ret = ui_callback_ecdh_ok(false);

    TEST_ASSERT_FALSE(ret);
    TEST_ASSERT_EQUAL_HEX16(E_SECURITY_STATUS_NOT_SATISFIED, g_captured_sw);
}

void test_ecdh_ok_reports_security_error_on_ecdh_failure(void) {
    bip32_derive_with_seed_init_privkey_256_ExpectAnyArgsAndReturn(CX_OK);
    cx_ecdh_no_throw_ExpectAnyArgsAndReturn(CX_INVALID_PARAMETER);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    bool ret = ui_callback_ecdh_ok(false);

    TEST_ASSERT_FALSE(ret);
    TEST_ASSERT_EQUAL_HEX16(E_SECURITY_STATUS_NOT_SATISFIED, g_captured_sw);
}

void test_ecdh_ok_sends_shared_secret_on_success(void) {
    bip32_derive_with_seed_init_privkey_256_ExpectAnyArgsAndReturn(CX_OK);
    cx_ecdh_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    bool ret = ui_callback_ecdh_ok(false);

    TEST_ASSERT_TRUE(ret);
    TEST_ASSERT_EQUAL_HEX16(E_OK, g_captured_sw);
}

// --- format_signature_out: independently-derived DER r/s -> raw 64-byte vectors ---

void test_format_signature_out_both_32_bytes_no_padding(void) {
    uint8_t sig[4 + 32 + 2 + 32] = {0};
    sig[0] = 0x30;
    sig[1] = 68;
    sig[2] = 0x02;
    sig[3] = 32;
    for (int i = 0; i < 32; i++) sig[4 + i] = (uint8_t) (0x01 + i);       // r = 01..20
    sig[36] = 0x02;
    sig[37] = 32;
    for (int i = 0; i < 32; i++) sig[38 + i] = (uint8_t) (0x41 + i);      // s = 41..60

    format_signature_out(sig);

    uint8_t expect_r[32], expect_s[32];
    for (int i = 0; i < 32; i++) expect_r[i] = (uint8_t) (0x01 + i);
    for (int i = 0; i < 32; i++) expect_s[i] = (uint8_t) (0x41 + i);
    TEST_ASSERT_EQUAL_MEMORY(expect_r, G_io_apdu_buffer, 32);
    TEST_ASSERT_EQUAL_MEMORY(expect_s, G_io_apdu_buffer + 32, 32);
}

void test_format_signature_out_strips_der_leading_zero_padding(void) {
    // r is DER-encoded as 33 bytes (0x00 prefix + 32 real bytes, high bit set).
    uint8_t sig[4 + 33 + 2 + 32] = {0};
    sig[0] = 0x30;
    sig[1] = 69;
    sig[2] = 0x02;
    sig[3] = 33;
    sig[4] = 0x00;
    for (int i = 0; i < 32; i++) sig[5 + i] = (uint8_t) (0x80 + i);  // r's 32 real bytes
    sig[37] = 0x02;
    sig[38] = 32;
    for (int i = 0; i < 32; i++) sig[39 + i] = (uint8_t) (0x41 + i);  // s

    format_signature_out(sig);

    uint8_t expect_r[32], expect_s[32];
    for (int i = 0; i < 32; i++) expect_r[i] = (uint8_t) (0x80 + i);
    for (int i = 0; i < 32; i++) expect_s[i] = (uint8_t) (0x41 + i);
    TEST_ASSERT_EQUAL_MEMORY(expect_r, G_io_apdu_buffer, 32);
    TEST_ASSERT_EQUAL_MEMORY(expect_s, G_io_apdu_buffer + 32, 32);
}

void test_format_signature_out_left_zero_pads_a_short_r(void) {
    // r is DER-encoded as 31 bytes (its natural high byte was zero, trimmed).
    uint8_t sig[4 + 31 + 2 + 32] = {0};
    sig[0] = 0x30;
    sig[2] = 0x02;
    sig[3] = 31;
    for (int i = 0; i < 31; i++) sig[4 + i] = (uint8_t) (0x01 + i);
    sig[35] = 0x02;
    sig[36] = 32;
    for (int i = 0; i < 32; i++) sig[37 + i] = (uint8_t) (0x41 + i);

    format_signature_out(sig);

    uint8_t expect_r[32] = {0};
    for (int i = 0; i < 31; i++) expect_r[1 + i] = (uint8_t) (0x01 + i);  // left-padded with one 0x00
    uint8_t expect_s[32];
    for (int i = 0; i < 32; i++) expect_s[i] = (uint8_t) (0x41 + i);
    TEST_ASSERT_EQUAL_MEMORY(expect_r, G_io_apdu_buffer, 32);
    TEST_ASSERT_EQUAL_MEMORY(expect_s, G_io_apdu_buffer + 32, 32);
}

// --- ui_callback_signMessage712_v0_ok ---

void test_signMessage712_v0_ok_returns_false_silently_on_hash_init_failure(void) {
    cx_keccak_init_no_throw_ExpectAnyArgsAndReturn(CX_INVALID_PARAMETER);

    bool ret = ui_callback_signMessage712_v0_ok(false);

    TEST_ASSERT_FALSE(ret);
    TEST_ASSERT_EQUAL_HEX16(0, g_captured_sw);  // no response sent at all on this path
}

void test_signMessage712_v0_ok_reports_security_error_on_key_derivation_failure(void) {
    cx_keccak_init_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_hash_no_throw_IgnoreAndReturn(CX_OK);
    bip32_derive_with_seed_init_privkey_256_ExpectAnyArgsAndReturn(CX_INVALID_PARAMETER);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    bool ret = ui_callback_signMessage712_v0_ok(false);

    TEST_ASSERT_FALSE(ret);
    TEST_ASSERT_EQUAL_HEX16(E_SECURITY_STATUS_NOT_SATISFIED, g_captured_sw);
}

static cx_err_t fake_sign_cb(const cx_ecfp_private_key_t *key, uint32_t mode, cx_md_t hashID,
                             const uint8_t *hash, size_t hash_len, uint8_t *sig, size_t *sig_len,
                             uint32_t *info, int n) {
    (void) key;
    (void) mode;
    (void) hashID;
    (void) hash;
    (void) hash_len;
    (void) n;
    memset(sig, 0, *sig_len);
    sig[0] = 0x30;
    sig[2] = 0x02;
    sig[3] = 32;
    for (int i = 0; i < 32; i++) sig[4 + i] = (uint8_t) (0x01 + i);
    sig[36] = 0x02;
    sig[37] = 32;
    for (int i = 0; i < 32; i++) sig[38 + i] = (uint8_t) (0x41 + i);
    *info = CX_ECCINFO_PARITY_ODD;
    return CX_OK;
}

void test_signMessage712_v0_ok_success_sets_signature_and_parity_byte(void) {
    cx_keccak_init_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_hash_no_throw_IgnoreAndReturn(CX_OK);
    bip32_derive_with_seed_init_privkey_256_ExpectAnyArgsAndReturn(CX_OK);
    cx_ecdsa_sign_no_throw_AddCallback(fake_sign_cb);
    cx_ecdsa_sign_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    bool ret = ui_callback_signMessage712_v0_ok(false);

    TEST_ASSERT_TRUE(ret);
    TEST_ASSERT_EQUAL_HEX16(E_OK, g_captured_sw);
    TEST_ASSERT_EQUAL_UINT32(65, g_captured_size);
    TEST_ASSERT_EQUAL_HEX8(0x01, g_captured_resp[64]);  // parity-odd bit set
}

// --- ui_callback_signMessage712_v0_cancel ---

void test_signMessage712_v0_cancel_writes_rejection_sw_directly(void) {
    bool ret = ui_callback_signMessage712_v0_cancel(false);

    TEST_ASSERT_TRUE(ret);
    TEST_ASSERT_EQUAL_HEX8(0x69, G_io_apdu_buffer[0]);
    TEST_ASSERT_EQUAL_HEX8(0x85, G_io_apdu_buffer[1]);
    TEST_ASSERT_FALSE(g_review_pending);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_address_ok_sends_pubkey_and_clears_review_pending);
    RUN_TEST(test_address_ok_redisplays_idle_menu_when_asked);
    RUN_TEST(test_tx_ok_sends_signature_on_success);
    RUN_TEST(test_tx_ok_reports_security_error_on_signing_failure);
    RUN_TEST(test_signMessage_ok_sends_signature_on_success);
    RUN_TEST(test_tx_cancel_reports_conditions_not_satisfied);
    RUN_TEST(test_ecdh_ok_reports_security_error_on_key_derivation_failure);
    RUN_TEST(test_ecdh_ok_reports_security_error_on_ecdh_failure);
    RUN_TEST(test_ecdh_ok_sends_shared_secret_on_success);
    RUN_TEST(test_format_signature_out_both_32_bytes_no_padding);
    RUN_TEST(test_format_signature_out_strips_der_leading_zero_padding);
    RUN_TEST(test_format_signature_out_left_zero_pads_a_short_r);
    RUN_TEST(test_signMessage712_v0_ok_returns_false_silently_on_hash_init_failure);
    RUN_TEST(test_signMessage712_v0_ok_reports_security_error_on_key_derivation_failure);
    RUN_TEST(test_signMessage712_v0_ok_success_sets_signature_and_parity_byte);
    RUN_TEST(test_signMessage712_v0_cancel_writes_rejection_sw_directly);

    return UNITY_END();
}
