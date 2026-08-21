// parseTokenName()/parseExchange(): decode a Ledger-signed TokenDetails/
// ExchangeDetails attestation (received on a later INS_SIGN chunk) and merge it
// into the already-decoded txContent_t. The signature check itself is the SDK's
// (mocked); these tests cover parse.c's own decode/merge/validation logic.

#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "Mocklcx_sha256.h"
#include "Mocklcx_ecfp.h"
#include "Mocklcx_ecdsa.h"
#include "Mockledger_assert_internals.h"

#include "parse.h"
#include "tokens.h"
#include "misc/TronApp.pb.h"
#include "pb_encode.h"

uint8_t N_storage_real = 0;

void os_longjmp(unsigned int exception) {
    (void) exception;
    abort();
}

void setUp(void) {
    Mocklcx_sha256_Init();
    Mocklcx_ecfp_Init();
    Mocklcx_ecdsa_Init();
    Mockledger_assert_internals_Init();
}

void tearDown(void) {
    Mocklcx_sha256_Verify();
    Mocklcx_ecfp_Verify();
    Mocklcx_ecdsa_Verify();
    Mockledger_assert_internals_Verify();

    Mocklcx_sha256_Destroy();
    Mocklcx_ecfp_Destroy();
    Mocklcx_ecdsa_Destroy();
    Mockledger_assert_internals_Destroy();
}

static void expect_signature_check(bool ok) {
    cx_hash_sha256_ExpectAnyArgsAndReturn(32);
    cx_ecfp_init_public_key_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_ecdsa_verify_no_throw_ExpectAnyArgsAndReturn(ok ? 1 : 0);
}

// parseTokenName

void test_parseTokenName_merges_name_and_id_on_valid_signature(void) {
    TokenDetails details = {0};
    strcpy(details.name, "MyToken");
    details.precision = 6;

    uint8_t buf[128];
    pb_ostream_t stream = pb_ostream_from_buffer(buf, sizeof(buf));
    TEST_ASSERT_TRUE(pb_encode(&stream, TokenDetails_fields, &details));

    txContent_t content = {0};
    strcpy(content.tokenNames[0], "1000001");

    expect_signature_check(true);
    TEST_ASSERT_TRUE(parseTokenName(0, buf, stream.bytes_written, &content));
    TEST_ASSERT_EQUAL_STRING("MyToken[1000001]", content.tokenNames[0]);
    TEST_ASSERT_EQUAL(strlen("MyToken[1000001]"), content.tokenNamesLength[0]);
    TEST_ASSERT_EQUAL(6, content.decimals[0]);
}

void test_parseTokenName_rejects_invalid_signature(void) {
    TokenDetails details = {0};
    strcpy(details.name, "MyToken");
    details.precision = 6;

    uint8_t buf[128];
    pb_ostream_t stream = pb_ostream_from_buffer(buf, sizeof(buf));
    TEST_ASSERT_TRUE(pb_encode(&stream, TokenDetails_fields, &details));

    txContent_t content = {0};
    strcpy(content.tokenNames[0], "1000001");

    expect_signature_check(false);
    TEST_ASSERT_FALSE(parseTokenName(0, buf, stream.bytes_written, &content));
}

void test_parseTokenName_rejects_precision_above_max_even_with_valid_signature(void) {
    TokenDetails details = {0};
    strcpy(details.name, "MyToken");
    details.precision = MAX_TOKEN_PRECISION + 1;

    uint8_t buf[128];
    pb_ostream_t stream = pb_ostream_from_buffer(buf, sizeof(buf));
    TEST_ASSERT_TRUE(pb_encode(&stream, TokenDetails_fields, &details));

    txContent_t content = {0};
    strcpy(content.tokenNames[0], "1000001");

    expect_signature_check(true);
    TEST_ASSERT_FALSE(parseTokenName(0, buf, stream.bytes_written, &content));
}

// parseExchange

static void encode_exchange_details(ExchangeDetails *details, uint8_t *buf, size_t buf_cap,
                                    size_t *out_len) {
    pb_ostream_t stream = pb_ostream_from_buffer(buf, buf_cap);
    TEST_ASSERT_TRUE(pb_encode(&stream, ExchangeDetails_fields, details));
    *out_len = stream.bytes_written;
}

void test_parseExchange_merges_both_token_names_on_valid_signature(void) {
    ExchangeDetails details = {0};
    details.exchangeId = 5;
    strcpy(details.token1Id, "1000001");
    strcpy(details.token1Name, "TokenA");
    details.token1Precision = 6;
    strcpy(details.token2Id, "_");
    strcpy(details.token2Name, "TRX");
    details.token2Precision = 6;

    uint8_t buf[256];
    size_t len;
    encode_exchange_details(&details, buf, sizeof(buf), &len);

    txContent_t content = {0};
    content.exchangeID = 5;
    strcpy(content.tokenNames[0], "1000001");

    expect_signature_check(true);
    TEST_ASSERT_TRUE(parseExchange(buf, len, &content));
    TEST_ASSERT_EQUAL_STRING("TokenA[1000001]", content.tokenNames[0]);
    TEST_ASSERT_EQUAL_STRING("TRX[_]", content.tokenNames[1]);
    TEST_ASSERT_EQUAL(6, content.decimals[0]);
    TEST_ASSERT_EQUAL(6, content.decimals[1]);
}

void test_parseExchange_rejects_exchangeId_mismatch_without_checking_signature(void) {
    ExchangeDetails details = {0};
    details.exchangeId = 5;
    strcpy(details.token1Id, "1000001");
    strcpy(details.token2Id, "_");

    uint8_t buf[256];
    size_t len;
    encode_exchange_details(&details, buf, sizeof(buf), &len);

    txContent_t content = {0};
    content.exchangeID = 6;  // does not match details.exchangeId
    strcpy(content.tokenNames[0], "1000001");

    TEST_ASSERT_FALSE(parseExchange(buf, len, &content));
}

void test_parseExchange_rejects_malformed_token1Id_length_without_checking_signature(void) {
    ExchangeDetails details = {0};
    details.exchangeId = 5;
    strcpy(details.token1Id, "abc");  // neither 1 nor 7 chars
    strcpy(details.token2Id, "_");

    uint8_t buf[256];
    size_t len;
    encode_exchange_details(&details, buf, sizeof(buf), &len);

    txContent_t content = {0};
    content.exchangeID = 5;
    strcpy(content.tokenNames[0], "1000001");

    TEST_ASSERT_FALSE(parseExchange(buf, len, &content));
}

void test_parseExchange_rejects_when_neither_token_id_matches_the_pending_pair(void) {
    ExchangeDetails details = {0};
    details.exchangeId = 5;
    strcpy(details.token1Id, "1000001");
    strcpy(details.token2Id, "_");

    uint8_t buf[256];
    size_t len;
    encode_exchange_details(&details, buf, sizeof(buf), &len);

    txContent_t content = {0};
    content.exchangeID = 5;
    strcpy(content.tokenNames[0], "9999999");  // matches neither token1Id nor token2Id

    expect_signature_check(true);
    TEST_ASSERT_FALSE(parseExchange(buf, len, &content));
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_parseTokenName_merges_name_and_id_on_valid_signature);
    RUN_TEST(test_parseTokenName_rejects_invalid_signature);
    RUN_TEST(test_parseTokenName_rejects_precision_above_max_even_with_valid_signature);

    RUN_TEST(test_parseExchange_merges_both_token_names_on_valid_signature);
    RUN_TEST(test_parseExchange_rejects_exchangeId_mismatch_without_checking_signature);
    RUN_TEST(test_parseExchange_rejects_malformed_token1Id_length_without_checking_signature);
    RUN_TEST(test_parseExchange_rejects_when_neither_token_id_matches_the_pending_pair);

    return UNITY_END();
}
