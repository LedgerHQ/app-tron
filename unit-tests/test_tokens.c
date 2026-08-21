// Selector values checked independently against keccak256() function signatures.

#include <string.h>

#include "unity.h"

#include "Mocklcx_sha256.h"
#include "Mocklcx_ecfp.h"
#include "Mocklcx_ecdsa.h"
#include "Mockledger_assert_internals.h"

#include "tokens.h"

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

void test_selector_transfer_matches_keccak256_signature(void) {
    const uint8_t expect[4] = {0xA9, 0x05, 0x9C, 0xBB};  // keccak256("transfer(address,uint256)")[:4]
    TEST_ASSERT_EQUAL_MEMORY(expect, SELECTOR[0], 4);
}

void test_selector_approve_matches_keccak256_signature(void) {
    const uint8_t expect[4] = {0x09, 0x5E, 0xA7, 0xB3};  // keccak256("approve(address,uint256)")[:4]
    TEST_ASSERT_EQUAL_MEMORY(expect, SELECTOR[1], 4);
}

void test_all_trc20_entries_are_well_formed(void) {
    for (size_t i = 0; i < NUM_TOKENS_TRC20; i++) {
        // Tron mainnet address prefix.
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x41, TOKENS_TRC20[i].address[0], "bad address prefix");

        size_t ticker_len = strnlen(TOKENS_TRC20[i].ticker, sizeof(TOKENS_TRC20[i].ticker));
        TEST_ASSERT_MESSAGE(ticker_len > 0, "empty ticker");
        TEST_ASSERT_LESS_THAN_MESSAGE(sizeof(TOKENS_TRC20[i].ticker), ticker_len, "ticker not NUL-terminated");

        TEST_ASSERT_LESS_OR_EQUAL_MESSAGE(18, TOKENS_TRC20[i].decimals, "decimals implausibly large");
    }
}

void test_no_duplicate_trc20_addresses(void) {
    for (size_t i = 0; i < NUM_TOKENS_TRC20; i++) {
        for (size_t j = i + 1; j < NUM_TOKENS_TRC20; j++) {
            TEST_ASSERT_NOT_EQUAL_MESSAGE(
                0,
                memcmp(TOKENS_TRC20[i].address, TOKENS_TRC20[j].address, sizeof(TOKENS_TRC20[i].address)),
                "duplicate TRC20 address entry");
        }
    }
}

// verifyTokenNameID / verifyExchangeID: forward the SDK's signature-verification result.

void test_verifyTokenNameID_rejects_oversized_tokenId_without_touching_crypto(void) {
    char token_id[34];
    memset(token_id, 'A', sizeof(token_id) - 1);
    token_id[sizeof(token_id) - 1] = '\0';

    uint8_t sig[1] = {0};
    TEST_ASSERT_EQUAL(0, verifyTokenNameID(token_id, "TICKER", 6, sig, sizeof(sig)));
}

void test_verifyTokenNameID_forwards_sdk_verification_result(void) {
    cx_hash_sha256_ExpectAnyArgsAndReturn(32);
    cx_ecfp_init_public_key_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_ecdsa_verify_no_throw_ExpectAnyArgsAndReturn(1);

    uint8_t sig[1] = {0};
    TEST_ASSERT_EQUAL(1, verifyTokenNameID("id", "TICKER", 6, sig, sizeof(sig)));
}

void test_verifyExchangeID_forwards_sdk_rejection(void) {
    cx_hash_sha256_ExpectAnyArgsAndReturn(32);
    cx_ecfp_init_public_key_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_ecdsa_verify_no_throw_ExpectAnyArgsAndReturn(0);

    uint8_t data[4] = {0};
    uint8_t sig[1] = {0};
    TEST_ASSERT_EQUAL(0, verifyExchangeID(data, sizeof(data), sig, sizeof(sig)));
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_selector_transfer_matches_keccak256_signature);
    RUN_TEST(test_selector_approve_matches_keccak256_signature);
    RUN_TEST(test_all_trc20_entries_are_well_formed);
    RUN_TEST(test_no_duplicate_trc20_addresses);

    RUN_TEST(test_verifyTokenNameID_rejects_oversized_tokenId_without_touching_crypto);
    RUN_TEST(test_verifyTokenNameID_forwards_sdk_verification_result);
    RUN_TEST(test_verifyExchangeID_forwards_sdk_rejection);

    return UNITY_END();
}
