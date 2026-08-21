// Mock-free: adjustDecimals/print_amount/setContractType/setExchangeContractDetail/bytes_to_string
// are pure logic (bytes_to_string links the SDK's real format_hex, not a mock).

#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "Mocklcx_sha256.h"
#include "Mocklcx_ecfp.h"
#include "Mocklcx_ecdsa.h"
#include "Mockledger_assert_internals.h"

#include "parse.h"
#include "settings.h"

// parse.c also defines initTx()/processTx()/getKnownToken(), which reference these;
// unused by the tests below but required to link.
const internal_storage_t N_storage_real = 0;

// print_amount()'s THROW(E_INCORRECT_LENGTH) path needs numDigits > 19, unreachable from any
// real int64 protobuf field; stub it loudly rather than pull in the SDK's exception machinery.
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

// adjustDecimals

void test_adjustDecimals_zero_input_yields_zero(void) {
    char out[8];
    TEST_ASSERT_TRUE(adjustDecimals("0", 1, out, sizeof(out), 6));
    TEST_ASSERT_EQUAL_STRING("0", out);
}

void test_adjustDecimals_zero_input_fails_on_undersized_buffer(void) {
    char out[1];
    TEST_ASSERT_FALSE(adjustDecimals("0", 1, out, sizeof(out), 6));
}

void test_adjustDecimals_srcLength_below_decimals_pads_leading_zeros(void) {
    char out[16];
    TEST_ASSERT_TRUE(adjustDecimals("5", 1, out, sizeof(out), 6));
    TEST_ASSERT_EQUAL_STRING("0.000005", out);
}

void test_adjustDecimals_trims_trailing_zeros_in_fraction(void) {
    char out[16];
    TEST_ASSERT_TRUE(adjustDecimals("500", 3, out, sizeof(out), 6));
    TEST_ASSERT_EQUAL_STRING("0.0005", out);
}

void test_adjustDecimals_undersized_buffer_fails_below_decimals_branch(void) {
    char out[4];
    TEST_ASSERT_FALSE(adjustDecimals("5", 1, out, sizeof(out), 6));
}

void test_adjustDecimals_srcLength_above_decimals_inserts_point(void) {
    char out[16];
    TEST_ASSERT_TRUE(adjustDecimals("123456", 6, out, sizeof(out), 2));
    TEST_ASSERT_EQUAL_STRING("1234.56", out);
}

void test_adjustDecimals_zero_decimals_yields_plain_integer(void) {
    char out[16];
    TEST_ASSERT_TRUE(adjustDecimals("12345", 5, out, sizeof(out), 0));
    TEST_ASSERT_EQUAL_STRING("12345", out);
}

void test_adjustDecimals_trims_trailing_zero_fraction_and_its_point(void) {
    char out[16];
    TEST_ASSERT_TRUE(adjustDecimals("100", 3, out, sizeof(out), 2));
    TEST_ASSERT_EQUAL_STRING("1", out);
}

void test_adjustDecimals_undersized_buffer_fails_above_decimals_branch(void) {
    char out[4];
    TEST_ASSERT_FALSE(adjustDecimals("123456", 6, out, sizeof(out), 2));
}

// print_amount

void test_print_amount_inserts_decimal_point_at_sun_position(void) {
    char out[32];
    unsigned short len = print_amount(1500000, out, sizeof(out), 6);
    TEST_ASSERT_EQUAL_STRING("1.5", out);
    TEST_ASSERT_EQUAL(strlen("1.5"), len);
}

void test_print_amount_zero(void) {
    // amount==0 yields an empty digit string, not "0"; no trailing-zero trim kicks in.
    char out[32];
    print_amount(0, out, sizeof(out), 6);
    TEST_ASSERT_EQUAL_STRING("0.000000", out);
}

void test_print_amount_max_int64_fits_19_digits(void) {
    char out[32];
    unsigned short len = print_amount(9223372036854775807ULL, out, sizeof(out), 0);
    TEST_ASSERT_EQUAL_STRING("9223372036854775807", out);
    TEST_ASSERT_EQUAL(strlen("9223372036854775807"), len);
}

void test_print_amount_reports_empty_string_when_it_does_not_fit(void) {
    char out[3];
    unsigned short len = print_amount(1500000, out, sizeof(out), 6);
    TEST_ASSERT_EQUAL_STRING("", out);
    TEST_ASSERT_EQUAL(0, len);
}

// setContractType

void test_setContractType_known_type(void) {
    char out[32];
    TEST_ASSERT_TRUE(setContractType(WITHDRAWBALANCECONTRACT, out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("Claim Rewards", out);
}

void test_setContractType_unknown_marker(void) {
    char out[32];
    TEST_ASSERT_TRUE(setContractType(UNKNOWN_CONTRACT, out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("Unknown Type", out);
}

void test_setContractType_rejects_types_with_their_own_dedicated_screen(void) {
    char out[32] = "unchanged";
    TEST_ASSERT_FALSE(setContractType(TRANSFERCONTRACT, out, sizeof(out)));
}

// setExchangeContractDetail

void test_setExchangeContractDetail_known_type(void) {
    char out[16];
    TEST_ASSERT_TRUE(setExchangeContractDetail(EXCHANGEWITHDRAWCONTRACT, out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("withdraw", out);
}

void test_setExchangeContractDetail_rejects_non_exchange_type(void) {
    char out[16];
    TEST_ASSERT_FALSE(setExchangeContractDetail(TRANSFERCONTRACT, out, sizeof(out)));
}

// bytes_to_string

void test_bytes_to_string_prefixes_0x_and_hex_encodes(void) {
    const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    char out[16];
    TEST_ASSERT_EQUAL(0, bytes_to_string(out, sizeof(out), data, sizeof(data)));
    TEST_ASSERT_EQUAL_STRING("0xDEADBEEF", out);
}

void test_bytes_to_string_fails_when_buffer_too_small_for_prefix(void) {
    const uint8_t data[] = {0xAB};
    char out[2];
    TEST_ASSERT_EQUAL(-1, bytes_to_string(out, sizeof(out), data, sizeof(data)));
}

void test_bytes_to_string_fails_when_buffer_too_small_for_hex_digits(void) {
    const uint8_t data[] = {0xAB, 0xCD};
    char out[4];  // room for "0x" + 1 digit, not the 4 needed
    TEST_ASSERT_EQUAL(-1, bytes_to_string(out, sizeof(out), data, sizeof(data)));
    TEST_ASSERT_EQUAL_STRING("", out);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_adjustDecimals_zero_input_yields_zero);
    RUN_TEST(test_adjustDecimals_zero_input_fails_on_undersized_buffer);
    RUN_TEST(test_adjustDecimals_srcLength_below_decimals_pads_leading_zeros);
    RUN_TEST(test_adjustDecimals_trims_trailing_zeros_in_fraction);
    RUN_TEST(test_adjustDecimals_undersized_buffer_fails_below_decimals_branch);
    RUN_TEST(test_adjustDecimals_srcLength_above_decimals_inserts_point);
    RUN_TEST(test_adjustDecimals_zero_decimals_yields_plain_integer);
    RUN_TEST(test_adjustDecimals_trims_trailing_zero_fraction_and_its_point);
    RUN_TEST(test_adjustDecimals_undersized_buffer_fails_above_decimals_branch);

    RUN_TEST(test_print_amount_inserts_decimal_point_at_sun_position);
    RUN_TEST(test_print_amount_zero);
    RUN_TEST(test_print_amount_max_int64_fits_19_digits);
    RUN_TEST(test_print_amount_reports_empty_string_when_it_does_not_fit);

    RUN_TEST(test_setContractType_known_type);
    RUN_TEST(test_setContractType_unknown_marker);
    RUN_TEST(test_setContractType_rejects_types_with_their_own_dedicated_screen);

    RUN_TEST(test_setExchangeContractDetail_known_type);
    RUN_TEST(test_setExchangeContractDetail_rejects_non_exchange_type);

    RUN_TEST(test_bytes_to_string_prefixes_0x_and_hex_encodes);
    RUN_TEST(test_bytes_to_string_fails_when_buffer_too_small_for_prefix);
    RUN_TEST(test_bytes_to_string_fails_when_buffer_too_small_for_hex_digits);

    return UNITY_END();
}
