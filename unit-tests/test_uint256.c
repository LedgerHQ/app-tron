// Expected values computed independently in Python, not derived from this code.

#include <string.h>

#include "unity.h"
#include "uint256.h"

void setUp(void) {
}

void tearDown(void) {
}

// convertUint256BE / readu256BE

void test_convertUint256BE_short_buffer_is_left_zero_padded(void) {
    const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint256_t n;

    convertUint256BE(data, sizeof(data), &n);

    TEST_ASSERT_EQUAL_HEX64(0, n.elements[0].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0, n.elements[0].elements[1]);
    TEST_ASSERT_EQUAL_HEX64(0, n.elements[1].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0xDEADBEEF, n.elements[1].elements[1]);
}

void test_convertUint256BE_full_32_bytes(void) {
    const uint8_t data[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                              0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0};
    uint256_t n;

    convertUint256BE(data, sizeof(data), &n);

    TEST_ASSERT_EQUAL_HEX64(0x0123456789abcdef, n.elements[0].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0xfedcba9876543210, n.elements[0].elements[1]);
    TEST_ASSERT_EQUAL_HEX64(0x0011223344556677, n.elements[1].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0x8899aabbccddeef0, n.elements[1].elements[1]);
}

// zero / equal / gt / gte

void test_zero256_true_for_all_zero(void) {
    uint256_t n = {0};
    TEST_ASSERT_TRUE(zero256(&n));
}

void test_zero256_false_if_any_limb_set(void) {
    uint256_t n = {0};
    n.elements[1].elements[1] = 1;
    TEST_ASSERT_FALSE(zero256(&n));
}

void test_equal256_true_for_identical_values(void) {
    uint256_t a = {0}, b = {0};
    a.elements[0].elements[0] = 0x1122334455667788ULL;
    b.elements[0].elements[0] = 0x1122334455667788ULL;
    TEST_ASSERT_TRUE(equal256(&a, &b));
}

void test_equal256_false_when_only_lowest_limb_differs(void) {
    uint256_t a = {0}, b = {0};
    a.elements[1].elements[1] = 5;
    b.elements[1].elements[1] = 6;
    TEST_ASSERT_FALSE(equal256(&a, &b));
}

void test_gt256_compares_upper_before_lower(void) {
    uint256_t a = {0}, b = {0};
    a.elements[0].elements[0] = 1;
    a.elements[1].elements[1] = 0xFFFFFFFFFFFFFFFFULL;
    b.elements[0].elements[0] = 2;

    TEST_ASSERT_TRUE(gt256(&b, &a));
    TEST_ASSERT_FALSE(gt256(&a, &b));
}

void test_gte256_true_on_equality(void) {
    uint256_t a = {0}, b = {0};
    a.elements[1].elements[1] = 42;
    b.elements[1].elements[1] = 42;
    TEST_ASSERT_TRUE(gte256(&a, &b));
}

// add256 / minus256: carry/borrow across the 128-bit boundary

void test_add256_carries_from_lower_into_upper(void) {
    uint256_t a = {0}, b = {0}, result;
    a.elements[1].elements[1] = 0xFFFFFFFFFFFFFFFFULL;
    a.elements[1].elements[0] = 0xFFFFFFFFFFFFFFFFULL;
    b.elements[1].elements[1] = 1;

    add256(&a, &b, &result);

    TEST_ASSERT_EQUAL_HEX64(0, result.elements[0].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(1, result.elements[0].elements[1]);
    TEST_ASSERT_EQUAL_HEX64(0, result.elements[1].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0, result.elements[1].elements[1]);
}

void test_add256_matches_independently_computed_sum(void) {
    uint256_t a = {0}, b = {0}, result;
    a.elements[0].elements[0] = 0x0123456789abcdefULL;
    a.elements[0].elements[1] = 0xfedcba9876543210ULL;
    a.elements[1].elements[0] = 0x0011223344556677ULL;
    a.elements[1].elements[1] = 0x8899aabbccddeef0ULL;
    b.elements[1].elements[0] = 0x0100000000000000ULL;
    b.elements[1].elements[1] = 0x0000000000000001ULL;

    add256(&a, &b, &result);

    TEST_ASSERT_EQUAL_HEX64(0x0123456789abcdefULL, result.elements[0].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0xfedcba9876543210ULL, result.elements[0].elements[1]);
    TEST_ASSERT_EQUAL_HEX64(0x0111223344556677ULL, result.elements[1].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0x8899aabbccddeef1ULL, result.elements[1].elements[1]);
}

void test_minus256_borrows_from_upper_into_lower(void) {
    uint256_t a = {0}, b = {0}, result;
    a.elements[0].elements[1] = 1;
    b.elements[1].elements[1] = 1;

    minus256(&a, &b, &result);

    TEST_ASSERT_EQUAL_HEX64(0, result.elements[0].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0, result.elements[0].elements[1]);
    TEST_ASSERT_EQUAL_HEX64(0xFFFFFFFFFFFFFFFFULL, result.elements[1].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0xFFFFFFFFFFFFFFFFULL, result.elements[1].elements[1]);
}

// mul256: wraps modulo 2^256

void test_mul256_matches_independently_computed_product(void) {
    uint256_t m1 = {0}, m2 = {0}, product;
    m1.elements[0].elements[0] = 0x0000000000000100ULL;
    m1.elements[1].elements[1] = 0x0000000000003039ULL;
    m2.elements[1].elements[0] = 0x0000001000000000ULL;
    m2.elements[1].elements[1] = 0x0000000000000007ULL;

    mul256(&m1, &m2, &product);

    TEST_ASSERT_EQUAL_HEX64(0x0000000000000700ULL, product.elements[0].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0x0000000000000000ULL, product.elements[0].elements[1]);
    TEST_ASSERT_EQUAL_HEX64(0x0003039000000000ULL, product.elements[1].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0x000000000001518fULL, product.elements[1].elements[1]);
}

void test_divmod256_matches_independently_computed_quotient_and_remainder(void) {
    uint256_t d1 = {0}, d2 = {0}, q, r;
    d1.elements[0].elements[0] = 0x001234567890abcdULL;
    d1.elements[0].elements[1] = 0xef1234567890abcdULL;
    d1.elements[1].elements[0] = 0xef1234567890abcdULL;
    d1.elements[1].elements[1] = 0xef1234567890abcdULL;
    d2.elements[1].elements[1] = 0x00000000feedbeefULL;

    divmod256(&d1, &d2, &q, &r);

    TEST_ASSERT_EQUAL_HEX64(0x00000000001247ecULL, q.elements[0].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0x18bcdeea1ecb696aULL, q.elements[0].elements[1]);
    TEST_ASSERT_EQUAL_HEX64(0xfe5b13f9540ccbeeULL, q.elements[1].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0x928aa23c823bbb5aULL, q.elements[1].elements[1]);

    TEST_ASSERT_TRUE(zero128(&UPPER(r)));
    TEST_ASSERT_EQUAL_HEX64(0, r.elements[1].elements[0]);
    TEST_ASSERT_EQUAL_HEX64(0x00000000cf6df6c7ULL, r.elements[1].elements[1]);
}

void test_divmod256_divisor_larger_than_dividend_returns_dividend_as_remainder(void) {
    uint256_t small = {0}, big = {0}, q, r;
    small.elements[1].elements[1] = 5;
    big.elements[1].elements[1] = 100;

    divmod256(&small, &big, &q, &r);

    TEST_ASSERT_TRUE(zero256(&q));
    TEST_ASSERT_TRUE(equal256(&r, &small));
}

void test_shiftl256_boundary_values(void) {
    static const struct {
        uint32_t shift;
        uint64_t expect_upper_hi, expect_upper_lo, expect_lower_hi, expect_lower_lo;
    } cases[] = {
        {0, 0, 0, 0, 1},
        {1, 0, 0, 0, 2},
        {63, 0, 0, 0, 0x8000000000000000ULL},
        {64, 0, 0, 1, 0},
        {65, 0, 0, 2, 0},
        {127, 0, 0, 0x8000000000000000ULL, 0},
        {128, 0, 1, 0, 0},
        {129, 0, 2, 0, 0},
        {255, 0x8000000000000000ULL, 0, 0, 0},
        {256, 0, 0, 0, 0},
        {300, 0, 0, 0, 0},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint256_t one = {0}, result;
        one.elements[1].elements[1] = 1;

        shiftl256(&one, cases[i].shift, &result);

        TEST_ASSERT_EQUAL_HEX64_MESSAGE(cases[i].expect_upper_hi,
                                        result.elements[0].elements[0],
                                        "upper_hi mismatch");
        TEST_ASSERT_EQUAL_HEX64_MESSAGE(cases[i].expect_upper_lo,
                                        result.elements[0].elements[1],
                                        "upper_lo mismatch");
        TEST_ASSERT_EQUAL_HEX64_MESSAGE(cases[i].expect_lower_hi,
                                        result.elements[1].elements[0],
                                        "lower_hi mismatch");
        TEST_ASSERT_EQUAL_HEX64_MESSAGE(cases[i].expect_lower_lo,
                                        result.elements[1].elements[1],
                                        "lower_lo mismatch");
    }
}

void test_shiftr256_boundary_values(void) {
    static const struct {
        uint32_t shift;
        uint64_t expect_upper_hi, expect_upper_lo, expect_lower_hi, expect_lower_lo;
    } cases[] = {
        {0, 0x8000000000000000ULL, 0, 0, 0},
        {1, 0x4000000000000000ULL, 0, 0, 0},
        {63, 1, 0, 0, 0},
        {64, 0, 0x8000000000000000ULL, 0, 0},
        {65, 0, 0x4000000000000000ULL, 0, 0},
        {127, 0, 1, 0, 0},
        {128, 0, 0, 0x8000000000000000ULL, 0},
        {129, 0, 0, 0x4000000000000000ULL, 0},
        {255, 0, 0, 0, 1},
        {256, 0, 0, 0, 0},
        {300, 0, 0, 0, 0},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint256_t top_bit = {0}, result;
        top_bit.elements[0].elements[0] = 0x8000000000000000ULL;

        shiftr256(&top_bit, cases[i].shift, &result);

        TEST_ASSERT_EQUAL_HEX64_MESSAGE(cases[i].expect_upper_hi,
                                        result.elements[0].elements[0],
                                        "upper_hi mismatch");
        TEST_ASSERT_EQUAL_HEX64_MESSAGE(cases[i].expect_upper_lo,
                                        result.elements[0].elements[1],
                                        "upper_lo mismatch");
        TEST_ASSERT_EQUAL_HEX64_MESSAGE(cases[i].expect_lower_hi,
                                        result.elements[1].elements[0],
                                        "lower_hi mismatch");
        TEST_ASSERT_EQUAL_HEX64_MESSAGE(cases[i].expect_lower_lo,
                                        result.elements[1].elements[1],
                                        "lower_lo mismatch");
    }
}

// bits256

void test_bits256_boundary_values(void) {
    uint256_t n;

    clear256(&n);
    TEST_ASSERT_EQUAL_UINT32(0, bits256(&n));

    clear256(&n);
    n.elements[1].elements[1] = 1;
    TEST_ASSERT_EQUAL_UINT32(1, bits256(&n));

    clear256(&n);
    n.elements[1].elements[0] = 0x8000000000000000ULL;  // 2^127
    TEST_ASSERT_EQUAL_UINT32(128, bits256(&n));

    clear256(&n);
    n.elements[0].elements[1] = 1;  // 2^128
    TEST_ASSERT_EQUAL_UINT32(129, bits256(&n));

    clear256(&n);
    n.elements[0].elements[0] = 0x8000000000000000ULL;  // 2^255
    TEST_ASSERT_EQUAL_UINT32(256, bits256(&n));
}

// tostring256

void test_tostring256_hex_matches_independently_computed_string(void) {
    uint256_t n = {0};
    char out[80];
    n.elements[1].elements[1] = 0xFF;

    TEST_ASSERT_TRUE(tostring256(&n, 16, out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("ff", out);
}

void test_tostring256_decimal_matches_independently_computed_string(void) {
    uint256_t n = {0};
    char out[80];
    n.elements[1].elements[1] = 255;

    TEST_ASSERT_TRUE(tostring256(&n, 10, out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("255", out);
}

void test_tostring256_binary_matches_independently_computed_string(void) {
    uint256_t n = {0};
    char out[300];
    n.elements[1].elements[1] = 5;

    TEST_ASSERT_TRUE(tostring256(&n, 2, out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("101", out);
}

void test_tostring256_rejects_base_below_2(void) {
    uint256_t n = {0};
    char out[80];
    n.elements[1].elements[1] = 1;

    TEST_ASSERT_FALSE(tostring256(&n, 1, out, sizeof(out)));
    TEST_ASSERT_FALSE(tostring256(&n, 0, out, sizeof(out)));
}

void test_tostring256_rejects_base_above_16(void) {
    uint256_t n = {0};
    char out[80];
    n.elements[1].elements[1] = 1;

    TEST_ASSERT_FALSE(tostring256(&n, 17, out, sizeof(out)));
}

void test_tostring256_fails_when_buffer_too_small_for_digits(void) {
    uint256_t n = {0};
    char out[2];
    n.elements[1].elements[1] = 0xFFF;

    TEST_ASSERT_FALSE(tostring256(&n, 16, out, sizeof(out)));
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_convertUint256BE_short_buffer_is_left_zero_padded);
    RUN_TEST(test_convertUint256BE_full_32_bytes);

    RUN_TEST(test_zero256_true_for_all_zero);
    RUN_TEST(test_zero256_false_if_any_limb_set);
    RUN_TEST(test_equal256_true_for_identical_values);
    RUN_TEST(test_equal256_false_when_only_lowest_limb_differs);
    RUN_TEST(test_gt256_compares_upper_before_lower);
    RUN_TEST(test_gte256_true_on_equality);

    RUN_TEST(test_add256_carries_from_lower_into_upper);
    RUN_TEST(test_add256_matches_independently_computed_sum);
    RUN_TEST(test_minus256_borrows_from_upper_into_lower);

    RUN_TEST(test_mul256_matches_independently_computed_product);

    RUN_TEST(test_divmod256_matches_independently_computed_quotient_and_remainder);
    RUN_TEST(test_divmod256_divisor_larger_than_dividend_returns_dividend_as_remainder);

    RUN_TEST(test_shiftl256_boundary_values);
    RUN_TEST(test_shiftr256_boundary_values);

    RUN_TEST(test_bits256_boundary_values);

    RUN_TEST(test_tostring256_hex_matches_independently_computed_string);
    RUN_TEST(test_tostring256_decimal_matches_independently_computed_string);
    RUN_TEST(test_tostring256_binary_matches_independently_computed_string);
    RUN_TEST(test_tostring256_rejects_base_below_2);
    RUN_TEST(test_tostring256_rejects_base_above_16);
    RUN_TEST(test_tostring256_fails_when_buffer_too_small_for_digits);

    return UNITY_END();
}
