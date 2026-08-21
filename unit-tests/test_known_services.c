// Tronify address independently decoded from base58check (TUFXua1qzfCsFpcZEGXaU7oGFURqQ7RQpy).

#include <string.h>

#include "unity.h"
#include "known_services.h"

void setUp(void) {
}

void tearDown(void) {
}

static const uint8_t TRONIFY_ADDRESS[21] = {0x41, 0xC8, 0x88, 0xB3, 0x6E, 0x17, 0x95, 0x8E, 0x39, 0x14, 0x00,
                                            0x51, 0xEB, 0x5D, 0x8C, 0xBC, 0x1B, 0x5C, 0x10, 0x9D, 0x6D};

void test_known_address_returns_its_label(void) {
    const char *label = get_known_service_label(TRONIFY_ADDRESS);
    TEST_ASSERT_NOT_NULL(label);
    TEST_ASSERT_EQUAL_STRING("Energy rental - Tronify", label);
}

void test_unknown_address_returns_null(void) {
    uint8_t unknown[21] = {0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    TEST_ASSERT_NULL(get_known_service_label(unknown));
}

void test_address_off_by_one_byte_returns_null(void) {
    uint8_t almost[21];
    memcpy(almost, TRONIFY_ADDRESS, sizeof(almost));
    almost[20] ^= 0x01;
    TEST_ASSERT_NULL(get_known_service_label(almost));
}

void test_null_address_returns_null(void) {
    TEST_ASSERT_NULL(get_known_service_label(NULL));
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_known_address_returns_its_label);
    RUN_TEST(test_unknown_address_returns_null);
    RUN_TEST(test_address_off_by_one_byte_returns_null);
    RUN_TEST(test_null_address_returns_null);

    return UNITY_END();
}
