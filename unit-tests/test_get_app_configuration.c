// Response: [config, major, minor, patch]. config is the public wire layout.

#include <string.h>

#include "unity.h"

#include "Mockio.h"

#include "handlers.h"
#include "app_errors.h"

// settings.h bits, redefined to avoid its OS dependencies.
#define S_DATA_ALLOWED    0
#define S_CUSTOM_CONTRACT 1
#define S_SIGN_BY_HASH    2

// Public wire bits.
#define CONFIG_BIT_DATA_ALLOWED    0
#define CONFIG_BIT_CUSTOM_CONTRACT 1
#define CONFIG_BIT_SIGN_BY_HASH    3

uint8_t N_storage_real = 0;

// copy the bytes now, the source buffer is a stack temporary
static uint8_t g_captured[4];
static size_t g_captured_size;

static int send_cb(const buffer_t *rdatalist, size_t count, uint16_t sw, int n) {
    (void) count;
    (void) sw;
    (void) n;
    g_captured_size = rdatalist->size;
    memcpy(g_captured, rdatalist->ptr, rdatalist->size);
    return 0x4242;
}

void setUp(void) {
    Mockio_Init();
    N_storage_real = 0;
    memset(g_captured, 0, sizeof(g_captured));
    g_captured_size = 0;
    io_send_response_buffers_AddCallback(send_cb);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
}

void tearDown(void) {
    Mockio_Verify();
    Mockio_Destroy();
}

void test_response_layout_and_version(void) {
    N_storage_real = (1 << S_DATA_ALLOWED) | (1 << S_SIGN_BY_HASH);

    int ret = handleGetAppConfiguration(0, 0, NULL, 0);

    TEST_ASSERT_EQUAL(0x4242, ret);
    TEST_ASSERT_EQUAL_UINT32(4, g_captured_size);
    TEST_ASSERT_EQUAL_HEX8((1 << CONFIG_BIT_DATA_ALLOWED) | (1 << CONFIG_BIT_SIGN_BY_HASH),
                           g_captured[0]);
    TEST_ASSERT_EQUAL_HEX8(MAJOR_VERSION, g_captured[1]);
    TEST_ASSERT_EQUAL_HEX8(MINOR_VERSION, g_captured[2]);
    TEST_ASSERT_EQUAL_HEX8(PATCH_VERSION, g_captured[3]);
}

void test_data_allowed_and_custom_contract_map_to_same_bit(void) {
    N_storage_real = (1 << S_DATA_ALLOWED) | (1 << S_CUSTOM_CONTRACT);

    handleGetAppConfiguration(0, 0, NULL, 0);

    TEST_ASSERT_EQUAL_HEX8((1 << CONFIG_BIT_DATA_ALLOWED) | (1 << CONFIG_BIT_CUSTOM_CONTRACT),
                           g_captured[0]);
}

void test_unused_high_bits_never_leak(void) {
    N_storage_real = 0xFF;

    handleGetAppConfiguration(0, 0, NULL, 0);

    TEST_ASSERT_EQUAL_HEX8((1 << CONFIG_BIT_DATA_ALLOWED) | (1 << CONFIG_BIT_CUSTOM_CONTRACT) |
                               (1 << CONFIG_BIT_SIGN_BY_HASH),
                           g_captured[0]);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_response_layout_and_version);
    RUN_TEST(test_data_allowed_and_custom_contract_map_to_same_bit);
    RUN_TEST(test_unused_high_bits_never_leak);

    return UNITY_END();
}
