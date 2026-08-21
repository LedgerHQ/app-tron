// handleGetAppConfiguration(): response layout is [settings & 0x0f, major, minor,
// patch] — independently checked against the version numbers the build injects
// via -D (see ledger-secure-sdk/Makefile.standard_app) and the low nibble of
// N_settings (the settings byte's high nibble must never leak into this reply).

#include <string.h>

#include "unity.h"

#include "Mockio.h"

#include "handlers.h"
#include "app_errors.h"

uint8_t N_storage_real = 0;

// rdatalist and the buffer it points to are both stack temporaries inside
// handleGetAppConfiguration(); copy the bytes out now, not just the pointer.
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
    N_storage_real = 0x05;

    int ret = handleGetAppConfiguration(0, 0, NULL, 0);

    TEST_ASSERT_EQUAL(0x4242, ret);
    TEST_ASSERT_EQUAL_UINT32(4, g_captured_size);
    TEST_ASSERT_EQUAL_HEX8(0x05, g_captured[0]);
    TEST_ASSERT_EQUAL_HEX8(MAJOR_VERSION, g_captured[1]);
    TEST_ASSERT_EQUAL_HEX8(MINOR_VERSION, g_captured[2]);
    TEST_ASSERT_EQUAL_HEX8(PATCH_VERSION, g_captured[3]);
}

void test_settings_high_nibble_is_masked_out(void) {
    N_storage_real = 0xFF;

    handleGetAppConfiguration(0, 0, NULL, 0);

    TEST_ASSERT_EQUAL_HEX8(0x0F, g_captured[0]);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_response_layout_and_version);
    RUN_TEST(test_settings_high_nibble_is_masked_out);

    return UNITY_END();
}
