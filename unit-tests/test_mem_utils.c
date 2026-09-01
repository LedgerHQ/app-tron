#include "unity.h"

#include "Mockapp_mem_utils.h"

#include "mem_utils.h"

void setUp(void) {
    Mockapp_mem_utils_Init();
}

void tearDown(void) {
    Mockapp_mem_utils_Verify();
    Mockapp_mem_utils_Destroy();
}

static void *g_captured_heap_start;
static size_t g_captured_heap_size;

static bool init_capture_cb(void *heap_start, size_t heap_size, int cmock_num_calls) {
    (void) cmock_num_calls;
    g_captured_heap_start = heap_start;
    g_captured_heap_size = heap_size;
    return true;
}

void test_app_mem_init_forwards_a_nonnull_buffer_and_its_size(void) {
    mem_utils_init_AddCallback(init_capture_cb);
    mem_utils_init_ExpectAnyArgsAndReturn(true);

    bool ok = app_mem_init();

    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_NOT_NULL(g_captured_heap_start);
    TEST_ASSERT_EQUAL_UINT32(1024 * 8, g_captured_heap_size);
}

void test_app_mem_init_forwards_failure(void) {
    mem_utils_init_ExpectAnyArgsAndReturn(false);

    TEST_ASSERT_FALSE(app_mem_init());
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_app_mem_init_forwards_a_nonnull_buffer_and_its_size);
    RUN_TEST(test_app_mem_init_forwards_failure);

    return UNITY_END();
}
