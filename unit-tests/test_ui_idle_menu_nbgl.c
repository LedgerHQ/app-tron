// ui_idle_menu_nbgl.c: settingsControlsCallback() is the only real logic here
// (toggle a settings bit, refresh the switches' displayed state) — captured via
// CMock AddCallback on nbgl_useCaseHomeAndSettings(), same pattern as
// app-boilerplate's test_menu_nbgl.c. onQuitCallback() just forwards to
// os_sched_exit().

#include <string.h>

#include "unity.h"

#include "Mocknbgl_use_case.h"
#include "Mockos_nvm.h"
#include "Mockos_task.h"

#include "ui_idle_menu.h"

// Declared (not defined) in fakes/glyphs.h; TARGET_FLEX's LARGE_ICON_SIZE==64
// picks this specific symbol (see [[phase1-unit-tests]] Phase 6 notes).
const nbgl_icon_details_t C_app_tron_64px = {0};

#define S_DATA_ALLOWED    0
#define S_CUSTOM_CONTRACT 1
#define S_SIGN_BY_HASH    2
uint8_t N_storage_real = 0;

// Not declared in any header (see [[phase1-unit-tests]] Phase 6 notes).
void onQuitCallback(void);

static const nbgl_genericContents_t *g_captured_settings;

static void on_home_and_settings(const char *appName, const nbgl_icon_details_t *appIcon,
                                 const char *tagline, const uint8_t initSettingPage,
                                 const nbgl_genericContents_t *settingContents,
                                 const nbgl_contentInfoList_t *infosList,
                                 const nbgl_homeAction_t *action, nbgl_callback_t quitCallback,
                                 int n) {
    (void) appName;
    (void) appIcon;
    (void) tagline;
    (void) initSettingPage;
    (void) infosList;
    (void) action;
    (void) quitCallback;
    (void) n;
    g_captured_settings = settingContents;
}

static void on_nvm_write(void *dst, void *src, unsigned int len, int n) {
    (void) n;
    memcpy(dst, src, len);
}

void setUp(void) {
    Mocknbgl_use_case_Init();
    Mockos_nvm_Init();
    Mockos_task_Init();
    N_storage_real = 0;
    g_captured_settings = NULL;
}

void tearDown(void) {
    Mocknbgl_use_case_Verify();
    Mockos_nvm_Verify();
    Mockos_task_Verify();
    Mocknbgl_use_case_Destroy();
    Mockos_nvm_Destroy();
    Mockos_task_Destroy();
}

static nbgl_contentActionCallback_t get_controls_callback(void) {
    nbgl_useCaseHomeAndSettings_AddCallback(on_home_and_settings);
    nbgl_useCaseHomeAndSettings_ExpectAnyArgs();
    ui_idle();
    return g_captured_settings->contentsList[0].contentActionCallback;
}

static nbgl_layoutSwitch_t *get_switches(void) {
    return g_captured_settings->contentsList[0].content.switchesList.switches;
}

void test_onQuitCallback_exits(void) {
    os_sched_exit_ExpectAnyArgs();
    onQuitCallback();
}

void test_ui_idle_wires_up_switches_and_quit_callback(void) {
    nbgl_contentActionCallback_t cb = get_controls_callback();
    TEST_ASSERT_NOT_NULL(cb);
    // All settings default off (N_storage_real == 0 in setUp).
    TEST_ASSERT_EQUAL(OFF_STATE, get_switches()[0].initState);
    TEST_ASSERT_EQUAL(OFF_STATE, get_switches()[1].initState);
    TEST_ASSERT_EQUAL(OFF_STATE, get_switches()[2].initState);
}

void test_toggle_data_allowed_flips_bit_and_updates_switch(void) {
    nbgl_contentActionCallback_t cb = get_controls_callback();

    nvm_write_AddCallback(on_nvm_write);
    nvm_write_ExpectAnyArgs();
    cb(FIRST_USER_TOKEN, 0, 0);  // SWITCH_ALLOW_TX_DATA_TOKEN

    TEST_ASSERT_EQUAL(1 << S_DATA_ALLOWED, N_storage_real);
    TEST_ASSERT_EQUAL(ON_STATE, get_switches()[0].initState);
    TEST_ASSERT_EQUAL(OFF_STATE, get_switches()[1].initState);
}

void test_toggle_custom_contract_flips_only_its_own_bit(void) {
    nbgl_contentActionCallback_t cb = get_controls_callback();

    nvm_write_AddCallback(on_nvm_write);
    nvm_write_ExpectAnyArgs();
    cb(FIRST_USER_TOKEN + 1, 0, 0);  // SWITCH_ALLOW_CSTM_CONTRACTS_TOKEN

    TEST_ASSERT_EQUAL(1 << S_CUSTOM_CONTRACT, N_storage_real);
    TEST_ASSERT_EQUAL(OFF_STATE, get_switches()[0].initState);
    TEST_ASSERT_EQUAL(ON_STATE, get_switches()[1].initState);
}

void test_toggle_sign_by_hash_twice_restores_original_state(void) {
    nbgl_contentActionCallback_t cb = get_controls_callback();

    nvm_write_AddCallback(on_nvm_write);
    nvm_write_ExpectAnyArgs();
    cb(FIRST_USER_TOKEN + 2, 0, 0);  // SWITCH_ALLOW_HASH_TX_TOKEN
    TEST_ASSERT_EQUAL(ON_STATE, get_switches()[2].initState);

    nvm_write_ExpectAnyArgs();
    cb(FIRST_USER_TOKEN + 2, 0, 0);

    TEST_ASSERT_EQUAL(0, N_storage_real);
    TEST_ASSERT_EQUAL(OFF_STATE, get_switches()[2].initState);
}

void test_unknown_token_does_nothing(void) {
    nbgl_contentActionCallback_t cb = get_controls_callback();
    // No nvm_write expectation queued — CMock fails the test if it's called anyway.
    cb(0xFF, 0, 0);
    TEST_ASSERT_EQUAL(0, N_storage_real);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_onQuitCallback_exits);
    RUN_TEST(test_ui_idle_wires_up_switches_and_quit_callback);
    RUN_TEST(test_toggle_data_allowed_flips_bit_and_updates_switch);
    RUN_TEST(test_toggle_custom_contract_flips_only_its_own_bit);
    RUN_TEST(test_toggle_sign_by_hash_twice_restores_original_state);
    RUN_TEST(test_unknown_token_does_nothing);

    return UNITY_END();
}
