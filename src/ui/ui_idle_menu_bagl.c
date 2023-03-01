/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2018 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#ifdef HAVE_BAGL
#include "os.h"
#include "os_io_seproxyhal.h"
#include "ui_idle_menu.h"
#include "ux.h"
#include "settings.h"

#if defined(HAVE_UX_FLOW)

static void display_settings(const ux_flow_step_t* const);
static void switch_settings_contract_data();
static void switch_settings_custom_contracts();
static void switch_settings_truncate_address();
static void switch_settings_sign_by_hash();
static char settings_param_value[40];

#if defined(TARGET_NANOS)

UX_STEP_VALID(ux_settings_flow_1_step,
              bnnn_paging,
              switch_settings_contract_data(),
              {
                  .title = "Transactions Data",
                  .text = settings_param_value,
              });

UX_STEP_VALID(ux_settings_flow_2_step,
              bnnn_paging,
              switch_settings_custom_contracts(),
              {.title = "Custom Contracts", .text = settings_param_value + 12});

UX_STEP_VALID(ux_settings_flow_3_step,
              bnnn_paging,
              switch_settings_truncate_address(),
              {.title = "Truncate Address", .text = settings_param_value + 24});

UX_STEP_VALID(ux_settings_flow_4_step,
              bnnn_paging,
              switch_settings_sign_by_hash(),
              {.title = "Sign by Hash", .text = settings_param_value + 28});

#else

UX_STEP_VALID(ux_settings_flow_1_step,
              bnnn,
              switch_settings_contract_data(),
              {
                  "Transactions data",
                  "Allow extra data",
                  "in transactions",
                  settings_param_value,
              });

UX_STEP_VALID(ux_settings_flow_2_step,
              bnnn,
              switch_settings_custom_contracts(),
              {"Custom contracts", "Allow unverified", "contracts", settings_param_value + 12});

UX_STEP_VALID(ux_settings_flow_3_step,
              bnnn,
              switch_settings_truncate_address(),
              {"Truncate Address", "Display truncated", "addresses", settings_param_value + 24});

UX_STEP_VALID(ux_settings_flow_4_step,
              bnnn,
              switch_settings_sign_by_hash(),
              {"Sign by Hash", "Allow hash-only", "transactions", settings_param_value + 28});

#endif

UX_STEP_VALID(ux_settings_flow_5_step,
              pb,
              ui_idle(),
              {
                  &C_icon_back,
                  "Back",
              });

UX_DEF(ux_settings_flow,
       &ux_settings_flow_1_step,
       &ux_settings_flow_2_step,
       &ux_settings_flow_3_step,
       &ux_settings_flow_4_step,
       &ux_settings_flow_5_step);

static void display_settings(const ux_flow_step_t* const start_step) {
    strlcpy(settings_param_value, (HAS_SETTING(S_DATA_ALLOWED) ? "Allowed" : "NOT Allowed"), 12);
    strlcpy(settings_param_value + 12,
            (HAS_SETTING(S_CUSTOM_CONTRACT) ? "Allowed" : "NOT Allowed"),
            12);
    strlcpy(settings_param_value + 24, (HAS_SETTING(S_TRUNCATE_ADDRESS) ? "Yes" : "No"), 4);
    strlcpy(settings_param_value + 28,
            (HAS_SETTING(S_SIGN_BY_HASH) ? "Allowed" : "NOT Allowed"),
            sizeof(settings_param_value) - 28);
    ux_flow_init(0, ux_settings_flow, start_step);
}

static void switch_settings_contract_data() {
    SETTING_TOGGLE(S_DATA_ALLOWED);
    display_settings(&ux_settings_flow_1_step);  // same effect as NULL
}

static void switch_settings_custom_contracts() {
    SETTING_TOGGLE(S_CUSTOM_CONTRACT);
    display_settings(&ux_settings_flow_2_step);
}

static void switch_settings_truncate_address() {
    SETTING_TOGGLE(S_TRUNCATE_ADDRESS);
    display_settings(&ux_settings_flow_3_step);
}

static void switch_settings_sign_by_hash() {
    SETTING_TOGGLE(S_SIGN_BY_HASH);
    display_settings(&ux_settings_flow_4_step);
}

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_idle_flow_1_step,
             pnn,
             {
                 &C_icon,
                 "Application",
                 "is ready",
             });
UX_STEP_NOCB(ux_idle_flow_2_step,
             bn,
             {
                 "Version",
                 APPVERSION,
             });
UX_STEP_VALID(ux_idle_flow_3_step,
              pb,
              display_settings(NULL),
              {
                  &C_icon_coggle,
                  "Settings",
              });

UX_STEP_VALID(ux_idle_flow_4_step,
              pb,
              os_sched_exit(-1),
              {
                  &C_icon_dashboard_x,
                  "Quit",
              });

UX_DEF(ux_idle_flow,
       &ux_idle_flow_1_step,
       &ux_idle_flow_2_step,
       &ux_idle_flow_3_step,
       &ux_idle_flow_4_step);
#endif  // HAVE_UX_FLOW

void ui_idle(void) {
#if defined(HAVE_UX_FLOW)
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);
#endif  // #if TARGET_ID
}
#endif  // HAVE_BAGL
