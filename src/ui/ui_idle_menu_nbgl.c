/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2022 Ledger
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
#ifdef HAVE_NBGL

#include "os.h"
#include "ui_idle_menu.h"
#include "glyphs.h"
#include "ux.h"
#include "nbgl_use_case.h"
#include "settings.h"

enum {
    SWITCH_ALLOW_TX_DATA_TOKEN = FIRST_USER_TOKEN,
    SWITCH_ALLOW_CSTM_CONTRACTS_TOKEN,
    SWITCH_ALLOW_HASH_TX_TOKEN
};

#define NB_INFO_FIELDS 3
static const char* const infoTypes[] = {"Version", "Developer", "Copyright"};
static const char* const infoContents[] = {APPVERSION, "Klever", "(c) 2023 Ledger"};

#define NB_SETTINGS_SWITCHES 3
#define SETTING_IDX(token)   (token - SWITCH_ALLOW_TX_DATA_TOKEN)
static uint8_t settings[NB_SETTINGS_SWITCHES] = {S_DATA_ALLOWED, S_CUSTOM_CONTRACT, S_SIGN_BY_HASH};
static nbgl_layoutSwitch_t switches[NB_SETTINGS_SWITCHES];

static void displaySettingsMenu(void);
static void settingsControlsCallback(int token, uint8_t index);
static bool settingsNavCallback(uint8_t page, nbgl_pageContent_t* content);

void onQuitCallback(void) {
    os_sched_exit(-1);
}

static bool settingsNavCallback(uint8_t page, nbgl_pageContent_t* content) {
    if (page == 0) {
        content->type = INFOS_LIST;
        content->infosList.nbInfos = NB_INFO_FIELDS;
        content->infosList.infoTypes = infoTypes;
        content->infosList.infoContents = infoContents;
    } else if (page == 1) {
        switches[0].text = "Transactions data";
        switches[0].subText = "Allow extra data in\ntransactions";
        switches[0].token = SWITCH_ALLOW_TX_DATA_TOKEN;
        switches[0].tuneId = TUNE_TAP_CASUAL;
        switches[0].initState = (HAS_SETTING(S_DATA_ALLOWED)) ? ON_STATE : OFF_STATE;
        switches[1].text = "Custom contracts";
        switches[1].subText = "Allow unverified contracts";
        switches[1].token = SWITCH_ALLOW_CSTM_CONTRACTS_TOKEN;
        switches[1].tuneId = TUNE_TAP_CASUAL;
        switches[1].initState = (HAS_SETTING(S_CUSTOM_CONTRACT)) ? ON_STATE : OFF_STATE;
        switches[2].text = "Blind signing";
        switches[2].subText = "Allow transaction blind signing";
        switches[2].token = SWITCH_ALLOW_HASH_TX_TOKEN;
        switches[2].tuneId = TUNE_TAP_CASUAL;
        switches[2].initState = (HAS_SETTING(S_SIGN_BY_HASH)) ? ON_STATE : OFF_STATE;
        content->type = SWITCHES_LIST;
        content->switchesList.nbSwitches = NB_SETTINGS_SWITCHES;
        content->switchesList.switches = (nbgl_layoutSwitch_t*) switches;
    } else {
        return false;
    }
    return true;
}

static void settingsControlsCallback(int token, uint8_t index) {
    UNUSED(index);
    switch (token) {
        case SWITCH_ALLOW_TX_DATA_TOKEN:
        case SWITCH_ALLOW_CSTM_CONTRACTS_TOKEN:
        case SWITCH_ALLOW_HASH_TX_TOKEN:
            SETTING_TOGGLE(settings[SETTING_IDX(token)]);
            break;
        default:
            PRINTF("Should not happen !");
            break;
    }
}

static void displaySettingsMenu(void) {
    nbgl_useCaseSettings("Tron settings",
                         0,
                         2,
                         false,
                         ui_idle,
                         settingsNavCallback,
                         settingsControlsCallback);
}

void ui_idle(void) {
    nbgl_useCaseHome("Tron",
                     &C_stax_app_tron_64px,
                     NULL,
                     true,
                     displaySettingsMenu,
                     onQuitCallback);
}
#endif  // HAVE_NBGL
