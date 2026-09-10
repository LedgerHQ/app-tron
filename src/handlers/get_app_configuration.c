/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2023 Ledger
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
#include <stdint.h>

#include "io.h"

#include "settings.h"
#include "app_errors.h"

// Public wire bits, independent from internal settings.h positions.
#define CONFIG_BIT_DATA_ALLOWED    0
#define CONFIG_BIT_CUSTOM_CONTRACT 1
#define CONFIG_BIT_RESERVED        2
#define CONFIG_BIT_SIGN_BY_HASH    3

int handleGetAppConfiguration(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(workBuffer);
    UNUSED(dataLength);

    uint8_t config = 0;
    config |= HAS_SETTING(S_DATA_ALLOWED) << CONFIG_BIT_DATA_ALLOWED;
    config |= HAS_SETTING(S_CUSTOM_CONTRACT) << CONFIG_BIT_CUSTOM_CONTRACT;
    config |= HAS_SETTING(S_SIGN_BY_HASH) << CONFIG_BIT_SIGN_BY_HASH;

    uint8_t resp[4] = {0};
    resp[0] = config;
    resp[1] = MAJOR_VERSION;
    resp[2] = MINOR_VERSION;
    resp[3] = PATCH_VERSION;
    return io_send_response_pointer(resp, 4, E_OK);
}
