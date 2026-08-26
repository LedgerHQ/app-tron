/*******************************************************************************
 *   Ledger Blue
 *   (c) 2016 Ledger
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

#include "os.h"
#include "parse.h"

int verifyTokenNameID(const char *tokenId,
                      const char *tokenName,
                      uint8_t decimals,
                      uint8_t *signature,
                      uint8_t signatureLength);
int verifyExchangeID(const unsigned char *exchangeValidation,
                     uint8_t datLength,
                     uint8_t *signature,
                     uint8_t signatureLength);

typedef struct tokenDefinition_t {
    uint8_t address[21];
    char ticker[10];
    uint8_t decimals;
} tokenDefinition_t;

// A contract method that is not a plain TRC20 transfer/approve (e.g. USDD PSM
// buyGem/sellGem, JustLend jUSDD cToken borrow/repay/...). Matched by its unique
// 4-byte selector and the target contract address, then shown with a clear label
// instead of the raw hex selector.
typedef struct knownContractMethod_t {
    uint8_t contract[21];  // 0x41-prefixed contract address
    uint32_t selector;     // 4-byte method selector
    char method[18];       // display name (e.g. "repayBorrowBehalf")
    char token[10];        // display token name (e.g. "USDD", "jUSDD")
    uint8_t decimals;
    uint8_t hasAddress;     // 1 if first argument is an address to display
    uint8_t labelOnly;      // 1 if args can't be decoded to (uint256) or (address,uint256)
    char contractName[24];  // display name of the contract (e.g. "JustLend Distributor")
} knownContractMethod_t;

#define NUM_TOKENS_TRC20 384

#define NUM_PROTOCOL_METHODS 8

extern tokenDefinition_t const TOKENS_TRC20[NUM_TOKENS_TRC20];

extern const uint8_t SELECTOR[][4];

extern knownContractMethod_t const PROTOCOL_METHODS[NUM_PROTOCOL_METHODS];

// Returns the index of the protocol method with the given selector, or -1.
int8_t findProtocolMethodBySelector(uint32_t selector);
