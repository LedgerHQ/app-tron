#ifndef PARSE_H
#define PARSE_H

#include "proto/core/Contract.pb.h"
#include "proto/misc/TronApp.pb.h"

typedef union {
    protocol_TransferContract transfer_contract;
    protocol_TransferAssetContract transfer_asset_contract;
    protocol_TriggerSmartContract trigger_smart_contract;
    protocol_VoteWitnessContract vote_witness_contract;
    protocol_ProposalCreateContract proposal_create_contract;
    protocol_ExchangeCreateContract exchange_create_contract;
    protocol_ExchangeInjectContract exchange_inject_contract;
    protocol_ExchangeWithdrawContract exchange_withdraw_contract;
    protocol_ExchangeTransactionContract exchange_transaction_contract;
    protocol_AccountUpdateContract account_update_contract;
    protocol_ProposalApproveContract proposal_approve_contract;
    protocol_ProposalDeleteContract proposal_delete_contract;
    protocol_WithdrawBalanceContract withdraw_balance_contract;
    protocol_FreezeBalanceContract freeze_balance_contract;
    protocol_UnfreezeBalanceContract unfreeze_balance_contract;
    protocol_AccountPermissionUpdateContract account_permission_update_contract;
} contract_t;

extern contract_t msg;

#endif
