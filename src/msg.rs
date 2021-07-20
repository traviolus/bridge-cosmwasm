use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use obi::{OBIDecode, OBISchema, OBIEncode};

use cosmwasm_std::{CanonicalAddr, Uint128};
use crate::libraries::tm_signature;
use crate::libraries::multi_store;
use crate::libraries::block_header_merkle_path;
use crate::libraries::result_codec::Result;
use crate::libraries::iavl_merkle_path;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub validators: Vec<ValidatorWithPower>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    RelayBlock { multi_store: multi_store::Data, merkle_paths: block_header_merkle_path::Data, signatures: Vec<tm_signature::Data> },
    UpdateValidatorsPower { block_height: u64, validators: Vec<ValidatorWithPower> },
    RelayAndVerifyEth { data: String },
    RelayCandidateBlock { data: String },
    AppendSignature { data: String },
    VerifyAndSaveResult { data: String },
    RemoveCandidateBlock { block_height: u64 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetValidatorPower { validator: CanonicalAddr },
    VerifyOracleData { block_height: u64, result: Result, version: Uint128, merkle_paths: Vec<iavl_merkle_path::Data> },
    VerifyRequestsCount { block_height: u64, count: u64, version: Uint128, merkle_paths: Vec<iavl_merkle_path::Data> },
    GetResult { request_id: u64 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ValidatorWithPower {
    pub addr: CanonicalAddr,
    pub power: Uint128,
}

#[derive(Debug)]
pub struct RelayBlockParams {
    pub multi_store: multi_store::Data,
    pub merkle_paths: block_header_merkle_path::Data,
    pub signatures: Vec<tm_signature::Data>
}

#[derive(Debug, Serialize)]
pub struct VerifyDataParams {
    pub block_height: u64,
    pub result: Result,
    pub version: Uint128,
    pub merkle_paths: Vec<iavl_merkle_path::Data>
}

#[derive(Debug)]
pub struct VerifyCountParams {
    pub block_height: u64,
    pub count: u64,
    pub version: Uint128,
    pub merkle_paths: Vec<iavl_merkle_path::Data>
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct VerifyOracleDataResponse {
    pub result: Result,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct VerifyRequestsCountResponse {
    pub time_second: u64,
    pub count: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct GetValidatorPowerResponse {
    pub power: Uint128,
}

// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// pub struct MultiStoreInputData {
//     pub auth_to_ibc_transfer_stores_merkle_hash: String,
//     pub mint_store_merkle_hash: String,
//     pub oracle_iavl_state_hash: String,
//     pub params_to_slash_stores_merkle_hash: String,
//     pub staking_to_upgrade_stores_merkle_hash: String,
// }
//
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// pub struct BlockHeaderInputData {
//     pub version_and_chain_id_hash: String,
//     pub height: u64,
//     pub time_second: u64,
//     pub time_nano_second: u32,
//     pub last_block_id_and_other: String,
//     pub next_validator_hash_and_consensus_hash: String,
//     pub last_results_hash: String,
//     pub evidence_and_proposer_hash: String,
// }
//
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// pub struct SignatureInputData {
//     pub r: String,
//     pub s: String,
//     pub v: u8,
//     pub signed_data_prefix: String,
//     pub signed_data_suffix: String,
// }
//
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, OBIDecode, OBISchema, OBIEncode)]
// pub struct ResultInputData {
//     pub client_id: String,
//     pub oracle_script_id: u64,
//     pub params: String,
//     pub ask_count: u64,
//     pub min_count: u64,
//     pub request_id: u64,
//     pub ans_count: u64,
//     pub request_time: u64,
//     pub resolve_time: u64,
//     pub resolve_status: u64,
//     pub result: String,
// }
//
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// pub struct IavlInputData {
//     pub is_data_on_right: bool,
//     pub sub_tree_height: u8,
//     pub sub_tree_size: Uint128,
//     pub sub_tree_version: Uint128,
//     pub sibling_hash: String
// }
