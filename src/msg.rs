use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    UpdateValidatorsPower { validators: Vec<ValidatorWithPower> },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    VerifyOracleData { block_height: Uint128, result: Result, version: Uint128, merkle_paths: Vec<iavl_merkle_path::Data> },
    VerifyRequestsCount { block_height: Uint128, count: u64, version: Uint128, merkle_paths: Vec<iavl_merkle_path::Data> },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ValidatorWithPower {
    pub addr: CanonicalAddr,
    pub power: Uint128,
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
