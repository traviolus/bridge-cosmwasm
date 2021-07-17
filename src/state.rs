use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use cosmwasm_std::{Uint128, Storage, CanonicalAddr};
use cosmwasm_storage::{singleton, singleton_read, ReadonlySingleton, Singleton, PrefixedStorage,
ReadonlyPrefixedStorage};

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct BlockDetail {
    pub oracle_state: Vec<u8>,
    pub time_second: u64,
    pub time_nano_second_fraction: u32, // between 0 to 10^9
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct CandidateBlockDetail {
    pub block_header: Vec<u8>,
    pub last_signer_hex: String,
    pub sum_voting_power: u128,
    pub block_detail: BlockDetail,
}

pub static OWNER_KEY: &[u8] = b"owner";
pub static BLOCK_DETAILS_KEY: &[u8] = b"block_details";
pub static VALIDATORS_POWER_KEY: &[u8] = b"validators_power";
pub static TOTAL_VALIDATOR_POWER_KEY: &[u8] = b"total_validators_power";
pub static CANDIDATE_BLOCK_DETAILS: &[u8] = b"candidate_block_details";
pub static VERIFIED_RESULTS_KEY: &[u8] = b"verified_results";
pub static TOTAL_VALIDATOR_POWER_LAST_UPDATED: &[u8] = b"total_validator_power_last_updated";

pub fn owner<S: Storage>(storage: &mut S) -> Singleton<S, CanonicalAddr> {
    singleton(storage, OWNER_KEY)
}

pub fn owner_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, CanonicalAddr> {
    singleton_read(storage, OWNER_KEY)
}

pub fn block_details<S: Storage>(storage: &mut S) -> PrefixedStorage<S> {
    PrefixedStorage::new(BLOCK_DETAILS_KEY, storage)
}

pub fn block_details_read<S: Storage>(storage: &S) -> ReadonlyPrefixedStorage<S> {
    ReadonlyPrefixedStorage::new(BLOCK_DETAILS_KEY, storage)
}

pub fn validators_power<S: Storage>(storage: &mut S) -> PrefixedStorage<S> {
    PrefixedStorage::new(VALIDATORS_POWER_KEY, storage)
}

pub fn validators_power_read<S: Storage>(storage: &S) -> ReadonlyPrefixedStorage<S> {
    ReadonlyPrefixedStorage::new(VALIDATORS_POWER_KEY, storage)
}

pub fn total_validator_power<S: Storage>(storage: &mut S) -> Singleton<S, Uint128> {
    singleton(storage, TOTAL_VALIDATOR_POWER_KEY)
}

pub fn total_validator_power_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, Uint128> {
    singleton_read(storage, TOTAL_VALIDATOR_POWER_KEY)
}

pub fn candidate_block_details<S: Storage>(storage: &mut S) -> PrefixedStorage<S> {
    PrefixedStorage::new(CANDIDATE_BLOCK_DETAILS, storage)
}

pub fn candidate_block_details_read<S: Storage>(storage: &S) -> ReadonlyPrefixedStorage<S> {
    ReadonlyPrefixedStorage::new(CANDIDATE_BLOCK_DETAILS, storage)
}

pub fn verified_results<S: Storage>(storage: &mut S) -> PrefixedStorage<S> {
    PrefixedStorage::new(VERIFIED_RESULTS_KEY, storage)
}

pub fn verified_results_read<S: Storage>(storage: &S) -> ReadonlyPrefixedStorage<S> {
    ReadonlyPrefixedStorage::new(VERIFIED_RESULTS_KEY, storage)
}

pub fn total_validator_power_last_updated<S: Storage>(storage: &mut S) -> Singleton<S, u64> {
    singleton(storage, TOTAL_VALIDATOR_POWER_LAST_UPDATED)
}

pub fn total_validator_power_last_updated_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, u64> {
    singleton_read(storage, TOTAL_VALIDATOR_POWER_LAST_UPDATED)
}
