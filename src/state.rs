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

// #[derive(Serialize, Deserialize, Debug, Hash)]
// pub struct State {
//     pub block_details: HashMap<Uint128, BlockDetail>,
//     pub validators_power: HashMap<HumanAddr, Uint128>,
//     pub total_validator_power: Uint128,
// }

pub static OWNER_KEY: &[u8] = b"owner";
pub static BLOCK_DETAILS_KEY: &[u8] = b"block_details";
pub static VALIDATORS_POWER_KEY: &[u8] = b"validators_power";
pub static TOTAL_VALIDATOR_POWER_KEY: &[u8] = b"total_validators_power";

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
