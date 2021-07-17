use cosmwasm_std::{to_binary, Api, Binary, Env, Extern, HandleResponse, InitResponse, Querier, StdResult, Storage, ReadonlyStorage, Uint128, StdError, CanonicalAddr, LogAttribute};
use std::ops::Sub;
use sha2::{Sha256, Digest};
use std::str::FromStr;
use hex::{encode as HexEncode, decode as HexDecode};
use prost::encoding::{encode_key, encode_varint, WireType};

use crate::msg::{HandleMsg, InitMsg, QueryMsg, ValidatorWithPower, VerifyOracleDataResponse,
                 VerifyRequestsCountResponse, GetValidatorPowerResponse};
use crate::state::{validators_power, total_validator_power, block_details, BlockDetail, owner, block_details_read, total_validator_power_read, validators_power_read, candidate_block_details, total_validator_power_last_updated_read, CandidateBlockDetail, total_validator_power_last_updated, candidate_block_details_read, verified_results, verified_results_read};
use crate::libraries::multi_store;
use crate::libraries::tm_signature;
use crate::libraries::block_header_merkle_path;
use crate::libraries::iavl_merkle_path;
use crate::libraries::result_codec;
use crate::libraries::utils;
use crate::libraries::abi::{eth_decode, eth_decode_relay_data, eth_decode_verify_data, AbiTypes};

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    owner(&mut deps.storage).save(&deps.api.canonical_address(&env.message.sender)?)?;
    total_validator_power(&mut deps.storage).save(&Uint128::from(0u64))?;
    total_validator_power_last_updated(&mut deps.storage).save(&0u64)?;
    for idx in 0usize..msg.validators.len() {
        let validator = &msg.validators[idx];
        match validators_power_read(&deps.storage).get(&validator.addr.as_slice()) {
            Some(_data) => return Err(StdError::generic_err("DUPLICATION_IN_INITIAL_VALIDATOR_SET")),
            _ => {
                validators_power(&mut deps.storage).set(&validator.addr.as_slice(), validator.power.to_string().as_bytes());
                let old_total_validator_power = total_validator_power_read(&deps.storage).load().unwrap();
                total_validator_power(&mut deps.storage).save(&(old_total_validator_power + validator.power))?;
            }
        }
    }
    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    match msg {
        HandleMsg::RelayBlock { multi_store, merkle_paths, signatures } => try_relay_block(deps, multi_store, merkle_paths, signatures),
        HandleMsg::UpdateValidatorsPower { block_height, validators } => try_update_validators_power(deps, block_height, validators),
        HandleMsg::RelayAndVerifyEth { data } => try_relay_and_verify_eth(deps, data),
        HandleMsg::RelayCandidateBlock { multi_store, merkle_paths } => try_relay_candidate_block(deps, env, multi_store, merkle_paths),
        HandleMsg::AppendSignature { block_height, signatures } => try_append_signature(deps, env, block_height, signatures),
        HandleMsg::VerifyAndSaveResult { block_height, result, version, merkle_paths } => try_verify_and_save_result(deps, block_height, result, version, merkle_paths),
    }
}

pub fn try_update_validators_power<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    block_height: u64,
    validators: Vec<ValidatorWithPower>,
) -> StdResult<HandleResponse> {
    let mut total_validator_power_state = total_validator_power(&mut deps.storage).load().unwrap();
    let mut validators_power_state = validators_power(&mut deps.storage);
    for idx in 0usize..validators.len() {
        let validator = &validators[idx];
        let validator_power = match validators_power_state.get(validator.addr.as_slice()) {
            Some(data) => u128::from_str(String::from_utf8(data).unwrap().as_str()).unwrap(),
            None => 0u128,
        };
        total_validator_power_state = total_validator_power_state.sub(Uint128::from(validator_power)).unwrap();
        validators_power_state.set(validator.addr.as_slice(), validator.power.to_string().as_bytes());
        total_validator_power_state += validator.power;
    }
    total_validator_power_last_updated(&mut deps.storage).save(&block_height)?;
    Ok(HandleResponse::default())
}

pub fn try_relay_block<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    multi_store: multi_store::Data,
    merkle_paths: block_header_merkle_path::Data,
    signatures: Vec<tm_signature::Data>,
) -> StdResult<HandleResponse> {
    let block_details_state_read = block_details_read(&deps.storage);
    match &block_details_state_read.get(&merkle_paths.height.to_be_bytes()) {
        Some(data) => {
            let block_details_state_data: BlockDetail = bincode::deserialize(data).unwrap();
            if  block_details_state_data.oracle_state == multi_store.oracle_iavl_state_hash &&
                block_details_state_data.time_second == merkle_paths.time_second &&
                block_details_state_data.time_nano_second_fraction == merkle_paths.time_nano_second
            {
                return Ok(HandleResponse::default());
            }
        },
        None => {},
    };
    let app_hash = multi_store.clone().get_app_hash();
    let block_header = &merkle_paths.clone().get_block_header(app_hash);
    let mut last_signer_hex = String::from("");
    let mut sum_voting_power = 0u128;
    let validators_power_state = validators_power(&mut deps.storage);
    for idx in 0usize..signatures.len() {
        let signer = signatures[idx].clone().recover_signer(block_header);
        if HexEncode(signer.as_slice()).to_ascii_lowercase() <= last_signer_hex {
            return Err(StdError::generic_err("INVALID_SIGNATURE_SIGNER_ORDER"));
        }
        let value = match validators_power_state.get(signer.as_slice()) {
            Some(data) => u128::from_str(String::from_utf8(data).unwrap().as_str()).unwrap(),
            None => 0u128,
        };
        sum_voting_power += value;
        last_signer_hex = HexEncode(signer.as_slice()).to_ascii_lowercase();
    }
    let total_validator_power_state = total_validator_power(&mut deps.storage);
    if sum_voting_power * 3 <= total_validator_power_state.load().unwrap().u128() * 2 {
        return Err(StdError::generic_err("INSUFFICIENT_VALIDATOR_SIGNATURES"));
    }
    let mut block_details_state = block_details(&mut deps.storage);
    let new_block_detail = BlockDetail {
        oracle_state: multi_store.oracle_iavl_state_hash.clone(),
        time_second: merkle_paths.time_second.clone(),
        time_nano_second_fraction: merkle_paths.time_nano_second.clone()
    };
    block_details_state.set(&merkle_paths.height.to_be_bytes(), &bincode::serialize(&new_block_detail).unwrap());
    Ok(HandleResponse::default())
}

fn try_verify_proof(
    root_hash: Vec<u8>,
    version: Uint128,
    key: Vec<u8>,
    data_hash: Vec<u8>,
    merkle_paths: Vec<iavl_merkle_path::Data>
) -> bool {
    let encoded_version: Vec<u8> = utils::encode_varint_signed(version);

    let mut hasher = Sha256::new();
    hasher.update([
        &[0u8],
        &[2u8],
        encoded_version.as_slice(),
        &[key.len() as u8],
        key.as_slice(),
        &[32u8],
        data_hash.as_slice(),
    ].concat());
    let mut current_merkle_hash = Vec::from(&hasher.finalize()[..]);

    for idx in 0usize..merkle_paths.len() {
        let merkle_path = merkle_paths[idx].clone();
        current_merkle_hash = merkle_path.get_parent_hash(&current_merkle_hash);
    }

    return current_merkle_hash == root_hash;
}

pub fn try_verify_oracle_data<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    block_height: u64,
    result: result_codec::Result,
    version: Uint128,
    merkle_paths: Vec<iavl_merkle_path::Data>
) -> StdResult<VerifyOracleDataResponse> {
    let block_details_state_read = block_details_read(&deps.storage);
    let oracle_state_root = match &block_details_state_read.get(&block_height.to_be_bytes()) {
        Some(data) => {
            let block: BlockDetail = bincode::deserialize(data).unwrap();
            block.oracle_state
        },
        None => return Err(StdError::generic_err("NO_ORACLE_ROOT_STATE_DATA")),
    };
    let mut hasher = Sha256::new();
    hasher.update(result.clone().encode());
    let data_hash = &hasher.finalize()[..];
    let verify_proof = try_verify_proof(oracle_state_root, version, [&[255u8][..], &result.request_id.to_be_bytes()[..]].concat(), Vec::from(data_hash), merkle_paths);
    if !verify_proof {
        return Err(StdError::generic_err("INVALID_ORACLE_DATA_PROOF"));
    }
    Ok(VerifyOracleDataResponse { result })
}

pub fn try_relay_and_verify_eth<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    data: String
) -> StdResult<HandleResponse> {
    return match eth_decode(AbiTypes::RelayAndVerifyTypes, data).as_slice() {
        [relay_data, verify_data] => {
            let decoded_relay_data = eth_decode_relay_data(relay_data).unwrap();
            match try_relay_block(deps, decoded_relay_data.multi_store, decoded_relay_data.merkle_paths, decoded_relay_data.signatures) {
                Ok(_result) => {},
                _ => return Err(StdError::generic_err("RELAY_BLOCK_FAILED")),
            }
            let decoded_verify_data = eth_decode_verify_data(verify_data).unwrap();
            let verify_result = match try_verify_oracle_data(deps, decoded_verify_data.block_height, decoded_verify_data.result, decoded_verify_data.version, decoded_verify_data.merkle_paths) {
                Ok(result) => result.result,
                _ => return Err(StdError::generic_err("VERIFY_ORACLE_DATA_FAILED")),
            };
            let mut res = HandleResponse::default();
            res.data.insert(to_binary(&verify_result).unwrap());
            Ok(res)
        },
        _ => Err(StdError::generic_err("Invalid message")),
    }
}

pub fn try_relay_candidate_block<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    multi_store: multi_store::Data,
    merkle_paths: block_header_merkle_path::Data,
) -> StdResult<HandleResponse> {
    let block_details_state_read = block_details_read(&deps.storage);
    let total_validator_power_last_updated_state_read = total_validator_power_last_updated_read(&deps.storage);
    let candidate_block_state_read = candidate_block_details_read(&deps.storage);
    let block_height_data = merkle_paths.height;

    match &block_details_state_read.get(&block_height_data.to_be_bytes()) {
        Some(_data) => return Err(StdError::generic_err("Block height already relayed")),
        None => {},
    };

    let candidate_block_key = [env.message.sender.as_str().as_bytes(), &block_height_data.to_be_bytes()].concat();
    match &candidate_block_state_read.get(candidate_block_key.as_slice()) {
        Some(_data) => return Err(StdError::generic_err("Candidate block found for this sender and the specified block height [DUPLICATE]")),
        None => {},
    };

    match &total_validator_power_last_updated_state_read.load() {
        Ok(data) => {
            if data > &block_height_data {
                return Err(StdError::generic_err("Relayed data is already outdated"));
            }
        },
        Err(_e) => return Err(StdError::generic_err("Cannot load total validator power last updated state")),
    }

    let app_hash = multi_store.clone().get_app_hash();
    let block_header = merkle_paths.clone().get_block_header(app_hash.to_vec());
    let new_candidate_block_key = [env.message.sender.as_str().as_bytes(), &block_height_data.to_be_bytes()].concat();
    let new_candidate_block_detail = CandidateBlockDetail {
        block_header,
        last_signer_hex: String::from(""),
        sum_voting_power: 0u128,
        block_detail: BlockDetail {
            oracle_state: multi_store.oracle_iavl_state_hash.clone(),
            time_second: merkle_paths.time_second.clone(),
            time_nano_second_fraction: merkle_paths.time_nano_second.clone()
        }
    };
    let mut candidate_block_state = candidate_block_details(&mut deps.storage);
    candidate_block_state.set(new_candidate_block_key.as_slice(), &bincode::serialize(&new_candidate_block_detail).unwrap());
    Ok(HandleResponse::default())
}

pub fn try_append_signature<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    block_height: u64,
    signatures: Vec<tm_signature::Data>,
) -> StdResult<HandleResponse> {
    let block_details_state_read = block_details_read(&deps.storage);
    let total_validator_power_last_updated_state_read = total_validator_power_last_updated_read(&deps.storage);
    let candidate_block_state_read = candidate_block_details_read(&deps.storage);

    match &block_details_state_read.get(&block_height.to_be_bytes()) {
        Some(_data) => return Err(StdError::generic_err("Block height already relayed")),
        None => {},
    };

    match &total_validator_power_last_updated_state_read.load() {
        Ok(data) => {
            if data > &block_height {
                return Err(StdError::generic_err("Relayed data is already outdated"));
            }
        },
        Err(_e) => return Err(StdError::generic_err("Cannot load total validator power last updated state")),
    }

    let candidate_block_key = [env.message.sender.as_str().as_bytes(), &block_height.to_be_bytes()].concat();
    let mut candidate_block_detail: CandidateBlockDetail = match &candidate_block_state_read.get(candidate_block_key.as_slice()) {
        Some(data) => bincode::deserialize(data.as_slice()).unwrap(),
        None => return Err(StdError::generic_err("No candidate block found for this sender and the specified block height")),
    };

    let mut sum_voting_power = candidate_block_detail.clone().sum_voting_power;
    let mut last_signer_hex = candidate_block_detail.clone().last_signer_hex;
    let validators_power_state = validators_power_read(&deps.storage);
    for idx in 0usize..signatures.len() {
        let signer = signatures[idx].clone().recover_signer(&candidate_block_detail.block_header);
        if &HexEncode(signer.as_slice()).to_ascii_lowercase() <= &candidate_block_detail.last_signer_hex {
            return Err(StdError::generic_err("Invalid signature signer order"));
        }
        let value = match validators_power_state.get(signer.as_slice()) {
            Some(data) => u128::from_str(String::from_utf8(data).unwrap().as_str()).unwrap(),
            None => 0u128,
        };
        sum_voting_power += &value;
        last_signer_hex = HexEncode(signer.as_slice()).to_ascii_lowercase();
    }
    let total_validator_power_state = total_validator_power_read(&deps.storage);
    if sum_voting_power * 3 <= total_validator_power_state.load().unwrap().u128() * 2 {
        let mut candidate_block_state = candidate_block_details(&mut deps.storage);
        candidate_block_detail.last_signer_hex = last_signer_hex;
        candidate_block_detail.sum_voting_power = sum_voting_power;
        candidate_block_state.set(&candidate_block_key, &bincode::serialize(&candidate_block_detail).unwrap());
        let mut res = HandleResponse::default();
        res.log.push(LogAttribute { key: "Result".to_string(), value: "Signatures appended; Voting power is still too low".to_string() });
        return Ok(res);
    } else {
        let mut block_details_state = block_details(&mut deps.storage);
        let new_block_detail = BlockDetail {
            oracle_state: candidate_block_detail.block_detail.oracle_state.clone(),
            time_second: candidate_block_detail.block_detail.time_second.clone(),
            time_nano_second_fraction: candidate_block_detail.block_detail.time_nano_second_fraction.clone(),
        };
        block_details_state.set(&block_height.to_be_bytes(), &bincode::serialize(&new_block_detail).unwrap());
        let mut candidate_block_state = candidate_block_details(&mut deps.storage);
        candidate_block_state.remove(&candidate_block_key);
        let mut res = HandleResponse::default();
        res.log.push(LogAttribute { key: "Result".to_string(), value: "Block detail relayed".to_string() });
        return Ok(res);
    }
}

pub fn try_verify_and_save_result<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    block_height: u64,
    result: result_codec::Result,
    version: Uint128,
    merkle_paths: Vec<iavl_merkle_path::Data>,
) -> StdResult<HandleResponse> {
    let verify_result = match try_verify_oracle_data(deps, block_height, result, version, merkle_paths) {
        Ok(result) => result.result,
        _ => return Err(StdError::generic_err("Failed to verify oracle data")),
    };
    let verified_result_key = &verify_result.request_id.to_be_bytes();
    let verified_result_serialized = bincode::serialize(&verify_result).unwrap();
    verified_results(&mut deps.storage).set(verified_result_key, verified_result_serialized.as_slice());
    return Ok(HandleResponse::default());
}

pub fn try_verify_requests_count<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    block_height: u64,
    count: u64,
    version: Uint128,
    merkle_paths: Vec<iavl_merkle_path::Data>
) -> StdResult<VerifyRequestsCountResponse> {
    let block_detail: BlockDetail = match block_details_read(&deps.storage).get(&block_height.to_be_bytes()) {
        Some(data) => bincode::deserialize(data.as_slice()).unwrap(),
        None => return Err(StdError::generic_err("NO_ORACLE_ROOT_STATE_DATA")),
    };
    let mut buf_key: Vec<u8> = Vec::new();
    encode_key(
        1u32,
        WireType::Varint,
        &mut buf_key
    );
    let mut buf_int: Vec<u8> = Vec::new();
    encode_varint(count, &mut buf_int);
    let encoded_count: Vec<u8> = [buf_key, buf_int].concat();
    let mut hasher = Sha256::new();
    hasher.update([utils::encode_varint_unsigned(Uint128::from(encoded_count.len() as u64)), encoded_count].concat());
    let data_hash = &hasher.finalize()[..];
    let verify_proof = try_verify_proof(block_detail.oracle_state, version, HexDecode("0052657175657374436f756e74").unwrap(), Vec::from(data_hash), merkle_paths);
    if !verify_proof {
        return Err(StdError::generic_err("INVALID_ORACLE_DATA_PROOF"));
    }
    Ok(VerifyRequestsCountResponse { time_second: block_detail.time_second, count })
}

pub fn try_get_validator<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    validator: CanonicalAddr,
) -> StdResult<GetValidatorPowerResponse> {
    let validators_power_state_read = validators_power_read(&deps.storage);
    match validators_power_state_read.get(&validator.as_slice()) {
        Some(data) => Ok(GetValidatorPowerResponse { power: Uint128::from(u128::from_str(String::from_utf8(data).unwrap().as_str()).unwrap()) }),
        _ => Err(StdError::not_found("Validator not found")),
    }
}

pub fn try_get_result<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    request_id: u64,
) -> StdResult<result_codec::Result> {
    let verified_results_state_read = verified_results_read(&deps.storage);
    match verified_results_state_read.get(&request_id.to_be_bytes()) {
        Some(data) => {
            let deserialized_result: result_codec::Result = bincode::deserialize(data.as_slice()).unwrap();
            Ok(deserialized_result)
        },
        _ => Err(StdError::not_found("Verified result not found")),
    }
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    match msg {
        QueryMsg::VerifyOracleData { block_height, result, version, merkle_paths } => to_binary(&try_verify_oracle_data(deps, block_height, result, version, merkle_paths).unwrap()),
        QueryMsg::VerifyRequestsCount { block_height, count, version, merkle_paths } => to_binary(&try_verify_requests_count(deps, block_height, count, version, merkle_paths).unwrap()),
        QueryMsg::GetValidatorPower { validator } => to_binary(&try_get_validator(deps, validator).unwrap()),
        QueryMsg::GetResult { request_id } => to_binary(&try_get_result(deps, request_id).unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{CanonicalAddr, from_binary};
    use hex::decode;

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(20, &[]);

        let mut validators_set: Vec<ValidatorWithPower> = Vec::new();
        let a = ValidatorWithPower {
            addr: CanonicalAddr::from(decode("652D89a66Eb4eA55366c45b1f9ACfc8e2179E1c5").unwrap()),
            power: Uint128::from(100u64),
        };
        validators_set.push(a);
        let msg = InitMsg { validators: validators_set };
        let env = mock_env("sender01", &[]);

        let res = init(&mut deps, env, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn update_validator_power_test() {
        let mut deps = mock_dependencies(20, &[]);

        let validators_set: Vec<ValidatorWithPower> = vec![
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("652D89a66Eb4eA55366c45b1f9ACfc8e2179E1c5").unwrap()),
                power: Uint128::from(100u64),
            }
        ];
        let msg = InitMsg { validators: validators_set };
        let env = mock_env("initiator", &[]);
        let _res = init(&mut deps, env, msg).unwrap();

        let msg = QueryMsg::GetValidatorPower { validator: CanonicalAddr::from(decode("652D89a66Eb4eA55366c45b1f9ACfc8e2179E1c5").unwrap()) };
        let res: GetValidatorPowerResponse = from_binary(&query(&deps, msg).unwrap()).unwrap();
        assert_eq!(res, GetValidatorPowerResponse { power: Uint128::from(100u64) });

        let validators_set: Vec<ValidatorWithPower> = vec![
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("652D89a66Eb4eA55366c45b1f9ACfc8e2179E1c5").unwrap()),
                power: Uint128::from(20u64),
            }
        ];
        let msg = HandleMsg::UpdateValidatorsPower { block_height: 3417u64, validators: validators_set };
        let env = mock_env("sender", &[]);
        let _res = handle(&mut deps, env, msg).unwrap();

        let msg = QueryMsg::GetValidatorPower { validator: CanonicalAddr::from(decode("652D89a66Eb4eA55366c45b1f9ACfc8e2179E1c5").unwrap()) };
        let res: GetValidatorPowerResponse = from_binary(&query(&deps, msg).unwrap()).unwrap();
        assert_eq!(res, GetValidatorPowerResponse { power: Uint128::from(20u64) });
    }

    #[test]
    fn relay_block_test() {
        let mut deps = mock_dependencies(20, &[]);

        let validators_set: Vec<ValidatorWithPower> = vec![
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("652D89a66Eb4eA55366c45b1f9ACfc8e2179E1c5").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("88e1cd00710495EEB93D4f522d16bC8B87Cb00FE").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("aAA22E077492CbaD414098EBD98AA8dc1C7AE8D9").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("B956589b6fC5523eeD0d9eEcfF06262Ce84ff260").unwrap()),
                power: Uint128::from(100u64),
            },
        ];
        let msg = InitMsg { validators: validators_set };
        let env = mock_env("sender01", &[]);

        let _res = init(&mut deps, env, msg).unwrap();

        let env = mock_env("msg01", &[]);
        let multi_store_data = multi_store::Data {
            auth_to_ibc_transfer_stores_merkle_hash: decode("94FE4A060FCF744C5BFCE1155CF1AB99B386F9170BC1C0105060994AEBEDE65C").unwrap(),
            mint_store_merkle_hash: decode("81A0E5D8922FA8C8FE948D9B4D5698FEFA77E52FB8DF370AE274C43230B4D669").unwrap(),
            oracle_iavl_state_hash: decode("7920D562EC07A9979286FDCDA975F943D41D31974B01B8DC5B1B374878B194DA").unwrap(),
            params_to_slash_stores_merkle_hash: decode("B1AA552EFF4C5CEDE334037AC62520E89AA76FA4326A4C56E9A92996C0BF7E26").unwrap(),
            staking_to_upgrade_stores_merkle_hash: decode("739AA168868729CA2139B3AC5A066BDEB8BF06A059C2FE35E9D7D65504E26F55").unwrap(),
        };
        let merkle_paths_data = block_header_merkle_path::Data {
            version_and_chain_id_hash: decode("3F02642D9E70D5C1C493A4F732BFE9C9B95A4A42651703B816EDCFC8FADA5312").unwrap(),
            height: 3418u64,
            time_second: 1622115652u64,
            time_nano_second: 146102103u32,
            last_block_id_and_other: decode("E5A87E02ABE1B519CE5C57E8E35F033F5E707D368C6DF352EADFEB41FE69E3B2").unwrap(),
            next_validator_hash_and_consensus_hash: decode("6206F2FFDFBB93B83BD917B05B13CA59C12330268611242F5FD5734E67307915").unwrap(),
            last_results_hash: decode("9FB9C7533CAF1D218DA3AF6D277F6B101C42E3C3B75D784242DA663604DD53C2").unwrap(),
            evidence_and_proposer_hash: decode("8A153906A4AFDFBF3AEA3F0AA4C4002A7F1B9FB0970200F828C8799DF424B00C").unwrap(),
        };
        let signature_data = vec![
            tm_signature::Data {
                r: decode("9B27A5994109DC23F315FFB58B1B37E1FBAD2DD675F580073956581AD029446C").unwrap(),
                s: decode("042811200893728CF01A56CCFE68F71284F54C973DFE5734EC554760B19DEDB4").unwrap(),
                v: 27u8,
                signed_data_prefix: decode("6E0802115A0D00000000000022480A20").unwrap(),
                signed_data_suffix: decode("122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0C08C58ABE850610D58E9DDA03320962616E64636861696E").unwrap(),
            },
            tm_signature::Data {
                r: decode("43859A093DF6E5E786FF2E1A7D42B5454512E79DDAAB674E2EAE40649B0309D6").unwrap(),
                s: decode("0D67C785A5695106B91A38974B1F7BC0AE0954F18C12A5AB184625A23E38D3AE").unwrap(),
                v: 27u8,
                signed_data_prefix: decode("6D0802115A0D00000000000022480A20").unwrap(),
                signed_data_suffix: decode("122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610E58EC501320962616E64636861696E").unwrap(),
            },
            tm_signature::Data {
                r: decode("166EB606586E9D932A468F52545A66882DCBF751D974D369FCD058D5B87D2C2F").unwrap(),
                s: decode("02051DFCE46A45188E4042B007E0F6A9C265F3AAFDAA35F6EBB7586B0BB395C7").unwrap(),
                v: 27u8,
                signed_data_prefix: decode("6D0802115A0D00000000000022480A20").unwrap(),
                signed_data_suffix: decode("122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610CAE7FA02320962616E64636861696E").unwrap(),
            },
            tm_signature::Data {
                r: decode("DE2B93A4D1CD495ADD00C9E8D1A9BA5FB8D00D335C58254578D730E57DEF3E01").unwrap(),
                s: decode("71A7BFBCDEECAB7E12BB8BACF50208AF78979F7BFD7F297F404E19842582E448").unwrap(),
                v: 27u8,
                signed_data_prefix: decode("6D0802115A0D00000000000022480A20").unwrap(),
                signed_data_suffix: decode("122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610A1DE9202320962616E64636861696E").unwrap(),
            },
        ];
        let msg = HandleMsg::RelayBlock {
            multi_store: multi_store_data,
            merkle_paths: merkle_paths_data,
            signatures: signature_data,
        };
        let _res = handle(&mut deps, env, msg).unwrap();
    }

    #[test]
    fn verify_oracle_data_test() {
        let mut deps = mock_dependencies(20, &[]);
        let validators_set: Vec<ValidatorWithPower> = vec![
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("652D89a66Eb4eA55366c45b1f9ACfc8e2179E1c5").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("88e1cd00710495EEB93D4f522d16bC8B87Cb00FE").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("aAA22E077492CbaD414098EBD98AA8dc1C7AE8D9").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("B956589b6fC5523eeD0d9eEcfF06262Ce84ff260").unwrap()),
                power: Uint128::from(100u64),
            },
        ];
        let msg = InitMsg { validators: validators_set };
        let env = mock_env("sender01", &[]);
        let _res = init(&mut deps, env, msg).unwrap();

        let mock_block_detail = BlockDetail {
            oracle_state: decode("7920D562EC07A9979286FDCDA975F943D41D31974B01B8DC5B1B374878B194DA").unwrap(),
            time_second: 1622111198u64,
            time_nano_second_fraction: 1622111200u32,
        };

        block_details(&mut deps.storage).set(&3417u64.to_be_bytes(), &bincode::serialize(&mock_block_detail).unwrap());
        let query_data: BlockDetail = bincode::deserialize(&block_details_read(&deps.storage).get(&3417u64.to_be_bytes()).unwrap()).unwrap();
        assert_eq!(query_data, mock_block_detail);

        let result_data = result_codec::Result {
            client_id: String::from("from_scan"),
            oracle_script_id: 1u64,
            params: decode("0000000342544300000000000f4240").unwrap(),
            ask_count: 1u64,
            min_count: 1u64,
            request_id: 1u64,
            ans_count: 1u64,
            request_time: 1622111198u64,
            resolve_time: 1622111200u64,
            resolve_status: result_codec::ResolveStatus::ResolveStatusSuccess.to_u64(),
            result: decode("000000092b6826f2").unwrap(),
        };
        let merkle_paths_data = vec![
            iavl_merkle_path::Data {
                is_data_on_right: true,
                sub_tree_height: 1u8,
                sub_tree_size: Uint128::from(2u64),
                sub_tree_version: Uint128::from(1007u64),
                sibling_hash: decode("EB739BB22F48B7F3053A90BA2BA4FE07FAB262CADF8664489565C50FF505B8BD").unwrap(),
            },
            iavl_merkle_path::Data {
                is_data_on_right: true,
                sub_tree_height: 2u8,
                sub_tree_size: Uint128::from(4u64),
                sub_tree_version: Uint128::from(1007u64),
                sibling_hash: decode("BF32F8B214E4C36170D09B5125395C4EF1ABFA26583E676EF79AA3BA20A535A4").unwrap(),
            },
            iavl_merkle_path::Data {
                is_data_on_right: true,
                sub_tree_height: 3u8,
                sub_tree_size: Uint128::from(6u64),
                sub_tree_version: Uint128::from(1007u64),
                sibling_hash: decode("F732D5B5007633C64B77F6CCECF01ECAB2537501D28ED623B6EC97DA4C1C6005").unwrap(),
            },
            iavl_merkle_path::Data {
                is_data_on_right: true,
                sub_tree_height: 4u8,
                sub_tree_size: Uint128::from(10u64),
                sub_tree_version: Uint128::from(1007u64),
                sibling_hash: decode("F054C5E2412E1519951DBD7A60E2C5EDE41BABA494A6AF6FD0B0BAC4A4695C41").unwrap(),
            },
            iavl_merkle_path::Data {
                is_data_on_right: true,
                sub_tree_height: 5u8,
                sub_tree_size: Uint128::from(20u64),
                sub_tree_version: Uint128::from(3417u64),
                sibling_hash: decode("FFA5A376D4DCA03596020A9A256DF9B73FE42ADEF285DD0ABE7E89A9819144EF").unwrap(),
            },
        ];
        let msg = QueryMsg::VerifyOracleData {
            block_height: 3417u64,
            result: result_data.clone(),
            version: Uint128::from(1007u64),
            merkle_paths: merkle_paths_data,
        };

        let res = query(&deps, msg).unwrap();
        let res: VerifyOracleDataResponse = from_binary(&res).unwrap();
        assert_eq!(res.result, result_data);
    }

    #[test]
    fn relay_and_verify_test() {
        let mut deps = mock_dependencies(20, &[]);

        let validators_set: Vec<ValidatorWithPower> = vec![
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("652D89a66Eb4eA55366c45b1f9ACfc8e2179E1c5").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("88e1cd00710495EEB93D4f522d16bC8B87Cb00FE").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("aAA22E077492CbaD414098EBD98AA8dc1C7AE8D9").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("B956589b6fC5523eeD0d9eEcfF06262Ce84ff260").unwrap()),
                power: Uint128::from(100u64),
            },
        ];
        let msg = InitMsg { validators: validators_set };
        let env = mock_env("sender01", &[]);
        let _res = init(&mut deps, env, msg).unwrap();

        let env = mock_env("msg01", &[]);
        let calldata = String::from("000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000007C0000000000000000000000000000000000000000000000000000000000000076094FE4A060FCF744C5BFCE1155CF1AB99B386F9170BC1C0105060994AEBEDE65C81A0E5D8922FA8C8FE948D9B4D5698FEFA77E52FB8DF370AE274C43230B4D6697920D562EC07A9979286FDCDA975F943D41D31974B01B8DC5B1B374878B194DAB1AA552EFF4C5CEDE334037AC62520E89AA76FA4326A4C56E9A92996C0BF7E26739AA168868729CA2139B3AC5A066BDEB8BF06A059C2FE35E9D7D65504E26F553F02642D9E70D5C1C493A4F732BFE9C9B95A4A42651703B816EDCFC8FADA53120000000000000000000000000000000000000000000000000000000000000D5A0000000000000000000000000000000000000000000000000000000060AF85440000000000000000000000000000000000000000000000000000000008B55757E5A87E02ABE1B519CE5C57E8E35F033F5E707D368C6DF352EADFEB41FE69E3B26206F2FFDFBB93B83BD917B05B13CA59C12330268611242F5FD5734E673079159FB9C7533CAF1D218DA3AF6D277F6B101C42E3C3B75D784242DA663604DD53C28A153906A4AFDFBF3AEA3F0AA4C4002A7F1B9FB0970200F828C8799DF424B00C00000000000000000000000000000000000000000000000000000000000001C00000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001C0000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000004409B27A5994109DC23F315FFB58B1B37E1FBAD2DD675F580073956581AD029446C042811200893728CF01A56CCFE68F71284F54C973DFE5734EC554760B19DEDB4000000000000000000000000000000000000000000000000000000000000001B00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106E0802115A0D00000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003F122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0C08C58ABE850610D58E9DDA03320962616E64636861696E0043859A093DF6E5E786FF2E1A7D42B5454512E79DDAAB674E2EAE40649B0309D60D67C785A5695106B91A38974B1F7BC0AE0954F18C12A5AB184625A23E38D3AE000000000000000000000000000000000000000000000000000000000000001B00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106D0802115A0D00000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003E122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610E58EC501320962616E64636861696E0000166EB606586E9D932A468F52545A66882DCBF751D974D369FCD058D5B87D2C2F02051DFCE46A45188E4042B007E0F6A9C265F3AAFDAA35F6EBB7586B0BB395C7000000000000000000000000000000000000000000000000000000000000001B00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106D0802115A0D00000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003E122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610CAE7FA02320962616E64636861696E0000DE2B93A4D1CD495ADD00C9E8D1A9BA5FB8D00D335C58254578D730E57DEF3E0171A7BFBCDEECAB7E12BB8BACF50208AF78979F7BFD7F297F404E19842582E448000000000000000000000000000000000000000000000000000000000000001B00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106D0802115A0D00000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003E122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610A1DE9202320962616E64636861696E000000000000000000000000000000000000000000000000000000000000000005E00000000000000000000000000000000000000000000000000000000000000D5A000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000003EF00000000000000000000000000000000000000000000000000000000000002A00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001A000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000060AF73DE0000000000000000000000000000000000000000000000000000000060AF73E0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001E0000000000000000000000000000000000000000000000000000000000000000966726F6D5F7363616E0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000F0000000342544300000000000F424000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000092B6826F2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000003EFEB739BB22F48B7F3053A90BA2BA4FE07FAB262CADF8664489565C50FF505B8BD00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000003EFBF32F8B214E4C36170D09B5125395C4EF1ABFA26583E676EF79AA3BA20A535A400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000003EFF732D5B5007633C64B77F6CCECF01ECAB2537501D28ED623B6EC97DA4C1C600500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000A00000000000000000000000000000000000000000000000000000000000003EFF054C5E2412E1519951DBD7A60E2C5EDE41BABA494A6AF6FD0B0BAC4A4695C410000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000D59FFA5A376D4DCA03596020A9A256DF9B73FE42ADEF285DD0ABE7E89A9819144EF");
        let msg = HandleMsg::RelayAndVerifyEth { data: calldata };
        let _res = handle(&mut deps, env, msg);
    }

    #[test]
    fn relay_candidate_block_test() {
        let mut deps = mock_dependencies(20, &[]);
        let validators_set: Vec<ValidatorWithPower> = vec![
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("652D89a66Eb4eA55366c45b1f9ACfc8e2179E1c5").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("88e1cd00710495EEB93D4f522d16bC8B87Cb00FE").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("aAA22E077492CbaD414098EBD98AA8dc1C7AE8D9").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("B956589b6fC5523eeD0d9eEcfF06262Ce84ff260").unwrap()),
                power: Uint128::from(100u64),
            },
        ];
        let msg = InitMsg { validators: validators_set };
        let env = mock_env("initiator", &[]);
        let _res = init(&mut deps, env, msg);

        let multi_store_data = multi_store::Data {
            auth_to_ibc_transfer_stores_merkle_hash: decode("94FE4A060FCF744C5BFCE1155CF1AB99B386F9170BC1C0105060994AEBEDE65C").unwrap(),
            mint_store_merkle_hash: decode("81A0E5D8922FA8C8FE948D9B4D5698FEFA77E52FB8DF370AE274C43230B4D669").unwrap(),
            oracle_iavl_state_hash: decode("7920D562EC07A9979286FDCDA975F943D41D31974B01B8DC5B1B374878B194DA").unwrap(),
            params_to_slash_stores_merkle_hash: decode("B1AA552EFF4C5CEDE334037AC62520E89AA76FA4326A4C56E9A92996C0BF7E26").unwrap(),
            staking_to_upgrade_stores_merkle_hash: decode("739AA168868729CA2139B3AC5A066BDEB8BF06A059C2FE35E9D7D65504E26F55").unwrap(),
        };
        let merkle_paths_data = block_header_merkle_path::Data {
            version_and_chain_id_hash: decode("3F02642D9E70D5C1C493A4F732BFE9C9B95A4A42651703B816EDCFC8FADA5312").unwrap(),
            height: 3418u64,
            time_second: 1622115652u64,
            time_nano_second: 146102103u32,
            last_block_id_and_other: decode("E5A87E02ABE1B519CE5C57E8E35F033F5E707D368C6DF352EADFEB41FE69E3B2").unwrap(),
            next_validator_hash_and_consensus_hash: decode("6206F2FFDFBB93B83BD917B05B13CA59C12330268611242F5FD5734E67307915").unwrap(),
            last_results_hash: decode("9FB9C7533CAF1D218DA3AF6D277F6B101C42E3C3B75D784242DA663604DD53C2").unwrap(),
            evidence_and_proposer_hash: decode("8A153906A4AFDFBF3AEA3F0AA4C4002A7F1B9FB0970200F828C8799DF424B00C").unwrap(),
        };

        let msg = HandleMsg::RelayCandidateBlock {
            multi_store: multi_store_data,
            merkle_paths: merkle_paths_data.clone(),
        };
        let env = mock_env("sender01", &[]);
        let res = handle(&mut deps, env, msg).unwrap();
        assert_eq!(res.messages.len(), 0);

        let query_data: CandidateBlockDetail = bincode::deserialize(&candidate_block_details_read(&deps.storage).get(["sender01".as_bytes(), &merkle_paths_data.height.to_be_bytes()].concat().as_slice()).unwrap().as_slice()).unwrap();
        assert_eq!(query_data, CandidateBlockDetail { block_header: vec![70, 131, 98, 21, 161, 84, 114, 223, 120, 95, 111, 140, 147, 226, 231, 76, 40, 255, 176, 55, 101, 136, 27, 111, 114, 205, 58, 21, 214, 3, 235, 249], last_signer_hex: String::from(""), sum_voting_power: 0u128, block_detail: BlockDetail { oracle_state: vec![121, 32, 213, 98, 236, 7, 169, 151, 146, 134, 253, 205, 169, 117, 249, 67, 212, 29, 49, 151, 75, 1, 184, 220, 91, 27, 55, 72, 120, 177, 148, 218], time_second: 1622115652, time_nano_second_fraction: 146102103 } } )
    }

    #[test]
    fn append_signatures_test() {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("initiator", &[]);
        let validators_set: Vec<ValidatorWithPower> = vec![
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("652D89a66Eb4eA55366c45b1f9ACfc8e2179E1c5").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("88e1cd00710495EEB93D4f522d16bC8B87Cb00FE").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("aAA22E077492CbaD414098EBD98AA8dc1C7AE8D9").unwrap()),
                power: Uint128::from(100u64),
            },
            ValidatorWithPower {
                addr: CanonicalAddr::from(decode("B956589b6fC5523eeD0d9eEcfF06262Ce84ff260").unwrap()),
                power: Uint128::from(100u64),
            },
        ];
        let msg = InitMsg { validators: validators_set };
        let _res = init(&mut deps, env, msg);

        let multi_store_data = multi_store::Data {
            auth_to_ibc_transfer_stores_merkle_hash: decode("94FE4A060FCF744C5BFCE1155CF1AB99B386F9170BC1C0105060994AEBEDE65C").unwrap(),
            mint_store_merkle_hash: decode("81A0E5D8922FA8C8FE948D9B4D5698FEFA77E52FB8DF370AE274C43230B4D669").unwrap(),
            oracle_iavl_state_hash: decode("7920D562EC07A9979286FDCDA975F943D41D31974B01B8DC5B1B374878B194DA").unwrap(),
            params_to_slash_stores_merkle_hash: decode("B1AA552EFF4C5CEDE334037AC62520E89AA76FA4326A4C56E9A92996C0BF7E26").unwrap(),
            staking_to_upgrade_stores_merkle_hash: decode("739AA168868729CA2139B3AC5A066BDEB8BF06A059C2FE35E9D7D65504E26F55").unwrap(),
        };
        let merkle_paths_data = block_header_merkle_path::Data {
            version_and_chain_id_hash: decode("3F02642D9E70D5C1C493A4F732BFE9C9B95A4A42651703B816EDCFC8FADA5312").unwrap(),
            height: 3418u64,
            time_second: 1622115652u64,
            time_nano_second: 146102103u32,
            last_block_id_and_other: decode("E5A87E02ABE1B519CE5C57E8E35F033F5E707D368C6DF352EADFEB41FE69E3B2").unwrap(),
            next_validator_hash_and_consensus_hash: decode("6206F2FFDFBB93B83BD917B05B13CA59C12330268611242F5FD5734E67307915").unwrap(),
            last_results_hash: decode("9FB9C7533CAF1D218DA3AF6D277F6B101C42E3C3B75D784242DA663604DD53C2").unwrap(),
            evidence_and_proposer_hash: decode("8A153906A4AFDFBF3AEA3F0AA4C4002A7F1B9FB0970200F828C8799DF424B00C").unwrap(),
        };

        let msg = HandleMsg::RelayCandidateBlock {
            multi_store: multi_store_data,
            merkle_paths: merkle_paths_data.clone(),
        };
        let env = mock_env("sender02", &[]);
        let res = handle(&mut deps, env, msg).unwrap();

        let signature_data = vec![
            tm_signature::Data {
                r: decode("9B27A5994109DC23F315FFB58B1B37E1FBAD2DD675F580073956581AD029446C").unwrap(),
                s: decode("042811200893728CF01A56CCFE68F71284F54C973DFE5734EC554760B19DEDB4").unwrap(),
                v: 27u8,
                signed_data_prefix: decode("6E0802115A0D00000000000022480A20").unwrap(),
                signed_data_suffix: decode("122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0C08C58ABE850610D58E9DDA03320962616E64636861696E").unwrap(),
            },
            tm_signature::Data {
                r: decode("43859A093DF6E5E786FF2E1A7D42B5454512E79DDAAB674E2EAE40649B0309D6").unwrap(),
                s: decode("0D67C785A5695106B91A38974B1F7BC0AE0954F18C12A5AB184625A23E38D3AE").unwrap(),
                v: 27u8,
                signed_data_prefix: decode("6D0802115A0D00000000000022480A20").unwrap(),
                signed_data_suffix: decode("122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610E58EC501320962616E64636861696E").unwrap(),
            },
        ];
        let env = mock_env("sender02", &[]);
        let msg = HandleMsg::AppendSignature {
            block_height: 3418u64,
            signatures: signature_data,
        };
        let res = handle(&mut deps, env, msg).unwrap();

        let signature_data = vec![
            tm_signature::Data {
                r: decode("166EB606586E9D932A468F52545A66882DCBF751D974D369FCD058D5B87D2C2F").unwrap(),
                s: decode("02051DFCE46A45188E4042B007E0F6A9C265F3AAFDAA35F6EBB7586B0BB395C7").unwrap(),
                v: 27u8,
                signed_data_prefix: decode("6D0802115A0D00000000000022480A20").unwrap(),
                signed_data_suffix: decode("122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610CAE7FA02320962616E64636861696E").unwrap(),
            },
            tm_signature::Data {
                r: decode("DE2B93A4D1CD495ADD00C9E8D1A9BA5FB8D00D335C58254578D730E57DEF3E01").unwrap(),
                s: decode("71A7BFBCDEECAB7E12BB8BACF50208AF78979F7BFD7F297F404E19842582E448").unwrap(),
                v: 27u8,
                signed_data_prefix: decode("6D0802115A0D00000000000022480A20").unwrap(),
                signed_data_suffix: decode("122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610A1DE9202320962616E64636861696E").unwrap(),
            },
        ];
        let env = mock_env("sender02", &[]);
        let msg = HandleMsg::AppendSignature {
            block_height: 3418u64,
            signatures: signature_data,
        };
        let res = handle(&mut deps, env, msg).unwrap();
    }
}
