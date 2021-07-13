use cosmwasm_std::Uint128;
use ethabi::{decode as EthDecode, ParamType, Token};
use hex::decode;

use crate::libraries::tm_signature;
use crate::libraries::multi_store;
use crate::libraries::block_header_merkle_path;
use crate::libraries::iavl_merkle_path;
use crate::libraries::result_codec::{Result, ResolveStatus};

#[derive(Debug)]
pub struct RelayBlockParams {
    multi_store: multi_store::Data,
    merkle_paths: block_header_merkle_path::Data,
    signatures: Vec<tm_signature::Data>
}

#[derive(Debug)]
pub struct VerifyDataParams {
    block_height: Uint128,
    result: Result,
    version: Uint128,
    merkle_paths: Vec<iavl_merkle_path::Data>
}

#[derive(Debug)]
pub struct VerifyCountParams {
    block_height: Uint128,
    count: u64,
    version: Uint128,
    merkle_paths: Vec<iavl_merkle_path::Data>
}

pub enum AbiTypes {
    RelayTypes,
    VerifyTypes,
    VerifyCountTypes,
    RelayAndVerifyTypes,
}

pub fn get_abi_types(msg: AbiTypes) -> Vec<ParamType> {
    return match msg {
        AbiTypes::RelayTypes => vec![
            ParamType::Tuple(vec![
                Box::new(ParamType::FixedBytes(32)),
                Box::new(ParamType::FixedBytes(32)),
                Box::new(ParamType::FixedBytes(32)),
                Box::new(ParamType::FixedBytes(32)),
                Box::new(ParamType::FixedBytes(32)),
            ]),
            ParamType::Tuple(vec![
                Box::new(ParamType::FixedBytes(32)),
                Box::new(ParamType::Uint(64)),
                Box::new(ParamType::Uint(64)),
                Box::new(ParamType::Uint(32)),
                Box::new(ParamType::FixedBytes(32)),
                Box::new(ParamType::FixedBytes(32)),
                Box::new(ParamType::FixedBytes(32)),
                Box::new(ParamType::FixedBytes(32)),
            ]),
            ParamType::Array(
                Box::new(ParamType::Tuple(vec![
                    Box::new(ParamType::FixedBytes(32)),
                    Box::new(ParamType::FixedBytes(32)),
                    Box::new(ParamType::Uint(8)),
                    Box::new(ParamType::Bytes),
                    Box::new(ParamType::Bytes),
                ]))
            )
        ],
        AbiTypes::VerifyTypes => vec![
            ParamType::Uint(256),
            ParamType::Tuple(vec![
                Box::new(ParamType::String),
                Box::new(ParamType::Uint(64)),
                Box::new(ParamType::Bytes),
                Box::new(ParamType::Uint(64)),
                Box::new(ParamType::Uint(64)),
                Box::new(ParamType::Uint(64)),
                Box::new(ParamType::Uint(64)),
                Box::new(ParamType::Uint(64)),
                Box::new(ParamType::Uint(64)),
                Box::new(ParamType::Uint(8)),
                Box::new(ParamType::Bytes),
            ]),
            ParamType::Uint(256),
            ParamType::Array(
                Box::new(ParamType::Tuple(vec![
                    Box::new(ParamType::Bool),
                    Box::new(ParamType::Uint(8)),
                    Box::new(ParamType::Uint(256)),
                    Box::new(ParamType::Uint(256)),
                    Box::new(ParamType::FixedBytes(32)),
                ]))
            )
        ],
        AbiTypes::VerifyCountTypes => vec![
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Array(
                Box::new(ParamType::Tuple(vec![
                    Box::new(ParamType::Bool),
                    Box::new(ParamType::Uint(8)),
                    Box::new(ParamType::Uint(256)),
                    Box::new(ParamType::Uint(256)),
                    Box::new(ParamType::FixedBytes(32)),
                ]))
            ),
        ],
        AbiTypes::RelayAndVerifyTypes => vec![
            ParamType::Bytes,
            ParamType::Bytes,
        ],
    }
}

pub fn eth_decode(types: AbiTypes, msg: String) -> Vec<Token> {
    let decoded = EthDecode(get_abi_types(types).as_slice(), decode(msg).unwrap().as_slice());
    decoded.unwrap()
}

pub fn eth_decode_relay_data(data: &Token) -> RelayBlockParams {
    return match eth_decode(AbiTypes::RelayTypes, data.to_string()).as_slice() {
        [Token::Tuple(relay_multi_store), Token::Tuple(relay_merkle_paths), Token::Array(relay_signatures)] => {
            let decoded_multi_store = match relay_multi_store.as_slice() {
                [Token::FixedBytes(mult1), Token::FixedBytes(mult2), Token::FixedBytes(mult3), Token::FixedBytes(mult4), Token::FixedBytes(mult5)] => multi_store::Data {
                    auth_to_ibc_transfer_stores_merkle_hash: mult1.to_vec(),
                    mint_store_merkle_hash: mult2.to_vec(),
                    oracle_iavl_state_hash: mult3.to_vec(),
                    params_to_slash_stores_merkle_hash: mult4.to_vec(),
                    staking_to_upgrade_stores_merkle_hash: mult5.to_vec(),
                },
                _ => panic!("Invalid multi store data"),
            };
            let decoded_merkle_paths = match relay_merkle_paths.as_slice() {
                [Token::FixedBytes(merk1), Token::Uint(merk2), Token::Uint(merk3), Token::Uint(merk4), Token::FixedBytes(merk5), Token::FixedBytes(merk6), Token::FixedBytes(merk7), Token::FixedBytes(merk8)] => block_header_merkle_path::Data {
                    version_and_chain_id_hash: merk1.to_vec(),
                    height: merk2.as_u64(),
                    time_second: merk3.as_u64(),
                    time_nano_second: merk4.as_u32(),
                    last_block_id_and_other: merk5.to_vec(),
                    next_validator_hash_and_consensus_hash: merk6.to_vec(),
                    last_results_hash: merk7.to_vec(),
                    evidence_and_proposer_hash: merk8.to_vec(),
                },
                _ => panic!("Invalid merkle paths"),
            };
            let mut decoded_signatures: Vec<tm_signature::Data> = Vec::new();
            for data_tuple in relay_signatures.as_slice() {
                let data = match data_tuple {
                    Token::Tuple(arr) => arr,
                    _ => panic!("Invalid signatures"),
                };
                let signature_item = match data.as_slice() {
                    [Token::FixedBytes(sign1), Token::FixedBytes(sign2), Token::Uint(sign3), Token::Bytes(sign4), Token::Bytes(sign5)] => tm_signature::Data {
                        r: sign1.to_vec(),
                        s: sign2.to_vec(),
                        v: sign3.byte(0),
                        signed_data_prefix: sign4.to_vec(),
                        signed_data_suffix: sign5.to_vec(),
                    },
                    _ => panic!("Invalid signatures"),
                };
                decoded_signatures.push(signature_item);
            }

            RelayBlockParams {
                multi_store: decoded_multi_store,
                merkle_paths: decoded_merkle_paths,
                signatures: decoded_signatures,
            }
        },
        _ => panic!("Invalid relay block data"),
    };
}

pub fn eth_decode_verify_data(data: &Token) -> VerifyDataParams {
    return match eth_decode(AbiTypes::VerifyTypes, data.to_string()).as_slice() {
        [Token::Uint(verify_block_height), Token::Tuple(verify_result), Token::Uint(verify_version), Token::Array(verify_merkle_paths)] => {
            let decoded_block_height = Uint128::from(verify_block_height.as_u128());
            let decoded_result = match verify_result.as_slice() {
                [Token::String(res1), Token::Uint(res2), Token::Bytes(res3), Token::Uint(res4), Token::Uint(res5), Token::Uint(res6), Token::Uint(res7), Token::Uint(res8), Token::Uint(res9), Token::Uint(res10), Token::Bytes(res11)] => Result {
                    client_id: res1.to_string(),
                    oracle_script_id: res2.as_u64(),
                    params: res3.to_vec(),
                    ask_count: res4.as_u64(),
                    min_count: res5.as_u64(),
                    request_id: res6.as_u64(),
                    ans_count: res7.as_u64(),
                    request_time: res8.as_u64(),
                    resolve_time: res9.as_u64(),
                    resolve_status: ResolveStatus::from_u64(res10.as_u64()),
                    result: res11.to_vec(),
                },
                _ => panic!("Invalid verify result")
            };
            let decoded_version = Uint128::from(verify_version.as_u128());
            let mut decoded_merkle_paths: Vec<iavl_merkle_path::Data> = Vec::new();
            for data_tuple in verify_merkle_paths.as_slice() {
                let data = match data_tuple {
                    Token::Tuple(arr) => arr,
                    _ => panic!("Invalid merkle paths"),
                };
                let merkle_paths_item = match data.as_slice() {
                    [Token::Bool(mer1), Token::Uint(mer2), Token::Uint(mer3), Token::Uint(mer4), Token::FixedBytes(mer5)] => iavl_merkle_path::Data {
                        is_data_on_right: mer1.clone(),
                        sub_tree_height: mer2.byte(0),
                        sub_tree_size: Uint128::from(mer3.as_u128()),
                        sub_tree_version: Uint128::from(mer4.as_u128()),
                        sibling_hash: mer5.to_vec(),
                    },
                    _ => panic!("Invalid merkle paths"),
                };
                decoded_merkle_paths.push(merkle_paths_item);
            }

            VerifyDataParams {
                block_height: decoded_block_height,
                result: decoded_result,
                version: decoded_version,
                merkle_paths: decoded_merkle_paths,
            }
        },
        _ => panic!("Invalid verify oracle data"),
    };
}

pub fn eth_decode_verify_count(data: &Token) -> VerifyCountParams {
    return match eth_decode(AbiTypes::VerifyCountTypes, data.to_string()).as_slice() {
        [Token::Uint(verify_block_height), Token::Uint(verify_count), Token::Uint(verify_version), Token::Array(verify_merkle_paths)] => {
            let decoded_block_height = Uint128::from(verify_block_height.as_u128());
            let decoded_count = verify_count.as_u64();
            let decoded_version = Uint128::from(verify_version.as_u128());
            let mut decoded_merkle_paths: Vec<iavl_merkle_path::Data> = Vec::new();
            for data_tuple in verify_merkle_paths.as_slice() {
                let data = match data_tuple {
                    Token::Tuple(arr) => arr,
                    _ => panic!("Invalid merkle paths"),
                };
                let merkle_paths_item = match data.as_slice() {
                    [Token::Bool(mer1), Token::Uint(mer2), Token::Uint(mer3), Token::Uint(mer4), Token::FixedBytes(mer5)] => iavl_merkle_path::Data {
                        is_data_on_right: mer1.clone(),
                        sub_tree_height: mer2.byte(0),
                        sub_tree_size: Uint128::from(mer3.as_u128()),
                        sub_tree_version: Uint128::from(mer4.as_u128()),
                        sibling_hash: mer5.to_vec(),
                    },
                    _ => panic!("Invalid merkle paths"),
                };
                decoded_merkle_paths.push(merkle_paths_item);
            }

            VerifyCountParams {
                block_height: decoded_block_height,
                count: decoded_count,
                version: decoded_version,
                merkle_paths: decoded_merkle_paths,
            }
        },
        _ => panic!("Invalid verify requests count data"),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eth_decode_relayandverify_test() {
        let calldata = String::from("000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000007C0000000000000000000000000000000000000000000000000000000000000076094FE4A060FCF744C5BFCE1155CF1AB99B386F9170BC1C0105060994AEBEDE65C81A0E5D8922FA8C8FE948D9B4D5698FEFA77E52FB8DF370AE274C43230B4D6697920D562EC07A9979286FDCDA975F943D41D31974B01B8DC5B1B374878B194DAB1AA552EFF4C5CEDE334037AC62520E89AA76FA4326A4C56E9A92996C0BF7E26739AA168868729CA2139B3AC5A066BDEB8BF06A059C2FE35E9D7D65504E26F553F02642D9E70D5C1C493A4F732BFE9C9B95A4A42651703B816EDCFC8FADA53120000000000000000000000000000000000000000000000000000000000000D5A0000000000000000000000000000000000000000000000000000000060AF85440000000000000000000000000000000000000000000000000000000008B55757E5A87E02ABE1B519CE5C57E8E35F033F5E707D368C6DF352EADFEB41FE69E3B26206F2FFDFBB93B83BD917B05B13CA59C12330268611242F5FD5734E673079159FB9C7533CAF1D218DA3AF6D277F6B101C42E3C3B75D784242DA663604DD53C28A153906A4AFDFBF3AEA3F0AA4C4002A7F1B9FB0970200F828C8799DF424B00C00000000000000000000000000000000000000000000000000000000000001C00000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001C0000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000004409B27A5994109DC23F315FFB58B1B37E1FBAD2DD675F580073956581AD029446C042811200893728CF01A56CCFE68F71284F54C973DFE5734EC554760B19DEDB4000000000000000000000000000000000000000000000000000000000000001B00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106E0802115A0D00000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003F122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0C08C58ABE850610D58E9DDA03320962616E64636861696E0043859A093DF6E5E786FF2E1A7D42B5454512E79DDAAB674E2EAE40649B0309D60D67C785A5695106B91A38974B1F7BC0AE0954F18C12A5AB184625A23E38D3AE000000000000000000000000000000000000000000000000000000000000001B00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106D0802115A0D00000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003E122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610E58EC501320962616E64636861696E0000166EB606586E9D932A468F52545A66882DCBF751D974D369FCD058D5B87D2C2F02051DFCE46A45188E4042B007E0F6A9C265F3AAFDAA35F6EBB7586B0BB395C7000000000000000000000000000000000000000000000000000000000000001B00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106D0802115A0D00000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003E122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610CAE7FA02320962616E64636861696E0000DE2B93A4D1CD495ADD00C9E8D1A9BA5FB8D00D335C58254578D730E57DEF3E0171A7BFBCDEECAB7E12BB8BACF50208AF78979F7BFD7F297F404E19842582E448000000000000000000000000000000000000000000000000000000000000001B00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106D0802115A0D00000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003E122408011220DDC9D747EC2D522D6368E7C1BB8F2DCFCA46B739E2EB60D465068E1F4816948A2A0B08C68ABE850610A1DE9202320962616E64636861696E000000000000000000000000000000000000000000000000000000000000000005E00000000000000000000000000000000000000000000000000000000000000D5A000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000003EF00000000000000000000000000000000000000000000000000000000000002A00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001A000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000060AF73DE0000000000000000000000000000000000000000000000000000000060AF73E0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001E0000000000000000000000000000000000000000000000000000000000000000966726F6D5F7363616E0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000F0000000342544300000000000F424000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000092B6826F2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000003EFEB739BB22F48B7F3053A90BA2BA4FE07FAB262CADF8664489565C50FF505B8BD00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000003EFBF32F8B214E4C36170D09B5125395C4EF1ABFA26583E676EF79AA3BA20A535A400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000003EFF732D5B5007633C64B77F6CCECF01ECAB2537501D28ED623B6EC97DA4C1C600500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000A00000000000000000000000000000000000000000000000000000000000003EFF054C5E2412E1519951DBD7A60E2C5EDE41BABA494A6AF6FD0B0BAC4A4695C410000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000D59FFA5A376D4DCA03596020A9A256DF9B73FE42ADEF285DD0ABE7E89A9819144EF");
        if let [relay_data, verify_data] = eth_decode(AbiTypes::RelayAndVerifyTypes, calldata).as_slice() {
            let decoded_relay_data = eth_decode_relay_data(relay_data);
            let decoded_verify_data = eth_decode_verify_data(verify_data);
            println!("RELAY: {:?}", decoded_relay_data);
            println!("VERIFY: {:?}", decoded_verify_data);
        }
    }

    #[test]
    fn eth_decode_relayandverifycount_test() {
        let calldata = String::from("00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000660000000000000000000000000000000000000000000000000000000000000060075C236506323653765775311C9A0370CFE8A30C80D894D4FBBFAA2B94817177AD3BC881551885DF743DDB73FF122E7BFF60596A5AB7A8E0CFC6A0E53BA9DE1CECFC997F04BA6771B7D2B1AD06A89CED14EC0B736C5298FCCFFC3777036FEF98A8332A3B22A636160CC9ED9B57865CE365697716D4891E4F546FCEECBF71788011EAFD3AB6CEB5303CC3BB766F25E997399F1A38E1072EE4DAA8E47D7049FE20B3F02642D9E70D5C1C493A4F732BFE9C9B95A4A42651703B816EDCFC8FADA53120000000000000000000000000000000000000000000000000000000000051F7E0000000000000000000000000000000000000000000000000000000060BF5D4D000000000000000000000000000000000000000000000000000000001E08F35EA563B6EC9B68E5A213B6C842C5C33D836B8F84392337D669BA8D078D8ADF727E6206F2FFDFBB93B83BD917B05B13CA59C12330268611242F5FD5734E673079159FB9C7533CAF1D218DA3AF6D277F6B101C42E3C3B75D784242DA663604DD53C28A153906A4AFDFBF3AEA3F0AA4C4002A7F1B9FB0970200F828C8799DF424B00C00000000000000000000000000000000000000000000000000000000000001C00000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001A000000000000000000000000000000000000000000000000000000000000002E0F9A484B9B53A34A03D17245A0D32819939FD3A7AC874113C9853449FDF7AC5E20E45C6AEC370D693F9CD99DBEDDC2156E93AE56D0C892B09FA1CB410A4F76139000000000000000000000000000000000000000000000000000000000000001C00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106E0802117E1F05000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003F122408011220DD201AD7FEC2FCDDCEF3FF2862A3EEA35DFCDFECCE081D492C1C5AFAECE1B7B82A0C08CFBAFD850610B4D389AB01320962616E64636861696E002F787381B9B2CD736CF46EA3B08EA1C7187690168E7CCF2EECEBFFAC81C359AB4F8B8CEC90B96946DD1B1D103B7E91693E44DAEFEF8E23FA0F9A144F99ACD676000000000000000000000000000000000000000000000000000000000000001B00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106E0802117E1F05000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003F122408011220DD201AD7FEC2FCDDCEF3FF2862A3EEA35DFCDFECCE081D492C1C5AFAECE1B7B82A0C08CFBAFD850610DADF8DAB01320962616E64636861696E0093626CEA9DCAA61B861F64D3568240C6C4A075064FBFF54E66D5A7F1F126C4F10B5D2C6CF40693D84F03E90D9942B5818FE7FD979B77BC41BED5B963C8D2E585000000000000000000000000000000000000000000000000000000000000001B00000000000000000000000000000000000000000000000000000000000000A000000000000000000000000000000000000000000000000000000000000000E000000000000000000000000000000000000000000000000000000000000000106E0802117E1F05000000000022480A2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003F122408011220DD201AD7FEC2FCDDCEF3FF2862A3EEA35DFCDFECCE081D492C1C5AFAECE1B7B82A0C08CFBAFD85061082DDB0A801320962616E64636861696E0000000000000000000000000000000000000000000000000000000000000003C00000000000000000000000000000000000000000000000000000000000051F7E0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000988F000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000051F7D027DBF32A6049857E32F9AAE014FBBD2F64F63D7960D53B22C15B9D12EABC4340000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000051F7D2050E8C634813206790D59B6C7A47432304509CC6E78D1854192AA3895662D460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000051F7DDBA3A429AB0A568451ADE913871925CD0BCC300367992D6B4BE5BBFF74E5475200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000D0000000000000000000000000000000000000000000000000000000000051F7D462A6B932BDFE922B07629358A6082F72C7D89B9ACD5642312FE1F9897B163440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000190000000000000000000000000000000000000000000000000000000000051F7D8832FCF4675CDCB76905763B7C9AD725F681ED55F57105D1A26D994469B336EE");
        if let [relay_data, verify_count_data] = eth_decode(AbiTypes::RelayAndVerifyTypes, calldata).as_slice() {
            let decoded_relay_data = eth_decode_relay_data(relay_data);
            let decoded_verify_count_data = eth_decode_verify_count(verify_count_data);
            println!("RELAY: {:?}", decoded_relay_data);
            println!("VERIFY COUNT: {:?}", decoded_verify_count_data);
        }
    }
}
