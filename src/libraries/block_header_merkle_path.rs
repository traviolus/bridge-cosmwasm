use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use obi::{OBIDecode, OBISchema, OBIEncode};

use crate::libraries::utils;

// @dev Library for computing Tendermint's block header hash from app hash, time, and height.
//
// In Tendermint, a block header hash is the Merkle hash of a binary tree with 14 leaf nodes.
// Each node encodes a data piece of the blockchain. The notable data leaves are: [A] app_hash,
// [2] height, and [3] - time. All data pieces are combined into one 32-byte hash to be signed
// by block validators. The structure of the Merkle tree is shown below.
//
//                      _____________[BlockHeader]____________
//                     |                                      \
//                   [3A]                                    [3B]
//                 /      \                                /      \
//         [2A]                [2B]                [2C]                [2D]
//        /    \              /    \              /    \              /    \
//    [1A]      [1B]      [1C]      [1D]      [1E]      [1F]        [C]    [D]
//    /  \      /  \      /  \      /  \      /  \      /  \
//  [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]  [8]  [9]  [A]  [B]
//
//  [0] - version               [1] - chain_id            [2] - height        [3] - time
//  [4] - last_block_id         [5] - last_commit_hash    [6] - data_hash     [7] - validators_hash
//  [8] - next_validators_hash  [9] - consensus_hash      [A] - app_hash      [B] - last_results_hash
//  [C] - evidence_hash         [D] - proposer_address
//
// Notice that NOT all leaves of the Merkle tree are needed in order to compute the Merkle
// root hash, since we only want to validate the correctness of [A], [2], and [3]. In fact, only
// [1A], [2B], [1E], [B], and [2D] are needed in order to compute [BlockHeader].

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, OBIDecode, OBISchema, OBIEncode)]
pub struct Data {
    pub version_and_chain_id_hash: Vec<u8>, // [1A]
    pub height: u64, // [2]
    pub time_second: u64, // [3]
    pub time_nano_second: u32, // between 0 to 10^9 [3]
    pub last_block_id_and_other: Vec<u8>, // [2B]
    pub next_validator_hash_and_consensus_hash: Vec<u8>, // [1E]
    pub last_results_hash: Vec<u8>, // [B]
    pub evidence_and_proposer_hash: Vec<u8>, // [2D]
}

impl Data {
    pub fn get_block_header(self, app_hash: Vec<u8>) -> Vec<u8> {
        return utils::merkle_inner_hash( // [BlockHeader]
            utils::merkle_inner_hash( // [3A]
                utils::merkle_inner_hash( // [2A]
                    self.version_and_chain_id_hash, // [1A]
                    utils::merkle_inner_hash( // [1B]
                        utils::merkle_leaf_hash( // [2]
                            [&[8u8], utils::encode_varint_unsigned(self.height).as_slice()].concat()
                        ),
                        utils::merkle_leaf_hash( // [3]
                            utils::encode_time(
                                self.time_second,
                                self.time_nano_second
                            )
                        )
                    )
                ),
                self.last_block_id_and_other // [2B]
            ),
            utils::merkle_inner_hash( // [3B]
                utils::merkle_inner_hash( // [2C]
                    self.next_validator_hash_and_consensus_hash, // [1E]
                    utils::merkle_inner_hash( // [1F]
                        utils::merkle_leaf_hash( // [A]
                            [&[10u8], &[32u8], app_hash.as_slice()].concat()
                        ),
                        self.last_results_hash // [B]
                    )
                ),
                self.evidence_and_proposer_hash // [2D]
            )
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn get_block_header_test() {
        let data = Data {
            version_and_chain_id_hash: decode("E2082320A69AC962782E931075D14B13CD98F3E7FC5D8580D4EB60FBC0D622D5").unwrap(),
            height: 180356u64,
            time_second: 1621412443u64,
            time_nano_second: 922160838u32,
            last_block_id_and_other: decode("4021DC4D787B5F0842D8F14EA4C87BDF2AAB95F201036D4A3E0EF1E9D2E7816B").unwrap(),
            next_validator_hash_and_consensus_hash: decode("025E8953C93B0A8B399568160FFE8B29FC5394CAF235B07EC41DF1391ACF1A35").unwrap(),
            last_results_hash: decode("68BD2057602D88D956B166F2FC88D1B6E18CE4846CCA241558FBBD0062DC6344").unwrap(),
            evidence_and_proposer_hash: decode("23198513920C899234DA2518EDF1D35109AEB9BE637BAA272A0D94DB5530745A").unwrap(),
        };
        let app_hash = decode("E500B3DD21816EE04BE5E77271EC0D8286B8AFF81EF96344FED74B52992E6D23").unwrap();
        let result = data.get_block_header(app_hash);
        assert_eq!(result, decode("8C36C3D12A378BD7E4E8F26BDECCA68B48390240DA456EE9C3292B6E36756AC4").unwrap());
    }
}
