use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use hex::decode;
use sha2::{Sha256, Digest};
use obi::{OBIDecode, OBISchema, OBIEncode};

use crate::libraries::utils;

// MultiStoreProof stores a compact of other Cosmos-SDK modules' storage hash in multistore to
// compute (in combination with oracle store hash) Tendermint's application state hash at a given block.
//                         ________________[AppHash]_______________
//                        /                                        \
//             _______[I10]______                          _______[I11]________
//            /                  \                        /                    \
//       __[I6]__             __[I7]__                __[I8]__              __[I9]__
//      /         \          /         \            /          \           /         \
//    [I0]       [I1]     [I2]        [I3]        [I4]        [I5]       [C]         [D]
//   /   \      /   \    /    \      /    \      /    \      /    \
// [0]   [1]  [2]   [3] [4]   [5]  [6]    [7]  [8]    [9]  [A]    [B]
// [0] - auth   [1] - bank     [2] - capability  [3] - dist    [4] - evidence
// [5] - gov    [6] - ibchost  [7] - ibctransfer [8] - mint    [9] - oracle
// [A] - params [B] - slashing [C] - staking     [D] - upgrade
// Notice that NOT all leaves of the Merkle tree are needed in order to compute the Merkle
// root hash, since we only want to validate the correctness of [9] In fact, only
// [8], [I5], [I9], and [I10] are needed in order to compute [AppHash].

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, OBIDecode, OBISchema, OBIEncode)]
pub struct Data {
    pub auth_to_ibc_transfer_stores_merkle_hash: Vec<u8>, // [I10]
    pub mint_store_merkle_hash: Vec<u8>, // [8]
    pub oracle_iavl_state_hash: Vec<u8>, // [9]
    pub params_to_slash_stores_merkle_hash: Vec<u8>, // [I5]
    pub staking_to_upgrade_stores_merkle_hash: Vec<u8>, // [I9]
}

impl Data {
    pub fn get_app_hash(self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.oracle_iavl_state_hash);
        let hashed_oracle_iavl_state_hash = &hasher.finalize()[..];

        return utils::merkle_inner_hash( // [AppHash]
            self.auth_to_ibc_transfer_stores_merkle_hash, // [I10]
            utils::merkle_inner_hash( // [I11]
                utils::merkle_inner_hash( // [I8]
                    utils::merkle_inner_hash( // [I4]
                        self.mint_store_merkle_hash, // [8]
                        utils::merkle_leaf_hash( // [9]
                            [decode("066f7261636c6520").unwrap().as_slice(), hashed_oracle_iavl_state_hash].concat()
                        )
                    ),
                    self.params_to_slash_stores_merkle_hash // [I5]
                ),
                self.staking_to_upgrade_stores_merkle_hash // [I9]
            )
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_app_hash_test() {
        let data = Data {
            auth_to_ibc_transfer_stores_merkle_hash: decode("7FA9321529B99458C89F4B1B1626B2C2C04C41EB0E47FCBD2FBA7EA78B9D65D7").unwrap(),
            mint_store_merkle_hash: decode("AE7F0418BCE8C09D2C33B981A6EA261BA330C75D88DC1637A452BCC65C5AE8C1").unwrap(),
            oracle_iavl_state_hash: decode("98FCDC7C08F480BE7A8268A07B8635333D902847EC0EA5606F33D43A2E936C0E").unwrap(),
            params_to_slash_stores_merkle_hash: decode("E0004F2B2DDAB5F19E2027F8CDE6CBE7FC2A0B7BFA2EF48BB614F8591113CBF0").unwrap(),
            staking_to_upgrade_stores_merkle_hash: decode("EF14C7E1F5EDCD25AB616E394B6ED8961F66ED2BC363607B50FCF3BA2760C6F8").unwrap(),
        };
        let result = data.get_app_hash();
        assert_eq!(result, decode("E500B3DD21816EE04BE5E77271EC0D8286B8AFF81EF96344FED74B52992E6D23").unwrap())
    }
}
