use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use sha2::{Sha256, Digest};
use obi::{OBIDecode, OBISchema, OBIEncode};

use crate::libraries::utils::encode_varint_signed;

// @dev Library for computing iAVL Merkle root from (1) data leaf and (2) a list of "MerklePath"
// from such leaf to the root of the tree. Each Merkle path (i.e. proof component) consists of:
//
// - isDataOnRight: whether the data is on the right subtree of this internal node.
// - subtreeHeight: well, it is the height of this subtree.
// - subtreeVersion: the latest block height that this subtree has been updated.
// - siblingHash: 32-byte hash of the other child subtree
//
// To construct a hash of an internal Merkle node, the hashes of the two subtrees are combined
// with extra data of this internal node. See implementation below. Repeatedly doing this from
// the leaf node until you get to the root node to get the final iAVL Merkle hash.

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, OBIDecode, OBISchema, OBIEncode)]
pub struct Data {
    pub is_data_on_right: bool,
    pub sub_tree_height: u8,
    pub sub_tree_size: u64,
    pub sub_tree_version: u64,
    pub sibling_hash: Vec<u8>,
}

impl Data {
    pub fn get_parent_hash(self, data_subtree_hash: &Vec<u8>) -> Vec<u8> {
        let left_subtree = if self.is_data_on_right { &self.sibling_hash } else { data_subtree_hash };
        let right_subtree = if self.is_data_on_right { data_subtree_hash } else { &self.sibling_hash };
        let mut hasher = Sha256::new();
        hasher.update([
            &[self.sub_tree_height << 1],
            encode_varint_signed(self.sub_tree_size).as_slice(),
            encode_varint_signed(self.sub_tree_version).as_slice(),
            &[32u8],
            left_subtree.as_slice(),
            &[32u8],
            right_subtree.as_slice(),
        ].concat());
        let hash_result = &hasher.finalize()[..];
        return Vec::from(hash_result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn get_parent_hash_test() {
        let data01 = Data {
            is_data_on_right: false,
            sub_tree_height: 1u8,
            sub_tree_size: 2u64,
            sub_tree_version: 436u64,
            sibling_hash: decode("6763EDF42C0D7A3765E8CD9B970AE0E20DC6D3CF5DF0DC63CAD2C85FAFC6A803").unwrap(),
        };
        let subtree_hash01 = decode("22AA109AFDA802E032EB0D4755090E67237F421DDCD5F2491128CB7768EA17A9").unwrap();
        let result01 = data01.get_parent_hash(&subtree_hash01);
        assert_eq!(result01, decode("9CE895E70AEB8767D86B7D80C03B0DE7C6F03422E0A6050B474C737D272ABE2B").unwrap());

        let data02 = Data {
            is_data_on_right: true,
            sub_tree_height: 2u8,
            sub_tree_size: 4u64,
            sub_tree_version: 439u64,
            sibling_hash: decode("92F33601466769D62670A58771C8F8F2695E7142B3852197DD3CA6825B8A3B26").unwrap(),
        };
        let subtree_hash02 = decode("9CE895E70AEB8767D86B7D80C03B0DE7C6F03422E0A6050B474C737D272ABE2B").unwrap();
        let result02 = data02.get_parent_hash(&subtree_hash02);
        assert_eq!(result02, decode("A36F3D44C03782769E03B659BFA473CA668C846E5C04300A08C1B0B33EB7FFA2").unwrap());
    }
}
