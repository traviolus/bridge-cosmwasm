use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use sha2::{Sha256, Digest as sha2Digest};
use sha3::Keccak256;
use cosmwasm_std::CanonicalAddr;
use cosmwasm_crypto::secp256k1_recover_pubkey;
use obi::{OBIDecode, OBISchema, OBIEncode};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, OBIDecode, OBISchema, OBIEncode)]
pub struct Data {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub v: u8,
    pub signed_data_prefix: Vec<u8>,
    pub signed_data_suffix: Vec<u8>,
}

impl Data {
    pub fn recover_signer(self, block_hash: &Vec<u8>) -> CanonicalAddr {
        let mut hasher = Sha256::new();
        hasher.update([self.signed_data_prefix.as_slice(), block_hash.as_slice(), self.signed_data_suffix.as_slice()].concat());
        let hash_result = Vec::from(&hasher.finalize()[..]);
        let signature = [self.r, self.s].concat();
        let addr_result = secp256k1_recover_pubkey(hash_result.as_slice(), signature.as_slice(), self.v-27u8).unwrap();
        let mut hasher = Keccak256::new();
        hasher.update(&addr_result.as_slice()[1..]);
        let result = &hasher.finalize()[12..32];
        return CanonicalAddr::from(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn recover_signer_test() {
        let block_hash = decode("8C36C3D12A378BD7E4E8F26BDECCA68B48390240DA456EE9C3292B6E36756AC4").unwrap();
        let data01 = Data {
            r: decode("6916405D52FF02EC26DD78E831E0A179C89B99CBBDB15C9DA802B75A7621D5EB").unwrap(),
            s: decode("69CF40BE7AC1AA176B13BA4D57EB2B8735A5832014F0DC168EA6F580C51BB222").unwrap(),
            v: 28,
            signed_data_prefix: decode("7808021184C002000000000022480A20").unwrap(),
            signed_data_suffix: decode("12240801122044551F853D916A7C630C0C210C921BAC7D05CE0C249DFC6088C0274F058418272A0C08DE9493850610F0FFAEEB02321362616E642D6C616F7A692D746573746E657431").unwrap(),
        };
        let result01 = data01.recover_signer(&block_hash);
        let data02 = Data {
            r: decode("6A8E3C35DEED991D257BCA9451360BFBE7978D388AF8D2F864A6919FE1083C7E").unwrap(),
            s: decode("14D145DD6BC1A770ACBDF37DAC08DD8076AB888FDA2739BE9B9767B23A387D1E").unwrap(),
            v: 27,
            signed_data_prefix: decode("7808021184C002000000000022480A20").unwrap(),
            signed_data_suffix: decode("12240801122044551F853D916A7C630C0C210C921BAC7D05CE0C249DFC6088C0274F058418272A0C08DE9493850610DAEB8D9C03321362616E642D6C616F7A692D746573746E657431").unwrap(),
        };
        let result02 = data02.recover_signer(&block_hash);
        assert_eq!(result01, CanonicalAddr::from(decode("3b759C4d728e50D5cC04c75f596367829d5b5061").unwrap()));
        assert_eq!(result02, CanonicalAddr::from(decode("49897b9D617AD700b84a935616E81f9f4b5305bc").unwrap()));
    }
}
