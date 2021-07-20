use sha2::{Sha256, Digest};
use hex::decode;
use core::convert::TryFrom;
use num::ToPrimitive;

pub fn merkle_leaf_hash(value: Vec<u8>) -> Vec<u8> {
    let new_value = [&[0u8], value.as_slice()].concat();
    let mut hasher = Sha256::new();
    hasher.update(new_value);
    let result = hasher.finalize();
    return result[..].to_vec();
}

pub fn merkle_inner_hash(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
    let new_value = [&[1u8], [left.as_slice(), right.as_slice()].concat().as_slice()].concat();
    let mut hasher = Sha256::new();
    hasher.update(new_value);
    let result = hasher.finalize();
    return result[..].to_vec();
}

pub fn encode_varint_unsigned(value: u64) -> Vec<u8> {
    let mut temp_value = value.clone().to_u128().unwrap();
    let mut size = 0u128;
    while temp_value > 0u128 {
        size += 1u128;
        temp_value >>= 7;
    }
    let mut result = Vec::new();
    result.resize(size as usize, 0u8);
    temp_value = value.clone().to_u128().unwrap();
    for idx in 0u128..size {
        result[idx as usize] = 128u8 | u8::try_from(temp_value & 127).unwrap();
        temp_value >>= 7;
    }
    let last_idx = (size - 1u128) as usize;
    result[last_idx] &= 127u8;
    return result;
}

pub fn encode_varint_signed(value: u64) -> Vec<u8> {
    return encode_varint_unsigned(value + value);
}

pub fn encode_time(second: u64, nano_second: u32) -> Vec<u8> {
    let mut result = [decode("08").unwrap(), encode_varint_unsigned(second)].concat();
    if nano_second > 0u32 {
        result = [result, decode("10").unwrap(), encode_varint_unsigned(u64::from(nano_second))].concat();
    }
    return result;
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_leaf_hash_test() {
        let result1 = merkle_leaf_hash(decode(String::from("08d1082cc8d85a0833da8815ff1574675c415760e0aff7fb4e32de6de27faf86")).unwrap());
        let result2 = decode("35b401b2a74452d2252df60574e0a6c029885965ae48f006ebddc18e53427e26").unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn merkle_inner_hash_test() {
        let result1 = merkle_inner_hash(decode(String::from("08d1082cc8d85a0833da8815ff1574675c415760e0aff7fb4e32de6de27faf86")).unwrap(), decode(String::from("789411d15a12768a9c3eb99d3453d6ebb4481c2a03ab59cc262a97e25757afe6")).unwrap());
        let result2 = decode("ca48b611419f0848bf0fce9750caca6fd4fb8ef96ba8d7d3ccd4f05bf2af1661").unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn encode_varint_unsigned_test() {
        let mut encode_result = encode_varint_unsigned(116u64);
        assert_eq!(encode_result, decode("74").unwrap());
        encode_result = encode_varint_unsigned(14947u64);
        assert_eq!(encode_result, decode("e374").unwrap());
        encode_result = encode_varint_unsigned(244939043u64);
        assert_eq!(encode_result, decode("a3f2e574").unwrap());
    }

    #[test]
    fn encode_varint_signed_test() {
        let mut encode_result = encode_varint_signed(58u64);
        assert_eq!(encode_result, decode("74").unwrap());
        encode_result = encode_varint_signed(7473u64);
        assert_eq!(encode_result, decode("e274").unwrap());
        encode_result = encode_varint_signed(122469521u64);
        assert_eq!(encode_result, decode("a2f2e574").unwrap());
    }

    #[test]
    fn encode_time_test() {
        let encode_result = encode_time(1605781207u64, 476745924u32);
        assert_eq!(encode_result, decode("08d78dd9fd0510c4a1aae301").unwrap());
    }
}
