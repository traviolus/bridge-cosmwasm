use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use prost::encoding::{encode_key, encode_varint, WireType};
use obi::{OBIDecode, OBISchema, OBIEncode};

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, JsonSchema)]
pub enum ResolveStatus {
    ResolveStatusOpenUnspecified = 0,
    ResolveStatusSuccess = 1,
    ResolveStatusFailure = 2,
    ResolveStatusExpired = 3,
}

impl ResolveStatus {
    pub fn from_u64(value: u64) -> ResolveStatus {
        match value {
            0 => ResolveStatus::ResolveStatusOpenUnspecified,
            1 => ResolveStatus::ResolveStatusSuccess,
            2 => ResolveStatus::ResolveStatusFailure,
            3 => ResolveStatus::ResolveStatusExpired,
            _ => ResolveStatus::ResolveStatusOpenUnspecified,
        }
    }

    pub fn to_u64(self) -> u64 {
        match self {
            ResolveStatus::ResolveStatusOpenUnspecified => 0u64,
            ResolveStatus::ResolveStatusSuccess => 1u64,
            ResolveStatus::ResolveStatusFailure => 2u64,
            ResolveStatus::ResolveStatusExpired => 3u64,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, OBIDecode, OBISchema, OBIEncode)]
pub struct Result {
    pub client_id: String,
    pub oracle_script_id: u64,
    pub params: Vec<u8>,
    pub ask_count: u64,
    pub min_count: u64,
    pub request_id: u64,
    pub ans_count: u64,
    pub request_time: u64,
    pub resolve_time: u64,
    pub resolve_status: u64,
    pub result: Vec<u8>,
}

impl Result {
    pub fn encode(self) -> Vec<u8> {
        let mut final_encoded: Vec<u8> = Vec::new();

        if self.client_id.as_bytes().len() > 0usize {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                1u32,
                WireType::LengthDelimited,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.client_id.as_bytes().len() as u64, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
                Vec::from(self.client_id.as_bytes()),
            ].concat();
        }

        if self.oracle_script_id != 0u64 {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                2u32,
                WireType::Varint,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.oracle_script_id, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
            ].concat();
        }

        if self.params.len() > 0 {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                3u32,
                WireType::LengthDelimited,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.params.len() as u64, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
                self.params,
            ].concat();
        }

        if self.ask_count != 0u64 {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                4u32,
                WireType::Varint,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.ask_count, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
            ].concat();
        }

        if self.min_count != 0u64 {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                5u32,
                WireType::Varint,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.min_count, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
            ].concat();
        }

        if self.request_id != 0u64 {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                6u32,
                WireType::Varint,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.request_id, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
            ].concat();
        }

        if self.ans_count != 0u64 {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                7u32,
                WireType::Varint,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.ans_count, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
            ].concat();
        }

        if self.request_time != 0u64 {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                8u32,
                WireType::Varint,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.request_time, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
            ].concat();
        }

        if self.resolve_time != 0u64 {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                9u32,
                WireType::Varint,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.resolve_time, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
            ].concat();
        }

        if self.resolve_status as u64 != 0u64 {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                10u32,
                WireType::Varint,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.resolve_status as u64, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
            ].concat();
        }

        if self.result.len() > 0usize {
            let mut buf_key: Vec<u8> = Vec::new();
            encode_key(
                11u32,
                WireType::LengthDelimited,
                &mut buf_key
            );
            let mut buf_int: Vec<u8> = Vec::new();
            encode_varint(self.result.len() as u64, &mut buf_int);
            final_encoded = [
                final_encoded,
                buf_key,
                buf_int,
                self.result
            ].concat();
        }

        return final_encoded;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn encode_test() {
        let data01 = Result {
            client_id: String::from("tester"),
            oracle_script_id: 1u64,
            params: decode("0000000342544300000000000003e8").unwrap(),
            ask_count: 1u64,
            min_count: 1u64,
            request_id: 2u64,
            ans_count: 1u64,
            request_time: 1591622616u64,
            resolve_time: 1591622618u64,
            resolve_status: ResolveStatus::ResolveStatusSuccess.to_u64(),
            result: decode("00000000009443ee").unwrap(),
        };
        let result01 = data01.encode();
        assert_eq!(result01, decode("0a0674657374657210011a0f0000000342544300000000000003e8200128013002380140d8f7f8f60548daf7f8f60550015a0800000000009443ee").unwrap());

        let data02 = Result {
            client_id: String::from("client_id"),
            oracle_script_id: 1u64,
            params: decode("0000000342544300000000000003e8").unwrap(),
            ask_count: 1u64,
            min_count: 1u64,
            request_id: 1u64,
            ans_count: 1u64,
            request_time: 1591622426u64,
            resolve_time: 1591622429u64,
            resolve_status: ResolveStatus::ResolveStatusFailure.to_u64(),
            result: decode("").unwrap(),
        };
        let result02 = data02.encode();
        assert_eq!(result02, decode("0a09636c69656e745f696410011a0f0000000342544300000000000003e82001280130013801409af6f8f605489df6f8f6055002").unwrap());
    }
}
