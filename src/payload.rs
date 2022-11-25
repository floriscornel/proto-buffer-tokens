use chrono::{LocalResult, TimeZone, Utc};
use prost::{DecodeError, Message};
use uuid::Uuid;

use crate::Token;

#[derive(PartialEq, Eq, Message)]
pub struct Payload {
    #[prost(fixed64, tag = "1")]
    pub uuid_lhs: u64,
    #[prost(fixed64, tag = "2")]
    pub uuid_rhs: u64,
    #[prost(int64, tag = "3")]
    pub not_before: i64,
    #[prost(int64, tag = "4")]
    pub not_after: i64,
}

impl Payload {
    pub fn from_bytes(payload_bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(payload_bytes)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    pub fn from_token(token: &Token) -> Self {
        let (uuid_lhs, uuid_rhs) = token.user_id.as_u64_pair();
        Self {
            uuid_lhs,
            uuid_rhs,
            not_before: token.not_before.timestamp(),
            not_after: token.not_after.timestamp(),
        }
    }

    pub fn to_token(&self) -> Option<Token> {
        let LocalResult::Single(not_before) = Utc.timestamp_opt(self.not_before, 0) else {
            return None;
        };
        let LocalResult::Single(not_after) = Utc.timestamp_opt(self.not_after, 0)  else {
            return None;
        };
        Some(Token {
            user_id: Uuid::from_u64_pair(self.uuid_lhs, self.uuid_rhs),
            not_before,
            not_after,
        })
    }
}
