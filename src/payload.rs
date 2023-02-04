use byteorder::{ByteOrder, LittleEndian};
use chrono::{LocalResult, TimeZone, Utc};
use std::fmt;
use uuid::Uuid;

use crate::Token;

#[derive(PartialEq, Eq)]
pub struct Payload {
    pub uuid_lhs: u64,
    pub uuid_rhs: u64,
    pub not_before: u64,
    pub not_after: u64,
}

const VARIABLE_COUNT: usize = 4;
const VARIABLE_LENGTH_BYTES: usize = 64 / 8;
const PAYLOAD_LENGTH_BYTES: usize = VARIABLE_COUNT * VARIABLE_LENGTH_BYTES;

impl Payload {
    pub fn from_bytes(payload_bytes: &[u8]) -> Result<Self, DecodingError> {
        if payload_bytes.len() != PAYLOAD_LENGTH_BYTES {
            return Err(DecodingError);
        }

        let mut u64_array = [0; VARIABLE_COUNT];
        LittleEndian::read_u64_into(payload_bytes, &mut u64_array);

        Ok(Self {
            uuid_lhs: u64_array[0],
            uuid_rhs: u64_array[1],
            not_before: u64_array[2],
            not_after: u64_array[3],
        })
    }

    pub fn as_bytes(&self) -> [u8; PAYLOAD_LENGTH_BYTES] {
        let mut bytes = [0; PAYLOAD_LENGTH_BYTES];
        let u64_array = [
            self.uuid_lhs,
            self.uuid_rhs,
            self.not_before,
            self.not_after,
        ];
        LittleEndian::write_u64_into(&u64_array, &mut bytes);
        bytes
    }

    pub fn from_token(token: &Token) -> Self {
        let (uuid_lhs, uuid_rhs) = token.user_id.as_u64_pair();
        Self {
            uuid_lhs,
            uuid_rhs,
            not_before: token.not_before.timestamp() as u64,
            not_after: token.not_after.timestamp() as u64,
        }
    }

    pub fn to_token(&self) -> Option<Token> {
        let LocalResult::Single(not_before) = Utc.timestamp_opt(self.not_before as i64, 0) else {
            return None;
        };
        let LocalResult::Single(not_after) = Utc.timestamp_opt(self.not_after as i64, 0)  else {
            return None;
        };
        Some(Token {
            user_id: Uuid::from_u64_pair(self.uuid_lhs, self.uuid_rhs),
            not_before,
            not_after,
        })
    }
}

pub struct DecodingError;
impl fmt::Display for DecodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not create SingedPayload from bytes.")
    }
}
