use ed25519::Signature;
use prost::{DecodeError, Message};

use crate::payload::Payload;

#[derive(PartialEq, Eq, Message)]
pub struct SignedPayload {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub payload: ::prost::alloc::vec::Vec<u8>,
}

impl SignedPayload {
    pub fn new(payload: Payload, signature: Signature) -> Self {
        Self {
            signature: signature.to_bytes().to_vec(),
            payload: payload.as_bytes(),
        }
    }

    pub fn from_bytes(singed_payload_bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(singed_payload_bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}
