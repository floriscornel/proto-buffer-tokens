use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
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
    pub fn from_bytes(singed_payload_bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(singed_payload_bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    pub fn from_payload(payload: Payload, keypair: &Keypair) -> Self {
        let payload_bytes = payload.encode_to_vec();
        Self {
            signature: keypair.sign(&payload_bytes).to_bytes().to_vec(),
            payload: payload_bytes,
        }
    }

    pub fn verify_signature(&self, public_key: &PublicKey) -> bool {
        match Signature::from_bytes(&self.signature) {
            Ok(sig) => public_key.verify(&self.payload, &sig).is_ok(),
            Err(_) => false,
        }
    }

    pub fn get_payload(&self, public_key: &PublicKey) -> Option<Payload> {
        if self.verify_signature(public_key) {
            match Payload::from_bytes(&self.payload) {
                Ok(payload) => Some(payload),
                Err(_) => None,
            }
        } else {
            None
        }
    }
}
