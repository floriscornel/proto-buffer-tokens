use chrono::prelude::*;
use ed25519_dalek::{Keypair, PublicKey};
use uuid::Uuid;

use crate::{payload::Payload, singed_payload::SignedPayload};

pub struct Token {
    pub user_id: Uuid,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl Token {
    pub fn from_bytes(bytes: &[u8], public_key: &PublicKey) -> Option<Self> {
        if let Ok(signed_token) = SignedPayload::from_bytes(bytes) {
            signed_token.get_payload(public_key)?.to_token()
        } else {
            None
        }
    }

    pub fn to_bytes(self, keypair: &Keypair) -> Vec<u8> {
        SignedPayload::from_payload(Payload::from_token(self), keypair).to_bytes()
    }

    pub fn from_base64(token_string: &str, public_key: &PublicKey) -> Option<Self> {
        if let Ok(bytes) = base64::decode(token_string) {
            Self::from_bytes(&bytes, public_key)
        } else {
            None
        }
    }

    pub fn to_base64(self, keypair: &Keypair) -> String {
        base64::encode(self.to_bytes(keypair))
    }

    pub fn from_base91(token_string: &str, public_key: &PublicKey) -> Option<Self> {
        Self::from_bytes(&base91::slice_decode(token_string.as_bytes()), public_key)
    }

    pub fn to_base91(self, keypair: &Keypair) -> String {
        String::from_utf8(base91::slice_encode(&self.to_bytes(keypair))).unwrap()
    }
}
