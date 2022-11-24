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
    pub fn from_base64(token_string: &str, public_key: &PublicKey) -> Option<Self> {
        match base64::decode(token_string) {
            Ok(singed_payload_bytes) => match SignedPayload::from_bytes(&singed_payload_bytes) {
                Ok(signed_token) => {
                    if let Some(payload) = signed_token.get_payload(public_key) {
                        payload.to_token()
                    } else {
                        None
                    }
                }
                Err(_) => None,
            },
            Err(_) => None,
        }
    }

    pub fn to_base64(self, keypair: &Keypair) -> String {
        let payload = Payload::from_token(self);
        let singed_payload = SignedPayload::from_payload(payload, keypair);
        base64::encode(singed_payload.to_bytes())
    }

    pub fn from_base91(token_string: &str, public_key: &PublicKey) -> Option<Self> {
        match SignedPayload::from_bytes(&base91::slice_decode(token_string.as_bytes())) {
            Ok(signed_token) => {
                if let Some(payload) = signed_token.get_payload(public_key) {
                    payload.to_token()
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    pub fn to_base91(self, keypair: &Keypair) -> String {
        let payload = Payload::from_token(self);
        let singed_payload = SignedPayload::from_payload(payload, keypair);
        let encoded = base91::slice_encode(&singed_payload.to_bytes());
        String::from_utf8(encoded).unwrap()
    }
}
