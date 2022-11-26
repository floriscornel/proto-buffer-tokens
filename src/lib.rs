mod payload;
mod singed_payload;

use crate::{payload::Payload, singed_payload::SignedPayload};
use chrono::prelude::*;
use ed25519::{
    signature::{Signer, Verifier},
    Signature,
};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub struct Token {
    pub user_id: Uuid,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

pub struct TokenSigner<S>
where
    S: Signer<Signature>,
{
    pub keypair: S,
}

impl<S> TokenSigner<S>
where
    S: Signer<Signature>,
{
    pub fn new(keypair: S) -> Self {
        Self { keypair }
    }

    // Creates a signed payload containing the token and signature
    pub fn sign_token(&self, token: &Token) -> Vec<u8> {
        let payload = Payload::from_token(token).as_bytes();
        let signature = self.keypair.sign(&payload);
        SignedPayload::new(payload, signature).to_bytes()
    }
}

pub struct TokenVerifier<V> {
    pub public_key: V,
}

impl<V> TokenVerifier<V>
where
    V: Verifier<Signature>,
{
    pub fn new(public_key: V) -> Self {
        Self { public_key }
    }

    // Verifies a signed payload and extracts the token if valid
    pub fn get_verified_token(&self, signed_payload: &[u8]) -> Option<Token> {
        if let Ok(signed_payload) = SignedPayload::from_bytes(signed_payload) {
            if let Ok(signature) = signed_payload.get_signature() {
                if self
                    .public_key
                    .verify(&signed_payload.payload, &signature)
                    .is_ok()
                {
                    if let Ok(payload) = Payload::from_bytes(&signed_payload.payload) {
                        return payload.to_token();
                    }
                }
            }
        }
        None
    }
}
