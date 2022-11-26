use ed25519::Signature;
use std::fmt;

pub struct SignedPayload {
    pub signature: [u8; Signature::BYTE_SIZE],
    pub payload: Vec<u8>,
}

impl SignedPayload {
    pub fn new(payload: Vec<u8>, signature: Signature) -> Self {
        Self {
            signature: signature.to_bytes(),
            payload,
        }
    }

    pub fn from_bytes(singed_payload_bytes: &[u8]) -> Result<Self, DecodingError> {
        if singed_payload_bytes.len() < Signature::BYTE_SIZE {
            return Err(DecodingError);
        }
        let mut payload = singed_payload_bytes.to_vec();
        let signature: [u8; Signature::BYTE_SIZE] =
            match payload.drain(0..Signature::BYTE_SIZE).as_slice().try_into() {
                Ok(val) => val,
                Err(_) => return Err(DecodingError),
            };
        Ok(Self { signature, payload })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        vec![self.signature.to_vec(), self.payload.clone()].concat()
    }

    pub fn get_signature(&self) -> Result<Signature, ed25519::Error> {
        Signature::from_bytes(&self.signature)
    }
}

pub struct DecodingError;
impl fmt::Display for DecodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not create SingedPayload from bytes.")
    }
}
