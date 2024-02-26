
use ed25519_dalek::{PublicKey, SecretKey, Signer};
use crate::{Algorithm, EncodingKey, Header};
use crate::errors::Result;
use crate::serialization::b64_encode;
use crate::crypto::error;

/// The actual EdDSA signing + encoding
/// The key needs to be in PKCS8 format
pub fn sign(key: &EncodingKey, message: &[u8]) -> Result<String> {
    let secret_key: [u8; 32] = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key.content[..]);
        arr // Return the array
    };
    let secret_key = SecretKey::from_bytes(&secret_key).unwrap();
    let public_key = PublicKey::from(&secret_key);

    let keypair = ed25519_dalek::Keypair {
        secret: secret_key,
        public: public_key,
    };

    let out = keypair.sign(message);
    Ok(b64_encode(out))
}


