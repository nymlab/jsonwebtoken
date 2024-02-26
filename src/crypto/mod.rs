use ed25519_dalek::Verifier;

use crate::algorithms::Algorithm;
use crate::decoding::{DecodingKey, DecodingKeyKind};
use crate::encoding::EncodingKey;
use crate::errors::Result;
use crate::serialization::{b64_decode, b64_encode};

//pub(crate) mod ecdsa;
pub(crate) mod eddsa;
//pub(crate) mod rsa;
pub(crate) mod error;

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// If you just want to encode a JWT, use `encode` instead.
pub fn sign(message: &[u8], key: &EncodingKey, algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::HS256 => Ok(String::new()),
        Algorithm::HS384 => Ok(String::new()),
        Algorithm::HS512 => Ok(String::new()),

        Algorithm::ES256 | Algorithm::ES384 => Ok(String::new()),

        Algorithm::EdDSA => eddsa::sign(&key, message),

        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => Ok(String::new()),
    }
}

/// See Ring docs for more details
fn verify_ring(
    algorithm: Algorithm,
    signature: &str,
    message: &[u8],
    key: &[u8],
) -> Result<bool> {
    let signature = b64_decode(signature).unwrap();
    let key_without_headers = &key[12..44];

    let dalek_signature = ed25519_dalek::Signature::from_bytes(&signature).unwrap();
    let public_key = ed25519_dalek::PublicKey::from_bytes(key_without_headers).unwrap();

    let res = public_key.verify(&message, &dalek_signature);

    Ok(res.is_ok())
}

/// Compares the signature given with a re-computed signature for HMAC or using the public key
/// for RSA/EC.
///
/// If you just want to decode a JWT, use `decode` instead.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `message` is base64(header) + "." + base64(claims)
pub fn verify(
    signature: &str,
    message: &[u8],
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<bool> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => Ok(false),
        Algorithm::ES256 | Algorithm::ES384 => Ok(false),
        Algorithm::EdDSA => verify_ring(
            algorithm,
            signature,
            message,
            key.as_bytes(),
        ),
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            Ok(false)
        }
    }
}


