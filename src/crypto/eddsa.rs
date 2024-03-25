use crate::errors::Result;
use crate::serialization::b64_encode;

#[cfg(feature = "ptd")]
use crate::EncodingKey;
#[cfg(feature = "ptd")]
use ed25519_dalek::{PublicKey, SecretKey, Signer};

#[cfg(not(feature = "ptd"))]
use crate::Algorithm;
#[cfg(not(feature = "ptd"))]
use ring::signature;

/// Only used internally when signing or validating EdDSA, to map from our enum to the Ring EdDSAParameters structs.
#[cfg(not(feature = "ptd"))]
pub(crate) fn alg_to_ec_verification(alg: Algorithm) -> &'static signature::EdDSAParameters {
    // To support additional key subtypes, like Ed448, we would need to match on the JWK's ("crv")
    // parameter.
    match alg {
        Algorithm::EdDSA => &signature::ED25519,
        _ => unreachable!("Tried to get EdDSA alg for a non-EdDSA algorithm"),
    }
}

/// The actual EdDSA signing + encoding
/// The key needs to be in PKCS8 format
#[cfg(not(feature = "ptd"))]
pub fn sign(key: &[u8], message: &[u8]) -> Result<String> {
    let signing_key = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(key)?;
    let out = signing_key.sign(message);
    Ok(b64_encode(out))
}

/// The actual EdDSA signing + encoding
/// The key needs to be in PKCS8 format
#[cfg(feature = "ptd")]
pub fn sign(key: &EncodingKey, message: &[u8]) -> Result<String> {
    let secret_key: [u8; 32] = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key.content[..]);
        arr // Return the array
    };
    let secret_key = SecretKey::from_bytes(&secret_key).unwrap();
    let public_key = PublicKey::from(&secret_key);

    let keypair = ed25519_dalek::Keypair { secret: secret_key, public: public_key };

    let out = keypair.sign(message);
    Ok(b64_encode(out))
}
