#[cfg(not(feature = "no_rand"))]
use ring::{constant_time::verify_slices_are_equal, hmac, signature};

use crate::algorithms::Algorithm;
use crate::decoding::DecodingKey;
#[cfg(not(feature = "no_rand"))]
use crate::decoding::DecodingKeyKind;
#[cfg(not(feature = "no_rand"))]
use crate::encoding::EncodingKey;
use crate::errors::Result;
use crate::serialization::b64_decode;

#[cfg(not(feature = "no_rand"))]
use crate::serialization::b64_encode;

#[cfg(not(feature = "no_rand"))]
pub(crate) mod ecdsa;
#[cfg(not(feature = "no_rand"))]
pub(crate) mod eddsa;
#[cfg(not(feature = "no_rand"))]
pub(crate) mod rsa;

/// The actual HS signing + encoding
/// Could be in its own file to match RSA/EC but it's 2 lines...
#[cfg(not(feature = "no_rand"))]
pub(crate) fn sign_hmac(alg: hmac::Algorithm, key: &[u8], message: &[u8]) -> String {
    let digest = hmac::sign(&hmac::Key::new(alg, key), message);
    b64_encode(digest)
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// If you just want to encode a JWT, use `encode` instead.
#[cfg(not(feature = "no_rand"))]
pub fn sign(message: &[u8], key: &EncodingKey, algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::HS256 => Ok(sign_hmac(hmac::HMAC_SHA256, key.inner(), message)),
        Algorithm::HS384 => Ok(sign_hmac(hmac::HMAC_SHA384, key.inner(), message)),
        Algorithm::HS512 => Ok(sign_hmac(hmac::HMAC_SHA512, key.inner(), message)),

        Algorithm::ES256 | Algorithm::ES384 => {
            ecdsa::sign(ecdsa::alg_to_ec_signing(algorithm), key.inner(), message)
        }

        Algorithm::EdDSA => eddsa::sign(key.inner(), message),

        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => rsa::sign(rsa::alg_to_rsa_signing(algorithm), key.inner(), message),
    }
}

/// See Ring docs for more details
#[cfg(not(feature = "no_rand"))]
fn verify_ring(
    alg: &'static dyn signature::VerificationAlgorithm,
    signature: &str,
    message: &[u8],
    key: &[u8],
) -> Result<bool> {
    let signature_bytes = b64_decode(signature)?;
    let public_key = signature::UnparsedPublicKey::new(alg, key);
    let res = public_key.verify(message, &signature_bytes);

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
    #[cfg(not(feature = "no_rand"))]
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let signed = sign(message, &EncodingKey::from_secret(key.as_bytes()), algorithm)?;
            Ok(verify_slices_are_equal(signature.as_ref(), signed.as_ref()).is_ok())
        }
        Algorithm::ES256 | Algorithm::ES384 => verify_ring(
            ecdsa::alg_to_ec_verification(algorithm),
            signature,
            message,
            key.as_bytes(),
        ),
        Algorithm::EdDSA => verify_ring(
            eddsa::alg_to_ec_verification(algorithm),
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
            let alg = rsa::alg_to_rsa_parameters(algorithm);
            match &key.kind {
                DecodingKeyKind::SecretOrDer(bytes) => verify_ring(alg, signature, message, bytes),
                DecodingKeyKind::RsaModulusExponent { n, e } => {
                    rsa::verify_from_components(alg, signature, message, (n, e))
                }
            }
        }
    }
    #[cfg(feature = "no_rand")]
    match algorithm {
        Algorithm::EdDSA => {
            let sig = b64_decode(signature)?;
            let dalek_signature = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| {
                crate::errors::new_error(crate::errors::ErrorKind::InvalidSignature)
            })?;

            let key_bytes: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH] =
                key.as_bytes().try_into().map_err(|_| {
                    crate::errors::new_error(crate::errors::ErrorKind::InvalidKeyFormat)
                })?;

            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).unwrap();

            let res = verifying_key.verify_strict(message, &dalek_signature);

            Ok(res.is_ok())
        }
        _ => Err(crate::errors::new_error(crate::errors::ErrorKind::InvalidAlgorithm)),
    }
}
