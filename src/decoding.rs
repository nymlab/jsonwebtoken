use base64::{engine::general_purpose::STANDARD, Engine};
use serde::de::DeserializeOwned;

use crate::algorithms::AlgorithmFamily;
use crate::crypto::verify;
use crate::errors::{new_error, ErrorKind, Result};
use crate::header::Header;
use crate::jwk::{AlgorithmParameters, Jwk};
#[cfg(feature = "use_pem")]
use crate::pem::decoder::PemEncodedKey;
use crate::serialization::{b64_decode, DecodedJwtPartClaims};
use crate::validation::{validate, Validation};

/// The return type of a successful call to [decode](fn.decode.html).
#[derive(Debug)]
pub struct TokenData<T> {
    /// The decoded JWT header
    pub header: Header,
    /// The decoded JWT claims
    pub claims: T,
}

impl<T> Clone for TokenData<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self { header: self.header.clone(), claims: self.claims.clone() }
    }
}

/// Takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(new_error(ErrorKind::InvalidToken)),
        }
    }};
}

#[derive(Clone)]
pub(crate) enum DecodingKeyKind {
    SecretOrDer(Vec<u8>),
    RsaModulusExponent { n: Vec<u8>, e: Vec<u8> },
}

/// All the different kind of keys we can use to decode a JWT.
/// This key can be re-used so make sure you only initialize it once if you can for better performance.
#[derive(Clone)]
pub struct DecodingKey {
    pub(crate) family: AlgorithmFamily,
    pub(crate) kind: DecodingKeyKind,
}

impl DecodingKey {
    /// If you're using HMAC, use this.
    pub fn from_secret(secret: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Hmac,
            kind: DecodingKeyKind::SecretOrDer(secret.to_vec()),
        }
    }

    /// If you're using HMAC with a base64 encoded secret, use this.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        let out = STANDARD.decode(secret)?;
        Ok(DecodingKey { family: AlgorithmFamily::Hmac, kind: DecodingKeyKind::SecretOrDer(out) })
    }

    /// If you have a EdDSA public key in PEM format, use this.
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_ed_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ed_public_key()?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Ed,
            kind: DecodingKeyKind::SecretOrDer(content.to_vec()),
        })
    }

    /// If you know what you're doing and have a RSA DER encoded public key, use this.
    pub fn from_rsa_der(der: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::SecretOrDer(der.to_vec()),
        }
    }

    /// If you know what you're doing and have a RSA EC encoded public key, use this.
    pub fn from_ec_der(der: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Ec,
            kind: DecodingKeyKind::SecretOrDer(der.to_vec()),
        }
    }

    /// If you know what you're doing and have a Ed DER encoded public key, use this.
    pub fn from_ed_der(der: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Ed,
            kind: DecodingKeyKind::SecretOrDer(der.to_vec()),
        }
    }

    /// From x part (base64 encoded) of the JWK encoding
    pub fn from_ed_components(x: &str) -> Result<Self> {
        let x_decoded = b64_decode(x)?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Ed,
            kind: DecodingKeyKind::SecretOrDer(x_decoded),
        })
    }

    /// If you have a key in Jwk format
    pub fn from_jwk(jwk: &Jwk) -> Result<Self> {
        match &jwk.algorithm {
            AlgorithmParameters::RSA(params) => {
                return Err(new_error(ErrorKind::MissingAlgorithm));
            }
            AlgorithmParameters::EllipticCurve(params) => {
                return Err(new_error(ErrorKind::MissingAlgorithm));
            }
            AlgorithmParameters::OctetKeyPair(params) => DecodingKey::from_ed_components(&params.x),
            AlgorithmParameters::OctetKey(params) => {
                let out = b64_decode(&params.value)?;
                Ok(DecodingKey {
                    family: AlgorithmFamily::Hmac,
                    kind: DecodingKeyKind::SecretOrDer(out),
                })
            }
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        match &self.kind {
            DecodingKeyKind::SecretOrDer(b) => b,
            DecodingKeyKind::RsaModulusExponent { .. } => unreachable!(),
        }
    }
}

/// Verify signature of a JWT, and return header object and raw payload
///
/// If the token or its signature is invalid, it will return an error.
fn verify_signature<'a>(
    token: &'a str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<(Header, &'a str)> {
    if validation.validate_signature && validation.algorithms.is_empty() {
        return Err(new_error(ErrorKind::MissingAlgorithm));
    }

    if validation.validate_signature {
        for alg in &validation.algorithms {
            if key.family != alg.family() {
                return Err(new_error(ErrorKind::InvalidAlgorithm));
            }
        }
    }

    let (signature, message) = expect_two!(token.rsplitn(2, '.'));
    let (payload, header) = expect_two!(message.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    if validation.validate_signature && !validation.algorithms.contains(&header.alg) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    if validation.validate_signature && !verify(signature, message.as_bytes(), key, header.alg)? {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    Ok((header, payload))
}

/// Decode and validate a JWT
///
/// If the token or its signature is invalid or the claims fail validation, it will return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_message = decode::<Claims>(&token, &DecodingKey::from_secret("secret".as_ref()), &Validation::new(Algorithm::HS256));
/// ```
pub fn decode<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>> {
    match verify_signature(token, key, validation) {
        Err(e) => Err(e),
        Ok((header, claims)) => {
            let decoded_claims = DecodedJwtPartClaims::from_jwt_part_claims(claims)?;
            let claims = decoded_claims.deserialize()?;
            validate(decoded_claims.deserialize()?, validation)?;

            Ok(TokenData { header, claims })
        }
    }
}

/// Decode a JWT without any signature verification/validations and return its [Header](struct.Header.html).
///
/// If the token has an invalid format (ie 3 parts separated by a `.`), it will return an error.
///
/// ```rust
/// use jsonwebtoken::decode_header;
///
/// let token = "a.jwt.token".to_string();
/// let header = decode_header(&token);
/// ```
pub fn decode_header(token: &str) -> Result<Header> {
    let (_, message) = expect_two!(token.rsplitn(2, '.'));
    let (_, header) = expect_two!(message.rsplitn(2, '.'));
    Header::from_encoded(header)
}
