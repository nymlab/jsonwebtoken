#[cfg(not(feature = "ptd"))]
use jsonwebtoken_wasm::errors::ErrorKind;
#[cfg(not(feature = "ptd"))]
use jsonwebtoken_wasm::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: u64,
}

#[cfg(not(feature = "ptd"))]
fn main() {
    let my_claims =
        Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 10000000000 };
    let key = b"secret";

    let header =
        Header { kid: Some("signing_key".to_owned()), alg: Algorithm::HS512, ..Default::default() };

    let token = match encode(&header, &my_claims, &EncodingKey::from_secret(key)) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };
    println!("{:?}", token);

    let token_data = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(key),
        &Validation::new(Algorithm::HS512),
    ) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!(), // Example on how to handle a specific error
            _ => panic!(),
        },
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
}

#[cfg(feature = "ptd")]
fn main() {}
