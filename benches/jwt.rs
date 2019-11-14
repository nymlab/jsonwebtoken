#![feature(test)]
extern crate test;

use jsonwebtoken::{decode, encode, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
}

#[bench]
fn bench_encode(b: &mut test::Bencher) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned() };

    b.iter(|| encode(&Header::default(), &claim, "secret".as_ref()));
}

#[bench]
fn bench_decode(b: &mut test::Bencher) {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    b.iter(|| decode::<Claims>(token, "secret".as_ref(), &Validation::default()));
}
