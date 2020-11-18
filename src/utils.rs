use base64;
use ring::digest::{self, digest, SHA256_OUTPUT_LEN};
use ring::hmac::{self, Context, Key, HMAC_SHA256};
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256 as SHA256};
use std::num::NonZeroU32;

/// Parses a part of a SCRAM message, after it has been split on commas.
/// Checks to make sure there's a key, and then verifies its the right key.
/// Returns everything after the first '='.
/// Returns a `ExpectedField` error when one of the above conditions fails.
macro_rules! parse_part {
    ($iter:expr, $field:ident, $key:expr) => {
        if let Some(part) = $iter.next() {
            if part.len() < 2 {
                return Err(Error::Protocol(Kind::ExpectedField(Field::$field)));
            } else if &part.as_bytes()[..2] == $key {
                &part[2..]
            } else {
                return Err(Error::Protocol(Kind::ExpectedField(Field::$field)));
            }
        } else {
            return Err(Error::Protocol(Kind::ExpectedField(Field::$field)));
        }
    };
}

/// Hashes a password with SHA-256 with the given salt and number of iterations.  This should
/// be used by [`AuthenticationProvider`](crate::server::AuthenticationProvider) implementors to
/// hash any passwords prior to being saved.
pub fn hash_password(
    password: &str,
    iterations: NonZeroU32,
    salt: &[u8],
) -> [u8; SHA256_OUTPUT_LEN] {
    let mut salted_password = [0u8; SHA256_OUTPUT_LEN];
    pbkdf2::derive(
        SHA256,
        iterations,
        salt,
        password.as_bytes(),
        &mut salted_password,
    );
    salted_password
}

/// Finds the client proof and server signature based on the shared hashed key.
pub fn find_proofs(
    gs2header: &str,
    client_first_bare: &str,
    server_first: &str,
    salted_password: &[u8],
    nonce: &str,
) -> ([u8; SHA256_OUTPUT_LEN], hmac::Tag) {
    fn sign_slice(key: &Key, slice: &[&[u8]]) -> hmac::Tag {
        let mut signature_context = Context::with_key(key);
        for item in slice {
            signature_context.update(item);
        }
        signature_context.sign()
    }

    let client_final_without_proof =
        format!("c={},r={}", base64::encode(gs2header.as_bytes()), nonce);
    let auth_message = [
        client_first_bare.as_bytes(),
        b",",
        server_first.as_bytes(),
        b",",
        client_final_without_proof.as_bytes(),
    ];

    let salted_password_signing_key = Key::new(HMAC_SHA256, salted_password);
    let client_key = hmac::sign(&salted_password_signing_key, b"Client Key");
    let server_key = hmac::sign(&salted_password_signing_key, b"Server Key");
    let stored_key = digest(&digest::SHA256, client_key.as_ref());
    let stored_key_signing_key = Key::new(HMAC_SHA256, stored_key.as_ref());
    let client_signature = sign_slice(&stored_key_signing_key, &auth_message);
    let server_signature_signing_key = Key::new(HMAC_SHA256, server_key.as_ref());
    let server_signature = sign_slice(&server_signature_signing_key, &auth_message);
    let mut client_proof = [0u8; SHA256_OUTPUT_LEN];
    let xor_iter = client_key
        .as_ref()
        .iter()
        .zip(client_signature.as_ref())
        .map(|(k, s)| k ^ s);
    for (p, x) in client_proof.iter_mut().zip(xor_iter) {
        *p = x
    }
    (client_proof, server_signature)
}
