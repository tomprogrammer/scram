use std::borrow::Cow;
use std::num::NonZeroU32;

use base64;
use rand::distributions::{Distribution, Uniform};
use rand::{rngs::OsRng, Rng};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::hmac;

use error::{Error, Field, Kind};
use utils::{find_proofs, hash_password};
use NONCE_LENGTH;

#[deprecated(
    since = "0.2.0",
    note = "Please use `ScramClient` instead. (exported at crate root)"
)]
pub type ClientFirst<'a> = ScramClient<'a>;

/// Parses a `server_first_message` returning a (none, salt, iterations) tuple if successful.
fn parse_server_first(data: &str) -> Result<(&str, Vec<u8>, NonZeroU32), Error> {
    if data.len() < 2 {
        return Err(Error::Protocol(Kind::ExpectedField(Field::Nonce)));
    }
    let mut parts = data.split(',').peekable();
    match parts.peek() {
        Some(part) if &part.as_bytes()[..2] == b"m=" => {
            return Err(Error::UnsupportedExtension);
        }
        Some(_) => {}
        None => {
            return Err(Error::Protocol(Kind::ExpectedField(Field::Nonce)));
        }
    }
    let nonce = match parts.next() {
        Some(part) if &part.as_bytes()[..2] == b"r=" => &part[2..],
        _ => {
            return Err(Error::Protocol(Kind::ExpectedField(Field::Nonce)));
        }
    };
    let salt = match parts.next() {
        Some(part) if &part.as_bytes()[..2] == b"s=" => base64::decode(part[2..].as_bytes())
            .map_err(|_| Error::Protocol(Kind::InvalidField(Field::Salt)))?,
        _ => {
            return Err(Error::Protocol(Kind::ExpectedField(Field::Salt)));
        }
    };
    let iterations = match parts.next() {
        Some(part) if &part.as_bytes()[..2] == b"i=" => part[2..]
            .parse()
            .map_err(|_| Error::Protocol(Kind::InvalidField(Field::Iterations)))?,
        _ => {
            return Err(Error::Protocol(Kind::ExpectedField(Field::Iterations)));
        }
    };
    Ok((nonce, salt, iterations))
}

fn parse_server_final(data: &str) -> Result<Vec<u8>, Error> {
    if data.len() < 2 {
        return Err(Error::Protocol(Kind::ExpectedField(Field::VerifyOrError)));
    }
    match &data[..2] {
        "v=" => base64::decode(&data.as_bytes()[2..])
            .map_err(|_| Error::Protocol(Kind::InvalidField(Field::VerifyOrError))),
        "e=" => Err(Error::Authentication(data[2..].to_string())),
        _ => Err(Error::Protocol(Kind::ExpectedField(Field::VerifyOrError))),
    }
}

/// The initial state of the SCRAM mechanism. It's the entry point for a SCRAM handshake.
#[derive(Debug)]
pub struct ScramClient<'a> {
    gs2header: Cow<'static, str>,
    password: &'a str,
    nonce: String,
    authcid: &'a str,
}

impl<'a> ScramClient<'a> {
    /// Constructs an initial state for the SCRAM mechanism using the provided credentials.
    ///
    /// # Arguments
    ///
    /// * authcid - An username used for authentication.
    /// * password - A password used to prove that the user is authentic.
    /// * authzid - An username used for authorization. This can be used to impersonate as `authzid`
    /// using the credentials of `authcid`. If `authzid` is `None` the authorized username will be
    /// the same as the authenticated username.
    ///
    /// # Return value
    ///
    /// An I/O error is returned if the internal random number generator couldn't be constructed.
    pub fn new(authcid: &'a str, password: &'a str, authzid: Option<&'a str>) -> Self {
        Self::with_rng(authcid, password, authzid, &mut OsRng)
    }

    /// Constructs an initial state for the SCRAM mechanism using the provided credentials and a
    /// custom random number generator.
    ///
    /// # Arguments
    ///
    /// * authcid - An username used for authentication.
    /// * password - A password used to prove that the user is authentic.
    /// * authzid - An username used for authorization. This can be used to impersonate as `authzid`
    /// using the credentials of `authcid`. If `authzid` is `None` the authorized username will be
    /// the same as the authenticated username.
    /// * rng: A random number generator used to generate random nonces. Please only use a
    /// cryptographically secure random number generator!
    pub fn with_rng<R: Rng + ?Sized>(
        authcid: &'a str,
        password: &'a str,
        authzid: Option<&'a str>,
        rng: &mut R,
    ) -> Self {
        let gs2header: Cow<'static, str> = match authzid {
            Some(authzid) => format!("n,a={},", authzid).into(),
            None => "n,,".into(),
        };
        let nonce: String = Uniform::from(33..125)
            .sample_iter(rng)
            .map(|x: u8| if x > 43 { (x + 1) as char } else { x as char })
            .take(NONCE_LENGTH)
            .collect();
        ScramClient {
            gs2header,
            password,
            authcid,
            nonce,
        }
    }

    /// Returns the next state and the first client message.
    ///
    /// Call the
    /// [`ServerFirst::handle_server_first`](struct.ServerFirst.html#method.handle_server_first)
    /// method to continue the SCRAM handshake.
    pub fn client_first(self) -> (ServerFirst<'a>, String) {
        let escaped_authcid: Cow<'a, str> =
            if self.authcid.chars().any(|chr| chr == ',' || chr == '=') {
                self.authcid.into()
            } else {
                self.authcid.replace(',', "=2C").replace('=', "=3D").into()
            };
        let client_first_bare = format!("n={},r={}", escaped_authcid, self.nonce);
        let client_first = format!("{}{}", self.gs2header, client_first_bare);
        let server_first = ServerFirst {
            gs2header: self.gs2header,
            password: self.password,
            client_nonce: self.nonce,
            client_first_bare,
        };
        (server_first, client_first)
    }
}

/// The second state of the SCRAM mechanism after the first client message was computed.
#[derive(Debug)]
pub struct ServerFirst<'a> {
    gs2header: Cow<'static, str>,
    password: &'a str,
    client_nonce: String,
    client_first_bare: String,
}

impl<'a> ServerFirst<'a> {
    /// Processes the first answer from the server and returns the next state or an error. If an
    /// error is returned the SCRAM handshake is aborted.
    ///
    /// Call the [`ClientFinal::client_final`](struct.ClientFinal.html#method.client_final) method
    /// to continue the handshake.
    ///
    /// # Return value
    ///
    /// This method returns only a subset of the errors defined in [`Error`](../enum.Error.html):
    ///
    /// * Error::Protocol
    /// * Error::UnsupportedExtension
    pub fn handle_server_first(self, server_first: &str) -> Result<ClientFinal, Error> {
        let (nonce, salt, iterations) = parse_server_first(server_first)?;
        if !nonce.starts_with(&self.client_nonce) {
            return Err(Error::Protocol(Kind::InvalidNonce));
        }
        let salted_password = hash_password(self.password, iterations, &salt);
        let (client_proof, server_signature): ([u8; SHA256_OUTPUT_LEN], hmac::Tag) = find_proofs(
            &self.gs2header,
            &self.client_first_bare,
            &server_first,
            &salted_password,
            nonce,
        );
        let client_final = format!(
            "c={},r={},p={}",
            base64::encode(self.gs2header.as_bytes()),
            nonce,
            base64::encode(&client_proof)
        );
        Ok(ClientFinal {
            server_signature,
            client_final,
        })
    }
}

/// The third state of the SCRAM mechanism after the first server message was successfully
/// processed.
#[derive(Debug)]
pub struct ClientFinal {
    server_signature: hmac::Tag,
    client_final: String,
}

impl ClientFinal {
    /// Returns the next state and the final client message.
    ///
    /// Call the
    /// [`ServerFinal::handle_server_final`](struct.ServerFinal.html#method.handle_server_final)
    /// method to continue the SCRAM handshake.
    #[inline]
    pub fn client_final(self) -> (ServerFinal, String) {
        let server_final = ServerFinal {
            server_signature: self.server_signature,
        };
        (server_final, self.client_final)
    }
}

/// The final state of the SCRAM mechanism after the final client message was computed.
#[derive(Debug)]
pub struct ServerFinal {
    server_signature: hmac::Tag,
}

impl ServerFinal {
    /// Processes the final answer from the server and returns the authentication result.
    ///
    /// # Return value
    ///
    /// * A value of `Ok(())` signals a successful authentication attempt.
    /// * A value of `Err(Error::Protocol(_)` or `Err(Error::UnsupportedExtension)` means that the
    /// authentication request failed.
    /// * A value of `Err(Error::InvalidServer)` or `Err(Error::Authentication(_))` means that the
    /// authentication request was rejected.
    ///
    /// Detailed semantics are documented in the [`Error`](../enum.Error.html) type.
    pub fn handle_server_final(self, server_final: &str) -> Result<(), Error> {
        if self.server_signature.as_ref() == &*parse_server_final(server_final)? {
            Ok(())
        } else {
            Err(Error::InvalidServer)
        }
    }
}
