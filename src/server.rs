use std::borrow::Cow;

use base64;
use rand::distributions::{Distribution, Uniform};
use rand::{rngs::OsRng, Rng};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::hmac;

use error::{Error, Field, Kind};
use utils::find_proofs;
use NONCE_LENGTH;

/// Responds to client authentication challenges. It's the entrypoint for the SCRAM server side
/// implementation.
pub struct ScramServer<P: AuthenticationProvider> {
    /// The ['AuthenticationProvider'] that will find passwords and check authorization.
    provider: P,
}

/// Contains information about stored passwords. In particular, it stores the password that has been
/// salted and hashed, the salt that was used, and the number of iterations of the hashing algorithm
pub struct PasswordInfo {
    hashed_password: Vec<u8>,
    salt: Vec<u8>,
    iterations: u16,
}

/// The status of authentication after the final client message has been received by the server.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum AuthenticationStatus {
    /// The client has correctly authenticated, and has been authorized.
    Authenticated,
    /// The client was not correctly authenticated, meaning they supplied an incorrect password.
    NotAuthenticated,
    /// The client authenticated correctly, but was not authorized for the alternate user they
    /// requested.
    NotAuthorized,
}

impl PasswordInfo {
    /// Create a new `PasswordInfo` from the given information. The password is assumed to have
    /// already been hashed using the given salt and iterations.
    pub fn new(hashed_password: Vec<u8>, iterations: u16, salt: Vec<u8>) -> Self {
        PasswordInfo {
            hashed_password,
            iterations,
            salt,
        }
    }
}

/// An `AuthenticationProvider` looks up password information for a given user, and also checks if a
/// user is authorized to act on another user's behalf. The authorization component is optional, and
/// if not implemented will simply allow users to act on their own behalf, and no one else's.
///
/// To ensure the password is hashed correctly, cleartext passwords can be hased using the
/// [`hash_password`](crate::utils::hash_password) function provided in the crate root.
pub trait AuthenticationProvider {
    /// Gets the [`PasswordInfo`] for the given user.
    fn get_password_for(&self, username: &str) -> Option<PasswordInfo>;

    /// Checks to see if the user given by `authcid` is authorized to act as the user given by
    /// `authzid.` Implementors do not need to implement this method. The default implementation
    /// just checks if the two are equal
    fn authorize(&self, authcid: &str, authzid: &str) -> bool {
        authcid == authzid
    }
}

/// Parses a client's first message by splitting it on commas and analyzing each part. Gives an
/// error if the data was malformed in any way
fn parse_client_first(data: &str) -> Result<(&str, Option<&str>, &str), Error> {
    let mut parts = data.split(',');

    // Channel binding
    if let Some(part) = parts.next() {
        if let Some(cb) = part.chars().next() {
            if cb == 'p' {
                return Err(Error::UnsupportedExtension);
            }
            if cb != 'n' && cb != 'y' || part.len() > 1 {
                return Err(Error::Protocol(Kind::InvalidField(Field::ChannelBinding)));
            }
        } else {
            return Err(Error::Protocol(Kind::ExpectedField(Field::ChannelBinding)));
        }
    } else {
        return Err(Error::Protocol(Kind::ExpectedField(Field::ChannelBinding)));
    }

    // Authzid
    let authzid = if let Some(part) = parts.next() {
        if part.is_empty() {
            None
        } else if part.len() < 2 || &part.as_bytes()[..2] != b"a=" {
            return Err(Error::Protocol(Kind::ExpectedField(Field::Authzid)));
        } else {
            Some(&part[2..])
        }
    } else {
        return Err(Error::Protocol(Kind::ExpectedField(Field::Authzid)));
    };

    // Authcid
    let authcid = parse_part!(parts, Authcid, b"n=");

    // Nonce
    let nonce = match parts.next() {
        Some(part) if &part.as_bytes()[..2] == b"r=" => &part[2..],
        _ => {
            return Err(Error::Protocol(Kind::ExpectedField(Field::Nonce)));
        }
    };
    Ok((authcid, authzid, nonce))
}

/// Parses the client's final message. Gives an error if the data was malformed.
fn parse_client_final(data: &str) -> Result<(&str, &str, &str), Error> {
    // 6 is the length of the required parts of the message
    let mut parts = data.split(',');
    let gs2header = parse_part!(parts, GS2Header, b"c=");
    let nonce = parse_part!(parts, Nonce, b"r=");
    let proof = parse_part!(parts, Proof, b"p=");
    Ok((gs2header, nonce, proof))
}

impl<P: AuthenticationProvider> ScramServer<P> {
    /// Creates a new `ScramServer` using the given authentication provider.
    pub fn new(provider: P) -> Self {
        ScramServer { provider }
    }

    /// Handle a challenge message sent by the client to the server. If the message is well formed,
    /// and the requested user exists, then this will progress to the next stage of the
    /// authentication process, [`ServerFirst`]. Otherwise, it will return an error.
    pub fn handle_client_first<'a>(
        &'a self,
        client_first: &'a str,
    ) -> Result<ServerFirst<'a, P>, Error> {
        let (authcid, authzid, client_nonce) = parse_client_first(client_first)?;
        let password_info = self
            .provider
            .get_password_for(authcid)
            .ok_or_else(|| Error::InvalidUser(authcid.to_string()))?;
        Ok(ServerFirst {
            client_nonce,
            authcid,
            authzid,
            provider: &self.provider,
            password_info,
        })
    }
}

/// Represents the first stage in the authentication process, after the client has submitted their
/// first message. This struct is responsible for responding to the message
pub struct ServerFirst<'a, P: 'a + AuthenticationProvider> {
    client_nonce: &'a str,
    authcid: &'a str,
    authzid: Option<&'a str>,
    provider: &'a P,
    password_info: PasswordInfo,
}

impl<'a, P: AuthenticationProvider> ServerFirst<'a, P> {
    /// Creates the server's first message in response to the client's first message. By default,
    /// this method uses [`OsRng`] as its source of randomness for the nonce. To specify the
    /// randomness source, use [`server_first_with_rng`](Self::server_first_with_rng). This method
    /// will return an error when it cannot initialize the OS's randomness source. See the
    /// documentation on `OsRng` for more information.
    pub fn server_first(self) -> (ClientFinal<'a, P>, String) {
        self.server_first_with_rng(&mut OsRng)
    }

    /// Creates the server's first message in response to the client's first message, with the
    /// given source of randomness used for the server's nonce. The randomness is assigned here
    /// instead of universally in [`ScramServer`] for increased flexibility, and also to keep
    /// `ScramServer` immutable.
    pub fn server_first_with_rng<R: Rng>(self, rng: &mut R) -> (ClientFinal<'a, P>, String) {
        let mut nonce = String::with_capacity(self.client_nonce.len() + NONCE_LENGTH);
        nonce.push_str(self.client_nonce);
        nonce.extend(
            Uniform::from(33..125)
                .sample_iter(rng)
                .map(|x: u8| if x > 43 { (x + 1) as char } else { x as char })
                .take(NONCE_LENGTH),
        );

        let gs2header: Cow<'static, str> = match self.authzid {
            Some(authzid) => format!("n,a={},", authzid).into(),
            None => "n,,".into(),
        };
        let client_first_bare: Cow<'static, str> =
            format!("n={},r={}", self.authcid, self.client_nonce).into();
        let server_first: Cow<'static, str> = format!(
            "r={},s={},i={}",
            nonce,
            base64::encode(self.password_info.salt.as_slice()),
            self.password_info.iterations
        )
        .into();
        (
            ClientFinal {
                hashed_password: self.password_info.hashed_password,
                nonce,
                gs2header,
                client_first_bare,
                server_first: server_first.clone(),
                authcid: self.authcid,
                authzid: self.authzid,
                provider: self.provider,
            },
            server_first.into_owned(),
        )
    }

    /// The username parsed from client first message that used for authentication.
    pub fn authcid(&self) -> &str {
        self.authcid
    }

    /// The username parsed from client first message that used for authorization.
    pub fn authzid(&self) -> Option<&str> {
        self.authzid
    }

    /// The nonce value parsed from client first message.
    pub fn client_nonce(&self) -> &str {
        self.client_nonce
    }
}

/// Represents the stage after the server has generated its first response to the client. This
/// struct is responsible for handling the client's final message.
pub struct ClientFinal<'a, P: 'a + AuthenticationProvider> {
    hashed_password: Vec<u8>,
    nonce: String,
    gs2header: Cow<'static, str>,
    client_first_bare: Cow<'static, str>,
    server_first: Cow<'static, str>,
    authcid: &'a str,
    authzid: Option<&'a str>,
    provider: &'a P,
}

impl<'a, P: AuthenticationProvider> ClientFinal<'a, P> {
    /// Handle the final client message. If the message is not well formed, or the authorization
    /// header is invalid, then this will return an error. In all other cases (including when
    /// authentication or authorization has failed), this will return `Ok` along with a message to
    /// send the client. In cases where authentication or authorization has failed, the message will
    /// contain error information for the client. To check if authentication and authorization have
    /// succeeded, use [`server_final`](ServerFinal::server_final) on the return value.
    pub fn handle_client_final(self, client_final: &str) -> Result<ServerFinal, Error> {
        let (gs2header_enc, nonce, proof) = parse_client_final(client_final)?;
        if !self.verify_header(gs2header_enc) {
            return Err(Error::Protocol(Kind::InvalidField(Field::GS2Header)));
        }
        if !self.verify_nonce(nonce) {
            return Err(Error::Protocol(Kind::InvalidField(Field::Nonce)));
        }
        if let Some(signature) = self.verify_proof(proof)? {
            if let Some(authzid) = self.authzid {
                if self.provider.authorize(self.authcid, authzid) {
                    Ok(ServerFinal {
                        status: AuthenticationStatus::Authenticated,
                        signature,
                    })
                } else {
                    Ok(ServerFinal {
                        status: AuthenticationStatus::NotAuthorized,
                        signature: format!(
                            "e=User '{}' not authorized to act as '{}'",
                            self.authcid, authzid
                        ),
                    })
                }
            } else {
                Ok(ServerFinal {
                    status: AuthenticationStatus::Authenticated,
                    signature,
                })
            }
        } else {
            Ok(ServerFinal {
                status: AuthenticationStatus::NotAuthenticated,
                signature: "e=Invalid Password".to_string(),
            })
        }
    }

    /// The username parsed from client first message that used for authentication.
    pub fn authcid(&self) -> &str {
        self.authcid
    }

    /// The username parsed from client first message that used for authorization.
    pub fn authzid(&self) -> Option<&str> {
        self.authzid
    }

    /// Checks that the gs2header received from the client is the same as the one we've stored
    fn verify_header(&self, gs2header: &str) -> bool {
        let server_gs2header = base64::encode(self.gs2header.as_bytes());
        server_gs2header == gs2header
    }

    /// Checks that the client has sent the same nonce
    fn verify_nonce(&self, nonce: &str) -> bool {
        nonce == self.nonce
    }

    /// Checks that the proof from the client matches our saved credentials
    fn verify_proof(&self, proof: &str) -> Result<Option<String>, Error> {
        let (client_proof, server_signature): ([u8; SHA256_OUTPUT_LEN], hmac::Tag) = find_proofs(
            &self.gs2header,
            &self.client_first_bare,
            &self.server_first,
            self.hashed_password.as_slice(),
            &self.nonce,
        );
        let proof = if let Ok(proof) = base64::decode(proof.as_bytes()) {
            proof
        } else {
            return Err(Error::Protocol(Kind::InvalidField(Field::Proof)));
        };
        if proof != client_proof {
            return Ok(None);
        }

        let server_signature_string = format!("v={}", base64::encode(server_signature.as_ref()));
        Ok(Some(server_signature_string))
    }
}

/// Represents the final stage of authentication, after we have generated the final server message
/// to send to the client
pub struct ServerFinal {
    status: AuthenticationStatus,
    signature: String,
}

impl ServerFinal {
    /// Get the [`AuthenticationStatus`] of the exchange. This status can be successful, failed
    /// because of invalid authentication or failed because of invalid authorization.
    pub fn server_final(self) -> (AuthenticationStatus, String) {
        (self.status, self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Error, Field, Kind};
    use super::{parse_client_final, parse_client_first};

    #[test]
    fn test_parse_client_first_success() {
        let (authcid, authzid, nonce) = parse_client_first("n,,n=user,r=abcdefghijk").unwrap();
        assert_eq!(authcid, "user");
        assert!(authzid.is_none());
        assert_eq!(nonce, "abcdefghijk");

        let (authcid, authzid, nonce) =
            parse_client_first("y,a=other user,n=user,r=abcdef=hijk").unwrap();
        assert_eq!(authcid, "user");
        assert_eq!(authzid, Some("other user"));
        assert_eq!(nonce, "abcdef=hijk");

        let (authcid, authzid, nonce) = parse_client_first("n,,n=,r=").unwrap();
        assert_eq!(authcid, "");
        assert!(authzid.is_none());
        assert_eq!(nonce, "");
    }

    #[test]
    fn test_parse_client_first_missing_fields() {
        assert_eq!(
            parse_client_first("n,,n=user").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::Nonce))
        );
        assert_eq!(
            parse_client_first("n,,r=user").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::Authcid))
        );
        assert_eq!(
            parse_client_first("n,n=user,r=abc").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::Authzid))
        );
        assert_eq!(
            parse_client_first(",,n=user,r=abc").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::ChannelBinding))
        );
        assert_eq!(
            parse_client_first("").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::ChannelBinding))
        );
        assert_eq!(
            parse_client_first(",,,").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::ChannelBinding))
        );
    }
    #[test]
    fn test_parse_client_first_invalid_data() {
        assert_eq!(
            parse_client_first("a,,n=user,r=abc").unwrap_err(),
            Error::Protocol(Kind::InvalidField(Field::ChannelBinding))
        );
        assert_eq!(
            parse_client_first("p,,n=user,r=abc").unwrap_err(),
            Error::UnsupportedExtension
        );
        assert_eq!(
            parse_client_first("nn,,n=user,r=abc").unwrap_err(),
            Error::Protocol(Kind::InvalidField(Field::ChannelBinding))
        );
        assert_eq!(
            parse_client_first("n,,n,r=abc").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::Authcid))
        );
    }

    #[test]
    fn test_parse_client_final_success() {
        let (gs2head, nonce, proof) = parse_client_final("c=abc,r=abcefg,p=783232").unwrap();
        assert_eq!(gs2head, "abc");
        assert_eq!(nonce, "abcefg");
        assert_eq!(proof, "783232");

        let (gs2head, nonce, proof) = parse_client_final("c=,r=,p=").unwrap();
        assert_eq!(gs2head, "");
        assert_eq!(nonce, "");
        assert_eq!(proof, "");
    }

    #[test]
    fn test_parse_client_final_missing_fields() {
        assert_eq!(
            parse_client_final("c=whatever,r=something").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::Proof))
        );
        assert_eq!(
            parse_client_final("c=whatever,p=words").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::Nonce))
        );
        assert_eq!(
            parse_client_final("c=whatever").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::Nonce))
        );
        assert_eq!(
            parse_client_final("c=").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::Nonce))
        );
        assert_eq!(
            parse_client_final("").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::GS2Header))
        );
        assert_eq!(
            parse_client_final("r=anonce").unwrap_err(),
            Error::Protocol(Kind::ExpectedField(Field::GS2Header))
        );
    }
}
