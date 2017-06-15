use std::{error, fmt};

/// The SCRAM mechanism error cases.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// A message wasn't formatted as required. `Kind` contains further information.
    ///
    /// RFC5803 section 7 describes the format of the exchanged messages.
    Protocol(Kind),
    /// The server required a mandatory extension to be present that this client doesn't support.
    UnsupportedExtension,
    /// The server couldn't be validated. This usually means that the server didn't posess a stored
    /// key to verify the credentials.
    InvalidServer,
    /// The server rejected the authentication request. `String` contains a message from the server.
    Authentication(String),
    /// The username supplied was not valid
    InvalidUser(String),
}

/// The kinds of protocol errors.
#[derive(Debug, PartialEq)]
pub enum Kind {
    /// The server responded with a nonce that doesn't start with our nonce.
    InvalidNonce,
    /// The content of the field `Field` is invalid.
    InvalidField(Field),
    /// The field `Field` was expected but not found.
    ExpectedField(Field),
}

/// The fields used in the exchanged messages.
#[derive(Debug, PartialEq)]
pub enum Field {
    /// Nonce
    Nonce,
    /// Salt
    Salt,
    /// Iterations
    Iterations,
    /// Verify or Error
    VerifyOrError,
    /// Channel Binding
    ChannelBinding,
    /// Authtorization ID
    Authzid,
    /// Authcid
    Authcid,
    /// GS2Header
    GS2Header,
    /// Client Proof
    Proof,
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        use self::Kind::*;
        match *self {
            Protocol(InvalidNonce) => write!(fmt, "Invalid nonce"),
            Protocol(InvalidField(ref field)) => write!(fmt, "Invalid field {:?}", field),
            Protocol(ExpectedField(ref field)) => write!(fmt, "Expected field {:?}", field),
            UnsupportedExtension => write!(fmt, "Unsupported extension"),
            InvalidServer => write!(fmt, "Server failed validation"),
            InvalidUser(ref username) => write!(fmt, "Invalid user: '{}'", username),
            Authentication(ref msg) => write!(fmt, "authentication error {}", msg),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        use self::Error::*;
        use self::Kind::*;
        match *self {
            Protocol(InvalidNonce) => "Invalid nonce",
            Protocol(InvalidField(_)) => "Invalid field",
            Protocol(ExpectedField(_)) => "Expected field",
            UnsupportedExtension => "Unsupported extension",
            InvalidServer => "Server failed validation",
            InvalidUser(_) => "Invalid user",
            Authentication(_) => "Unspecified error",
        }
    }
}
