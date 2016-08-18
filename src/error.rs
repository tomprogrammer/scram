use std::{error, fmt};

/// SCRAM mechanism error cases.
#[derive(Debug)]
pub enum Error {
    /// A message wasn't formatted as required. `Kind` contains further information.
    ///
    /// RFC5803 section 7 describes the format of the exchanged messages.
    Protocol(Kind),
    /// The server required a mandatory extension to be present that this client doesn't support.
    UnsupportedExtension,
    /// The server couldn't be validated.
    InvalidServer,
    /// The server rejected the authentication request.
    Authentication(String),
}

/// Kinds of protocol errors.
#[derive(Debug)]
pub enum Kind {
    /// The server responded with a nonce that doesn't start with our nonce.
    InvalidNonce,
    /// The content of the field `Field` is invalid.
    InvalidField(Field),
    /// The field `Field` was expected but not found.
    ExpectedField(Field),
}

/// Fields used in the exchanged messages.
#[derive(Debug)]
pub enum Field {
    /// Nonce
    Nonce,
    /// Salt
    Salt,
    /// Iterations
    Iterations,
    /// Verify or Error
    VerifyOrError,
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
            Authentication(_) => "Unspecified error",
        }
    }
}
