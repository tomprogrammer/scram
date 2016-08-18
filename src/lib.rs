//! Salted Challenge Response Authentication Mechanism (SCRAM)
//!
//! This implementation currently provides the SCRAM-SHA-256 mechanism according to RFC5802 and
//! RFC7677.

#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate data_encoding;
extern crate rand;
extern crate ring;

mod error;
mod client;

use std::fmt;
use std::ops::Deref;
use ring::digest::Digest;

pub use error::{Error, Kind, Field};
pub use client::{ClientFirst, ServerFirst, ClientFinal, ServerFinal};

// Work around `ring::digest::Digest` not implementing `Debug`.
struct DebugDigest(Digest);

impl fmt::Debug for DebugDigest {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str("SHA-256:"));
        for byte in self.0.as_ref() {
            try!(write!(fmt, "{:02x}", byte));
        }
        Ok(())
    }
}

impl Deref for DebugDigest {
    type Target = Digest;
    fn deref(&self) -> &Digest {
        &self.0
    }
}
