//! # Salted Challenge Response Authentication Mechanism (SCRAM)
//!
//! This implementation currently provides a client for the SCRAM-SHA-256 mechanism according to
//! RFC5802 and RFC7677. It doesn't support channel-binding.
//!
//! # Usage
//!
//! A typical usage scenario is shown below. For a detailed explanation of the methods please
//! consider their documentation. In productive code you should replace the unwrapping by proper
//! error handling.
//!
//! At first the user and the password must be supplied using either of the methods
//! [`ClientFirst::new`](struct.ClientFirst.html#method.new) or
//! [`ClientFirst::with_rng`](struct.ClientFirst.html#method.with_rng). These methods return a SCRAM
//! state you can use to compute the first client message.
//!
//! The server and the client exchange four messages using the SCRAM mechanism. There is a rust type
//! for each one of them. Calling the methods
//! [`client_first`](struct.ClientFirst.html#method.client_first),
//! [`handle_server_first`](struct.ServerFirst.html#method.handle_server_first),
//! [`client_final`](struct.ClientFinal.html#method.client_final) and
//! [`handle_server_final`](struct.ServerFinal.html#method.handle_server_final) on the different
//! types advances the SCRAM handshake step by step. Computing client messages never fails but
//! processing server messages can result in failure.
//!
//! ``` rust,norun
//! use scram::ClientFirst;
//!
//! // This function represents your I/O implementation.
//! fn send_and_receive(message: &str) -> String {
//!     unimplemented!()
//! }
//!
//! // Create a SCRAM state from the credentials.
//! let scram = ClientFirst::new("user", "password", None).unwrap();
//!
//! // Get the client message and reassign the SCRAM state.
//! let (scram, client_first) = scram.client_first();
//!
//! // Send the client first message and receive the servers reply.
//! let server_first = send_and_receive(&client_first);
//!
//! // Process the reply and again reassign the SCRAM state. You can add error handling to
//! // abort the authentication attempt.
//! let scram = scram.handle_server_first(server_first).unwrap();
//!
//! // Get the client final message and reassign the SCRAM state.
//! let (scram, client_final) = scram.client_final();
//!
//! // Send the client final message and receive the servers reply.
//! let server_final = send_and_receive(&client_final);
//!
//! // Process the last message. Any error returned means that the authentication attempt
//! // wasn't successful.
//! let () = scram.handle_server_final(server_final).unwrap();
//! ```

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
