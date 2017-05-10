# Salted Challenge Response Authentication Mechanism (SCRAM)

This implementation provides a client and a server for the SCRAM-SHA-256 mechanism according to
RFC5802 and RFC7677. It doesn't support channel-binding.

[Read the documentation.](https://tomprogrammer.github.io/scram/scram/index.html)

# Limitations

The mandatory SCRAM-SHA-1 authentication mechanism is currently not implemented. This is also true
for the *-PLUS variants, because channel-binding is not supported by this library. If you like to
contribute or maintain them I appreciate that.

# Usage

## Client

A typical usage scenario is shown below. For a detailed explanation of the methods please
consider their documentation. In productive code you should replace the unwrapping by proper
error handling.

At first the user and the password must be supplied using either of the methods
`ClientFirst::new` or `ClientFirst::with_rng`. These methods return a SCRAM
state you can use to compute the first client message.

The server and the client exchange four messages using the SCRAM mechanism. There is a rust type
for each one of them. Calling the methods `client_first`, `handle_server_first`, `client_final`
and `handle_server_final` on the different types advances the SCRAM handshake step by step.
Computing client messages never fails but processing server messages can result in failure.

```rust
use scram::ScramClient;

// This function represents your I/O implementation.
fn send_and_receive(message: &str) -> String {
    unimplemented!()
}

// Create a SCRAM state from the credentials.
let scram = ScramClient::new("user", "password", None).unwrap();

// Get the client message and reassign the SCRAM state.
let (scram, client_first) = scram.client_first();

// Send the client first message and receive the servers reply.
let server_first = send_and_receive(&client_first);

// Process the reply and again reassign the SCRAM state. You can add error handling to
// abort the authentication attempt.
let scram = scram.handle_server_first(&server_first).unwrap();

// Get the client final message and reassign the SCRAM state.
let (scram, client_final) = scram.client_final();

// Send the client final message and receive the servers reply.
let server_final = send_and_receive(&client_final);

// Process the last message. Any error returned means that the authentication attempt
// wasn't successful.
let () = scram.handle_server_final(&server_final).unwrap();
```

## Server

The server is created to respond to incoming challenges from a client.  A typical usage pattern,
with a default provider is shown below.  In production, you would implement an AuthenticationProvider
that could look up user credentials based on a username

The server and the client exchange four messages using the SCRAM mechanism. There is a rust type for
each one of them. Calling the methods `handle_client_first()`, `server_first()`,
`handle_client_final()` and `server_final()` on the different types advances the SCRAM handshake
step by step. Computing server messages never fails (unless the source of randomness for the nonce
fails), but processing client messages can result in failure.

The final step will not return an error if authentication failed, but will return an
`AuthenticationStatus` which you can use to determine if authentication was successful or not.

```rust
use scram::{ScramServer, AuthenticationStatus, AuthenticationProvider, PasswordInfo};

// Create a dummy authentication provider
struct ExampleProvider;
impl AuthenticationProvider for ExampleProvider {
    // Here you would look up password information for the the given username
    fn get_password_for(&self, username: &str) -> Option<PasswordInfo> {
       unimplemented!()
    }

}
// These functions represent your I/O implementation.
# #[allow(unused_variables)]
fn receive() -> String {
    unimplemented!()
}
# #[allow(unused_variables)]
fn send(message: &str) {
    unimplemented!()
}

// Create a new ScramServer using the example authenication provider
let scram_server = ScramServer::new(ExampleProvider{});

// Receive a message from the client
let client_first = receive();

// Create a SCRAM state from the client's first message
let scram_server = scram_server.handle_client_first(&client_first).unwrap();
// Craft a response to the client's message and advance the SCRAM state
// We could use our own source of randomness here, with `server_first_with_rng()`
let (scram_server, server_first) = scram_server.server_first().unwrap();
// Send our message to the client and read the response
send(&server_first);
let client_final = receive();

// Process the client's challenge and re-assign the SCRAM state.  This could fail if the
// message was poorly formatted
let scram_server = scram_server.handle_client_final(&client_final).unwrap();

// Prepare the final message and get the authentication status
let(status, server_final) = scram_server.server_final();
// Send our final message to the client
send(&server_final);

// Check if the client successfully authenticated
assert_eq!(status, AuthenticationStatus::Authenticated);
```
