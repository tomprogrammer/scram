extern crate rand;
extern crate ring;
extern crate scram;

use ring::digest::SHA256_OUTPUT_LEN;
use scram::*;

struct TestProvider {
    user_password: [u8; SHA256_OUTPUT_LEN],
    admin_password: [u8; SHA256_OUTPUT_LEN],
}

impl TestProvider {
    pub fn new() -> Self {
        let user_password = hash_password("password", 4096, b"salt");
        let admin_password = hash_password("admin_password", 8192, b"messy");
        TestProvider {
            user_password: user_password,
            admin_password: admin_password,
        }
    }
}

impl server::AuthenticationProvider for TestProvider {
    fn get_password_for(&self, username: &str) -> Option<server::PasswordInfo> {
        match username {
            "user" => Some(server::PasswordInfo::new(
                self.user_password.to_vec(),
                4096,
                "salt".bytes().collect(),
            )),
            "admin" => Some(server::PasswordInfo::new(
                self.admin_password.to_vec(),
                8192,
                "messy".bytes().collect(),
            )),
            _ => None,
        }
    }

    fn authorize(&self, authcid: &str, authzid: &str) -> bool {
        authcid == authzid || authcid == "admin" && authzid == "user"
    }
}

#[test]
fn test_simple_success() {
    let scram_client = ScramClient::new("user", "password", None).unwrap();
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first().unwrap();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    scram_client.handle_server_final(&server_final).unwrap();

    assert_eq!(status, AuthenticationStatus::Authenticated);
}

#[test]
fn test_bad_password() {
    let scram_client = ScramClient::new("user", "badpassword", None).unwrap();
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first().unwrap();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::NotAuthenticated);
    assert!(scram_client.handle_server_final(&server_final).is_err());
}

#[test]
fn test_authorize_different() {
    let scram_client = ScramClient::new("admin", "admin_password", Some("user")).unwrap();
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first().unwrap();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    scram_client.handle_server_final(&server_final).unwrap();

    assert_eq!(status, AuthenticationStatus::Authenticated);
}

#[test]
fn test_authorize_fail() {
    let scram_client = ScramClient::new("user", "password", Some("admin")).unwrap();
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first().unwrap();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::NotAuthorized);
    assert!(scram_client.handle_server_final(&server_final).is_err());
}

#[test]
fn test_authorize_non_existent() {
    let scram_client = ScramClient::new("admin", "admin_password", Some("nonexistent")).unwrap();
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first().unwrap();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::NotAuthorized);
    assert!(scram_client.handle_server_final(&server_final).is_err());
}

#[test]
fn test_invalid_user() {
    let scram_client = ScramClient::new("nobody", "password", None).unwrap();
    let scram_server = ScramServer::new(TestProvider::new());

    let (_, client_first) = scram_client.client_first();

    assert!(scram_server.handle_client_first(&client_first).is_err())
}

#[test]
fn test_empty_username() {
    let scram_client = ScramClient::new("", "password", None).unwrap();
    let scram_server = ScramServer::new(TestProvider::new());

    let (_, client_first) = scram_client.client_first();

    assert!(scram_server.handle_client_first(&client_first).is_err())
}

#[test]
fn test_empty_password() {
    let scram_client = ScramClient::new("user", "", None).unwrap();
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first().unwrap();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::NotAuthenticated);
    assert!(scram_client.handle_server_final(&server_final).is_err());
}
