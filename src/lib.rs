use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use ic_cdk::{api::management_canister::main::raw_rand, caller, query, update};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use p256::pkcs8::DecodePrivateKey;
use serde_json::json;

/// Include the private key PEM file
const PRIVATE_KEY_PEM: &[u8] = include_bytes!("private_key_pkcs8.pem");

/// Parse the private key from the included PEM file.
fn parse_private_key() -> SigningKey {
    let pem_str = std::str::from_utf8(PRIVATE_KEY_PEM).expect("Invalid PEM file");
    let key_data = pem_str
        .lines()
        .filter(|line| !line.starts_with("---"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::decode(key_data).expect("Invalid base64 in PEM file");
    SigningKey::from_pkcs8_der(&der).expect("Failed to parse private key")
}

/// Get the verifying (public) key.
fn get_verifying_key() -> VerifyingKey {
    *parse_private_key().verifying_key()
}

#[update]
async fn create_jwt(name: String) -> String {
    let secret_key = parse_private_key();

    // Get the caller's Principal ID as the subject
    let sub = caller().to_string();

    let now = ic_cdk::api::time() / 1_000_000_000;
    let exp = now + 60 * 60;

    // Generate randomness for the `jti` claim
    let (raw_randomness,) = raw_rand().await.expect("Failed to get randomness");
    let jti = base64::encode_config(raw_randomness, URL_SAFE_NO_PAD);

    // JWT Header
    let header = json!({
        "alg": "ES256",
        "typ": "JWT"
    });

    // JWT Payload
    let payload = json!({
        "sub": sub,
        "name": name,
        "exp": exp,
        "iat": now,
        "jti": jti
    });

    // Base64URL encode header and payload
    let encoded_header = encode_config(header.to_string(), URL_SAFE_NO_PAD);
    let encoded_payload = encode_config(payload.to_string(), URL_SAFE_NO_PAD);

    // Create signing input
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);

    // Sign the input
    let signature: Signature = secret_key.sign(signing_input.as_bytes());

    // Serialize the signature and Base64URL encode it
    let encoded_signature = encode_config(signature.to_der().as_ref(), URL_SAFE_NO_PAD);

    // Create the final JWT
    format!(
        "{}.{}.{}",
        encoded_header, encoded_payload, encoded_signature
    )
}

/// Validate a JWT
#[query]
fn validate_jwt(jwt: String) -> bool {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        ic_cdk::println!("Invalid JWT format");
        return false; // Invalid JWT format
    }

    let (encoded_header, encoded_payload, encoded_signature) = (parts[0], parts[1], parts[2]);
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);

    // Decode the signature
    let signature = match decode_config(encoded_signature, URL_SAFE_NO_PAD) {
        Ok(sig) => sig,
        Err(_) => {
            ic_cdk::println!("Failed to decode signature");
            return false;
        }
    };

    // Verify the signature
    let public_key = get_verifying_key();
    match Signature::from_der(&signature) {
        Ok(sig) => {
            if public_key.verify(signing_input.as_bytes(), &sig).is_ok() {
                ic_cdk::println!("JWT is valid");
                true
            } else {
                ic_cdk::println!("Signature verification failed");
                false
            }
        }
        Err(_) => {
            ic_cdk::println!("Invalid signature format");
            false
        }
    }
}

/// Expose the public key
#[query]
fn get_public_key() -> String {
    let public_key = get_verifying_key();
    let encoded_point = public_key.to_encoded_point(false);

    // Convert to PEM format
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        encode_config(encoded_point.as_bytes(), base64::STANDARD)
    )
}

#[query(name = "__get_candid_interface_tmp_hack")]
pub fn export_candid_interface() -> String {
    use candid::export_service;

    export_service!();
    __export_service()
}

/// Save the Candid interface to a file
#[test]
pub fn save_candid_interface() {
    use std::env;
    use std::fs::write;
    use std::path::PathBuf;

    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dir = dir.parent().unwrap().join("candid");
    write(dir.join("jwt_generate.did"), export_candid_interface())
        .expect("Failed to write Candid file.");
}
