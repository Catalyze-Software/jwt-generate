use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use ic_cdk::{caller, query, update};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use p256::pkcs8::DecodePrivateKey;
use serde_json::json;

/// Include the private key PEM file
const PRIVATE_KEY_PEM: &[u8] = include_bytes!("private_key.pem");

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
fn create_jwt(name: String) -> String {
    let secret_key = parse_private_key();

    let sub = caller().to_string();

    let now = ic_cdk::api::time() / 1_000_000_000; // Convert nanoseconds to seconds
    let exp = now + 60 * 60; // 1 hour expiration

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
    });

    // Base64URL encode header and payload
    let encoded_header = encode_config(header.to_string(), URL_SAFE_NO_PAD);
    let encoded_payload = encode_config(payload.to_string(), URL_SAFE_NO_PAD);

    // Create signing input
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);

    // Sign the input
    let signature: Signature = secret_key.sign(signing_input.as_bytes());

    // Convert the DER-encoded signature to raw format (64 bytes)
    let der_bytes = signature.to_der();
    let asn1_sig = Signature::from_der(der_bytes.as_ref()).expect("Invalid DER signature");

    let mut r_padded = [0u8; 32];
    let mut s_padded = [0u8; 32];

    // Ensure r and s are padded to 32 bytes
    let r_bytes = asn1_sig.r().to_bytes();
    let s_bytes = asn1_sig.s().to_bytes();
    r_padded[32 - r_bytes.len()..].copy_from_slice(&r_bytes);
    s_padded[32 - s_bytes.len()..].copy_from_slice(&s_bytes);

    // Combine `r` and `s` into a 64-byte raw signature
    let mut raw_signature = [0u8; 64];
    raw_signature[..32].copy_from_slice(&r_padded);
    raw_signature[32..].copy_from_slice(&s_padded);

    let encoded_signature = encode_config(raw_signature, URL_SAFE_NO_PAD);

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

    // Ensure the signature is 64 bytes (raw ECDSA format)
    if signature.len() != 64 {
        ic_cdk::println!("Invalid signature length: {}", signature.len());
        return false;
    }

    // Verify the signature
    let public_key = get_verifying_key();
    match Signature::try_from(&signature[..]) {
        Ok(sig) => {
            if public_key.verify(signing_input.as_bytes(), &sig).is_ok() {
                ic_cdk::println!("Signature is valid");
            } else {
                ic_cdk::println!("Signature verification failed");
                return false;
            }
        }
        Err(_) => {
            ic_cdk::println!("Invalid signature format");
            return false;
        }
    }

    // Decode the payload
    let payload_json = match decode_config(encoded_payload, URL_SAFE_NO_PAD) {
        Ok(payload) => match String::from_utf8(payload) {
            Ok(json) => match serde_json::from_str::<serde_json::Value>(&json) {
                Ok(payload) => payload,
                Err(_) => {
                    ic_cdk::println!("Failed to parse payload");
                    return false;
                }
            },
            Err(_) => {
                ic_cdk::println!("Failed to decode payload");
                return false;
            }
        },
        Err(_) => {
            ic_cdk::println!("Failed to decode payload");
            return false;
        }
    };

    // Validate expiry
    if let Some(exp) = payload_json.get("exp").and_then(|e| e.as_u64()) {
        let now = ic_cdk::api::time() / 1_000_000_000; // Convert nanoseconds to seconds
        if now > exp {
            ic_cdk::println!("Token has expired");
            return false;
        }
    } else {
        ic_cdk::println!("Missing or invalid 'exp' claim");
        return false;
    }

    ic_cdk::println!("JWT is valid");
    true
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
