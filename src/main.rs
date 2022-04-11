use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

const SECRET: &str = "My_VeRy_StRoNg_SeCrEt";

fn main() {
    // This implementation uses HMAC SHA256 for signing header and payload.

    // Create header and encode it
    let header = json!({
        "alg": "HS256",
        "typ": "JWT"
    });
    let header_encoded = base64::encode_config(&header.to_string(), base64::URL_SAFE_NO_PAD);

    // Create payload and encode it
    let payload = json!({
        "iat": Utc::now().to_rfc3339(),
        "username": "amirheidarikhoram",
        "email": "amir.heidari.khoram@gmail.com",
        // expires after 7 days from now
        "exp": (Utc::now() + Duration::days(7)).to_rfc3339(),
    });
    let payload_encoded = base64::encode_config(&payload.to_string(), base64::URL_SAFE_NO_PAD);

    // Sign and get tag
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(format!("{}.{}", header_encoded, payload_encoded).as_bytes());
    let res = mac.finalize().into_bytes();
    let sign_tag = res.as_slice();

    // Encode tag
    let signature_encoded = base64::encode_config(sign_tag, base64::URL_SAFE_NO_PAD);

    // Print JWT
    let token = format!(
        "{}.{}.{}",
        header_encoded, payload_encoded, signature_encoded
    );
    println!(">>> Token:\n{}\n\n", token);

    // Verify JWT
    let splitted_token = token.split(".").collect::<Vec<&str>>();
    let encoded_header_payload = format!("{}.{}", splitted_token[0], splitted_token[1]);
    let encoded_tag = splitted_token[2];
    let ver_tag =
        base64::decode_config(encoded_tag, base64::URL_SAFE_NO_PAD).expect("Could not decode tag");
    let mut ver_mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
    ver_mac.update(encoded_header_payload.as_bytes());
    
    
    match ver_mac.verify_slice(&ver_tag[..]) {
        Ok(_) => {
            println!(">>>[Ok] Token signature verified")
        }
        Err(err) => {
            println!(">>>[Err] Token signature not verified, {}", err)
        }
    }
}
