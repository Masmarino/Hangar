//! Encrypts a secret at rest with AES-256-GCM, keyed from `JWT_SECRET` rather than a second operational secret.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hangar_domain::error::DomainError;
use rand::Rng;
use sha2::{Digest, Sha256};

/// Deterministic — the same `jwt_secret` always derives the same key.
fn derive_key(jwt_secret: &str) -> [u8; 32] {
    Sha256::digest(jwt_secret.as_bytes()).into()
}

/// Returns `(ciphertext, nonce)` — both must be stored to decrypt later.
pub fn encrypt(plaintext: &str, jwt_secret: &str) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(derive_key(jwt_secret)));
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).expect("AES-GCM encryption of a bounded in-memory plaintext cannot fail");
    (ciphertext, nonce_bytes.to_vec())
}

pub fn decrypt(ciphertext: &[u8], nonce: &[u8], jwt_secret: &str) -> Result<String, DomainError> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(derive_key(jwt_secret)));
    let nonce = Nonce::try_from(nonce).map_err(|_| DomainError::Infrastructure("stored nonce had an unexpected length".to_string()))?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| DomainError::Infrastructure("failed to decrypt stored secret".to_string()))?;
    String::from_utf8(plaintext).map_err(|_| DomainError::Infrastructure("decrypted secret was not valid UTF-8".to_string()))
}

/// Packs nonce + ciphertext into one hex string, for columns that store a single value.
pub fn encrypt_packed(plaintext: &str, jwt_secret: &str) -> String {
    let (ciphertext, nonce) = encrypt(plaintext, jwt_secret);
    hex::encode([nonce, ciphertext].concat())
}

/// Falls back to treating `packed` as legacy plaintext if it isn't valid ciphertext.
pub fn decrypt_packed(packed: &str, jwt_secret: &str) -> String {
    let Ok(bytes) = hex::decode(packed) else { return packed.to_string() };
    if bytes.len() < 12 {
        return packed.to_string();
    }
    let (nonce, ciphertext) = bytes.split_at(12);
    decrypt(ciphertext, nonce, jwt_secret).unwrap_or_else(|_| {
        tracing::warn!("a stored secret looked like packed ciphertext but failed to decrypt — treating as legacy plaintext; if this is unexpected, check whether JWT_SECRET changed");
        packed.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypting_then_decrypting_returns_the_original_plaintext() {
        let (ciphertext, nonce) = encrypt("hunter2", "jwt-secret");
        assert_eq!(decrypt(&ciphertext, &nonce, "jwt-secret").unwrap(), "hunter2");
    }

    #[test]
    fn decrypting_with_the_wrong_key_fails() {
        let (ciphertext, nonce) = encrypt("hunter2", "jwt-secret-a");
        assert!(decrypt(&ciphertext, &nonce, "jwt-secret-b").is_err());
    }

    #[test]
    fn two_encryptions_of_the_same_plaintext_use_different_nonces() {
        let (ciphertext_a, nonce_a) = encrypt("hunter2", "jwt-secret");
        let (ciphertext_b, nonce_b) = encrypt("hunter2", "jwt-secret");
        assert_ne!(nonce_a, nonce_b, "a reused nonce would break AES-GCM's security guarantees");
        assert_ne!(ciphertext_a, ciphertext_b);
    }

    #[test]
    fn packed_encryption_round_trips() {
        let packed = encrypt_packed("hunter2", "jwt-secret");
        assert_eq!(decrypt_packed(&packed, "jwt-secret"), "hunter2");
    }

    #[test]
    fn packed_value_never_contains_the_plaintext() {
        let packed = encrypt_packed("hunter2", "jwt-secret");
        assert!(!packed.contains("hunter2"));
    }

    #[test]
    fn decrypt_packed_falls_back_to_treating_unrecognized_input_as_legacy_plaintext() {
        assert_eq!(decrypt_packed("not-encrypted-at-all", "jwt-secret"), "not-encrypted-at-all");
    }

    #[test]
    fn decrypt_packed_falls_back_when_the_key_no_longer_matches() {
        let packed = encrypt_packed("hunter2", "jwt-secret-a");
        assert_eq!(decrypt_packed(&packed, "jwt-secret-b"), packed, "must not panic or lose data on a key mismatch");
    }
}
