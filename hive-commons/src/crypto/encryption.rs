use crate::crypto::CryptoError;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

pub fn encrypt(key_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // TODO improve nonce
    let nonce = Nonce::from_slice(&[0u8; 12] as &[u8]);

    cipher
        .encrypt(nonce, payload)
        .map_err(|_cause| CryptoError::Cipher {
            message: "encryption failure!".to_string(),
        })
}

pub fn decrypt(key_bytes: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // TODO improve nonce
    let nonce = Nonce::from_slice(&[0u8; 12] as &[u8]);

    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_cause| CryptoError::Cipher {
            message: "decryption failure!".to_string(),
        })
}

#[cfg(test)]
pub mod encryption_tests {
    use super::*;

    #[test]
    fn test_full_roundtrip() {
        use rand_core::{OsRng, RngCore};

        let mut key_bytes = [0u8; 32];
        OsRng::default().fill_bytes(&mut key_bytes);

        let data: &[u8] = b"testdata is overrated";

        let encrypted = encrypt(&key_bytes, data).unwrap();
        let decrypted = decrypt(&key_bytes, &encrypted[..]).unwrap();

        assert_eq!(data, &decrypted[..])
    }
}
