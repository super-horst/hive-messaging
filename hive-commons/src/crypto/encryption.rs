use chacha20poly1305;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

pub fn encrypt(key_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // TODO improve nonce
    let nonce = Nonce::from_slice(&[0u8; 12] as &[u8]);

    // TODO error handling
    cipher.encrypt(nonce, payload).expect("encryption failure!")
}

pub fn decrypt(key_bytes: &[u8], encrypted: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // TODO improve nonce
    let nonce = Nonce::from_slice(&[0u8; 12] as &[u8]);

    // TODO error handling
    cipher
        .decrypt(nonce, encrypted)
        .expect("decryption failure!")
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

        let encrypted = encrypt(&key_bytes, data);
        let decrypted = decrypt(&key_bytes, &encrypted[..]);

        assert_eq!(data, &decrypted[..])
    }
}
