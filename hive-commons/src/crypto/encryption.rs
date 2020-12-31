use chacha20poly1305;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

fn encrypt(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(&[] as &[u8]);

    // TODO error handling
    cipher.encrypt(nonce, payload).expect("encryption failure!")
}

fn decrypt(key: &[u8], encrypted: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(&[] as &[u8]);

    // TODO error handling
    cipher
        .decrypt(nonce, encrypted)
        .expect("decryption failure!")
}
