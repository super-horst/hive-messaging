use hkdf::Hkdf;
use sha2::Sha512;

use crate::error::*;

use failure::{Error, Fail};

#[derive(Debug, Fail)]
pub enum RatchetError {
    #[fail(display = "KDF encountered an invalid length: {}", message)]
    InvalidLength {
        message: String,
        #[fail(cause)] cause: hkdf::InvalidLength,
    },
}

pub struct DhRatchet;

pub struct KdfChain {
    current: [u8; 32],
}

impl KdfChain {
    pub fn init(key: [u8; 32]) -> KdfChain {
        KdfChain { current: key }
    }

    pub fn update(&mut self) -> Result<[u8; 32], RatchetError> {
        let h = Hkdf::<Sha512>::new(None, &self.current);

        let mut okm = [0u8; 64];
        h.expand(&[0u8; 0], &mut okm).map_err(|e| RatchetError::InvalidLength {
            message: "Buffer underflow in HKDF expansion ".to_string(),
            cause: e,
        })?;

        let mut kdf_update = [0u8; 32];
        let mut output = [0u8; 32];

        kdf_update.clone_from_slice(&okm[..32]);
        output.clone_from_slice(&okm[32..]);

        self.current = kdf_update;

        Ok(output)
    }
}

fn testing() {
    /*use chacha20poly1305::ChaCha20Poly1305;

    let chacha = ChaCha20Poly1305::new(Default::default());
    chacha.encrypt(&Default::default(), &*buf));*/
}