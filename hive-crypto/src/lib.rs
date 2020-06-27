

use std::sync::Arc;

mod cryptostorage;
mod error;
pub use error::*;

#[cfg(test)]
mod test_utils;


mod dalek_keys;
mod certificates;

pub use dalek_keys::{PrivateKey,
                     PublicKey,
                     SimpleDalekIdentities};

pub use certificates::{Certificate,
                       CertificateInfoBundle,
                       CertificateEncoding,
                       CertificateFactory};

mod ratchet;
mod x3dh;

pub use ratchet::*;

/// Identity provider
#[async_trait::async_trait]
pub trait Identities: Send + Sync {
    /// resolve identity from the given bytes
    /// async covers I/O use cases
    async fn resolve_id(&self, id: &[u8]) -> Result<PublicKey, CryptoError>;

    /// the current main identity
    fn my_id(&self) -> &PrivateKey;

    /// the current main identity
    fn my_certificate(&self) -> &Arc<Certificate>;
}



// TODO IMPLEMENTATION RUINS -> RECYCLE IF POSSIBLE

/*
pub trait KeyImplementation {
    type PublicKey: PublicIdentity;
    type PrivateKey: PrivateIdentity;

    fn generate_private() -> Result<Self::PrivateKey, CryptoError>;

    fn public_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError>;

    fn diffie_hellman(private: &Self::PrivateKey, public: &Self::PublicKey) -> Result<Vec<u8>, CryptoError>;
}

pub struct Dalek;

impl KeyImplementation for Dalek {
    type PublicKey = DalekEd25519PublicId;
    type PrivateKey = DalekEd25519PrivateId;

    fn generate_private() -> Result<Self::PrivateKey, CryptoError> {
        DalekEd25519PrivateId::generate()
    }

    fn public_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError> {
        DalekEd25519PublicId::from_raw_bytes(bytes)
    }

    fn diffie_hellman(private: &Self::PrivateKey, public: &Self::PublicKey) -> Result<Vec<u8>, CryptoError> {
        Ok(private.diffie_hellman(public).as_bytes().to_vec())
    }
}*/
