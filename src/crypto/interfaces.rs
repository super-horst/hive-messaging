use std::fmt;

use failure::{Error, Fail};

#[derive(Debug, Fail)]
pub enum CryptoError {
    #[fail(display = "Error message: {}", message)]
    Message {
        message: String,
    },
    #[fail(display = "Unspecified error: {}", message)]
    GenericError {
        message: String,
        #[fail(cause)] cause: Error,
    },
    #[fail(display = "Encoding failed: {}", message)]
    Encoding {
        message: String,
        #[fail(cause)] cause: prost::EncodeError,
    },
    #[fail(display = "Failed to process signature: {}", message)]
    Signature {
        message: String,
        #[fail(cause)] cause: ed25519_dalek::errors::SignatureError,
    },
}

/// Identity provider
#[async_trait::async_trait]
pub trait Identities: Send + Sync {
    /// resolve identity from the given bytes
    /// async covers I/O use cases
    async fn resolve_id(&self, id: &[u8]) -> Result<Box<dyn PublicIdentity>, CryptoError>;

    /// the current main identity
    fn my_id(&self) -> &dyn PrivateIdentity;
}

/// A cryptographic identity
pub trait Identity: fmt::Debug + Send + Sync {
    /// Hexstring of this cryptographic identity
    fn id(&self) -> String;

    /// this identity's namespace
    fn namespace(&self) -> String;
}

pub trait PublicIdentity: Identity {
    ///Verify a raw byte signature
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;

    /// encode public identities as bytes
    fn as_bytes(&self) -> Vec<u8>;
}

pub trait PrivateIdentity: Identity {
    /// Sign some data using the underlying private key.
    /// Since the digest used is SHA512, output will be 64 bytes
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn public_id(&self) -> &dyn PublicIdentity;
}