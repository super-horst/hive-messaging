use crate::prelude::*;

use crate::crypto::PrivateIdentity;

use failure::{Error, Fail};

#[derive(Debug, Fail)]
pub enum AccountsError {
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
    #[fail(display = "Transport failed: {}", message)]
    Transport {
        message: String,
        #[fail(cause)] cause: tonic::Status,
    },
    #[fail(display = "Error during I/O: {}", message)]
    IoError {
        message: String,
        #[fail(cause)] cause: io::Error,
    },
    #[fail(display = "Cryptography failed: {}", message)]
    Cryptography {
        message: String,
        #[fail(cause)] cause: crate::crypto::CryptoError,
    },
}

#[async_trait::async_trait]
pub trait AccountService: Send + Sync {
    /// Refresh the current attestation from the server
    async fn update_attestation(&mut self, id: &dyn PrivateIdentity) -> Result<(), AccountsError>;
}
