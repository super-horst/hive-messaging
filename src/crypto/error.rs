use failure::{Error, Fail};
#[derive(Debug, Fail)]
pub enum CryptoError {
    #[fail(display = "Error message: {}", message)]
    Message {
        message: String,
    },
    #[fail(display = "Unspecified error: {}", message)]
    Unspecified {
        message: String,
        #[fail(cause)] cause: Error,
    },
    #[fail(display = "Encoding failed: {}", message)]
    Encoding {
        message: String,
        #[fail(cause)] cause: prost::EncodeError,
    },
    #[fail(display = "Failed to process key: {}", message)]
    Key {
        message: String,
        #[fail(cause)] cause: ed25519_dalek::errors::SignatureError,
    },
    #[fail(display = "Failed to process signature: {}", message)]
    Signature {
        message: String,
        #[fail(cause)] cause: ed25519_dalek::errors::SignatureError,
    },
}
