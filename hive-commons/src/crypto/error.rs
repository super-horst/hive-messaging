use failure::{Error, Fail};

#[derive(Debug, Fail)]
pub enum CryptoError {
    #[fail(display = "Error message: {}", message)]
    Message { message: String },
    #[fail(display = "Unspecified error: {}", message)]
    Unspecified {
        message: String,
        #[fail(cause)]
        cause: Error,
    },
    #[fail(display = "I/O operation failed: {}", message)]
    IOError {
        message: String,
        #[fail(cause)]
        cause: std::io::Error,
    },
    #[fail(display = "Failed to process key: {}", message)]
    Key {
        message: String,
    },
    #[fail(display = "Failed to process signature: {}", message)]
    Signature {
        message: String,
    },
    #[fail(display = "KDF encountered an invalid length: {}", message)]
    InvalidLength {
        message: String,
        #[fail(cause)]
        cause: hkdf::InvalidLength,
    },
    #[fail(display = "Serialisation failed: {}", message)]
    Serialisation {
        message: String,
        #[fail(cause)]
        cause: crate::model::SerialisationError,
    },
    #[fail(display = "Failure: {}", message)]
    Common {
        message: String,
        #[fail(cause)]
        cause: crate::error::CommonError,
    },
}
