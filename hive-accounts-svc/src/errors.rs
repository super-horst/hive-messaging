use failure::{Error, Fail};

#[derive(Debug, Fail)]
pub enum AccountsError {
    #[fail(display = "Error message: {}", message)]
    Message { message: String },
    #[fail(display = "Unspecified error: {}", message)]
    GenericError {
        message: String,
        #[fail(cause)]
        cause: Error,
    },
    #[fail(display = "Conversion failed: {}", message)]
    Conversion {
        message: String,
        #[fail(cause)]
        cause: hex::FromHexError,
    },
    #[fail(display = "Transport failed: {}", message)]
    Transport {
        message: String,
        #[fail(cause)]
        cause: tonic::Status,
    },
    #[fail(display = "Cryptography failed: {}", message)]
    Cryptography {
        message: String,
        #[fail(cause)]
        cause: hive_crypto::CryptoError,
    },
    #[fail(display = "Database operation failed: {}", message)]
    Database {
        message: String,
        #[fail(cause)]
        cause: crate::persistence::RepositoryError,
    },
    #[fail(display = "Resource not found: {}", message)]
    NotFound { message: String },
    #[fail(display = "Resource already exists failed: {}", message)]
    AlreadyExists { message: String },
}
