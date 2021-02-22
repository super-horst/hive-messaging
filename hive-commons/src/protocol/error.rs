use failure::Fail;

use crate::crypto::CryptoError;
use crate::error::CommonError;
use crate::model::SerialisationError;

#[derive(Debug, Fail)]
pub enum ProtocolError {
    #[fail(display = "Error message: {}", message)]
    Message { message: String },
    #[fail(display = "Invalid session state: {}", message)]
    InvalidSessionState { message: String },
    #[fail(display = "Error during protocol cryptography: {}", message)]
    FailedCryptography {
        message: String,
        #[fail(cause)]
        cause: CryptoError,
    },
    #[fail(display = "Serialisation failed")]
    FailedSerialisation {
        #[fail(cause)]
        cause: SerialisationError,
    },
    #[fail(display = "Failure: {}", message)]
    CommonFailure {
        message: String,
        #[fail(cause)]
        cause: CommonError,
    },
    #[fail(display = "Input is invalid: {}", message)]
    InvalidInput { message: String },
}
