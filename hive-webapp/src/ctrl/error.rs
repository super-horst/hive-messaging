use failure::Fail;

use hive_commons::crypto::CryptoError;
use hive_commons::model::SerialisationError;
use hive_commons::protocol::ProtocolError;

#[derive(Debug, Fail)]
pub enum ControllerError {
    #[fail(display = "Error message: {}", message)]
    Message { message: String },
    #[fail(display = "Invalid controller state: {}", message)]
    InvalidState { message: String },
    #[fail(display = "No data found: {}", message)]
    NoDataFound { message: String },
    #[fail(display = "Error during protocol execution: {}", message)]
    ProtocolExecution {
        message: String,
        #[fail(cause)]
        cause: ProtocolError,
    },
    #[fail(display = "Serialisation failed")]
    FailedSerialisation {
        #[fail(cause)]
        cause: SerialisationError,
    },
    #[fail(display = "Serialisation failed")]
    IOError {
        #[fail(cause)]
        cause: std::io::Error,
    },
    #[fail(display = "Error during cryptography: {}", message)]
    CryptographicError {
        message: String,
        #[fail(cause)]
        cause: CryptoError,
    },
}
