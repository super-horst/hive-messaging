use failure::{Error, Fail};

#[derive(Debug, Fail)]
pub enum CommonError {
    #[fail(display = "Error message: {}", message)]
    Message { message: String },
    #[cfg(not(feature = "web"))]
    #[fail(display = "Unspecified error: {}", message)]
    TimeError {
        message: String,
        #[fail(cause)]
        cause: std::time::SystemTimeError,
    },
    #[cfg(feature = "web")]
    #[fail(display = "Unspecified error: {}", message)]
    TimeError {
        message: String,
        #[fail(cause)]
        cause: std::time::SystemTimeError,
    },
}
