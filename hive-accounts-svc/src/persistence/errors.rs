use failure::Fail;

#[derive(Debug, Fail)]
pub enum RepositoryError {
    #[fail(display = "Conversion failed: {}", message)]
    Conversion {
        message: String,
        #[fail(cause)]
        cause: hex::FromHexError,
    },
    #[fail(display = "Persistence operation failed: {}", message)]
    Database { message: String },
    #[fail(display = "Resource not found: {}", message)]
    NotFound { message: String },
    #[fail(display = "Resource already exists failed: {}", message)]
    AlreadyExists { message: String },
}
