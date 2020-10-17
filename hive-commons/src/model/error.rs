use failure::Fail;

#[derive(Debug, Fail)]
pub enum SerialisationError {
    #[fail(display = "Serialisation failed: {}", message)]
    Message { message: String },
    #[fail(display = "Decoding failed: {}", message)]
    Decoding {
        message: String,
        #[fail(cause)]
        cause: prost::DecodeError,
    },
    #[fail(display = "Encoding failed: {}", message)]
    Encoding {
        message: String,
        #[fail(cause)]
        cause: prost::EncodeError,
    },
}
