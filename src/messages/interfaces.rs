use crate::prelude::*;

use crate::crypto::PublicIdentity;

use failure::{Error, Fail};

#[derive(Debug, Fail)]
pub enum MessagesError {
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
    #[fail(display = "Cryptography failed: {}", message)]
    Cryptography {
        message: String,
        #[fail(cause)] cause: crate::crypto::CryptoError,
    },
}

//TODO
pub struct ReceiptFuture;

pub struct Message;

pub struct MessageState;

#[async_trait]
pub trait MessageService: Send + Sync {
    async fn send_message(&self, dst: &dyn PublicIdentity, msg: Message) -> Result<ReceiptFuture, MessagesError>;

    async fn recv_message(&self, state: &MessageState) -> Result<Message, MessagesError>;
}
