use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::*;

use crypto::FromBytes;
use hive_commons::*;

use hive_commons::model::messages::message_filter::State;
use model::common;
pub use model::messages::messages_server::*;
use model::{Decodable, Encodable};

use crate::persistence::*;
use hive_commons::model::messages::{MessageEnvelope, MessageFilter, MessageSendResult};
use tonic::{Request, Response, Status};

#[cfg(test)]
mod tests;

fn match_to_status(error: RepositoryError) -> tonic::Status {
    // TODO log

    match error {
        RepositoryError::AlreadyExists { message: _ } => {
            tonic::Status::already_exists("resource already exists")
        }
        RepositoryError::NotFound { message: _ } => tonic::Status::not_found("resource not found"),
        _ => tonic::Status::internal("internal error"),
    }
}

pub(crate) struct MessageService {
    repository: Box<dyn MessagesRepository>,
}

impl MessageService {
    pub fn new(repository: Box<dyn MessagesRepository>) -> Self {
        MessageService { repository }
    }
}

#[async_trait::async_trait]
impl Messages for MessageService {
    async fn get_messages(
        &self,
        request: Request<MessageFilter>,
    ) -> Result<Response<MessageEnvelope>, Status> {
        let filter = request.into_inner();

        let state = match filter.state {
            x if x == State::New as i32 => Ok("NEW".to_string()),
            _ => Err(tonic::Status::failed_precondition("unknown state")),
        }?;

        let dst_peer =
            filter.dst.ok_or_else(|| tonic::Status::failed_precondition("missing peer"))?;

        let mut messages = self
            .repository
            .retrieve_messages(dst_peer, state)
            .await
            .map_err(|e| tonic::Status::internal("internal error"))?;

        if let Some(message) = messages.pop() {
            let envelope = MessageEnvelope::decode(message)
                .map_err(|e| tonic::Status::internal("failed to decode message"))?;

            Ok(tonic::Response::new(envelope))
        } else {
            Err(tonic::Status::not_found("no message found"))
        }
    }

    async fn send_message(
        &self,
        request: Request<MessageEnvelope>,
    ) -> Result<Response<MessageSendResult>, Status> {
        let envelope = request.into_inner();
        let x: Vec<u8> = envelope.encode().map_err(|e| tonic::Status::internal("internal error"))?;

        let dst = envelope.dst.ok_or_else(|| tonic::Status::failed_precondition("no destination found"))?;

        self.repository.save_message(dst, x)
            .await.map_err(|e| tonic::Status::internal("failed to save message"))?;

        Ok(Response::new(MessageSendResult {}))
    }
}
