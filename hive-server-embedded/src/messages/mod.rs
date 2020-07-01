use dashmap::*;

mod interfaces;

pub use interfaces::*;

use hive_grpc::common;
use hive_grpc::messages;
use messages::messages_server;

// TODO gruesome implementation - only maybe use for tests
pub struct InMemoryMessageServer {
    messages: DashMap<common::Peer, Vec<messages::MessageEnvelope>>,
}

impl InMemoryMessageServer {
    pub fn new() -> InMemoryMessageServer {
        InMemoryMessageServer {
            messages: DashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl messages_server::Messages for InMemoryMessageServer {
    async fn get_messages(&self, request: tonic::Request<messages::MessageFilter>,
    ) -> Result<tonic::Response<messages::MessageEnvelope>, tonic::Status> {
        let message = request.into_inner();

        let dst = message.dst.as_ref().ok_or(tonic::Status::invalid_argument("no destination"))?;

        let mut msgs = self.messages.get_mut(dst)
                           .ok_or(tonic::Status::not_found("no message"))?;

        let message = msgs.value_mut().pop().ok_or(tonic::Status::not_found("no message"))?;

        Ok(tonic::Response::new(message))
    }

    async fn send_message(&self, request: tonic::Request<messages::MessageEnvelope>,
    ) -> Result<tonic::Response<messages::MessageSendResult>, tonic::Status> {
        let message = request.into_inner();

        let dst = message.dst.as_ref().ok_or(tonic::Status::invalid_argument("no destination"))?;

        let mut msgs = self.messages.get_mut(dst);
        if msgs.is_none() {
            self.messages.insert(dst.clone(), vec![]);

            msgs = self.messages.get_mut(dst);
        }

        msgs.unwrap().value_mut().push(message);

        Ok(tonic::Response::new(messages::MessageSendResult {}))
    }
}