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


/*fn prepare_identity(name: &str) {
    let my_key = PrivateKey::generate().unwrap();

    let pre_private_key = PrivateKey::generate().unwrap();
    let pre_public_key = pre_private_key.id().copy();

    let signed_pre_key = my_key.sign(&pre_public_key.id_bytes()[..]).unwrap();

    let otp_1 = PrivateKey::generate().unwrap();
    let otp_2 = PrivateKey::generate().unwrap();
    let otp_3 = PrivateKey::generate().unwrap();
    let otp_4 = PrivateKey::generate().unwrap();
    let otp_5 = PrivateKey::generate().unwrap();

    let otp_privates = vec![otp_1.secret_bytes().to_vec(),
                            otp_2.secret_bytes().to_vec(),
                            otp_3.secret_bytes().to_vec(),
                            otp_4.secret_bytes().to_vec(),
                            otp_5.secret_bytes().to_vec()];

    let otp_publics = vec![otp_1.id().id_bytes(),
                           otp_2.id().id_bytes(),
                           otp_3.id().id_bytes(),
                           otp_4.id().id_bytes(),
                           otp_5.id().id_bytes()];

    let private_bundle = common::PreKeyBundle {
        identity: my_key.secret_bytes().to_vec(),
        namespace: "my_namespace".to_string(),
        pre_key: pre_private_key.secret_bytes().to_vec(),
        pre_key_signature: vec![],
        one_time_pre_keys: otp_privates,
    };

    let public_bundle = common::PreKeyBundle {
        identity: my_key.id().id_bytes(),
        namespace: "my_namespace".to_string(),
        pre_key: pre_public_key.id_bytes(),
        pre_key_signature: signed_pre_key,
        one_time_pre_keys: otp_publics,
    };

    let _r = std::fs::create_dir("../target/server_tests");

    let mut privates = std::fs::OpenOptions::new().create(true).write(true)
                                                  .open(format!("../target/server_tests/{}_private_bundle", name)).unwrap();

    let mut privates_bytes = BytesMut::with_capacity(private_bundle.encoded_len());
    private_bundle.encode(&mut privates_bytes).unwrap();

    privates.write_all(&privates_bytes[..]).unwrap();

    let mut publics = std::fs::OpenOptions::new().create(true).write(true)
                                                 .open(format!("../target/server_tests/{}_public_bundle", name)).unwrap();

    let mut public_bytes = BytesMut::with_capacity(public_bundle.encoded_len());
    public_bundle.encode(&mut public_bytes).unwrap();

    publics.write_all(&public_bytes[..]).unwrap();
}

#[test]
fn prepare_pre_key() {
    prepare_identity("bob");
}

#[tokio::test]
async fn alice_publish_and_read_messages() {
    let mut client = hive_grpc::accounts::accounts_client::AccountsClient::connect("http://[::1]:50051").await.unwrap();
    let mut file = tokio::fs::File::open("../target/server_tests/alice_public_bundle").await.unwrap();

    let mut contents = vec![];
    file.read_to_end(&mut contents).await.unwrap();

    let alice_pre_keys = common::PreKeyBundle::decode(Bytes::from(contents)).unwrap();

    client.update_pre_keys(tonic::Request::new(alice_pre_keys.clone())).await.unwrap();

    // ############# finished account preparation

    let mut file = tokio::fs::File::open("../target/server_tests/alice_private_bundle").await.unwrap();

    let mut contents = vec![];
    file.read_to_end(&mut contents).await.unwrap();

    let private_pre_keys = common::PreKeyBundle::decode(Bytes::from(contents)).unwrap();

    let ik = PrivateKey::from_bytes(&private_pre_keys.identity[..]).unwrap();
    let pre_key = PrivateKey::from_bytes(&private_pre_keys.pre_key[..]).unwrap();

    let mut msg_client = hive_grpc::messages::messages_client::MessagesClient::connect("http://[::1]:50051").await.unwrap();

    let peer = hive_grpc::common::Peer {
        identity: alice_pre_keys.identity.to_vec(),
        namespace: alice_pre_keys.namespace.clone(),
    };

    let filter = hive_grpc::messages::MessageFilter {
        state: 0,
        dst: Some(peer),
    };
    let ratchet_key: PublicKey;
    let mut ratchet;
    loop {
        let response = msg_client.get_messages(tonic::Request::new(filter.clone())).await;

        if response.is_err() {
            println!("no message yet");
            tokio::time::delay_for(Duration::from_secs(1)).await;
            continue;
        }

        let msg = response.unwrap().into_inner();

        let key_ex = msg.payload.unwrap().key_ex.unwrap();
        let other_peer = key_ex.origin.unwrap();

        let ik_b = PublicKey::from_bytes(&other_peer.identity[..]).unwrap();
        let ek_b = PublicKey::from_bytes(&key_ex.ephemeral_key[..]).unwrap();

        ratchet_key = PublicKey::from_bytes(&msg.ratchet_key[..]).unwrap();

        let sk = x3dh_agree_respond(&ik_b, &ik, &ek_b, &pre_key, None);

        println!("alice sk {:?}", &sk);

        ratchet = ManagedRatchet::initialise_received(&sk, &ik, &ratchet_key).unwrap();

        break;
    }

    let recv_step = ratchet.recv_step_for(&ratchet_key, );

    println!("alice ratchet {:?}", recv_step.secret);
}

#[tokio::test]
async fn bob_request_and_send_messages() {
    let mut client = hive_grpc::accounts::accounts_client::AccountsClient::connect("http://[::1]:50051").await.unwrap();
    let mut file = tokio::fs::File::open("../target/server_tests/alice_public_bundle").await.unwrap();

    let mut contents = vec![];
    file.read_to_end(&mut contents).await.unwrap();

    let alice_pre_keys = common::PreKeyBundle::decode(Bytes::from(contents)).unwrap();

    let peer = common::Peer {
        identity: alice_pre_keys.identity.clone(),
        namespace: alice_pre_keys.namespace.clone(),
    };

    let bundle = client.get_pre_keys(tonic::Request::new(peer.clone())).await.unwrap().into_inner();

    let ik_a = PublicKey::from_bytes(&bundle.identity[..]).unwrap();
    let pre_key = PublicKey::from_bytes(&bundle.pre_key[..]).unwrap();

    let mut file = tokio::fs::File::open("../target/server_tests/bob_private_bundle").await.unwrap();

    let mut contents = vec![];
    file.read_to_end(&mut contents).await.unwrap();

    let private_pre_keys = common::PreKeyBundle::decode(Bytes::from(contents)).unwrap();
    let ik_b = PrivateKey::from_bytes(&private_pre_keys.identity[..]).unwrap();

    let (eph_b, sk) = x3dh_agree_initial(&ik_b, &ik_a, &pre_key, None);

    println!("bob sk {:?}", &sk);

    let mut ratchet = ManagedRatchet::initialise_to_send(&sk, &ik_a).unwrap();

    let send_step = ratchet.send_step();

    println!("bob ratchet {:?}", send_step.secret);

    let origin = hive_grpc::common::Peer {
        identity: ik_b.id().id_bytes(),
        namespace: "my_namespace".to_string(),
    };

    let key_ex = hive_grpc::messages::KeyExchange {
        origin: Some(origin),
        ephemeral_key: eph_b.id_bytes(),
        one_time_key: vec![],
    };

    let payload = hive_grpc::messages::Payload {
        encrypted_content: vec![],
        key_ex: Some(key_ex),
    };

    let envelope = hive_grpc::messages::MessageEnvelope {
        payload: Some(payload),
        dst: Some(peer.clone()),
        ratchet_key: ratchet.current_public().id_bytes(),
        chain_idx: 0,
    };

    let mut msg_client = hive_grpc::messages::messages_client::MessagesClient::connect("http://[::1]:50051").await.unwrap();

    msg_client.send_message(tonic::Request::new(envelope)).await.unwrap();
}*/