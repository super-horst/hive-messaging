use std::sync::Arc;
use std::time::Duration;

use log::*;
use simple_logger;

use tokio;
use tokio::prelude::*;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite};

mod messages;
mod accounts;

use hive_grpc::GrpcCertificateEncoding;
use hive_grpc::common;
use hive_grpc::accounts::accounts_server::AccountsServer;
use hive_grpc::messages::messages_server::MessagesServer;
use hive_crypto::*;
use tonic::transport::Server;

const KEY_FILE: &'static str = "target/server_key";
const CERT_FILE: &'static str = "target/server_cert";

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(Level::Debug).unwrap();

    let store = initialise_cryptostore().await;
    let arced_store = Arc::new(store) as Arc<dyn Identities>;

    let accs = accounts::InMemoryAccounts::new(arced_store);
    let msgs = messages::InMemoryMessageServer::new();

    let addr = "[::1]:50051".parse().unwrap();

    info!("Server listening on {}", addr);

    Server::builder()
        .add_service(AccountsServer::new(accs))
        .add_service(MessagesServer::new(msgs))
        .serve(addr)
        .await.unwrap();
}

async fn initialise_cryptostore() -> CryptoStore {
    let key = load_private_key().await;
    let cert = load_certificate(&key).await;

    CryptoStoreBuilder::new().my_key(key).my_certificate(cert).build().unwrap()
}

async fn load_private_key() -> PrivateKey {
    let f = fs::File::open(KEY_FILE).await;
    if f.is_ok() {
        let mut file = f.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        return PrivateKey::from_raw_bytes(&contents[..]).unwrap();
    } else {
        let server_id = PrivateKey::generate().unwrap();

        let mut f = fs::File::create(KEY_FILE).await.unwrap();
        f.write_all(server_id.secret_bytes()).await.unwrap();

        return server_id;
    }
}

async fn load_certificate(server_id: &PrivateKey) -> Certificate {
    let f = fs::File::open(CERT_FILE).await;
    if f.is_ok() {
        let mut file = f.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        let raw_cert = GrpcCertificateEncoding::deserialise(contents).unwrap();

        let (cert, _) = GrpcCertificateEncoding::decode_partial(raw_cert).unwrap();

        return cert;
    } else {
        let server_public = server_id.id().copy();

        let cert = CertificateFactory::default()
            .certified(server_public)
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(server_id).unwrap();

        let mut f = fs::File::create(CERT_FILE).await.unwrap();
        f.write_all(&GrpcCertificateEncoding::serialise(&cert).unwrap()[..]).await.unwrap();

        return cert;
    }
}


#[cfg(test)]
mod account_grpc_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tonic::{transport::Server, Request, Response, Status};
    use std::io::Write;
    use bytes::{Bytes, BytesMut};
    use prost::Message;

    fn prepare_identity(name: &str) {
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

        std::fs::create_dir("../target/server_tests");

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

        /// ############# finished account preparation

        let mut file = tokio::fs::File::open("../target/server_tests/alice_private_bundle").await.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        let private_pre_keys = common::PreKeyBundle::decode(Bytes::from(contents)).unwrap();

        let ik = PrivateKey::from_raw_bytes(&private_pre_keys.identity[..]).unwrap();
        let pre_key = PrivateKey::from_raw_bytes(&private_pre_keys.pre_key[..]).unwrap();

        let mut msg_client = hive_grpc::messages::messages_client::MessagesClient::connect("http://[::1]:50051").await.unwrap();

        let peer = hive_grpc::common::Peer {
            identity: alice_pre_keys.identity.to_vec(),
            namespace: alice_pre_keys.namespace.clone(),
        };

        let filter = hive_grpc::messages::MessageFilter {
            state: 0,
            dst: Some(peer),
        };

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

            let ik_b = PublicKey::from_raw_bytes(&other_peer.identity[..]).unwrap();
            let ek_b = PublicKey::from_raw_bytes(&key_ex.ephemeral_key[..]).unwrap();

            let ratchet_key = PublicKey::from_raw_bytes(&msg.ratchet_key[..]).unwrap();

            let sk = x3dh_agree_respond(&ik_b, &ik, &ek_b, &pre_key, None);

            println!("alice sk {:?}", &sk);

            ratchet = DoubleRatchet::initialise_received(&sk, &ik, &ratchet_key).unwrap();

            break;
        }

        println!("alice ratchet {:?}", ratchet.recv_step());
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

        let ik_a = PublicKey::from_raw_bytes(&bundle.identity[..]).unwrap();
        let pre_key = PublicKey::from_raw_bytes(&bundle.pre_key[..]).unwrap();

        let mut file = tokio::fs::File::open("../target/server_tests/bob_private_bundle").await.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        let private_pre_keys = common::PreKeyBundle::decode(Bytes::from(contents)).unwrap();
        let ik_b = PrivateKey::from_raw_bytes(&private_pre_keys.identity[..]).unwrap();

        let (eph_b, sk) = x3dh_agree_initial(&ik_b, &ik_a, &pre_key, None);

        println!("bob sk {:?}", &sk);

        let mut ratchet = DoubleRatchet::initialise_to_send(&sk, &ik_a).unwrap();

        println!("bob ratchet {:?}", ratchet.send_step());

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
    }
}