use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::fmt;

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use prost::Message;
use dashmap::DashMap;

use log::*;

use hive_crypto::{
    PublicKey,
    PrivateKey,
    Identities,
    CertificateFactory,
};

use super::interfaces::*;

use hive_grpc::*;
use hive_grpc::common::*;
use hive_grpc::accounts::accounts_client::AccountsClient;
use hive_grpc::accounts::accounts_server;

const CHALLENGE_GRACE_SECONDS: u64 = 11;
const DEFAULT_CLIENT_CERT_VALIDITY: Duration = Duration::from_secs(2 * 24 * 60 * 60);//2 days

// #################### client ####################

pub struct GrpcAccountService {
    client: AccountsClient<tonic::transport::Channel>,
}

impl fmt::Debug for GrpcAccountService {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "GrpcAccountService")
    }
}

#[async_trait::async_trait]
impl AccountService for GrpcAccountService {
    async fn update_attestation(&mut self, id: &PrivateKey) -> Result<(), AccountsError> {
        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();
        let public = id.id();
        let challenge = signed_challenge::Challenge {
            identity: public.id_bytes(),
            namespace: public.namespace(),
            timestamp: now,
        };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        challenge.encode(&mut buf).map_err(|e| AccountsError::Encoding {
            message: "unable to serialise challenge".to_string(),
            cause: e,
        })?;

        let signature = id.sign(&buf)
                          .map_err(|e| AccountsError::Cryptography {
                              message: "failed to sign challenge".to_string(),
                              cause: e,
                          })?;

        let signed = SignedChallenge { challenge: buf, signature };

        let request = tonic::Request::new(signed);

        let _result = self.client.update_attestation(request).await
                          .map_err(|e| AccountsError::Transport {
                              message: "failed to update attestation".to_string(),
                              cause: e,
                          })?;

        Ok(())
    }
}

pub struct InMemoryAccounts {
    ids: Arc<dyn Identities>,
    pre_keys: DashMap<PublicKey, common::PreKeyBundle>,
}

impl InMemoryAccounts {
    pub fn new(ids: Arc<dyn Identities>) -> InMemoryAccounts {
        InMemoryAccounts {
            ids,
            pre_keys: DashMap::new(),
        }
    }
}

impl fmt::Debug for InMemoryAccounts {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "InMemoryAccounts")
    }
}

#[async_trait::async_trait]
impl accounts_server::Accounts for InMemoryAccounts {

    async fn create_account(
        &self,
        request: tonic::Request<SignedChallenge>,
    ) -> Result<tonic::Response<Certificate>, tonic::Status> {
        Err(tonic::Status::unimplemented("none"))
    }


    async fn update_attestation(
        &self,
        request: tonic::Request<SignedChallenge>,
    ) -> Result<tonic::Response<common::Certificate>, tonic::Status> {
        let inner_req = request.into_inner();

        let raw_challenge = BytesMut::from(inner_req.challenge.as_ref() as &[u8]);
        let challenge = signed_challenge::Challenge::decode(raw_challenge)
            .map_err(|e| {
                debug!("Received malformed challenge {}", e);
                tonic::Status::invalid_argument("malformed challenge")
            })?;

        // check challenge timestamp
        // TODO handle error
        let d = SystemTime::now().duration_since(UNIX_EPOCH)
                                 .map(|d| d.as_secs()).map_err(|e| tonic::Status::internal("internal error"))?;

        if d - CHALLENGE_GRACE_SECONDS >= challenge.timestamp ||
            d + CHALLENGE_GRACE_SECONDS <= challenge.timestamp {
            return Err(tonic::Status::deadline_exceeded("challenge expired"));
        }

        // identity is verified inside Identities
        let id = self.ids.resolve_id(&challenge.identity)
                     .map_err(|e| {
                         debug!("Received unknown identity '{}': {}", hex::encode(challenge.identity), e);
                         tonic::Status::not_found("unable to verify identity")
                     })?;

        // check signature
        id.verify(&inner_req.challenge, &inner_req.signature)
          .map_err(|e| {
              debug!("Failed to verify challenge: {}", e);
              tonic::Status::unauthenticated("signature error")
          })?;

        // everything OK so far, let's generate certificates
        let my_id = self.ids.my_id();
        let my_cert = self.ids.my_certificate();

        let their_cert = CertificateFactory::default()
            .expiration(DEFAULT_CLIENT_CERT_VALIDITY)
            .certified(id).sign::<GrpcCertificateEncoding>(my_id, Some(my_cert))
            .map_err(|e| {
                debug!("Failed to sign certificate: {}", e);
                tonic::Status::unknown("attestation error")
            })?;

        Ok(tonic::Response::new(common::Certificate {
            certificate: their_cert.encoded_certificate().to_vec(),
            signature: their_cert.signature().to_vec(),
        }))
    }

    async fn update_pre_keys(
        &self,
        request: tonic::Request<common::PreKeyBundle>,
    ) -> Result<tonic::Response<accounts::UpdateKeyResult>, tonic::Status> {
        let pre_key_update = request.into_inner();

        //TODO error handling
        let public = self.ids.resolve_id(&pre_key_update.identity[..])
                         .map_err(|e| tonic::Status::not_found("invalid identity"))?;

        //TODO error handling
        public.verify(&pre_key_update.pre_key[..], &pre_key_update.pre_key_signature[..])
              .map_err(|e| tonic::Status::failed_precondition("signature error"))?;

        self.pre_keys.insert(public, pre_key_update);

        Ok(tonic::Response::new(accounts::UpdateKeyResult {}))
    }

    async fn get_pre_keys(
        &self,
        request: tonic::Request<common::Peer>,
    ) -> Result<tonic::Response<common::PreKeyBundle>, tonic::Status> {
        let peer = request.into_inner();

        //TODO error handling
        let public = self.ids.resolve_id(&peer.identity[..])
                         .map_err(|e| tonic::Status::not_found("invalid peer"))?;

        //TODO error handling
        let mut entry_ref = self.pre_keys.get_mut(&public)
                                .ok_or(tonic::Status::not_found("invalid peer"))?;

        let pre_key_ref = entry_ref.value_mut();

        let otp: &mut Vec<Vec<u8>> = &mut pre_key_ref.one_time_pre_keys;

        let otp_response: Vec<Vec<u8>>;

        if otp.len() > 1 {
            let key = otp.remove(0);
            otp_response = vec![key];
        } else {
            otp_response = vec![];
        }

        let pre_key_response = common::PreKeyBundle {
            identity: pre_key_ref.identity.clone(),
            namespace: pre_key_ref.namespace.clone(),
            pre_key: pre_key_ref.pre_key.clone(),
            pre_key_signature: pre_key_ref.pre_key_signature.clone(),
            one_time_pre_keys: otp_response,
        };

        Ok(tonic::Response::new(pre_key_response))
    }
}

#[cfg(test)]
mod account_grpc_tests {
    use super::*;
    use tokio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use hive_crypto::PrivateKey;
    use hive_crypto::Identities;
    use hive_crypto::{CryptoStore, CryptoStoreBuilder};
    use accounts_server::*;
    use std::borrow::Borrow;
    use tonic::{transport::Server, Request, Response, Status};
    use std::io::Write;

    pub fn build_server() -> (impl accounts_server::Accounts, Arc<dyn Identities>) {
        let server_id = PrivateKey::generate()
            .map_err(|e| AccountsError::Cryptography {
                message: "Unable to generate new key".to_string(),
                cause: e,
            }).unwrap();

        let server_public = server_id.id().copy();

        let cert = CertificateFactory::default()
            .certified(server_public)
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&server_id).unwrap();

        let b = CryptoStoreBuilder::new().my_key(server_id)
                                         .my_certificate(cert);

        let store = b.build().unwrap();

        let ids = Arc::new(store) as Arc<dyn Identities>;
        let inner_accs = InMemoryAccounts { ids: Arc::clone(&ids), pre_keys: DashMap::new() };
        return (inner_accs, ids);
    }

    #[tokio::test]
    async fn test_run_server() {
        let (accs, ids) = build_server();

        let addr = "[::1]:50051".parse().unwrap();

        println!("Server listening on {}", addr);

        Server::builder()
            .add_service(AccountsServer::new(accs))
            .serve(addr)
            .await.unwrap();
    }

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
        prepare_identity("alice");
    }

    #[tokio::test]
    async fn publish_alice_to_server() {
        let mut client = AccountsClient::connect("http://[::1]:50051").await.unwrap();
        let mut file = tokio::fs::File::open("../target/server_tests/alice_public_bundle").await.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        let pre_keys = common::PreKeyBundle::decode(Bytes::from(contents)).unwrap();

        client.update_pre_keys(tonic::Request::new(pre_keys)).await.unwrap();
    }

    #[tokio::test]
    async fn get_alice_from_server() {
        let mut client = AccountsClient::connect("http://[::1]:50051").await.unwrap();
        let mut file = tokio::fs::File::open("../target/server_tests/alice_public_bundle").await.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        let pre_keys = common::PreKeyBundle::decode(Bytes::from(contents)).unwrap();

        let peer = common::Peer {
            identity: pre_keys.identity.clone(),
            namespace: pre_keys.namespace.clone(),
        };

        let bundle = client.get_pre_keys(tonic::Request::new(peer.clone())).await.unwrap().into_inner();
        println!("{:?}", bundle);
    }

    #[tokio::test]
    async fn test_refresh_attestation() -> Result<(), failure::Error> {
        let (accs, ids) = build_server();

        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();

        let client_id = PrivateKey::generate()?;
        let challenge = signed_challenge::Challenge {
            identity: client_id.id().id_bytes(),
            namespace: client_id.id().namespace(),
            timestamp: now,
        };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        challenge.encode(&mut buf).unwrap();

        let signature = client_id.sign(&buf).unwrap();

        let signed = SignedChallenge { challenge: buf, signature };

        let response = accs.update_attestation(tonic::Request::new(signed)).await.unwrap();

        let cert_response = response.into_inner();

        let buf = BytesMut::from(cert_response.certificate.as_ref() as &[u8]);
        let inner_sender_cert = certificate::TbsCertificate::decode(buf).unwrap();

        //TODO analyse signer
        ids.my_id().id().verify(&cert_response.certificate, &cert_response.signature).unwrap();

        Ok(())
    }

    pub fn build_client_challenge() -> SignedChallenge {
        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();

        let client_id = PrivateKey::generate().unwrap();
        let challenge = signed_challenge::Challenge {
            identity: client_id.id().id_bytes(),
            namespace: client_id.id().namespace(),
            timestamp: now,
        };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        challenge.encode(&mut buf).unwrap();

        let signature = client_id.sign(&buf).unwrap();

        return SignedChallenge { challenge: buf, signature };
    }
}