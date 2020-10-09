use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use log::*;
use prost::Message;

use hive_crypto::{Certificate, CertificateFactory, FromBytes, PrivateKey, PublicKey};

pub use hive_grpc::accounts::accounts_server::*;
use hive_grpc::accounts::UpdateKeyResult;
use hive_grpc::common;
use hive_grpc::GrpcCertificateEncoding;

use crate::persistence::*;

const CHALLENGE_GRACE_SECONDS: u64 = 11;
const DEFAULT_CLIENT_CERT_VALIDITY: Duration = Duration::from_secs(2 * 24 * 60 * 60); //2 days

pub(crate) struct AccountService {
    my_key: PrivateKey,
    my_certificate: Arc<Certificate>,
    repository: Box<dyn AccountsRepository>,
}

impl AccountService {
    pub fn new(
        my_key: PrivateKey,
        my_certificate: Arc<Certificate>,
        repository: Box<dyn AccountsRepository>,
    ) -> Self {
        AccountService {
            my_key,
            my_certificate,
            repository,
        }
    }
}

#[async_trait::async_trait]
impl Accounts for AccountService {
    async fn create_account(
        &self,
        request: tonic::Request<common::SignedChallenge>,
    ) -> Result<tonic::Response<common::Certificate>, tonic::Status> {
        let inner_req = request.into_inner();

        let raw_challenge = BytesMut::from(inner_req.challenge.as_ref() as &[u8]);
        let challenge =
            common::signed_challenge::Challenge::decode(raw_challenge).map_err(|e| {
                debug!("Received malformed challenge {}", e);
                tonic::Status::invalid_argument("malformed challenge")
            })?;

        // check challenge timestamp
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| tonic::Status::internal("internal error"))?;

        if d - CHALLENGE_GRACE_SECONDS >= challenge.timestamp
            || d + CHALLENGE_GRACE_SECONDS <= challenge.timestamp
        {
            return Err(tonic::Status::deadline_exceeded("challenge expired"));
        }

        let id = PublicKey::from_bytes(&challenge.identity[..])
            .map_err(|e| tonic::Status::invalid_argument("malformed identity"))?;

        let account = self.repository.retrieve_account(&id).await;

        match account {
            Ok(_) => {
                debug!("Account exists: {}", id.id_string());
                return Err(tonic::Status::already_exists("account exists"));
            }
            Err(e) => {
                // TODO
            }
        }

        // check signature
        id.verify(&inner_req.challenge, &inner_req.signature)
            .map_err(|e| {
                debug!("Failed to verify challenge: {}", e);
                tonic::Status::unauthenticated("signature error")
            })?;

        let account_entity = self
            .repository
            .create_account(&id)
            .await
            .map_err(|e| tonic::Status::internal("internal error"))?;

        // everything OK so far, let's generate certificates
        let their_cert = CertificateFactory::default()
            .expiration(DEFAULT_CLIENT_CERT_VALIDITY)
            .certified(id)
            .sign::<GrpcCertificateEncoding>(&self.my_key, Some(&self.my_certificate))
            .map_err(|e| {
                debug!("Failed to sign certificate: {}", e);
                tonic::Status::unknown("attestation error")
            })?;

        self.repository
            .refresh_certificate(&account_entity, &their_cert)
            .await
            .map_err(|e| {
                debug!("Failed to sign certificate: {}", e);
                tonic::Status::internal("internal error")
            })?;

        Ok(tonic::Response::new(common::Certificate {
            certificate: their_cert.encoded_certificate().to_vec(),
            signature: their_cert.signature().to_vec(),
        }))
    }

    async fn update_attestation(
        &self,
        request: tonic::Request<common::SignedChallenge>,
    ) -> Result<tonic::Response<common::Certificate>, tonic::Status> {
        Err(tonic::Status::unimplemented("none"))
    }

    async fn update_pre_keys(
        &self,
        request: tonic::Request<common::PreKeyBundle>,
    ) -> Result<tonic::Response<UpdateKeyResult>, tonic::Status> {
        let incoming_bundle = request.into_inner();

        let id = PublicKey::from_bytes(&incoming_bundle.identity[..])
            .map_err(|e| tonic::Status::invalid_argument("malformed identity"))?;

        id.verify(
            &incoming_bundle.pre_key[..],
            &incoming_bundle.pre_key_signature[..],
        )
        .map_err(|e| tonic::Status::failed_precondition("invalid signature"))?;

        let account = self
            .repository
            .retrieve_account(&id)
            .await
            .map_err(|e| tonic::Status::not_found("account not found"))?;

        self.repository
            .refresh_pre_key_bundle(&account, incoming_bundle)
            .await
            .map_err(|e| tonic::Status::internal("internal error"))?;

        Ok(tonic::Response::new(UpdateKeyResult {}))
    }

    async fn get_pre_keys(
        &self,
        request: tonic::Request<common::Peer>,
    ) -> Result<tonic::Response<common::PreKeyBundle>, tonic::Status> {
        let peer = request.into_inner();

        let id = PublicKey::from_bytes(&peer.identity[..])
            .map_err(|e| tonic::Status::invalid_argument("malformed identity"))?;

        let bundle = self
            .repository
            .retrieve_pre_key_bundle(&id)
            .await
            .map_err(|e| tonic::Status::internal("internal error"))?;

        Ok(tonic::Response::new(bundle))
    }
}

#[cfg(test)]
mod service_tests {
    use super::*;
    use hive_grpc::accounts::accounts_client::*;

    //#[tokio::test]
    async fn workflow_test() {
        let client_id = PrivateKey::generate().unwrap();

        let mut client = AccountsClient::connect("http://0.0.0.0:8080")
            .await
            .unwrap();

        create_account(&mut client, &client_id).await;

        // upload pre keys

        // retrieve prekeys until no more one time key
    }

    async fn create_account(
        client: &mut AccountsClient<tonic::transport::Channel>,
        client_id: &PrivateKey,
    ) {
        let challenge = build_client_challenge(client_id);

        let cert_response = client
            .create_account(tonic::Request::new(challenge))
            .await
            .unwrap();

        let cert = cert_response.into_inner();
    }

    fn build_client_challenge(client_id: &PrivateKey) -> common::SignedChallenge {
        // preparing client request
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap();

        let challenge = common::signed_challenge::Challenge {
            identity: client_id.id().id_bytes(),
            namespace: client_id.id().namespace(),
            timestamp: now,
        };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        challenge.encode(&mut buf).unwrap();

        let signature = client_id.sign(&buf).unwrap();

        return common::SignedChallenge {
            challenge: buf,
            signature,
        };
    }
}
