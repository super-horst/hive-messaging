use std::sync::Arc;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::fmt;
use chrono::{DateTime, Utc};

use log::*;
use bytes::BytesMut;
use prost::Message;

use hive_crypto::{
    PublicKey,
    PrivateKey,
    Identities,
    CertificateFactory,
    Certificate,
    FromBytes,
};

use hive_grpc::GrpcCertificateEncoding;
use hive_grpc::common;
use hive_grpc::accounts::UpdateKeyResult;
pub use hive_grpc::accounts::accounts_server::*;

use crate::config;
use crate::persistence::*;

const CHALLENGE_GRACE_SECONDS: u64 = 11;
const DEFAULT_CLIENT_CERT_VALIDITY: Duration = Duration::from_secs(2 * 24 * 60 * 60);//2 days

pub struct AccountService {
    my_key: PrivateKey,
    my_certificate: Arc<Certificate>,
    db: DB,
}

impl AccountService {
    pub fn new(my_key: PrivateKey,
               my_certificate: Arc<Certificate>,
               db: DB) -> Self {
        AccountService {
            my_key,
            my_certificate,
            db,
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
        let challenge = common::signed_challenge::Challenge::decode(raw_challenge)
            .map_err(|e| {
                debug!("Received malformed challenge {}", e);
                tonic::Status::invalid_argument("malformed challenge")
            })?;

        // check challenge timestamp
        let d = SystemTime::now().duration_since(UNIX_EPOCH)
                                 .map(|d| d.as_secs())
                                 .map_err(|e| tonic::Status::internal("internal error"))?;

        if d - CHALLENGE_GRACE_SECONDS >= challenge.timestamp ||
            d + CHALLENGE_GRACE_SECONDS <= challenge.timestamp {
            return Err(tonic::Status::deadline_exceeded("challenge expired"));
        }

        let id = PublicKey::from_bytes(&challenge.identity[..])
            .map_err(|e| tonic::Status::invalid_argument("malformed identity"))?;

        let account: Option<entities::Account> = entities::Account::first(&self.db, "public_key = $1", &[&id.id_string()])
            .await.map_err(|e| tonic::Status::internal("internal error"))?;

        if account.is_some() {
            debug!("Account exists: {}", id.id_string());
            return Err(tonic::Status::already_exists("account exists"));
        }

        // check signature
        id.verify(&inner_req.challenge, &inner_req.signature)
          .map_err(|e| {
              debug!("Failed to verify challenge: {}", e);
              tonic::Status::unauthenticated("signature error")
          })?;

        let mut account_entity = entities::Account::for_public_key(&id);
        match account_entity.save(&self.db).await {
            Ok(true) => {
                info!("Account saved");
                Ok(())
            }
            Ok(false) => {
                error!("Failed to save account");
                Err(tonic::Status::internal("internal error"))
            }
            Err(error) => {
                //error!(error = format!("{:?}", error).as_str(), "Failed to save account");
                error!("Failed to save account");
                Err(tonic::Status::internal("internal error"))
            }
        }?;

        // everything OK so far, let's generate certificates
        let their_cert = CertificateFactory::default()
            .expiration(DEFAULT_CLIENT_CERT_VALIDITY)
            .certified(id)
            .sign::<GrpcCertificateEncoding>(&self.my_key, Some(&self.my_certificate))
            .map_err(|e| {
                debug!("Failed to sign certificate: {}", e);
                tonic::Status::unknown("attestation error")
            })?;

        let mut cert_entity = entities::Certificate::default();
        cert_entity.account_id = account_entity.id;
        cert_entity.expires = DateTime::<Utc>::from(their_cert.expires().clone());
        cert_entity.certificate = hex::encode(their_cert.encoded_certificate().to_vec());
        cert_entity.signature = hex::encode(their_cert.signature().to_vec());

        match cert_entity.save(&self.db).await {
            Ok(true) => {
                info!("Account saved");
                Ok(())
            }
            Ok(false) => {
                error!("Failed to save certificate");
                Err(tonic::Status::internal("internal error"))
            }
            Err(error) => {
                //error!(error = format!("{:?}", error).as_str(), "Failed to save account");
                error!("Failed to save certificate");
                Err(tonic::Status::internal("internal error"))
            }
        }?;

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
        Err(tonic::Status::unimplemented("none"))
    }

    async fn get_pre_keys(
        &self,
        request: tonic::Request<common::Peer>,
    ) -> Result<tonic::Response<common::PreKeyBundle>, tonic::Status> {
        Err(tonic::Status::unimplemented("none"))
    }
}

#[cfg(test)]
mod service_tests {
    use super::*;

    #[tokio::test]
    async fn testing() {
        use hive_grpc::accounts::accounts_client::*;

        let mut client = AccountsClient::connect("http://localhost:8080").await.unwrap();

        let challenge = build_client_challenge();

        let cert_response = client.create_account(tonic::Request::new(challenge)).await.unwrap();

        let cert = cert_response.into_inner();
    }

    pub fn build_client_challenge() -> common::SignedChallenge {
        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();

        let client_id = PrivateKey::generate().unwrap();
        let challenge = common::signed_challenge::Challenge {
            identity: client_id.id().id_bytes(),
            namespace: client_id.id().namespace(),
            timestamp: now,
        };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        challenge.encode(&mut buf).unwrap();

        let signature = client_id.sign(&buf).unwrap();

        return common::SignedChallenge { challenge: buf, signature };
    }
}
