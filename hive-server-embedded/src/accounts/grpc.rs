use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::fmt;

use std::convert::{TryFrom, TryInto};
use std::ops::Add;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use prost::Message;
use uuid::Uuid;

use log::*;

use hive_crypto::{CryptoError,
                  PublicKey,
                  PrivateKey,
                  Identities,
                  CertificateFactory,
                  CertificateInfoBundle,
                  CertificateEncoding};

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
}

impl fmt::Debug for InMemoryAccounts {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "InMemoryAccounts")
    }
}

#[async_trait::async_trait]
impl accounts_server::Accounts for InMemoryAccounts {
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
        let id = self.ids.resolve_id(&challenge.identity).await
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

    async fn check_attestation(
        &self,
        request: tonic::Request<common::Certificate>,
    ) -> Result<tonic::Response<accounts::CheckResult>, tonic::Status> {
        //TODO
        Ok(tonic::Response::new(accounts::CheckResult {}))
    }

    async fn publish_pre_keys(
        &self,
        request: tonic::Request<common::PreKeyBundle>,
    ) -> Result<tonic::Response<accounts::PublishKeyResult>, tonic::Status> {
        //TODO
        Ok(tonic::Response::new(accounts::PublishKeyResult {}))
    }
}

#[cfg(test)]
mod account_grpc_tests {
    use super::*;
    use tokio;
    use hive_crypto::PrivateKey;
    use hive_crypto::Identities;
    use hive_crypto::{CryptoStore, CryptoStoreBuilder};
    use accounts_server::Accounts;
    use std::borrow::Borrow;

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
        let inner_accs = InMemoryAccounts { ids: Arc::clone(&ids) };
        return (inner_accs, ids);
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