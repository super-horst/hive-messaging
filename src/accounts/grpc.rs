use crate::prelude::*;

use std::convert::{TryFrom, TryInto};
use std::ops::Add;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use prost::Message;
use uuid::Uuid;

use crate::crypto;
use crate::crypto::{CryptoError, PublicKey, CertificateInfoBundle};

use super::interfaces::*;

mod common {
    tonic::include_proto!("common");
}

mod accounts {
    tonic::include_proto!("accounts");
}

use common::*;
use accounts::*;
use accounts::accounts_server;

const CHALLENGE_GRACE_SECONDS: u64 = 11;
const DEFAULT_CLIENT_CERT_VALIDITY: Duration = Duration::from_secs(2 * 24 * 60 * 60);//2 days

pub struct GrpcCertificateEncoding;

impl crypto::CertificateEncoding for GrpcCertificateEncoding {
    type CertificateType = common::Certificate;

    fn serialise_tbs(infos: &crypto::CertificateInfoBundle) -> Result<Vec<u8>, CryptoError> {
        let expires = infos.expires().duration_since(UNIX_EPOCH)
                           .map(|d| d.as_secs())
                           .map_err(|e| CryptoError::Message { message: e.to_string() })?;

        let id = infos.public_key();

        let mut tbs_cert = certificate::TbsCertificate {
            identity: id.id_bytes(),
            namespace: id.namespace(),
            expires,
            uuid: infos.serial().to_string(),
            signer: None,
        };

        match infos.signer_certificate() {
            Some(c) => {
                let gc = common::Certificate {
                    certificate: c.encoded_certificate().to_vec(),
                    signature: c.signature().to_vec(),
                };
                tbs_cert.signer = Some(gc);
            }
            None => (),
        }

        let mut buf: Vec<u8> = Vec::with_capacity(tbs_cert.encoded_len());
        tbs_cert.encode(&mut buf).map_err(|e| CryptoError::Encoding {
            message: "Failed to encode TBS certificate".to_string(),
            cause: e,
        })?;

        Ok(buf)
    }

    fn serialise(data: &crypto::Certificate) -> Result<Vec<u8>, CryptoError> {
        let cert = common::Certificate {
            certificate: data.encoded_certificate().to_vec(),
            signature: data.signature().to_vec(),
        };

        let mut buf: Vec<u8> = Vec::with_capacity(cert.encoded_len());
        cert.encode(&mut buf).map_err(|e| CryptoError::Encoding {
            message: "Failed to encode certificate".to_string(),
            cause: e,
        })?;

        Ok(buf)
    }

    fn decode_partial(serialised: common::Certificate) -> Result<(crypto::Certificate, Option<common::Certificate>), CryptoError> {
        let buf = Bytes::from(serialised.certificate.to_vec());
        let tbs_cert = common::certificate::TbsCertificate::decode(buf).map_err(|e| CryptoError::Decoding {
            message: "failed to decode certificate".to_string(),
            cause: e,
        })?;

        let signed_identity = PublicKey::from_raw_bytes(&tbs_cert.identity[..])?;

        let expiration = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(tbs_cert.expires))
            .ok_or(CryptoError::Message {
                message: format!("is invalid system time '{}'", tbs_cert.expires)
            })?;

        let cert_info = crypto::CertificateInfoBundle {
            identity: signed_identity,
            expiration,
            serial: tbs_cert.uuid,
            signer_certificate: None,
        };

        let cert = crypto::Certificate {
            cert: serialised.certificate,
            signature: serialised.signature,
            infos: cert_info,
        };

        Ok((cert, tbs_cert.signer))
    }


    fn deserialise(bytes: Vec<u8>) -> Result<common::Certificate, CryptoError> {
        let buf = Bytes::from(bytes);
        let cert = common::Certificate::decode(buf).map_err(|e| CryptoError::Decoding {
            message: "failed to decode certificate".to_string(),
            cause: e,
        })?;

        Ok(cert)
    }
}

// #################### client ####################

pub struct GrpcAccountService {
    client: accounts_client::AccountsClient<tonic::transport::Channel>,
}

impl fmt::Debug for GrpcAccountService {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "GrpcAccountService")
    }
}

#[async_trait::async_trait]
impl AccountService for GrpcAccountService {
    async fn update_attestation(&mut self, id: &crypto::PrivateKey) -> Result<(), AccountsError> {
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
    ids: Arc<dyn crypto::Identities>,
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

        let their_cert = crypto::CertificateFactory::default()
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
    ) -> Result<tonic::Response<CheckResult>, tonic::Status> {
        //TODO
        Ok(tonic::Response::new(CheckResult {}))
    }

    async fn publish_pre_keys(
        &self,
        request: tonic::Request<PreKeyBundle>,
    ) -> Result<tonic::Response<PublishKeyResult>, tonic::Status> {
        //TODO
        Ok(tonic::Response::new(PublishKeyResult {}))
    }
}

#[cfg(test)]
mod account_grpc_tests {
    use super::*;
    use tokio;
    use crate::crypto;
    use crypto::PrivateKey;
    use crypto::Identities;
    use crate::accounts::interfaces::AccountsError;
    use crate::accounts::GrpcCertificateEncoding;
    use accounts_server::Accounts;
    use std::borrow::Borrow;

    pub fn build_server() -> (impl accounts_server::Accounts, Arc<dyn Identities>) {
        let server_id = crypto::PrivateKey::generate()
            .map_err(|e| AccountsError::Cryptography {
                message: "Unable to generate new key".to_string(),
                cause: e,
            }).unwrap();

        let server_public = server_id.id().copy();

        let cert = crypto::CertificateFactory::default()
            .certified(server_public)
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&server_id).unwrap();

        let ids = Arc::new(crypto::SimpleDalekIdentities::new(server_id, Arc::new(cert)));
        let inner_accs = InMemoryAccounts { ids: Arc::clone(&ids) as Arc<dyn crypto::Identities> };
        return (inner_accs, ids);
    }

    #[tokio::test]
    async fn test_refresh_attestation() -> Result<(), failure::Error> {
        let (accs, ids) = build_server();

        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();

        let client_id = crypto::PrivateKey::generate()?;
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

        let client_id = crypto::PrivateKey::generate().unwrap();
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