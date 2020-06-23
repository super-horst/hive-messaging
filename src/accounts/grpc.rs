use crate::prelude::*;

use std::convert::{TryFrom, TryInto};
use std::ops::Add;
use std::sync::Arc;

use bytes::BytesMut;
use prost::Message;
use uuid::Uuid;

use crate::crypto;
use crate::crypto::CryptoError;

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
    fn encode_tbs(infos: &crypto::CertificateInfoBundle) -> Result<Vec<u8>, CryptoError> {
        let expires = infos.expires().duration_since(UNIX_EPOCH)
                           .map(|d| d.as_secs())
                           .map_err(|e| CryptoError::Message { message: e.to_string() })?;

        let id = infos.public_key();

        let mut tbs_cert = certificate::TbsCertificate {
            identity: id.as_bytes(),
            namespace: id.namespace(),
            expires,
            uuid: infos.serial().to_string(),
            signer: None,
        };

        match *infos.signer_certificate() {
            Some(c) => {
                let gc = Certificate {
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

    fn encode(data: &crypto::Certificate) -> Result<Vec<u8>, CryptoError> {
        let cert = Certificate {
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
    async fn update_attestation(&mut self, id: &dyn crypto::PrivateIdentity) -> Result<(), AccountsError> {
        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();
        let pulbic = id.public_id();
        let challenge = signed_challenge::Challenge {
            identity: pulbic.as_bytes(),
            namespace: pulbic.namespace(),
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
    ) -> Result<tonic::Response<Certificate>, tonic::Status> {
        let inner_req = request.into_inner();

        let raw_challenge = BytesMut::from(inner_req.challenge.as_ref() as &[u8]);
        let challenge = signed_challenge::Challenge::decode(raw_challenge)
            .map_err(|e| {
                debug!("Received malformed challenge {}", e);
                tonic::Status::invalid_argument("malformed challenge")
            })?;

        // check challenge timestamp
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

        Ok(tonic::Response::new(Certificate {
            certificate: their_cert.encoded_certificate().to_vec(),
            signature: their_cert.signature().to_vec(),
        }))
    }

    async fn check_attestation(
        &self,
        request: tonic::Request<Certificate>,
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
mod account_svc_tests {
    use super::*;
    use tokio;
    use crate::crypto;
    use crypto::PrivateIdentity;
    use crate::accounts::interfaces::AccountsError;
    use crate::accounts::GrpcCertificateEncoding;
    use accounts_server::Accounts;
    use std::borrow::Borrow;

    #[tokio::test]
    async fn test_refresh_attestation() -> Result<(), failure::Error> {
        let server_id = crypto::DalekEd25519PrivateId::generate()
            .map_err(|e| AccountsError::Cryptography {
                message: "Unable to generate new key".to_string(),
                cause: e,
            })?;

        let public_bytes = &server_id.public_id().as_bytes()[..];

        let server_public = crypto::DalekEd25519PublicId::from_raw_bytes(public_bytes).unwrap();

        let cert = crypto::CertificateFactory::default()
            .certified(Box::new(server_public))
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&server_id).unwrap();

        let ids = Arc::new(crypto::SimpleDalekIdentities::new(Box::new(server_id), cert));
        let accs = InMemoryAccounts { ids: Arc::clone(&ids) as Arc<dyn crypto::Identities> };

        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();

        let client_id = crypto::DalekEd25519PrivateId::generate()?;
        let challenge = signed_challenge::Challenge {
            identity: client_id.public_id().as_bytes(),
            namespace: client_id.public_id().namespace(),
            timestamp: now,
        };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        challenge.encode(&mut buf).unwrap();

        // TODO handle error
        let signature = client_id.sign(&buf).unwrap();

        let signed = SignedChallenge { challenge: buf, signature };

        let response = accs.update_attestation(tonic::Request::new(signed)).await.unwrap();

        let cert_response = response.into_inner();

        let buf = BytesMut::from(cert_response.certificate.as_ref() as &[u8]);
        let inner_sender_cert = Certificate::decode(buf).unwrap();

        Ok(())

        //TODO fix me
        /*
        let signer = match inner_sender_cert.signer {
            Some(s) => s,
            None => panic!("No signer"),
        };

        let buf = BytesMut::from(signer.certificate.as_ref() as &[u8]);
        let inner_server_cert = grpc::Certificate::decode(buf).unwrap();

        let server_public = ids.resolve_id(&inner_server_cert.identity).await.unwrap();

        server_public.verify(&cert_response.certificate, &cert_response.signature).unwrap();

        Ok(())*/
    }

    pub fn build_server() -> impl accounts_server::Accounts {
        let server_id = crypto::DalekEd25519PrivateId::generate()
            .map(Box::new)
            .map_err(|e| AccountsError::Cryptography {
                message: "Unable to generate new key".to_string(),
                cause: e,
            }).unwrap();

        let server_public = server_id.public_id().copy();

        let cert = crypto::CertificateFactory::default()
            .certified(server_public)
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(server_id.as_ref()).unwrap();

        let ids = Arc::new(crypto::SimpleDalekIdentities::new(server_id, cert));
        let inner_accs = InMemoryAccounts { ids: Arc::clone(&ids) as Arc<dyn crypto::Identities> };
        return inner_accs;
    }

    pub fn build_client_challenge() -> SignedChallenge {
        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();

        // TODO error handling
        let client_id = crypto::DalekEd25519PrivateId::generate().unwrap();
        let challenge = signed_challenge::Challenge {
            identity: client_id.public_id().as_bytes(),
            namespace: client_id.public_id().namespace(),
            timestamp: now,
        };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        challenge.encode(&mut buf).unwrap();

        let signature = client_id.sign(&buf).unwrap();

        return SignedChallenge { challenge: buf, signature };
    }
    /*
        #[tokio::test]
        async fn test_server_client() {
            //simple_logger::init_with_level(log::Level::Debug).unwrap();

            let addr = "[::1]:50051".parse().unwrap();

            debug!("GreeterServer listening on {}", addr);

            let server = Server::builder()
                .add_service(AccountsServer::new(build_server()))
                .serve(addr);

            tokio::spawn(async move { server.await.unwrap() });

            tokio::time::delay_for(Duration::from_millis(1000)).await;

            let client = AccountsClient::connect("http://[::1]:50051").await.unwrap();

            let mut account_svc = GrpcAccountService { client };

            let client_id = crypto::DalekEd25519PrivateId::generate().unwrap();
            //let ctx= &ExecutionContext::Tracer(Uuid::new_v4().to_string());
            account_svc.update_attestation(&client_id).await.unwrap();
        }*/
}