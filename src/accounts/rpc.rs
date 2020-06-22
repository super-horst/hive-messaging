use crate::prelude::*;

use tonic;
use prost::Message;

use uuid::Uuid;
use bytes::BytesMut;
use std::sync::Arc;
use std::ops::Add;

use crate::crypto;
use super::grpc;
use grpc::accounts_server::Accounts as AccountsServerTrait;

const CHALLENGE_GRACE_SECONDS: u64 = 11;

// #################### server handler ####################

fn convert_id(id: &dyn crypto::PrivateIdentity) -> Result<grpc::ServerCertificate, Box<dyn std::error::Error>> {
    let uuid = Uuid::new_v4().to_string();
    let identity = id.public_id().as_bytes();

    let inner = grpc::server_certificate::Certificate { uuid, identity, namespace: "my::namespace".to_string() };

    let mut buf: Vec<u8> = Vec::with_capacity(inner.encoded_len());
    inner.encode(&mut buf)?;

    // TODO handle error
    let signature = id.sign(&buf).unwrap();

    Ok(grpc::ServerCertificate { certificate: buf, signature })
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
impl AccountsServerTrait for InMemoryAccounts {
    async fn update_attestation(
        &self,
        request: tonic::Request<grpc::SignedChallenge>,
    ) -> Result<tonic::Response<grpc::SenderCertificate>, tonic::Status> {
        let inner_req = request.into_inner();

        info!("Inside update_attestation");

        let raw_challenge = BytesMut::from(inner_req.challenge.as_ref() as &[u8]);
        let challenge = grpc::signed_challenge::Challenge::decode(raw_challenge)
            .map_err(|_| tonic::Status::invalid_argument("malformed challenge"))?;

        // check challenge timestamp
        let d = SystemTime::now().duration_since(UNIX_EPOCH)
                                 .map(|d| d.as_secs()).map_err(|e| tonic::Status::internal("internal error"))?;

        if d - CHALLENGE_GRACE_SECONDS >= challenge.timestamp ||
            d + CHALLENGE_GRACE_SECONDS <= challenge.timestamp {
            return Err(tonic::Status::deadline_exceeded("challenge expired"));
        }

        // identity is verified inside Identities
        //TODO log error
        let id = self.ids.resolve_id(&challenge.identity).await
                     .map_err(|op| tonic::Status::not_found("unable to find identity"))?;

        // check signature
        // TODO log error
        id.verify(&inner_req.challenge, &inner_req.signature)
          .map_err(|e| tonic::Status::unauthenticated("signature error"))?;

        // generate certificates
        let my_id = self.ids.my_id();

        // TODO log error
        let server_cert = convert_id(my_id)
            .map_err(|e| tonic::Status::internal("internal error"))?;

        let uuid = Uuid::new_v4().to_string();
        let identity = my_id.public_id().as_bytes();

        // TODO log error
        let expires = SystemTime::now().add(Duration::from_secs(30))
                                       .duration_since(UNIX_EPOCH).map(|d| d.as_secs())
                                       .map_err(|e| tonic::Status::internal("internal error"))?;

        let inner = grpc::sender_certificate::Certificate {
            uuid,
            namespace: "my::namespace".to_string(),
            expires,
            identity,
            signer: Some(server_cert),
        };

        // TODO log error
        let mut buf: Vec<u8> = Vec::with_capacity(inner.encoded_len());
        inner.encode(&mut buf).map_err(|e| tonic::Status::internal("internal error"))?;

        // TODO handle error
        let signature = my_id.sign(&buf).unwrap();

        Ok(tonic::Response::new(grpc::SenderCertificate { certificate: buf, signature }))
    }

    async fn check_attestation(
        &self,
        request: tonic::Request<grpc::SenderCertificate>,
    ) -> Result<tonic::Response<grpc::CheckResult>, tonic::Status> {
        //TODO
        Ok(tonic::Response::new(grpc::CheckResult {}))
    }

    async fn publish_pre_keys(
        &self,
        request: tonic::Request<grpc::PreKeyBundle>,
    ) -> Result<tonic::Response<grpc::PublishKeyResult>, tonic::Status> {
        //TODO
        Ok(tonic::Response::new(grpc::PublishKeyResult {}))
    }
}

#[cfg(test)]
mod account_svc_tests {
    use super::*;
    use tokio;
    use crate::crypto::*;
    use crate::accounts::interfaces::AccountError;

    #[tokio::test]
    async fn test_refresh_attestation() -> Result<(), failure::Error> {
        let server_id = Arc::new(crypto::DalekEd25519PrivateId::generate()
            .map_err(|e| AccountError::Cryptography {
                message: "Unable to generate new key".to_string(),
                cause: e,
            })?);

        let ids = Arc::new(crypto::SimpleDalekIdentities::new(Arc::clone(&server_id) as Arc<dyn PrivateIdentity>));
        let accs = InMemoryAccounts { ids: Arc::clone(&ids) as Arc<dyn crypto::Identities> };

        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();

        let client_id = crypto::DalekEd25519PrivateId::generate()?;
        let challenge = grpc::signed_challenge::Challenge { identity: client_id.public_id().as_bytes(), timestamp: now };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        challenge.encode(&mut buf).unwrap();

        // TODO handle error
        let signature = client_id.sign(&buf).unwrap();

        let signed = grpc::SignedChallenge { challenge: buf, signature };

        let response = accs.update_attestation(tonic::Request::new(signed)).await.unwrap();

        let cert_response = response.into_inner();

        let buf = BytesMut::from(cert_response.certificate.as_ref() as &[u8]);
        let inner_sender_cert = grpc::sender_certificate::Certificate::decode(buf).unwrap();

        let signer = match inner_sender_cert.signer {
            Some(s) => s,
            None => panic!("No signer"),
        };

        let buf = BytesMut::from(signer.certificate.as_ref() as &[u8]);
        let inner_server_cert = grpc::server_certificate::Certificate::decode(buf).unwrap();

        let server_public = ids.resolve_id(&inner_server_cert.identity).await.unwrap();

        server_public.verify(&cert_response.certificate, &cert_response.signature).unwrap();

        Ok(())
    }

    pub fn build_server() -> impl AccountsServerTrait {
        let server_id = Arc::new(crypto::DalekEd25519PrivateId::generate().unwrap());

        let ids = Arc::new(crypto::SimpleDalekIdentities::new(Arc::clone(&server_id) as Arc<dyn PrivateIdentity>));
        let inner_accs = InMemoryAccounts { ids: Arc::clone(&ids) as Arc<dyn crypto::Identities> };
        return inner_accs;
    }

    pub fn build_client_challenge() -> grpc::SignedChallenge {
        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();

        // TODO error handling
        let client_id = crypto::DalekEd25519PrivateId::generate().unwrap();
        let challenge = grpc::signed_challenge::Challenge { identity: client_id.public_id().as_bytes(), timestamp: now };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        challenge.encode(&mut buf).unwrap();

        let signature = client_id.sign(&buf).unwrap();

        return grpc::SignedChallenge { challenge: buf, signature };
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
