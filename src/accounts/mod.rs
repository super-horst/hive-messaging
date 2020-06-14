use tonic;
use bytes::BytesMut;
use prost::Message;
use std::sync::Arc;
use super::crypto::*;
use std::error::Error;

use uuid::Uuid;

use std::ops::Add;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

const CHALLENGE_GRACE_SECONDS: u64 = 11;

/*
#[derive(Default)]
struct InternalErrorMapper;

impl FnOnce(Box<dyn std::error::Error>) -> Self::Output for InternalErrorMapper {
    type Output = tonic::Status;

    fn call_once(self, args: (Box<dyn std::error::Error>)) -> Self::Output {
        //TODO log error
        return tonic::Status::internal("internal error");
    }
}*/


use accounts_rpc_svc::accounts_server::Accounts as accounts_rpc_trait;
use accounts_rpc_svc::*;

pub mod accounts_rpc_svc {
    tonic::include_proto!("accounts_svc");
}

fn convert_id(id: &dyn PrivateIdentity) -> Result<ServerCertificate, Box<dyn std::error::Error>> {
    let uuid = Uuid::new_v4().to_string();
    let identity = id.as_bytes();

    let inner = server_certificate::Certificate { uuid, identity, namespace: "my::namespace".to_string() };

    let mut buf: Vec<u8> = Vec::with_capacity(inner.encoded_len());
    inner.encode(&mut buf)?;

    let signature = id.sign(&buf);

    Ok(ServerCertificate { certificate: buf, signature })
}

pub struct InMemoryAccounts {
    ids: Arc<dyn Identities>,
}

#[async_trait::async_trait]
impl accounts_rpc_trait for InMemoryAccounts {
    async fn refresh_attestation(
        &self,
        request: tonic::Request<SignedChallenge>,
    ) -> Result<tonic::Response<SenderCertificate>, tonic::Status> {
        let inner_req = request.into_inner();

        let raw_challenge = BytesMut::from(inner_req.challenge.as_ref() as &[u8]);
        let challenge = signed_challenge::Challenge::decode(raw_challenge)
            .map_err(|op| tonic::Status::invalid_argument("malformed challenge"))?;

        // check challenge timestamp
        let d = SystemTime::now().duration_since(UNIX_EPOCH)
                                 .map(|d| d.as_secs()).map_err(|e| tonic::Status::internal("internal error"))?;

        if d - CHALLENGE_GRACE_SECONDS >= challenge.timestamp ||
            d + CHALLENGE_GRACE_SECONDS <= challenge.timestamp {
            //TODO log error
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
        let identity = my_id.as_bytes();

        // TODO log error
        let expires = SystemTime::now().add(Duration::from_secs(30))
                                       .duration_since(UNIX_EPOCH).map(|d| d.as_secs())
                                       .map_err(|e| tonic::Status::internal("internal error"))?;

        let inner = sender_certificate::Certificate {
            uuid,
            namespace: "my::namespace".to_string(),
            expires,
            identity,
            signer: Some(server_cert),
        };

        // TODO log error
        let mut buf: Vec<u8> = Vec::with_capacity(inner.encoded_len());
        inner.encode(&mut buf).map_err(|e| tonic::Status::internal("internal error"))?;

        let signature = my_id.sign(&buf);

        Ok(tonic::Response::new(SenderCertificate { certificate: buf, signature }))
    }

    async fn check_attestation(
        &self,
        request: tonic::Request<SenderCertificate>,
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

    #[tokio::test]
    async fn test_refresh_attestation() -> Result<(), Box<dyn std::error::Error>> {
        let server_id = Arc::new(DalekEd25519PrivateId::generate());

        let ids = Arc::new(SimpleIdentities::new(Arc::clone(&server_id) as Arc<dyn PrivateIdentity>));
        let accs = InMemoryAccounts { ids: Arc::clone(&ids) as Arc<dyn Identities>};

        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();

        let client_id = DalekEd25519PrivateId::generate();
        let challenge = signed_challenge::Challenge { identity: client_id.as_bytes(), timestamp: now };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        challenge.encode(&mut buf).unwrap();

        let signature = client_id.sign(&buf);

        let signed = SignedChallenge { challenge: buf, signature };

        let response = accs.refresh_attestation(tonic::Request::new(signed)).await.unwrap();

        let cert_response = response.into_inner();

        let buf = BytesMut::from(cert_response.certificate.as_ref() as &[u8]);
        let inner_sender_cert = sender_certificate::Certificate::decode(buf).unwrap();

        let signer = match inner_sender_cert.signer {
            Some(s) => s,
            None => panic!("No signer"),
        };

        let buf = BytesMut::from(signer.certificate.as_ref() as &[u8]);
        let inner_server_cert = server_certificate::Certificate::decode(buf).unwrap();

        let server_public = ids.resolve_id(&inner_server_cert.identity).await.unwrap();

        server_public.verify(&cert_response.certificate, &cert_response.signature).unwrap();

        Ok(())
    }
}
