use crate::prelude::*;

use std::convert::TryFrom;
use std::ops::Add;
use std::sync::Arc;

use bytes::BytesMut;
use prost::Message;
use uuid::Uuid;

use crate::crypto;
use crate::crypto::CryptoError;

use super::interfaces::*;

const CHALLENGE_GRACE_SECONDS: u64 = 11;

tonic::include_proto!("accounts_svc");

/// conversion extension for tonic ServerCertificate
impl TryFrom<crypto::CertificateBundle<'_, crypto::ServerCertificate<'_>>> for ServerCertificate {
    type Error = CryptoError;

    fn try_from(value: crypto::CertificateBundle<'_, crypto::ServerCertificate<'_>>) -> Result<Self, Self::Error> {
        let id = value.certificate.identity;
        let signer = value.signer;

        let inner = server_certificate::Certificate {
            uuid: value.certificate.uuid,
            identity: id.as_bytes(),
            namespace: id.namespace(),
        };

        let mut buf: Vec<u8> = Vec::with_capacity(inner.encoded_len());
        inner.encode(&mut buf).map_err(|e| CryptoError::Encoding {
            message: "Failed to serialise inner server certificate".to_string(),
            cause: e,
        })?;

        let signature = signer.sign(&buf)?;

        Ok(ServerCertificate { certificate: buf, signature })
    }
}

/// conversion extension for tonic SenderCertificate
impl TryFrom<crypto::CertificateBundle<'_, crypto::ClientCertificate<'_>>> for SenderCertificate {
    type Error = CryptoError;

    fn try_from(value: crypto::CertificateBundle<'_, crypto::ClientCertificate<'_>>) -> Result<Self, Self::Error> {
        let id = value.certificate.identity;
        let signer = value.signer;

        // TODO dont use server certificate for sender certificate
        let inner = server_certificate::Certificate {
            uuid: value.certificate.uuid,
            identity: id.as_bytes(),
            namespace: id.namespace(),
        };

        let mut buf: Vec<u8> = Vec::with_capacity(inner.encoded_len());
        inner.encode(&mut buf).map_err(|e| CryptoError::Encoding {
            message: "Failed to serialise inner sender certificate".to_string(),
            cause: e,
        })?;

        let signature = signer.sign(&buf)?;

        Ok(SenderCertificate { certificate: buf, signature })
    }
}

impl TryFrom<&crypto::Certificate<'_>> for Certificate {
    type Error = CryptoError;

    fn try_from(value: &crypto::Certificate<'_>) -> Result<Self, Self::Error> {
        Ok(Certificate {
            certificate: value.encoded_certificate().to_vec(),
            signature: value.signature().to_vec(),
        })
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
    async fn update_attestation(&mut self, id: &dyn crypto::PrivateIdentity) -> Result<(), AccountError> {
        // preparing client request
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                   .map(|d| d.as_secs()).unwrap();

        let challenge = signed_challenge::Challenge { identity: id.public_id().as_bytes(), timestamp: now };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        // TODO handle error
        challenge.encode(&mut buf).unwrap();

        // TODO handle error
        let signature = id.sign(&buf).unwrap();

        let signed = SignedChallenge { challenge: buf, signature };

        let mut request = tonic::Request::new(signed);

        // include tracer if there is one
        /*ctx.put_tracer(|x| {
            info!("Requesting {}", x);

            // there should never be an error here!
            let value = MetadataValue::<Ascii>::from_str(x.as_str())?;
            request.metadata_mut().append(METADATA_TRACE_KEY, value);
            Ok(())
        })?;*/

        // TODO handle error
        let _result = self.client.update_attestation(request).await.unwrap();

        Ok(())
    }
}


/// TODO delete me
fn convert_id(id: &dyn crypto::PrivateIdentity) -> Result<ServerCertificate, Box<dyn std::error::Error>> {
    let uuid = Uuid::new_v4().to_string();
    let identity = id.public_id().as_bytes();

    let inner = server_certificate::Certificate { uuid, identity, namespace: "my::namespace".to_string() };

    let mut buf: Vec<u8> = Vec::with_capacity(inner.encoded_len());
    inner.encode(&mut buf)?;

    // TODO handle error
    let signature = id.sign(&buf).unwrap();

    Ok(ServerCertificate { certificate: buf, signature })
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
        let my_public = my_id.public_id();

        let server_cert: ServerCertificate = crypto::CertificateFactory::build_for(my_public, my_id)
            .server_certificate().map_err(|e| {
            error!("Error while building server certificate {}", e);
            tonic::Status::internal("internal error")
        })?;

        let uuid = Uuid::new_v4().to_string();
        let identity = my_public.as_bytes();


        // TODO ADAPT certificate factory for sender certs

        let expires = SystemTime::now().add(Duration::from_secs(30))
                                       .duration_since(UNIX_EPOCH).map(|d| d.as_secs())
                                       .map_err(|e| {
                                           error!("Error while handling system time {}", e);
                                           tonic::Status::internal("internal error")
                                       })?;

        let inner = sender_certificate::Certificate {
            uuid,
            namespace: "my::namespace".to_string(),
            expires,
            identity,
            signer: Some(server_cert),
        };

        let mut buf: Vec<u8> = Vec::with_capacity(inner.encoded_len());
        inner.encode(&mut buf).map_err(|e| {
            error!("Failed to encode certificate {}", e);
            tonic::Status::internal("internal error")
        })?;

        let signature = my_id.sign(&buf)
                             .map_err(|e| {
                                 error!("Failed to generate signature {}", e);
                                 tonic::Status::internal("internal error")
                             })?;

        Ok(tonic::Response::new(SenderCertificate {
            certificate: buf,
            signature,
        }))
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
