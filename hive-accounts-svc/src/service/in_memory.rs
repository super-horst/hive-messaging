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