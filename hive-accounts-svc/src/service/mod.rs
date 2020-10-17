use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::*;

use crypto::FromBytes;
use hive_commons::*;

pub use model::accounts::accounts_server::*;
use model::accounts::UpdateKeyResult;
use model::common;
use model::Decodable;

use crate::persistence::*;

#[cfg(test)]
mod tests;

const CHALLENGE_GRACE_SECONDS: u64 = 11;
const DEFAULT_CLIENT_CERT_VALIDITY: Duration = Duration::from_secs(2 * 24 * 60 * 60); //2 days

fn match_to_status(error: RepositoryError) -> tonic::Status {
    // TODO log

    match error {
        RepositoryError::AlreadyExists { message: _ } => {
            tonic::Status::already_exists("resource already exists")
        }
        RepositoryError::NotFound { message: _ } => tonic::Status::not_found("resource not found"),
        _ => tonic::Status::internal("internal error"),
    }
}

pub(crate) struct AccountService {
    my_key: crypto::PrivateKey,
    my_certificate: Arc<crypto::Certificate>,
    repository: Box<dyn AccountsRepository>,
}

impl AccountService {
    pub fn new(
        my_key: crypto::PrivateKey,
        my_certificate: Arc<crypto::Certificate>,
        repository: Box<dyn AccountsRepository>,
    ) -> Self {
        AccountService {
            my_key,
            my_certificate,
            repository,
        }
    }

    async fn create_update_certificate(
        &self,
        tbc: crypto::PublicKey,
        account: &entities::Account,
    ) -> Result<crypto::Certificate, tonic::Status> {
        // everything OK so far, let's generate certificates
        let their_cert = crypto::CertificateFactory::default()
            .expiration(DEFAULT_CLIENT_CERT_VALIDITY)
            .certified(tbc)
            .sign(&self.my_key, Some(&self.my_certificate))
            .map_err(|e| {
                debug!("Failed to sign certificate: {}", e);
                tonic::Status::unknown("attestation error")
            })?;

        self.repository
            .refresh_certificate(&account, &their_cert)
            .await
            .map_err(match_to_status)?;

        Ok(their_cert)
    }

    fn verify_challenge(
        signed_challenge: common::SignedChallenge,
    ) -> Result<crypto::PublicKey, tonic::Status> {
        let raw_challenge = (signed_challenge.challenge.as_ref() as &[u8]).to_vec();
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

        let id = crypto::PublicKey::from_bytes(&challenge.identity[..])
            .map_err(|e| tonic::Status::invalid_argument("malformed identity"))?;

        // check signature
        id.verify(&signed_challenge.challenge, &signed_challenge.signature)
            .map_err(|e| {
                debug!("Failed to verify challenge: {}", e);
                tonic::Status::permission_denied("signature error")
            })?;

        Ok(id)
    }
}

#[async_trait::async_trait]
impl Accounts for AccountService {
    async fn create_account(
        &self,
        request: tonic::Request<common::SignedChallenge>,
    ) -> Result<tonic::Response<common::Certificate>, tonic::Status> {
        let inner_req = request.into_inner();

        let id = Self::verify_challenge(inner_req)?;

        let account = self.repository.retrieve_account(&id).await;

        match account {
            Ok(_) => {
                debug!("Account exists: {}", id.id_string());
                Err(tonic::Status::already_exists("account exists"))?
            }
            Err(e) => match e {
                RepositoryError::NotFound { message: _ } => (),
                error => Err(match_to_status(error))?,
            },
        }

        let account = self
            .repository
            .create_account(&id)
            .await
            .map_err(match_to_status)?;

        // everything OK so far, let's generate certificates
        let their_cert = self.create_update_certificate(id, &account).await?;

        Ok(tonic::Response::new(common::Certificate {
            certificate: their_cert.encoded_certificate().to_vec(),
            signature: their_cert.signature().to_vec(),
        }))
    }

    async fn update_attestation(
        &self,
        request: tonic::Request<common::SignedChallenge>,
    ) -> Result<tonic::Response<common::Certificate>, tonic::Status> {
        let inner_req = request.into_inner();

        let id = Self::verify_challenge(inner_req)?;

        let account = self
            .repository
            .retrieve_account(&id)
            .await
            .map_err(match_to_status)?;

        // everything OK so far, let's generate certificates
        let their_cert = self.create_update_certificate(id, &account).await?;

        Ok(tonic::Response::new(common::Certificate {
            certificate: their_cert.encoded_certificate().to_vec(),
            signature: their_cert.signature().to_vec(),
        }))
    }

    async fn update_pre_keys(
        &self,
        request: tonic::Request<common::PreKeyBundle>,
    ) -> Result<tonic::Response<UpdateKeyResult>, tonic::Status> {
        let incoming_bundle = request.into_inner();

        let id = crypto::PublicKey::from_bytes(&incoming_bundle.identity[..])
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
            .map_err(match_to_status)?;

        self.repository
            .refresh_pre_key_bundle(&account, incoming_bundle)
            .await
            .map_err(match_to_status)?;

        Ok(tonic::Response::new(UpdateKeyResult {}))
    }

    async fn get_pre_keys(
        &self,
        request: tonic::Request<common::Peer>,
    ) -> Result<tonic::Response<common::PreKeyBundle>, tonic::Status> {
        let peer = request.into_inner();

        let id = crypto::PublicKey::from_bytes(&peer.identity[..])
            .map_err(|e| tonic::Status::invalid_argument("malformed identity"))?;

        let bundle = self
            .repository
            .retrieve_pre_key_bundle(&id)
            .await
            .map_err(match_to_status)?;

        Ok(tonic::Response::new(bundle))
    }
}
