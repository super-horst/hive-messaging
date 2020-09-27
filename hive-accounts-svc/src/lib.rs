use std::fmt;

use failure::{Error, Fail};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
mod errors;
mod persistence;
mod grpc;
use prost::Message;

//#[cfg(test)]
mod config;
mod service;

pub use errors::*;
pub use grpc::*;
use hive_grpc::common::*;

use tonic;

use hive_crypto::PrivateKey;

pub struct Accounts<T> {
    wrapped: T,
}

#[async_trait::async_trait]
impl<T> AccountService for Accounts<T>
    where
        T: AccountService + fmt::Debug, {
    async fn update_attestation(&mut self, id: &PrivateKey) -> Result<(), AccountsError> {
        self.wrapped.update_attestation(id).await
    }
}

#[async_trait::async_trait]
pub trait AccountService: Send + Sync {
    /// Refresh the current attestation from the server
    async fn update_attestation(&mut self, id: &PrivateKey) -> Result<(), AccountsError>;
}

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
