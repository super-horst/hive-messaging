use std::env;
use std::fmt;
use std::sync::Arc;

mod errors;
//mod grpc;

//#[cfg(test)]
pub mod config;
pub mod persistence;
mod service;

pub use errors::*;
//pub use grpc::*;

use tonic;

use hive_commons::crypto::PrivateKey;

use env_logger;
use log::*;
use tonic::transport::Server;

pub async fn run_service() {
    let cfg = config::load_config_from_env().unwrap();

    env::set_var("RUST_LOG", &cfg.loglevel);
    env_logger::init();

    let addr = format!("0.0.0.0:{}", cfg.port).parse().unwrap();
    info!("Server listening on {}", addr);

    let my_key = hive_commons::crypto::load_private_key(&cfg.key).await;
    let cert =
        hive_commons::crypto::load_certificate(&my_key, &cfg.certificate).await;
    let my_certificate = Arc::new(cert);

    let db_repo = persistence::DatabaseRepository::connect(&cfg.db_config)
        .await
        .unwrap();

    let inner = service::AccountService::new(my_key, my_certificate, Box::new(db_repo));

    let service = service::AccountsServer::new(inner);

    Server::builder()
        .add_service(service)
        .serve(addr)
        .await
        .unwrap();
}

pub struct Accounts<T> {
    wrapped: T,
}

#[async_trait::async_trait]
impl<T> AccountService for Accounts<T>
where
    T: AccountService + fmt::Debug,
{
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
/*
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap();
        let public = id.id();
        let challenge = signed_challenge::Challenge {
            identity: public.id_bytes(),
            namespace: public.namespace(),
            timestamp: now,
        };

        let mut buf: Vec<u8> = Vec::with_capacity(challenge.encoded_len());
        /*challenge
        .encode(&mut buf)
        .map_err(|e| AccountsError::Encoding {
            message: "unable to serialise challenge".to_string(),
            cause: e,
        })?;*/

        let signature = id.sign(&buf).map_err(|e| AccountsError::Cryptography {
            message: "failed to sign challenge".to_string(),
            cause: e,
        })?;

        let signed = SignedChallenge {
            challenge: buf,
            signature,
        };

        let request = tonic::Request::new(signed);

        let _result = self.client.update_attestation(request).await.map_err(|e| {
            AccountsError::Transport {
                message: "failed to update attestation".to_string(),
                cause: e,
            }
        })?;

        Ok(())
    }
}*/
