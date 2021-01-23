use std::env;
use std::fmt;
use std::sync::Arc;

mod errors;

pub mod config;
pub mod persistence;
mod service;

pub use errors::*;

use tonic;

use hive_commons::crypto::{Certificate, PrivateKey};

use env_logger;
use log::*;
use serde::de::DeserializeOwned;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tonic::transport::Server;

pub async fn run_service() {
    let cfg = config::load_config_from_env().unwrap();

    env::set_var("RUST_LOG", &cfg.loglevel);
    env_logger::init();

    let addr = format!("0.0.0.0:{}", cfg.port).parse().unwrap();
    info!("Server listening on {}", addr);

    let my_key: PrivateKey = load_json(&cfg.key).await;
    let cert: Certificate = load_json(&cfg.certificate).await;
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

async fn load_json<T: DeserializeOwned>(path: &str) -> T {
    let mut buffer = Vec::new();

    let mut file = File::open(path).await.unwrap();
    file.read_to_end(&mut buffer).await.unwrap();

    serde_json::from_slice(&buffer).unwrap()
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
