use failure::Error;
use std::env;
use tonic::transport::Server;
use log::*;
pub use oxidizer::{DB, entity::IEntity};
use hive_grpc::GrpcCertificateEncoding;
use std::sync::Arc;
use env_logger;

mod config;
mod persistence;
mod service;
mod errors;

const DB_CONNECTION: &'static str = "postgres://postgres:docker@172.17.0.2:5432/postgres";

// SERVICE entry
#[tokio::main]
async fn main() -> Result<(), String> {
    let cfg = config::load_config_from_env().unwrap();

    env::set_var("RUST_LOG", &cfg.loglevel);
    env_logger::init();

    let addr = format!("0.0.0.0:{}", cfg.port).parse().unwrap();
    info!("Server listening on {}", addr);

    let my_key = hive_crypto::load_private_key("./privates").await;
    let cert = hive_crypto::load_certificate::<GrpcCertificateEncoding>(&my_key, "./certs").await;
    let my_certificate = Arc::new(cert);

    let db = persistence::connect_db(&cfg.db_config).await?;

    let inner = service::AccountService::new(
        my_key, my_certificate, db, );

    let service = service::AccountsServer::new(inner);

    Server::builder()
        .add_service(service)
        .serve(addr).await
        .map_err(|e| e.to_string())?;

    Ok(())
}
