use env_logger;
use hive_grpc::GrpcCertificateEncoding;
use log::*;
pub use oxidizer::{entity::IEntity, DB};
use std::env;
use std::sync::Arc;
use tonic::transport::Server;

mod config;
mod errors;
mod persistence;
mod service;

// SERVICE entry
#[tokio::main]
async fn main() -> Result<(), String> {
    let cfg = config::load_config_from_env().unwrap();

    env::set_var("RUST_LOG", &cfg.loglevel);
    env_logger::init();

    let addr = format!("0.0.0.0:{}", cfg.port).parse().unwrap();
    info!("Server listening on {}", addr);

    let my_key = hive_crypto::load_private_key(&cfg.key).await;
    let cert =
        hive_crypto::load_certificate::<GrpcCertificateEncoding>(&my_key, &cfg.certificate).await;
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

    Ok(())
}
