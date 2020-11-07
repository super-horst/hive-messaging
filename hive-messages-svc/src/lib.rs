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

    let db_repo = persistence::DatabaseRepository::connect(&cfg.db_config).await.unwrap();

    let inner = service::MessageService::new(Box::new(db_repo));

    let service = service::MessagesServer::new(inner);

    Server::builder().add_service(service).serve(addr).await.unwrap();
}
