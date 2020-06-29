use std::sync::Arc;
use std::time::Duration;

use log::*;
use simple_logger;

use tokio;
use tokio::prelude::*;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite};

mod messages;
mod accounts;

use hive_grpc::GrpcCertificateEncoding;
use hive_grpc::accounts::accounts_server::AccountsServer;
use hive_crypto::*;
use tonic::transport::Server;

const KEY_FILE: &'static str = "target/server_key";
const CERT_FILE: &'static str = "target/server_cert";

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(Level::Debug).unwrap();

    let store = initialise_cryptostore().await;
    let arced_store = Arc::new(store) as Arc<dyn Identities>;

    let accs = accounts::InMemoryAccounts::new(arced_store);

    let addr = "[::1]:50051".parse().unwrap();

    info!("Server listening on {}", addr);

    Server::builder()
        .add_service(AccountsServer::new(accs))
        .serve(addr)
        .await.unwrap();
}

async fn initialise_cryptostore() -> CryptoStore {
    let key = load_private_key().await;
    let cert = load_certificate(&key).await;

    CryptoStoreBuilder::new().my_key(key).my_certificate(cert).build().unwrap()
}

async fn load_private_key() -> PrivateKey {
    let f = fs::File::open(KEY_FILE).await;
    if f.is_ok() {
        let mut file = f.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        return PrivateKey::from_raw_bytes(&contents[..]).unwrap();
    } else {
        let server_id = PrivateKey::generate().unwrap();

        let mut f = fs::File::create(KEY_FILE).await.unwrap();
        f.write_all(server_id.secret_bytes()).await.unwrap();

        return server_id;
    }
}

async fn load_certificate(server_id: &PrivateKey) -> Certificate {
    let f = fs::File::open(CERT_FILE).await;
    if f.is_ok() {
        let mut file = f.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        let raw_cert = GrpcCertificateEncoding::deserialise(contents).unwrap();

        let (cert, _) = GrpcCertificateEncoding::decode_partial(raw_cert).unwrap();

        return cert;
    } else {
        let server_public = server_id.id().copy();

        let cert = CertificateFactory::default()
            .certified(server_public)
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(server_id).unwrap();

        let mut f = fs::File::create(CERT_FILE).await.unwrap();
        f.write_all(&GrpcCertificateEncoding::serialise(&cert).unwrap()[..]).await.unwrap();

        return cert;
    }
}
