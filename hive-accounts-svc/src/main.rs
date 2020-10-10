#[tokio::main]
async fn main() {
    hive_accounts_svc::run_service().await;
}
