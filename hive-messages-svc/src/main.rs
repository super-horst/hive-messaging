#[tokio::main]
async fn main() {
    hive_messages_svc::run_service().await;
}
