#[cfg(test)]
mod entity_tests {
    use crate::config::DbConfig;
    use crate::persistence::connect_db;
    use crate::persistence::entities;
    use hive_commons::crypto;

    use oxidizer::{db::DB, entity::IEntity, migration::Migration};

    use testcontainers::images::postgres::Postgres as PsqlImage;
    use testcontainers::{clients, Docker};

    #[tokio::test]
    async fn entity_test() {
        let docker = clients::Cli::default();
        let postgres_image = PsqlImage::default();
        let node = docker.run(postgres_image);

        let db_conf = DbConfig {
            host: "localhost".to_string(),
            port: node.get_host_port(5432).unwrap(),
            dbname: "postgres".to_string(),
            user: "postgres".to_string(),
            password: "postgres".to_string(),
            ssl_mode: true,
        };

        let db = connect_db(&db_conf).await.unwrap();

        test_migrations(&db).await;
        test_inserts(&db).await;
        test_selects(&db).await;
    }

    async fn test_migrations(db: &DB) {
        let account_migration = entities::Account::create_migration().unwrap();
        let certificate_migration = entities::Certificate::create_migration().unwrap();
        let pre_key_migration = entities::PreKeyBundle::create_migration().unwrap();
        let one_time_key_migration = entities::OneTimeKey::create_migration().unwrap();

        let migrations = vec![
            account_migration,
            certificate_migration,
            pre_key_migration,
            one_time_key_migration,
        ];

        db.migrate_tables(&migrations[..]).await.unwrap();
    }

    async fn test_inserts(db: &DB) {
        let key = crypto::PrivateKey::generate().unwrap();

        let mut account = entities::Account::for_public_key(key.public_key().id_string());
        let saved = account.save(db).await.unwrap();
        assert!(saved);

        let mut certificate = entities::Certificate::default();
        certificate.account_id = account.id;
        let saved = certificate.save(db).await.unwrap();
        assert!(saved);

        let mut bundle = entities::PreKeyBundle::default();
        bundle.account_id = account.id;
        let saved = bundle.save(db).await.unwrap();
        assert!(saved);

        let mut otk = entities::OneTimeKey::default();
        otk.pre_key_id = bundle.id;
        let saved = otk.save(db).await.unwrap();
        assert!(saved);
    }

    async fn test_selects(db: &DB) {
        //let accounts = entities::Account::find(db, "", &vec![]).await.unwrap();
        //TODO
    }
}
