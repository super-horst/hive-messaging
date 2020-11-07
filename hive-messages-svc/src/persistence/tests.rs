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
        let peer_migration = entities::Peer::create_migration().unwrap();
        let message_migration = entities::Message::create_migration().unwrap();

        let migrations = vec![peer_migration, message_migration];

        db.migrate_tables(&migrations[..]).await.unwrap();
    }

    async fn test_inserts(db: &DB) {
        let mut peer = entities::Peer::default();
        let saved = peer.save(db).await.unwrap();
        assert!(saved);

        let mut message = entities::Message::for_peer(&peer);
        let saved = message.save(db).await.unwrap();
        assert!(saved);
    }

    async fn test_selects(db: &DB) {
        //let accounts = entities::Account::find(db, "", &vec![]).await.unwrap();
        //TODO
    }
}
