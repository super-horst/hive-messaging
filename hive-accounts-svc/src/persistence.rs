use chrono::{DateTime, Utc};
use hive_crypto::{PrivateKey, PublicKey};

use crate::config::DbConfig;

pub use oxidizer::{DB, entity::IEntity};

pub mod entities {
    use oxidizer::*;
    use chrono::{DateTime, Utc};

    #[derive(Entity)]
    #[has_many(model = "Certificate", field = "account_id")]
    #[has_many(model = "PreKeyBundle", field = "account_id")]
    pub struct Account {
        #[primary_key]
        pub id: i32,

        #[indexed]
        pub public_key: String,

        pub timestamp: DateTime<Utc>,
    }

    #[derive(Entity)]
    pub struct Certificate {
        #[primary_key]
        pub id: i32,

        pub account_id: i32,

        pub certificate: String,

        pub signature: String,

        #[indexed]
        pub expires: DateTime<Utc>,
    }

    #[derive(Entity)]
    #[has_many(model = "OneTimeKey", field = "pre_key_id")]
    pub struct PreKeyBundle {
        #[primary_key]
        pub id: i32,

        pub account_id: i32,

        pub pre_key: String,

        pub pre_key_signature: String,

        #[indexed]
        pub expires: DateTime<Utc>,
    }

    #[derive(Entity)]
    pub struct OneTimeKey {
        #[primary_key]
        pub id: i32,

        pub pre_key_id: i32,

        pub key: String,
    }
}

impl entities::Account {
    pub fn for_public_key(key: &PublicKey) -> Self {
        entities::Account {
            id: i32::default(),
            public_key: key.id_string(),
            timestamp: Utc::now(),
        }
    }
}

impl Default for entities::Certificate {
    fn default() -> Self {
        entities::Certificate {
            id: i32::default(),
            account_id: i32::default(),
            certificate: String::default(),
            signature: String::default(),
            expires: Utc::now(),
        }
    }
}

pub async fn connect_db(cfg: &DbConfig) -> Result<DB, String> {
    let encoded_pwd = percent_encoding::utf8_percent_encode(&cfg.password, percent_encoding::CONTROLS);

    let db_string = format!("postgres://{user}:{password}@{host}:{port}/{db}",
                            user = cfg.user,
                            password = encoded_pwd,
                            host = cfg.host,
                            port = cfg.port,
                            db = cfg.dbname, );

    //TODO error handling
    let db = DB::connect(db_string.as_str(), 50, None).await.map_err(|_e| "DatabaseError".to_string())?;

    let account_migration = entities::Account::create_migration().map_err(|_e| "CannotCreateAccountMigrations".to_string())?;
    let certificate_migration = entities::Certificate::create_migration().map_err(|_e| "CannotCreateCertificateMigrations".to_string())?;
    let pre_key_migration = entities::PreKeyBundle::create_migration().map_err(|_e| "CannotCreatePreKeyBundleMigrations".to_string())?;
    db.migrate_tables(&[account_migration, certificate_migration, pre_key_migration]).await.map_err(|_e| "MigrationError".to_string())?;

    Ok(db)
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use super::entities::*;

    #[ignore]
    #[tokio::test]
    async fn test_entity() {
        let db_conf = DbConfig {
            host: "172.17.0.2".to_string(),
            port: 5432,
            dbname: "postgres".to_string(),
            user: "postgres".to_string(),
            password: "docker".to_string(),
            ssl_mode: true,
        };

        let db = connect_db(&db_conf).await.unwrap();
        let private = PrivateKey::generate().unwrap();

        let mut entity = Account::for_public_key(private.id());
        let creating = entity.save(&db).await.unwrap();
        assert_eq!(creating, true);
    }
}
