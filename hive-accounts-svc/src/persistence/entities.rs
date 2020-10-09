use chrono::{DateTime, Utc};
use oxidizer::*;

use crate::persistence::RepositoryError;

pub use oxidizer::{entity::IEntity, migration::Migration};

pub(crate) fn collect_migrations() -> Result<Vec<Migration>, RepositoryError> {
    let account_migration = Account::create_migration().map_err(|e| RepositoryError::Database {
        message: format!("{:?}", e),
    })?;
    let certificate_migration =
        Certificate::create_migration().map_err(|e| RepositoryError::Database {
            message: format!("{:?}", e),
        })?;
    let pre_key_migration =
        PreKeyBundle::create_migration().map_err(|e| RepositoryError::Database {
            message: format!("{:?}", e),
        })?;
    let one_time_key_migration =
        OneTimeKey::create_migration().map_err(|e| RepositoryError::Database {
            message: format!("{:?}", e),
        })?;

    Ok(vec![
        account_migration,
        certificate_migration,
        pre_key_migration,
        one_time_key_migration,
    ])
}

#[derive(Entity)]
#[has_many(model = "Certificate", field = "account_id")]
#[has_many(model = "PreKeyBundle", field = "account_id")]
pub(crate) struct Account {
    #[primary_key]
    pub id: i32,

    #[indexed]
    pub public_key: String,

    pub timestamp: DateTime<Utc>,
}

impl Account {
    pub fn for_public_key(key: String) -> Self {
        Account {
            id: i32::default(),
            public_key: key,
            timestamp: Utc::now(),
        }
    }
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

impl Default for Certificate {
    fn default() -> Self {
        Certificate {
            id: i32::default(),
            account_id: i32::default(),
            certificate: String::default(),
            signature: String::default(),
            expires: Utc::now(),
        }
    }
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

impl Default for PreKeyBundle {
    fn default() -> Self {
        PreKeyBundle {
            id: i32::default(),
            account_id: i32::default(),
            pre_key: String::default(),
            pre_key_signature: String::default(),
            expires: Utc::now(),
        }
    }
}

#[derive(Entity)]
pub struct OneTimeKey {
    #[primary_key]
    pub id: i32,

    pub pre_key_id: i32,

    pub key: String,
}

impl Default for OneTimeKey {
    fn default() -> Self {
        OneTimeKey {
            id: i32::default(),
            pre_key_id: i32::default(),
            key: String::default(),
        }
    }
}
