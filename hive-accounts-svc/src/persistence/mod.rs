use chrono::{DateTime, Utc};
use oxidizer::{entity::IEntity, DB};

use hive_commons::crypto;
use hive_commons::model::common;

use crate::config::DbConfig;

pub mod entities;
mod errors;

pub use errors::*;

#[cfg(test)]
use mockall::automock;

#[cfg(test)]
mod tests;

#[cfg_attr(test, automock)]
#[async_trait::async_trait]
pub(crate) trait AccountsRepository: Send + Sync {
    async fn create_account(
        &self,
        peer: &crypto::PublicKey,
    ) -> Result<entities::Account, RepositoryError>;

    async fn retrieve_account(
        &self,
        peer: &crypto::PublicKey,
    ) -> Result<entities::Account, RepositoryError>;

    async fn refresh_pre_key_bundle(
        &self,
        account: &entities::Account,
        pre_key_update: common::PreKeyBundle,
    ) -> Result<(), RepositoryError>;

    async fn retrieve_pre_key_bundle(
        &self,
        peer: &crypto::PublicKey,
    ) -> Result<common::PreKeyBundle, RepositoryError>;

    async fn refresh_certificate(
        &self,
        account: &entities::Account,
        cert_update: &crypto::Certificate,
    ) -> Result<(), RepositoryError>;
}

pub struct DatabaseRepository {
    db: DB,
}

impl DatabaseRepository {
    pub async fn connect(cfg: &DbConfig) -> Result<Self, RepositoryError> {
        let db = connect_db(cfg).await?;

        Ok(DatabaseRepository { db })
    }
}

#[async_trait::async_trait]
impl AccountsRepository for DatabaseRepository {
    async fn create_account(
        &self,
        peer: &crypto::PublicKey,
    ) -> Result<entities::Account, RepositoryError> {
        let mut account = entities::Account::for_public_key(peer.id_string());

        match account.save(&self.db).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(RepositoryError::AlreadyExists {
                message: format!("Account already exists"),
            }),
            Err(error) => Err(RepositoryError::Database {
                message: format!("Account save failed {:?}", error),
            }),
        }?;

        Ok(account)
    }

    async fn retrieve_account(
        &self,
        peer: &crypto::PublicKey,
    ) -> Result<entities::Account, RepositoryError> {
        let account: Option<entities::Account> =
            entities::Account::first(&self.db, "public_key = $1", &[&peer.id_string()])
                .await
                .map_err(|e| RepositoryError::Database {
                    message: format!("DB request failed: {:?}", e),
                })?;

        account.ok_or(RepositoryError::NotFound {
            message: format!("Could not find account: {:?}", peer),
        })
    }

    async fn refresh_pre_key_bundle(
        &self,
        account: &entities::Account,
        pre_key_update: common::PreKeyBundle,
    ) -> Result<(), RepositoryError> {
        let bundles: Vec<entities::PreKeyBundle> =
            entities::PreKeyBundle::find(&self.db, "account_id = $1", &[&account.id])
                .await
                .map_err(|e| RepositoryError::Database {
                    message: format!("DB request failed: {:?}", e),
                })?;

        // insert update
        let mut bundle_update = entities::PreKeyBundle {
            id: i32::default(),
            account_id: account.id,
            pre_key: hex::encode(&pre_key_update.pre_key[..]),
            pre_key_signature: hex::encode(&pre_key_update.pre_key_signature[..]),
            expires: Utc::now(), // TODO
        };

        match bundle_update.save(&self.db).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(RepositoryError::AlreadyExists {
                message: format!("Prekey already exists failed"),
            }),
            Err(error) => Err(RepositoryError::Database {
                message: format!("Prekey save failed {:?}", error),
            }),
        }?;

        for mut bundle in bundles {
            // TODO replace by foreign keys & cascade
            self.db
                .execute(
                    "DELETE FROM one_time_key 
                    WHERE pre_key_id =  {};",
                    &[&bundle.id],
                )
                .await
                .map_err(|e| RepositoryError::Database {
                    message: format!("DB request failed: {:?}", e),
                })?;

            bundle
                .delete(&self.db)
                .await
                .map_err(|e| RepositoryError::Database {
                    message: format!("DB request failed: {:?}", e),
                })?;
        }

        Ok(())
    }

    async fn retrieve_pre_key_bundle(
        &self,
        peer: &crypto::PublicKey,
    ) -> Result<common::PreKeyBundle, RepositoryError> {
        let account = self.retrieve_account(peer).await?;

        let bundle_option: Option<entities::PreKeyBundle> =
            entities::PreKeyBundle::first(&self.db, "account_id = $1", &[&account.id])
                .await
                .map_err(|e| RepositoryError::Database {
                    message: format!("DB request failed: {:?}", e),
                })?;

        let bundle = bundle_option.ok_or(RepositoryError::NotFound {
            message: format!("Could not find pre key bundle: {:?}", peer),
        })?;

        let otk: Option<entities::OneTimeKey> =
            entities::OneTimeKey::first(&self.db, "pre_key_id = $1", &[&bundle.id])
                .await
                .map_err(|e| RepositoryError::Database {
                    message: format!("DB request failed: {:?}", e),
                })?;

        let bundled_otk = if let Some(mut key) = otk {
            let decoded =
                hex::decode(key.key.clone()).map_err(|e| RepositoryError::Conversion {
                    message: "Hex decoding failed".to_string(),
                    cause: e,
                })?;

            key.delete(&self.db)
               .await
               .map_err(|e| RepositoryError::Database {
                   message: format!("DB request failed: {:?}", e),
               })?;

            vec![decoded]
        } else {
            vec![]
        };

        let decoded_pre_key =
            hex::decode(bundle.pre_key).map_err(|e| RepositoryError::Conversion {
                message: "Hex decoding failed".to_string(),
                cause: e,
            })?;

        let decoded_pre_key_signature =
            hex::decode(bundle.pre_key_signature).map_err(|e| RepositoryError::Conversion {
                message: "Hex decoding failed".to_string(),
                cause: e,
            })?;

        let peer_dto = common::Peer {
            identity: peer.id_bytes().clone(),
            namespace: "namespace".to_string(),
        };

        Ok(common::PreKeyBundle {
            identity: Some(peer_dto),
            pre_key: decoded_pre_key,
            pre_key_signature: decoded_pre_key_signature,
            one_time_pre_keys: bundled_otk,
        })
    }

    async fn refresh_certificate(
        &self,
        account: &entities::Account,
        cert_update: &crypto::Certificate,
    ) -> Result<(), RepositoryError> {
        let mut cert_entity = entities::Certificate::default();
        cert_entity.account_id = account.id;
        cert_entity.expires = DateTime::<Utc>::from(cert_update.expires().clone());
        cert_entity.certificate = hex::encode(cert_update.encoded_certificate().to_vec());
        cert_entity.signature = hex::encode(cert_update.signature().to_vec());

        match cert_entity.save(&self.db).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(RepositoryError::AlreadyExists {
                message: format!("Certificate already exists"),
            }),
            Err(error) => Err(RepositoryError::Database {
                message: format!("Certificate save failed {:?}", error),
            }),
        }
    }
}

async fn connect_db(cfg: &DbConfig) -> Result<DB, RepositoryError> {
    let encoded_pwd =
        percent_encoding::utf8_percent_encode(&cfg.password, percent_encoding::CONTROLS);

    let db_string = format!(
        "postgres://{user}:{password}@{host}:{port}/{db}",
        user = cfg.user,
        password = encoded_pwd,
        host = cfg.host,
        port = cfg.port,
        db = cfg.dbname,
    );

    let db = DB::connect(db_string.as_str(), 50, None)
        .await
        .map_err(|e| RepositoryError::Database {
            message: format!("{:?}", e),
        })?;

    let migrations = entities::collect_migrations()?;

    db.migrate_tables(&migrations[..])
      .await
      .map_err(|e| RepositoryError::Database {
          message: format!("{:?}", e),
      })?;

    Ok(db)
}
