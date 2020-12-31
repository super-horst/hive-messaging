use chrono::{DateTime, Utc};
use oxidizer::{entity::IEntity, DB};

use hive_commons::crypto;
use hive_commons::model::common;
use hive_commons::model::messages;
use hive_commons::model::Decodable;

use crate::config::DbConfig;

pub mod entities;
mod errors;

pub use errors::*;

use hive_commons::crypto::PublicKey;
use hive_commons::model::messages::MessageEnvelope;
#[cfg(test)]
use mockall::automock;

#[cfg(test)]
mod tests;

#[cfg_attr(test, automock)]
#[async_trait::async_trait]
pub(crate) trait MessagesRepository: Send + Sync {
    async fn save_message(
        &self,
        peer: common::Peer,
        envelope: Vec<u8>,
    ) -> Result<(), RepositoryError>;

    async fn retrieve_messages(
        &self,
        peer: common::Peer,
        status: String,
    ) -> Result<Vec<Vec<u8>>, RepositoryError>;
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
impl MessagesRepository for DatabaseRepository {
    async fn save_message(
        &self,
        peer: common::Peer,
        envelope: Vec<u8>,
    ) -> Result<(), RepositoryError> {
        let peer = self.get_or_save_peer(peer).await?;

        let mut message = entities::Message::for_peer(&peer);
        message.message = hex::encode(envelope);
        message.status = "NEW".to_string();

        match message.save(&self.db).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(RepositoryError::AlreadyExists {
                message: "Message already exists".to_string(),
            }),
            Err(error) => Err(RepositoryError::Database {
                message: format!("Message save failed {:?}", error),
            }),
        }?;

        Ok(())
    }

    async fn retrieve_messages(
        &self,
        peer: common::Peer,
        status: String,
    ) -> Result<Vec<Vec<u8>>, RepositoryError> {
        let peer = entities::Peer::from_common(peer);

        let peer = entities::Peer::first(
            &self.db,
            "identity = $1, namespace = $2",
            &[&peer.identity, &peer.namespace],
        )
        .await
        .map_err(|error| RepositoryError::Database {
            message: format!("Failed to retrieve peer {:?}", error),
        })?
        .ok_or_else(|| RepositoryError::NotFound {
            message: "Peer not found".to_string(),
        })?;

        let message_entities: Vec<entities::Message> = entities::Message::find(
            &self.db,
            "dst_peer_id = $1, status = $2",
            &[&peer.id, &status],
        )
        .await
        .map_err(|e| RepositoryError::Database {
            message: format!("DB request failed: {:?}", e),
        })?;

        let mut encoded_messages = Vec::with_capacity(message_entities.len());

        for entity in message_entities {
            let decoded = hex::decode(entity.message).map_err(|e| RepositoryError::Conversion {
                message: "Failed to decode message".to_string(),
                cause: e,
            })?;

            encoded_messages.push(decoded);
        }

        Ok(encoded_messages)
    }
}

impl DatabaseRepository {
    async fn get_or_save_peer(
        &self,
        peer: common::Peer,
    ) -> Result<entities::Peer, RepositoryError> {
        let mut peer = entities::Peer::from_common(peer);

        match entities::Peer::first(
            &self.db,
            "identity = $1, namespace = $2",
            &[&peer.identity, &peer.namespace],
        )
        .await
        {
            Ok(result) => {
                if result.is_some() {
                    peer = result.unwrap();
                } else {
                    match peer.save(&self.db).await {
                        Ok(true) => Ok(()),
                        Ok(false) => Err(RepositoryError::AlreadyExists {
                            message: format!("Peer already exists"),
                        }),
                        Err(error) => Err(RepositoryError::Database {
                            message: format!("Peer save failed {:?}", error),
                        }),
                    }?;
                }
            }
            Err(error) => Err(RepositoryError::Database {
                message: format!("Peer retrieval failed {:?}", error),
            })?,
        }

        Ok(peer)
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

impl entities::Peer {
    pub fn from_common(peer: common::Peer) -> Self {
        let mut entity = entities::Peer::default();
        entity.identity = hex::encode(&peer.identity);
        entity.namespace = peer.namespace;

        return entity;
    }
}
