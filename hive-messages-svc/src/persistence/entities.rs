use chrono::{DateTime, Utc};
use oxidizer::*;

use crate::persistence::RepositoryError;

pub(crate) fn collect_migrations() -> Result<Vec<migration::Migration>, RepositoryError> {
    let peer_migration = Peer::create_migration()
        .map_err(|e| RepositoryError::Database { message: format!("{:?}", e) })?;
    let message_migration = Message::create_migration()
        .map_err(|e| RepositoryError::Database { message: format!("{:?}", e) })?;

    Ok(vec![peer_migration, message_migration])
}

#[derive(Entity, PartialEq, Debug, Clone)]
pub struct Message {
    #[primary_key]
    pub id: i32,

    #[indexed]
    pub dst_peer_id: i32,

    pub message: String,

    #[indexed]
    pub status: String,

    pub timestamp: DateTime<Utc>,
}

impl Message {
    pub fn for_peer(peer: &Peer) -> Self {
        Message {
            id: i32::default(),
            dst_peer_id: peer.id,
            message: String::default(),
            status: String::default(),
            timestamp: Utc::now(),
        }
    }
}

#[has_many(model = "Message", field = "peer_id")]
#[derive(Entity, PartialEq, Debug)]
pub struct Peer {
    #[primary_key]
    pub id: i32,

    #[indexed]
    pub identity: String,

    #[indexed]
    pub namespace: String,
}

impl Default for Peer {
    fn default() -> Self {
        Peer { id: i32::default(), identity: String::default(), namespace: String::default() }
    }
}
