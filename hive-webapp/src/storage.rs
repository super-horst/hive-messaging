use std::hash::{Hash, Hasher};
use std::sync::Arc;

use yew::format::Json;
use yew::services::storage::{Area, StorageService};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hive_commons::crypto;

const IDENTITY_KEY: &'static str = "hive.webapp.identity";
const CONTACTS_KEY: &'static str = "hive.webapp.contacts";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Identity {
    pub key: Arc<crypto::PrivateKey>,
    pub certificate: Option<crypto::Certificate>,
    pub pre_keys: Option<crypto::utils::PrivatePreKeys>
}

impl Identity {
    pub fn new(key: crypto::PrivateKey) -> Self {
        Identity {
            key: Arc::new(key),
            certificate: None,
            pre_keys: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Contact {
    pub id: Uuid,
    pub key: String,
    pub ratchet: Option<crypto::ManagedRatchet>,
}

impl Hash for Contact {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl std::cmp::PartialEq<Contact> for Contact {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for Contact {}

pub struct StorageController {
    service: StorageService,
}

impl StorageController {
    pub fn new() -> Self {
        //TODO error handling
        let service = StorageService::new(Area::Local).expect("storage was disabled by the user");

        StorageController { service }
    }

    pub fn get_identity(&self) -> Option<Identity> {
        //TODO error handling
        let Json(identity) = self.service.restore(IDENTITY_KEY);
        identity.ok()
    }

    pub fn set_identity(&mut self, identity: &Identity) {
        //TODO error handling
        self.service.store(IDENTITY_KEY, Json(&identity));
    }

    pub fn get_contacts(&self) -> Vec<Contact> {
        //TODO error handling
        let Json(contacts) = self.service.restore(CONTACTS_KEY);
        contacts.unwrap_or_else(|_| vec![])
    }

    pub fn set_contacts(&mut self, contacts: &Vec<Contact>) {
        //TODO error handling
        self.service.store(CONTACTS_KEY, Json(&contacts));
    }
}
