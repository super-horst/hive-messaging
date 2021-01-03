use std::hash::{Hash, Hasher};

use yew::format::Json;
use yew::services::storage::{Area, StorageService};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hive_commons::crypto;
use wasm_bindgen::__rt::std::sync::{Arc, RwLock};

const IDENTITY_KEY: &'static str = "hive.webapp.identity";
const CONTACTS_KEY: &'static str = "hive.webapp.contacts";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityModel {
    pub key: crypto::PrivateKey,
    pub certificate: Option<crypto::Certificate>,
    pub pre_keys: Option<crypto::utils::PrivatePreKeys>,
}

impl IdentityModel {
    pub fn new(key: crypto::PrivateKey) -> Self {
        IdentityModel {
            key,
            certificate: None,
            pre_keys: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactModel {
    pub id: Uuid,
    pub key: crypto::PublicKey,
    pub ratchet: Option<crypto::ManagedRatchet>,
}

impl Hash for ContactModel {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl std::cmp::PartialEq<ContactModel> for ContactModel {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for ContactModel {}

#[derive(Clone)]
pub struct StorageController {
    service: Arc<RwLock<StorageService>>,
}

impl StorageController {
    pub fn new() -> Self {
        //TODO error handling
        let service = StorageService::new(Area::Local).expect("storage was disabled by the user");

        StorageController {
            service: Arc::new(RwLock::new(service)),
        }
    }

    pub fn get_identity(&self) -> Option<IdentityModel> {
        //TODO error handling
        let storage = self.service.read().unwrap();
        let Json(identity) = storage.restore(IDENTITY_KEY);
        identity.ok()
    }

    pub fn set_identity(&self, identity: &IdentityModel) {
        //TODO error handling
        let mut storage = self.service.write().unwrap();
        storage.store(IDENTITY_KEY, Json(&identity));
    }

    pub fn get_contacts(&self) -> Vec<ContactModel> {
        //TODO error handling
        let storage = self.service.read().unwrap();
        let Json(contacts) = storage.restore(CONTACTS_KEY);
        contacts.unwrap_or_else(|_| vec![])
    }

    pub fn set_contacts(&self, contacts: &Vec<ContactModel>) {
        //TODO error handling
        let mut storage = self.service.write().unwrap();
        storage.store(CONTACTS_KEY, Json(&contacts));
    }
}
