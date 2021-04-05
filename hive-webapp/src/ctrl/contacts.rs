use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::Arc;

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::futures_0_3::JsFuture;

use log::*;
use uuid::Uuid;

use async_lock::{Mutex, RwLock};

use serde::{Deserialize, Serialize};

use hive_commons::crypto::{encryption, PublicKey, SendStep};
use hive_commons::model;
use hive_commons::model::{Decodable, Encodable};

use hive_commons::protocol::{KeyAccess, ProtocolError, SendingStatus, Session, SessionManager};

use crate::bindings::*;
use crate::ctrl::{prompt, ControllerError, IdentityController, StorageController};
use crate::transport::ConnectionManager;

const KNOWN_CONTACTS_KEY: &'static str = "hive.core.contacts";
const CONTACT_KEY_PREFIX: &'static str = "hive.core.contact.";

#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct ContactProfileModel {
    pub(crate) id: Uuid,
    pub(crate) key: PublicKey,
    pub(crate) name: String,
}

impl std::cmp::PartialEq<ContactProfileModel> for ContactProfileModel {
    fn eq(&self, other: &Self) -> bool {
        return self.id == other.id;
    }
}

impl Eq for ContactProfileModel {}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ContactModel {
    session: Session,
}

impl Hash for ContactModel {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.session.hash(state);
    }
}

impl std::cmp::PartialEq<ContactModel> for ContactModel {
    fn eq(&self, other: &Self) -> bool {
        return self.session == other.session;
    }
}

impl Eq for ContactModel {}

#[derive(Clone)]
pub struct ContactManager {
    storage: StorageController,
    connections: ConnectionManager,
    identity: Arc<dyn KeyAccess>,
    known_contacts: Arc<RwLock<HashMap<String, ContactProfileModel>>>,
    cached_contacts: Arc<RwLock<HashMap<PublicKey, Arc<Contact>>>>,
}

impl ContactManager {
    pub fn new(
        storage: StorageController,
        connections: ConnectionManager,
        identity: IdentityController,
    ) -> Result<ContactManager, ControllerError> {
        let known_contacts =
            match storage.load::<HashMap<String, ContactProfileModel>>(KNOWN_CONTACTS_KEY) {
                Ok(contacts) => Ok(contacts),
                Err(ControllerError::NoDataFound { .. }) => Ok(Default::default()),
                Err(e) => Err(e),
            }?;

        let identity: Arc<dyn KeyAccess> = Arc::new(identity.clone());

        Ok(ContactManager {
            storage,
            connections,
            identity,
            known_contacts: Arc::new(RwLock::new(known_contacts)),
            cached_contacts: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn identity(&self) -> String {
        self.identity.public_key().id_string()
    }

    pub async fn store_contact(&self, contact: &Contact) -> Result<(), ControllerError> {
        let key = CONTACT_KEY_PREFIX.to_owned() + &contact.model.id.to_string();

        let guard = contact.session.lock().await;
        self.storage.store(
            &key,
            &ContactModel {
                session: guard.session().clone(),
            },
        )
    }

    async fn access_cached(&self, public_key: &PublicKey) -> Option<Arc<Contact>> {
        let guard = self.cached_contacts.read().await;
        let retrieved = guard.get(public_key);

        retrieved.map(|c| c.clone())
    }

    async fn store_cached(&self, contact: Contact) -> Arc<Contact> {
        let mut guard = self.cached_contacts.write().await;
        guard
            .entry(contact.peer_identity().clone())
            .or_insert_with(|| Arc::new(contact))
            .clone()
    }

    async fn access_stored(&self, public_key: &PublicKey) -> Result<Arc<Contact>, ControllerError> {
        let guard = self.known_contacts.read().await;

        return if let Some(profile) = guard.get(&public_key.id_string()) {
            let key = CONTACT_KEY_PREFIX.to_owned() + &profile.id.to_string();

            let contact_model = self.storage.load::<Option<ContactModel>>(&key)?;

            if let Some(model) = contact_model {
                let contact = Contact::initialise(
                    profile.clone(),
                    model.session,
                    self.connections.clone(),
                    self.identity.clone(),
                );

                Ok(self.store_cached(contact).await)
            } else {
                Err(ControllerError::InvalidState {
                    message: format!("Unable to load contact: '{}'", public_key.id_string()),
                })
            }
        } else {
            Err(ControllerError::InvalidState {
                message: format!("Unknown contact: '{}'", public_key.id_string()),
            })
        };
    }

    pub async fn access_known_contacts(&self) -> Vec<ContactProfileModel> {
        let guard = self.known_contacts.read().await;
        let profiles: Vec<ContactProfileModel> = guard
            .values()
            .into_iter()
            .map(|profile| profile.clone())
            .collect();

        return profiles;
    }

    pub async fn access_contact(
        &self,
        public_key: &PublicKey,
    ) -> Result<Arc<Contact>, ControllerError> {
        let cached = self.access_cached(public_key).await;
        if let Some(contact) = cached {
            return Ok(contact);
        }

        self.access_stored(public_key).await
    }

    pub async fn add_contact(
        &self,
        public_key: PublicKey,
    ) -> Result<Vec<ContactProfileModel>, ControllerError> {
        let name = prompt("Contact name:");

        let profile;
        {
            let mut guard = self.known_contacts.write().await;
            profile = guard
                .entry(public_key.id_string())
                .or_insert_with(|| ContactProfileModel {
                    id: Uuid::new_v4(),
                    key: public_key.clone(),
                    name,
                })
                .clone();

            if let Err(e) = self.storage.store(KNOWN_CONTACTS_KEY, &guard.deref()) {
                error!("{:?}", e);
            }
        }

        let contact = Contact::new(
            profile.clone(),
            self.connections.clone(),
            self.identity.clone(),
        );

        {
            let key = CONTACT_KEY_PREFIX.to_owned() + &profile.id.to_string();

            let guard = contact.session.lock().await;
            self.storage.store(
                &key,
                &ContactModel {
                    session: guard.session().clone(),
                },
            )?;
        }

        {
            let mut guard = self.cached_contacts.write().await;
            guard.insert(public_key, Arc::new(contact));
        }

        Ok(self.access_known_contacts().await)
    }
}

pub struct Contact {
    model: ContactProfileModel,
    connections: ConnectionManager,
    session: Mutex<SessionManager>,
}

impl Hash for Contact {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.model.id.hash(state);
    }
}

impl std::cmp::PartialEq<Contact> for Contact {
    fn eq(&self, other: &Self) -> bool {
        return self.model.id == other.model.id;
    }
}

impl Eq for Contact {}

impl Contact {
    pub fn new(
        model: ContactProfileModel,
        connections: ConnectionManager,
        keys: Arc<dyn KeyAccess>,
    ) -> Contact {
        let mgr = SessionManager::new(model.key.clone(), keys);

        Contact {
            model,
            connections,
            session: Mutex::new(mgr),
        }
    }

    pub fn initialise(
        model: ContactProfileModel,
        session: Session,
        connections: ConnectionManager,
        keys: Arc<dyn KeyAccess>,
    ) -> Contact {
        let mgr = SessionManager::manage_session(session, keys);

        Contact {
            model,
            connections,
            session: Mutex::new(mgr),
        }
    }

    pub fn profile(&self) -> &ContactProfileModel {
        &self.model
    }

    pub fn peer_identity(&self) -> &PublicKey {
        &self.model.key
    }

    pub async fn incoming_message(
        &self,
        session_params: model::messages::SessionParameters,
        encrypted_payload: &[u8],
    ) -> Result<model::messages::Payload, ProtocolError> {
        let mut session_guard = self.session.lock().await;
        let recv_step = session_guard.receive(&session_params)?;

        let decrypted = encryption::decrypt(&recv_step.secret[..], &encrypted_payload[..])
            .map_err(|cause| ProtocolError::FailedCryptography {
                message: "Message decryption failed".to_string(),
                cause,
            })?;

        model::messages::Payload::decode(decrypted)
            .map_err(|cause| ProtocolError::FailedSerialisation { cause })
    }

    pub async fn outgoing_message(
        &self,
        payload: &model::messages::Payload,
    ) -> Result<(model::messages::SessionParameters, Vec<u8>), ProtocolError> {
        let (key_exchange, send_step) = self.step_for_sending().await?;

        let payload = payload
            .encode()
            .map_err(|cause| ProtocolError::FailedSerialisation { cause })?;

        let encrypted =
            encryption::encrypt(&send_step.secret[..], &payload[..]).map_err(|cause| {
                ProtocolError::FailedCryptography {
                    message: "Message encryption failed".to_string(),
                    cause,
                }
            })?;

        let enc_params: model::messages::EncryptionParameters = send_step.into();

        let session_params = model::messages::SessionParameters {
            origin: None,
            params: Some(enc_params),
            key_exchange,
        };

        Ok((session_params, encrypted))
    }

    async fn step_for_sending(
        &self,
    ) -> Result<(Option<model::messages::KeyExchange>, SendStep), ProtocolError> {
        let mut session_guard = self.session.lock().await;
        loop {
            let send_status = session_guard.send()?;
            match send_status {
                SendingStatus::RequirePreKeys {} => {
                    let pre_keys = self.retrieve_pre_key_bundle().await.map_err(|e| {
                        ProtocolError::Message {
                            message: format!("Failed to retrieve pre keys: '{}'", e),
                        }
                    })?;
                    session_guard.received_pre_keys(pre_keys)?;
                }
                SendingStatus::Ok { key_exchange, step } => {
                    return Ok((key_exchange, step));
                }
            }
        }
    }

    async fn retrieve_pre_key_bundle(&self) -> Result<model::common::PreKeyBundle, String> {
        debug!("Retrieve pre keys for {}", self.model.key.id_string());

        let peer: common_bindings::Peer = self.model.key.into_peer().into();
        let promise = self.connections.accounts().getPreKeys(peer);
        let value = JsFuture::from(promise)
            .await
            .map_err(|error| format!("{:?}", error))?;

        let bound_bundle: common_bindings::PreKeyBundle =
            value.dyn_into().map_err(|error| format!("{:?}", error))?;

        Ok(bound_bundle.into())
    }
}
