use yew::prelude::*;
use yew::{
    html, Component, ComponentLink, Html, InputData, KeyboardEvent, Properties, ShouldRender,
};

use log::*;

use wasm_bindgen::JsCast;
use wasm_bindgen::__rt::std::sync::Arc;
use wasm_bindgen_futures::futures_0_3::spawn_local;
use wasm_bindgen_futures::futures_0_3::JsFuture;

use hive_commons::crypto;
use hive_commons::crypto::FromBytes;
use hive_commons::model;

use crate::bindings::*;
use crate::identity::LocalIdentity;
use crate::storage::{ContactModel, StorageController};
use crate::transport::ConnectionManager;
use wasm_bindgen::__rt::std::borrow::Borrow;

pub enum ContactListMsg {
    Update(String),
    Add,
    Select(Arc<ContactModel>),
    ContactUpdate(Arc<ContactModel>),
    Nope,
}

#[derive(Clone, Properties)]
pub struct ListProps {
    pub on_select: Callback<Arc<ContactModel>>,
    pub identity: LocalIdentity,
    pub storage: StorageController,
    pub connections: ConnectionManager,
}

pub struct ContactList {
    link: ComponentLink<Self>,
    props: ListProps,
    value: String,
    stored_contacts: Vec<Arc<ContactModel>>,
}

impl Component for ContactList {
    type Message = ContactListMsg;
    type Properties = ListProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let stored_contacts = props
            .storage
            .get_contacts()
            .drain(..)
            .map(Arc::new)
            .collect();

        ContactList {
            link,
            props,
            value: "".to_string(),
            stored_contacts,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        return match msg {
            ContactListMsg::Update(val) => {
                self.value = val;
                true
            }
            ContactListMsg::Add => {
                let val = self.value.clone();
                if val.is_empty() {
                    return false;
                }

                let bytes = hex::decode(&val).unwrap();
                let public = crypto::PublicKey::from_bytes(&bytes[..]).unwrap();

                let contact = Arc::new(ContactModel {
                    id: uuid::Uuid::new_v4(),
                    key: public,
                    ratchet: None,
                });

                info!("Adding account {}", &contact.id);

                self.stored_contacts.push(contact);
                let contact_copy = self
                    .stored_contacts
                    .iter()
                    .map(Arc::as_ref)
                    .map(ContactModel::clone)
                    .collect();

                self.props.storage.set_contacts(&contact_copy);

                self.value = "".to_string();
                return true;
            }
            ContactListMsg::Select(key) => {
                self.props.on_select.emit(key);
                true
            }
            ContactListMsg::ContactUpdate(contact) =>{
                let position = self.stored_contacts
                    .iter()
                    .position(|s| s.as_ref().eq(contact.as_ref()));

                debug!("Update account {}", &contact.id);

                self.stored_contacts[position.unwrap()] = contact;

                let contact_copy = self
                    .stored_contacts
                    .iter()
                    .map(Arc::as_ref)
                    .map(ContactModel::clone)
                    .collect();

                self.props.storage.set_contacts(&contact_copy);

                true
            },
            _ => true,
        };
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        let id_string = self.props.identity.public_key().id_string();
        html! {
        <div class="box contacts">
            <div class="box contact_add_field">
                <input placeholder="Add new contact..." style="width: 100%;"
                    value=&self.value
                    oninput=self.link.callback(|e: InputData| ContactListMsg::Update(e.value))
                    onkeypress=self.link.callback(|e: KeyboardEvent| {
                       if e.key() == "Enter" { ContactListMsg::Add } else { ContactListMsg::Nope }
                   }) />
            </div>

            {for self.stored_contacts.iter().map(|c| {
                let stored = Arc::clone(c);
                html! {
                <Contact
                on_select = self.link.callback(move | c | ContactListMsg::Select(c))
                on_update = self.link.callback(move | c | ContactListMsg::ContactUpdate(c))
                identity = self.props.identity.clone()
                connections = self.props.connections.clone()
                stored = stored />
                }
            } )}
            <div style="width:100%;resize:none;overflow:always;">
                <input style="width: 100%;" value=&id_string/>
            </div>
        </div>
        }
    }
}

pub enum ContactMsg {
    IncomingPreKey(model::common::PreKeyBundle),
    // TODO
    Select,
    Nope,
}

#[derive(Clone, Properties)]
pub struct ContactProps {
    pub on_select: Callback<Arc<ContactModel>>,
    pub on_update: Callback<Arc<ContactModel>>,
    pub stored: Arc<ContactModel>,
    pub identity: LocalIdentity,
    pub connections: ConnectionManager,
}

#[derive(Clone)]
pub struct Contact {
    link: ComponentLink<Self>,
    props: ContactProps,
}

impl Component for Contact {
    type Message = ContactMsg;
    type Properties = ContactProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let contact = Contact {
            link: link.clone(),
            props,
        };

        if contact.props.stored.ratchet.is_none() {
            let other_key = contact.props.stored.key.clone();
            let cloned = contact.clone();

            spawn_local(async move {
                let bundle = cloned.retrieve_pre_key_bundle(&other_key).await;
                link.send_message(ContactMsg::IncomingPreKey(bundle));
            });
        }

        return contact;
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        return match msg {
            ContactMsg::Select => {
                self.props.on_select.emit(self.props.stored.clone());
                true
            }
            ContactMsg::IncomingPreKey(pre_key) => {
                // TODO error handling
                let ratchet = self.props.identity.prepare_ratchet(pre_key);

                let mut contact = self.props.stored.as_ref().clone();
                contact.ratchet = Some(ratchet);

                let arced = Arc::new(contact);
                self.props.on_update.emit(arced);

                true
            }
            _ => true,
        };
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
        <div class = "box contact" onclick = self.link.callback( move | _ | ContactMsg::Select) >
        { & self.props.stored.id }
        </div>
        }
    }
}

impl Contact {

    pub async fn send_message(&mut self, message: String) {
        // TODO implement crypto & transport here
    }

    async fn retrieve_pre_key_bundle(
        &self,
        other: &crypto::PublicKey,
    ) -> model::common::PreKeyBundle {
        // TODO error handling
        info!("retrieve pre keys");

        let peer = common_bindings::Peer::new();
        peer.setIdentity(js_sys::Uint8Array::from(&other.id_bytes()[..]));
        peer.setNamespace(other.namespace());

        let promise = self.props.connections.accounts().getPreKeys(peer);
        let value = JsFuture::from(promise).await.unwrap();

        let bound_bundle: common_bindings::PreKeyBundle =
            value.dyn_into().expect("response not working...");

        bound_bundle.into()
    }
}
