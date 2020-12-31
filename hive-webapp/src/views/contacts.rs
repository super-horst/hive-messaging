use std::sync::Arc;

use log::*;

use yew::format::Json;
use yew::prelude::*;
use yew::{
    html, ChildrenWithProps, Component, ComponentLink, Href, Html, InputData, KeyboardEvent,
    Properties, ShouldRender,
};

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::futures_0_3::spawn_local;
use wasm_bindgen_futures::futures_0_3::JsFuture;

use hive_commons::crypto;
use hive_commons::crypto::{FromBytes, ManagedRatchet};
use hive_commons::model;

use crate::bindings::*;
use crate::storage;
use crate::transport;
use crate::identity::LocalIdentity;

pub enum ContactListMsg {
    Update(String),
    Add,
    Select(Arc<storage::ContactModel>),
    ContactUpdate(Arc<storage::ContactModel>),
    Nope,
}

#[derive(Clone, Properties)]
pub struct ListProps {
    pub on_select: Callback<Arc<storage::ContactModel>>,
    pub identity: LocalIdentity,
}

pub struct ContactList {
    link: ComponentLink<Self>,
    props: ListProps,
    value: String,
    storage: storage::StorageController,
    stored_contacts: Vec<Arc<storage::ContactModel>>,
}

impl Component for ContactList {
    type Message = ContactListMsg;
    type Properties = ListProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let storage = storage::StorageController::new();
        let stored_contacts = storage.get_contacts().drain(..).map(Arc::new).collect();

        ContactList {
            link,
            props,
            value: "".to_string(),
            storage,
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

                info!("adding account {}", &val);

                let bytes = hex::decode(&val).unwrap();
                let public = crypto::PublicKey::from_bytes(&bytes[..]).unwrap();

                let contact = Arc::new(storage::ContactModel {
                    id: uuid::Uuid::new_v4(),
                    key: public,
                    ratchet: None,
                });

                self.stored_contacts.push(contact);
                let contact_copy = self
                    .stored_contacts
                    .iter()
                    .map(Arc::as_ref)
                    .map(storage::ContactModel::clone)
                    .collect();

                self.storage.set_contacts(&contact_copy);

                self.value = "".to_string();
                return true;
            }
            ContactListMsg::Select(key) => {
                self.props.on_select.emit(key);
                true
            }
            ContactListMsg::ContactUpdate(contact) => true,
            _ => true,
        };
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
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
                stored = stored />
                }
            } )}
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
    pub on_select: Callback<Arc<storage::ContactModel>>,
    pub on_update: Callback<Arc<storage::ContactModel>>,
    pub stored: Arc<storage::ContactModel>,
    pub identity: LocalIdentity,
}

pub struct Contact {
    link: ComponentLink<Self>,
    props: ContactProps,
}

impl Component for Contact {
    type Message = ContactMsg;
    type Properties = ContactProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        if props.stored.ratchet.is_none() {
            let contact_link = link.clone();
            let other_key = props.stored.key.clone();
            spawn_local(async move {
                let bundle = retrieve_pre_key_bundle(&other_key).await;
                contact_link.send_message(ContactMsg::IncomingPreKey(bundle));
            });
        }
        Contact { link, props }
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

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
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

async fn retrieve_pre_key_bundle(other: &crypto::PublicKey) -> model::common::PreKeyBundle {
    // TODO error handling
    info!("retrieve pre keys");

    let peer = common_bindings::Peer::new();
    peer.setIdentity(js_sys::Uint8Array::from(&other.id_bytes()[..]));
    peer.setNamespace(other.namespace());

    let client = accounts_svc_bindings::AccountsPromiseClient::new(transport::create_service_url());

    let promise = client.getPreKeys(peer);
    let value = JsFuture::from(promise).await.unwrap();

    let bound_bundle: common_bindings::PreKeyBundle =
        value.dyn_into().expect("response not working...");

    bound_bundle.into()
}
