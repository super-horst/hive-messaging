use wasm_bindgen::prelude::*;
use yew::prelude::*;

use std::collections::HashMap;
use std::sync::Arc;

use yew::{html, Component, ComponentLink, Href, Html, InputData, KeyboardEvent, ShouldRender};

use wasm_bindgen_futures::futures_0_3::JsFuture;
use wasm_bindgen_futures::futures_0_3::spawn_local;
use wasm_bindgen::JsCast;

use log::*;

use hive_commons::crypto;
use hive_commons::model::*;
use crypto::FromBytes;

use crate::bindings::accounts_svc_bindings;
use crate::bindings::common_bindings;

use crate::storage::*;
use crate::contacts::*;

struct Message {}

pub struct State {
    contacts: Vec<Arc<Contact>>,
    messages: HashMap<Arc<Contact>, Vec<Message>>,
}

pub enum StateChange {
    UpdateCertificate(crypto::Certificate),
    SelectContact(Arc<Contact>),
    AddContact(String),
}

pub struct AppContainer {
    link: ComponentLink<Self>,
    selected_contact: Option<Arc<Contact>>,
    state: State,
    storage: StorageController,
    identity: Identity,
}


impl Component for AppContainer {
    type Message = StateChange;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        let state = State {
            contacts: vec![],
            messages: HashMap::new(),
        };

        let mut storage = StorageController::new();

        let id = match storage.get_identity() {
            Some(id) => id,
            None => {
                let key = crypto::PrivateKey::generate().unwrap();

                let created = Identity::new(key);
                storage.set_identity(&created);

                let certificate_link = link.clone();
                spawn_local(async move {
                    let client = accounts_svc_bindings::AccountsPromiseClient::new("http://localhost:8080".to_string());
                    let certificate = create_account(&client).await;
                    certificate_link.send_message(StateChange::UpdateCertificate(certificate));
                });

                created
            }
        };

        AppContainer {
            link,
            selected_contact: None,
            state,
            storage,
            identity: id,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        return match msg {
            StateChange::UpdateCertificate(c) => {
                self.identity.certificate = Some(c);
                self.storage.set_identity(&self.identity);
                true
            }
            StateChange::SelectContact(c) => {
                self.selected_contact = Some(c);
                true
            }
            StateChange::AddContact(key) => {
                self.state.contacts.push(Arc::new(Contact { key, ratchet: None }));
                true
            }
        };
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        // don't render
        false
    }

    fn view(&self) -> Html {
        let contacts = self.state.contacts.clone();
        html! {
        <div class="app_layout">
            <ContactList
                contacts=contacts
                on_select=self.link.callback(move |c| StateChange::SelectContact(c))
                on_add=self.link.callback(move |k| StateChange::AddContact(k)) />
            <div class="box msg_view_layout">
                <div class="msg_header">
                    <div class="center">
                        {match &self.selected_contact {
                            Some(c) => c.key.clone(),
                            None => "EMPTY".to_string(),
                         }}
                    </div>
                </div>

                <div class="msg_view">
                    {"Messages"}
                </div>

                <div class="msg_input_view">
                    <input class="center" placeholder="Compose a message" style="width: 100%;"/>
                    <button class="center">{"Send"}</button>
                </div>
            </div>
        </div>
        }
    }
}

impl AppContainer {
    fn add_contact(&mut self, key: String) -> Result<Contact, String> {
        let key_bytes = base64::decode(&key).map_err(|e| e.to_string())?;
        let pk = crypto::PublicKey::from_bytes(&key_bytes[..]).map_err(|e| e.to_string())?;

        Ok(Contact { key, ratchet: None })
    }
}

async fn create_account(client: &accounts_svc_bindings::AccountsPromiseClient) -> crypto::Certificate {
    info!("create_account entry");
    let key = crypto::PrivateKey::generate().unwrap();

    let challenge = crypto::signing::sign_challenge(&key).unwrap();
    let unsig_challenge = common::signed_challenge::Challenge::decode(challenge.challenge.clone()).unwrap();

    info!("Challenge timestamp {}", unsig_challenge.timestamp);

    let bound_challenge = common_bindings::SignedChallenge::new();
    bound_challenge.setChallenge(js_sys::Uint8Array::from(&challenge.challenge[..]));
    bound_challenge.setSignature(js_sys::Uint8Array::from(&challenge.signature[..]));

    let promise = client.createAccount(bound_challenge);
    let value = JsFuture::from(promise).await.unwrap();

    let certificate_binding: common_bindings::Certificate = value.dyn_into().expect("response not working...");

    let (certificate, ignore_for_now) = crypto::CertificateFactory::decode(certificate_binding.into()).unwrap();

    info!("Certificate serial {}", certificate.infos().serial());

    return certificate;
}
