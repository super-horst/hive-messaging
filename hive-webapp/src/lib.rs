#![recursion_limit = "512"]

mod contacts;
mod messages;

use crate::contacts::{ContactList, Contact};
use crate::messages::Message;

use serde::{Deserialize, Serialize};

use yew::{html, Component, ComponentLink, Href, Html, InputData, KeyPressEvent, ShouldRender};
use std::sync::Arc;
use std::collections::HashMap;
use hive_crypto::{PublicKey, FromBytes};

const STORAGE_KEY: &'static str = "hive.webapp.self";

pub struct State {
    contacts: Vec<Arc<Contact>>,
    messages: HashMap<Arc<Contact>, Vec<Message>>,
}

pub enum StateChange {
    SelectContact(Arc<Contact>),
    AddContact(String),
}

pub struct AppContainer {
    link: ComponentLink<Self>,
    selected_contact: Option<Arc<Contact>>,
    state: State,
}

impl Component for AppContainer {
    type Message = StateChange;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        let state = State {
            contacts: vec![],
            messages: HashMap::new(),
        };

        AppContainer {
            link,
            selected_contact: None,
            state,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        return match msg {
            StateChange::SelectContact(c) => {
                self.selected_contact = Some(c);
                true
            }
            StateChange::AddContact(key) => {
                self.state.contacts.push(Arc::new(Contact {
                    key,
                }));
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
        let pk = PublicKey::from_bytes(&key_bytes[..]).map_err(|e| e.to_string())?;




        Ok(Contact {
            key,
        })

    }
}