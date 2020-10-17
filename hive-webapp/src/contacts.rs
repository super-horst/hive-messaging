use std::hash::{Hash, Hasher};

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use yew::format::Json;
use yew::prelude::*;
use yew::services::storage::{Area, StorageService};
use yew::{
    html, Component, ComponentLink, Href, Html, InputData, KeyPressEvent, Properties, ShouldRender,
};

use hive_commons::crypto::*;

const KEY: &'static str = "hive.webapp.contacts";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub key: String,
    //ratchet: ManagedRatchet,
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

pub enum ContactMsg {
    Update(String),
    Add,
    Select(Arc<Contact>),
    Nope,
}

#[derive(PartialEq, Clone, Properties)]
pub struct Props {
    pub contacts: Vec<Arc<Contact>>,
    pub on_select: Callback<Arc<Contact>>,
    pub on_add: Callback<String>,
}

pub struct ContactList {
    link: ComponentLink<Self>,
    on_add: Callback<String>,
    on_select: Callback<Arc<Contact>>,
    value: String,
    contacts: Vec<Arc<Contact>>,
}

impl Component for ContactList {
    type Message = ContactMsg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut contacts = vec![];

        let mut cto_store = vec![
            Arc::new(Contact {
                key: "firstC".to_string(),
            }),
            Arc::new(Contact {
                key: "2ndC".to_string(),
            }),
        ];
        contacts.append(&mut cto_store);

        /*let mut storage = StorageService::new(Area::Local).expect("storage was disabled by the user");
        storage.store(KEY, Json(&cto_store));

        let mut entries = {
            if let Json(Ok(restored_model)) = storage.restore(KEY) {
                restored_model
            } else {
                Vec::new()
            }
        };

        contacts.append(&mut entries);*/

        ContactList {
            link,
            on_add: props.on_add,
            on_select: props.on_select,
            value: "".to_string(),
            contacts: props.contacts,
        }
    }

    fn update(&mut self, msg: Self::Message) -> bool {
        match msg {
            ContactMsg::Update(val) => {
                self.value = val;
            }
            ContactMsg::Add => {
                self.on_add.emit(self.value.clone());
                self.value = "".to_string();
            }
            ContactMsg::Select(key) => {
                self.on_select.emit(key);
            }
            _ => {}
        }

        true
    }

    fn change(&mut self, props: Self::Properties) -> bool {
        self.contacts = props.contacts;

        true
    }

    fn view(&self) -> Html {
        html! {
        <div class="box contacts">
            <div class="box contact_add_field">
                <input placeholder="Add new contact..." style="width: 100%;"
                    value=&self.value
                    oninput=self.link.callback(|e: InputData| ContactMsg::Update(e.value))
                    onkeypress=self.link.callback(|e: KeyPressEvent| {
                       if e.key() == "Enter" { ContactMsg::Add } else { ContactMsg::Nope }
                   }) />
            </div>

            {for self.contacts.iter().map(|c| self.view_contact(c) )}
        </div>
        }
    }
}

impl ContactList {
    fn view_contact(&self, contact: &Arc<Contact>) -> Html {
        let c = Arc::clone(contact);
        html! {
        <div class = "box contact" onclick = self.link.callback( move | _ | ContactMsg::Select(Arc::clone( & c)))>
        { & contact.key }
        </div>
        }
    }
}
