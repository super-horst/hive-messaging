use std::sync::Arc;

use yew::format::Json;
use yew::prelude::*;
use yew::services::storage::{Area, StorageService};
use yew::{
    html, Component, ComponentLink, Href, Html, InputData, KeyboardEvent, Properties, ShouldRender,
};

use crate::storage::*;
use log::*;

pub enum ContactMsg {
    Update(String),
    Add,
    Select(Arc<Contact>),
    Nope,
}

#[derive(PartialEq, Clone, Properties)]
pub struct Props {
    pub on_select: Callback<Arc<Contact>>,
}

pub struct ContactList {
    link: ComponentLink<Self>,
    on_select: Callback<Arc<Contact>>,
    value: String,
    storage: StorageController,
    contacts: Vec<Arc<Contact>>,
}

impl Component for ContactList {
    type Message = ContactMsg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let storage = StorageController::new();
        let contacts = storage.get_contacts().drain(..).map(Arc::new).collect();

        ContactList {
            link,
            on_select: props.on_select,
            value: "".to_string(),
            storage,
            contacts,
        }
    }

    fn update(&mut self, msg: Self::Message) -> bool {
        return match msg {
            ContactMsg::Update(val) => {
                self.value = val;
                true
            }
            ContactMsg::Add => {
                let val = self.value.clone();
                if val.is_empty() {
                    return false;
                }

                info!("adding account {}", &val);
                let contact = Arc::new(Contact {
                    key: val,
                    ratchet: None,
                });

                self.contacts.push(contact);
                let contact_copy = self
                    .contacts
                    .iter()
                    .map(Arc::as_ref)
                    .map(Contact::clone)
                    .collect();

                self.storage.set_contacts(&contact_copy);

                self.value = "".to_string();
                return true;
            }
            ContactMsg::Select(key) => {
                self.on_select.emit(key);
                true
            }
            _ => true,
        };
    }

    fn change(&mut self, props: Self::Properties) -> bool {
        false
    }

    fn view(&self) -> Html {
        html! {
        <div class="box contacts">
            <div class="box contact_add_field">
                <input placeholder="Add new contact..." style="width: 100%;"
                    value=&self.value
                    oninput=self.link.callback(|e: InputData| ContactMsg::Update(e.value))
                    onkeypress=self.link.callback(|e: KeyboardEvent| {
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
