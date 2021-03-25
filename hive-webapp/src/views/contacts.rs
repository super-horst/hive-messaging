use std::sync::Arc;

use yew::prelude::*;
use yew::{
    html, Component, ComponentLink, Html, InputData, KeyboardEvent, Properties, ShouldRender,
};

use hive_commons::crypto::{FromBytes, PublicKey};

use crate::ctrl::{Contact, ContactManager, ContactProfileModel};

const CONTACTS_KEY: &'static str = "hive.core.contacts";

pub enum ContactListMsg {
    Update(String),
    Add,
    Select(ContactProfileModel),
    Nope,
}

#[derive(Clone, Properties)]
pub struct ListProps {
    pub on_error: Callback<String>,
    pub on_select: Callback<Arc<Contact>>,
    pub contacts: ContactManager,
}

pub struct ContactListView {
    link: ComponentLink<Self>,
    on_error: Callback<String>,
    on_select: Callback<Arc<Contact>>,
    value: String,
    contacts: ContactManager,
    known_contacts: Vec<ContactProfileModel>,
}

impl Component for ContactListView {
    type Message = ContactListMsg;
    type Properties = ListProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let known_contacts = props.contacts.access_known_contacts();

        ContactListView {
            link,
            on_error: props.on_error,
            on_select: props.on_select,
            value: "".to_string(),
            contacts: props.contacts,
            known_contacts,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        // TODO error handling?
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
                let public = PublicKey::from_bytes(&bytes[..]).unwrap();

                let name = format!("User {}", self.known_contacts.len() as u64);

                let contact_list_update = self.contacts.add_contact(public, name);

                self.known_contacts = contact_list_update;
                self.value = "".to_string();
                true
            }
            ContactListMsg::Select(profile) => {
                let result = self.contacts.access_contact(&profile.key);

                match result {
                    Ok(contact) => self.on_select.emit(contact),
                    Err(error) => {
                        self.on_error.emit(format!("{:?}", error));
                        panic!(error)
                    }
                }

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
        <div class="box contacts">
            <div class="box contact_add_field">
                <input placeholder="Add new contact..." style="width: 100%;"
                    value=&self.value
                    oninput=self.link.callback(|e: InputData| ContactListMsg::Update(e.value))
                    onkeypress=self.link.callback(|e: KeyboardEvent| {
                       if e.key() == "Enter" { ContactListMsg::Add } else { ContactListMsg::Nope }
                   }) />
            </div>

            {for self.known_contacts.iter().map(|c| {
                let stored = c.clone();
                html! {
                <ContactView
                on_select = self.link.callback(|c| ContactListMsg::Select(c))
                stored = stored />
                }
            } )}
        </div>
        }
    }
}

pub enum ContactMsg {
    Select,
    Nope,
}

#[derive(Clone, Properties)]
pub struct ContactProps {
    pub on_select: Callback<ContactProfileModel>,
    pub stored: ContactProfileModel,
}

#[derive(Clone)]
pub struct ContactView {
    link: ComponentLink<Self>,
    on_select: Callback<ContactProfileModel>,
    stored: ContactProfileModel,
}

impl Component for ContactView {
    type Message = ContactMsg;
    type Properties = ContactProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let contact =
            ContactView {
                link: link.clone(),
                on_select: props.on_select,
                stored: props.stored,
            };

        return contact;
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        return match msg {
            ContactMsg::Select => {
                self.on_select.emit(self.stored.clone());
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
        { & self.stored.name }
        </div>
        }
    }
}
