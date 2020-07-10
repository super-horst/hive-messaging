use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

use yew::prelude::*;
use yew::{html, Component, Properties, ComponentLink, Href, Html, InputData, KeyPressEvent, ShouldRender};

use hive_crypto::*;

pub enum ContactMsg {
    Add(String),
    Select(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Contact {
    key: String,
    ratchet: ManagedRatchet,
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

impl Contact {
    fn view(&self) -> Html {
        html! {
            <div class="contact">
                { &self.key }
            </div>
        }
    }
}

pub struct ContactList {
    link: ComponentLink<Self>,
    contacts: Vec<Contact>,
}

impl Component for ContactList {
    type Message = ContactMsg;
    type Properties = ();

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut contacts = vec![];

        ContactList {
            link,
            contacts,
        }
    }

    fn update(&mut self, msg: Self::Message) -> bool {
        unimplemented!()
    }

    fn change(&mut self, _props: Self::Properties) -> bool {
        unimplemented!()
    }

    fn view(&self) -> Html {
        html! {
            <div class="box contacts">
                { for self.contacts.iter().map(Contact::view) }
            </div>
        }
    }
}