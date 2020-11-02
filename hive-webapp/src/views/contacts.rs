use std::sync::Arc;

use yew::format::Json;
use yew::prelude::*;
use yew::{
    html, Component, ComponentLink, Href, Html, ChildrenWithProps, InputData, KeyboardEvent, Properties, ShouldRender,
};

use crate::storage;
use log::*;

pub enum ContactListMsg {
    Update(String),
    Add,
    Select(Arc<storage::Contact>),
    Nope,
}

#[derive(PartialEq, Clone, Properties)]
pub struct ListProps {
    pub on_select: Callback<Arc<storage::Contact>>,
}

pub struct ContactList {
    link: ComponentLink<Self>,
    props: ListProps,
    value: String,
    storage: storage::StorageController,
    stored_contacts: Vec<Arc<storage::Contact>>,
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
                let contact = Arc::new(storage::Contact {
                    id: uuid::Uuid::new_v4(),
                    key: val,
                    ratchet: None,
                });

                self.stored_contacts.push(contact);
                let contact_copy = self
                    .stored_contacts
                    .iter()
                    .map(Arc::as_ref)
                    .map(storage::Contact::clone)
                    .collect();

                self.storage.set_contacts(&contact_copy);

                self.value = "".to_string();
                return true;
            }
            ContactListMsg::Select(key) => {
                self.props.on_select.emit(key);
                true
            }
            _ => true,
        };
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        if self.props != props {
            self.props = props;
            true
        } else {
            false
        }
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

            {for self.stored_contacts.iter().map(|c| self.view_contact(c) )}
        </div>
        }
    }
}

impl ContactList {
    fn view_contact(&self, contact: &Arc<storage::Contact>) -> Html {
        let stored = Arc::clone(contact);
        html! {
        <Contact
        on_select = self.link.callback(move | c | ContactListMsg::Select(c))
        stored = stored />
        }
    }
}

pub enum ContactMsg {
    IncomingPreKey(String),
    // TODO
    Select,
    Nope,
}

#[derive(PartialEq, Clone, Properties)]
pub struct ContactProps {
    pub on_select: Callback<Arc<storage::Contact>>,
    pub stored: Arc<storage::Contact>,
}

pub struct Contact {
    link: ComponentLink<Self>,
    on_select: Callback<Arc<storage::Contact>>,
    stored: Arc<storage::Contact>,
}

impl Component for Contact {
    type Message = ContactMsg;
    type Properties = ContactProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let stored = props.stored;

        if stored.ratchet.is_none() {
            // TODO get pre keys
        }

        Contact {
            link,
            on_select: props.on_select,
            stored,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        false
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
        <div class = "box contact" onclick = self.link.callback( move | _ | ContactMsg::Select) >
        { & self.stored.id }
        </div>
        }
    }
}



