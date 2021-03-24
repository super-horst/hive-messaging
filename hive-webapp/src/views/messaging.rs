use std::hash::{Hash, Hasher};
use std::sync::Arc;

use wasm_bindgen_futures::futures_0_3::spawn_local;

use yew::prelude::*;
use yew::{html, Component, ComponentLink, Html, Properties, ShouldRender};

use log::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hive_commons::model;
use hive_commons::model::Encodable;

use crate::ctrl::{
    Contact, ContactManager, IdentityController, MessagingController, StorageController,
};
use crate::views::contacts;

const MSG_KEY_PREFIX: &'static str = "hive.core.messages.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageModel {
    pub id: Uuid,
    pub message: String,
    pub timestamp: u64,
}

impl Hash for MessageModel {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl std::cmp::PartialEq<MessageModel> for MessageModel {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for MessageModel {}

pub enum MessagingViewMessage {
    Update(String),
    Send,
    SelectContact(Arc<Contact>),
    Nope,
}

#[derive(Clone, Properties)]
pub struct MessagingProperties {
    pub on_error: Callback<String>,
    pub storage: StorageController,
    pub identity: IdentityController,
    pub contacts: ContactManager,
    pub messaging: MessagingController,
}

pub struct MessagingView {
    link: ComponentLink<Self>,
    on_error: Callback<String>,
    storage: StorageController,
    identity: IdentityController,
    contacts: ContactManager,
    messaging: MessagingController,
    selected_contact: Option<Arc<Contact>>,
    composed_message: String,
}

impl Component for MessagingView {
    type Message = MessagingViewMessage;
    type Properties = MessagingProperties;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        MessagingView {
            link,
            on_error: props.on_error,
            storage: props.storage,
            identity: props.identity,
            contacts: props.contacts,
            messaging: props.messaging,
            selected_contact: None,
            composed_message: "".to_string(),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            MessagingViewMessage::Nope => {
                //NOOP
            }
            MessagingViewMessage::Send => {
                info!("Sending {}", &self.composed_message);

                if let Some(ref contact) = self.selected_contact {
                    let message = self.composed_message.clone();

                    // TODO handle errors
                    let msg_payload = model::messages::MessagePayload { message }.encode().unwrap();

                    let payload = model::messages::Payload { header: None, payload: msg_payload };

                    let local_contact = contact.clone();
                    let local_messaging = self.messaging.clone();
                    let local_on_error = self.on_error.clone();
                    spawn_local(async move {
                        if let Err(error) =
                            local_messaging.outgoing_message(&local_contact, &payload).await
                        {
                            local_on_error.emit(format!("Failed to access messages {:?}", error));
                            panic!(error)
                        }
                    });
                    self.composed_message = "".to_string();
                }
            }
            MessagingViewMessage::Update(val) => {
                self.composed_message = val;
            }
            MessagingViewMessage::SelectContact(c) => {
                self.selected_contact = Some(c);
            }
        };

        return true;
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        // don't render
        false
    }

    fn view(&self) -> Html {
        // TODO handle errors
        let messages: Vec<String> = match self.selected_contact {
            Some(ref c) => {
                let key = MSG_KEY_PREFIX.to_owned() + &c.profile().id.to_string();

                let load_result = self.storage.load::<Vec<MessageModel>>(&key);

                match load_result {
                    Ok(messages) => messages.iter().map(|m| m.message.clone()).collect(),
                    Err(error) => {
                        self.on_error.emit(format!("Failed to access messages {:?}", error));
                        panic!(error)
                    }
                }
            }
            None => vec![],
        };

        html! {
        <div class="view_layout">
            <contacts::ContactListView
                on_error=self.on_error.clone()
                on_select=self.link.callback(move |c| MessagingViewMessage::SelectContact(c))
                contacts=self.contacts.clone() />
            <div class="box msg_view_layout">
                <div class="msg_header">
                    <div class="center">
                        {"Not available"}
                        /*{match &self.selected_contact {
                            Some(c) => c.key.id_string(),
                            None => "".to_string(),
                         }}*/
                    </div>
                </div>

                <div class="msg_view">
                    {for messages.iter().map(|c| {
                        html! {
                        <p>{c}</p>
                        }
                    } )}
                </div>
                <div class="msg_input_view">
                    <input placeholder="Compose a message..." style="width: 100%;"
                        value=&self.composed_message
                        oninput=self.link.callback(|e: InputData| MessagingViewMessage::Update(e.value))
                        onkeypress=self.link.callback(|e: KeyboardEvent| {
                           if e.key() == "Enter" { MessagingViewMessage::Send } else { MessagingViewMessage::Nope }
                   }) />
                </div>
            </div>
        </div>
        }
    }
}
