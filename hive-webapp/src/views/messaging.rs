use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::Arc;

use wasm_bindgen_futures::futures_0_3::spawn_local;

use yew::prelude::*;
use yew::{html, Component, ComponentLink, Html, Properties, ShouldRender};

use log::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hive_commons::model;
use hive_commons::model::{Decodable, Encodable};

use crate::ctrl::{
    Contact, ContactManager, ControllerError, IdentityController, MessagingController,
    StorageController,
};
use crate::transport::ConnectionManager;
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
    UpdateInput(String),
    Send,
    ReceiveMessage((Arc<Contact>, model::messages::Payload)),
    SelectContact(Arc<Contact>),
    Nope,
}

#[derive(Clone, Properties)]
pub struct MessagingProperties {
    pub on_error: Callback<String>,
    pub storage: StorageController,
    pub identity: IdentityController,
    pub contacts: ContactManager,
    pub connections: ConnectionManager,
}

pub struct MessagingView {
    link: ComponentLink<Self>,
    on_error: Callback<String>,
    storage: StorageController,
    contacts: ContactManager,
    messaging: MessagingController,
    selected_contact: Option<Arc<Contact>>,
    current_messages: Vec<MessageModel>,
    composed_message: String,
}

impl Component for MessagingView {
    type Message = MessagingViewMessage;
    type Properties = MessagingProperties;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let messaging = MessagingController::new(
            props.on_error.clone(),
            props.identity.clone(),
            props.contacts.clone(),
            props.connections.clone(),
            link.callback(MessagingViewMessage::ReceiveMessage),
        );

        MessagingView {
            link,
            on_error: props.on_error,
            storage: props.storage,
            contacts: props.contacts,
            messaging,
            selected_contact: None,
            current_messages: vec![],
            composed_message: "".to_string(),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            MessagingViewMessage::Nope => {
                //NOOP
                false
            }
            MessagingViewMessage::Send => {
                if let Some(ref contact) = self.selected_contact {
                    self.current_messages = self.send_message(contact, &self.composed_message);

                    self.composed_message = "".to_string();
                    return true;
                }
                false
            }
            MessagingViewMessage::ReceiveMessage((contact, message)) => {
                let messages = self.receive_message(&contact, message);
                match self.selected_contact {
                    Some(ref selected) => {
                        if selected.deref().eq(contact.deref()) {
                            self.current_messages = messages;
                            return true;
                        }
                        false
                    }
                    None => false,
                }
            }
            MessagingViewMessage::UpdateInput(val) => {
                self.composed_message = val;
                false
            }
            MessagingViewMessage::SelectContact(c) => {
                self.current_messages = self.load_messages(c.deref());
                self.selected_contact = Some(c);

                true
            }
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        // don't render
        false
    }

    fn view(&self) -> Html {
        let messages: Vec<String> = self
            .current_messages
            .iter()
            .map(|m| m.message.clone())
            .collect();

        html! {
        <div class="view_layout">
            <contacts::ContactListView
                on_error=self.on_error.clone()
                on_select=self.link.callback(move |c| MessagingViewMessage::SelectContact(c))
                contacts=self.contacts.clone() />
            <div class="box msg_view_layout">
                <div class="msg_header">
                    <div class="center">
                        {match &self.selected_contact {
                            Some(c) => &c.profile().name,
                            None => "",
                         }}
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
                        oninput=self.link.callback(|e: InputData| MessagingViewMessage::UpdateInput(e.value))
                        onkeypress=self.link.callback(|e: KeyboardEvent| {
                           if e.key() == "Enter" { MessagingViewMessage::Send } else { MessagingViewMessage::Nope }
                   }) />
                </div>
            </div>
        </div>
        }
    }
}

impl MessagingView {
    fn load_messages(&self, contact: &Contact) -> Vec<MessageModel> {
        let key = MSG_KEY_PREFIX.to_owned() + &contact.profile().id.to_string();

        let load_result = self.storage.load::<Vec<MessageModel>>(&key);

        match load_result {
            Ok(messages) => messages,
            Err(ControllerError::NoDataFound { .. }) => vec![],
            Err(error) => {
                error!("Failed to access messages {:?}", error);
                panic!(error)
            }
        }
    }

    fn send_message(&self, contact: &Arc<Contact>, message: &str) -> Vec<MessageModel> {
        // TODO handle errors
        let msg_payload = model::messages::MessagePayload {
            message: message.to_string(),
        }
        .encode()
        .unwrap();

        let messages = self.append_message(&contact, message.to_string());

        let payload = model::messages::Payload {
            header: None,
            payload: msg_payload,
        };

        let local_contact = contact.clone();
        let local_messaging = self.messaging.clone();
        let local_on_error = self.on_error.clone();
        spawn_local(async move {
            if let Err(error) = local_messaging
                .outgoing_message(&local_contact, &payload)
                .await
            {
                local_on_error.emit(format!("Failed to access messages {:?}", error));
                error!("Failed to access messages {:?}", error);
                panic!(error)
            }
        });

        messages
    }

    fn receive_message(
        &self,
        contact: &Arc<Contact>,
        payload: model::messages::Payload,
    ) -> Vec<MessageModel> {
        // TODO handle errors
        let msg_payload = model::messages::MessagePayload::decode(payload.payload).unwrap();

        self.append_message(contact, msg_payload.message)
    }

    fn append_message(&self, contact: &Arc<Contact>, message: String) -> Vec<MessageModel> {
        let mut load_result = self.load_messages(contact);
        load_result.push(MessageModel {
            id: Uuid::new_v4(),
            message,
            timestamp: 0,
        });

        // TODO handle errors
        let key = MSG_KEY_PREFIX.to_owned() + &contact.profile().id.to_string();
        self.storage.store(&key, &load_result).unwrap();

        load_result
    }
}
