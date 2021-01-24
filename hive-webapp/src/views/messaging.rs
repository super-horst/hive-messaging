use yew::prelude::*;
use yew::{html, Component, ComponentLink, Html, Properties, ShouldRender};

use log::*;

use wasm_bindgen::__rt::std::sync::Arc;

use crate::identity::LocalIdentity;
use crate::storage::{ContactModel, StorageController};

use crate::transport::ConnectionManager;
use crate::views::contacts;

pub enum MessagingViewMessage {
    Update(String),
    Send,
    SelectContact(Arc<ContactModel>),
    Nope,
}

pub struct MessagingView {
    link: ComponentLink<Self>,
    props: MessagingProperties,
    selected_contact: Option<Arc<ContactModel>>,
    composed_message: String,
}

#[derive(Clone, Properties)]
pub struct MessagingProperties {
    pub identity: LocalIdentity,
    pub storage: StorageController,
    pub connections: ConnectionManager,
}

impl Component for MessagingView {
    type Message = MessagingViewMessage;
    type Properties = MessagingProperties;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        MessagingView {
            link,
            props,
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

                let mut c = self.selected_contact.as_ref().unwrap().as_ref().clone();

                let mut ratchet = c.ratchet.unwrap();

                let send_step = ratchet.send_step();

                // TODO find a way to propagate mutated contact back

                self.composed_message = "".to_string();
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
        let messages: Vec<String> = match &self.selected_contact {
            Some(c) => self
                .props
                .storage
                .get_messages(c)
                .iter()
                .map(|m| m.message.clone())
                .collect(),
            None => vec![],
        };

        html! {
        <div class="view_layout">
            <contacts::ContactList
                on_select=self.link.callback(move |c| MessagingViewMessage::SelectContact(c))
                identity=self.props.identity.clone()
                connections=self.props.connections.clone(),
                storage=self.props.storage.clone() />
            <div class="box msg_view_layout">
                <div class="msg_header">
                    <div class="center">
                        {match &self.selected_contact {
                            Some(c) => c.key.id_string(),
                            None => "".to_string(),
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
