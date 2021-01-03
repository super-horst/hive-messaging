use yew::prelude::*;
use yew::{html, Component, ComponentLink, Html, Properties, ShouldRender};

use wasm_bindgen::__rt::std::sync::Arc;

use crate::identity::LocalIdentity;
use crate::storage::{ContactModel, StorageController};

use crate::transport::ConnectionManager;
use crate::views::contacts;

pub enum MessagingViewMessage {
    SelectContact(Arc<ContactModel>),
    Nope,
}

pub struct MessagingView {
    link: ComponentLink<Self>,
    props: MessagingProperties,
    selected_contact: Option<Arc<ContactModel>>,
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
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            MessagingViewMessage::Nope => {
                //NOOP
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
                    {"Messages"}
                </div>

                <div class="msg_input_view">
                    <input class="center" placeholder="Compose a message" style="width: 100%;"/>
                    <button class="center" onclick=self.link.callback(move |_| MessagingViewMessage::Nope)>{"Send"}</button>
                </div>
            </div>
        </div>
        }
    }
}
