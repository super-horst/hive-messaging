use std::sync::Arc;
use yew::prelude::*;

use yew::{html, Component, ComponentLink, Html, ShouldRender};

use crate::bindings;
use crate::identity::LocalIdentity;
use crate::storage;
use crate::storage::IdentityModel;

mod contacts;

pub enum MessagingViewMessage {
    SelectContact(Arc<storage::ContactModel>),
    Nope,
}

pub struct MessagingView {
    link: ComponentLink<Self>,
    identity: LocalIdentity,
    selected_contact: Option<Arc<storage::ContactModel>>,
}

#[derive(Clone, Properties)]
pub struct MessagingProperties {
    pub identity: LocalIdentity,
}

impl Component for MessagingView {
    type Message = MessagingViewMessage;
    type Properties = MessagingProperties;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        MessagingView {
            link,
            identity: props.identity,
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

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        // don't render
        false
    }

    fn view(&self) -> Html {
        html! {
        <div class="view_layout">
            <contacts::ContactList
                on_select=self.link.callback(move |c| MessagingViewMessage::SelectContact(c))
                identity=self.identity.clone() />
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
