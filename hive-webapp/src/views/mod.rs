use std::sync::Arc;
use yew::prelude::*;

use yew::{html, Component, ComponentLink, Html, ShouldRender};

use crate::bindings;
use crate::storage;

mod contacts;

pub enum MessagingViewMessage {
    SelectContact(Arc<storage::Contact>),
    Nope,
}

pub struct MessagingView {
    link: ComponentLink<Self>,
    selected_contact: Option<Arc<storage::Contact>>,
}

impl Component for MessagingView {
    type Message = MessagingViewMessage;
    type Properties = ();

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        MessagingView {
            link,
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
                on_select=self.link.callback(move |c| MessagingViewMessage::SelectContact(c)) />
            <div class="box msg_view_layout">
                <div class="msg_header">
                    <div class="center">
                        {match &self.selected_contact {
                            Some(c) => c.key.clone(),
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
