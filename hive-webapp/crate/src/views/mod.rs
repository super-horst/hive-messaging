use std::sync::Arc;

use yew::format::Json;
use yew::prelude::*;
use yew::services::storage::{Area, StorageService};
use yew::{
    html, Component, ComponentLink, Href, Html, InputData, KeyboardEvent, Properties, ShouldRender,
};

use crate::storage::*;

mod contacts;
use contacts::*;

pub enum MessagingViewMessage {
    SelectContact(Arc<Contact>),
    Nope,
}

pub struct MessagingView {
    link: ComponentLink<Self>,
    storage: StorageController,
    selected_contact: Option<Arc<Contact>>,
}

impl Component for MessagingView {
    type Message = MessagingViewMessage;
    type Properties = ();

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        MessagingView {
            link,
            storage: StorageController::new(),
            selected_contact: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> bool {
        match msg {
            MessagingViewMessage::Nope => {}
            MessagingViewMessage::SelectContact(c) => {
                self.selected_contact = Some(c);
            }
        };

        return true;
    }

    fn change(&mut self, props: Self::Properties) -> bool {
        // don't render
        false
    }

    fn view(&self) -> Html {
        html! {
        <div class="view_layout">
            <ContactList
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
                    <button class="center">{"Send"}</button>
                </div>
            </div>
        </div>
        }
    }
}
