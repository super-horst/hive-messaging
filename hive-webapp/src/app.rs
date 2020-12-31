use yew::{html, Component, ComponentLink, Html, ShouldRender};

use log::*;

use crate::identity::LocalIdentity;
use crate::views::*;

pub struct AppContainer {
    link: ComponentLink<Self>,
    identity: LocalIdentity,
}

impl Component for AppContainer {
    type Message = ();
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        info!("Initialising app");

        AppContainer {
            link,
            identity: LocalIdentity::initialise(),
        }
    }

    fn update(&mut self, _: Self::Message) -> ShouldRender {
        // don't render
        return false;
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        // don't render
        false
    }

    fn view(&self) -> Html {
        let id = self.identity.clone();
        html! {
        <div>
            <MessagingView identity = id/>
        </div>
        }
    }
}
