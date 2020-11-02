



pub struct QrScannerView {
    link: ComponentLink<Self>,
}

impl Component for QrScannerView {
    type Message = ();
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {

        QrScannerView {
            link,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        false
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        // don't render
        false
    }

    fn view(&self) -> Html {
        html! {
        <div>
            <MessagingView />
        </div>
        }
    }
}