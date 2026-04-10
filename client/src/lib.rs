use leptos::*;
use leptos_meta::*;
use leptos_router::*;

mod components;
mod pages;
mod auth;
mod types;

use components::{Header, Footer};
use pages::{HomePage, LoginPage, RegisterPage, DashboardPage, OAuthConsentPage};

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Title text="W9 Database - OAuth Provider"/>
        <Meta name="viewport" content="width=device-width, initial-scale=1"/>
        <Meta name="description" content="W9 Database OAuth Provider"/>
        <Stylesheet id="voxel" href="/pkg/w9-db-client.css"/>

        <Router>
            <div class="app-container">
                <Header/>
                <main class="main-content">
                    <Routes>
                        <Route path="" view=HomePage/>
                        <Route path="/login" view=LoginPage/>
                        <Route path="/register" view=RegisterPage/>
                        <Route path="/dashboard" view=DashboardPage/>
                        <Route path="/authorize" view=OAuthConsentPage/>
                    </Routes>
                </main>
                <Footer/>
            </div>
        </Router>
    }
}
