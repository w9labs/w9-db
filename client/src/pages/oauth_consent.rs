use leptos::*;

#[component]
pub fn OAuthConsentPage() -> impl IntoView {
    view! {
        <div class="page oauth-consent-page">
            <h2 class="page-title">"AUTHORIZE"</h2>
            <div class="voxel-card">
                <p>"An application wants access to your account."</p>
            </div>
            <div class="consent-actions">
                <a href="/" class="voxel-button">"DENY"</a>
                <a href="/" class="voxel-button">"AUTHORIZE"</a>
            </div>
        </div>
    }
}
