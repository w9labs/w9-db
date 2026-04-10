use leptos::*;

#[component]
pub fn HomePage() -> impl IntoView {
    view! {
        <div class="page home-page">
            <section class="hero-section">
                <h2 class="hero-title">"W9 DATABASE"</h2>
                <p class="hero-subtitle">"CENTRAL OAUTH PROVIDER"</p>
                <p class="hero-description">
                    "Secure authentication for all W9 services."
                </p>
                <div class="hero-actions">
                    <a href="/login" class="voxel-button">"LOGIN"</a>
                    <a href="/register" class="voxel-button">"REGISTER"</a>
                </div>
            </section>

            <section class="features-section">
                <h2 class="section-title">"FEATURES"</h2>
                <div class="card-grid">
                    <div class="voxel-card">
                        <h3 class="card-title">"OAUTH 2.0"</h3>
                        <p>"Standards-compliant OAuth provider."</p>
                    </div>
                    <div class="voxel-card">
                        <h3 class="card-title">"USER MANAGEMENT"</h3>
                        <p>"Role-based access control."</p>
                    </div>
                    <div class="voxel-card">
                        <h3 class="card-title">"API TOKENS"</h3>
                        <p>"Programmatic access tokens."</p>
                    </div>
                    <div class="voxel-card">
                        <h3 class="card-title">"SURREALDB"</h3>
                        <p>"Fast, scalable storage."</p>
                    </div>
                </div>
            </section>
        </div>
    }
}
