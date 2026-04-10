use leptos::*;

#[component]
pub fn Header() -> impl IntoView {
    view! {
        <header class="voxel-header">
            <div class="header-content">
                <a href="/" class="logo-link">
                    <h1 class="logo-text">"W9 DB"</h1>
                </a>
                <nav class="header-nav">
                    <a href="/">"HOME"</a>
                    <a href="/dashboard">"DASHBOARD"</a>
                    <a href="/login">"LOGIN"</a>
                </nav>
            </div>
        </header>
    }
}

#[component]
pub fn Footer() -> impl IntoView {
    view! {
        <footer class="voxel-footer">
            <div class="footer-content">
                <div class="footer-section">
                    <h3>"W9 DATABASE"</h3>
                    <p>"Central OAuth Provider"</p>
                </div>
                <div class="footer-section">
                    <h3>"NETWORK"</h3>
                    <a href="https://w9.se">"Homepage"</a>
                    <a href="https://tools.w9.nu">"Tools"</a>
                    <a href="https://mail.w9.nu">"Mail"</a>
                </div>
                <div class="footer-section">
                    <p>"© 2026 W9 Labs"</p>
                </div>
            </div>
        </footer>
    }
}
