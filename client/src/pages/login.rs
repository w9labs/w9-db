use leptos::*;

use crate::auth::login;

#[component]
pub fn LoginPage() -> impl IntoView {
    let (email, set_email) = create_signal(String::new());
    let (password, set_password) = create_signal(String::new());
    let (error, set_error) = create_signal(Option::<String>::None);
    let (loading, set_loading) = create_signal(false);

    let do_login = move |_| {
        let email_val = email.get_untracked();
        let password_val = password.get_untracked();
        if email_val.is_empty() || password_val.is_empty() {
            set_error.set(Some("Please fill in all fields".to_string()));
            return;
        }
        set_loading.set(true);
        spawn_local(async move {
            match login(email_val, password_val).await {
                Ok(_user) => {
                    window().location().set_href("/dashboard").ok();
                }
                Err(e) => {
                    set_error.set(Some(e));
                    set_loading.set(false);
                }
            }
        });
    };

    view! {
        <div class="page login-page">
            <div class="login-container">
                <h2 class="page-title">"LOGIN"</h2>
                {move || error.get().map(|e| view! { <div class="error-message">{e}</div> })}
                <div class="form-group">
                    <label>"EMAIL"</label>
                    <input class="voxel-input" placeholder="your@email.com"
                        on:input=move |ev| set_email.set(event_target_value(&ev))/>
                </div>
                <div class="form-group">
                    <label>"PASSWORD"</label>
                    <input class="voxel-input" placeholder="••••••••" type="password"
                        on:input=move |ev| set_password.set(event_target_value(&ev))/>
                </div>
                <div class="form-actions">
                    <button class="voxel-button" on:click=do_login>
                        {move || if loading.get() { "LOGGING IN..." } else { "LOGIN" }}
                    </button>
                </div>
                <div class="login-footer">
                    <p>"Don't have an account? " <a href="/register">"Register"</a></p>
                </div>
            </div>
        </div>
    }
}

fn window() -> web_sys::Window {
    web_sys::window().unwrap()
}
