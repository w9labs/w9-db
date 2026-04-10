use leptos::*;

use crate::auth::register;

#[component]
pub fn RegisterPage() -> impl IntoView {
    let (email, set_email) = create_signal(String::new());
    let (password, set_password) = create_signal(String::new());
    let (display_name, set_display_name) = create_signal(String::new());
    let (error, set_error) = create_signal(Option::<String>::None);
    let (loading, set_loading) = create_signal(false);

    let do_register = move |_| {
        let email_val = email.get_untracked();
        let password_val = password.get_untracked();
        if email_val.is_empty() || password_val.is_empty() {
            set_error.set(Some("Please fill in required fields".to_string()));
            return;
        }
        set_loading.set(true);
        spawn_local(async move {
            match register(email_val, password_val, display_name.get_untracked()).await {
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
        <div class="page register-page">
            <div class="register-container">
                <h2 class="page-title">"REGISTER"</h2>
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
                    <button class="voxel-button" on:click=do_register>
                        {move || if loading.get() { "REGISTERING..." } else { "REGISTER" }}
                    </button>
                </div>
                <div class="register-footer">
                    <p>"Already have an account? " <a href="/login">"Login"</a></p>
                </div>
            </div>
        </div>
    }
}

fn window() -> web_sys::Window {
    web_sys::window().unwrap()
}
