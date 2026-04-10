use leptos::*;

use crate::auth::{get_current_user, logout};
use crate::types::UserInfo;

#[component]
pub fn DashboardPage() -> impl IntoView {
    let (user, set_user) = create_signal(Option::<UserInfo>::None);
    let (loading, set_loading) = create_signal(true);

    spawn_local(async move {
        if let Some(u) = get_current_user().await {
            set_user.set(Some(u));
        }
        set_loading.set(false);
    });

    view! {
        <div class="page dashboard-page">
            <h2 class="page-title">"DASHBOARD"</h2>
            {move || match (loading.get(), user.get()) {
                (true, _) => view! { <p>"Loading..."</p> }.into_view(),
                (false, None) => view! {
                    <div class="not-logged-in">
                        <p>"Not logged in. " <a href="/login">"Login"</a></p>
                    </div>
                }.into_view(),
                (false, Some(u)) => view! {
                    <div class="dashboard-content">
                        <div class="voxel-card">
                            <h3 class="card-title">"PROFILE"</h3>
                            <p><strong>"Email:"</strong> {u.email}</p>
                            {u.display_name.map(|n| view! { <p><strong>"Name:"</strong> {n}</p> })}
                            <p><strong>"Role:"</strong> {u.role}</p>
                        </div>
                        <button class="voxel-button" on:click=move |_| logout()>"LOGOUT"</button>
                    </div>
                }.into_view(),
            }}
        </div>
    }
}
