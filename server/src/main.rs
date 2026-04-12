use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_postgres::{Client, NoTls};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

// ============================================================
// Shared CSS & Config
// ============================================================
const CSS: &str = include_str!("../infra/templates/voxel.css");
const TURNSTILE_SITE_KEY: &str = "0x4AAAAAACCVXG8QGZQCQVCA";
const SCOPES_TEXT: &str = "openid profile email";

// ============================================================
// Application State
// ============================================================
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Client>,
    pub jwt_secret: String,
    pub turnstile_secret: String,
    pub issuer_url: String,
    pub http_client: reqwest::Client,
}

// ============================================================
// Models
// ============================================================
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserRecord {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub role: String,
    pub is_verified: bool,
    pub created_at: String,
}

// ============================================================
// Turnstile Verification
// ============================================================
async fn verify_turnstile(state: &AppState, token: &str) -> bool {
    #[derive(Deserialize)]
    struct TurnstileResponse { success: bool }
    let res = state.http_client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&[("secret", &state.turnstile_secret), ("response", &token.to_string())])
        .send().await;
    match res {
        Ok(resp) => resp.json::<TurnstileResponse>().await.map(|t| t.success).unwrap_or(false),
        Err(_) => false,
    }
}

// ============================================================
// Password Hashing (argon2)
// ============================================================
fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt).expect("argon2 hash");
    hash.to_string()
}

fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

// ============================================================
// Session Management
// ============================================================
fn set_session(jar: CookieJar, token: String) -> CookieJar {
    jar.add(axum_extra::extract::cookie::Cookie::build(("w9_session", token))
        .path("/").http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::days(7)).finish())
}

fn clear_session(jar: CookieJar) -> CookieJar {
    jar.remove(axum_extra::extract::cookie::Cookie::named("w9_session"))
}

fn get_session_token(jar: &CookieJar) -> Option<String> {
    jar.get("w9_session").map(|c| c.value().to_string())
}

// ============================================================
// HTML Layout Helpers
// ============================================================
fn layout(title: &str, body: &str, nav: &str) -> String {
    format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/><title>{title} — W9 DB</title><style>{CSS}</style></head><body><div class="app"><nav class="nav"><a href="/" class="brand">🗄️ W9 DB</a><a href="/">Home</a>{nav}</nav>{body}<footer class="footer"><p>W9 DB — OAuth 2.0 / OIDC Provider</p><p class="text-xs text-muted">Rust + Axum + PostgreSQL + argon2</p></footer></div></body></html>"#, title=title, CSS=CSS, nav=nav, body=body)
}

fn auth_layout(title: &str, body: &str) -> String { layout(title, body, r#"<a href="/login">Login</a><a href="/register">Register</a>"#) }
fn user_layout(title: &str, body: &str) -> String { layout(title, body, r#"<a href="/dashboard">Dashboard</a><a href="/profile">Profile</a><a href="/logout">Logout</a>"#) }
fn admin_layout(title: &str, body: &str) -> String { layout(title, body, r#"<a href="/dashboard">Dashboard</a><a href="/admin">Admin</a><a href="/logout">Logout</a>"#) }

const TURNSTILE_WIDGET: &str = r#"<div class="mt-2"><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script><div class="cf-turnstile" data-sitekey="SITE_KEY" data-callback="onSubmit"></div></div>"#;
fn turnstile_html() -> String {
    let widget = TURNSTILE_WIDGET.replace("SITE_KEY", TURNSTILE_SITE_KEY);
    format!("{}<script>function onSubmit(token){{document.getElementById('turnstile-token').value=token;document.querySelector('form').submit();}}</script>", widget)
}

// ============================================================
// Pages: Home
// ============================================================
fn home_html() -> String {
    auth_layout("W9 DB", r#"<div class="hero"><h1>🗄️ W9 DB</h1><p>OAuth 2.0 / OIDC Provider for the W9 Network</p><p class="text-sm text-muted">Central authentication shared across all W9 projects</p><div class="flex mt-3" style="justify-content:center"><a href="/register" class="btn">Create Account</a><a href="/login" class="btn btn--ghost">Sign In</a></div></div><div class="grid mt-3"><div class="card"><h3>🔐 OAuth 2.0</h3><p class="text-sm">Standards-based authentication. All W9 services authenticate through this provider.</p></div><div class="card"><h3>👤 User Management</h3><p class="text-sm">Secure registration with argon2 hashing. Three roles: client, developer, admin.</p></div><div class="card"><h3>🤖 Bot Protection</h3><p class="text-sm">Cloudflare Turnstile on all auth pages to prevent automated attacks.</p></div></div>"#)
}

// ============================================================
// Pages: Login / Register / Reset
// ============================================================
fn login_html(msg: Option<&str>, err: Option<&str>) -> String {
    let alert = match (msg, err) { (Some(m),_) => format!(r#"<div class="alert alert--ok">{}</div>"#,m), (_,Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#,e), (None,None) => String::new() };
    auth_layout("Login", &format!(r#"<div class="card" style="max-width:420px;margin:2rem auto"><h1>🔐 Sign In</h1>{}<form method="POST" action="/login"><label>Email</label><input type="email" name="email" required placeholder="you@w9.nu"/><label>Password</label><input type="password" name="password" required placeholder="••••••••"/><input type="hidden" name="turnstile_token" id="turnstile-token"/>{}</label><button type="submit" class="btn mt-2" style="width:100%">Sign In</button></form><p class="text-sm text-center mt-2"><a href="/reset">Forgot password?</a> · <a href="/register">Create account</a></p></div>"#, alert, turnstile_html()))
}

fn register_html(msg: Option<&str>, err: Option<&str>) -> String {
    let alert = match (msg, err) { (Some(m),_) => format!(r#"<div class="alert alert--ok">{}</div>"#,m), (_,Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#,e), (None,None) => String::new() };
    auth_layout("Register", &format!(r#"<div class="card" style="max-width:420px;margin:2rem auto"><h1>📝 Create Account</h1>{}<form method="POST" action="/register"><label>Email</label><input type="email" name="email" required placeholder="you@w9.nu"/><label>Display Name</label><input type="text" name="display_name" placeholder="Your Name"/><label>Password</label><input type="password" name="password" required minlength="8" placeholder="Min 8 characters"/><label>Confirm Password</label><input type="password" name="password_confirm" required minlength="8" placeholder="Repeat password"/><input type="hidden" name="turnstile_token" id="turnstile-token"/>{}</label><button type="submit" class="btn mt-2" style="width:100%">Create Account</button></form><p class="text-sm text-center mt-2">Already have an account? <a href="/login">Sign In</a></p></div>"#, alert, turnstile_html()))
}

fn reset_html(msg: Option<&str>, err: Option<&str>) -> String {
    let alert = match (msg, err) { (Some(m),_) => format!(r#"<div class="alert alert--ok">{}</div>"#,m), (_,Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#,e), (None,None) => String::new() };
    auth_layout("Reset Password", &format!(r#"<div class="card" style="max-width:420px;margin:2rem auto"><h1>🔑 Reset Password</h1>{}<form method="POST" action="/reset"><label>Email</label><input type="email" name="email" required placeholder="you@w9.nu"/><input type="hidden" name="turnstile_token" id="turnstile-token"/>{}</label><button type="submit" class="btn mt-2" style="width:100%">Send Reset Link</button></form><p class="text-sm text-center mt-2"><a href="/login">Back to login</a></p></div>"#, alert, turnstile_html()))
}

// ============================================================
// Pages: Dashboard / Profile / Admin
// ============================================================
fn dashboard_html(user: &UserRecord) -> String {
    let role_badge = match user.role.as_str() { "admin" => r#"<span class="badge badge--err">ADMIN</span>"#, "developer" => r#"<span class="badge badge--warn">DEVELOPER</span>"#, _ => r#"<span class="badge badge--ok">CLIENT</span>"# };
    let verify_badge = if user.is_verified { r#"<span class="badge badge--ok">✓ VERIFIED</span>"# } else { r#"<span class="badge badge--warn">PENDING</span>"# };
    let admin_link = if user.role == "admin" { r#"<a href="/admin" class="btn" style="display:block;text-align:center;margin:.5rem 0">⚙️ Admin Panel</a>"# } else { "" };
    user_layout("Dashboard", &format!(r#"<div class="hero"><h1>👤 Welcome, {}</h1><p class="text-sm">Account Dashboard</p></div><div class="grid"><div class="card"><h3>Profile</h3><table><tr><td>Email</td><td>{}</td></tr><tr><td>Display Name</td><td>{}</td></tr><tr><td>Role</td><td>{}</td></tr><tr><td>Verified</td><td>{}</td></tr><tr><td>Member Since</td><td>{}</td></tr></table></div><div class="card"><h3>Quick Actions</h3><a href="/profile" class="btn" style="display:block;text-align:center;margin:.5rem 0">Edit Profile</a>{}<a href="/logout" class="btn btn--ghost" style="display:block;text-align:center;margin:.5rem 0">Sign Out</a></div></div>"#, user.display_name.as_deref().unwrap_or(&user.email), user.email, user.display_name.as_deref().unwrap_or("—"), role_badge, verify_badge, user.created_at, admin_link))
}

fn profile_html(user: &UserRecord, msg: Option<&str>, err: Option<&str>) -> String {
    let alert = match (msg, err) { (Some(m),_) => format!(r#"<div class="alert alert--ok">{}</div>"#,m), (_,Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#,e), (None,None) => String::new() };
    user_layout("Profile", &format!(r#"<div class="card" style="max-width:500px;margin:2rem auto"><h1>✏️ Edit Profile</h1>{}<form method="POST" action="/profile"><label>Display Name</label><input type="text" name="display_name" value="{}" placeholder="Your Name"/><label>Current Password (to confirm)</label><input type="password" name="current_password" required placeholder="••••••••"/><button type="submit" class="btn mt-2" style="width:100%">Save Changes</button></form></div>"#, alert, user.display_name.as_deref().unwrap_or("")))
}

fn admin_html(users: &[(String, String, String, String, bool, String)], msg: Option<&str>, err: Option<&str>) -> String {
    let alert = match (msg, err) { (Some(m),_) => format!(r#"<div class="alert alert--ok">{}</div>"#,m), (_,Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#,e), (None,None) => String::new() };
    let rows: String = users.iter().map(|(id, email, name, role, verified, created)| {
        let role_badge = match role.as_str() { "admin" => r#"<span class="badge badge--err">ADMIN</span>"#, "developer" => r#"<span class="badge badge--warn">DEV</span>"#, _ => r#"<span class="badge badge--ok">CLIENT</span>"# };
        let v = if *verified { "✓" } else { "—" };
        format!(r#"<tr><td class="text-xs">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class="text-xs">{}</td><td><a href="/admin/promote/{}" class="btn btn--sm">Promote</a> <a href="/admin/demote/{}" class="btn btn--sm btn--ghost">Demote</a></td></tr>"#, id, email, name.as_str().replace("None", "—"), role_badge, v, created, id, id)
    }).collect();
    admin_layout("Admin Panel", &format!(r#"<div class="card" style="max-width:900px;margin:2rem auto"><h1>⚙️ Admin Panel</h1>{}<div class="flex flex-between mb-2"><h2>User Management</h2><span class="text-sm text-muted">{} total users</span></div><table><tr><th>ID</th><th>Email</th><th>Name</th><th>Role</th><th>Verified</th><th>Joined</th><th>Actions</th></tr>{}</table></div>"#, alert, users.len(), rows))
}

// ============================================================
// Form Structs
// ============================================================
#[derive(Debug, Deserialize)]
struct LoginReq { email: String, password: String, turnstile_token: Option<String> }
#[derive(Debug, Deserialize)]
struct RegisterReq { email: String, display_name: Option<String>, password: String, password_confirm: String, turnstile_token: Option<String> }
#[derive(Debug, Deserialize)]
struct ResetReq { email: String, turnstile_token: Option<String> }
#[derive(Debug, Deserialize)]
struct ProfileReq { display_name: Option<String>, current_password: String }

// ============================================================
// Handlers: Public Pages
// ============================================================
async fn home() -> Html<String> { Html(home_html()) }
async fn login_page(jar: CookieJar) -> impl IntoResponse {
    if get_session_token(&jar).is_some() { return Redirect::to("/dashboard").into_response(); }
    Html(login_html(None, None)).into_response()
}
async fn register_page(jar: CookieJar) -> impl IntoResponse {
    if get_session_token(&jar).is_some() { return Redirect::to("/dashboard").into_response(); }
    Html(register_html(None, None)).into_response()
}
async fn reset_page(jar: CookieJar) -> impl IntoResponse {
    if get_session_token(&jar).is_some() { return Redirect::to("/dashboard").into_response(); }
    Html(reset_html(None, None)).into_response()
}

// ============================================================
// Handlers: Auth Actions
// ============================================================
async fn login_post(State(state): State<AppState>, jar: CookieJar, Form(form): Form<LoginReq>) -> impl IntoResponse {
    if let Some(t) = form.turnstile_token { if !t.is_empty() && !verify_turnstile(&state, &t).await { return Html(login_html(None, Some("Turnstile failed"))).into_response(); } }
    let row = match state.db.query_opt("SELECT id::text, email, password_hash, display_name, role, is_verified, created_at::text FROM users WHERE email = $1", &[&form.email]).await {
        Ok(Some(r)) => r, Ok(None) => return Html(login_html(None, Some("Invalid email or password"))).into_response(),
        Err(e) => { tracing::error!("Login: {}", e); return Html(login_html(None, Some("Database error"))).into_response() }
    };
    let pw: String = row.get("password_hash");
    if !verify_password(&form.password, &pw) { return Html(login_html(None, Some("Invalid email or password"))).into_response(); }
    let email: String = row.get("email");
    let user_id: String = row.get("id");
    let token = format!("sess-{}-{}-{}", email, Uuid::new_v4(), Utc::now().timestamp());
    let expires = Utc::now() + Duration::days(7);
    let _ = state.db.execute("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,$4)", &[&Uuid::new_v4(), &user_id, &token, &expires]).await;
    (set_session(jar, token), Redirect::to("/dashboard")).into_response()
}

async fn register_post(State(state): State<AppState>, jar: CookieJar, Form(form): Form<RegisterReq>) -> impl IntoResponse {
    if let Some(t) = form.turnstile_token { if !t.is_empty() && !verify_turnstile(&state, &t).await { return Html(register_html(None, Some("Turnstile failed"))).into_response(); } }
    if form.password != form.password_confirm { return Html(register_html(None, Some("Passwords do not match"))).into_response(); }
    if form.password.len() < 8 { return Html(register_html(None, Some("Password must be 8+ characters"))).into_response(); }
    let exists: bool = state.db.query_one("SELECT COUNT(*) FROM users WHERE email = $1", &[&form.email]).await.map(|r| { let c: i64 = r.get(0); c > 0 }).unwrap_or(false);
    if exists { return Html(register_html(None, Some("Email already registered"))).into_response(); }
    let pw_hash = hash_password(&form.password);
    let uid = Uuid::new_v4();
    if let Err(e) = state.db.execute("INSERT INTO users (id, email, password_hash, display_name, role, is_verified) VALUES ($1,$2,$3,$4,$5,$6)", &[&uid, &form.email, &pw_hash, &form.display_name, &"client", &false]).await {
        tracing::error!("Register: {}", e); return Html(register_html(None, Some("Registration failed"))).into_response();
    }
    let token = format!("sess-{}-{}-{}", form.email, Uuid::new_v4(), Utc::now().timestamp());
    let expires = Utc::now() + Duration::days(7);
    let _ = state.db.execute("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,$4)", &[&Uuid::new_v4(), &uid.to_string(), &token, &expires]).await;
    (set_session(jar, token), Redirect::to("/dashboard")).into_response()
}

async fn reset_post(State(state): State<AppState>, Form(form): Form<ResetReq>) -> impl IntoResponse {
    if let Some(t) = form.turnstile_token { if !t.is_empty() && !verify_turnstile(&state, &t).await { return Html(reset_html(None, Some("Turnstile failed"))).into_response(); } }
    let exists: bool = state.db.query_one("SELECT COUNT(*) FROM users WHERE email = $1", &[&form.email]).await.map(|r| { let c: i64 = r.get(0); c > 0 }).unwrap_or(false);
    if exists { tracing::info!("Reset requested: {}", form.email); /* TODO: call w9-mail API */ }
    Html(reset_html(Some("If an account exists, a reset link has been sent."), None)).into_response()
}

// ============================================================
// Auth Helper
// ============================================================
async fn require_auth(jar: &CookieJar, state: &AppState) -> Option<UserRecord> {
    let token = get_session_token(jar)?;
    let row = state.db.query_opt("SELECT u.id::text, u.email, u.display_name, u.role, u.is_verified, u.created_at::text FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > $2", &[&token, &Utc::now()]).await.ok()??;
    Some(UserRecord { id: row.get(0), email: row.get(1), display_name: row.get(2), role: row.get(3), is_verified: row.get(4), created_at: row.get(5) })
}

// ============================================================
// Handlers: User Pages
// ============================================================
async fn dashboard(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    match require_auth(&jar, &state).await { Some(u) => Html(dashboard_html(&u)).into_response(), None => (clear_session(jar), Redirect::to("/login")).into_response() }
}
async fn profile_page(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    match require_auth(&jar, &state).await { Some(u) => Html(profile_html(&u, None, None)).into_response(), None => (clear_session(jar), Redirect::to("/login")).into_response() }
}
async fn profile_post(State(state): State<AppState>, jar: CookieJar, Form(form): Form<ProfileReq>) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await { Some(u) => u, None => return (clear_session(jar), Redirect::to("/login")).into_response() };
    let row = match state.db.query_opt("SELECT password_hash FROM users WHERE id = $1", &[&user.id]).await { Ok(Some(r)) => r, _ => return Html(profile_html(&user, None, Some("DB error"))).into_response() };
    let pw: String = row.get("password_hash");
    if !verify_password(&form.current_password, &pw) { return Html(profile_html(&user, None, Some("Current password incorrect"))).into_response(); }
    if let Err(e) = state.db.execute("UPDATE users SET display_name = $1 WHERE id = $2", &[&form.display_name, &user.id]).await {
        tracing::error!("Profile: {}", e); return Html(profile_html(&user, None, Some("Update failed"))).into_response();
    }
    Html(profile_html(&UserRecord { display_name: form.display_name, ..user }, Some("Profile updated!"), None)).into_response()
}
async fn logout(jar: CookieJar) -> impl IntoResponse { (clear_session(jar), Redirect::to("/")).into_response() }

// ============================================================
// Handlers: Admin
// ============================================================
async fn admin_page(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await { Some(u) => u, None => return (clear_session(jar), Redirect::to("/login")).into_response() };
    if user.role != "admin" { return Html(layout("Forbidden", r#"<div class="card" style="max-width:400px;margin:3rem auto;text-align:center"><h1>🚫 Forbidden</h1><p>Admin access required.</p><a href="/dashboard" class="btn mt-2">Dashboard</a></div>"#, "")).into_response(); }
    let users = match state.db.query("SELECT id::text, email, COALESCE(display_name, '—') as name, role, is_verified, created_at::text FROM users ORDER BY created_at DESC", &[]).await {
        Ok(rows) => rows.iter().map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5))).collect(),
        Err(_) => Vec::new(),
    };
    Html(admin_html(&users, None, None)).into_response()
}
async fn admin_promote(State(state): State<AppState>, jar: CookieJar, axum::extract::Path(uid): axum::extract::Path<String>) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await { Some(u) => u, None => return (clear_session(jar), Redirect::to("/login")).into_response() };
    if user.role != "admin" { return Redirect::to("/dashboard").into_response(); }
    let _ = state.db.execute("UPDATE users SET role = CASE WHEN role='client' THEN 'developer' WHEN role='developer' THEN 'admin' ELSE role END WHERE id=$1", &[&uid]).await;
    Redirect::to("/admin").into_response()
}
async fn admin_demote(State(state): State<AppState>, jar: CookieJar, axum::extract::Path(uid): axum::extract::Path<String>) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await { Some(u) => u, None => return (clear_session(jar), Redirect::to("/login")).into_response() };
    if user.role != "admin" || uid == user.id { return Redirect::to("/admin").into_response(); }
    let _ = state.db.execute("UPDATE users SET role = CASE WHEN role='admin' THEN 'developer' WHEN role='developer' THEN 'client' ELSE role END WHERE id=$1", &[&uid]).await;
    Redirect::to("/admin").into_response()
}

// ============================================================
// Handlers: API + OAuth
// ============================================================
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.query_one("SELECT 1", &[]).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"status":"ok","service":"w9-db","database":"connected","timestamp":Utc::now().to_rfc3339()}))),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"status":"error","service":"w9-db","error":e.to_string()}))),
    }
}
async fn oidc_discovery() -> impl IntoResponse {
    let issuer = std::env::var("ISSUER_URL").unwrap_or_else(|_| "https://db.w9.nu".into());
    (StatusCode::OK, Json(serde_json::json!({"issuer":issuer,"authorization_endpoint":format!("{}/oauth/authorize",issuer),"token_endpoint":format!("{}/oauth/token",issuer),"userinfo_endpoint":format!("{}/api/auth/me",issuer),"response_types_supported":["code"],"scopes_supported":["openid","profile","email"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["HS256"]})))
}

#[derive(Debug, Deserialize)]
struct OAuthAuthQuery { client_id: Option<String>, redirect_uri: Option<String>, response_type: Option<String>, state: Option<String> }
async fn oauth_authorize(State(state): State<AppState>, jar: CookieJar, Query(q): Query<OAuthAuthQuery>) -> impl IntoResponse {
    if get_session_token(&jar).is_none() {
        return Redirect::to(&format!("/login?redirect={}", q.redirect_uri.as_deref().unwrap_or("/"))).into_response();
    }
    let user = match require_auth(&jar, &state).await { Some(u) => u, None => return (clear_session(jar), Redirect::to("/login")).into_response() };
    let code = format!("auth-{}-{}-{}", user.email, Uuid::new_v4(), Utc::now().timestamp());
    let expires = Utc::now() + Duration::minutes(10);
    let _ = state.db.execute("INSERT INTO oauth_tokens (id, token, token_type, user_id, scopes, expires_at) VALUES ($1,$2,$3,$4,$5,$6)", &[&Uuid::new_v4(), &code, &"authorization_code", &user.id, &SCOPES_TEXT, &expires]).await;
    let redir = q.redirect_uri.as_deref().unwrap_or("/");
    let sep = if redir.contains('?') { "&" } else { "?" };
    Redirect::to(&format!("{}{}code={}&state={}", redir, sep, code, q.state.as_deref().unwrap_or(""))).into_response()
}

#[derive(Debug, Deserialize)]
struct OAuthTokenReq { grant_type: String, code: Option<String>, client_id: Option<String>, client_secret: Option<String>, redirect_uri: Option<String> }
async fn oauth_token(State(state): State<AppState>, Form(form): Form<OAuthTokenReq>) -> (StatusCode, Json<serde_json::Value>) {
    if form.grant_type != "authorization_code" { return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"unsupported_grant_type"}))); }
    let code = match form.code { Some(c) => c, None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid_request"}))) };
    let row = match state.db.query_opt("SELECT user_id FROM oauth_tokens WHERE token=$1 AND token_type='authorization_code' AND expires_at>$2", &[&code, &Utc::now()]).await { Ok(Some(r)) => r, _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid_grant"}))) };
    let user_id: String = row.get("user_id");
    let user_row = match state.db.query_opt("SELECT email, display_name, role, is_verified FROM users WHERE id=$1", &[&user_id]).await { Ok(Some(r)) => r, _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"server_error"}))) };
    let access_token = format!("access-{}-{}-{}", user_id, Uuid::new_v4(), Utc::now().timestamp());
    let expires = Utc::now() + Duration::hours(24);
    let _ = state.db.execute("INSERT INTO oauth_tokens (id, token, token_type, user_id, scopes, expires_at) VALUES ($1,$2,$3,$4,$5,$6)", &[&Uuid::new_v4(), &access_token, &"bearer", &user_id, &SCOPES_TEXT, &expires]).await;
    let _ = state.db.execute("DELETE FROM oauth_tokens WHERE token=$1", &[&code]).await;
    (StatusCode::OK, Json(serde_json::json!({"access_token":access_token,"token_type":"bearer","expires_in":86400,"scope":SCOPES_TEXT,"user":{"email":user_row.get::<_,String>("email"),"display_name":user_row.get::<_,Option<String>>("display_name"),"role":user_row.get::<_,String>("role"),"is_verified":user_row.get::<_,bool>("is_verified")}})))
}

async fn handle_me(headers: HeaderMap, State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    if let Some(auth) = headers.get("Authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if let Ok(Some(r)) = state.db.query_opt("SELECT u.email, u.display_name, u.role, u.is_verified FROM users u JOIN oauth_tokens t ON u.id=t.user_id WHERE t.token=$1 AND t.token_type='bearer' AND t.expires_at>$2", &[&token, &Utc::now()]).await {
                return (StatusCode::OK, Json(serde_json::json!({"email":r.get::<_,String>("email"),"display_name":r.get::<_,Option<String>>("display_name"),"role":r.get::<_,String>("role"),"is_verified":r.get::<_,bool>("is_verified")})));
            }
        }
    }
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Not authenticated"})))
}

// ============================================================
// Admin Seeder
// ============================================================
async fn seed_admin(db: &Arc<Client>, email: &str, password: &str) {
    let exists = db.query_one("SELECT COUNT(*) FROM users WHERE email=$1", &[&email]).await.map(|r| { let c: i64 = r.get(0); c > 0 }).unwrap_or(false);
    if !exists {
        let pw_hash = hash_password(password);
        if let Err(e) = db.execute("INSERT INTO users (id, email, password_hash, display_name, role, is_verified) VALUES ($1,$2,$3,$4,$5,$6)", &[&Uuid::new_v4(), &email, &pw_hash, &"Default Admin", &"admin", &true]).await {
            tracing::error!("Seed admin: {}", e);
        } else { tracing::info!("✅ Seeded admin: {}", email); }
    }
}

// ============================================================
// Main
// ============================================================
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).with(tracing_subscriber::fmt::layer()).init();
    dotenvy::dotenv().ok();
    let port = std::env::var("PORT").unwrap_or_else(|_| "8082".into());
    let db_url = std::env::var("W9_DB_URL").or_else(|_| std::env::var("DATABASE_URL")).unwrap_or_else(|_| "postgres://w9_admin:password@w9-postgres:5432/w9_users".into());
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "change-me".into());
    let turnstile_secret = std::env::var("TURNSTILE_SECRET_KEY").unwrap_or_default();
    let issuer_url = std::env::var("ISSUER_URL").unwrap_or_else(|_| "https://db.w9.nu".into());
    tracing::info!("Connecting to PostgreSQL...");
    let (client, conn) = tokio_postgres::connect(&db_url, NoTls).await?;
    tokio::spawn(async move { if let Err(e) = conn.await { tracing::error!("DB: {}", e); } });
    client.query_one("SELECT 1", &[]).await?;
    tracing::info!("✅ Connected to PostgreSQL");
    let db = Arc::new(client);
    let http_client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build()?;
    let admin_email = std::env::var("W9_DB_ADMIN_EMAIL").unwrap_or_else(|_| "admin@w9.nu".into());
    let admin_pw = std::env::var("W9_DB_ADMIN_PASSWORD").unwrap_or_else(|_| "W9Admin123!".into());
    seed_admin(&db, &admin_email, &admin_pw).await;
    let state = AppState { db, jwt_secret, turnstile_secret, issuer_url, http_client };
    let router = Router::new()
        .route("/", get(home)).route("/login", get(login_page)).route("/login", post(login_post))
        .route("/register", get(register_page)).route("/register", post(register_post))
        .route("/reset", get(reset_page)).route("/reset", post(reset_post))
        .route("/dashboard", get(dashboard)).route("/profile", get(profile_page)).route("/profile", post(profile_post))
        .route("/logout", get(logout))
        .route("/admin", get(admin_page)).route("/admin/promote/:id", get(admin_promote)).route("/admin/demote/:id", get(admin_demote))
        .route("/api/health", get(health_check)).route("/api/auth/me", get(handle_me))
        .route("/oauth/authorize", get(oauth_authorize)).route("/oauth/token", post(oauth_token))
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .with_state(state)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()).layer(CorsLayer::permissive()));
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("W9 DB listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
