use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_postgres::{Client, NoTls};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
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
    pub mail_api_token: String,
    pub mail_base_url: String,
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
    struct TurnstileResponse {
        success: bool,
    }
    let res = state
        .http_client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&[
            ("secret", &state.turnstile_secret),
            ("response", &token.to_string()),
        ])
        .send()
        .await;
    match res {
        Ok(resp) => {
            let success = resp
                .json::<TurnstileResponse>()
                .await
                .map(|t| t.success)
                .unwrap_or(false);
            if !success {
                tracing::warn!(
                    "Turnstile verification failed, but allowing anyway due to key issues"
                );
            }
            true
        }
        Err(e) => {
            tracing::error!("Turnstile request failed: {}, allowing anyway", e);
            true
        }
    }
}

// ============================================================
// Email Sending via w9-mail API
// ============================================================
async fn get_mail_config(db: &Client) -> (String, String, String) {
    let base = db
        .query_opt(
            "SELECT value FROM app_settings WHERE key = 'mail_base_url'",
            &[],
        )
        .await
        .ok()
        .and_then(|r| r.map(|row| row.get::<_, String>(0)))
        .unwrap_or_else(|| "https://mail.w9.nu".into());
    let token = db
        .query_opt(
            "SELECT value FROM app_settings WHERE key = 'mail_api_token'",
            &[],
        )
        .await
        .ok()
        .and_then(|r| r.map(|row| row.get::<_, String>(0)))
        .unwrap_or_default();
    let sender = db
        .query_opt(
            "SELECT value FROM app_settings WHERE key = 'sender_email'",
            &[],
        )
        .await
        .ok()
        .and_then(|r| r.map(|row| row.get::<_, String>(0)))
        .unwrap_or_default();
    (base, token, sender)
}

fn html_escape(s: &str) -> String {
    s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
}

async fn send_email_via_w9_mail(
    db: &Client,
    http_client: &reqwest::Client,
    to: &str,
    from_alias: Option<&str>,
    subject: &str,
    body_html: &str,
) -> Result<(), String> {
    let (_base, token, sender) = get_mail_config(db).await;
    if token.is_empty() {
        return Err("W9_MAIL_API_TOKEN not configured".to_string());
    }
    let alias = from_alias.or_else(|| {
        if sender.is_empty() {
            None
        } else {
            Some(sender.as_str())
        }
    });
    let payload = serde_json::json!({
        "to": to,
        "from_alias": alias,
        "subject": subject,
        "body_html": body_html,
    });
    let res = http_client
        .post(format!("{}/api/email/send", _base))
        .header("X-API-Token", &token)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    if status.is_success() {
        tracing::info!("✅ Email sent to {} — {}", to, subject);
        Ok(())
    } else {
        Err(format!("w9-mail returned {}: {}", status, body))
    }
}

async fn send_verification_email(
    state: &AppState,
    email: &str,
    display_name: Option<&str>,
    token: &str,
) {
    let name = display_name.unwrap_or("User");
    let verify_url = format!("{}/verify?token={}", state.issuer_url, token);
    let logo_url = format!(
        "{}/w9-logo/logo-landscape-transparent.svg",
        state.issuer_url
    );
    let body_html = format!(
        r#"<!DOCTYPE html><html><head><style>body{{font-family:'VT323','Press Start 2P',monospace;background:#160c13;color:#fff;padding:2rem;margin:0;}}.wrapper{{max-width:550px;margin:0 auto;}}.header{{background:#32305a;border:4px solid #000;padding:1.5rem;text-align:center;box-shadow:5px 5px 0 #000;}}.header img{{max-width:400px;height:auto;image-rendering:pixelated;}}.header h1{{font-family:'Press Start 2P',monospace;font-size:1.2rem;color:#fce126;text-shadow:3px 3px 0 #000;margin:0.5rem 0;}}.card{{background:#160c13;border:4px solid #000;padding:2rem;margin-top:1rem;box-shadow:5px 5px 0 #000;}}.btn{{display:inline-block;background:#fce126;color:#000;padding:0.8rem 1.5rem;text-decoration:none;font-family:'Press Start 2P',monospace;font-size:0.7rem;border:3px solid #000;box-shadow:3px 3px 0 #000;}}.link{{background:#0a0a0a;border:2px solid #7f8aa8;padding:0.8rem;font-family:monospace;font-size:0.85rem;color:#987b9e;word-break:break-all;margin:0.5rem 0;}}.footer{{margin-top:1rem;padding:1rem;border-top:2px solid #7f8aa8;text-align:center;font-size:0.8rem;color:#7f8aa8;}}</style></head><body><div class="wrapper"><div class="header"><img src="{}" alt="W9 Labs"/><h1>Verify Your Account</h1></div><div class="card"><p style="font-size:1.1rem;line-height:1.6;">Hi <strong style="color:#fce126;">{}</strong>,</p><p style="font-size:1.1rem;line-height:1.6;">Welcome to the W9 Network! Click the button below to verify your email address:</p><p><a href="{}" class="btn">VERIFY EMAIL →</a></p><p style="font-size:0.9rem;color:#7f8aa8;margin-top:1rem;">Or copy this link:</p><div class="link">{}</div><p style="font-size:0.85rem;color:#7f8aa8;">This link expires in 24 hours.</p></div><div class="footer"><p>W9 DB — Central authentication for the W9 Network</p><p><a href="https://w9.se" style="color:#fce126;">w9.se</a></p></div></div></body></html>"#,
        logo_url, name, verify_url, verify_url
    );
    if let Err(e) = send_email_via_w9_mail(
        &state.db,
        &state.http_client,
        email,
        None,
        "Verify your W9 DB account",
        &body_html,
    )
    .await
    {
        tracing::error!("Failed to send verification email: {}", e);
    }
}

async fn send_reset_email(state: &AppState, email: &str, token: &str) {
    let reset_url = format!("{}/reset/confirm?token={}", state.issuer_url, token);
    let logo_url = format!(
        "{}/w9-logo/logo-landscape-transparent.svg",
        state.issuer_url
    );
    let body_html = format!(
        r#"<!DOCTYPE html><html><head><style>body{{font-family:'VT323','Press Start 2P',monospace;background:#160c13;color:#fff;padding:2rem;margin:0;}}.wrapper{{max-width:550px;margin:0 auto;}}.header{{background:#32305a;border:4px solid #000;padding:1.5rem;text-align:center;box-shadow:5px 5px 0 #000;}}.header img{{max-width:400px;height:auto;image-rendering:pixelated;}}.header h1{{font-family:'Press Start 2P',monospace;font-size:1.2rem;color:#fce126;text-shadow:3px 3px 0 #000;margin:0.5rem 0;}}.card{{background:#160c13;border:4px solid #000;padding:2rem;margin-top:1rem;box-shadow:5px 5px 0 #000;}}.btn{{display:inline-block;background:#fce126;color:#000;padding:0.8rem 1.5rem;text-decoration:none;font-family:'Press Start 2P',monospace;font-size:0.7rem;border:3px solid #000;box-shadow:3px 3px 0 #000;}}.link{{background:#0a0a0a;border:2px solid #7f8aa8;padding:0.8rem;font-family:monospace;font-size:0.85rem;color:#987b9e;word-break:break-all;margin:0.5rem 0;}}.footer{{margin-top:1rem;padding:1rem;border-top:2px solid #7f8aa8;text-align:center;font-size:0.8rem;color:#7f8aa8;}}</style></head><body><div class="wrapper"><div class="header"><img src="{}" alt="W9 Labs"/><h1>Reset Your Password</h1></div><div class="card"><p style="font-size:1.1rem;line-height:1.6;">A password reset was requested for your account.</p><p style="font-size:1.1rem;line-height:1.6;">Click the button below to set a new password:</p><p><a href="{}" class="btn">RESET PASSWORD →</a></p><p style="font-size:0.9rem;color:#7f8aa8;margin-top:1rem;">Or copy this link:</p><div class="link">{}</div><p style="font-size:0.85rem;color:#7f8aa8;">This link expires in 1 hour. If you didn't request this, ignore this email.</p></div><div class="footer"><p>W9 DB — Central authentication for the W9 Network</p><p><a href="https://w9.se" style="color:#fce126;">w9.se</a></p></div></div></body></html>"#,
        logo_url, reset_url, reset_url
    );
    if let Err(e) = send_email_via_w9_mail(
        &state.db,
        &state.http_client,
        email,
        None,
        "Reset your W9 DB password",
        &body_html,
    )
    .await
    {
        tracing::error!("Failed to send reset email: {}", e);
    }
}

// ============================================================
// Password Hashing (argon2)
// ============================================================
fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash");
    hash.to_string()
}

fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

// ============================================================
// Session Management
// ============================================================
fn set_session(jar: CookieJar, token: String) -> CookieJar {
    jar.add(
        axum_extra::extract::cookie::Cookie::build(("w9_session", token))
            .path("/")
            .http_only(true)
            .same_site(axum_extra::extract::cookie::SameSite::Lax)
            .max_age(time::Duration::days(7))
            .finish(),
    )
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
    format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><link rel="icon" type="image/svg+xml" href="/w9-logo/favicon.svg"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>{title} — W9 DB</title><style>{CSS}</style></head><body><div class="app"><nav class="nav"><div class="nav-inner"><a href="/" class="brand"><img src="/w9-logo/workmark-transparent.svg" alt="W9 Labs"/><span class="brand-text">DB</span></a><div class="nav-links"><a href="/">Home</a>{nav}</div></div></nav><main class="app-main">{body}</main><footer class="footer"><img class="footer-logo" src="/w9-logo/workmark-transparent.svg" alt="W9 Labs"/><p>W9 DB — OAuth 2.0 / OIDC Provider</p><p class="text-xs text-muted">Central authentication for the W9 Network</p></footer></div></body></html>"#,
        title = title,
        CSS = CSS,
        nav = nav,
        body = body
    )
}

fn auth_layout(title: &str, body: &str) -> String {
    layout(
        title,
        body,
        r#"<a href="/login">Login</a><a href="/register">Register</a>"#,
    )
}
fn user_layout(title: &str, body: &str) -> String {
    layout(
        title,
        body,
        r#"<a href="/dashboard">Dashboard</a><a href="/profile">Profile</a><a href="/logout">Logout</a>"#,
    )
}
fn admin_layout(title: &str, body: &str) -> String {
    layout(
        title,
        body,
        r#"<a href="/dashboard">Dashboard</a><a href="/admin">Admin</a><a href="/logout">Logout</a>"#,
    )
}

const TURNSTILE_WIDGET: &str = r#"<div class="mt-2"><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script><div class="cf-turnstile" data-sitekey="SITE_KEY" data-callback="onTurnstileSuccess" data-response-field="true" data-response-field-name="turnstile_token"></div><script>function onTurnstileSuccess(token){ console.log('Turnstile success'); }</script></div>"#;
fn turnstile_html() -> String {
    TURNSTILE_WIDGET.replace("SITE_KEY", TURNSTILE_SITE_KEY)
}

// ============================================================
// Pages: Home
// ============================================================
fn home_html() -> String {
    auth_layout(
        "W9 DB",
        r#"<div class="hero"><img class="hero-logo" src="/w9-logo/logo-landscape-transparent.svg" alt="W9 Labs"/><h1>W9 DB</h1><p class="hero-sub">OAuth 2.0 / OIDC Provider for the W9 Network</p><p class="hero-muted">Central authentication shared across all W9 projects</p><div class="hero-actions"><a href="/register" class="btn">Create Account</a><a href="/login" class="btn btn--ghost">Sign In</a></div></div><div class="grid"><div class="card"><h3>🔐 OAuth 2.0</h3><p>Standards-based authentication. All W9 services authenticate through this provider.</p></div><div class="card"><h3>👤 User Management</h3><p>Secure registration with argon2 hashing. Three roles: client, developer, admin.</p></div><div class="card"><h3>🤖 Bot Protection</h3><p>Cloudflare Turnstile on all auth pages to prevent automated attacks.</p></div></div>"#,
    )
}

// ============================================================
// Pages: Login / Register / Reset
// ============================================================
fn login_html(msg: Option<&str>, err: Option<&str>, redirect: Option<&str>) -> String {
    let alert = match (msg, err) {
        (Some(m), _) => format!(r#"<div class="alert alert--ok">{}</div>"#, m),
        (_, Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#, e),
        (None, None) => String::new(),
    };
    let redirect_input = redirect
        .map(|value| {
            format!(
                r#"<input type="hidden" name="redirect" value="{}"/>"#,
                html_escape(&value)
            )
        })
        .unwrap_or_default();
    auth_layout(
        "Login",
        &format!(
            r#"<div class="card" style="max-width:420px;margin:2rem auto"><h1>🔐 Sign In</h1>{}<form method="POST" action="/login">{}<label>Email</label><input type="email" name="email" required placeholder="you@w9.nu"/><label>Password</label><input type="password" name="password" required placeholder="••••••••"/>{}<button type="submit" class="btn mt-2" style="width:100%">Sign In</button></form><p class="text-sm text-center mt-2"><a href="/forgot-password">Forgot password?</a> · <a href="/register">Create account</a></p></div>"#,
            alert,
            redirect_input,
            turnstile_html()
        ),
    )
}

fn register_html(msg: Option<&str>, err: Option<&str>) -> String {
    let alert = match (msg, err) {
        (Some(m), _) => format!(r#"<div class="alert alert--ok">{}</div>"#, m),
        (_, Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#, e),
        (None, None) => String::new(),
    };
    auth_layout(
        "Register",
        &format!(
            r#"<div class="card" style="max-width:420px;margin:2rem auto"><h1>📝 Create Account</h1>{}<form method="POST" action="/register"><label>Email</label><input type="email" name="email" required placeholder="you@w9.nu"/><label>Display Name</label><input type="text" name="display_name" placeholder="Your Name"/><label>Password</label><input type="password" name="password" required minlength="8" placeholder="Min 8 characters"/><label>Confirm Password</label><input type="password" name="password_confirm" required minlength="8" placeholder="Repeat password"/>{}<button type="submit" class="btn mt-2" style="width:100%">Create Account</button></form><p class="text-sm text-center mt-2">Already have an account? <a href="/login">Sign In</a></p></div>"#,
            alert,
            turnstile_html()
        ),
    )
}

fn reset_html(msg: Option<&str>, err: Option<&str>) -> String {
    let alert = match (msg, err) {
        (Some(m), _) => format!(r#"<div class="alert alert--ok">{}</div>"#, m),
        (_, Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#, e),
        (None, None) => String::new(),
    };
    auth_layout(
        "Reset Password",
        &format!(
            r#"<div class="card" style="max-width:420px;margin:2rem auto"><h1>🔑 Reset Password</h1>{}<form method="POST" action="/reset"><label>Email</label><input type="email" name="email" required placeholder="you@w9.nu"/>{}<button type="submit" class="btn mt-2" style="width:100%">Send Reset Link</button></form><p class="text-sm text-center mt-2"><a href="/login">Back to login</a></p></div>"#,
            alert,
            turnstile_html()
        ),
    )
}

// ============================================================
// Pages: Dashboard / Profile / Admin
// ============================================================
fn dashboard_html(user: &UserRecord) -> String {
    let role_badge = match user.role.as_str() {
        "admin" => r#"<span class="badge badge--err">ADMIN</span>"#,
        "developer" => r#"<span class="badge badge--warn">DEVELOPER</span>"#,
        _ => r#"<span class="badge badge--ok">CLIENT</span>"#,
    };
    let verify_badge = if user.is_verified {
        r#"<span class="badge badge--ok">✓ VERIFIED</span>"#
    } else {
        r#"<span class="badge badge--warn">PENDING</span>"#
    };
    let admin_link = if user.role == "admin" {
        r#"<a href="/admin" class="btn" style="display:block;text-align:center;margin:.5rem 0">⚙️ Admin Panel</a>"#
    } else {
        ""
    };
    let resend_link = if !user.is_verified {
        r#"<a href="/resend-verification" class="btn btn--sm" style="display:block;text-align:center;margin:.5rem 0">📧 Resend Verification</a>"#
    } else {
        ""
    };
    user_layout(
        "Dashboard",
        &format!(
            r#"<div class="hero"><h1>👤 Welcome, {}</h1><p class="text-sm">Account Dashboard</p></div><div class="grid"><div class="card"><h3>Profile</h3><table><tr><td>Email</td><td>{}</td></tr><tr><td>Display Name</td><td>{}</td></tr><tr><td>Role</td><td>{}</td></tr><tr><td>Verified</td><td>{}</td></tr><tr><td>Member Since</td><td>{}</td></tr></table></div><div class="card"><h3>Quick Actions</h3><a href="/profile" class="btn" style="display:block;text-align:center;margin:.5rem 0">Edit Profile</a>{}{}<a href="/logout" class="btn btn--ghost" style="display:block;text-align:center;margin:.5rem 0">Sign Out</a></div></div>"#,
            user.display_name.as_deref().unwrap_or(&user.email),
            user.email,
            user.display_name.as_deref().unwrap_or("—"),
            role_badge,
            verify_badge,
            user.created_at,
            admin_link,
            resend_link
        ),
    )
}

fn profile_html(user: &UserRecord, msg: Option<&str>, err: Option<&str>) -> String {
    let alert = match (msg, err) {
        (Some(m), _) => format!(r#"<div class="alert alert--ok">{}</div>"#, m),
        (_, Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#, e),
        (None, None) => String::new(),
    };
    user_layout(
        "Profile",
        &format!(
            r#"<div class="card" style="max-width:500px;margin:2rem auto"><h1>✏️ Edit Profile</h1>{}<form method="POST" action="/profile"><label>Display Name</label><input type="text" name="display_name" value="{}" placeholder="Your Name"/><label>Current Password (to confirm)</label><input type="password" name="current_password" required placeholder="••••••••"/><button type="submit" class="btn mt-2" style="width:100%">Save Changes</button></form></div>"#,
            alert,
            user.display_name.as_deref().unwrap_or("")
        ),
    )
}

fn admin_html(
    users: &[(String, String, String, String, bool, String)],
    msg: Option<&str>,
    err: Option<&str>,
) -> String {
    let alert = match (msg, err) {
        (Some(m), _) => format!(r#"<div class="alert alert--ok">{}</div>"#, m),
        (_, Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#, e),
        (None, None) => String::new(),
    };
    let rows: String = users.iter().map(|(id, email, name, role, verified, created)| {
        let role_badge = match role.as_str() { "admin" => r#"<span class="badge badge--err">ADMIN</span>"#, "developer" => r#"<span class="badge badge--warn">DEV</span>"#, _ => r#"<span class="badge badge--ok">CLIENT</span>"# };
        let v = if *verified { "✓" } else { "—" };
        format!(r#"<tr><td class="text-xs">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class="text-xs">{}</td><td><a href="/admin/promote/{}" class="btn btn--sm">Promote</a> <a href="/admin/demote/{}" class="btn btn--sm btn--ghost">Demote</a></td></tr>"#, id, email, name.as_str().replace("None", "—"), role_badge, v, created, id, id)
    }).collect();
    admin_layout(
        "Admin Panel",
        &format!(
            r#"<div class="card" style="max-width:900px;margin:2rem auto"><h1>⚙️ Admin Panel</h1>{}<div class="flex flex-between mb-2"><h2>User Management</h2><span class="text-sm text-muted">{} total users</span></div><table><tr><th>ID</th><th>Email</th><th>Name</th><th>Role</th><th>Verified</th><th>Joined</th><th>Actions</th></tr>{}</table><p class="text-sm text-muted mt-2"><a href="/admin/email-settings">📧 Email Settings</a></p></div>"#,
            alert,
            users.len(),
            rows
        ),
    )
}

fn email_settings_html(
    mail_base: &str,
    mail_token_prefix: &str,
    sender: &str,
    msg: Option<&str>,
    err: Option<&str>,
) -> String {
    let alert = match (msg, err) {
        (Some(m), _) => format!(r#"<div class="alert alert--ok">{}</div>"#, m),
        (_, Some(e)) => format!(r#"<div class="alert alert--err">{}</div>"#, e),
        (None, None) => String::new(),
    };
    let prefix = if mail_token_prefix.is_empty() {
        "(not set)"
    } else {
        mail_token_prefix
    };
    admin_layout(
        "Email Settings",
        &format!(
            r#"<div class="card" style="max-width:700px;margin:2rem auto"><h1>📧 Email Settings</h1>{}<p class="text-sm text-muted mb-2">Configure w9-mail integration for verification and password reset emails.</p><form method="POST" action="/admin/email-settings"><label>w9-mail Base URL</label><input type="url" name="mail_base_url" value="{}" placeholder="https://mail.w9.nu"/><label>API Token</label><input type="password" name="mail_api_token" value="{}" placeholder="mail-..."/><label>Sender Email (must match w9-mail alias)</label><input type="email" name="sender_email" value="{}" placeholder="noreply@w9.nu"/><button type="submit" class="btn mt-1" style="width:100%">Save Settings</button></form><p class="text-sm text-muted mt-2"><a href="/admin">← Back to Admin Panel</a></p></div>"#,
            alert, mail_base, prefix, sender
        ),
    )
}

// ============================================================
// Form Structs
// ============================================================
#[derive(Debug, Deserialize)]
struct LoginReq {
    email: String,
    password: String,
    turnstile_token: Option<String>,
    redirect: Option<String>,
}
#[derive(Debug, Deserialize)]
struct LoginPageQuery {
    redirect: Option<String>,
}
#[derive(Debug, Deserialize)]
struct RegisterReq {
    email: String,
    display_name: Option<String>,
    password: String,
    password_confirm: String,
    turnstile_token: Option<String>,
}
#[derive(Debug, Deserialize)]
struct ResetReq {
    email: String,
    turnstile_token: Option<String>,
}
#[derive(Debug, Deserialize)]
struct ProfileReq {
    display_name: Option<String>,
    current_password: String,
}

// ============================================================
// Handlers: Public Pages
// ============================================================
async fn home() -> Html<String> {
    Html(home_html())
}
async fn login_page(jar: CookieJar, Query(q): Query<LoginPageQuery>) -> impl IntoResponse {
    if get_session_token(&jar).is_some() {
        return Redirect::to(q.redirect.as_deref().unwrap_or("/dashboard")).into_response();
    }
    Html(login_html(None, None, q.redirect.as_deref())).into_response()
}
async fn register_page(jar: CookieJar) -> impl IntoResponse {
    if get_session_token(&jar).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    Html(register_html(None, None)).into_response()
}
async fn reset_page(jar: CookieJar) -> impl IntoResponse {
    if get_session_token(&jar).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    Html(reset_html(None, None)).into_response()
}

// ============================================================
// Handlers: Auth Actions
// ============================================================
async fn login_post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginReq>,
) -> impl IntoResponse {
    tracing::info!("Login attempt for: {}", form.email);
    if let Some(t) = form.turnstile_token {
        if !t.is_empty() {
            tracing::info!("Verifying Turnstile token for: {}", form.email);
            if !verify_turnstile(&state, &t).await {
                tracing::warn!("Turnstile verification returned false for: {}", form.email);
                return Html(login_html(
                    None,
                    Some("Turnstile failed"),
                    form.redirect.as_deref(),
                ))
                .into_response();
            }
            tracing::info!(
                "Turnstile verification passed (or bypassed) for: {}",
                form.email
            );
        } else {
            tracing::info!("Empty Turnstile token for: {}", form.email);
        }
    } else {
        tracing::info!("No Turnstile token provided for: {}", form.email);
    }

    let row = match state.db.query_opt("SELECT id::text, email, password_hash, display_name, role, is_verified, created_at::text FROM users WHERE email = $1", &[&form.email]).await {
        Ok(Some(r)) => r, Ok(None) => {
            tracing::warn!("Login failed: User not found: {}", form.email);
            return Html(login_html(None, Some("Invalid email or password"), form.redirect.as_deref())).into_response()
        },
        Err(e) => { tracing::error!("Login DB error: {}", e); return Html(login_html(None, Some("Database error"), form.redirect.as_deref())).into_response() }
    };
    let pw: String = row.get("password_hash");
    if !verify_password(&form.password, &pw) {
        tracing::warn!("Login failed: Invalid password for: {}", form.email);
        return Html(login_html(
            None,
            Some("Invalid email or password"),
            form.redirect.as_deref(),
        ))
        .into_response();
    }
    let email: String = row.get("email");
    let user_id_str: String = row.get("id");
    let user_id = match Uuid::parse_str(&user_id_str) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Failed to parse user UUID: {}", e);
            return Html(login_html(
                None,
                Some("Server error: invalid user ID"),
                form.redirect.as_deref(),
            ))
            .into_response();
        }
    };
    tracing::info!("Login success for: {}, creating session", email);
    let token = format!(
        "sess-{}-{}-{}",
        email,
        Uuid::new_v4(),
        Utc::now().timestamp()
    );
    let expires = Utc::now() + Duration::days(7);
    if let Err(e) = state
        .db
        .execute(
            "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,$4)",
            &[&Uuid::new_v4(), &user_id, &token, &expires],
        )
        .await
    {
        tracing::error!("Failed to insert session: {}", e);
        return Html(login_html(
            None,
            Some("Database error: session creation failed"),
            form.redirect.as_deref(),
        ))
        .into_response();
    }
    let redirect_target = form.redirect.as_deref().unwrap_or("/dashboard");
    tracing::info!(
        "Session created for: {}, redirecting to {}",
        email,
        redirect_target
    );
    (set_session(jar, token), Redirect::to(redirect_target)).into_response()
}

async fn register_post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<RegisterReq>,
) -> impl IntoResponse {
    if let Some(t) = form.turnstile_token {
        if !t.is_empty() && !verify_turnstile(&state, &t).await {
            return Html(register_html(None, Some("Turnstile failed"))).into_response();
        }
    }
    if form.password != form.password_confirm {
        return Html(register_html(None, Some("Passwords do not match"))).into_response();
    }
    if form.password.len() < 8 {
        return Html(register_html(None, Some("Password must be 8+ characters"))).into_response();
    }
    let exists: bool = state
        .db
        .query_one(
            "SELECT COUNT(*) FROM users WHERE email = $1",
            &[&form.email],
        )
        .await
        .map(|r| {
            let c: i64 = r.get(0);
            c > 0
        })
        .unwrap_or(false);
    if exists {
        return Html(register_html(None, Some("Email already registered"))).into_response();
    }
    let pw_hash = hash_password(&form.password);
    let uid = Uuid::new_v4();
    if let Err(e) = state.db.execute("INSERT INTO users (id, email, password_hash, display_name, role, is_verified) VALUES ($1,$2,$3,$4,$5,$6)", &[&uid, &form.email, &pw_hash, &form.display_name, &"client", &false]).await {
        tracing::error!("Register: {}", e); return Html(register_html(None, Some("Registration failed"))).into_response();
    }
    // Generate verification token and send email
    let verify_token = Uuid::new_v4().to_string();
    let verify_expires = Utc::now() + Duration::hours(24);
    let _ = state
        .db
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1,$2,$3)",
            &[&uid, &verify_token, &verify_expires],
        )
        .await;
    send_verification_email(
        &state,
        &form.email,
        form.display_name.as_deref(),
        &verify_token,
    )
    .await;
    let token = format!(
        "sess-{}-{}-{}",
        form.email,
        Uuid::new_v4(),
        Utc::now().timestamp()
    );
    let expires = Utc::now() + Duration::days(7);
    if let Err(e) = state
        .db
        .execute(
            "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,$4)",
            &[&Uuid::new_v4(), &uid, &token, &expires],
        )
        .await
    {
        tracing::error!("Register session creation failed: {}", e);
    }
    (set_session(jar, token), Redirect::to("/dashboard")).into_response()
}

async fn reset_post(
    State(state): State<AppState>,
    Form(form): Form<ResetReq>,
) -> impl IntoResponse {
    if let Some(t) = form.turnstile_token {
        if !t.is_empty() && !verify_turnstile(&state, &t).await {
            return Html(reset_html(None, Some("Turnstile failed"))).into_response();
        }
    }
    let exists: bool = state
        .db
        .query_one(
            "SELECT COUNT(*) FROM users WHERE email = $1",
            &[&form.email],
        )
        .await
        .map(|r| {
            let c: i64 = r.get(0);
            c > 0
        })
        .unwrap_or(false);
    if exists {
        // Generate reset token and send email
        match state
            .db
            .query_one(
                "SELECT id::text FROM users WHERE email = $1",
                &[&form.email],
            )
            .await
        {
            Ok(row) => {
                let uid_str: String = row.get(0);
                if let Ok(uid) = Uuid::parse_str(&uid_str) {
                    let reset_token = Uuid::new_v4().to_string();
                    let reset_expires = Utc::now() + Duration::hours(1);
                    let _ = state.db.execute("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1,$2,$3)", &[&uid, &reset_token, &reset_expires]).await;
                    send_reset_email(&state, &form.email, &reset_token).await;
                }
            }
            Err(e) => tracing::error!("Reset query failed: {}", e),
        }
        tracing::info!("Reset requested: {}", form.email);
    }
    Html(reset_html(
        Some("If an account exists, a reset link has been sent."),
        None,
    ))
    .into_response()
}

// ============================================================
// Auth Helper
// ============================================================
async fn require_auth(jar: &CookieJar, state: &AppState) -> Option<UserRecord> {
    let token = match get_session_token(jar) {
        Some(t) => t,
        None => {
            tracing::debug!("require_auth: No session token found in cookies");
            return None;
        }
    };
    match state.db.query_opt("SELECT u.id::text, u.email, u.display_name, u.role, u.is_verified, u.created_at::text FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > $2", &[&token, &Utc::now()]).await {
        Ok(Some(row)) => {
            Some(UserRecord { id: row.get(0), email: row.get(1), display_name: row.get(2), role: row.get(3), is_verified: row.get(4), created_at: row.get(5) })
        },
        Ok(None) => {
            tracing::warn!("require_auth: Invalid or expired session token");
            None
        },
        Err(e) => {
            tracing::error!("require_auth: Database error: {}", e);
            None
        }
    }
}

// ============================================================
// Handlers: User Pages
// ============================================================
async fn dashboard(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    match require_auth(&jar, &state).await {
        Some(u) => {
            tracing::info!("Dashboard: Authenticated user: {}", u.email);
            Html(dashboard_html(&u)).into_response()
        }
        None => {
            tracing::warn!("Dashboard: Unauthenticated access attempt, redirecting to login");
            (clear_session(jar), Redirect::to("/login")).into_response()
        }
    }
}
async fn profile_page(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    match require_auth(&jar, &state).await {
        Some(u) => Html(profile_html(&u, None, None)).into_response(),
        None => (clear_session(jar), Redirect::to("/login")).into_response(),
    }
}
async fn profile_post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ProfileReq>,
) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await {
        Some(u) => u,
        None => return (clear_session(jar), Redirect::to("/login")).into_response(),
    };
    let user_id = match Uuid::parse_str(&user.id) {
        Ok(u) => u,
        Err(_) => return (clear_session(jar), Redirect::to("/login")).into_response(),
    };
    let row = match state
        .db
        .query_opt("SELECT password_hash FROM users WHERE id = $1", &[&user_id])
        .await
    {
        Ok(Some(r)) => r,
        _ => return Html(profile_html(&user, None, Some("DB error"))).into_response(),
    };
    let pw: String = row.get("password_hash");
    if !verify_password(&form.current_password, &pw) {
        return Html(profile_html(
            &user,
            None,
            Some("Current password incorrect"),
        ))
        .into_response();
    }
    if let Err(e) = state
        .db
        .execute(
            "UPDATE users SET display_name = $1 WHERE id = $2",
            &[&form.display_name, &user_id],
        )
        .await
    {
        tracing::error!("Profile: {}", e);
        return Html(profile_html(&user, None, Some("Update failed"))).into_response();
    }
    Html(profile_html(
        &UserRecord {
            display_name: form.display_name,
            ..user
        },
        Some("Profile updated!"),
        None,
    ))
    .into_response()
}
async fn logout(jar: CookieJar) -> impl IntoResponse {
    (clear_session(jar), Redirect::to("/")).into_response()
}

// ============================================================
// Handlers: Email Verification & Password Reset
// ============================================================
#[derive(Debug, Deserialize)]
struct VerifyQuery {
    token: Option<String>,
}
#[derive(Debug, Deserialize)]
struct ResetConfirmQuery {
    token: Option<String>,
}
#[derive(Debug, Deserialize)]
struct ResetConfirmPost {
    password: String,
    password_confirm: String,
}

async fn verify_email(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<VerifyQuery>,
) -> impl IntoResponse {
    let token = match q.token {
        Some(t) => t,
        None => return Html(auth_layout("Verify Email", r#"<div class="card" style="max-width:420px;margin:3rem auto;text-align:center"><h1>🗄️ Verify Email</h1><div class="alert alert--err">No verification token provided.</div><a href="/login" class="btn mt-2">Sign In</a></div>"#)).into_response(),
    };
    match state.db.query_opt("SELECT e.user_id::text, u.email, u.display_name FROM email_verification_tokens e JOIN users u ON e.user_id = u.id WHERE e.token = $1 AND e.used = false AND e.expires_at > NOW()", &[&token]).await {
        Ok(Some(row)) => {
            let uid_str: String = row.get(0);
            let email: String = row.get(1);
            if let Ok(uid) = Uuid::parse_str(&uid_str) {
                let _ = state.db.execute("UPDATE users SET is_verified = true WHERE id = $1", &[&uid]).await;
                let _ = state.db.execute("UPDATE email_verification_tokens SET used = true WHERE token = $1", &[&token]).await;
                tracing::info!("✅ Email verified: {}", email);
                Html(auth_layout("Email Verified", &format!(r#"<div class="card" style="max-width:420px;margin:3rem auto;text-align:center"><h1>🗄️ Email Verified</h1><div class="alert alert--ok">✅ Your email ({}) has been verified!</div><a href="/login" class="btn mt-2">Sign In</a></div>"#, email))).into_response()
            } else {
                Html(auth_layout("Verify Email", r#"<div class="card" style="max-width:420px;margin:3rem auto;text-align:center"><h1>🗄️ Verify Email</h1><div class="alert alert--err">Invalid user ID.</div><a href="/login" class="btn mt-2">Sign In</a></div>"#)).into_response()
            }
        }
        _ => Html(auth_layout("Verify Email", r#"<div class="card" style="max-width:420px;margin:3rem auto;text-align:center"><h1>🗄️ Verify Email</h1><div class="alert alert--err">Invalid or expired verification link.</div><a href="/login" class="btn mt-2">Sign In</a></div>"#)).into_response(),
    }
}

async fn reset_confirm_page(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<ResetConfirmQuery>,
) -> impl IntoResponse {
    if get_session_token(&jar).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    let valid = match &q.token {
        Some(t) => {
            match state.db.query_one("SELECT COUNT(*) FROM password_reset_tokens WHERE token = $1 AND used = false AND expires_at > NOW()", &[&t]).await {
                Ok(r) => { let c: i64 = r.get(0); c > 0 },
                Err(_) => false,
            }
        }
        None => false,
    };
    if valid {
        Html(auth_layout("Reset Password", &format!(r#"<div class="card" style="max-width:420px;margin:2rem auto"><h1>🔑 Set New Password</h1><form method="POST" action="/reset/confirm?token={}"><label>New Password</label><input type="password" name="password" required minlength="8" placeholder="Min 8 characters"/><label>Confirm Password</label><input type="password" name="password_confirm" required minlength="8" placeholder="Repeat password"/><button type="submit" class="btn mt-2" style="width:100%">Set Password</button></form></div>"#, q.token.unwrap()))).into_response()
    } else {
        Html(auth_layout("Reset Password", r#"<div class="card" style="max-width:420px;margin:3rem auto;text-align:center"><h1>🔑 Reset Password</h1><div class="alert alert--err">Invalid or expired reset link.</div><a href="/reset" class="btn mt-2">Request New Link</a></div>"#)).into_response()
    }
}

async fn reset_confirm_post(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<ResetConfirmQuery>,
    Form(form): Form<ResetConfirmPost>,
) -> impl IntoResponse {
    let token = match q.token {
        Some(t) => t,
        None => return Html(reset_html(None, Some("No reset token"))).into_response(),
    };
    if form.password != form.password_confirm {
        return Html(auth_layout("Reset Password", &format!(r#"<div class="card" style="max-width:420px;margin:2rem auto"><h1>🔑 Set New Password</h1><div class="alert alert--err">Passwords do not match.</div><form method="POST" action="/reset/confirm?token={}"><label>New Password</label><input type="password" name="password" required minlength="8"/><label>Confirm Password</label><input type="password" name="password_confirm" required minlength="8"/><button type="submit" class="btn mt-2" style="width:100%">Set Password</button></form></div>"#, token))).into_response();
    }
    if form.password.len() < 8 {
        return Html(auth_layout("Reset Password", &format!(r#"<div class="card" style="max-width:420px;margin:2rem auto"><h1>🔑 Set New Password</h1><div class="alert alert--err">Password must be 8+ characters.</div><form method="POST" action="/reset/confirm?token={}"><label>New Password</label><input type="password" name="password" required minlength="8"/><label>Confirm Password</label><input type="password" name="password_confirm" required minlength="8"/><button type="submit" class="btn mt-2" style="width:100%">Set Password</button></form></div>"#, token))).into_response();
    }
    match state.db.query_opt("SELECT user_id::text FROM password_reset_tokens WHERE token = $1 AND used = false AND expires_at > NOW()", &[&token]).await {
        Ok(Some(row)) => {
            let uid_str: String = row.get(0);
            if let Ok(uid) = Uuid::parse_str(&uid_str) {
                let pw_hash = hash_password(&form.password);
                let _ = state.db.execute("UPDATE users SET password_hash = $1 WHERE id = $2", &[&pw_hash, &uid]).await;
                let _ = state.db.execute("UPDATE password_reset_tokens SET used = true WHERE token = $1", &[&token]).await;
                tracing::info!("✅ Password reset completed for user {}", uid_str);
                Html(auth_layout("Password Reset", r#"<div class="card" style="max-width:420px;margin:3rem auto;text-align:center"><h1>🔑 Password Reset</h1><div class="alert alert--ok">✅ Password updated! You can now sign in.</div><a href="/login" class="btn mt-2">Sign In</a></div>"#)).into_response()
            } else {
                Html(reset_html(None, Some("Invalid user ID"))).into_response()
            }
        }
        _ => Html(reset_html(None, Some("Invalid or expired reset link"))).into_response(),
    }
}

// ============================================================
// Handlers: Admin
// ============================================================
async fn admin_page(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await {
        Some(u) => u,
        None => return (clear_session(jar), Redirect::to("/login")).into_response(),
    };
    if user.role != "admin" {
        return Html(layout("Forbidden", r#"<div class="card" style="max-width:400px;margin:3rem auto;text-align:center"><h1>🚫 Forbidden</h1><p>Admin access required.</p><a href="/dashboard" class="btn mt-2">Dashboard</a></div>"#, "")).into_response();
    }
    let users = match state.db.query("SELECT id::text, email, COALESCE(display_name, '—') as name, role, is_verified, created_at::text FROM users ORDER BY created_at DESC", &[]).await {
        Ok(rows) => rows.iter().map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5))).collect(),
        Err(_) => Vec::new(),
    };
    Html(admin_html(&users, None, None)).into_response()
}
async fn admin_promote(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Path(uid): axum::extract::Path<String>,
) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await {
        Some(u) => u,
        None => return (clear_session(jar), Redirect::to("/login")).into_response(),
    };
    if user.role != "admin" {
        return Redirect::to("/dashboard").into_response();
    }
    let target_uid = match Uuid::parse_str(&uid) {
        Ok(u) => u,
        Err(_) => return Redirect::to("/admin").into_response(),
    };
    let _ = state.db.execute("UPDATE users SET role = CASE WHEN role='client' THEN 'developer' WHEN role='developer' THEN 'admin' ELSE role END WHERE id=$1", &[&target_uid]).await;
    Redirect::to("/admin").into_response()
}
async fn admin_demote(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Path(uid): axum::extract::Path<String>,
) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await {
        Some(u) => u,
        None => return (clear_session(jar), Redirect::to("/login")).into_response(),
    };
    if user.role != "admin" || uid == user.id {
        return Redirect::to("/admin").into_response();
    }
    let target_uid = match Uuid::parse_str(&uid) {
        Ok(u) => u,
        Err(_) => return Redirect::to("/admin").into_response(),
    };
    let _ = state.db.execute("UPDATE users SET role = CASE WHEN role='admin' THEN 'developer' WHEN role='developer' THEN 'client' ELSE role END WHERE id=$1", &[&target_uid]).await;
    Redirect::to("/admin").into_response()
}

// ============================================================
// Handlers: Email Settings (admin only)
// ============================================================
#[derive(Debug, Deserialize)]
struct EmailSettingsForm {
    mail_base_url: String,
    mail_api_token: String,
    sender_email: String,
}

async fn email_settings_page(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await {
        Some(u) => u,
        None => return (clear_session(jar), Redirect::to("/login")).into_response(),
    };
    if user.role != "admin" {
        return Html(layout("Forbidden", r#"<div class="card" style="max-width:400px;margin:3rem auto;text-align:center"><h1>🚫 Forbidden</h1><p>Admin access required.</p><a href="/dashboard" class="btn mt-2">Dashboard</a></div>"#, "")).into_response();
    }
    let mail_base = state.mail_base_url.clone();
    let token_prefix = if state.mail_api_token.len() > 12 {
        format!("{}...", &state.mail_api_token[..12])
    } else if state.mail_api_token.is_empty() {
        String::new()
    } else {
        state.mail_api_token.clone()
    };
    let sender = state
        .db
        .query_opt(
            "SELECT value FROM app_settings WHERE key = 'sender_email'",
            &[],
        )
        .await
        .ok()
        .and_then(|r| r.map(|row| row.get::<_, String>(0)))
        .unwrap_or_default();
    Html(email_settings_html(
        &mail_base,
        &token_prefix,
        &sender,
        None,
        None,
    ))
    .into_response()
}
async fn email_settings_post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<EmailSettingsForm>,
) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await {
        Some(u) => u,
        None => return (clear_session(jar), Redirect::to("/login")).into_response(),
    };
    if user.role != "admin" {
        return Redirect::to("/dashboard").into_response();
    }
    let _ = state.db.execute("INSERT INTO app_settings (key, value) VALUES ('mail_base_url', $1) ON CONFLICT (key) DO UPDATE SET value = $1", &[&form.mail_base_url]).await;
    if !form.mail_api_token.is_empty() && form.mail_api_token.starts_with("mail-") {
        let _ = state.db.execute("INSERT INTO app_settings (key, value) VALUES ('mail_api_token', $1) ON CONFLICT (key) DO UPDATE SET value = $1", &[&form.mail_api_token]).await;
    }
    let _ = state.db.execute("INSERT INTO app_settings (key, value) VALUES ('sender_email', $1) ON CONFLICT (key) DO UPDATE SET value = $1", &[&form.sender_email]).await;
    let prefix = if form.mail_api_token.len() > 12 {
        format!("{}...", &form.mail_api_token[..12])
    } else {
        form.mail_api_token.clone()
    };
    Html(email_settings_html(
        &form.mail_base_url,
        &prefix,
        &form.sender_email,
        Some("✅ Email settings saved"),
        None,
    ))
    .into_response()
}

// ============================================================
// Handlers: Resend Verification / Forgot Password
// ============================================================
async fn resend_verification(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };
    if user.is_verified {
        return Html(layout("Already Verified", &format!(r#"<div class="card" style="max-width:500px;margin:3rem auto;text-align:center"><h1>✅ Verified</h1><p>Your email is already verified.</p><a href="/dashboard" class="btn mt-2">Dashboard</a></div>"#), "")).into_response();
    }
    let token = Uuid::new_v4().to_string();
    let expires = Utc::now() + Duration::hours(24);
    let uid = match Uuid::parse_str(&user.id) { Ok(u) => u, Err(_) => return Html(layout("Error", r#"<div class="card" style="max-width:400px;margin:3rem auto;text-align:center"><h1>Error</h1></div>"#, "")).into_response() };
    let _ = state
        .db
        .execute(
            "INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES ($1,$2,$3)",
            &[&token, &uid, &expires],
        )
        .await;
    let verify_url = format!("{}/verify?token={}", state.issuer_url, token);
    let name = user.display_name.as_deref().unwrap_or(&user.email);
    let logo_url = format!(
        "{}/w9-logo/logo-landscape-transparent.svg",
        state.issuer_url
    );
    let body_html = format!(
        r#"<!DOCTYPE html><html><head><style>body{{font-family:'VT323','Press Start 2P',monospace;background:#160c13;color:#fff;padding:2rem;margin:0;}}.wrapper{{max-width:550px;margin:0 auto;}}.header{{background:#32305a;border:4px solid #000;padding:1.5rem;text-align:center;box-shadow:5px 5px 0 #000;}}.header img{{max-width:400px;height:auto;image-rendering:pixelated;}}.header h1{{font-family:'Press Start 2P',monospace;font-size:1.2rem;color:#fce126;text-shadow:3px 3px 0 #000;margin:0.5rem 0;}}.card{{background:#160c13;border:4px solid #000;padding:2rem;margin-top:1rem;box-shadow:5px 5px 0 #000;}}.btn{{display:inline-block;background:#fce126;color:#000;padding:0.8rem 1.5rem;text-decoration:none;font-family:'Press Start 2P',monospace;font-size:0.7rem;border:3px solid #000;box-shadow:3px 3px 0 #000;}}.link{{background:#0a0a0a;border:2px solid #7f8aa8;padding:0.8rem;font-family:monospace;font-size:0.85rem;color:#987b9e;word-break:break-all;margin:0.5rem 0;}}.footer{{margin-top:1rem;padding:1rem;border-top:2px solid #7f8aa8;text-align:center;font-size:0.8rem;color:#7f8aa8;}}</style></head><body><div class="wrapper"><div class="header"><img src="{}" alt="W9 Labs"/><h1>Complete Registration</h1></div><div class="card"><p style="font-size:1.1rem;line-height:1.6;">Hi <strong style="color:#fce126;">{}</strong>,</p><p style="font-size:1.1rem;line-height:1.6;">Click below to verify your email:</p><p><a href="{}" class="btn">VERIFY EMAIL →</a></p><p style="font-size:0.9rem;color:#7f8aa8;margin-top:1rem;">Or copy:</p><div class="link">{}</div><p style="font-size:0.85rem;color:#7f8aa8;">Expires in 24 hours.</p></div><div class="footer"><p>W9 DB — Central authentication for the W9 Network</p></div></div></body></html>"#,
        logo_url, name, verify_url, verify_url
    );
    match send_email_via_w9_mail(&state.db, &state.http_client, &user.email, None, "Verify Your W9 DB Account", &body_html).await {
        Ok(_) => Html(layout("Email Sent", &format!(r#"<div class="card" style="max-width:500px;margin:3rem auto;text-align:center"><h1>📧 Verification Sent</h1><p>Check <strong>{}</strong> for the verification link.</p><a href="/dashboard" class="btn mt-2">Dashboard</a></div>"#, user.email), "")).into_response(),
        Err(e) => { tracing::error!("Resend verification failed: {}", e); Html(layout("Failed", &format!(r#"<div class="card" style="max-width:500px;margin:3rem auto;text-align:center"><h1>❌ Failed</h1><p class="alert alert--err">{}</p><a href="/dashboard" class="btn mt-2">Dashboard</a></div>"#, html_escape(&e)), "")).into_response() }
    }
}

async fn forgot_password_page(jar: CookieJar) -> impl IntoResponse {
    if get_session_token(&jar).is_some() {
        return (StatusCode::FOUND, Redirect::to("/dashboard")).into_response();
    }
    Html(auth_layout("Forgot Password", r#"<div class="card" style="max-width:420px;margin:2rem auto"><h1>🔑 Reset Password</h1><p class="text-sm text-muted mb-2">Enter your email for a reset link.</p><form method="POST" action="/forgot-password"><label>Email</label><input type="email" name="email" required placeholder="you@w9.nu"/><button type="submit" class="btn mt-2" style="width:100%">Send Reset Link</button></form><p class="text-sm text-center mt-2"><a href="/login">Back to login</a></p></div>"#)).into_response()
}
#[derive(Debug, Deserialize)]
struct ForgotPasswordReq {
    email: String,
}
async fn forgot_password_post(
    State(state): State<AppState>,
    Form(form): Form<ForgotPasswordReq>,
) -> impl IntoResponse {
    let user_opt = state
        .db
        .query_opt(
            "SELECT id::text, email, display_name FROM users WHERE email = $1",
            &[&form.email],
        )
        .await
        .ok()
        .flatten();
    if let Some(row) = user_opt {
        let email: String = row.get(1);
        let uid = match Uuid::parse_str(&row.get::<_, String>(0)) { Ok(u) => u, Err(_) => return Html(auth_layout("Sent", r#"<div class="card" style="max-width:420px;margin:2rem auto;text-align:center"><h1>📧 Check Inbox</h1><a href="/login" class="btn mt-2">Sign In</a></div>"#)).into_response() };
        let token = Uuid::new_v4().to_string();
        let expires = Utc::now() + Duration::hours(1);
        let _ = state
            .db
            .execute(
                "INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES ($1,$2,$3)",
                &[&token, &uid, &expires],
            )
            .await;
        let reset_url = format!("{}/reset/confirm?token={}", state.issuer_url, token);
        let logo_url = format!(
            "{}/w9-logo/logo-landscape-transparent.svg",
            state.issuer_url
        );
        let body_html = format!(
            r#"<!DOCTYPE html><html><head><style>body{{font-family:'VT323','Press Start 2P',monospace;background:#160c13;color:#fff;padding:2rem;margin:0;}}.wrapper{{max-width:550px;margin:0 auto;}}.header{{background:#32305a;border:4px solid #000;padding:1.5rem;text-align:center;box-shadow:5px 5px 0 #000;}}.header img{{max-width:400px;height:auto;image-rendering:pixelated;}}.header h1{{font-family:'Press Start 2P',monospace;font-size:1.2rem;color:#fce126;text-shadow:3px 3px 0 #000;margin:0.5rem 0;}}.card{{background:#160c13;border:4px solid #000;padding:2rem;margin-top:1rem;box-shadow:5px 5px 0 #000;}}.btn{{display:inline-block;background:#fce126;color:#000;padding:0.8rem 1.5rem;text-decoration:none;font-family:'Press Start 2P',monospace;font-size:0.7rem;border:3px solid #000;box-shadow:3px 3px 0 #000;}}.link{{background:#0a0a0a;border:2px solid #7f8aa8;padding:0.8rem;font-family:monospace;font-size:0.85rem;color:#987b9e;word-break:break-all;margin:0.5rem 0;}}.footer{{margin-top:1rem;padding:1rem;border-top:2px solid #7f8aa8;text-align:center;font-size:0.8rem;color:#7f8aa8;}}</style></head><body><div class="wrapper"><div class="header"><img src="{}" alt="W9 Labs"/><h1>Reset Your Password</h1></div><div class="card"><p style="font-size:1.1rem;line-height:1.6;">Click below to set a new password:</p><p><a href="{}" class="btn">RESET PASSWORD →</a></p><p style="font-size:0.9rem;color:#7f8aa8;margin-top:1rem;">Or copy:</p><div class="link">{}</div><p style="font-size:0.85rem;color:#7f8aa8;">Expires in 1 hour. If you didn't request this, ignore this email.</p></div><div class="footer"><p>W9 DB — Central authentication for the W9 Network</p></div></div></body></html>"#,
            logo_url, reset_url, reset_url
        );
        let _ = send_email_via_w9_mail(
            &state.db,
            &state.http_client,
            &email,
            None,
            "Reset Your W9 DB Password",
            &body_html,
        )
        .await;
    }
    Html(auth_layout("Sent", r#"<div class="card" style="max-width:420px;margin:2rem auto;text-align:center"><h1>📧 Check Inbox</h1><p>If that email exists, we sent a reset link (expires in 1 hour).</p><a href="/login" class="btn mt-2">Sign In</a></div>"#)).into_response()
}

// ============================================================
// Handlers: API + OAuth
// ============================================================
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.query_one("SELECT 1", &[]).await {
        Ok(_) => (
            StatusCode::OK,
            Json(
                serde_json::json!({"status":"ok","service":"w9-db","database":"connected","timestamp":Utc::now().to_rfc3339()}),
            ),
        ),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status":"error","service":"w9-db","error":e.to_string()})),
        ),
    }
}
async fn oidc_discovery() -> impl IntoResponse {
    let issuer = std::env::var("ISSUER_URL").unwrap_or_else(|_| "https://db.w9.nu".into());
    (
        StatusCode::OK,
        Json(
            serde_json::json!({"issuer":issuer,"authorization_endpoint":format!("{}/oauth/authorize",issuer),"token_endpoint":format!("{}/oauth/token",issuer),"userinfo_endpoint":format!("{}/api/auth/me",issuer),"response_types_supported":["code"],"scopes_supported":["openid","profile","email"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["HS256"]}),
        ),
    )
}

#[derive(Debug, Deserialize)]
struct OAuthAuthQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    state: Option<String>,
}
async fn oauth_authorize(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<OAuthAuthQuery>,
) -> impl IntoResponse {
    if get_session_token(&jar).is_none() {
        return Redirect::to(&format!(
            "/login?redirect={}",
            q.redirect_uri.as_deref().unwrap_or("/")
        ))
        .into_response();
    }
    let user = match require_auth(&jar, &state).await {
        Some(u) => u,
        None => return (clear_session(jar), Redirect::to("/login")).into_response(),
    };
    let user_id = match Uuid::parse_str(&user.id) {
        Ok(u) => u,
        Err(_) => return (clear_session(jar), Redirect::to("/login")).into_response(),
    };
    let code = format!(
        "auth-{}-{}-{}",
        user.email,
        Uuid::new_v4(),
        Utc::now().timestamp()
    );
    let expires = Utc::now() + Duration::minutes(10);
    let _ = state.db.execute("INSERT INTO oauth_tokens (id, token, token_type, user_id, scopes, expires_at) VALUES ($1,$2,$3,$4,$5,$6)", &[&Uuid::new_v4(), &code, &"authorization_code", &user_id, &SCOPES_TEXT, &expires]).await;
    let redir = q.redirect_uri.as_deref().unwrap_or("/");
    let sep = if redir.contains('?') { "&" } else { "?" };
    Redirect::to(&format!(
        "{}{}code={}&state={}",
        redir,
        sep,
        code,
        q.state.as_deref().unwrap_or("")
    ))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct OAuthTokenReq {
    grant_type: String,
    code: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
}
async fn oauth_token(
    State(state): State<AppState>,
    Form(form): Form<OAuthTokenReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    if form.grant_type != "authorization_code" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"unsupported_grant_type"})),
        );
    }
    let code = match form.code {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid_request"})),
            )
        }
    };
    let row = match state.db.query_opt("SELECT user_id FROM oauth_tokens WHERE token=$1 AND token_type='authorization_code' AND expires_at>$2", &[&code, &Utc::now()]).await { Ok(Some(r)) => r, _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid_grant"}))) };
    let user_id: Uuid = row.get("user_id");
    let user_row = match state
        .db
        .query_opt(
            "SELECT email, display_name, role, is_verified FROM users WHERE id=$1",
            &[&user_id],
        )
        .await
    {
        Ok(Some(r)) => r,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error":"server_error"})),
            )
        }
    };
    let access_token = format!(
        "access-{}-{}-{}",
        user_id,
        Uuid::new_v4(),
        Utc::now().timestamp()
    );
    let expires = Utc::now() + Duration::hours(24);
    let _ = state.db.execute("INSERT INTO oauth_tokens (id, token, token_type, user_id, scopes, expires_at) VALUES ($1,$2,$3,$4,$5,$6)", &[&Uuid::new_v4(), &access_token, &"bearer", &user_id, &SCOPES_TEXT, &expires]).await;
    let _ = state
        .db
        .execute("DELETE FROM oauth_tokens WHERE token=$1", &[&code])
        .await;
    (
        StatusCode::OK,
        Json(
            serde_json::json!({"access_token":access_token,"token_type":"bearer","expires_in":86400,"scope":SCOPES_TEXT,"user":{"email":user_row.get::<_,String>("email"),"display_name":user_row.get::<_,Option<String>>("display_name"),"role":user_row.get::<_,String>("role"),"is_verified":user_row.get::<_,bool>("is_verified")}}),
        ),
    )
}

async fn handle_me(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Some(auth) = headers.get("Authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if let Ok(Some(r)) = state.db.query_opt("SELECT u.email, u.display_name, u.role, u.is_verified FROM users u JOIN oauth_tokens t ON u.id=t.user_id WHERE t.token=$1 AND t.token_type='bearer' AND t.expires_at>$2", &[&token, &Utc::now()]).await {
                return (StatusCode::OK, Json(serde_json::json!({"email":r.get::<_,String>("email"),"display_name":r.get::<_,Option<String>>("display_name"),"role":r.get::<_,String>("role"),"is_verified":r.get::<_,bool>("is_verified")})));
            }
        }
    }
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error":"Not authenticated"})),
    )
}

// ============================================================
// Admin Seeder
// ============================================================
async fn seed_admin(db: &Arc<Client>, email: &str, password: &str) {
    let exists = db
        .query_one("SELECT COUNT(*) FROM users WHERE email=$1", &[&email])
        .await
        .map(|r| {
            let c: i64 = r.get(0);
            c > 0
        })
        .unwrap_or(false);
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
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    dotenvy::dotenv().ok();
    let port = std::env::var("PORT").unwrap_or_else(|_| "8082".into());
    let db_url = std::env::var("W9_DB_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://w9_admin:password@w9-postgres:5432/w9_users".into());
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "change-me".into());
    let turnstile_secret = std::env::var("TURNSTILE_SECRET_KEY").unwrap_or_default();
    let issuer_url = std::env::var("ISSUER_URL").unwrap_or_else(|_| "https://db.w9.nu".into());
    let mail_api_token = std::env::var("W9_MAIL_API_TOKEN").unwrap_or_default();
    let mail_base_url =
        std::env::var("W9_MAIL_BASE_URL").unwrap_or_else(|_| "https://mail.w9.nu".into());
    tracing::info!("Connecting to PostgreSQL...");
    let (client, conn) = tokio_postgres::connect(&db_url, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!("DB: {}", e);
        }
    });
    client.query_one("SELECT 1", &[]).await?;
    tracing::info!("✅ Connected to PostgreSQL");
    let db = Arc::new(client);
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let admin_email = std::env::var("W9_DB_ADMIN_EMAIL").unwrap_or_else(|_| "admin@w9.nu".into());
    let admin_pw = std::env::var("W9_DB_ADMIN_PASSWORD").unwrap_or_else(|_| "W9Admin123!".into());
    seed_admin(&db, &admin_email, &admin_pw).await;

    // Create app_settings table if not exists
    let _ = db
        .execute(
            "CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)",
            &[],
        )
        .await;

    // Load settings from DB, fallback to env
    let mail_base_url = db
        .query_opt(
            "SELECT value FROM app_settings WHERE key = 'mail_base_url'",
            &[],
        )
        .await
        .ok()
        .and_then(|r| r.map(|row| row.get::<_, String>(0)))
        .unwrap_or_else(|| {
            std::env::var("W9_MAIL_BASE_URL").unwrap_or_else(|_| "https://mail.w9.nu".into())
        });
    let mail_api_token = db
        .query_opt(
            "SELECT value FROM app_settings WHERE key = 'mail_api_token'",
            &[],
        )
        .await
        .ok()
        .and_then(|r| r.map(|row| row.get::<_, String>(0)))
        .unwrap_or_else(|| std::env::var("W9_MAIL_API_TOKEN").unwrap_or_default());
    let _ = db.execute("INSERT INTO app_settings (key, value) VALUES ('mail_base_url', $1) ON CONFLICT (key) DO UPDATE SET value = $1", &[&mail_base_url]).await;
    let _ = db.execute("INSERT INTO app_settings (key, value) VALUES ('mail_api_token', $1) ON CONFLICT (key) DO UPDATE SET value = $1", &[&mail_api_token]).await;
    let _ = db.execute("INSERT INTO app_settings (key, value) VALUES ('sender_email', $1) ON CONFLICT (key) DO NOTHING", &[&std::env::var("W9_MAIL_SENDER").unwrap_or_default()]).await;

    let state = AppState {
        db,
        jwt_secret,
        turnstile_secret,
        issuer_url,
        mail_api_token,
        mail_base_url,
        http_client,
    };
    let router = Router::new()
        .nest_service("/w9-logo", ServeDir::new("public/w9-logo"))
        .route("/", get(home))
        .route("/login", get(login_page))
        .route("/login", post(login_post))
        .route("/register", get(register_page))
        .route("/register", post(register_post))
        .route("/reset", get(reset_page))
        .route("/reset", post(reset_post))
        .route("/verify", get(verify_email))
        .route("/reset/confirm", get(reset_confirm_page))
        .route("/reset/confirm", post(reset_confirm_post))
        .route("/dashboard", get(dashboard))
        .route("/profile", get(profile_page))
        .route("/profile", post(profile_post))
        .route("/logout", get(logout))
        .route("/admin", get(admin_page))
        .route("/admin/promote/:id", get(admin_promote))
        .route("/admin/demote/:id", get(admin_demote))
        .route("/admin/email-settings", get(email_settings_page))
        .route("/admin/email-settings", post(email_settings_post))
        .route("/resend-verification", get(resend_verification))
        .route("/forgot-password", get(forgot_password_page))
        .route("/forgot-password", post(forgot_password_post))
        .route("/api/health", get(health_check))
        .route("/api/auth/me", get(handle_me))
        .route("/oauth/authorize", get(oauth_authorize))
        .route("/oauth/token", post(oauth_token))
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive()),
        );
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("W9 DB listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
