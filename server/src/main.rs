use axum::{routing::{get, post}, Router, http::StatusCode, response::{IntoResponse, Html}, Json, extract::State};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Clone)]
pub struct AppState {
    pub users: Arc<RwLock<HashMap<String, UserRecord>>>,
    pub jwt_secret: String,
    pub turnstile_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub email: String, pub password_hash: String, pub display_name: Option<String>,
    pub role: String, pub is_verified: bool, pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginReq { pub email: String, pub password: String }
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterReq { pub email: String, pub password: String, pub display_name: Option<String> }

fn html_root(service: &str) -> Html<String> {
    Html(format!(r#"<!DOCTYPE html><html><head><title>W9 {}</title></head><body style="background:#160c13;color:#fce126;font-family:monospace;text-align:center;padding:3rem"><h1>W9 {}</h1><p>Server running. WASM client building in CI.</p></body></html>"#, service, service))
}

async fn health_check(service: &str) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status":"ok","service":format!("w9-{}",service),"timestamp":Utc::now().to_rfc3339()})))
}

async fn handle_login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> (StatusCode, axum::Json<serde_json::Value>) {
    let users = state.users.read().unwrap();
    if let Some(user) = users.get(&req.email) {
        if user.password_hash == req.password {
            let token = format!("jwt-{}-{}", user.email, Utc::now().timestamp());
            return (StatusCode::OK, axum::Json(serde_json::json!({"token": token, "user": {"email": user.email, "display_name": user.display_name, "role": user.role, "is_verified": user.is_verified}})));
        }
    }
    (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error":"Invalid credentials"})))
}

async fn handle_register(State(state): State<AppState>, Json(req): Json<RegisterReq>) -> (StatusCode, axum::Json<serde_json::Value>) {
    { let users = state.users.read().unwrap(); if users.contains_key(&req.email) { return (StatusCode::CONFLICT, axum::Json(serde_json::json!({"error":"Email exists"}))); } }
    let user = UserRecord { email: req.email.clone(), password_hash: req.password, display_name: req.display_name.clone(), role: "user".into(), is_verified: true, created_at: Utc::now().to_rfc3339() };
    state.users.write().unwrap().insert(req.email.clone(), user.clone());
    (StatusCode::CREATED, axum::Json(serde_json::json!({"token": format!("jwt-{}-{}", req.email, Utc::now().timestamp()), "user": {"email": req.email, "display_name": req.display_name, "role": "user", "is_verified": true}})))
}

async fn handle_me(headers: axum::http::HeaderMap, State(state): State<AppState>) -> (StatusCode, axum::Json<serde_json::Value>) {
    if let Some(auth) = headers.get("Authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if let Some(email) = token.strip_prefix("jwt-").and_then(|t| t.split('-').next()) {
                if let Some(user) = state.users.read().unwrap().get(email) {
                    return (StatusCode::OK, axum::Json(serde_json::json!({"email": user.email, "display_name": user.display_name, "role": user.role, "is_verified": user.is_verified})));
                }
            }
        }
    }
    (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error":"Not authenticated"})))
}

async fn oidc_discovery() -> impl IntoResponse {
    let issuer = std::env::var("ISSUER_URL").unwrap_or_else(|_| "https://db.w9.nu".into());
    (StatusCode::OK, Json(serde_json::json!({"issuer": issuer, "authorization_endpoint": format!("{}/authorize", issuer), "token_endpoint": format!("{}/oauth/token", issuer), "userinfo_endpoint": format!("{}/userinfo", issuer), "response_types_supported": ["code"], "scopes_supported": ["openid","profile","email"]})))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).with(tracing_subscriber::fmt::layer()).init();
    dotenvy::dotenv().ok();
    let port = std::env::var("PORT").unwrap_or_else(|_| "8082".into());
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "change-me".into());
    let turnstile_secret = std::env::var("TURNSTILE_SECRET_KEY").unwrap_or_default();
    let admin_email = std::env::var("DEFAULT_ADMIN_EMAIL").unwrap_or_else(|_| "admin@w9.nu".into());
    let admin_password = std::env::var("DEFAULT_ADMIN_PASSWORD").unwrap_or_else(|_| "W9Admin123!".into());
    let mut users = HashMap::new();
    users.insert(admin_email.clone(), UserRecord { email: admin_email, password_hash: admin_password, display_name: Some("Default Admin".into()), role: "admin".into(), is_verified: true, created_at: Utc::now().to_rfc3339() });
    let state = AppState { users: Arc::new(RwLock::new(users)), jwt_secret, turnstile_secret };
    let router = Router::new()
        .route("/api/health", get(|| async { health_check("db").await }))
        .route("/api/auth/login", post(handle_login))
        .route("/api/auth/register", post(handle_register))
        .route("/api/auth/me", get(handle_me))
        .route("/userinfo", get(handle_me))
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .fallback(|| async { html_root("DB") })
        .with_state(state)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()).layer(CorsLayer::permissive()));
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("W9 DB listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
