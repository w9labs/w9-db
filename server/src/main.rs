use axum::{
    extract::State, http::StatusCode, response::Html, routing::{get, post}, Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_postgres::{Client, NoTls};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Client>,
    pub jwt_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginReq {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterReq {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

fn html_root() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html><html><head><title>W9 DB</title></head><body style="background:#160c13;color:#fce126;font-family:monospace;text-align:center;padding:3rem"><h1>W9 DB</h1><p>OAuth 2.0 / OIDC Provider — PostgreSQL</p></body></html>"#)
}

async fn health_check(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    match state.db.query_one("SELECT 1", &[]).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({
            "status": "ok", "service": "w9-db", "database": "connected",
            "timestamp": Utc::now().to_rfc3339()
        }))),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "status": "error", "service": "w9-db", "database": "disconnected",
            "error": e.to_string(), "timestamp": Utc::now().to_rfc3339()
        }))),
    }
}

async fn handle_login(
    State(state): State<AppState>,
    Json(req): Json<LoginReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let row = match state.db
        .query_opt("SELECT email, password_hash, display_name, role, is_verified FROM users WHERE email = $1", &[&req.email])
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid credentials"}))),
        Err(e) => { tracing::error!("Login query: {}", e); return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))); }
    };

    let pw_hash: String = row.get("password_hash");
    if pw_hash != req.password {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid credentials"})));
    }

    let email: String = row.get("email");
    let display_name: Option<String> = row.get("display_name");
    let role: String = row.get("role");
    let is_verified: bool = row.get("is_verified");
    let token = format!("jwt-{}-{}", email, Utc::now().timestamp());

    (StatusCode::OK, Json(serde_json::json!({
        "token": token,
        "user": { "email": email, "display_name": display_name, "role": role, "is_verified": is_verified }
    })))
}

async fn handle_register(
    State(state): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let exists = match state.db.query_one("SELECT COUNT(*) FROM users WHERE email = $1", &[&req.email]).await {
        Ok(r) => { let c: i64 = r.get(0); c > 0 }
        Err(e) => { tracing::error!("Register check: {}", e); return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))); }
    };
    if exists {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Email already exists"})));
    }

    let uid = Uuid::new_v4();
    match state.db.execute(
        "INSERT INTO users (id, email, password_hash, display_name, role, is_verified) VALUES ($1,$2,$3,$4,$5,$6)",
        &[&uid, &req.email, &req.password, &req.display_name, &"user", &true],
    ).await {
        Ok(_) => {
            let token = format!("jwt-{}-{}", req.email, Utc::now().timestamp());
            (StatusCode::CREATED, Json(serde_json::json!({
                "token": token,
                "user": { "email": req.email, "display_name": req.display_name, "role": "user", "is_verified": true }
            })))
        }
        Err(e) => { tracing::error!("Register insert: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to create user"}))) }
    }
}

async fn handle_me(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Some(auth) = headers.get("Authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if let Some(email) = token.strip_prefix("jwt-").and_then(|t| t.rsplit('-').nth(1)) {
                if let Ok(Some(r)) = state.db.query_opt("SELECT email, display_name, role, is_verified FROM users WHERE email = $1", &[&email]).await {
                    return (StatusCode::OK, Json(serde_json::json!({
                        "email": r.get::<_, String>("email"),
                        "display_name": r.get::<_, Option<String>>("display_name"),
                        "role": r.get::<_, String>("role"),
                        "is_verified": r.get::<_, bool>("is_verified"),
                    })));
                }
            }
        }
    }
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"})))
}

async fn oidc_discovery() -> impl axum::response::IntoResponse {
    let issuer = std::env::var("ISSUER_URL").unwrap_or_else(|_| "https://db.w9.nu".into());
    (StatusCode::OK, Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer),
        "token_endpoint": format!("{}/oauth/token", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
        "response_types_supported": ["code"],
        "scopes_supported": ["openid", "profile", "email"],
    })))
}

async fn seed_admin(db: &Arc<Client>, email: &str, password: &str) {
    let exists = db.query_one("SELECT COUNT(*) FROM users WHERE email = $1", &[&email])
        .await.map(|r| { let c: i64 = r.get(0); c > 0 }).unwrap_or(false);
    if !exists {
        let uid = Uuid::new_v4();
        if let Err(e) = db.execute(
            "INSERT INTO users (id, email, password_hash, display_name, role, is_verified) VALUES ($1,$2,$3,$4,$5,$6)",
            &[&uid, &email, &password, &"Default Admin", &"admin", &true],
        ).await { tracing::error!("Seed admin: {}", e); }
        else { tracing::info!("Seeded admin: {}", email); }
    } else { tracing::info!("Admin exists: {}", email); }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer()).init();
    dotenvy::dotenv().ok();

    let port = std::env::var("PORT").unwrap_or_else(|_| "8082".into());
    let db_url = std::env::var("W9_DB_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://w9_admin:password@w9-postgres:5432/w9_users".into());
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "change-me".into());

    tracing::info!("Connecting to PostgreSQL...");
    let (client, conn) = tokio_postgres::connect(&db_url, NoTls).await?;
    tokio::spawn(async move { if let Err(e) = conn.await { tracing::error!("DB conn error: {}", e); } });
    client.query_one("SELECT 1", &[]).await?;
    tracing::info!("Connected to PostgreSQL");

    let db = Arc::new(client);
    let admin_email = std::env::var("W9_DB_ADMIN_EMAIL").unwrap_or_else(|_| "admin@w9.nu".into());
    let admin_pw = std::env::var("W9_DB_ADMIN_PASSWORD").unwrap_or_else(|_| "W9Admin123!".into());
    seed_admin(&db, &admin_email, &admin_pw).await;

    let state = AppState { db, jwt_secret };
    let router = Router::new()
        .route("/api/health", get(health_check))
        .route("/api/auth/login", post(handle_login))
        .route("/api/auth/register", post(handle_register))
        .route("/api/auth/me", get(handle_me))
        .route("/userinfo", get(handle_me))
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .fallback(|| async { html_root() })
        .with_state(state)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()).layer(CorsLayer::permissive()));

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("W9 DB listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
