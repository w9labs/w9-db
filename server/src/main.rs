use axum::{
    routing::{get, post},
    Router,
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer, services::ServeDir};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod auth;
mod models;

use auth::*;

// Simple in-memory store
#[derive(Clone)]
pub struct AppState {
    pub users: Arc<RwLock<HashMap<String, models::User>>>,
    pub jwt_secret: String,
}

async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": "ok",
            "service": "w9-db",
            "timestamp": Utc::now().to_rfc3339()
        })),
    )
}

async fn oidc_discovery() -> impl IntoResponse {
    let issuer = std::env::var("ISSUER_URL").unwrap_or_else(|_| "https://db.w9.nu".to_string());
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}/authorize", issuer),
            "token_endpoint": format!("{}/oauth/token", issuer),
            "userinfo_endpoint": format!("{}/userinfo", issuer),
            "response_types_supported": ["code"],
            "scopes_supported": ["openid", "profile", "email"],
        })),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "w9_db=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenvy::dotenv().ok();

    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "w9-db-jwt-secret-change-me".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "8082".to_string());

    let admin_email = std::env::var("DEFAULT_ADMIN_EMAIL")
        .unwrap_or_else(|_| "admin@w9.nu".to_string());
    let admin_password = std::env::var("DEFAULT_ADMIN_PASSWORD")
        .unwrap_or_else(|_| "W9AdminSecure123!".to_string());

    // Create default admin
    let mut users = HashMap::new();
    users.insert(admin_email.clone(), models::User {
        id: Some("1".to_string()),
        email: admin_email,
        password_hash: admin_password, // Plain for now, hash later
        display_name: Some("Admin".to_string()),
        role: models::UserRole::Admin,
        is_verified: true,
        created_at: None,
    });

    let state = AppState {
        users: Arc::new(RwLock::new(users)),
        jwt_secret,
    };

    let router = Router::new()
        .route("/api/health", get(health_check))
        .route("/api/auth/login", post(handle_login))
        .route("/api/auth/register", post(handle_register))
        .route("/api/auth/me", get(handle_me))
        .route("/userinfo", get(handle_userinfo))
        .route("/oauth/token", post(handle_oauth_token))
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .nest_service("/", ServeDir::new("site/pkg"))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive()),
        );

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("W9 Database server listening on {}", addr);

    axum::serve(listener, router).await?;
    Ok(())
}
