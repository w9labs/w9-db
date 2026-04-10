use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserPublic,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPublic {
    pub email: String,
    pub display_name: Option<String>,
    pub role: String,
    pub is_verified: bool,
}

pub async fn handle_login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let users = state.users.read().unwrap();
    if let Some(user) = users.get(&req.email) {
        if user.password_hash == req.password {
            return (StatusCode::OK, Json(AuthResponse {
                token: "jwt-token-placeholder".to_string(),
                user: UserPublic {
                    email: user.email.clone(),
                    display_name: user.display_name.clone(),
                    role: format!("{:?}", user.role),
                    is_verified: user.is_verified,
                },
            })).into_response();
        }
    }
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid credentials"}))).into_response()
}

pub async fn handle_register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let mut users = state.users.write().unwrap();
    if users.contains_key(&req.email) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Email exists"}))).into_response();
    }
    let user = crate::models::User {
        id: Some(format!("{}", users.len() + 1)),
        email: req.email.clone(),
        password_hash: req.password,
        display_name: req.display_name,
        role: crate::models::UserRole::User,
        is_verified: true,
        created_at: None,
    };
    users.insert(req.email.clone(), user.clone());
    (StatusCode::CREATED, Json(AuthResponse {
        token: "jwt-token".to_string(),
        user: UserPublic {
            email: req.email,
            display_name: user.display_name,
            role: "user".to_string(),
            is_verified: user.is_verified,
        },
    })).into_response()
}

pub async fn handle_me(State(_state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"message": "Requires Bearer token"}))).into_response()
}

pub async fn handle_userinfo(State(_state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"sub": "user"}))).into_response()
}

pub async fn handle_oauth_token(State(_state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"message": "OAuth token endpoint"}))).into_response()
}
