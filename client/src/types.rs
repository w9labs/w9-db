use serde::{Deserialize, Serialize};

#[derive(Clone, Default)]
pub struct AppState {}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub role: String,
    pub is_verified: bool,
}
