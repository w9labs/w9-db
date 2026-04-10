use leptos::*;

pub fn store_token(token: &str) {
    _ = token;
    // TODO: Implement localStorage
}

pub fn get_token() -> Option<String> {
    None
}

pub fn clear_token() {}

pub async fn login(email: String, _password: String) -> Result<crate::types::UserInfo, String> {
    Ok(crate::types::UserInfo {
        id: "1".to_string(),
        email,
        display_name: Some("User".to_string()),
        role: "user".to_string(),
        is_verified: true,
    })
}

pub async fn register(email: String, _password: String, display_name: String) -> Result<crate::types::UserInfo, String> {
    Ok(crate::types::UserInfo {
        id: "1".to_string(),
        email,
        display_name: Some(display_name),
        role: "user".to_string(),
        is_verified: true,
    })
}

pub async fn get_current_user() -> Option<crate::types::UserInfo> {
    None
}

pub fn logout() {
    clear_token();
}
