use serde_json::json;

pub(crate) fn account_not_found() -> String {
    json!({
        "status": "error",
        "reason": "account not found, please registered and auth first"
    })
    .to_string()
}

pub(crate) fn email_already_exists() -> String {
    json!({ "status": "error", "reason": "email already exists" }).to_string()
}

pub(crate) fn email_not_verified() -> String {
    json!({ "status": "error", "reason": "email not verified" }).to_string()
}

pub(crate) fn failed_to_deploy_project(app_name: &str, version: &str) -> String {
    json!({
        "status": "error",
        "reason": &format!("failed to deploy {} with version {}", app_name, version),
    })
    .to_string()
}

pub(crate) fn failed_to_find_project() -> String {
    json!({ "status": "error", "reason": "failed to find project" }).to_string()
}

pub(crate) fn internal_error() -> String {
    json!({ "status": "error", "reason": "internal error" }).to_string()
}

pub(crate) fn invalid_token() -> String {
    json!({ "status": "error", "reason": "invalid token" }).to_string()
}

pub(crate) fn error_from_reason(reason: &str) -> String {
    json!({
        "status": "error",
        "reason": reason,
    })
    .to_string()
}
