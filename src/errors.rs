use serde_json::json;

pub(crate) fn account_not_found() -> String {
    error_from_reason("account not found, please registered and auth first")
}

pub(crate) fn email_already_exists() -> String {
    error_from_reason("email already exists")
}

pub(crate) fn email_not_verified() -> String {
    error_from_reason("email not verified")
}

pub(crate) fn failed_to_deploy_project(app_name: &str, version: &str) -> String {
    error_from_reason(&format!(
        "failed to deploy {} with version {}",
        app_name, version
    ))
}

pub(crate) fn failed_to_find_project() -> String {
    error_from_reason("failed to find project")
}

pub(crate) fn failed_to_get_user_projects() -> String {
    error_from_reason("failed to get user projects")
}

pub(crate) fn user_project_already_exists() -> String {
    error_from_reason("user project already exists")
}

pub(crate) fn failed_to_get_user_applications() -> String {
    error_from_reason("failed to get user applications")
}

pub(crate) fn user_application_already_exists() -> String {
    error_from_reason("user application already exists")
}

pub(crate) fn name_is_very_short(minimum_length: usize) -> String {
    error_from_reason(&format!("length name is less {} chars", minimum_length))
}

pub(crate) fn internal_error() -> String {
    error_from_reason("internal error")
}

pub(crate) fn invalid_token() -> String {
    error_from_reason("invalid token")
}

pub(crate) fn invalid_email_and_password() -> String {
    error_from_reason("invalid email and password")
}

pub(crate) fn invalid_original_uri() -> String {
    error_from_reason("invalid original_uri")
}

pub(crate) fn invalid_project_name() -> String {
    error_from_reason("invalid project_name")
}

pub(crate) fn error_from_reason(reason: &str) -> String {
    json!({
        "status": "error",
        "reason": reason,
    })
    .to_string()
}
