use lazy_static;
use regex::Regex;

lazy_static::lazy_static! {
    static ref PROJECT_NAME: Regex = Regex::new(r"[a-z0-9-]+").unwrap_or_else(|_| panic!("invalid PROJECT_NAME pattern"));
}

pub(crate) fn validate_project_name(project_name: &str) -> Result<(), String> {
    if PROJECT_NAME.is_match(project_name) {
        Ok(())
    } else {
        Err(crate::errors::invalid_project_name())
    }
}
