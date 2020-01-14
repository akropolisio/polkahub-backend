use argon2rs::argon2i_simple;
use hex;

const MIN_PASSWORD_LENGTH: usize = 8;
const MAX_PASSWORD_LENGTH: usize = 50;

pub(crate) fn password_with_salt(salt: &str, password: &str) -> String {
    hex::encode(argon2i_simple(salt, password))
}

pub(crate) fn validate_password(email: &str, password: &str, message: &str) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LENGTH {
        let reason = format!("password shorter than {} characters", MIN_PASSWORD_LENGTH);
        log::warn!("{}, email: {}, reason: {}", message, email, &reason);
        return Err(reason);
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        let reason = format!("password longer than {} characters", MAX_PASSWORD_LENGTH);
        log::warn!("{}, email: {}, reason: {}", message, email, &reason);
        return Err(reason);
    }

    Ok(())
}
