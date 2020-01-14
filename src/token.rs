use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::time::{SystemTime, UNIX_EPOCH};

const TOKEN_EXPIRATION_TIME_IN_SECONDS: i64 = 30 * 24 * 60 * 60;
const PROJECT_NAME: [u8; 8] = *b"polkahub";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    project_name: [u8; 8],
    timestamp: u128,
    uid: String,
}

pub(crate) fn token(secret: &str) -> String {
    let my_claims = Claims {
        project_name: PROJECT_NAME,
        timestamp: current_timestamp(),
        uid: Uuid::new_v4().to_string(),
    };
    encode(&Header::default(), &my_claims, secret.as_ref()).expect("Can not create new token")
}

pub(crate) fn token_expired_at() -> DateTime<Utc> {
    Utc::now()
        .checked_add_signed(Duration::seconds(TOKEN_EXPIRATION_TIME_IN_SECONDS))
        .expect("can not calculate token expiration time")
}

fn current_timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Can not get current timestamp")
        .as_nanos()
}
