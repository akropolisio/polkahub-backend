use super::schema::users;

use chrono::{DateTime, Utc};

#[derive(Debug, Queryable)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub password: String,
    pub email_verified: bool,
    pub token: Option<String>,
    pub token_expired_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub email: &'a str,
    pub password: &'a str,
}

#[derive(Debug, AsChangeset)]
#[table_name = "users"]
pub struct UserWithNewToken<'a> {
    pub token: &'a str,
    pub token_expired_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
