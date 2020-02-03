use super::schema::user_projects;
use super::schema::users;

use chrono::{DateTime, Utc};

#[derive(Debug, Queryable)]
pub struct User {
    pub id: i64,
    pub login: String,
    pub email: String,
    pub password: String,
    pub email_verified: bool,
    pub email_verification_token: Option<String>,
    pub token: Option<String>,
    pub token_expired_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub login: &'a str,
    pub email: &'a str,
    pub password: &'a str,
    pub email_verification_token: &'a str,
}

#[derive(Debug, AsChangeset)]
#[table_name = "users"]
pub struct UserWithNewToken<'a> {
    pub token: &'a str,
    pub token_expired_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Queryable)]
pub struct UserProject {
    pub user_id: i64,
    pub name: String,
    pub version: String,
    pub description: String,
}

#[derive(Debug, Insertable)]
#[table_name = "user_projects"]
pub struct NewUserProject<'a> {
    pub user_id: i64,
    pub name: &'a str,
    pub version: &'a str,
    pub description: Option<&'a str>,
}
