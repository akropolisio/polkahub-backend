#[macro_use]
extern crate diesel;

use actix_web::{middleware, web, App, HttpResponse, HttpServer, Responder};
use askama::Template;
use base64;
use chrono::{DateTime, Utc};
use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use dotenv::dotenv;
use reqwest::Client;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use tokio::{self, fs::File, io::AsyncWriteExt, process::Command};

use std::collections::HashMap;
use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;

mod config;
mod database;
mod errors;
mod login_utils;
mod models;
mod password_utils;
mod project_name_utils;
mod schema;
mod token;

use config::{DatabaseConfig, DeployerConfig, JenkinsConfig, MailgunSenderConfig};

struct State {
    base_domain: String,
    base_repo_dir: String,
    base_repo_domain: String,
    jenkins_config: JenkinsConfig,
    deployer_config: DeployerConfig,
    mailgun_sender_config: MailgunSenderConfig,
    client: Client,
    salt: String,
    pool: Pool<ConnectionManager<PgConnection>>,
    jwt_secert: String,
}

#[derive(Debug, Deserialize)]
struct CreateProjectRequest {
    project_name: String,
}

#[derive(Debug, Deserialize)]
struct FindProjectRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ExtendedSearchParams {
    name: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Default, Serialize)]
struct FoundProject {
    login: String,
    name: String,
    version: String,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct SearchResult {
    login: String,
    name: String,
    version: String,
    description: Option<String>,
    repo_url: String,
    ws_url: String,
    http_url: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct FoundUserProject {
    id: i64,
    name: String,
    version: String,
    description: Option<String>,
    repo_url: String,
    http_url: String,
    ws_url: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct FoundUserApplication {
    name: String,
    version: String,
    description: Option<String>,
    http_url: String,
    ws_url: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct InstallProjectRequest {
    app_name: String,
    login: String,
    project_name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct SignupRequest {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct InsertUserProjectsRequest {
    login: String,
    name: String,
    version: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateUserProjectsRequest {
    id: i64,
    description: String,
}

#[derive(Debug, Deserialize)]
struct InsertUserApplicationsRequest {
    login: String,
    name: String,
    version: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResetPasswordRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
struct UpdatePasswordRequest {
    email: String,
    password: String,
    token: String,
}

#[derive(Template)]
#[template(path = "git_hook.html")]
struct GitHookTemplte<'a> {
    jenkins_api: &'a str,
    jenkins_api_user: &'a str,
    jenkins_api_token: &'a str,
    job_name: &'a str,
    deployer_api: &'a str,
    deployer_api_user: &'a str,
    deployer_api_password: &'a str,
    login: &'a str,
    project_name: &'a str,
}

async fn create_project(
    data: web::Data<Arc<State>>,
    create_project_request: web::Json<CreateProjectRequest>,
    http_request: web::HttpRequest,
) -> impl Responder {
    handle_create_project(data, create_project_request, http_request).await
}

async fn find_project(
    data: web::Data<Arc<State>>,
    find_project_request: web::Json<FindProjectRequest>,
    http_request: web::HttpRequest,
) -> impl Responder {
    handle_find_project(data, find_project_request, http_request).await
}

async fn extended_search(
    data: web::Data<Arc<State>>,
    params: web::Query<ExtendedSearchParams>,
) -> impl Responder {
    handle_extended_search(data, params).await
}

async fn install_project(
    data: web::Data<Arc<State>>,
    install_project_request: web::Json<InstallProjectRequest>,
    http_request: web::HttpRequest,
) -> impl Responder {
    handle_install_project(data, install_project_request, http_request).await
}

async fn signup(
    data: web::Data<Arc<State>>,
    signup_request: web::Json<SignupRequest>,
) -> impl Responder {
    handle_signup(data, signup_request).await
}

async fn login(
    data: web::Data<Arc<State>>,
    login_request: web::Json<LoginRequest>,
) -> impl Responder {
    handle_login(data, login_request).await
}

async fn git_auth(data: web::Data<Arc<State>>, http_request: web::HttpRequest) -> HttpResponse {
    handle_git_auth(data, http_request).await
}

async fn get_user_projects(
    data: web::Data<Arc<State>>,
    http_request: web::HttpRequest,
) -> impl Responder {
    handle_get_user_projects(data, http_request).await
}

async fn insert_user_projects(
    data: web::Data<Arc<State>>,
    login_request: web::Json<InsertUserProjectsRequest>,
) -> impl Responder {
    handle_insert_user_projects(data, login_request).await
}

async fn update_user_projects(
    data: web::Data<Arc<State>>,
    request: web::Json<UpdateUserProjectsRequest>,
    http_request: web::HttpRequest,
) -> impl Responder {
    handle_update_user_projects(data, request, http_request).await
}

async fn get_user_applications(
    data: web::Data<Arc<State>>,
    http_request: web::HttpRequest,
) -> impl Responder {
    handle_get_user_applications(data, http_request).await
}

async fn insert_user_applications(
    data: web::Data<Arc<State>>,
    login_request: web::Json<InsertUserApplicationsRequest>,
) -> impl Responder {
    handle_insert_user_applications(data, login_request).await
}

async fn verify_email(data: web::Data<Arc<State>>, info: web::Path<String>) -> impl Responder {
    handle_verify_email(data, info).await
}

async fn reset_password(
    data: web::Data<Arc<State>>,
    request: web::Json<ResetPasswordRequest>,
) -> impl Responder {
    handle_reset_password(data, request).await
}

async fn update_password(
    data: web::Data<Arc<State>>,
    request: web::Json<UpdatePasswordRequest>,
) -> impl Responder {
    handle_update_password(data, request).await
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv().ok();

    let (
        ip,
        port,
        workers,
        base_domain,
        base_repo_dir,
        base_repo_domain,
        jwt_secert,
        jenkins_config,
        deployer_config,
        database_config,
        mailgun_sender_config,
    ) = config::read_env();

    let client = build_client().map_err(|e| {
        log::warn!("can not create HTTP client, reason: {}", e);
        std::io::Error::new(std::io::ErrorKind::Other, "can not create HTTP client")
    })?;
    let pool = database::create_pool(&database_config);
    let salt = database_config.salt;

    let state = Arc::new(State {
        base_domain,
        base_repo_dir,
        base_repo_domain,
        jenkins_config,
        deployer_config,
        mailgun_sender_config,
        client,
        salt,
        pool,
        jwt_secert,
    });

    HttpServer::new(move || {
        App::new()
            .data(state.clone())
            .route("/api/v1/projects", web::post().to(create_project))
            .route("/api/v1/find", web::post().to(find_project))
            .route("/api/v1/extended_search", web::get().to(extended_search))
            .route("/api/v1/install", web::post().to(install_project))
            .route("/api/v1/signup", web::post().to(signup))
            .route("/api/v1/login", web::post().to(login))
            .route("/api/v1/git_auth", web::get().to(git_auth))
            .route("/api/v1/user_projects", web::get().to(get_user_projects))
            .route(
                "/api/v1/user_projects",
                web::post().to(insert_user_projects),
            )
            .route("/api/v1/user_projects", web::put().to(update_user_projects))
            .route(
                "/api/v1/user_applications",
                web::get().to(get_user_applications),
            )
            .route(
                "/api/v1/user_applications",
                web::post().to(insert_user_applications),
            )
            .route("/api/v1/verify_email/{token}", web::get().to(verify_email))
            .route("/api/v1/reset_password", web::post().to(reset_password))
            .route("/api/v1/update_password", web::put().to(update_password))
            .default_service(web::route().to(HttpResponse::NotFound))
            .wrap(middleware::Logger::default())
    })
    .bind(format!("{}:{}", ip, port))?
    .workers(workers)
    .run()
    .await
}

fn build_client() -> Result<Client, reqwest::Error> {
    Client::builder().user_agent("polkahub-backend").build()
}

async fn handle_create_project(
    state: web::Data<Arc<State>>,
    request: web::Json<CreateProjectRequest>,
    http_request: web::HttpRequest,
) -> impl Responder {
    let login = match get_login_by_token(state.clone(), http_request) {
        Ok(login) => login,
        Err(err) => return err,
    };
    if let Err(reason) = project_name_utils::validate_project_name(&request.project_name) {
        return reason;
    };
    let repo_name = repo_name(&login, &request.project_name);
    match init_repo(
        &login,
        &request.project_name,
        &repo_name,
        &state.base_repo_dir,
        &state.jenkins_config,
        &state.deployer_config,
    )
    .await
    {
        Ok(()) => build_create_project_response(
            true,
            &repo_name,
            &state.base_domain,
            &state.base_repo_domain,
        ),
        Err(error) => match error.kind() {
            std::io::ErrorKind::AlreadyExists => build_create_project_response(
                false,
                &repo_name,
                &state.base_domain,
                &state.base_repo_domain,
            ),
            _ => errors::error_from_reason(&format!(
                "can not create repository directory: {}",
                error
            )),
        },
    }
}

async fn handle_find_project(
    state: web::Data<Arc<State>>,
    request: web::Json<FindProjectRequest>,
    http_request: web::HttpRequest,
) -> impl Responder {
    use crate::diesel::{QueryDsl, RunQueryDsl, TextExpressionMethods};
    use crate::schema::user_projects::dsl::{description, name, user_projects, version};
    use crate::schema::users::dsl::{login, users};

    let _login = match get_login_by_token(state.clone(), http_request) {
        Ok(l) => l,
        Err(err) => return err,
    };

    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };

    type Record = (String, String, String, Option<String>);
    let results: Result<Vec<Record>, diesel::result::Error> = user_projects
        .inner_join(users)
        .filter(name.like(format!("%{}%", &request.name)))
        .select((login, name, version, description))
        .limit(100)
        .get_results(&conn);
    match results {
        Ok(projects) => json!({
            "status": "ok",
            "payload": projects.into_iter().map(|p| FoundProject { login: p.0, name: p.1, version: p.2, description: p.3 }).collect::<Vec<_>>(),
        }).to_string(),
        Err(_) => errors::failed_to_find_project(),
    }
}

async fn handle_extended_search(
    state: web::Data<Arc<State>>,
    params: web::Query<ExtendedSearchParams>,
) -> impl Responder {
    use crate::diesel::{QueryDsl, RunQueryDsl, TextExpressionMethods};
    use crate::schema::user_projects::dsl::{
        created_at, description, name, updated_at, user_projects, version,
    };
    use crate::schema::users::dsl::{login, users};

    let limit = normalize_limit(params.limit);
    let offset = normalize_offset(params.offset);

    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };

    type Record = (
        String,
        String,
        String,
        Option<String>,
        DateTime<Utc>,
        DateTime<Utc>,
    );
    let results: Result<Vec<Record>, diesel::result::Error> = match &params.name {
        Some(n) => user_projects
            .inner_join(users)
            .filter(name.like(format!("%{}%", &n)))
            .select((login, name, version, description, created_at, updated_at))
            .limit(limit)
            .offset(offset)
            .get_results(&conn),
        None => user_projects
            .inner_join(users)
            .select((login, name, version, description, created_at, updated_at))
            .limit(limit)
            .offset(offset)
            .get_results(&conn),
    };
    let total: Result<i64, diesel::result::Error> = match &params.name {
        Some(n) => user_projects
            .filter(name.like(format!("%{}%", &n)))
            .count()
            .get_result(&conn),
        None => user_projects.count().get_result(&conn),
    };
    match (results, total) {
        (Ok(projects), Ok(total)) => {
            let build_search_result = |p: Record| {
                let repo_name = repo_name(&p.0, &p.1);
                SearchResult {
                    login: p.0,
                    name: p.1,
                    version: p.2,
                    description: p.3,
                    repo_url: repo_url(&repo_name, &state.base_domain),
                    http_url: http_url(&repo_name, &state.base_domain),
                    ws_url: ws_url(&repo_name, &state.base_domain),
                    created_at: p.4.timestamp(),
                    updated_at: p.5.timestamp(),
                }
            };
            json!({
                "status": "ok",
                "payload": {
                    "records": projects.into_iter().map(build_search_result).collect::<Vec<_>>(),
                    "total": total,
                },
            })
            .to_string()
        }
        _ => errors::failed_to_find_project(),
    }
}

async fn handle_install_project(
    state: web::Data<Arc<State>>,
    request: web::Json<InstallProjectRequest>,
    http_request: web::HttpRequest,
) -> impl Responder {
    let login = match get_login_by_token(state.clone(), http_request) {
        Ok(login) => login,
        Err(err) => return err,
    };
    if let Err(reason) = project_name_utils::validate_project_name(&request.app_name) {
        return reason;
    };
    let src_repo_name = repo_name(&request.login, &request.project_name);
    let dst_repo_name = repo_name(&login, &request.app_name);
    let jenkins_job_params = build_jenkins_params(
        &login,
        &src_repo_name,
        &dst_repo_name,
        &request.app_name,
        &request.version,
        &state.deployer_config,
    );
    match execute_deploy(&state.client, &state.jenkins_config, jenkins_job_params).await {
        Ok(_) => build_install_project_response(&dst_repo_name, &state.base_domain),
        Err(_) => errors::failed_to_deploy_project(&dst_repo_name, &request.version),
    }
}

async fn handle_signup(
    state: web::Data<Arc<State>>,
    request: web::Json<SignupRequest>,
) -> impl Responder {
    use crate::diesel::RunQueryDsl;
    use diesel::result::{DatabaseErrorKind, Error};

    if let Err(reason) = password_utils::validate_password(
        &request.email,
        &request.password,
        "can not create new user",
    ) {
        return errors::error_from_reason(&reason);
    }

    let password_with_salt = password_utils::password_with_salt(&state.salt, &request.password);
    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let login = &login_utils::login();
    let email_verification_token = &token::email_verification_token();
    let new_user = models::NewUser {
        login,
        email: &request.email,
        password: &password_with_salt,
        email_verification_token,
    };
    let result = diesel::insert_into(schema::users::table)
        .values(new_user)
        .execute(&conn);
    match result {
        Ok(_) => {
            log::info!("created new user, email: {}", &request.email);
            send_verification_email(&state, login, &request.email, email_verification_token).await;
            json!({ "status": "ok" }).to_string()
        }
        Err(Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
            log::warn!(
                "can not create new user, reason: email {} already exists",
                &request.email
            );
            errors::email_already_exists()
        }
        Err(err) => {
            log::error!(
                "can not create user, email: {}, reason: {:?}",
                &request.email,
                err
            );
            errors::internal_error()
        }
    }
}

async fn handle_login(
    state: web::Data<Arc<State>>,
    request: web::Json<LoginRequest>,
) -> impl Responder {
    use crate::diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use crate::models::{User, UserWithNewToken};
    use crate::schema::users::dsl::{email, id, password, users};

    if let Err(reason) =
        password_utils::validate_password(&request.email, &request.password, "can not login user")
    {
        return errors::error_from_reason(&reason);
    }

    let password_with_salt = password_utils::password_with_salt(&state.salt, &request.password);
    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let result = users
        .filter(email.eq(&request.email))
        .filter(password.eq(&password_with_salt))
        .first::<User>(&conn);

    match result {
        Ok(user) => {
            let token = token::token(&state.jwt_secert);
            let updated_at = Utc::now();
            let result = diesel::update(users.filter(id.eq(user.id)))
                .set(UserWithNewToken {
                    token: &token,
                    token_expired_at: token::token_expired_at(),
                    updated_at,
                })
                .execute(&conn);
            match result {
                Ok(_) => json!({ "status": "ok", "payload": { "token": token }}).to_string(),
                Err(reason) => {
                    log::warn!(
                        "can not update token, email: {}, reason: {}",
                        &request.email,
                        reason
                    );
                    errors::internal_error()
                }
            }
        }
        Err(diesel::result::Error::NotFound) => {
            log::warn!("user not found, email: {}", &request.email);
            errors::account_not_found()
        }
        Err(reason) => {
            log::warn!(
                "can not get user, email: {}, reason: {}",
                &request.email,
                reason
            );
            errors::internal_error()
        }
    }
}

async fn handle_git_auth(
    state: web::Data<Arc<State>>,
    http_request: web::HttpRequest,
) -> HttpResponse {
    match http_request.headers().get("authorization") {
        Some(_auth) => {
            let login = match get_login_by_email_and_password(state, &http_request) {
                Ok(login) => login,
                Err(reason) => {
                    return HttpResponse::Unauthorized()
                        .header("content-type", "application/json")
                        .body(reason)
                }
            };
            let original_uri = if let Some(value) = http_request.headers().get("x-original-uri") {
                if let Ok(value_str) = value.to_str() {
                    value_str
                } else {
                    return HttpResponse::Forbidden()
                        .header("content-type", "application/json")
                        .body(errors::invalid_original_uri());
                }
            } else {
                return HttpResponse::Forbidden()
                    .header("content-type", "application/json")
                    .body(errors::invalid_original_uri());
            };
            if !(&original_uri[login.len() + 1..login.len() + 2] == "-"
                && original_uri[1..=login.len()] == login)
            {
                return HttpResponse::Forbidden().into();
            }
            HttpResponse::Ok()
                .header("content-type", "application/json")
                .body(json!({"status": "ok"}).to_string())
        }
        None => HttpResponse::Unauthorized()
            .header(
                "WWW-Authenticate",
                "Basic realm=\"Please enter your email and password\"",
            )
            .finish(),
    }
}

async fn handle_get_user_projects(
    state: web::Data<Arc<State>>,
    http_request: web::HttpRequest,
) -> impl Responder {
    use crate::diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use crate::schema::user_projects::dsl::{
        created_at, description, id, name, updated_at, user_projects, version,
    };
    use crate::schema::users::dsl::{login, users};

    let user_login = match get_login_by_token(state.clone(), http_request) {
        Ok(user_login) => user_login,
        Err(err) => return err,
    };

    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };

    type Record = (
        i64,
        String,
        String,
        Option<String>,
        DateTime<Utc>,
        DateTime<Utc>,
    );
    let results: Result<Vec<Record>, diesel::result::Error> = users
        .inner_join(user_projects)
        .filter(login.eq(&user_login))
        .select((id, name, version, description, created_at, updated_at))
        .get_results(&conn);
    match results {
        Ok(projects) => {
            let build_found_user_project = |p: Record| {
                let repo_name = repo_name(&user_login, &p.1);
                FoundUserProject {
                    id: p.0,
                    name: p.1,
                    version: p.2,
                    description: p.3,
                    repo_url: repo_url(&repo_name, &state.base_domain),
                    http_url: http_url(&repo_name, &state.base_domain),
                    ws_url: ws_url(&repo_name, &state.base_domain),
                    created_at: p.4.timestamp(),
                    updated_at: p.5.timestamp(),
                }
            };
            json!({
                "status": "ok",
                "payload": projects.into_iter().map(build_found_user_project).collect::<Vec<_>>(),
            })
            .to_string()
        }
        Err(_) => errors::failed_to_get_user_projects(),
    }
}

async fn handle_insert_user_projects(
    state: web::Data<Arc<State>>,
    request: web::Json<InsertUserProjectsRequest>,
) -> impl Responder {
    use crate::diesel::{
        result::{DatabaseErrorKind, Error},
        ExpressionMethods, QueryDsl, RunQueryDsl,
    };
    use crate::models::{NewUserProject, User};
    use crate::schema::users::dsl::{login, users};

    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let result = users.filter(login.eq(&request.login)).first::<User>(&conn);

    match result {
        Ok(user) => {
            let new_user_project = NewUserProject {
                user_id: user.id,
                name: &request.name,
                version: &request.version,
                description: request.description.as_deref(),
            };
            let result = diesel::insert_into(schema::user_projects::table)
                .values(new_user_project)
                .execute(&conn);
            match result {
                Ok(_) => {
                    log::info!(
                        "created new user project, login: {}, name: {}, version: {}",
                        &request.login,
                        &request.name,
                        &request.version
                    );
                    json!({ "status": "ok" }).to_string()
                }
                Err(Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
                    log::warn!(
                        "can not create new user project, login: {}, name: {}, version: {}, reason: already exists",
                        &request.login,
                        &request.name,
                        &request.version
                    );
                    errors::user_project_already_exists()
                }
                Err(err) => {
                    log::error!(
                        "can not create user project, login: {}, name: {}, version: {}, reason: {:?}",
                        &request.login,
                        &request.name,
                        &request.version,
                        err
                    );
                    errors::internal_error()
                }
            }
        }
        Err(diesel::result::Error::NotFound) => {
            log::warn!("user not found, login: {}", &request.login);
            errors::account_not_found()
        }
        Err(reason) => {
            log::warn!(
                "can not get user, login: {}, reason: {}",
                &request.login,
                reason
            );
            errors::internal_error()
        }
    }
}

async fn handle_update_user_projects(
    state: web::Data<Arc<State>>,
    request: web::Json<UpdateUserProjectsRequest>,
    http_request: web::HttpRequest,
) -> impl Responder {
    use crate::diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use crate::schema::user_projects::dsl::{description, user_id, user_projects};

    let uid = match get_user_id_by_token(state.clone(), http_request) {
        Ok(i) => i,
        Err(err) => return err,
    };

    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let result: Result<usize, diesel::result::Error> =
        diesel::update(user_projects.find(request.id))
            .filter(user_id.eq(&uid))
            .set(description.eq(&request.description))
            .execute(&conn);

    match result {
        Ok(count) => json!({ "status": "ok", "payload": { "updated": count } }).to_string(),
        Err(err) => {
            log::error!(
                "can not update user project, id: {}, description: {}, reason: {:?}",
                &request.id,
                &request.description,
                err
            );
            errors::internal_error()
        }
    }
}

async fn handle_get_user_applications(
    state: web::Data<Arc<State>>,
    http_request: web::HttpRequest,
) -> impl Responder {
    use crate::diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use crate::schema::user_applications::dsl::{
        created_at, description, name, updated_at, user_applications, version,
    };
    use crate::schema::users::dsl::{login, users};

    let user_login = match get_login_by_token(state.clone(), http_request) {
        Ok(user_login) => user_login,
        Err(err) => return err,
    };

    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };

    type Record = (String, String, Option<String>, DateTime<Utc>, DateTime<Utc>);
    let results: Result<Vec<Record>, diesel::result::Error> = users
        .inner_join(user_applications)
        .filter(login.eq(&user_login))
        .select((name, version, description, created_at, updated_at))
        .get_results(&conn);
    match results {
        Ok(applications) => {
            let build_found_user_application = |p: Record| {
                let repo_name = repo_name(&user_login, &p.0);
                FoundUserApplication {
                    name: p.0,
                    version: p.1,
                    description: p.2,
                    http_url: http_url(&repo_name, &state.base_domain),
                    ws_url: ws_url(&repo_name, &state.base_domain),
                    created_at: p.3.timestamp(),
                    updated_at: p.4.timestamp(),
                }
            };
            json!({
                "status": "ok",
                "payload": applications.into_iter().map(build_found_user_application).collect::<Vec<_>>(),
            })
            .to_string()
        }
        Err(_) => errors::failed_to_get_user_applications(),
    }
}

async fn handle_insert_user_applications(
    state: web::Data<Arc<State>>,
    request: web::Json<InsertUserApplicationsRequest>,
) -> impl Responder {
    use crate::diesel::{
        result::{DatabaseErrorKind, Error},
        ExpressionMethods, QueryDsl, RunQueryDsl,
    };
    use crate::models::{NewUserApplication, User};
    use crate::schema::users::dsl::{login, users};

    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let result = users.filter(login.eq(&request.login)).first::<User>(&conn);

    match result {
        Ok(user) => {
            let new_user_application = NewUserApplication {
                user_id: user.id,
                name: &request.name,
                version: &request.version,
                description: request.description.as_deref(),
            };
            let result = diesel::insert_into(schema::user_applications::table)
                .values(new_user_application)
                .execute(&conn);
            match result {
                Ok(_) => {
                    log::info!(
                        "created new user application, login: {}, name: {}, version: {}",
                        &request.login,
                        &request.name,
                        &request.version
                    );
                    json!({ "status": "ok" }).to_string()
                }
                Err(Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
                    log::warn!(
                        "can not create new user application, login: {}, name: {}, version: {}, reason: already exists",
                        &request.login,
                        &request.name,
                        &request.version
                    );
                    errors::user_application_already_exists()
                }
                Err(err) => {
                    log::error!(
                        "can not create user application, login: {}, name: {}, version: {}, reason: {:?}",
                        &request.login,
                        &request.name,
                        &request.version,
                        err
                    );
                    errors::internal_error()
                }
            }
        }
        Err(diesel::result::Error::NotFound) => {
            log::warn!("user not found, login: {}", &request.login);
            errors::account_not_found()
        }
        Err(reason) => {
            log::warn!(
                "can not get user, login: {}, reason: {}",
                &request.login,
                reason
            );
            errors::internal_error()
        }
    }
}

async fn handle_verify_email(
    state: web::Data<Arc<State>>,
    info: web::Path<String>,
) -> impl Responder {
    use crate::diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use crate::schema::users::dsl::{email_verification_token, email_verified, users};

    let conn = match state
        .pool
        .get()
        .map_err(|_| "Internal error. Please try later.")
    {
        Ok(c) => c,
        Err(e) => return e,
    };
    let token = info.to_string();
    let filtered_users = users.filter(email_verification_token.eq(Some(&token)));
    let result = diesel::update(filtered_users)
        .set((
            email_verified.eq(true),
            email_verification_token.eq(None::<String>),
        ))
        .execute(&conn);

    match result {
        Ok(0) => {
            log::info!(
                "email not verified, because token not found, token: {}",
                token
            );
            "Invalid request"
        }
        Ok(_) => {
            log::info!("email verified, token: {}", token);
            "Your email verified."
        }
        Err(reason) => {
            log::error!(
                "email verification is failed, token: {}, reason: {}",
                token,
                reason
            );
            "Internal error. Please try later."
        }
    }
}

async fn handle_reset_password(
    state: web::Data<Arc<State>>,
    request: web::Json<ResetPasswordRequest>,
) -> impl Responder {
    use crate::diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use crate::models::UserWithNewPasswordResetToken;
    use crate::schema::users::dsl::{email, users};

    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let token = token::password_reset_token();

    let result: Result<usize, diesel::result::Error> =
        diesel::update(users.filter(email.eq(&request.email)))
            .set(UserWithNewPasswordResetToken {
                password_reset_token: &token,
                password_reset_token_expired_at: token::password_reset_token_expired_at(),
                updated_at: Utc::now(),
            })
            .execute(&conn);

    match result {
        Ok(count) => {
            if count > 0 {
                send_password_reset_email(&state, &request.email, &token).await;
            }
            json!({ "status": "ok", "payload": { "updated": count } }).to_string()
        }
        Err(err) => {
            log::error!(
                "can not update user, email: {}, reason: {:?}",
                &request.email,
                err
            );
            errors::internal_error()
        }
    }
}

async fn handle_update_password(
    state: web::Data<Arc<State>>,
    request: web::Json<UpdatePasswordRequest>,
) -> impl Responder {
    use crate::diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use crate::models::{User, UserWithNewPassword};
    use crate::schema::users::dsl::{
        email, password_reset_token, password_reset_token_expired_at, users,
    };

    if let Err(reason) = password_utils::validate_password(
        &request.email,
        &request.password,
        "can not update user's password",
    ) {
        return errors::error_from_reason(&reason);
    }

    let password_with_salt = password_utils::password_with_salt(&state.salt, &request.password);

    let conn = match state.pool.get().map_err(|_| errors::internal_error()) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let result = users
        .filter(email.eq(&request.email))
        .filter(password_reset_token.eq(&request.token))
        .filter(password_reset_token_expired_at.gt(Utc::now()))
        .first::<User>(&conn);

    match result {
        Ok(user) => {
            let result: Result<usize, diesel::result::Error> = diesel::update(users.find(user.id))
                .set(UserWithNewPassword {
                    password: &password_with_salt,
                    password_reset_token: Some(None),
                    password_reset_token_expired_at: Some(None),
                    updated_at: Utc::now(),
                })
                .execute(&conn);
            match result {
                Ok(count) => json!({ "status": "ok", "payload": { "updated": count } }).to_string(),
                Err(err) => {
                    log::error!(
                        "can not update user's password, email: {}, reason: {:?}",
                        &request.email,
                        err
                    );
                    errors::internal_error()
                }
            }
        }
        Err(_) => errors::account_not_found(),
    }
}

async fn init_repo(
    login: &str,
    project_name: &str,
    repo_name: &str,
    base_repo_dir: &str,
    jenkins_config: &JenkinsConfig,
    deployer_config: &DeployerConfig,
) -> Result<(), std::io::Error> {
    let repo_dir_name = format!("{}.git", repo_name);
    let repo_path = Path::new(base_repo_dir).join(repo_dir_name);
    tokio::fs::create_dir(&repo_path).await?;
    execute_command("git", &["--bare", "init"], &repo_path).await?;
    execute_command("git", &["update-server-info"], &repo_path).await?;
    execute_command(
        "git",
        &["config", "--file", "config", "http.receivepack", "true"],
        &repo_path,
    )
    .await?;
    execute_command(
        "git",
        &[
            "config",
            "--file",
            "config",
            "hooks.allowunannotated",
            "true",
        ],
        &repo_path,
    )
    .await?;
    execute_command("chown", &["-R", "service.www-data", "."], &repo_path).await?;
    execute_command("chmod", &["-R", "775", "."], &repo_path).await?;
    rewrite_description(&repo_path, &repo_name).await?;
    add_git_hook(
        jenkins_config,
        deployer_config,
        &repo_path,
        login,
        project_name,
    )
    .await?;
    execute_command("chmod", &["+x", "hooks/update"], &repo_path).await?;
    Ok(())
}

async fn execute_deploy(
    client: &Client,
    jenkins_config: &JenkinsConfig,
    jenkins_job_params: String,
) -> Result<(), std::io::Error> {
    let params = [("json", jenkins_job_params)];
    let url = &format!(
        "{}/job/deploy-fixed-version/build",
        &jenkins_config.jenkins_api
    );
    client
        .post(url)
        .form(&params)
        .basic_auth(
            &jenkins_config.jenkins_api_user,
            Some(&jenkins_config.jenkins_api_token),
        )
        .send()
        .await
        .map_err(|e| {
            log::warn!("request to Jenkins is failed, reason: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, "request to Jenkins is failed")
        })?;
    Ok(())
}

async fn execute_command<P: AsRef<Path> + Debug>(
    command: &str,
    args: &[&str],
    current_dir: P,
) -> Result<(), std::io::Error> {
    let status = Command::new(command)
        .args(args)
        .current_dir(&current_dir)
        .status()
        .await?;
    log::info!(
        "executed {} {:?}, current_dir: {:?}, exit_code: {}",
        command,
        args,
        current_dir,
        status
    );
    Ok(())
}

async fn rewrite_description<P>(repo_path: P, repo_name: &str) -> Result<(), std::io::Error>
where
    P: AsRef<Path> + Debug,
    P: std::convert::AsRef<std::ffi::OsStr>,
{
    let file_path = Path::new(&repo_path).join("description");
    let mut file = File::create(&file_path).await?;
    file.write_all(repo_name.as_bytes()).await?;
    log::info!("write git description, file_path: {:?}", file_path);
    Ok(())
}

async fn add_git_hook<P>(
    jenkins_config: &JenkinsConfig,
    deployer_config: &DeployerConfig,
    repo_path: P,
    login: &str,
    project_name: &str,
) -> Result<(), std::io::Error>
where
    P: AsRef<Path> + Debug,
    P: std::convert::AsRef<std::ffi::OsStr>,
{
    let data = GitHookTemplte {
        jenkins_api: &jenkins_config.jenkins_api,
        jenkins_api_user: &jenkins_config.jenkins_api_user,
        jenkins_api_token: &jenkins_config.jenkins_api_token,
        job_name: &jenkins_config.job_name,
        deployer_api: &deployer_config.deployer_api,
        deployer_api_user: &deployer_config.deployer_api_user,
        deployer_api_password: &deployer_config.deployer_api_password,
        login,
        project_name,
    }
    .render()
    .expect("can not render git hook data");

    let file_path = Path::new(&repo_path).join("hooks/update");
    let mut file = File::create(&file_path).await?;
    file.write_all(data.as_bytes()).await?;
    log::info!("write git hook, file_path: {:?}", file_path);
    Ok(())
}

fn build_create_project_response(
    repository_created: bool,
    repo_name: &str,
    base_domain: &str,
    base_repo_domain: &str,
) -> String {
    json!({
        "status": "ok",
        "payload": {
            "repository_created": repository_created,
            "repo_url": repo_url(repo_name, base_repo_domain),
            "http_url": http_url(repo_name, base_domain),
            "ws_url": ws_url(repo_name, base_domain)
        }
    })
    .to_string()
}

fn build_install_project_response(app_url: &str, base_domain: &str) -> String {
    json!({
        "status": "ok",
        "payload": {
            "http_url": http_url(app_url, base_domain),
            "ws_url": ws_url(app_url, base_domain)
        }
    })
    .to_string()
}

fn build_jenkins_params(
    login: &str,
    src_repo_name: &str,
    dst_repo_name: &str,
    dst_app_name: &str,
    version: &str,
    deployer_config: &DeployerConfig,
) -> String {
    json!({
        "parameter": [
            {"name":"LOGIN", "value": login},
            {"name":"SRC_REPO_NAME", "value": src_repo_name},
            {"name":"DST_REPO_NAME", "value": dst_repo_name},
            {"name":"DST_APP_NAME", "value": dst_app_name},
            {"name":"VERSION", "value": version},
            {"name":"DEPLOYER_API", "value": deployer_config.deployer_api},
            {"name":"DEPLOYER_API_USER", "value": deployer_config.deployer_api_user},
            {"name":"DEPLOYER_API_PASSWORD", "value": deployer_config.deployer_api_password}]
    })
    .to_string()
}

fn read_token(http_request: web::HttpRequest) -> Result<String, String> {
    match http_request.headers().get("authorization") {
        Some(auth) => {
            let parts = auth
                .to_str()
                .map_err(|_| errors::invalid_token())?
                .split(' ')
                .collect::<Vec<_>>();
            if parts.len() == 2 && parts[0] == "Bearer" {
                Ok(parts[1].to_string())
            } else {
                Err(errors::invalid_token())
            }
        }
        None => Err(errors::invalid_token()),
    }
}

fn read_email_and_password(http_request: &web::HttpRequest) -> Result<(String, String), String> {
    match http_request.headers().get("authorization") {
        Some(auth) => {
            let parts = auth
                .to_str()
                .map_err(|_| errors::invalid_email_and_password())?
                .split(' ')
                .collect::<Vec<_>>();
            if parts.len() == 2 && parts[0] == "Basic" {
                let decoded_credintals =
                    base64::decode(parts[1]).map_err(|_| errors::invalid_email_and_password())?;
                let decoded_credintals = String::from_utf8(decoded_credintals)
                    .map_err(|_| errors::invalid_email_and_password())?;
                if let Some(pos) = decoded_credintals.chars().position(|c| c == ':') {
                    let email = &decoded_credintals[..pos];
                    let password = &decoded_credintals[pos + 1..];
                    Ok((email.to_string(), password.to_string()))
                } else {
                    Err(errors::invalid_email_and_password())
                }
            } else {
                Err(errors::invalid_email_and_password())
            }
        }
        None => Err(errors::invalid_email_and_password()),
    }
}

fn get_login_by_token(
    state: web::Data<Arc<State>>,
    http_request: web::HttpRequest,
) -> Result<String, String> {
    use crate::diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use crate::models::User;
    use crate::schema::users::dsl::{token, token_expired_at, users};

    let auth_token = read_token(http_request)?;
    let conn = state.pool.get().map_err(|_| errors::internal_error())?;
    let result = users
        .filter(token.eq(&auth_token))
        .filter(token_expired_at.gt(Utc::now()))
        .first::<User>(&conn);
    match result {
        Ok(user) => {
            if user.email_verified {
                Ok(user.login)
            } else {
                Err(errors::email_not_verified())
            }
        }
        Err(_) => Err(errors::account_not_found()),
    }
}

fn get_user_id_by_token(
    state: web::Data<Arc<State>>,
    http_request: web::HttpRequest,
) -> Result<i64, String> {
    use crate::diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use crate::models::User;
    use crate::schema::users::dsl::{token, token_expired_at, users};

    let auth_token = read_token(http_request)?;
    let conn = state.pool.get().map_err(|_| errors::internal_error())?;
    let result = users
        .filter(token.eq(&auth_token))
        .filter(token_expired_at.gt(Utc::now()))
        .first::<User>(&conn);
    match result {
        Ok(user) => {
            if user.email_verified {
                Ok(user.id)
            } else {
                Err(errors::email_not_verified())
            }
        }
        Err(_) => Err(errors::account_not_found()),
    }
}

fn get_login_by_email_and_password(
    state: web::Data<Arc<State>>,
    http_request: &web::HttpRequest,
) -> Result<String, String> {
    use crate::diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use crate::models::User;
    use crate::schema::users::dsl::{email, password, users};

    let (user_email, user_password) = read_email_and_password(http_request)?;
    if user_email.is_empty() || user_password.len() < 8 {
        return Err(errors::invalid_email_and_password());
    }
    let user_password_with_salt = password_utils::password_with_salt(&state.salt, &user_password);
    let conn = state.pool.get().map_err(|_| errors::internal_error())?;
    let result = users
        .filter(email.eq(&user_email))
        .filter(password.eq(&user_password_with_salt))
        .first::<User>(&conn);
    match result {
        Ok(user) => {
            if user.email_verified {
                Ok(user.login)
            } else {
                Err(errors::email_not_verified())
            }
        }
        Err(_) => Err(errors::account_not_found()),
    }
}

async fn send_verification_email(
    state: &web::Data<Arc<State>>,
    login: &str,
    email: &str,
    token: &str,
) {
    send_email(
        state,
        login,
        email,
        "Polkahub email verification",
        &email_verification_text(token),
    )
    .await;
}

async fn send_password_reset_email(state: &web::Data<Arc<State>>, email: &str, token: &str) {
    send_email(
        state,
        "",
        email,
        "Polkahub password reset",
        &reset_password_text(token),
    )
    .await;
}

async fn send_email(
    state: &web::Data<Arc<State>>,
    login: &str,
    email: &str,
    subject: &str,
    text: &str,
) {
    let mut map = HashMap::new();
    map.insert("to", email);
    map.insert("subject", subject);
    map.insert("text", text);

    let _ = state
        .client
        .post(&state.mailgun_sender_config.mailgun_sender_api)
        .json(&map)
        .basic_auth(
            &state.mailgun_sender_config.mailgun_sender_api_user,
            Some(&state.mailgun_sender_config.mailgun_sender_api_password),
        )
        .send()
        .await
        .map_err(|e| {
            log::warn!(
                "can not sent email, login: {}, email: {}, reason: {}",
                &login,
                &email,
                e
            );
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "request to Mailgun Sender is failed",
            )
        });
}

fn email_verification_text(token: &str) -> String {
    format!(
        "Please open https://api.polkahub.org/api/v1/verify_email/{} for email verification.",
        token
    )
}

fn reset_password_text(token: &str) -> String {
    format!("Please use code: {} for reset password.", token)
}

fn normalize_limit(limit: Option<i64>) -> i64 {
    match limit {
        Some(l) if l > 0 && l <= 100 => l,
        _ => 100,
    }
}

fn normalize_offset(offset: Option<i64>) -> i64 {
    match offset {
        Some(o) if o > 0 => o,
        _ => 0,
    }
}

fn repo_name(login: &str, project_name: &str) -> String {
    format!("{}-{}", login, project_name)
}

fn repo_url(repo_name: &str, base_domain: &str) -> String {
    format!("https://git.{}/{}.git", base_domain, repo_name)
}

fn http_url(repo_name: &str, base_domain: &str) -> String {
    format!("https://{}-rpc.{}", repo_name, base_domain)
}

fn ws_url(repo_name: &str, base_domain: &str) -> String {
    format!("wss://{}.{}", repo_name, base_domain)
}
