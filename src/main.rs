#[macro_use]
extern crate diesel;

use actix_web::{client, middleware, web, App, Error, HttpResponse, HttpServer, Responder};
use askama::Template;
use base64;
use chrono::Utc;
use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use dotenv::dotenv;
use reqwest::Client;
use serde_derive::Deserialize;
use serde_json::json;
use tokio::{self, fs::File, io::AsyncWriteExt, process::Command};

use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;

mod config;
mod database;
mod errors;
mod login_utils;
mod models;
mod password_utils;
mod schema;
mod token;

use config::{DatabaseConfig, DeployerConfig, JenkinsConfig};

const FIND_URL1: &str = "https://registry.polkahub.org/v2/";
const FIND_URL2: &str = "/tags/list";

struct State {
    base_domain: String,
    base_repo_dir: String,
    base_repo_domain: String,
    jenkins_config: JenkinsConfig,
    deployer_config: DeployerConfig,
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
    project_name: String,
}

#[derive(Debug, Default, Deserialize)]
struct FoundProject {
    name: String,
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct InstallProjectRequest {
    app_name: String,
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
            .route("/api/v1/install", web::post().to(install_project))
            .route("/api/v1/signup", web::post().to(signup))
            .route("/api/v1/login", web::post().to(login))
            .route("/api/v1/git_auth", web::get().to(git_auth))
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
    let repo_name = repo_name(&login, &request.project_name);
    match init_repo(
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
    let _login = match get_login_by_token(state.clone(), http_request) {
        Ok(login) => login,
        Err(err) => return err,
    };
    let login = "akropolis";
    let repo_name = repo_name(login, &request.project_name);
    let versions = check_versions(&repo_name).await;
    match versions {
        Ok(v) => json!({
            "status": "ok",
            "payload": v,
        })
        .to_string(),
        Err(_) => errors::failed_to_find_project(),
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
    let account_name = "akropolis";
    let (project_name, app_name, v) = (&request.project_name, &request.app_name, &request.version);
    let app_url = repo_name(&login, &app_name);
    let repo_name = repo_name(&account_name, &project_name);
    match execute_deploy(
        &repo_name,
        &app_name,
        &v,
        &state.client,
        &state.jenkins_config,
        &state.deployer_config,
    )
    .await
    {
        Ok(_) => build_install_project_response(&app_url, &state.base_domain),
        Err(_) => errors::failed_to_deploy_project(app_name, v),
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
    let new_user = models::NewUser {
        login: &login_utils::login(),
        email: &request.email,
        password: &password_with_salt,
    };
    let result = diesel::insert_into(schema::users::table)
        .values(new_user)
        .execute(&conn);
    match result {
        Ok(_) => {
            log::info!("created new user, email: {}", &request.email);
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
                Ok(_) => json!({ "status": "ok", "token": token }).to_string(),
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

fn repo_name(login: &str, project_name: &str) -> String {
    format!("{}-{}", login, project_name)
}

/// check what versions of a project already exist
/// return array of strings or empty vector if none
async fn check_versions(name: &str) -> Result<Vec<String>, Error> {
    let body = get_request(&format!("{}{}{}", FIND_URL1, name, FIND_URL2)).await?;
    let found: FoundProject = match serde_json::from_slice(&body) {
        Ok(f) => f,
        Err(_) => FoundProject::default(),
    };

    Ok(found.tags)
}

async fn init_repo(
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
    execute_command("chown", &["-R", "service.www-data", "."], &repo_path).await?;
    execute_command("chmod", &["-R", "775", "."], &repo_path).await?;
    rewrite_description(&repo_path, &repo_name).await?;
    add_git_hook(jenkins_config, deployer_config, &repo_path).await?;
    execute_command("chmod", &["+x", "hooks/update"], &repo_path).await?;
    Ok(())
}

async fn execute_deploy(
    repo_name: &str,
    app_name: &str,
    version: &str,
    client: &Client,
    jenkins_config: &JenkinsConfig,
    deployer_config: &DeployerConfig,
) -> Result<(), std::io::Error> {
    let params = [(
        "json",
        build_jenkins_params(repo_name, app_name, version, deployer_config),
    )];
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
    repo_name: &str,
    app_name: &str,
    version: &str,
    deployer_config: &DeployerConfig,
) -> String {
    json!({
        "parameter": [
            {"name":"VERSION", "value": version},
            {"name":"APP_NAME", "value": app_name},
            {"name":"REPO_NAME", "value": repo_name},
            {"name":"DEPLOYER_API", "value": deployer_config.deployer_api},
            {"name":"DEPLOYER_API_USER", "value": deployer_config.deployer_api_user},
            {"name":"DEPLOYER_API_PASSWORD", "value": deployer_config.deployer_api_password}]
    })
    .to_string()
}

async fn get_request(url: &str) -> Result<web::Bytes, Error> {
    let client = client::Client::new();
    let mut response = client
        .get(url)
        .header("User-Agent", "Actix-web")
        .send()
        .await?;

    let body = response.body().await?;
    Ok(body)
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

fn repo_url(repo_name: &str, base_domain: &str) -> String {
    format!("https://git.{}/{}.git", base_domain, repo_name)
}

fn http_url(repo_name: &str, base_domain: &str) -> String {
    format!("https://{}-rpc.{}", repo_name, base_domain)
}

fn ws_url(repo_name: &str, base_domain: &str) -> String {
    format!("wss://{}.{}", repo_name, base_domain)
}
