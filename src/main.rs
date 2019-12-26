use actix_web::{client, middleware, web, App, Error, HttpResponse, HttpServer, Responder};
use askama::Template;
use dotenv::dotenv;
use serde_derive::Deserialize;
use serde_json::json;
use tokio::{self, fs::File, io::AsyncWriteExt, net::process::Command};

use std::collections::HashMap;
use std::env;
use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;

const FIND_URL1: &str = "https://registry.polkahub.org/v2/";
const FIND_URL2: &str = "/tags/list";

#[derive(Debug)]
struct State {
    base_domain: String,
    base_repo_dir: String,
    base_repo_domain: String,
    jenkins_config: JenkinsConfig,
    deployer_config: DeployerConfig,
    db: HashMap<u64, String>,
}

#[derive(Debug)]
struct JenkinsConfig {
    jenkins_api: String,
    jenkins_api_user: String,
    jenkins_api_token: String,
    job_name: String,
}

#[derive(Debug)]
struct DeployerConfig {
    deployer_api: String,
    deployer_api_user: String,
    deployer_api_password: String,
}

#[derive(Debug, Deserialize)]
struct CreateProjectRequest {
    account_id: u64,
    project_name: String,
}
#[derive(Debug, Deserialize)]
struct FindProjectRequest {
    account_id: u64,
    project_name: String,
}
#[derive(Debug, Default, Deserialize)]
struct FoundProject {
    name: String,
    tags: Vec<String>,
}
#[derive(Debug, Deserialize)]
struct InstallProjectRequest {
    account_id: u64,
    project_name: String,
    version: String,
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
) -> impl Responder {
    handle_create_project(data, create_project_request).await
}
async fn find_project(
    data: web::Data<Arc<State>>,
    find_project_request: web::Json<FindProjectRequest>,
) -> impl Responder {
    handle_find_project(data, find_project_request).await
}
async fn install_project(
    data: web::Data<Arc<State>>,
    install_project_request: web::Json<InstallProjectRequest>,
) -> impl Responder {
    handle_install_project(data, install_project_request).await
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
        jenkins_api,
        jenkins_api_user,
        jenkins_api_token,
        job_name,
        deployer_api,
        deployer_api_user,
        deployer_api_password,
    ) = read_env();

    let mut db = HashMap::new();
    db.insert(1u64, "akropolis".to_string());

    let state = Arc::new(State {
        base_domain,
        base_repo_dir,
        base_repo_domain,
        jenkins_config: JenkinsConfig {
            jenkins_api,
            jenkins_api_user,
            jenkins_api_token,
            job_name,
        },
        deployer_config: DeployerConfig {
            deployer_api,
            deployer_api_user,
            deployer_api_password,
        },
        db,
    });

    HttpServer::new(move || {
        App::new()
            .data(state.clone())
            .route("/api/v1/projects", web::post().to(create_project))
            .route("/api/v1/find", web::post().to(find_project))
            .route("/api/v1/install", web::post().to(install_project))
            .default_service(web::route().to(HttpResponse::NotFound))
            .wrap(middleware::Logger::default())
    })
    .bind(format!("{}:{}", ip, port))?
    .workers(workers)
    .start()
    .await
}

fn read_env() -> (
    String,
    u64,
    usize,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
) {
    (
        env::var("SERVER_IP").expect("can not read SERVER_IP"),
        env::var("SERVER_PORT")
            .expect("can not read SERVER_PORT")
            .parse()
            .expect("can not parse server port"),
        env::var("SERVER_WORKERS")
            .unwrap_or_else(|_| "1".to_string())
            .parse()
            .expect("can not parse server workres"),
        env::var("BASE_DOMAIN").expect("can not read BASE_DOMAIN"),
        env::var("BASE_REPO_DIR").expect("can not read BASE_REPO_DIR"),
        env::var("BASE_REPO_DOMAIN").expect("can not read BASE_REPO_DOMAIN"),
        env::var("JENKINS_API").expect("can not read JENKINS_API"),
        env::var("JENKINS_API_USER").expect("can not read JENKINS_API_USER"),
        env::var("JENKINS_API_TOKEN").expect("can not read JENKINS_API_TOKEN"),
        env::var("JOB_NAME").expect("can not read JOB_NAME"),
        env::var("DEPLOYER_API").expect("can not read DEPLOYER_API"),
        env::var("DEPLOYER_API_USER").expect("can not read DEPLOYER_API_USER"),
        env::var("DEPLOYER_API_PASSWORD").expect("can not read DEPLOYER_API_PASSWORD"),
    )
}

async fn handle_create_project(
    state: web::Data<Arc<State>>,
    request: web::Json<CreateProjectRequest>,
) -> impl Responder {
    if let Some(account_name) = state.db.get(&request.account_id) {
        let repo_name = repo_name(account_name, &request.project_name);
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
                _ => json!({
                    "status": "error",
                    "reason": format!("can not create repository directory: {}", error)
                })
                .to_string(),
            },
        }
    } else {
        json!({
            "status": "error",
            "reason": "account not found"
        })
        .to_string()
    }
}

async fn handle_find_project(
    state: web::Data<Arc<State>>,
    request: web::Json<FindProjectRequest>,
) -> impl Responder {
    if let Some(account_name) = state.db.get(&request.account_id) {
        let repo_name = repo_name(account_name, &request.project_name);
        let versions = check_versions(&repo_name).await;
        match versions {
            Ok(v) => json!({
                "status": "ok",
                "payload": v,
            })
            .to_string(),
            Err(_) => json!({
                "status": "error",
                "reason": "failed to find project"
            })
            .to_string(),
        }
    } else {
        json!({
            "status": "error",
            "reason": "account not found"
        })
        .to_string()
    }
}

async fn handle_install_project(
    state: web::Data<Arc<State>>,
    request: web::Json<InstallProjectRequest>,
) -> impl Responder {
    let (name, v, id) = (&request.project_name, &request.version, request.account_id);
    if let Some(account_name) = state.db.get(&id) {
        let repo_name = repo_name(account_name, &name);
        match execute_deploy(
            &repo_name,
            &v,
            &state.jenkins_config,
            &state.deployer_config,
        )
        .await
        {
            Ok(_) => build_create_project_response(
                false,
                &repo_name,
                &state.base_domain,
                &state.base_repo_domain,
            ),
            Err(_) => json!({
                "status": "error",
                "reason": &format!("failed to deploy {} with version {}", name, v),
            })
            .to_string(),
        }
    } else {
        json!({
            "status": "error",
            "reason": "account not found"
        })
        .to_string()
    }
}

fn repo_name(account_name: &str, project_name: &str) -> String {
    format!("{}-{}", account_name, project_name)
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
    version: &str,
    jenkins_config: &JenkinsConfig,
    deployer_config: &DeployerConfig,
) -> Result<(), std::io::Error> {
    let params = build_jenkins_params(repo_name, version, deployer_config);
    let user = &format!("{}:{}", &jenkins_config.jenkins_api_user, &jenkins_config.jenkins_api_token);
    let url = &format!("{}/job/deploy-fixed-version/build", &jenkins_config.jenkins_api);
    let json = &format!("json={}", params);
    let args = &[url, "-X", "POST", "-u", user, "--data-urlencode", json];
    let status = Command::new("curl")
        .args(args)
        .status()
        .await?;
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

fn repo_url(repo_name: &str, base_domain: &str) -> String {
    format!("https://git.{}/{}.git", base_domain, repo_name)
}

fn http_url(repo_name: &str, base_domain: &str) -> String {
    format!("https://{}-rpc.{}", repo_name, base_domain)
}

fn ws_url(repo_name: &str, base_domain: &str) -> String {
    format!("wss://{}.{}", repo_name, base_domain)
}

fn build_jenkins_params(repo_name: &str, v: &str, deployer_config: &DeployerConfig) -> String {
    json!({
        "parameter": [
            {"name":"VERSION", "value": v},
            {"name":"REPO_NAME", "value": repo_name},
            {"name":"DEPLOYER_API", "value": deployer_config.deployer_api},
            {"name":"DEPLOYER_API_USER", "value": deployer_config.deployer_api_user},
            {"name":"DEPLOYER_API_PASSWORD", "value": deployer_config.deployer_api_password}]
    })
    .to_string()
}
