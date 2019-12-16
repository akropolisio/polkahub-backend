use actix_web::{middleware, web, App, HttpResponse, HttpServer, Responder};
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

#[derive(Debug)]
struct State {
    base_domain: String,
    base_repo_dir: String,
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
            Ok(()) => build_create_project_response(true, &repo_name, &state.base_domain),
            Err(error) => match error.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    build_create_project_response(false, &repo_name, &state.base_domain)
                }
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

fn repo_name(account_name: &str, project_name: &str) -> String {
    format!("{}-{}", account_name, project_name)
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
) -> String {
    json!({
        "status": "ok",
        "payload": {
            "repository_created": repository_created,
            "repo_url": repo_url(repo_name, base_domain),
            "http_url": http_url(repo_name, base_domain),
            "ws_url": ws_url(repo_name, base_domain)
        }
    })
    .to_string()
}

fn repo_url(repo_name: &str, base_domain: &str) -> String {
    format!("https://git.{}/{}.git", base_domain, repo_name)
}

fn http_url(repo_name: &str, base_domain: &str) -> String {
    format!("https://{}.chain.{}:8443", repo_name, base_domain)
}

fn ws_url(repo_name: &str, base_domain: &str) -> String {
    format!("wss://{}.chain.{}", repo_name, base_domain)
}
