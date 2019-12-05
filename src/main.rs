use actix_web::{middleware, web, App, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use serde_derive::Deserialize;
use serde_json::json;

use std::collections::HashMap;
use std::env;
use std::fmt::Debug;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

#[derive(Debug)]
struct State {
    base_domain: String,
    base_repo_dir: String,
    db: HashMap<u64, String>,
}

#[derive(Debug, Deserialize)]
struct CreateProjectRequest {
    account_id: u64,
    project_name: String,
}

async fn create_project(
    data: web::Data<Arc<State>>,
    create_project_request: web::Json<CreateProjectRequest>,
) -> impl Responder {
    handle_create_project(data, create_project_request)
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv().ok();

    let (ip, port, workers, base_domain, base_repo_dir) = read_env();

    let mut db = HashMap::new();
    db.insert(1u64, "akropolis".to_string());

    let state = Arc::new(State {
        base_domain,
        base_repo_dir,
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

fn read_env() -> (String, u64, usize, String, String) {
    (
        env::var("SERVER_IP").expect("can not read SERVER_IP"),
        env::var("SERVER_PORT")
            .expect("can not read SERVER_PORT")
            .parse()
            .expect("can not parse server port"),
        env::var("SERVER_WORKERS")
            .unwrap_or_else(|_| "1".to_string())
            .parse()
            .unwrap_or_else(|_| 1),
        env::var("BASE_DOMAIN").expect("can not read BASE_DOMAIN"),
        env::var("BASE_REPO_DIR").expect("can not read BASE_REPO_DIR"),
    )
}

fn handle_create_project(
    state: web::Data<Arc<State>>,
    request: web::Json<CreateProjectRequest>,
) -> impl Responder {
    if let Some(account_name) = state.db.get(&request.account_id) {
        let repo_name = repo_name(account_name, &request.project_name);
        match init_repo(&repo_name, &state.base_repo_dir) {
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

fn init_repo(repo_name: &str, base_repo_dir: &str) -> Result<(), std::io::Error> {
    let repo_dir_name = format!("{}.git", repo_name);
    let repo_path = Path::new(base_repo_dir).join(repo_dir_name);
    std::fs::create_dir(&repo_path)?;
    execute_command("git", &["--bare", "init"], &repo_path)?;
    execute_command("git", &["update-server-info"], &repo_path)?;
    execute_command(
        "git",
        &["config", "--file", "config", "http.receivepack", "true"],
        &repo_path,
    )?;
    Ok(())
}

fn execute_command<P: AsRef<Path> + Debug>(
    command: &str,
    args: &[&str],
    current_dir: P,
) -> Result<(), std::io::Error> {
    let status = Command::new(command)
        .args(args)
        .current_dir(&current_dir)
        .status()?;
    log::info!(
        "executed {} {:?}, current_dir: {:?}, exit_code: {}",
        command,
        args,
        current_dir,
        status
    );
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
