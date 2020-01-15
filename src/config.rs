use std::env;

#[derive(Debug)]
pub(crate) struct JenkinsConfig {
    pub jenkins_api: String,
    pub jenkins_api_user: String,
    pub jenkins_api_token: String,
    pub job_name: String,
}

#[derive(Debug)]
pub(crate) struct DeployerConfig {
    pub deployer_api: String,
    pub deployer_api_user: String,
    pub deployer_api_password: String,
}

#[derive(Debug)]
pub(crate) struct DatabaseConfig {
    pub host: String,
    pub port: u32,
    pub database: String,
    pub user: String,
    pub password: String,
    pub salt: String,
    pub pool_size: u32,
}

pub(crate) fn read_env() -> (
    String,
    u64,
    usize,
    String,
    String,
    String,
    String,
    JenkinsConfig,
    DeployerConfig,
    DatabaseConfig,
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
        env::var("JWT_SECRET").expect("can not read JWT_SECRET"),
        read_jenkins_env(),
        read_deployer_env(),
        read_database_env(),
    )
}

fn read_jenkins_env() -> JenkinsConfig {
    JenkinsConfig {
        jenkins_api: env::var("JENKINS_API").expect("can not read JENKINS_API"),
        jenkins_api_user: env::var("JENKINS_API_USER").expect("can not read JENKINS_API_USER"),
        jenkins_api_token: env::var("JENKINS_API_TOKEN").expect("can not read JENKINS_API_TOKEN"),
        job_name: env::var("JOB_NAME").expect("can not read JOB_NAME"),
    }
}

fn read_deployer_env() -> DeployerConfig {
    DeployerConfig {
        deployer_api: env::var("DEPLOYER_API").expect("can not read DEPLOYER_API"),
        deployer_api_user: env::var("DEPLOYER_API_USER").expect("can not read DEPLOYER_API_USER"),
        deployer_api_password: env::var("DEPLOYER_API_PASSWORD")
            .expect("can not read DEPLOYER_API_PASSWORD"),
    }
}

fn read_database_env() -> DatabaseConfig {
    DatabaseConfig {
        host: env::var("POSTGRES_HOST").expect("can not read POSTGRES_HOST"),
        port: env::var("POSTGRES_PORT")
            .expect("can not read POSTGRES_PORT")
            .parse()
            .expect("can not parse POSTGRES_PORT"),
        database: env::var("POSTGRES_DATABASE").expect("can not read POSTGRES_DATABASE"),
        user: env::var("POSTGRES_USER").expect("can not read POSTGRES_USER"),
        password: env::var("POSTGRES_PASSWORD").expect("can not read POSTGRES_PASSWORD"),
        salt: env::var("POSTGRES_SALT").expect("can not read POSTGRES_SALT"),
        pool_size: env::var("POSTGRES_POOL_SIZE")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .expect("can not parse POSTGRES_POOL_SIZE"),
    }
}
