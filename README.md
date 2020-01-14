![alt text](https://github.com/akropolisio/polkahub-backend/blob/master/img/web3%20foundation_grants_badge_black.png "Project supported by web3 foundation grants program")

# Polkahub Backend

This is Polkahub Backend.

# Status

POC. Active development.

# Building

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Build:

```bash
cargo build
```

Prepare `.env` file with default environment variables:

```bash
cp .env.example .env
```

# Run

```bash
cargo run
```

# Environment variables description
SERVER_IP - IP address for binding, e.g. 127.0.0.1

SERVER_PORT - port for binding, e.g. 8080

BASE_DOMAIN - base domain where nodes will deploy, e.g. "example.org"

BASE_REPO_DIR - home directory for git repositories, e.g. "repo"

BASE_REPO_DOMAIN - base domain where git repositories storied, e.g. "example.org"

JENKINS_API - Jenkins API URL, e.g. "localhost:8080"

JENKINS_API_USER - Jenkins API user, e.g. "user"

JENKINS_API_TOKEN - Jenkins API token, e.g. "token"

JOB_NAME - Jenkins job name for building projects, e.g. "job"

DEPLOYER_API - Deployer API URL, e.g. "localhost:8081"

DEPLOYER_API_USER - Deployer API user, e.g. "user"

DEPLOYER_API_PASSWORD - Deployer API password, e.g. "password"

POSTGRES_HOST - Postgres host, e.g. 127.0.0.1

POSTGRES_PORT - Postgres port, e.g. 5432

POSTGRES_DATABASE - Postgres database name, e.g. polkahub

POSTGRES_USER - Postgres user, e.g. polkahub

POSTGRES_PASSWORD - Postgres password, e.g. password

POSTGRES_SALT - Postgres salt, e.g. salt

JWT_SECRET - JWT secret, e.g. secret
