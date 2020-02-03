use super::DatabaseConfig;
use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};

pub(crate) fn create_pool(config: &DatabaseConfig) -> Pool<ConnectionManager<PgConnection>> {
    let connection_string = format!(
        "host={} port={} user={} password={}",
        config.host, config.port, config.user, config.password
    );
    let manager = ConnectionManager::new(connection_string);
    Pool::builder()
        .max_size(config.pool_size)
        .build(manager)
        .expect("can not connection to database")
}
