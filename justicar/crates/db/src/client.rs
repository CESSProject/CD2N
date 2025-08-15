use redis::{
    aio::{ConnectionManager, ConnectionManagerConfig},
    AsyncCommands, Connection,
};
pub type Result<T> = redis::RedisResult<T>;
pub type Error = redis::RedisError;

pub struct RedisConn {
    conn: ConnectionManager,
}

impl RedisConn {
    pub async fn create_connection(url: &str) -> Result<RedisConn> {
        // connect to redis
        let client = redis::Client::open(url)?;
        let config = ConnectionManagerConfig::new();
        let conn = client.get_connection_manager_with_config(config).await?;

        Ok(Self { conn })
    }

    pub async fn get_data(&mut self, key: &str) -> Result<Option<String>> {
        self.conn.get(key).await
    }

    pub async fn set_data(&mut self, key: &str, value: &str) -> Result<()> {
        self.conn.set(key, value).await
    }
}
