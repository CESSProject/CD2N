pub mod client;

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_set_get_data() -> client::Result<()> {
        let mut conn =
            client::RedisConn::create_connection("redis://rwuser:rwuser_password@127.0.0.1/")
                .await?;
        conn.set_data("hello", "world!").await?;
        let result = conn.get_data("hello").await?;

        println!("{:?}", result);

        Ok(())
    }
}
