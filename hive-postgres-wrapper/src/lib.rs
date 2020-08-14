use tokio_postgres::{NoTls, Error};

#[tokio::main] // By default, tokio_postgres uses the tokio crate as its runtime.
async fn main() -> Result<(), Error> {
    // Connect to the database.
    //TODO handle error
    let (client, connection) =
        tokio_postgres::connect("host=localhost user=postgres", NoTls).await.unwrap();

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    // Now we can execute a simple statement that just returns its parameter.
    //TODO handle error
    let rows = client
        .query("SELECT $1::TEXT", &[&"hello world"])
        .await.unwrap();

    client.batch_execute("CREATE TABLE accounts ()").await?;

    // And then check that we got back the same string we sent over.
    let value: &str = rows[0].get(0);
    assert_eq!(value, "hello world");

    Ok(())
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
