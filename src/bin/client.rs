use clap::clap_app;
use std::net::ToSocketAddrs;
use tokio::io::{stdin, AsyncBufReadExt, AsyncWriteExt, BufReader, BufStream};
use tokio::net::TcpStream;
use tokio::select;
use tokio::stream::StreamExt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    sodiumoxide::init().unwrap();
    let matches = clap_app!(myapp =>
        (version: "0.1.0")
        (author: "Jack Lund <jackl@geekheads.net>")
        (about: "Encrypted chat")
        (@arg ADDR: +required "Address to connect to")
    )
    .get_matches();

    let password = rpassword::read_password_from_tty(Some("password: "))?;
    let key = trithemius::read_key_from_keyfile(&password)?;

    println!("{:?}", key.as_ref());

    let socket_addr = matches
        .value_of("ADDR")
        .unwrap()
        .to_socket_addrs()?
        .next()
        .unwrap();

    // Connect to server
    let stream = TcpStream::connect(socket_addr).await?;

    // Set up I/O
    let mut buffered = BufStream::new(stream);
    let mut line = String::new();
    let mut lines_from_stdin = BufReader::new(stdin()).lines().fuse();

    // Event loop
    loop {
        select! {
            // Read from network
            result = buffered.read_line(&mut line) => {
                match result {
                    Ok(0) => break,
                    Ok(_) => print!("{}", line),
                    Err(error) => Err(error)?,
                };
            },

            // Read from stdin
            line = lines_from_stdin.next() => match line {
                Some(line) => {
                    let line = line?;
                    buffered.write_all(line.as_bytes()).await?;
                    buffered.write_all(b"\n").await?;
                    buffered.flush().await?;
                }
                None => break,
            }

        }
    }

    Ok(())
}
