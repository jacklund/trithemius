use clap::clap_app;
use futures::SinkExt;
use sodiumoxide::crypto::secretbox;
use std::net::ToSocketAddrs;
use tokio::io::{stdin, AsyncBufReadExt, BufReader, BufStream};
use tokio::net::TcpStream;
use tokio::select;
use tokio::stream::StreamExt;
use tokio_serde::formats::SymmetricalMessagePack;
use trithemius::Message;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize crypto
    sodiumoxide::init().unwrap();

    let matches = clap_app!(myapp =>
        (version: "0.1.0")
        (author: "Jack Lund <jackl@geekheads.net>")
        (about: "Encrypted chat")
        (@arg ADDR: +required "Address to connect to")
        (@arg NAME: +required "Name of user")
    )
    .get_matches();

    let password = rpassword::read_password_from_tty(Some("password: "))?;
    let key = trithemius::read_key_from_keyfile(&password)?;

    // println!("{:?}", key.as_ref());

    let socket_addr = matches
        .value_of("ADDR")
        .unwrap()
        .to_socket_addrs()?
        .next()
        .unwrap();

    // Connect to server
    let stream = TcpStream::connect(socket_addr).await?;

    // Set up terminal I/O
    let mut lines_from_stdin = BufReader::new(stdin()).lines().fuse();

    // Set up network I/O
    let buffered = BufStream::new(stream);
    let mut framed = tokio_serde::SymmetricallyFramed::new(
        tokio_util::codec::Framed::new(buffered.into_inner(), tokio_util::codec::BytesCodec::new()),
        SymmetricalMessagePack::<Message>::default(),
    );

    // Send identity
    framed
        .send(Message::Identity(matches.value_of("NAME").unwrap().into()))
        .await?;

    // Event loop
    loop {
        select! {
            // Read from network
            message_opt = framed.next() => match message_opt {
                Some(Ok(message)) => match message {
                    Message::ChatMessage { sender, recipients: _, message, nonce } => {
                        let plaintext = secretbox::open(&message, &secretbox::Nonce::from_slice(&nonce).unwrap(), &key).unwrap();
                        println!("from {}: {}", sender.unwrap(), std::str::from_utf8(&plaintext)?);
                    },
                    Message::ErrorMessage(error) => println!("error: {}", error),
                    something => panic!("Unexpected message: {:?}", something),
                },
                Some(Err(error)) => Err(error)?,
                None => break,
            },

            // Read from stdin
            line = lines_from_stdin.next() => match line {
                Some(line) => {
                    let line = line?;
                    // Parse the recipients
                    let (dest, msg) = match line.find(':') {
                        None => (None, line.to_string()), // No dest, broadcast
                        Some(idx) => (
                            Some(
                                line[..idx]
                                    .split(',')
                                    .map(|name| name.trim().to_string())
                                    .collect::<Vec<String>>(),
                            ),
                            line[idx + 1..].trim().to_string(),
                        ),
                    };
                    // Encrypt the message
                    let message = Message::new_chat_message(&key, dest, &msg);

                    // Send it
                    framed.send(message).await?;
                }
                None => break,
            }

        }
    }

    Ok(())
}
