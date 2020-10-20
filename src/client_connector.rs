use crate::{keyring::Key, Message, Result};
use futures::{SinkExt, StreamExt};
use sodiumoxide::crypto::secretbox;
use std::net::SocketAddr;
use tokio::io::{stdin, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::select;
use tokio_serde::formats::SymmetricalMessagePack;

pub struct ClientConnector {
    stream: TcpStream,
}

impl ClientConnector {
    pub async fn connect(socket_addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            // Connect to server
            stream: TcpStream::connect(socket_addr).await?,
        })
    }

    pub async fn handle_events(self, key: &Key) -> Result<()> {
        // Set up terminal I/O
        let mut lines_from_stdin = BufReader::new(stdin()).lines().fuse();

        // Set up network I/O
        let mut framed = tokio_serde::SymmetricallyFramed::new(
            tokio_util::codec::Framed::new(self.stream, tokio_util::codec::BytesCodec::new()),
            SymmetricalMessagePack::<Message>::default(),
        );

        // Send identity
        framed.send(Message::Identity(key.get_name())).await?;

        // Event loop
        loop {
            select! {
                // Read from network
                message_opt = framed.next() => {
                    match message_opt {
                        Some(result) => Self::handle_network_message(&key, result).await?,
                        None => break,
                    }
                },

                // Read from stdin
                line = lines_from_stdin.next() => match line {
                    Some(line) => framed.send(Self::parse_line(line?, &key)).await?,
                    None => break,
                }

            }
        }

        Ok(())
    }

    async fn handle_network_message(key: &Key, result: tokio::io::Result<Message>) -> Result<()> {
        match result {
            Ok(message) => match message {
                Message::ChatMessage {
                    sender,
                    recipients: _,
                    message,
                    nonce,
                } => {
                    let plaintext = secretbox::open(
                        &message,
                        &secretbox::Nonce::from_slice(&nonce).unwrap(),
                        &key.get_key(),
                    )
                    .unwrap();
                    println!(
                        "from {}: {}",
                        sender.unwrap(),
                        std::str::from_utf8(&plaintext)?
                    );
                    Ok(())
                }
                Message::ErrorMessage(error) => {
                    println!("error: {}", error);
                    Ok(())
                }
                something => panic!("Unexpected message: {:?}", something),
            },
            Err(error) => Err(error)?,
        }
    }

    fn parse_line(line: String, key: &Key) -> Message {
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
        Message::new_chat_message(&key.get_key(), dest, &msg)
    }
}
