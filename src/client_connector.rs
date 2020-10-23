use crate::{keyring::Key, FramedConnection, Message, Result};
use futures::StreamExt;
use sodiumoxide::crypto::secretbox;
use std::net::SocketAddr;
use tokio::io::{stdin, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::select;

pub struct ClientConnector {
    sender: FramedConnection<TcpStream>,
}

impl ClientConnector {
    pub async fn connect(socket_addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            // Connect to server
            sender: FramedConnection::new(TcpStream::connect(socket_addr).await?),
        })
    }

    pub async fn handle_events(mut self, name: &str, key: &Key) -> Result<()> {
        // Set up terminal I/O
        let mut lines_from_stdin = BufReader::new(stdin()).lines().fuse();

        // Send identity
        self.sender.send(Message::Identity(name.into())).await?;

        // Event loop
        loop {
            select! {
                // Read from network
                message_opt = self.sender.next() => {
                    match message_opt {
                        Some(result) => Self::handle_network_message(&key, result).await?,
                        None => break,
                    }
                },

                // Read from stdin
                line = lines_from_stdin.next() => match line {
                    Some(line) => self.sender.send(Self::parse_line(line?, &key)).await?,
                    None => break,
                }

            }
        }

        Ok(())
    }

    async fn handle_network_message(key: &Key, result: Result<Message>) -> Result<()> {
        match result {
            Ok(message) => match message {
                Message::ChatMessage {
                    sender,
                    recipients: _,
                    message,
                    nonce,
                } => {
                    let nonce_object = match secretbox::Nonce::from_slice(&nonce) {
                        Some(nonce) => nonce,
                        None => Err("Unable to create nonce from bytes in message")?,
                    };
                    match secretbox::open(&message, &nonce_object, &key.get_key()) {
                        Ok(plaintext) => {
                            println!(
                                "from {}: {}",
                                sender.unwrap_or("unknown sender".into()),
                                std::str::from_utf8(&plaintext)?
                            );
                            Ok(())
                        }
                        Err(_) => Err(format!("Error decrypting message"))?,
                    }
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
