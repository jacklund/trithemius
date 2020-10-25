use crate::{keyring, FramedConnection, Message, Result};
use futures::StreamExt;
use sodiumoxide::crypto::secretbox;
use tokio::io::{stdin, AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::select;

pub struct ClientConnector<T: AsyncRead + AsyncWrite + std::marker::Unpin> {
    sender: FramedConnection<T>,
    identity: keyring::Identity,
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> ClientConnector<T> {
    pub async fn connect(stream: T, identity: &keyring::Identity) -> Result<Self> {
        Ok(Self {
            // Connect to server
            sender: FramedConnection::new(stream),
            identity: identity.clone(),
        })
    }

    pub async fn send_identity(&mut self) -> Result<()> {
        Ok(self
            .sender
            .send(Message::Identity(self.identity.name.clone()))
            .await?)
    }

    pub async fn send_message(&mut self, message: Message) -> Result<()> {
        Ok(self.sender.send(message).await?)
    }

    pub async fn next_message(&mut self) -> Option<Result<Message>> {
        self.sender.next().await.map(|r| r.map_err(|e| e))
    }

    pub async fn handle_events(mut self, key: &keyring::Key) -> Result<()> {
        // Set up terminal I/O
        let mut lines_from_stdin = BufReader::new(stdin()).lines().fuse();

        self.send_identity().await?;

        // Event loop
        loop {
            select! {
                // Read from network
                message_opt = self.next_message() => {
                    match message_opt {
                        Some(result) => Self::handle_network_message(&key, result?).await?,
                        None => break,
                    }
                },

                // Read from stdin
                line = lines_from_stdin.next() => match line {
                    Some(line) => self.send_message(Self::parse_line(line?, &key)).await?,
                    None => break,
                }

            }
        }

        Ok(())
    }

    async fn handle_network_message(key: &keyring::Key, message: Message) -> Result<()> {
        match message {
            Message::ChatMessage {
                sender,
                recipients: _,
                message,
                nonce,
            } => match secretbox::open(&message, &nonce, &key.get_key()) {
                Ok(plaintext) => {
                    println!(
                        "from {}: {}",
                        sender.unwrap_or("unknown sender".into()),
                        std::str::from_utf8(&plaintext)?
                    );
                    Ok(())
                }
                Err(_) => Err(format!("Error decrypting message"))?,
            },
            Message::ErrorMessage(error) => {
                println!("error: {}", error);
                Ok(())
            }
            something => panic!("Unexpected message: {:?}", something),
        }
    }

    fn parse_line(line: String, key: &keyring::Key) -> Message {
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
