use clap::clap_app;
use futures::stream::StreamExt;
use futures::{SinkExt, Stream};
use slog::{error, info, o, Drain, Logger};
use std::collections::{hash_map::Entry, HashMap};
use std::future::Future;
use std::net::ToSocketAddrs;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::mpsc;
use tokio::task;
use tokio_serde::formats::SymmetricalMessagePack;
use trithemius::{Message, Receiver, Result, Sender};

type PeerMap = HashMap<String, Sender<Message>>;

#[derive(Debug)]
enum Event {
    NewPeer {
        client_id: ClientIdentity,
        sender: Sender<Message>,
    },
    PeerDisconnected {
        name: String,
    },
    Message(Message),
}

#[derive(Clone, Debug)]
struct ClientIdentity {
    name: String,
    fingerprint: String,
}

// Need this so that I can substitute a UnixListener or TcpListener
macro_rules! server_event_loop {
    ($listener:expr, $addr:expr, $log:expr) => {
        // Set up broker
        let broker_sender = run_broker_loop();

        loop {
            let (stream, _socket_addr) = $listener.accept().await?;
            info!($log, "Accepting from: {:?}", stream.peer_addr()?);
            spawn_and_log_error(handle_connection(
                $log.new(o!()),
                broker_sender.clone(),
                stream,
            ));
        }
    };
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = clap_app!(myapp =>
        (version: "0.1.0")
        (author: "Jack Lund <jackl@geekheads.net>")
        (about: "Encrypted chat")
        (@arg ADDR: +required "Address to listen on")
    )
    .get_matches();

    let socket_addr = match matches.value_of("ADDR").unwrap().to_socket_addrs()?.next() {
        Some(socket_addr) => socket_addr,
        None => Err("Unable to parse ADDR as socket address")?,
    };

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, o!());

    let listener = TcpListener::bind(socket_addr).await?;
    server_event_loop!(listener, socket_addr, log);
}

fn run_broker_loop() -> Sender<Event> {
    let (broker_sender, broker_receiver) = mpsc::unbounded_channel();
    spawn_and_log_error(broker_loop(broker_receiver));

    broker_sender
}

fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        if let Err(e) = fut.await {
            eprintln!("{}", e)
        }
    })
}

async fn read_client_identity<R>(log: &Logger, framed: &mut R) -> Result<ClientIdentity>
where
    R: Stream<Item = std::result::Result<Message, std::io::Error>> + std::marker::Unpin,
{
    match framed.next().await {
        Some(Ok(Message::Identity { name, fingerprint })) => {
            Ok(ClientIdentity { name, fingerprint })
        }
        Some(Ok(something)) => {
            error!(log, "Got unexpected message {:?}, disconnecting", something);
            Err("Unexpected message type")?
        }
        Some(Err(error)) => Err(error)?,
        None => Err("Client disconnected")?,
    }
}

async fn handle_connection<T: AsyncRead + AsyncWrite + std::marker::Unpin>(
    log: Logger,
    broker: Sender<Event>,
    stream: T,
) -> Result<()> {
    // Set up network I/O
    let mut framed = tokio_serde::SymmetricallyFramed::new(
        tokio_util::codec::Framed::new(stream, tokio_util::codec::BytesCodec::new()),
        SymmetricalMessagePack::<Message>::default(),
    );

    // Read client name
    let client_id = read_client_identity(&log, &mut framed).await?;
    info!(log, "{} connected", client_id.name);

    // Inform broker of new client
    let (sender, mut receiver) = mpsc::unbounded_channel();
    match broker.send(Event::NewPeer {
        client_id: client_id.clone(),
        sender,
    }) {
        Ok(_) => (),
        Err(error) => Err(error)?,
    };

    // Event loop
    loop {
        select! {
            // Handle message coming from client
            message_opt = framed.next() => {
                match message_opt {
                    Some(Ok(message)) => match message {
                        // TODO: Handle name-change message (see below)
                        Message::ErrorMessage(_) => broker.send(Event::Message(message))?,
                        Message::ChatMessage{ sender: _, recipients, message, nonce } =>
                            broker.send(Event::Message(Message::ChatMessage{ sender: Some(client_id.name.clone()), recipients, message, nonce }))?,
                        something => panic!("Unexpected message {:?}", something),
                    },
                    Some(Err(error)) => Err(error)?,
                    None => break,
                };
            },

            // Handle message from broker
            message_opt = receiver.recv() => match message_opt {
                // Send IdentityTaken and disconnect
                Some(message @ Message::IdentityTaken { .. }) => {
                    framed.send(message).await?;
                    break;
                }
                Some(message) => framed.send(message).await?,
                None => break,
            },
        }
    }

    match broker.send(Event::PeerDisconnected {
        name: client_id.name.clone(),
    }) {
        Ok(_) => (),
        Err(error) => Err(error)?,
    };
    drop(broker);
    info!(log, "{} disconnected", client_id.name);

    Ok(())
}

fn add_peer(
    peers: &mut PeerMap,
    client_id: ClientIdentity,
    sender: Sender<Message>,
) -> Result<bool> {
    match peers.entry(client_id.name.clone()) {
        Entry::Occupied(..) => {
            sender.send(Message::IdentityTaken {
                name: client_id.name.clone(),
            })?;
            Ok(false)
        }
        Entry::Vacant(entry) => {
            // TODO: Send new peer message to all connected clients
            entry.insert(sender);
            Ok(true)
        }
    }
}

async fn broker_loop(mut events: Receiver<Event>) -> Result<()> {
    let mut peers = PeerMap::new();

    while let Some(event) = events.next().await {
        match event {
            Event::Message(message) => handle_chat_message(&mut peers, &message)?,
            Event::NewPeer { client_id, sender } => {
                if !add_peer(&mut peers, client_id, sender)? {
                    break;
                }
            }
            Event::PeerDisconnected { name } => {
                peers.remove(&name);
                for sender in peers.values() {
                    sender.send(Message::ErrorMessage(format!(
                        "client {} disconnected",
                        name
                    )))?;
                }
            }
        }
    }

    drop(peers);

    Ok(())
}

fn handle_chat_message(peers: &mut PeerMap, message: &Message) -> Result<()> {
    match message {
        Message::ChatMessage {
            ref sender,
            ref recipients,
            message: ref _msg,
            nonce: ref _nonce,
        } => {
            match recipients {
                // Send to recipients directly
                Some(recipients) => {
                    for addr in recipients {
                        match peers.get_mut(addr) {
                            Some(peer) => peer.send(message.clone())?,
                            None => {
                                // Notify sender that one of the recipients wasn't found
                                if let Some(sender) = peers.get_mut(&sender.clone().unwrap()) {
                                    sender.send(Message::ErrorMessage(format!(
                                        "from server: no client '{}' found",
                                        addr
                                    )))?;
                                }
                            }
                        }
                    }
                }
                // Broadcast
                None => {
                    for (name, peer) in peers.iter() {
                        if *name != sender.clone().unwrap() {
                            peer.send(message.clone())?;
                        }
                    }
                }
            }
        }
        _ => panic!("Unexpected message type!"),
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures_util::TryStreamExt;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use slog::{debug, o, Drain, Logger};
    use sodiumoxide::crypto::secretbox;
    use std::path::Path;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{UnixListener, UnixStream};
    use trithemius::{client_connector::ClientConnector, keyring::Identity};

    // Connect a client to a Unix socket
    async fn connect<P: AsRef<Path>>(path: &P, name: &str) -> Result<ClientConnector<UnixStream>> {
        loop {
            match UnixStream::connect(path).await {
                Ok(stream) => {
                    return Ok(ClientConnector::connect(stream, &Identity::new(name), &name).await?)
                }
                Err(error) => std::thread::sleep(std::time::Duration::from_secs(1)),
            }
        }
    }

    // Connect a client and send identity
    async fn connect_client<P: AsRef<Path>>(
        path: &P,
        name: &str,
    ) -> Result<ClientConnector<UnixStream>> {
        let mut connector: ClientConnector<UnixStream> = connect(&path, name).await?;
        connector.send_identity().await?;

        Ok(connector)
    }

    // Test setup
    fn setup() -> Result<(Logger, String, secretbox::Key)> {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        let log = slog::Logger::root(drain, o!());
        let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(6).collect();
        let path: String = "/tmp/.socket_".to_owned() + &rand_string;
        // Make sure the file isn't there
        std::fs::remove_file(path.clone());
        let session_key = secretbox::gen_key();

        Ok((log, path.into(), session_key))
    }

    // Test teardown
    fn teardown(path: &str) {
        std::fs::remove_file(path);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sending_unexpected_message() -> Result<()> {
        let (log, path, session_key) = setup()?;
        let listener = UnixListener::bind(path.clone())?;
        let new_log = log.new(o!());
        spawn_and_log_error(async move {
            server_event_loop!(listener, path, new_log);
        });

        let name = "foo";
        let mut connector: ClientConnector<UnixStream> = connect(&path, name).await?;
        connector
            .send_message(Message::new_chat_message(
                &session_key,
                Some(vec!["foo".into()]),
                "Hello",
            ))
            .await?;

        // Wait for server
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Server should disconnect, so next message attempt should fail
        assert!(connector
            .send_message(Message::new_chat_message(
                &session_key,
                Some(vec!["foo".into()]),
                "Hello",
            ))
            .await
            .is_err());

        // Shut down
        teardown(&path);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sending_garbage_message() -> Result<()> {
        let (log, path, session_key) = setup()?;
        let listener = UnixListener::bind(path.clone())?;
        let new_log = log.new(o!());
        spawn_and_log_error(async move {
            server_event_loop!(listener, path, new_log);
        });

        let name = "foo";
        let mut connector: ClientConnector<UnixStream> = connect(&path, name).await?;
        connector
            .get_mut()
            .send("You won't like that".as_bytes().into())
            .await?;

        // Wait for server
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Server should disconnect, so next message attempt should fail
        assert!(connector
            .send_message(Message::new_chat_message(
                &session_key,
                Some(vec!["foo".into()]),
                "Hello",
            ))
            .await
            .is_err());

        // Shut down
        teardown(&path);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sending_recipient_message() -> Result<()> {
        let (log, path, session_key) = setup()?;
        let listener = UnixListener::bind(path.clone())?;
        spawn_and_log_error(async move {
            server_event_loop!(listener, path, log);
        });

        // Connect two clients to server
        let mut framed = connect_client(&path, "foo").await?;
        let mut framed2 = connect_client(&path, "bar").await?;

        // Wait for server
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Send message from one
        framed2
            .send_message(Message::new_chat_message(
                &session_key,
                Some(vec!["foo".into()]),
                "Hello",
            ))
            .await?;

        // Wait for message
        let message = framed.next_message().await.unwrap()?;
        if let Message::ChatMessage {
            sender,
            recipients,
            message,
            nonce,
        } = message
        {
            let msg = secretbox::open(&message, &nonce, &session_key).unwrap();
            assert_eq!("Hello", std::str::from_utf8(&msg)?);
        } else {
            panic!("Got wrong type of message!");
        }

        // Shut down
        // control_sender.send(());
        teardown(&path);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sending_broadcast_message() -> Result<()> {
        let (log, path, session_key) = setup()?;
        let listener = UnixListener::bind(path.clone())?;
        spawn_and_log_error(async move {
            server_event_loop!(listener, path, log);
        });

        // Connect three clients
        let mut framed = connect_client(&path, "foo").await?;
        let mut framed2 = connect_client(&path, "bar").await?;
        let mut framed3 = connect_client(&path, "baz").await?;

        // Wait for server
        std::thread::sleep(std::time::Duration::from_secs(1));

        // One client sends broadcast message
        framed2
            .send_message(Message::new_chat_message(&session_key, None, "Hello"))
            .await?;

        // Check for message on other two clients
        let message = framed.next_message().await.unwrap()?;
        if let Message::ChatMessage {
            sender,
            recipients,
            message,
            nonce,
        } = message
        {
            let msg = secretbox::open(&message, &nonce, &session_key).unwrap();
            assert_eq!("Hello", std::str::from_utf8(&msg)?);
        } else {
            panic!("Got wrong type of message!");
        }

        let message = framed3.next_message().await.unwrap()?;
        if let Message::ChatMessage {
            sender,
            recipients,
            message,
            nonce,
        } = message
        {
            let msg = secretbox::open(&message, &nonce, &session_key).unwrap();
            assert_eq!("Hello", std::str::from_utf8(&msg)?);
        } else {
            panic!("Got wrong type of message!");
        }

        // Should really check to make sure the sending client doesn't get it,
        // but since Unix socket peek isn't a thing in Rust, ¯\_(ツ)_/¯

        teardown(&path);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sending_duplicate_identities() -> Result<()> {
        let (log, path, session_key) = setup()?;
        let listener = UnixListener::bind(path.clone())?;
        let spawn_log = log.new(o!());
        spawn_and_log_error(async move {
            server_event_loop!(listener, path, spawn_log);
        });

        // Connect two clients to server
        let mut framed = connect_client(&path, "foo").await?;
        let mut framed2 = connect_client(&path, "foo").await?;

        // Wait for server
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Wait for message
        let message = framed2.next_message().await.unwrap()?;

        assert_eq!(Message::IdentityTaken { name: "foo".into() }, message);

        // Server should disconnect, so next message attempt should fail
        assert!(framed2
            .send_message(Message::new_chat_message(
                &session_key,
                Some(vec!["foo".into()]),
                "Hello",
            ))
            .await
            .is_err());

        // Shut down
        // control_sender.send(());
        teardown(&path);

        Ok(())
    }
}
