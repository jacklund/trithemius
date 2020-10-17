use clap::clap_app;
use futures::stream::StreamExt;
use futures::{SinkExt, Stream};
use std::collections::{hash_map::Entry, HashMap};
use std::future::Future;
use std::net::ToSocketAddrs;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::mpsc;
use tokio::task;
use tokio_serde::formats::SymmetricalMessagePack;
use trithemius::Message;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Sender<T> = mpsc::UnboundedSender<T>;
type Receiver<T> = mpsc::UnboundedReceiver<T>;

#[derive(Debug)]
enum Event {
    NewPeer {
        name: String,
        sender: Sender<Message>,
    },
    PeerDisconnected {
        name: String,
    },
    Message(Message),
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

    let socket_addr = matches
        .value_of("ADDR")
        .unwrap()
        .to_socket_addrs()?
        .next()
        .unwrap();

    // Set up broker
    let (broker_sender, broker_receiver) = mpsc::unbounded_channel();
    task::spawn(broker_loop(broker_receiver));

    // Listen and handle incoming connections
    let listener = TcpListener::bind(socket_addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        println!("Accepting from: {}", stream.peer_addr()?);
        spawn_and_log_error(handle_connection(broker_sender.clone(), stream));
    }
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

async fn read_client_identity<R>(framed: &mut R) -> Result<String>
where
    R: Stream<Item = std::result::Result<Message, std::io::Error>> + std::marker::Unpin,
{
    match framed.next().await {
        Some(Ok(Message::Identity(name))) => Ok(name),
        Some(Ok(something)) => {
            println!("{:?}", something);
            panic!("Unexpected message type");
        }
        Some(Err(error)) => Err(error)?,
        None => return Ok("".into()),
    }
}

async fn handle_connection(broker: Sender<Event>, stream: TcpStream) -> Result<()> {
    // Set up network I/O
    let mut framed = tokio_serde::SymmetricallyFramed::new(
        tokio_util::codec::Framed::new(stream, tokio_util::codec::BytesCodec::new()),
        SymmetricalMessagePack::<Message>::default(),
    );

    // Read client name
    let name = read_client_identity(&mut framed).await?;
    println!("{} connected", name);

    // Inform broker of new client
    let (sender, mut receiver) = mpsc::unbounded_channel();
    broker
        .send(Event::NewPeer {
            name: name.clone(),
            sender,
        })
        .unwrap();

    // Event loop
    loop {
        select! {
            // Handle message coming from client
            message_opt = framed.next() => match message_opt {
                Some(Ok(message)) => match message {
                    Message::ErrorMessage(_) => broker.send(Event::Message(message))?,
                    Message::ChatMessage{ sender: _, recipients, message, nonce } => broker.send(Event::Message(Message::ChatMessage{ sender: Some(name.clone()), recipients, message, nonce }))?,
                    something => panic!("Unexpected message {:?}", something),
                },
                Some(Err(error)) => Err(error)?,
                None => break,
            },

            // Handle message from broker
            message_opt = receiver.recv() => match message_opt {
                Some(message) => framed.send(message).await?,
                None => break,
            },
        }
    }

    broker
        .send(Event::PeerDisconnected { name: name.clone() })
        .unwrap();
    drop(broker);
    println!("{} disconnected", name);

    Ok(())
}

async fn broker_loop(mut events: Receiver<Event>) -> Result<()> {
    let mut peers: HashMap<String, Sender<Message>> = HashMap::new();

    while let Some(event) = events.next().await {
        match event {
            Event::Message(message) => {
                match message {
                    Message::ChatMessage {
                        ref sender,
                        ref recipients,
                        message: ref _msg,
                        nonce: ref _nonce,
                    } => {
                        println!("Message: {:?}", message);
                        match recipients {
                            // Send to recipients directly
                            Some(recipients) => {
                                for addr in recipients {
                                    match peers.get_mut(addr) {
                                        Some(peer) => peer.send(message.clone())?,
                                        None => {
                                            // Notify sender that one of the recipients wasn't found
                                            println!("{} not found", addr);
                                            if let Some(sender) =
                                                peers.get_mut(&sender.clone().unwrap())
                                            {
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
                }
            }
            Event::NewPeer { name, sender } => {
                match peers.entry(name) {
                    Entry::Occupied(..) => (),
                    Entry::Vacant(entry) => {
                        entry.insert(sender);
                    }
                };
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
