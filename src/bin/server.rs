use clap::clap_app;
use std::collections::{hash_map::Entry, HashMap};
use std::future::Future;
use std::net::ToSocketAddrs;
use tokio::io::BufStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::select;
use tokio::stream::StreamExt;
use tokio::sync::mpsc;
use tokio::task;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Sender<T> = mpsc::UnboundedSender<T>;
type Receiver<T> = mpsc::UnboundedReceiver<T>;

#[derive(Debug)]
enum Event {
    NewPeer {
        name: String,
        sender: Sender<String>,
    },
    Message {
        from: String,
        to: Vec<String>,
        msg: String,
    },
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
    let _broker_handle = task::spawn(broker_loop(broker_receiver));

    // Listen and handle incoming connections
    let mut listener = TcpListener::bind(socket_addr).await?;
    let mut incoming = listener.incoming();
    while let Some(stream) = incoming.next().await {
        let stream = stream?;
        println!("Accepting from: {}", stream.peer_addr()?);
        spawn_and_log_error(handle_connection(broker_sender.clone(), stream));
    }

    Ok(())
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

async fn handle_connection(broker: Sender<Event>, stream: TcpStream) -> Result<()> {
    // Set up input buffer
    let mut buffered = BufStream::new(stream);
    let mut line = String::new();

    // Read client name
    buffered.read_line(&mut line).await?;
    let name = line.trim_end().to_string();
    println!("{} connected", name);
    line.clear();

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
            result = buffered.read_line(&mut line) => {
                match result {
                    Ok(0) => break,
                    Ok(_) => handle_message(&broker, &name, &line),
                    Err(error) => Err(error)?,
                }.await?;
                line.clear();
            },

            // Handle message from broker
            message_opt = receiver.recv() => match message_opt {
                Some(message) => {
                    println!("{}: Got message from broker, sending: {}", name, message);
                    buffered.write_all(message.as_bytes()).await?;
                    buffered.flush().await?;
                    println!("{}: Sent message {}", name, message);
                },
                None => continue,
            },
        }
    }
    Ok(())
}

// Handle message from client
async fn handle_message(broker: &Sender<Event>, name: &str, line: &str) -> Result<()> {
    println!("{}: Read line: {}", name, line);
    let (dest, msg) = match line.find(':') {
        None => return Ok(()),
        Some(idx) => (&line[..idx], line[idx + 1..].to_string()),
    };
    let dest: Vec<String> = dest
        .split(',')
        .map(|name| name.trim().to_string())
        .collect();
    println!("{}: Sending {} to {:?}", name, msg, dest);

    broker
        .send(Event::Message {
            from: name.to_string(),
            to: dest,
            msg,
        })
        .unwrap();

    Ok(())
}

async fn broker_loop(mut events: Receiver<Event>) -> Result<()> {
    let mut peers: HashMap<String, Sender<String>> = HashMap::new();

    while let Some(event) = events.next().await {
        match event {
            Event::Message { from, to, msg } => {
                println!("Broker got message event: {}, {:?}, {}", from, to, msg);
                for addr in to {
                    if let Some(peer) = peers.get_mut(&addr) {
                        let msg = format!("from {}: {}", from, msg);
                        peer.send(msg)?
                    }
                }
            }
            Event::NewPeer { name, sender } => {
                println!("Got new peer event: {}", name);
                match peers.entry(name) {
                    Entry::Occupied(..) => (),
                    Entry::Vacant(entry) => {
                        entry.insert(sender);
                    }
                };
            }
        }
    }
    Ok(())
}
