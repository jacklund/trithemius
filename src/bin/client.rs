use clap::{App, AppSettings, Arg, SubCommand};
use sodiumoxide::crypto::secretbox;
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::io::{stdin, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::LinesStream, StreamExt};
use trithemius::{
    client_connector::{ClientConnector, Event},
    keyring, Receiver, Result, Sender,
};

async fn connect_and_run(
    name: String,
    socket_addr: SocketAddr,
    identity: keyring::Identity,
    connector_receiver: Receiver<Event>,
    connector_sender: Sender<Event>,
    server_key: Option<keyring::Key>,
    keyring: keyring::KeyRing,
) -> Result<ClientConnector<TcpStream>> {
    Ok(ClientConnector::connect(
        TcpStream::connect(socket_addr).await?,
        &identity,
        &name,
        None,
    )
    .await?)
}

fn parse_line(line: String) -> Result<Event> {
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
    Ok(Event::ChatMessage {
        chat_name: None,
        message: msg,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize crypto
    sodiumoxide::init().unwrap();

    let app = App::new("Trithemius")
        .version("0.1.0")
        .author("Jack Lund <jackl@geekheads.net>")
        .about("Encrypted chat client")
        .setting(AppSettings::SubcommandRequired)
        // Connect subcommand
        .subcommand(
            SubCommand::with_name("connect")
                .about("Connect to server")
                .arg(
                    Arg::with_name("ADDR")
                        .required(true)
                        .help("Address to connect to"),
                )
                .arg(
                    Arg::with_name("IDENTITY")
                        .required(true)
                        .help("Name of identity"),
                )
                .arg(
                    Arg::with_name("NAME")
                        .required(false)
                        .help("Name to use when connecting (default is same as identity name)"),
                ),
        )
        // Identity subcommand
        .subcommand(
            SubCommand::with_name("identity")
                .subcommand(
                    SubCommand::with_name("add").about("Add identity").arg(
                        Arg::with_name("NAME")
                            .required(true)
                            .help("Name of identity"),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("remove")
                        .about("Remove identity")
                        .arg(
                            Arg::with_name("NAME")
                                .required(true)
                                .help("Name of identity"),
                        ),
                )
                .subcommand(SubCommand::with_name("list").about("List identities")),
        )
        // Key subcommand
        .subcommand(
            SubCommand::with_name("key")
                .subcommand(
                    SubCommand::with_name("add")
                        .arg(Arg::with_name("NAME").required(true).help("Server name")),
                )
                .subcommand(
                    SubCommand::with_name("remove")
                        .arg(Arg::with_name("NAME").required(true).help("Server name")),
                )
                .subcommand(SubCommand::with_name("list").about("List server keys")),
        );
    let matches = app.clone().get_matches();

    let password = rpassword::read_password_from_tty(Some("password: "))?;
    let mut keyfile = match dirs::home_dir() {
        Some(home_dir) => home_dir,
        None => Err("Unable to find home directory")?,
    };
    keyfile.push(".trithemius");
    let (mut keyring, mut keyring_file) = keyring::KeyRing::read_from_file(&keyfile, &password)?;

    match matches.subcommand() {
        ("connect", Some(connect_matches)) => {
            let address = connect_matches.value_of("ADDR").unwrap();
            let socket_addr = address.to_socket_addrs()?.next().unwrap();
            let identity_name = connect_matches.value_of("IDENTITY").unwrap();
            let name = match connect_matches.value_of("NAME") {
                Some(name) => name,
                None => identity_name,
            };
            let identity = match keyring.get_identity(&identity_name) {
                Some(identity) => identity.clone(),
                None => Err(format!("Couldn't find identity '{}'", name))?,
            };
            let (event_sender, connector_receiver) = mpsc::unbounded_channel();
            let (connector_sender, mut event_receiver) = mpsc::unbounded_channel();
            let server_key = keyring.get_key(&address).cloned();
            let my_keyring = keyring.clone();
            tokio::task::spawn(connect_and_run(
                name.into(),
                socket_addr,
                identity.clone(),
                connector_receiver,
                connector_sender,
                server_key,
                my_keyring,
            ))
            .await??;
            loop {
                // Set up terminal I/O
                let mut lines_from_stdin = LinesStream::new(BufReader::new(stdin()).lines());

                select! {
                    _event = event_receiver.recv() => unimplemented!(),
                    line = lines_from_stdin.next() => match line {
                        Some(line) => event_sender.send(parse_line(line?)?)?,
                        None => break,
                    }
                }
            }
        }
        ("identity", Some(identity_matches)) => {
            match identity_matches.subcommand() {
                ("add", Some(add_matches)) => {
                    let name = add_matches.value_of("NAME").unwrap();
                    keyring.add_identity(&name)?;
                    keyring.save(&mut keyring_file, &password)?;
                    let identity = keyring.get_identity(&name).unwrap();
                    println!(
                        "Identity {} ({}) added",
                        identity.get_name(),
                        identity.get_fingerprint()
                    );
                }
                ("remove", Some(remove_matches)) => {
                    let name = remove_matches.value_of("NAME").unwrap();
                    keyring.remove_identity(&name)?;
                    keyring.save(&mut keyring_file, &password)?;
                    println!("Identity {} removed", name);
                }
                ("list", Some(_)) => {
                    println!("Identities:");
                    for identity in keyring.get_identities() {
                        println!("{}\t{}", identity.get_name(), identity.get_fingerprint());
                    }
                }
                _ => panic!("Something went wrong"),
            };
        }
        ("key", Some(key_matches)) => {
            match key_matches.subcommand() {
                ("add", Some(add_matches)) => {
                    let name = add_matches.value_of("NAME").unwrap();
                    keyring.add_key(&name, &secretbox::gen_key())?;
                    keyring.save(&mut keyring_file, &password)?;
                    let key = keyring.get_key(&name).unwrap();
                    println!("Key {} ({}) added", key.get_name(), key.get_fingerprint());
                }
                ("remove", Some(remove_matches)) => {
                    let name = remove_matches.value_of("NAME").unwrap();
                    keyring.remove_key(&name)?;
                    println!("Key {} removed from keyring", name);
                }
                ("list", Some(_)) => {
                    for (name, key) in keyring.get_keys() {
                        println!("{}\t{}", name, key.get_fingerprint());
                    }
                }
                _ => panic!("Something went wrong"),
            };
        }
        _ => (),
    };

    Ok(())
}
