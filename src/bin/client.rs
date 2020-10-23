use clap::clap_app;
use sodiumoxide::crypto::secretbox;
use std::net::ToSocketAddrs;
use trithemius::{client_connector::ClientConnector, keyring::KeyRing, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize crypto
    sodiumoxide::init().unwrap();

    // TODO: Redo as code?
    let app = clap_app!(myapp =>
        (version: "0.1.0")
        (author: "Jack Lund <jackl@geekheads.net>")
        (about: "Encrypted chat client")
        (@setting SubcommandRequired)

        (@subcommand connect =>
         (about: "Connect to server")
         (@arg ADDR: +required "Address to connect to")
         (@arg NAME: +required "Name of identity"))

        (@subcommand identity =>
         (@setting SubcommandRequired)
         (@subcommand add =>
          (about: "Add identity")
          (@arg NAME: +required "Name of identity"))
         (@subcommand remove =>
          (about: "Remove identity")
          (@arg NAME: +required "Name of identity"))
         (@subcommand list =>
          (about: "List identities")))

        (@subcommand key =>
         (@setting SubcommandRequired)
         (@subcommand add =>
          (@arg NAME: +required "Server name"))
         (@subcommand remove =>
          (@arg NAME: +required "Server name"))
         (@subcommand list =>
          (about: "List server keys")))
    );
    let matches = app.clone().get_matches();

    let password = rpassword::read_password_from_tty(Some("password: "))?;
    let mut keyfile = match dirs::home_dir() {
        Some(home_dir) => home_dir,
        None => Err("Unable to find home directory")?,
    };
    keyfile.push(".trithemius");
    let (mut keyring, mut keyring_file) = KeyRing::read_from_file(&keyfile, &password)?;

    match matches.subcommand() {
        ("connect", Some(connect_matches)) => {
            let address = connect_matches.value_of("ADDR").unwrap();
            let socket_addr = address.to_socket_addrs()?.next().unwrap();
            let name = connect_matches.value_of("NAME").unwrap();
            let key = match keyring.get_key(&address) {
                Some(key) => key,
                None => Err(format!(
                    "Key for {} not found; '{} key add {}' to add key",
                    name,
                    app.get_name(),
                    name
                ))?,
            };
            ClientConnector::connect(socket_addr)
                .await?
                .handle_events(&name, &key)
                .await?;
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
