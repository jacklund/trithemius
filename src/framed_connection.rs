use crate::{ClientMessage, ServerMessage};
use tokio::io::{AsyncRead, AsyncWrite};

pub type FramedClientConnection<T: AsyncRead + AsyncWrite + std::marker::Unpin> =
    tokio_serde::Framed<
        tokio_util::codec::Framed<T, tokio_util::codec::BytesCodec>,
        ServerMessage,
        ClientMessage,
        tokio_serde::formats::MessagePack<ServerMessage, ClientMessage>,
    >;

pub fn new_client_connection<T: AsyncRead + AsyncWrite + std::marker::Unpin>(
    connection: T,
) -> FramedClientConnection<T> {
    FramedClientConnection::new(
        tokio_util::codec::Framed::new(connection, tokio_util::codec::BytesCodec::new()),
        tokio_serde::formats::MessagePack::<ServerMessage, ClientMessage>::default(),
    )
}

pub type FramedServerConnection<T: AsyncRead + AsyncWrite + std::marker::Unpin> =
    tokio_serde::Framed<
        tokio_util::codec::Framed<T, tokio_util::codec::BytesCodec>,
        ClientMessage,
        ServerMessage,
        tokio_serde::formats::MessagePack<ClientMessage, ServerMessage>,
    >;

pub fn new_server_connection<T: AsyncRead + AsyncWrite + std::marker::Unpin>(
    connection: T,
) -> FramedServerConnection<T> {
    FramedServerConnection::new(
        tokio_util::codec::Framed::new(connection, tokio_util::codec::BytesCodec::new()),
        tokio_serde::formats::MessagePack::<ClientMessage, ServerMessage>::default(),
    )
}
