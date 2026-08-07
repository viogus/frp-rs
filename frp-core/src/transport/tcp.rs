//! TCP transport: the raw [`tokio::net::TcpStream`] implements [`Transport`].

use std::net::SocketAddr;

use tokio::net::TcpStream;

use super::{BoxedReadHalf, BoxedWriteHalf, Transport};

impl Transport for TcpStream {
    fn debug_name(&self) -> &'static str {
        "IoStream::Tcp"
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr().ok()
    }
    fn try_tcp(&self) -> Option<&TcpStream> {
        Some(self)
    }
    fn try_tcp_mut(&mut self) -> Option<&mut TcpStream> {
        Some(self)
    }
    fn into_tcp(self: Box<Self>) -> Option<TcpStream> {
        Some(*self)
    }
    fn into_split(self: Box<Self>) -> std::io::Result<(BoxedReadHalf, BoxedWriteHalf)> {
        let (r, w) = tokio::io::split(*self);
        Ok((Box::new(r), Box::new(w)))
    }
}
