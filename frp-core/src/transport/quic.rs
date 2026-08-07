//! QUIC transport: [`QuicStream`] implements [`Transport`].

use std::io;

use crate::quic::QuicStream;

use super::{BoxedReadHalf, BoxedWriteHalf, Transport};

impl Transport for QuicStream {
    fn debug_name(&self) -> &'static str {
        "IoStream::Quic"
    }
    fn is_yamux_wrappable(&self) -> bool {
        // Go frp never wraps QUIC in yamux — the QUIC connection itself
        // multiplexes streams.
        false
    }
    fn into_split(self: Box<Self>) -> io::Result<(BoxedReadHalf, BoxedWriteHalf)> {
        let (r, w) = QuicStream::into_split(*self);
        Ok((Box::new(r), Box::new(w)))
    }
}
