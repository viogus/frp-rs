//! KCP transport: [`KcpStream`] implements [`Transport`].

use crate::kcp::KcpStream;

use super::Transport;

impl Transport for KcpStream {
    fn debug_name(&self) -> &'static str {
        "IoStream::Kcp"
    }
}
