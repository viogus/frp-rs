//! Accept-loop connection handlers, split into two submodules:
//! - [`transport`]: TLS/WebSocket/V2/V1/QUIC transport admission handlers
//! - [`dispatch`]: visitor/work-conn message dispatch (Login, NewWorkConn,
//!   NewVisitorConn, NatHoleVisitor routing)

mod dispatch;
mod transport;

pub(crate) use dispatch::*;
pub(crate) use transport::*;
