//! Abstraction over the single control-plane writer.
//!
//! `frp-client`'s [`crate::control_writer::ControlWriter`] (an mpsc channel
//! funnel to a dedicated writer task) implements this trait so downstream
//! crates — notably `frp-vnet`'s per-TUN controller — can emit control
//! messages without depending on the concrete write half. This keeps the
//! lock-free single-writer design (audit v0.70.1 P1-A1) across crate
//! boundaries.
//!
//! Implementations must not block indefinitely: the contract is bounded,
//! drop-when-full (Go frp parity), and `Err` reports writer failure or a
//! full channel.

use crate::msg::FrpMessage;

/// A sink that accepts control-plane messages for serialized delivery on
/// the control connection.
pub trait ControlSink: Send + Sync {
    /// Enqueue `msg` for delivery. Returns `Ok(())` once the message is
    /// accepted by the writer funnel; `Err` when the writer has failed or
    /// the bounded queue is full.
    fn send_msg(&self, msg: FrpMessage, v2: bool) -> Result<(), String>;
}
