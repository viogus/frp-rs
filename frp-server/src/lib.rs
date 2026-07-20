//! frp server daemon (`frps`) — manages proxy registrations, connection routing,
//! authentication, and relay between frpc clients and end users.

pub mod control;
#[cfg(feature = "dashboard")]
pub mod dashboard;
#[cfg(feature = "dashboard")]
pub mod event;
pub mod handlers;
pub mod lock;
pub mod metrics;
pub mod nathole;
pub mod plugin;
pub mod proxy;
pub mod registry;
pub mod service;
#[cfg(feature = "ssh")]
pub mod ssh_gateway;
pub mod state;
pub mod store;
pub mod tcpmux;
pub mod vhost;

pub(crate) use frp_core::auth::constant_time_eq_str;

#[cfg(feature = "dashboard")]
pub mod dashboard_v2;
