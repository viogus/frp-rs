//! CLI argument parsing for frps and frpc binaries.
//!
//! Uses bpaf combinators for the frps and frpc CLI surfaces.
//! All flags accept both hyphen (`--log-file`) and underscore (`--log_file`) forms.
//!
//! One module per concern; this file only declares and re-exports them.

#[macro_use]
mod macros;
mod argv;
mod csv;
mod durations;
mod flag_tables;
mod frpc;
mod frps;
mod help_render;
mod root;
mod values;

// Crate-internal surface: every module's items, visible only inside `frp-core`.
pub(crate) use argv::*;
pub(crate) use csv::*;
pub(crate) use durations::*;
pub(crate) use flag_tables::*;
pub(crate) use help_render::*;
pub(crate) use root::*;

// The crate's CLI surface, as named by the `frps`/`frpc` binaries and the
// cross-binary CLI tests (`grep -rn 'frp_core::cli::' frps/ frpc/`).
pub use frpc::{
    build_single_proxy_config, parse_frpc_args, FrpcCmd, FrpcRunArgs, ReloadArgs, StatusArgs,
    StopArgs,
};
pub use frps::{parse_frps_args, FrpsArgs, FrpsCmd};
pub use values::STRICT_CONFIG_SPACE_FORM_WARNING;

// Module-internal globs: names other modules and the CLI tests reference
// unqualified (`frps`'s parser tree is only reached through the tests and the
// two `pub use` names above, so its glob is test-only to stay warning-free).
pub(crate) use frpc::*;
#[cfg(test)]
pub(crate) use frps::*;
pub(crate) use values::*;

#[cfg(test)]
mod help_doc_tests;
#[cfg(test)]
mod hoist_tests;
#[cfg(test)]
mod tests;
