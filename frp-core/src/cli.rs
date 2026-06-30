//! CLI argument parsing for frps and frpc binaries.
//!
//! Uses bpaf combinators to match Go frp v0.69.1 CLI surface.
//! All flags accept both hyphen (`--log-file`) and underscore (`--log_file`) forms.

#![allow(clippy::collapsible_match)]

use bpaf::*;
use bpaf::Parser;

// ──────────────────────────────────────────────────────────────────────
// frps CLI — 30+ flags matching Go frp v0.69.1
// ──────────────────────────────────────────────────────────────────────

/// CLI arguments for frps (server). Mirrors Go frp v0.69.1 frps flags.
///
/// Fields that can also appear in the config file use `Option<T>`: `Some`
/// means the user explicitly passed the flag on the CLI and it should
/// override the config value.  `None` means the config value is used.
#[derive(Debug, Clone)]
pub struct FrpsArgs {
    pub config: String,
    pub config_dir: Option<String>,
    pub bind_addr: Option<String>,
    pub bind_port: Option<u16>,
    pub token: Option<String>,
    pub allow_ports: Option<String>,
    pub allow_unsafe: Vec<String>,
    pub dashboard_addr: Option<String>,
    pub dashboard_port: Option<u16>,
    pub dashboard_user: Option<String>,
    pub dashboard_pwd: Option<String>,
    pub dashboard_tls_cert_file: Option<String>,
    pub dashboard_tls_key_file: Option<String>,
    pub dashboard_tls_mode: bool,
    pub enable_prometheus: bool,
    pub disable_log_color: bool,
    pub log_file: Option<String>,
    pub log_level: Option<String>,
    pub log_max_days: Option<i32>,
    pub kcp_bind_port: Option<u16>,
    pub quic_bind_port: Option<u16>,
    pub max_ports_per_client: Option<u64>,
    pub proxy_bind_addr: Option<String>,
    pub subdomain_host: Option<String>,
    pub tls_only: bool,
    pub vhost_http_port: Option<u16>,
    pub vhost_https_port: Option<u16>,
    pub strict_config: bool,
    pub show_version: bool,
}

// Intermediate builder structs — each within bpaf construct! field limits.

struct SvrMeta {
    config: String,
    config_dir: Option<String>,
    strict_config: bool,
    show_version: bool,
}

struct SvrBind {
    bind_addr: Option<String>,
    bind_port: Option<u16>,
    proxy_bind_addr: Option<String>,
}

struct SvrAuth {
    token: Option<String>,
    allow_ports: Option<String>,
    allow_unsafe: Vec<String>,
}

struct SvrDashboard {
    dashboard_addr: Option<String>,
    dashboard_port: Option<u16>,
    dashboard_user: Option<String>,
    dashboard_pwd: Option<String>,
    dashboard_tls_cert_file: Option<String>,
    dashboard_tls_key_file: Option<String>,
    dashboard_tls_mode: bool,
    enable_prometheus: bool,
}

struct SvrLog {
    log_file: Option<String>,
    log_level: Option<String>,
    log_max_days: Option<i32>,
    disable_log_color: bool,
}

struct SvrTransport {
    kcp_bind_port: Option<u16>,
    quic_bind_port: Option<u16>,
    vhost_http_port: Option<u16>,
    vhost_https_port: Option<u16>,
    subdomain_host: Option<String>,
    max_ports_per_client: Option<u64>,
    tls_only: bool,
}

// Composed builder: these 6 parsers feed into the final FrpsArgs.
struct FrpsBuild {
    meta: SvrMeta,
    bind: SvrBind,
    auth: SvrAuth,
    dash: SvrDashboard,
    log: SvrLog,
    transport: SvrTransport,
}

impl From<FrpsBuild> for FrpsArgs {
    fn from(b: FrpsBuild) -> Self {
        FrpsArgs {
            config: b.meta.config,
            config_dir: b.meta.config_dir,
            strict_config: b.meta.strict_config,
            show_version: b.meta.show_version,
            bind_addr: b.bind.bind_addr,
            bind_port: b.bind.bind_port,
            proxy_bind_addr: b.bind.proxy_bind_addr,
            token: b.auth.token,
            allow_ports: b.auth.allow_ports,
            allow_unsafe: b.auth.allow_unsafe,
            dashboard_addr: b.dash.dashboard_addr,
            dashboard_port: b.dash.dashboard_port,
            dashboard_user: b.dash.dashboard_user,
            dashboard_pwd: b.dash.dashboard_pwd,
            dashboard_tls_cert_file: b.dash.dashboard_tls_cert_file,
            dashboard_tls_key_file: b.dash.dashboard_tls_key_file,
            dashboard_tls_mode: b.dash.dashboard_tls_mode,
            enable_prometheus: b.dash.enable_prometheus,
            log_file: b.log.log_file,
            log_level: b.log.log_level,
            log_max_days: b.log.log_max_days,
            disable_log_color: b.log.disable_log_color,
            kcp_bind_port: b.transport.kcp_bind_port,
            quic_bind_port: b.transport.quic_bind_port,
            vhost_http_port: b.transport.vhost_http_port,
            vhost_https_port: b.transport.vhost_https_port,
            subdomain_host: b.transport.subdomain_host,
            max_ports_per_client: b.transport.max_ports_per_client,
            tls_only: b.transport.tls_only,
        }
    }
}

// ─── Parser combinators ──────────────────────────────────────────────

fn svr_meta() -> impl Parser<SvrMeta> {
    let config = long("config")
        .short('c')
        .argument::<String>("FILE")
        .fallback("frps.toml".into());
    let config_dir = long("config-dir")
        .long("config_dir")
        .argument::<String>("DIR")
        .optional();
    let strict_config = long("strict-config")
        .long("strict_config")
        .switch()
        .fallback(true);
    let show_version = long("version").short('v').switch();
    construct!(SvrMeta { config, config_dir, strict_config, show_version })
}

fn svr_bind() -> impl Parser<SvrBind> {
    let bind_addr = long("bind-addr")
        .long("bind_addr")
        .argument::<String>("IP")
        .optional();
    let bind_port = long("bind-port")
        .short('p')
        .long("bind_port")
        .argument::<u16>("PORT")
        .optional();
    let proxy_bind_addr = long("proxy-bind-addr")
        .long("proxy_bind_addr")
        .argument::<String>("IP")
        .optional();
    construct!(SvrBind { bind_addr, bind_port, proxy_bind_addr })
}

fn svr_auth() -> impl Parser<SvrAuth> {
    let token = long("token").short('t').argument::<String>("TOKEN").optional();
    let allow_ports = long("allow-ports")
        .long("allow_ports")
        .argument::<String>("RANGES")
        .optional();
    let allow_unsafe = long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect::<Vec<_>>())
        .fallback(vec![]);
    construct!(SvrAuth { token, allow_ports, allow_unsafe })
}

fn svr_dashboard() -> impl Parser<SvrDashboard> {
    let dashboard_addr = long("dashboard-addr")
        .long("dashboard_addr")
        .argument::<String>("IP")
        .optional();
    let dashboard_port = long("dashboard-port")
        .long("dashboard_port")
        .argument::<u16>("PORT")
        .optional();
    let dashboard_user = long("dashboard-user")
        .long("dashboard_user")
        .argument::<String>("USER")
        .optional();
    let dashboard_pwd = long("dashboard-pwd")
        .long("dashboard_pwd")
        .argument::<String>("PWD")
        .optional();
    let dashboard_tls_cert_file = long("dashboard-tls-cert-file")
        .long("dashboard_tls_cert_file")
        .argument::<String>("FILE")
        .optional();
    let dashboard_tls_key_file = long("dashboard-tls-key-file")
        .long("dashboard_tls_key_file")
        .argument::<String>("FILE")
        .optional();
    let dashboard_tls_mode = long("dashboard-tls-mode")
        .long("dashboard_tls_mode")
        .switch();
    let enable_prometheus = long("enable-prometheus")
        .long("enable_prometheus")
        .switch();
    construct!(SvrDashboard {
        dashboard_addr, dashboard_port, dashboard_user, dashboard_pwd,
        dashboard_tls_cert_file, dashboard_tls_key_file, dashboard_tls_mode,
        enable_prometheus,
    })
}

fn svr_log() -> impl Parser<SvrLog> {
    let log_file = long("log-file")
        .long("log_file")
        .argument::<String>("FILE")
        .optional();
    let log_level = long("log-level")
        .long("log_level")
        .argument::<String>("LEVEL")
        .optional();
    let log_max_days = long("log-max-days")
        .long("log_max_days")
        .argument::<i32>("DAYS")
        .optional();
    let disable_log_color = long("disable-log-color")
        .long("disable_log_color")
        .switch();
    construct!(SvrLog { log_file, log_level, log_max_days, disable_log_color })
}

fn svr_transport() -> impl Parser<SvrTransport> {
    #[cfg(feature = "kcp")]
    let kcp_bind_port = long("kcp-bind-port")
        .long("kcp_bind_port")
        .argument::<u16>("PORT")
        .optional();
    #[cfg(not(feature = "kcp"))]
    let kcp_bind_port = bpaf::pure(None);
    #[cfg(feature = "quic")]
    let quic_bind_port = long("quic-bind-port")
        .long("quic_bind_port")
        .argument::<u16>("PORT")
        .optional();
    #[cfg(not(feature = "quic"))]
    let quic_bind_port = bpaf::pure(None);
    let vhost_http_port = long("vhost-http-port")
        .long("vhost_http_port")
        .argument::<u16>("PORT")
        .optional();
    let vhost_https_port = long("vhost-https-port")
        .long("vhost_https_port")
        .argument::<u16>("PORT")
        .optional();
    let subdomain_host = long("subdomain-host")
        .long("subdomain_host")
        .argument::<String>("HOST")
        .optional();
    let max_ports_per_client = long("max-ports-per-client")
        .long("max_ports_per_client")
        .argument::<u64>("N")
        .optional();
    let tls_only = long("tls-only").long("tls_only").switch();
    construct!(SvrTransport {
        kcp_bind_port, quic_bind_port, vhost_http_port, vhost_https_port,
        subdomain_host, max_ports_per_client, tls_only,
    })
}

fn frps_build() -> impl Parser<FrpsBuild> {
    let meta = svr_meta();
    let bind = svr_bind();
    let auth = svr_auth();
    let dash = svr_dashboard();
    let log = svr_log();
    let transport = svr_transport();
    construct!(FrpsBuild { meta, bind, auth, dash, log, transport })
}

/// Raw parser for frps CLI. Returns the parser, doesn't run it.
pub fn frps_args() -> impl Parser<FrpsArgs> {
    frps_build().map(FrpsArgs::from)
}

/// Parse frps CLI args. Prints help/version and exits as needed.
pub fn parse_frps_args() -> FrpsArgs {
    let args = frps_args()
        .to_options()
        .descr("frps is the server of frp-rs (https://github.com/fatedier/frp)")
        .run();
    if args.show_version {
        println!("frps {}", crate::VERSION);
        std::process::exit(0);
    }
    args
}

// ──────────────────────────────────────────────────────────────────────
// frpc CLI — run mode + 9 subcommands matching Go frp v0.69.1
// ──────────────────────────────────────────────────────────────────────

/// CLI arguments for frpc (client).
#[derive(Debug, Clone)]
pub enum FrpcCmd {
    /// Normal mode: load config file and run all proxies
    Run(FrpcRunArgs),
    /// Single TCP proxy (no config file)
    Tcp(TcpArgs),
    /// Single UDP proxy
    Udp(UdpArgs),
    /// Single HTTP proxy
    Http(HttpArgs),
    /// Single HTTPS proxy
    Https(HttpsArgs),
    /// Single STCP proxy
    Stcp(StcpArgs),
    /// Single XTCP proxy
    Xtcp(XtcpArgs),
    /// Single SUDP proxy
    Sudp(SudpArgs),
    /// Single TCPMUX proxy
    Tcpmux(TcpmuxArgs),
    /// Verify config file
    Verify(VerifyArgs),
}

#[derive(Debug, Clone)]
pub struct FrpcRunArgs {
    pub config: String,
    pub config_dir: Option<String>,
    pub strict_config: bool,
    pub allow_unsafe: Vec<String>,
    pub show_version: bool,
}

#[derive(Debug, Clone)]
pub struct TcpArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub proxy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UdpArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub proxy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub custom_domains: String,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub subdomain: Option<String>,
    pub locations: Option<String>,
    pub http_user: Option<String>,
    pub http_pwd: Option<String>,
    pub host_header_rewrite: Option<String>,
    pub proxy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpsArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub custom_domains: String,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub subdomain: Option<String>,
    pub proxy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StcpArgs {
    pub sk: String,
    pub server_name: Option<String>,
    pub local_ip: String,
    pub local_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct XtcpArgs {
    pub sk: String,
    pub server_name: Option<String>,
    pub local_ip: String,
    pub local_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SudpArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub proxy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TcpmuxArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub mux_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub proxy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifyArgs {
    pub config: String,
}

// ─── frpc parser combinators ─────────────────────────────────────────

fn run_mode() -> impl Parser<FrpcRunArgs> {
    let config = long("config")
        .short('c')
        .argument::<String>("FILE")
        .fallback("frpc.toml".into());
    let config_dir = long("config-dir")
        .long("config_dir")
        .argument::<String>("DIR")
        .optional();
    let strict_config = long("strict-config")
        .long("strict_config")
        .switch()
        .fallback(true);
    let allow_unsafe = long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect::<Vec<_>>())
        .fallback(vec![]);
    let show_version = long("version").short('v').switch();
    construct!(FrpcRunArgs { config, config_dir, strict_config, allow_unsafe, show_version })
}

// ─── Subcommand parsers (inlined — bpaf construct! doesn't support destructuring tuples from parser fns) ───

fn tcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip").long("local_ip").argument::<String>("IP").fallback("127.0.0.1".into());
    let local_port = long("local-port").long("local_port").argument::<u16>("PORT");
    let remote_port = long("remote-port").long("remote_port").argument::<u16>("PORT");
    let server_addr = long("server-addr").long("server_addr").argument::<String>("HOST").fallback("127.0.0.1".into());
    let server_port = long("server-port").long("server_port").argument::<u16>("PORT").fallback(7000);
    let token = long("token").short('t').argument::<String>("TOKEN").optional();
    let use_encryption = long("use-encryption").long("use_encryption").switch();
    let use_compression = long("use-compression").long("use_compression").switch();
    let proxy_name = long("proxy-name").long("proxy_name").argument::<String>("NAME").optional();
    let args = construct!(TcpArgs {
        local_ip, local_port, remote_port, server_addr, server_port, token,
        use_encryption, use_compression, proxy_name,
    });
    args.to_options().command("tcp").help("Run frpc with a single tcp proxy").map(FrpcCmd::Tcp)
}

fn udp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip").long("local_ip").argument::<String>("IP").fallback("127.0.0.1".into());
    let local_port = long("local-port").long("local_port").argument::<u16>("PORT");
    let remote_port = long("remote-port").long("remote_port").argument::<u16>("PORT");
    let server_addr = long("server-addr").long("server_addr").argument::<String>("HOST").fallback("127.0.0.1".into());
    let server_port = long("server-port").long("server_port").argument::<u16>("PORT").fallback(7000);
    let token = long("token").short('t').argument::<String>("TOKEN").optional();
    let proxy_name = long("proxy-name").long("proxy_name").argument::<String>("NAME").optional();
    let args = construct!(UdpArgs {
        local_ip, local_port, remote_port, server_addr, server_port, token, proxy_name,
    });
    args.to_options().command("udp").help("Run frpc with a single udp proxy").map(FrpcCmd::Udp)
}

fn http_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip").long("local_ip").argument::<String>("IP").fallback("127.0.0.1".into());
    let local_port = long("local-port").long("local_port").argument::<u16>("PORT");
    let custom_domains = long("custom-domains").long("custom_domains").argument::<String>("DOMAINS");
    let server_addr = long("server-addr").long("server_addr").argument::<String>("HOST").fallback("127.0.0.1".into());
    let server_port = long("server-port").long("server_port").argument::<u16>("PORT").fallback(7000);
    let token = long("token").short('t').argument::<String>("TOKEN").optional();
    let subdomain = long("subdomain").argument::<String>("SUB").optional();
    let locations = long("locations").argument::<String>("LOCS").optional();
    let http_user = long("http-user").long("http_user").argument::<String>("USER").optional();
    let http_pwd = long("http-pwd").long("http_pwd").argument::<String>("PWD").optional();
    let host_header_rewrite = long("host-header-rewrite").long("host_header_rewrite").argument::<String>("HOST").optional();
    let proxy_name = long("proxy-name").long("proxy_name").argument::<String>("NAME").optional();
    let args = construct!(HttpArgs {
        local_ip, local_port, custom_domains, server_addr, server_port, token,
        subdomain, locations, http_user, http_pwd, host_header_rewrite, proxy_name,
    });
    args.to_options().command("http").help("Run frpc with a single http proxy").map(FrpcCmd::Http)
}

fn https_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip").long("local_ip").argument::<String>("IP").fallback("127.0.0.1".into());
    let local_port = long("local-port").long("local_port").argument::<u16>("PORT");
    let custom_domains = long("custom-domains").long("custom_domains").argument::<String>("DOMAINS");
    let server_addr = long("server-addr").long("server_addr").argument::<String>("HOST").fallback("127.0.0.1".into());
    let server_port = long("server-port").long("server_port").argument::<u16>("PORT").fallback(7000);
    let token = long("token").short('t').argument::<String>("TOKEN").optional();
    let subdomain = long("subdomain").argument::<String>("SUB").optional();
    let proxy_name = long("proxy-name").long("proxy_name").argument::<String>("NAME").optional();
    let args = construct!(HttpsArgs {
        local_ip, local_port, custom_domains, server_addr, server_port, token, subdomain, proxy_name,
    });
    args.to_options().command("https").help("Run frpc with a single https proxy").map(FrpcCmd::Https)
}

fn stcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip").long("local_ip").argument::<String>("IP").fallback("127.0.0.1".into());
    let local_port = long("local-port").long("local_port").argument::<u16>("PORT");
    let sk = long("sk").argument::<String>("SECRET");
    let server_name = long("server-name").long("server_name").argument::<String>("NAME").optional();
    let server_addr = long("server-addr").long("server_addr").argument::<String>("HOST").fallback("127.0.0.1".into());
    let server_port = long("server-port").long("server_port").argument::<u16>("PORT").fallback(7000);
    let token = long("token").short('t').argument::<String>("TOKEN").optional();
    let args = construct!(StcpArgs {
        sk, server_name, local_ip, local_port, server_addr, server_port, token,
    });
    args.to_options().command("stcp").help("Run frpc with a single stcp proxy").map(FrpcCmd::Stcp)
}

fn xtcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip").long("local_ip").argument::<String>("IP").fallback("127.0.0.1".into());
    let local_port = long("local-port").long("local_port").argument::<u16>("PORT");
    let sk = long("sk").argument::<String>("SECRET");
    let server_name = long("server-name").long("server_name").argument::<String>("NAME").optional();
    let server_addr = long("server-addr").long("server_addr").argument::<String>("HOST").fallback("127.0.0.1".into());
    let server_port = long("server-port").long("server_port").argument::<u16>("PORT").fallback(7000);
    let token = long("token").short('t').argument::<String>("TOKEN").optional();
    let args = construct!(XtcpArgs {
        sk, server_name, local_ip, local_port, server_addr, server_port, token,
    });
    args.to_options().command("xtcp").help("Run frpc with a single xtcp proxy").map(FrpcCmd::Xtcp)
}

fn sudp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip").long("local_ip").argument::<String>("IP").fallback("127.0.0.1".into());
    let local_port = long("local-port").long("local_port").argument::<u16>("PORT");
    let remote_port = long("remote-port").long("remote_port").argument::<u16>("PORT");
    let server_addr = long("server-addr").long("server_addr").argument::<String>("HOST").fallback("127.0.0.1".into());
    let server_port = long("server-port").long("server_port").argument::<u16>("PORT").fallback(7000);
    let token = long("token").short('t').argument::<String>("TOKEN").optional();
    let proxy_name = long("proxy-name").long("proxy_name").argument::<String>("NAME").optional();
    let args = construct!(SudpArgs {
        local_ip, local_port, remote_port, server_addr, server_port, token, proxy_name,
    });
    args.to_options().command("sudp").help("Run frpc with a single sudp proxy").map(FrpcCmd::Sudp)
}

fn tcpmux_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip").long("local_ip").argument::<String>("IP").fallback("127.0.0.1".into());
    let local_port = long("local-port").long("local_port").argument::<u16>("PORT");
    let mux_port = long("mux-port").long("mux_port").argument::<u16>("PORT");
    let server_addr = long("server-addr").long("server_addr").argument::<String>("HOST").fallback("127.0.0.1".into());
    let server_port = long("server-port").long("server_port").argument::<u16>("PORT").fallback(7000);
    let token = long("token").short('t').argument::<String>("TOKEN").optional();
    let proxy_name = long("proxy-name").long("proxy_name").argument::<String>("NAME").optional();
    let args = construct!(TcpmuxArgs {
        local_ip, local_port, mux_port, server_addr, server_port, token, proxy_name,
    });
    args.to_options().command("tcpmux").help("Run frpc with a single tcpmux proxy").map(FrpcCmd::Tcpmux)
}

fn verify_cmd() -> impl Parser<FrpcCmd> {
    let config = long("config").short('c').argument::<String>("FILE");
    let args = construct!(VerifyArgs { config });
    args.to_options().command("verify").help("Verify that the configures is valid").map(FrpcCmd::Verify)
}

/// Compose all frpc subcommands + run-mode fallback.
fn frpc_parser() -> impl Parser<FrpcCmd> {
    let run = run_mode().map(|args| {
        if args.show_version {
            println!("frpc {}", crate::VERSION);
            std::process::exit(0);
        }
        FrpcCmd::Run(args)
    });

    construct!([
        tcp_cmd(),
        udp_cmd(),
        http_cmd(),
        https_cmd(),
        stcp_cmd(),
        xtcp_cmd(),
        sudp_cmd(),
        tcpmux_cmd(),
        verify_cmd(),
        run,
    ])
}

/// Parse frpc CLI args.
pub fn parse_frpc_args() -> FrpcCmd {
    frpc_parser()
        .to_options()
        .descr("frpc is the client of frp-rs (https://github.com/fatedier/frp)")
        .run()
}

// ──────────────────────────────────────────────────────────────────────
// CLI → Config merge layer
// ──────────────────────────────────────────────────────────────────────

impl FrpsArgs {
    /// Override ServerConfig fields with CLI values. Only fields explicitly
    /// set on the command line (`Some`) override config file values.
    pub fn override_server_config(&self, cfg: &mut crate::config::ServerConfig) {
        if let Some(ref v) = self.token { cfg.auth.token = v.clone(); }
        if let Some(ref v) = self.allow_ports { cfg.allow_ports = v.clone(); }
        if let Some(ref v) = self.bind_addr { cfg.bind_addr = v.clone(); }
        if let Some(v) = self.bind_port { cfg.bind_port = v; }
        if let Some(ref v) = self.proxy_bind_addr { cfg.proxy_bind_addr = v.clone(); }

        // Log
        if let Some(ref v) = self.log_file { cfg.log.file = v.clone(); }
        if let Some(ref v) = self.log_level { cfg.log.level = v.clone(); }
        if let Some(v) = self.log_max_days { cfg.log.max_days = v; }

        // Transport / ports
        #[cfg(feature = "kcp")]
        if let Some(v) = self.kcp_bind_port { cfg.kcp_bind_port = v; }
        #[cfg(feature = "quic")]
        if let Some(v) = self.quic_bind_port { cfg.quic_bind_port = v; }
        if let Some(v) = self.vhost_http_port { cfg.vhost_http_port = v; }
        if let Some(v) = self.vhost_https_port { cfg.vhost_https_port = v; }
        if let Some(ref v) = self.subdomain_host { cfg.sub_domain_host = v.clone(); }
        if let Some(v) = self.max_ports_per_client { cfg.max_ports_per_client = v; }
        if self.tls_only { cfg.tls_only = true; }

        // Dashboard
        if let Some(v) = self.dashboard_port { cfg.web_server.port = v; }
        if let Some(ref v) = self.dashboard_user { cfg.web_server.user = v.clone(); }
        if let Some(ref v) = self.dashboard_pwd { cfg.web_server.password = v.clone(); }
        if self.enable_prometheus { cfg.web_server.enable_prometheus = true; }
    }
}

/// Build a minimal ClientConfig from single-proxy subcommand args (no config file needed).
pub fn build_single_proxy_config(
    server_addr: &str,
    server_port: u16,
    token: Option<&str>,
    proxy: crate::config::ProxyConfig,
) -> crate::config::ClientConfig {
    crate::config::ClientConfig {
        server_addr: server_addr.to_string(),
        server_port,
        token: token.unwrap_or("").to_string(),
        proxies: vec![proxy],
        login_fail_exit: true,
        ..Default::default()
    }
}

// ─── ProxyConfig builders for each subcommand type ───────────────────

impl TcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self.proxy_name.clone().unwrap_or_else(|| {
                format!("tcp-{}->{}", self.local_port, self.remote_port)
            }),
            proxy_type: "tcp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            remote_port: self.remote_port,
            use_encryption: self.use_encryption,
            use_compression: self.use_compression,
            ..Default::default()
        }
    }
}

impl UdpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self.proxy_name.clone().unwrap_or_else(|| {
                format!("udp-{}->{}", self.local_port, self.remote_port)
            }),
            proxy_type: "udp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            remote_port: self.remote_port,
            ..Default::default()
        }
    }
}

impl HttpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let domains: Vec<String> = self.custom_domains
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        crate::config::ProxyConfig {
            name: self.proxy_name.clone().unwrap_or_else(|| {
                format!("http-{}", self.local_port)
            }),
            proxy_type: "http".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            custom_domains: domains,
            subdomain: self.subdomain.clone().unwrap_or_default(),
            locations: self.locations.clone().map(|l| {
                l.split(',').map(|s| s.trim().to_string()).collect()
            }).unwrap_or_default(),
            http_user: self.http_user.clone().unwrap_or_default(),
            http_pwd: self.http_pwd.clone().unwrap_or_default(),
            host_header_rewrite: self.host_header_rewrite.clone().unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl HttpsArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let domains: Vec<String> = self.custom_domains
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        crate::config::ProxyConfig {
            name: self.proxy_name.clone().unwrap_or_else(|| {
                format!("https-{}", self.local_port)
            }),
            proxy_type: "https".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            custom_domains: domains,
            subdomain: self.subdomain.clone().unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl StcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self.server_name.clone().unwrap_or_else(|| "stcp-proxy".into()),
            proxy_type: "stcp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            sk: self.sk.clone(),
            ..Default::default()
        }
    }
}

impl XtcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self.server_name.clone().unwrap_or_else(|| "xtcp-proxy".into()),
            proxy_type: "xtcp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            sk: self.sk.clone(),
            ..Default::default()
        }
    }
}

impl SudpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self.proxy_name.clone().unwrap_or_else(|| {
                format!("sudp-{}->{}", self.local_port, self.remote_port)
            }),
            proxy_type: "sudp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            remote_port: self.remote_port,
            ..Default::default()
        }
    }
}

impl TcpmuxArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self.proxy_name.clone().unwrap_or_else(|| {
                format!("tcpmux-{}", self.local_port)
            }),
            proxy_type: "tcpmux".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            remote_port: self.mux_port,
            multiplexer: "httpconnect".into(),
            ..Default::default()
        }
    }
}
