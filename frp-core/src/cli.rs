//! CLI argument parsing for frps and frpc binaries.
//!
//! Uses bpaf combinators for the frps and frpc CLI surfaces.
//! All flags accept both hyphen (`--log-file`) and underscore (`--log_file`) forms.

use std::time::Duration;

use bpaf::Parser;
use bpaf::*;

/// Parse a bool flag value with Go `strconv.ParseBool` spellings.
///
/// The **adjacent** form (`--strict-config=false`) matches Go pflag. The
/// **space-separated** form (`--strict-config false`) is an frp-rs extension,
/// **not** Go pflag semantics: measured on Go v0.71.0,
/// `frpc reload --strict-config false -c <unknown-key config>` prints
/// `json: unknown field "notAKnownFrpKey"` (strict stays `true`; `false` is an
/// unused positional argument), while frp-rs consumes the value as `false` and
/// proceeds. The same holds for `--strict-config foo`, where Go ignores the
/// token and frp-rs rejects it. The divergence is recorded in `TODO.md`.
fn parse_go_bool(value: String) -> Result<bool, String> {
    match value.as_str() {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!("invalid boolean value \"{value}\"")),
    }
}

/// Default of `--api-timeout`: Go frp v0.71.0's
/// `var adminAPITimeout = 30 * time.Second` (`cmd/frpc/sub/admin.go:32`).
pub const DEFAULT_ADMIN_API_TIMEOUT: Duration = Duration::from_secs(30);

/// Consume Go's `leadingInt` from `time.ParseDuration`: digits into a `u64`,
/// failing on the same overflow Go fails on.
fn leading_int(s: &[u8]) -> Result<(u64, usize), ()> {
    let mut x: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        if x > (1u64 << 63) / 10 {
            return Err(());
        }
        x = x * 10 + u64::from(s[i] - b'0');
        if x > 1u64 << 63 {
            return Err(());
        }
        i += 1;
    }
    Ok((x, i))
}

/// Consume Go's `leadingFraction`: the digits after a decimal point as a
/// `u64` plus the matching power-of-ten scale. On overflow Go stops updating
/// the value but keeps consuming digits; the scale stops growing too.
fn leading_fraction(s: &[u8]) -> (u64, f64, usize) {
    let mut x: u64 = 0;
    let mut scale = 1f64;
    let mut overflow = false;
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        if !overflow {
            if x > ((1u64 << 63) - 1) / 10 {
                overflow = true;
            } else {
                let y = x * 10 + u64::from(s[i] - b'0');
                if y > 1u64 << 63 {
                    overflow = true;
                } else {
                    x = y;
                    scale *= 10.0;
                }
            }
        }
        i += 1;
    }
    (x, scale, i)
}

/// Parse a duration with Go `time.ParseDuration`'s grammar, hand-written.
///
/// Needed because `Duration` does not implement `FromStr` on the pinned
/// toolchain and the dependency policy forbids adding a crate for it. Grammar
/// (Go's `ParseDuration`): one or more `number unit` groups, each number a
/// decimal integer with an optional fractional part, each unit one of
/// `ns us µs μs ms s m h` (lowercase only), behind an optional leading `+`/`-`.
/// A bare `0` is the only unit-less form; a number with no unit is
/// `time: missing unit in duration "…"`, an unknown unit is
/// `time: unknown unit "d" in duration "1d"`, and everything else malformed is
/// `time: invalid duration "…"` — Go's wording, measured through
/// `frpc stop --api-timeout=<value>` on the v0.71.0 binary. Overflow past
/// `2562047h47m16.854775807s` (`i64::MAX` ns) is rejected, never panicked.
///
/// A negative value parses (Go accepts `-1s`) but a [`Duration`] cannot be
/// negative and the only consumer is a deadline, where "negative" means
/// "already elapsed" — so it is represented as [`Duration::ZERO`], exactly like
/// a parsed `0`. Go distinguishes them only in the sign it later applies to an
/// already-expired context, which behaves the same.
///
/// One divergence, recorded rather than copied: Go accumulates the group total
/// in a `uint64` (`d += v`) and only checks `d > 1<<63`, so two groups that sum
/// past `2^64` wrap. Measured on the v0.71.0 binary,
/// `frpc stop --api-timeout=9223372036854775808ns9223372036854775808ns` is
/// accepted and reports `context deadline exceeded` (the wrapped total is 0 ns),
/// while this parser rejects it with `time: invalid duration`. frp-rs is
/// therefore **stricter** on that input and never panics: it uses checked
/// arithmetic instead of wrapping.
fn parse_go_duration(text: String) -> Result<Duration, String> {
    let orig = text.as_str();
    let invalid = || format!("time: invalid duration \"{orig}\"");
    let mut rest = text.as_bytes();
    let mut neg = false;
    if let Some((&c, tail)) = rest.split_first() {
        match c {
            b'-' => {
                neg = true;
                rest = tail;
            }
            b'+' => rest = tail,
            _ => {}
        }
    }
    // Go special-cases a bare "0" after the sign.
    if rest == b"0" {
        return Ok(Duration::ZERO);
    }
    if rest.is_empty() {
        return Err(invalid());
    }
    // Total nanoseconds, tracked in Go's unsigned domain so the overflow checks
    // match (`d > 1<<63` fails, `d == 1<<63` is still representable as -2^63).
    let mut total: u64 = 0;
    while !rest.is_empty() {
        if !(rest[0] == b'.' || rest[0].is_ascii_digit()) {
            return Err(invalid());
        }
        let (v, used) = leading_int(rest).map_err(|()| invalid())?;
        let pre = used != 0;
        rest = &rest[used..];
        let mut f: u64 = 0;
        let mut scale = 1f64;
        let mut post = false;
        if !rest.is_empty() && rest[0] == b'.' {
            rest = &rest[1..];
            let (ff, ss, used) = leading_fraction(rest);
            f = ff;
            scale = ss;
            rest = &rest[used..];
            post = used != 0;
        }
        if !pre && !post {
            return Err(invalid());
        }
        // The unit is the run of bytes that are neither a digit nor a point.
        let unit_len = rest
            .iter()
            .take_while(|c| **c != b'.' && !c.is_ascii_digit())
            .count();
        if unit_len == 0 {
            return Err(format!("time: missing unit in duration \"{orig}\""));
        }
        let unit_name = &rest[..unit_len];
        rest = &rest[unit_len..];
        let unit: u64 = match unit_name {
            b"ns" => 1,
            // U+00B5 MICRO SIGN and U+03BC GREEK SMALL LETTER MU, Go's two µs
            // spellings (UTF-8: C2 B5 and CE BC).
            b"us" | b"\xc2\xb5s" | b"\xce\xbcs" => 1_000,
            b"ms" => 1_000_000,
            b"s" => 1_000_000_000,
            b"m" => 60 * 1_000_000_000,
            b"h" => 3_600 * 1_000_000_000,
            _ => {
                return Err(format!(
                    "time: unknown unit \"{}\" in duration \"{orig}\"",
                    String::from_utf8_lossy(unit_name)
                ))
            }
        };
        if v > (1u64 << 63) / unit {
            return Err(invalid());
        }
        let mut v = v * unit;
        if f > 0 {
            // Go: `v += uint64(float64(f) * (float64(unit) / scale))`.
            let fraction = (f as f64) * (unit as f64 / scale);
            if !fraction.is_finite() || fraction < 0.0 {
                return Err(invalid());
            }
            v = v.checked_add(fraction as u64).ok_or_else(invalid)?;
            if v > 1u64 << 63 {
                return Err(invalid());
            }
        }
        total = total.checked_add(v).ok_or_else(invalid)?;
        if total > 1u64 << 63 {
            return Err(invalid());
        }
    }
    if neg {
        return Ok(Duration::ZERO);
    }
    if total > (1u64 << 63) - 1 {
        return Err(invalid());
    }
    Ok(Duration::from_nanos(total))
}

/// `--api-timeout` for the frpc admin subcommands.
///
/// Go frp v0.71.0 registers this flag **per subcommand**:
/// `init()`'s loop over `reload`/`status`/`stop` (`cmd/frpc/sub/admin.go:45-49`)
/// runs `cmd.Flags().DurationVar(&adminAPITimeout, "api-timeout",
/// adminAPITimeout, "Timeout for admin API calls")` at `:47`.
/// `NewAdminCommand` (`:52-73`) only builds the command and registers no flag.
/// It is not a root persistent flag; measured, `frpc verify --api-timeout=1s` is
/// `Error: unknown flag: --api-timeout`, exit 1. The underscore spelling
/// `--api_timeout` is registered as well, like every other flag in this file;
/// `docs/deployment.md` records the measured Go behaviour for both spellings.
fn api_timeout_parser() -> impl Parser<Duration> {
    long("api-timeout")
        .long("api_timeout")
        .argument::<String>("DURATION")
        .help("Timeout for admin API calls")
        .parse(parse_go_duration)
        .fallback(DEFAULT_ADMIN_API_TIMEOUT)
}

// ──────────────────────────────────────────────────────────────────────
// frps CLI — 30+ flags
// ──────────────────────────────────────────────────────────────────────

/// CLI arguments for frps (server).
///
/// Fields that can also appear in the config file use `Option<T>`: `Some`
/// means the user explicitly passed the flag on the CLI and it should
/// override the config value.  `None` means the config value is used.
#[derive(Debug, Clone)]
pub struct FrpsArgs {
    /// Config file path. `None` when `-c` was not given (default
    /// "frps.toml" is applied by [`FrpsArgs::config_path`]).
    /// Go frp v0.70.1 parity: when `-c` is given the file is authoritative
    /// and CLI config flags are ignored (audit task 9 finding 5).
    pub config: Option<String>,
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
    pub log_format: Option<String>,
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
    config: Option<String>,
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
    log_format: Option<String>,
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
            log_format: b.log.log_format,
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
        .optional();
    let config_dir = long("config-dir")
        .long("config_dir")
        .argument::<String>("DIR")
        .optional();
    // Go frp v0.71.0 pflag bool semantics: bare `--strict-config` → true,
    // `--strict-config=false` → false, absent → true. (The space-separated
    // form `--strict-config false` → false is an frp-rs extension, NOT Go
    // pflag semantics — see `parse_go_bool`.) A plain `.switch()` cannot parse
    // a value (audit task 9 finding 3); `or_else` picks the branch that
    // consumes more arguments, so the value form wins whenever a value is
    // present, while the bare form falls back to the switch (which yields
    // `true` both when present and absent).
    // bpaf's `argument` never consumes a `-`-prefixed token as a value, so
    // `--strict-config --config x` still lands on the switch.
    let strict_value = long("strict-config")
        .long("strict_config")
        .argument::<String>("BOOL")
        .parse(parse_go_bool);
    let strict_switch = long("strict-config").long("strict_config").flag(true, true);
    let strict_config = construct!([strict_value, strict_switch]);
    let show_version = long("version").short('v').switch();
    construct!(SvrMeta {
        config,
        config_dir,
        strict_config,
        show_version
    })
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
    construct!(SvrBind {
        bind_addr,
        bind_port,
        proxy_bind_addr
    })
}

fn svr_auth() -> impl Parser<SvrAuth> {
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let allow_ports = long("allow-ports")
        .long("allow_ports")
        .argument::<String>("RANGES")
        .optional();
    let allow_unsafe = long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .collect::<Vec<_>>()
        })
        .fallback(vec![]);
    construct!(SvrAuth {
        token,
        allow_ports,
        allow_unsafe
    })
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
    let enable_prometheus = long("enable-prometheus").long("enable_prometheus").switch();
    construct!(SvrDashboard {
        dashboard_addr,
        dashboard_port,
        dashboard_user,
        dashboard_pwd,
        dashboard_tls_cert_file,
        dashboard_tls_key_file,
        dashboard_tls_mode,
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
    let log_format = long("log-format")
        .long("log_format")
        .argument::<String>("FORMAT")
        .optional();
    let disable_log_color = long("disable-log-color").long("disable_log_color").switch();
    construct!(SvrLog {
        log_file,
        log_level,
        log_max_days,
        log_format,
        disable_log_color
    })
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
        kcp_bind_port,
        quic_bind_port,
        vhost_http_port,
        vhost_https_port,
        subdomain_host,
        max_ports_per_client,
        tls_only,
    })
}

fn frps_build() -> impl Parser<FrpsBuild> {
    let meta = svr_meta();
    let bind = svr_bind();
    let auth = svr_auth();
    let dash = svr_dashboard();
    let log = svr_log();
    let transport = svr_transport();
    construct!(FrpsBuild {
        meta,
        bind,
        auth,
        dash,
        log,
        transport
    })
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
        println!("frps {} (Rust)", crate::VERSION);
        std::process::exit(0);
    }
    args
}

// ──────────────────────────────────────────────────────────────────────
// frpc CLI — run mode + 12 subcommands: tcp, udp, http, https, stcp, xtcp,
// sudp, tcpmux, verify, reload, status, stop. Go frp v0.71.0's `frpc --help`
// lists those 12 plus `nathole` (not implemented here), `completion` and
// `help` (cobra built-ins).
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
    /// Reload running frpc configuration via admin API
    Reload(ReloadArgs),
    /// Query running frpc proxy status via admin API
    Status(StatusArgs),
    /// Stop running frpc via admin API
    Stop(StopArgs),
}

#[derive(Debug, Clone)]
pub struct FrpcRunArgs {
    pub config: String,
    pub config_dir: Option<String>,
    pub strict_config: bool,
    pub allow_unsafe: Vec<String>,
    pub show_version: bool,
    pub log_file: Option<String>,
    pub log_level: Option<String>,
    pub log_max_days: Option<i32>,
    pub log_format: Option<String>,
    pub disable_log_color: bool,
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
    /// Go frp v0.71.0: `strict_config` is a persistent rootCmd flag
    /// (cmd/frpc/sub/root.go), so `frpc verify` honors it too
    /// (cmd/frpc/sub/verify.go passes strictConfigMode to
    /// config.LoadClientConfig).
    pub strict_config: bool,
}

#[derive(Debug, Clone)]
pub struct ReloadArgs {
    pub config: Option<String>,
    pub strict_config: bool,
    pub admin_addr: Option<String>,
    pub admin_port: Option<u16>,
    pub admin_user: Option<String>,
    pub admin_pwd: Option<String>,
    /// Deadline for the whole admin HTTP call; default
    /// [`DEFAULT_ADMIN_API_TIMEOUT`] (Go's `adminAPITimeout`).
    pub api_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct StatusArgs {
    pub config: Option<String>,
    /// Go frp v0.71.0: `--strict-config` is a persistent rootCmd flag
    /// (cmd/frpc/sub/root.go), so `frpc status` accepts it too — and
    /// `NewAdminCommand` passes it to `config.LoadClientConfig`
    /// (cmd/frpc/sub/admin.go:57). Absent → true.
    pub strict_config: bool,
    pub json: bool,
    pub admin_addr: Option<String>,
    pub admin_port: Option<u16>,
    pub admin_user: Option<String>,
    pub admin_pwd: Option<String>,
    /// Deadline for the whole admin HTTP call; default
    /// [`DEFAULT_ADMIN_API_TIMEOUT`] (Go's `adminAPITimeout`).
    pub api_timeout: Duration,
}

/// Arguments of `frpc stop` — [`StatusArgs`] without `--json`, mirroring Go's
/// registration (all three admin commands get the same flag set).
#[derive(Debug, Clone)]
pub struct StopArgs {
    pub config: Option<String>,
    /// Go frp v0.71.0: `--strict-config` is a persistent rootCmd flag
    /// (cmd/frpc/sub/root.go), so `frpc stop` accepts it too — and
    /// `NewAdminCommand` passes it to `config.LoadClientConfig`
    /// (cmd/frpc/sub/admin.go:57). Absent → true.
    pub strict_config: bool,
    pub admin_addr: Option<String>,
    pub admin_port: Option<u16>,
    pub admin_user: Option<String>,
    pub admin_pwd: Option<String>,
    /// Deadline for the whole admin HTTP call; default
    /// [`DEFAULT_ADMIN_API_TIMEOUT`] (Go's `adminAPITimeout`).
    pub api_timeout: Duration,
}

// ─── frpc parser combinators ─────────────────────────────────────────

/// `-c`/`--config`, matching Go's pflag `StringVar`: a repeated flag is
/// **last-wins** and never an error.
///
/// Go registers `-c` with `StringVarP` in a package-level `var` initializer
/// (`cmd/frpc/sub/root.go`), so `frpc status -c a.toml -c b.toml` parses `a`
/// first and overwrites it with `b`. Measured on Go v0.71.0 darwin/arm64 with
/// `noweb.toml` (no `[webServer]`) followed by `p7499.toml`
/// (`[webServer] port = 7499`): `frpc status -c noweb.toml -c p7499.toml` dials
/// `127.0.0.1:7499` (rc 1, `connect: connection refused`) — the first config's
/// port-less refusal is never reached. The reverse order
/// (`-c p7499.toml -c noweb.toml`) prints
/// `web server port should be set if you want to use this feature`.
///
/// bpaf exits with `argument \`-c\` cannot be used multiple times in this
/// context` on the second occurrence, so every frpc parser that takes a config
/// path wraps the argument in [`Parser::last`] (bpaf's documented
/// contradicting-options combinator: run the inner parser as many times as it
/// succeeds and return the last value). `.last()` fails when the flag is
/// absent, exactly like the bare `argument` it replaces, so a required `-c`
/// stays required and an `.optional()`/`.fallback()` wrapper keeps its previous
/// meaning. The `frps` CLI is left alone: that is a separate surface, not part
/// of this item.
fn config_arg() -> impl Parser<String> {
    long("config").short('c').argument::<String>("FILE").last()
}

fn run_mode() -> impl Parser<FrpcRunArgs> {
    let config = config_arg().fallback("frpc.toml".into());
    let config_dir = long("config-dir")
        .long("config_dir")
        .argument::<String>("DIR")
        .optional();
    // Go frp v0.71.0 pflag bool semantics: bare `--strict-config` → true,
    // `--strict-config=false` → false, absent → true. (The space-separated
    // form `--strict-config false` → false is an frp-rs extension, NOT Go
    // pflag semantics — see `parse_go_bool`.) A plain `.switch()` cannot parse
    // a value (audit task 9 finding 3); `or_else` picks the branch that
    // consumes more arguments, so the value form wins whenever a value is
    // present, while the bare form falls back to the switch (which yields
    // `true` both when present and absent).
    // bpaf's `argument` never consumes a `-`-prefixed token as a value, so
    // `--strict-config --config x` still lands on the switch.
    let strict_value = long("strict-config")
        .long("strict_config")
        .argument::<String>("BOOL")
        .parse(parse_go_bool);
    let strict_switch = long("strict-config").long("strict_config").flag(true, true);
    let strict_config = construct!([strict_value, strict_switch]);
    let allow_unsafe = long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .collect::<Vec<_>>()
        })
        .fallback(vec![]);
    let show_version = long("version").short('v').switch();
    let log_file = long("log-file")
        .long("log_file")
        .argument::<String>("FILE")
        .optional();
    let log_level = long("log-level")
        .long("log_level")
        .short('L')
        .argument::<String>("LEVEL")
        .optional();
    let log_max_days = long("log-max-days")
        .long("log_max_days")
        .argument::<i32>("DAYS")
        .optional();
    let log_format = long("log-format")
        .long("log_format")
        .argument::<String>("FORMAT")
        .optional();
    let disable_log_color = long("disable-log-color").long("disable_log_color").switch();
    construct!(FrpcRunArgs {
        config,
        config_dir,
        strict_config,
        allow_unsafe,
        show_version,
        log_file,
        log_level,
        log_max_days,
        log_format,
        disable_log_color
    })
}

// ─── Subcommand parsers (inlined — bpaf construct! doesn't support destructuring tuples from parser fns) ───

fn tcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let remote_port = long("remote-port")
        .long("remote_port")
        .argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let use_encryption = long("use-encryption").long("use_encryption").switch();
    let use_compression = long("use-compression").long("use_compression").switch();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .argument::<String>("NAME")
        .optional();
    let args = construct!(TcpArgs {
        local_ip,
        local_port,
        remote_port,
        server_addr,
        server_port,
        token,
        use_encryption,
        use_compression,
        proxy_name,
    });
    args.to_options()
        .command("tcp")
        .help("Run frpc with a single tcp proxy")
        .map(FrpcCmd::Tcp)
}

fn udp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let remote_port = long("remote-port")
        .long("remote_port")
        .argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .argument::<String>("NAME")
        .optional();
    let args = construct!(UdpArgs {
        local_ip,
        local_port,
        remote_port,
        server_addr,
        server_port,
        token,
        proxy_name,
    });
    args.to_options()
        .command("udp")
        .help("Run frpc with a single udp proxy")
        .map(FrpcCmd::Udp)
}

fn http_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let custom_domains = long("custom-domains")
        .long("custom_domains")
        .argument::<String>("DOMAINS");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let subdomain = long("subdomain").argument::<String>("SUB").optional();
    let locations = long("locations").argument::<String>("LOCS").optional();
    let http_user = long("http-user")
        .long("http_user")
        .argument::<String>("USER")
        .optional();
    let http_pwd = long("http-pwd")
        .long("http_pwd")
        .argument::<String>("PWD")
        .optional();
    let host_header_rewrite = long("host-header-rewrite")
        .long("host_header_rewrite")
        .argument::<String>("HOST")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .argument::<String>("NAME")
        .optional();
    let args = construct!(HttpArgs {
        local_ip,
        local_port,
        custom_domains,
        server_addr,
        server_port,
        token,
        subdomain,
        locations,
        http_user,
        http_pwd,
        host_header_rewrite,
        proxy_name,
    });
    args.to_options()
        .command("http")
        .help("Run frpc with a single http proxy")
        .map(FrpcCmd::Http)
}

fn https_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let custom_domains = long("custom-domains")
        .long("custom_domains")
        .argument::<String>("DOMAINS");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let subdomain = long("subdomain").argument::<String>("SUB").optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .argument::<String>("NAME")
        .optional();
    let args = construct!(HttpsArgs {
        local_ip,
        local_port,
        custom_domains,
        server_addr,
        server_port,
        token,
        subdomain,
        proxy_name,
    });
    args.to_options()
        .command("https")
        .help("Run frpc with a single https proxy")
        .map(FrpcCmd::Https)
}

fn stcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let sk = long("sk").argument::<String>("SECRET");
    let server_name = long("server-name")
        .long("server_name")
        .argument::<String>("NAME")
        .optional();
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let args = construct!(StcpArgs {
        sk,
        server_name,
        local_ip,
        local_port,
        server_addr,
        server_port,
        token,
    });
    args.to_options()
        .command("stcp")
        .help("Run frpc with a single stcp proxy")
        .map(FrpcCmd::Stcp)
}

fn xtcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let sk = long("sk").argument::<String>("SECRET");
    let server_name = long("server-name")
        .long("server_name")
        .argument::<String>("NAME")
        .optional();
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let args = construct!(XtcpArgs {
        sk,
        server_name,
        local_ip,
        local_port,
        server_addr,
        server_port,
        token,
    });
    args.to_options()
        .command("xtcp")
        .help("Run frpc with a single xtcp proxy")
        .map(FrpcCmd::Xtcp)
}

fn sudp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let remote_port = long("remote-port")
        .long("remote_port")
        .argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .argument::<String>("NAME")
        .optional();
    let args = construct!(SudpArgs {
        local_ip,
        local_port,
        remote_port,
        server_addr,
        server_port,
        token,
        proxy_name,
    });
    args.to_options()
        .command("sudp")
        .help("Run frpc with a single sudp proxy")
        .map(FrpcCmd::Sudp)
}

fn tcpmux_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let mux_port = long("mux-port").long("mux_port").argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .argument::<String>("NAME")
        .optional();
    let args = construct!(TcpmuxArgs {
        local_ip,
        local_port,
        mux_port,
        server_addr,
        server_port,
        token,
        proxy_name,
    });
    args.to_options()
        .command("tcpmux")
        .help("Run frpc with a single tcpmux proxy")
        .map(FrpcCmd::Tcpmux)
}

fn verify_cmd() -> impl Parser<FrpcCmd> {
    // `-c` is required here and last-wins on repetition — see [`config_arg`].
    let config = config_arg();
    // Go frp v0.71.0 pflag bool semantics (same as run/reload): `strict_config`
    // is a persistent rootCmd flag (default true), so `verify` inherits it —
    // bare `--strict-config` → true, `--strict-config=false` → false, absent →
    // true. (The space-separated form `--strict-config false` → false is an
    // frp-rs extension, not Go pflag semantics — see `parse_go_bool`.) With
    // strict off, verify
    // accepts unknown fields, matching Go (cmd/frpc/sub/verify.go).
    let strict_value = long("strict-config")
        .long("strict_config")
        .argument::<String>("BOOL")
        .parse(parse_go_bool);
    let strict_switch = long("strict-config").long("strict_config").flag(true, true);
    let strict_config = construct!([strict_value, strict_switch]);
    let args = construct!(VerifyArgs {
        config,
        strict_config
    });
    args.to_options()
        .command("verify")
        .help("Verify that the configuration is valid")
        .map(FrpcCmd::Verify)
}

fn reload_cmd() -> impl Parser<FrpcCmd> {
    // Last-wins on repetition; still optional here — see [`config_arg`].
    let config = config_arg().optional();
    // Go frp v0.71.0 pflag bool semantics: `--strict_config` is a
    // *persistent* rootCmd flag (default true), so the reload subcommand
    // inherits the run-mode semantics — bare `--strict-config` → true,
    // `--strict-config=false` → false, absent → true. (The space-separated
    // form `--strict-config false` → false is an frp-rs extension, not Go
    // pflag semantics — see `parse_go_bool`.) The value is sent to the running
    // frpc as `{"strictConfig":...}`
    // (frpc run_reload → /api/reload). A plain `.switch()` cannot parse a
    // value (the same bug fixed in svr_meta/run_mode); `or_else` picks the
    // branch that consumes more arguments, so the value form wins whenever
    // a value is present, while the bare form falls back to the switch.
    // bpaf's `argument` never consumes a `-`-prefixed token as a value, so
    // `--strict-config --config x` still lands on the switch.
    let strict_value = long("strict-config")
        .long("strict_config")
        .argument::<String>("BOOL")
        .parse(parse_go_bool);
    let strict_switch = long("strict-config").long("strict_config").flag(true, true);
    let strict_config = construct!([strict_value, strict_switch]);
    let admin_addr = long("admin-addr")
        .long("admin_addr")
        .argument::<String>("IP")
        .optional();
    let admin_port = long("admin-port")
        .long("admin_port")
        .argument::<u16>("PORT")
        .optional();
    let admin_user = long("admin-user")
        .long("admin_user")
        .argument::<String>("USER")
        .optional();
    let admin_pwd = long("admin-pwd")
        .long("admin_pwd")
        .argument::<String>("PWD")
        .optional();
    let api_timeout = api_timeout_parser();
    let args = construct!(ReloadArgs {
        config,
        strict_config,
        admin_addr,
        admin_port,
        admin_user,
        admin_pwd,
        api_timeout
    });
    args.to_options()
        .command("reload")
        .help("Reload running frpc configuration")
        .map(FrpcCmd::Reload)
}

fn status_cmd() -> impl Parser<FrpcCmd> {
    // Last-wins on repetition; still optional here — see [`config_arg`].
    let config = config_arg().optional();
    // Go frp v0.71.0: `--strict-config` is a *persistent* rootCmd flag
    // (default true) inherited by every subcommand, `status` included — probe:
    // `frpc status --strict-config=false -c bad.toml` is accepted and tolerates
    // unknown fields. Same semantics as reload/run: bare `--strict-config` →
    // true, `--strict-config=false` → false, absent → true. (The
    // space-separated form `--strict-config false` → false is an frp-rs
    // extension, not Go pflag semantics — see `parse_go_bool`.)
    let strict_value = long("strict-config")
        .long("strict_config")
        .argument::<String>("BOOL")
        .parse(parse_go_bool);
    let strict_switch = long("strict-config").long("strict_config").flag(true, true);
    let strict_config = construct!([strict_value, strict_switch]);
    let json = long("json").switch();
    let admin_addr = long("admin-addr")
        .long("admin_addr")
        .argument::<String>("IP")
        .optional();
    let admin_port = long("admin-port")
        .long("admin_port")
        .argument::<u16>("PORT")
        .optional();
    let admin_user = long("admin-user")
        .long("admin_user")
        .argument::<String>("USER")
        .optional();
    let admin_pwd = long("admin-pwd")
        .long("admin_pwd")
        .argument::<String>("PWD")
        .optional();
    let api_timeout = api_timeout_parser();
    let args = construct!(StatusArgs {
        config,
        strict_config,
        json,
        admin_addr,
        admin_port,
        admin_user,
        admin_pwd,
        api_timeout
    });
    args.to_options()
        .command("status")
        .help("Query running frpc proxy status")
        .map(FrpcCmd::Status)
}

/// `frpc stop` — Go frp v0.71.0 `cmd/frpc/sub/admin.go:42` registers it with
/// the short text `Stop the running frpc`, the same config load / port refusal
/// as the other two admin commands, and the same `--api-timeout` flag.
fn stop_cmd() -> impl Parser<FrpcCmd> {
    // Last-wins on repetition; still optional here — see [`config_arg`].
    let config = config_arg().optional();
    // Same persistent-rootCmd-flag semantics as reload/status: bare
    // `--strict-config` → true, `--strict-config=false` → false, absent → true.
    // (The space-separated form `--strict-config false` → false is an frp-rs
    // extension, not Go pflag semantics — see `parse_go_bool`.)
    let strict_value = long("strict-config")
        .long("strict_config")
        .argument::<String>("BOOL")
        .parse(parse_go_bool);
    let strict_switch = long("strict-config").long("strict_config").flag(true, true);
    let strict_config = construct!([strict_value, strict_switch]);
    let admin_addr = long("admin-addr")
        .long("admin_addr")
        .argument::<String>("IP")
        .optional();
    let admin_port = long("admin-port")
        .long("admin_port")
        .argument::<u16>("PORT")
        .optional();
    let admin_user = long("admin-user")
        .long("admin_user")
        .argument::<String>("USER")
        .optional();
    let admin_pwd = long("admin-pwd")
        .long("admin_pwd")
        .argument::<String>("PWD")
        .optional();
    let api_timeout = api_timeout_parser();
    let args = construct!(StopArgs {
        config,
        strict_config,
        admin_addr,
        admin_port,
        admin_user,
        admin_pwd,
        api_timeout
    });
    args.to_options()
        .command("stop")
        .help("Stop the running frpc")
        .map(FrpcCmd::Stop)
}

/// Compose all frpc subcommands + run-mode fallback.
fn frpc_parser() -> impl Parser<FrpcCmd> {
    let run = run_mode().map(|args| {
        if args.show_version {
            println!("frpc {} (Rust)", crate::VERSION);
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
        reload_cmd(),
        status_cmd(),
        stop_cmd(),
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
    /// Config file path to load. Falls back to "frps.toml" when `-c` was
    /// not given on the command line.
    pub fn config_path(&self) -> String {
        self.config
            .clone()
            .unwrap_or_else(|| "frps.toml".to_string())
    }

    /// Whether CLI config flags may override the loaded config file.
    /// Go frp v0.70.1 parity: with an explicit `-c` (or `--config-dir`) the
    /// file is authoritative and flags are ignored; without `-c` the CLI
    /// flags act as overrides on top of the default config file (audit task
    /// 9 finding 5).
    pub fn cli_overrides_enabled(&self) -> bool {
        self.config.is_none() && self.config_dir.is_none()
    }

    /// Override ServerConfig fields with CLI values. Only fields explicitly
    /// set on the command line (`Some`) override config file values.
    /// Callers should skip this entirely when
    /// [`cli_overrides_enabled`](FrpsArgs::cli_overrides_enabled) is false
    /// (Go frp v0.70.1 gives the config file precedence when `-c` is given).
    pub fn override_server_config(&self, cfg: &mut crate::config::ServerConfig) {
        if let Some(ref v) = self.token {
            cfg.auth.token = v.clone();
        }
        if let Some(ref v) = self.allow_ports {
            cfg.allow_ports = v.clone();
        }
        if let Some(ref v) = self.bind_addr {
            cfg.bind_addr = v.clone();
        }
        if let Some(v) = self.bind_port {
            cfg.bind_port = v;
        }
        if let Some(ref v) = self.proxy_bind_addr {
            cfg.proxy_bind_addr = v.clone();
        }

        // Log
        if let Some(ref v) = self.log_file {
            cfg.log.file = v.clone();
        }
        if let Some(ref v) = self.log_level {
            cfg.log.level = v.clone();
        }
        if let Some(v) = self.log_max_days {
            cfg.log.max_days = v;
        }
        if let Some(ref v) = self.log_format {
            cfg.log.format = v.clone();
        }

        // Transport / ports
        #[cfg(feature = "kcp")]
        if let Some(v) = self.kcp_bind_port {
            cfg.kcp_bind_port = v;
        }
        #[cfg(feature = "quic")]
        if let Some(v) = self.quic_bind_port {
            cfg.quic_bind_port = v;
        }
        if let Some(v) = self.vhost_http_port {
            cfg.vhost_http_port = v;
        }
        if let Some(v) = self.vhost_https_port {
            cfg.vhost_https_port = v;
        }
        if let Some(ref v) = self.subdomain_host {
            cfg.sub_domain_host = v.clone();
        }
        if let Some(v) = self.max_ports_per_client {
            cfg.max_ports_per_client = v;
        }
        if self.tls_only {
            cfg.tls_only = true;
        }

        // Dashboard
        if let Some(ref v) = self.dashboard_addr {
            cfg.web_server.addr = v.clone();
        }
        if let Some(v) = self.dashboard_port {
            cfg.web_server.port = v;
        }
        if let Some(ref v) = self.dashboard_user {
            cfg.web_server.user = v.clone();
        }
        if let Some(ref v) = self.dashboard_pwd {
            cfg.web_server.password = v.clone();
        }
        if self.enable_prometheus {
            cfg.web_server.enable_prometheus = true;
        }
        if let Some(ref v) = self.dashboard_tls_cert_file {
            cfg.web_server.tls_cert_file = v.clone();
        }
        if let Some(ref v) = self.dashboard_tls_key_file {
            cfg.web_server.tls_key_file = v.clone();
        }
        // dashboard_tls_mode: no config field needed — TLS activates when both
        // cert_file and key_file are non-empty (implicit detection, matching Go frp).
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
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("tcp-{}->{}", self.local_port, self.remote_port)),
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
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("udp-{}->{}", self.local_port, self.remote_port)),
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
        let domains: Vec<String> = self
            .custom_domains
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        crate::config::ProxyConfig {
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("http-{}", self.local_port)),
            proxy_type: "http".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            custom_domains: domains,
            subdomain: self.subdomain.clone().unwrap_or_default(),
            locations: self
                .locations
                .clone()
                .map(|l| l.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            http_user: self.http_user.clone().unwrap_or_default(),
            http_pwd: self.http_pwd.clone().unwrap_or_default(),
            host_header_rewrite: self.host_header_rewrite.clone().unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl HttpsArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let domains: Vec<String> = self
            .custom_domains
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        crate::config::ProxyConfig {
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("https-{}", self.local_port)),
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
            name: self
                .server_name
                .clone()
                .unwrap_or_else(|| "stcp-proxy".into()),
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
            name: self
                .server_name
                .clone()
                .unwrap_or_else(|| "xtcp-proxy".into()),
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
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("sudp-{}->{}", self.local_port, self.remote_port)),
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
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("tcpmux-{}", self.local_port)),
            proxy_type: "tcpmux".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            remote_port: self.mux_port,
            multiplexer: "httpconnect".into(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_frps(args: &[&str]) -> Result<FrpsArgs, bpaf::ParseFailure> {
        frps_args().to_options().run_inner(args)
    }

    fn parse_frpc_run(args: &[&str]) -> Result<FrpcRunArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Run(a) => Ok(a),
            other => panic!("expected run mode, got {other:?}"),
        }
    }

    fn parse_frpc_reload(args: &[&str]) -> Result<ReloadArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Reload(a) => Ok(a),
            other => panic!("expected reload command, got {other:?}"),
        }
    }

    fn parse_frpc_verify(args: &[&str]) -> Result<VerifyArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Verify(a) => Ok(a),
            other => panic!("expected verify command, got {other:?}"),
        }
    }

    fn parse_frpc_status(args: &[&str]) -> Result<StatusArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Status(a) => Ok(a),
            other => panic!("expected status command, got {other:?}"),
        }
    }

    fn parse_frpc_stop(args: &[&str]) -> Result<StopArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Stop(a) => Ok(a),
            other => panic!("expected stop command, got {other:?}"),
        }
    }

    #[test]
    fn strict_config_defaults_to_true() {
        assert!(parse_frps(&[]).unwrap().strict_config);
        assert!(parse_frpc_run(&[]).unwrap().strict_config);
    }

    #[test]
    fn strict_config_bare_flag_is_true() {
        assert!(parse_frps(&["--strict-config"]).unwrap().strict_config);
        assert!(parse_frpc_run(&["--strict-config"]).unwrap().strict_config);
    }

    #[test]
    fn strict_config_equals_false_parses_and_disables() {
        // Audit task 9 finding 3: `--strict-config=false` was a parse error
        // with a plain switch; it must parse and disable strict mode.
        // Both hyphen and underscore forms, both frps and frpc run mode.
        for args in [
            &["--strict-config=false"][..],
            &["--strict_config=false"][..],
        ] {
            assert!(!parse_frps(args).unwrap().strict_config, "{args:?}");
            assert!(!parse_frpc_run(args).unwrap().strict_config, "{args:?}");
        }
    }

    #[test]
    fn strict_config_equals_true_parses() {
        assert!(parse_frps(&["--strict-config=true"]).unwrap().strict_config);
        assert!(
            parse_frpc_run(&["--strict-config=true"])
                .unwrap()
                .strict_config
        );
    }

    #[test]
    fn strict_config_space_separated_value_parses() {
        // frp-rs extension (NOT Go pflag semantics — Go keeps strict=true and
        // ignores the stray token): the space-separated form
        // `--strict-config false` disables strict mode just like
        // `--strict-config=false`. Both hyphen and underscore forms, both
        // frps and frpc run mode.
        for args in [
            &["--strict-config", "false"][..],
            &["--strict_config", "false"][..],
        ] {
            assert!(!parse_frps(args).unwrap().strict_config, "{args:?}");
            assert!(!parse_frpc_run(args).unwrap().strict_config, "{args:?}");
        }
        // Go strconv.ParseBool spellings.
        for v in ["1", "t", "T", "TRUE", "true", "True"] {
            assert!(
                parse_frps(&["--strict-config", v]).unwrap().strict_config,
                "{v}"
            );
            assert!(
                parse_frpc_run(&["--strict-config", v])
                    .unwrap()
                    .strict_config,
                "{v}"
            );
        }
        for v in ["0", "f", "F", "FALSE", "false", "False"] {
            assert!(
                !parse_frps(&["--strict-config", v]).unwrap().strict_config,
                "{v}"
            );
            assert!(
                !parse_frpc_run(&["--strict-config", v])
                    .unwrap()
                    .strict_config,
                "{v}"
            );
        }
    }

    #[test]
    fn reload_strict_config_matches_run_mode_semantics() {
        // Go frp v0.71.0: --strict_config is a persistent rootCmd flag
        // (default true), so the reload subcommand inherits run-mode
        // semantics — absent → true, bare → true, `--strict-config=false` →
        // false (matches Go pflag). The space-separated
        // `--strict-config false` → false is an frp-rs extension, NOT Go pflag
        // semantics (measured: Go keeps strict=true and leaves `false` as an
        // unused positional argument — see `parse_go_bool`). The old plain
        // switch made the `=false` form a parse error
        // and the absent default false; the value is sent to the running
        // frpc as `{"strictConfig":...}`, so the parsed value matters.
        // The subcommand word comes first: `reload [--strict-config ...]`.
        assert!(parse_frpc_reload(&["reload"]).unwrap().strict_config);
        assert!(
            parse_frpc_reload(&["reload", "--strict-config"])
                .unwrap()
                .strict_config
        );
        assert!(
            !parse_frpc_reload(&["reload", "--strict-config=false"])
                .unwrap()
                .strict_config
        );
        assert!(
            !parse_frpc_reload(&["reload", "--strict-config", "false"])
                .unwrap()
                .strict_config
        );
        assert!(
            parse_frpc_reload(&["reload", "--strict_config", "true"])
                .unwrap()
                .strict_config
        );
    }

    #[test]
    fn verify_strict_config_parses_like_run_mode() {
        // Go frp v0.71.0: --strict_config is a persistent rootCmd flag
        // (default true), so the `verify` subcommand inherits run-mode
        // semantics — absent → true, bare → true, `--strict-config=false` →
        // false (matches Go pflag), while the space-separated
        // `--strict-config false` → false is an frp-rs extension, NOT Go pflag
        // semantics (see `parse_go_bool`)
        // (cmd/frpc/sub/verify.go passes strictConfigMode to
        // config.LoadClientConfig). Round-8 fix 7e.
        let args = parse_frpc_verify(&["verify", "-c", "x.toml"]).unwrap();
        assert_eq!(args.config, "x.toml");
        assert!(
            args.strict_config,
            "verify defaults to strict config (Go rootCmd persistent flag)"
        );
        assert!(
            parse_frpc_verify(&["verify", "-c", "x.toml", "--strict-config"])
                .unwrap()
                .strict_config
        );
        assert!(
            !parse_frpc_verify(&["verify", "-c", "x.toml", "--strict-config=false"])
                .unwrap()
                .strict_config
        );
        assert!(
            !parse_frpc_verify(&["verify", "-c", "x.toml", "--strict-config", "false"])
                .unwrap()
                .strict_config
        );
        assert!(
            parse_frpc_verify(&["verify", "-c", "x.toml", "--strict_config=true"])
                .unwrap()
                .strict_config
        );
    }

    #[test]
    fn strict_config_invalid_value_errors_cleanly() {
        // `--strict-config foo`: the value branch fails parse_go_bool and
        // or_else backtracks to the switch, which consumes only the flag —
        // the leftover `foo` must then fail the parse, not be swallowed.
        // NOTE: Go does **not** error here — measured on v0.71.0,
        // `frpc reload --strict-config foo -c <cfg>` ignores the stray token
        // and keeps strict=true; Go errors only on the adjacent form
        // (`--strict-config=foo`), with a different message. frp-rs's
        // rejection is the stricter, frp-rs-specific behaviour (TODO.md).
        // Both frps and frpc, all
        // three surfaces (run mode, reload subcommand).
        assert!(parse_frps(&["--strict-config", "foo"]).is_err());
        assert!(parse_frpc_run(&["--strict-config", "foo"]).is_err());
        assert!(parse_frpc_reload(&["reload", "--strict-config", "foo"]).is_err());
    }

    #[test]
    fn strict_config_bare_before_other_flags_is_true() {
        // The optional value must not swallow a following flag token: bpaf's
        // `argument` never consumes a `-`-prefixed token, so a bare
        // `--strict-config` followed by another flag still means "true".
        let args = parse_frps(&["--strict-config", "--config", "frps.toml"]).unwrap();
        assert!(args.strict_config);
        assert_eq!(args.config_path(), "frps.toml");
    }

    #[test]
    fn dashboard_addr_flag_applied_to_web_server() {
        // Audit task 9 finding 4: --dashboard-addr was parsed but never
        // applied to the config.
        let args = parse_frps(&["--dashboard-addr", "1.2.3.4"]).unwrap();
        let mut cfg = crate::config::ServerConfig::default();
        args.override_server_config(&mut cfg);
        assert_eq!(cfg.web_server.addr, "1.2.3.4");
    }

    #[test]
    fn config_file_precedence_go_parity() {
        // Audit task 9 finding 5: with an explicit `-c` (or --config-dir)
        // the file is authoritative — CLI overrides are disabled, matching
        // Go frp v0.70.1 (root.go: flags only apply when cfgFile == "").
        let no_c = parse_frps(&[]).unwrap();
        assert_eq!(no_c.config_path(), "frps.toml");
        assert!(no_c.cli_overrides_enabled());

        let with_c = parse_frps(&["-c", "/etc/frp/frps.toml"]).unwrap();
        assert_eq!(with_c.config_path(), "/etc/frp/frps.toml");
        assert!(!with_c.cli_overrides_enabled());

        let with_dir = parse_frps(&["--config-dir", "/etc/frp/conf.d"]).unwrap();
        assert!(!with_dir.cli_overrides_enabled());
    }

    // ── frpc stop / --api-timeout ───────────────────────────────────────

    /// Parse `argv` (a whole admin-subcommand invocation) and return its
    /// `--api-timeout`, so a grammar case can be pinned on all three
    /// subcommands that must carry the flag.
    fn admin_api_timeout(argv: &[&str]) -> Duration {
        match argv[0] {
            "reload" => parse_frpc_reload(argv).unwrap().api_timeout,
            "status" => parse_frpc_status(argv).unwrap().api_timeout,
            "stop" => parse_frpc_stop(argv).unwrap().api_timeout,
            other => panic!("not an admin subcommand: {other}"),
        }
    }

    #[test]
    fn api_timeout_defaults_to_go_30s() {
        // Go frp v0.71.0 `var adminAPITimeout = 30 * time.Second`
        // (cmd/frpc/sub/admin.go:32); absent flag → 30 s. Checked on all three
        // subcommands because Go registers the default per subcommand.
        assert_eq!(DEFAULT_ADMIN_API_TIMEOUT, Duration::from_secs(30));
        assert_eq!(
            parse_frpc_reload(&["reload"]).unwrap().api_timeout,
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_frpc_status(&["status"]).unwrap().api_timeout,
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_frpc_stop(&["stop"]).unwrap().api_timeout,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn api_timeout_parses_go_duration_grammar() {
        // Every value on the left was measured *accepted* by Go v0.71.0
        // (`frpc stop --api-timeout=<v> -c frpc.toml` with a refused admin
        // port); the right-hand side is `time.ParseDuration`'s value. Run on
        // reload/status/stop so the grammar cannot be wired to one command.
        let cases: [(&str, Duration); 15] = [
            ("1m", Duration::from_secs(60)),
            ("500ms", Duration::from_millis(500)),
            ("1h2m3.5s", Duration::from_millis(3_723_500)),
            ("1s500ms", Duration::from_millis(1_500)),
            ("1m0s", Duration::from_secs(60)),
            ("1.5h", Duration::from_secs(5_400)),
            (".5s", Duration::from_millis(500)),
            ("+1s", Duration::from_secs(1)),
            ("100us", Duration::from_micros(100)),
            ("1µs", Duration::from_micros(1)),
            ("1μs", Duration::from_micros(1)),
            ("0", Duration::ZERO),
            ("0s", Duration::ZERO),
            ("-1s", Duration::ZERO),
            (
                "2562047h47m16.854775807s",
                Duration::from_nanos(i64::MAX as u64),
            ),
        ];
        for command in ["reload", "status", "stop"] {
            for (text, expected) in cases {
                let flag = format!("--api-timeout={text}");
                assert_eq!(
                    admin_api_timeout(&[command, &flag]),
                    expected,
                    "{command} {flag}"
                );
            }
        }
        // `-1s` reaches the CLI as ZERO because a `Duration` cannot be
        // negative and the consumer only needs "deadline already past"
        // (see `parse_go_duration`).
        assert_eq!(parse_go_duration("-1s".into()).unwrap(), Duration::ZERO);
    }

    #[test]
    fn api_timeout_rejects_what_go_rejects() {
        // Measured rejected by Go v0.71.0, exit 1, message + usage on stderr:
        // `1` → `time: missing unit in duration "1"`; `abc`/`Inf` →
        // `time: invalid duration "…"`; `1d`/`1S`/`1Ms`/`1e3s` → `time: unknown
        // unit "…" in duration "…"`; `2562048h` and a 21-digit hour count →
        // `time: invalid duration "…"` (overflow).
        for text in [
            "1",
            "abc",
            "1d",
            "1S",
            "1Ms",
            "1e3s",
            "Inf",
            "2562048h",
            "999999999999999999999h",
            "",
        ] {
            assert!(parse_go_duration(text.into()).is_err(), "{text:?}");
            for command in ["reload", "status", "stop"] {
                for prefix in ["--api-timeout", "--api_timeout"] {
                    let flag = format!("{prefix}={text}");
                    assert!(
                        frpc_parser()
                            .to_options()
                            .run_inner(&[command, &flag][..])
                            .is_err(),
                        "{command} {flag} must be rejected"
                    );
                }
            }
        }
        // The two wordings the brief pins verbatim.
        assert_eq!(
            parse_go_duration("1".into()).unwrap_err(),
            "time: missing unit in duration \"1\""
        );
        assert_eq!(
            parse_go_duration("abc".into()).unwrap_err(),
            "time: invalid duration \"abc\""
        );
    }

    #[test]
    fn api_timeout_rejects_go_uint64_wrap_where_go_accepts_zero() {
        // The one divergence a 420-value randomised differential sweep found:
        // Go accumulates the group total in a `uint64` (`d += v`) and only
        // checks `d > 1<<63`, so two 2^63 ns groups wrap to 0 and Go *accepts*
        // this input as 0 ns — measured on the v0.71.0 binary, `frpc stop
        // --api-timeout=9223372036854775808ns9223372036854775808ns` prints
        // `context deadline exceeded`, exit 1. frp-rs uses checked arithmetic
        // and rejects it: stricter than Go, and never a panic.
        let wrapped = "9223372036854775808ns9223372036854775808ns";
        assert_eq!(
            parse_go_duration(wrapped.into()).unwrap_err(),
            "time: invalid duration \"9223372036854775808ns9223372036854775808ns\""
        );
        for command in ["reload", "status", "stop"] {
            let flag = format!("--api-timeout={wrapped}");
            assert!(
                frpc_parser()
                    .to_options()
                    .run_inner(&[command, &flag][..])
                    .is_err(),
                "{command} {flag} must be rejected"
            );
        }
    }

    #[test]
    fn api_timeout_is_not_accepted_outside_the_three_admin_commands() {
        // Go registers `--api-timeout` per subcommand inside `init()`'s loop
        // (cmd/frpc/sub/admin.go:45-49, the DurationVar at :47); measured on
        // v0.71.0, `frpc verify --api-timeout=1s` → `Error: unknown flag:
        // --api-timeout`, exit 1. Same for the underscore spelling.
        let tcp: [&str; 5] = ["tcp", "--local-port", "1", "--remote-port", "2"];
        assert!(
            frpc_parser().to_options().run_inner(&tcp[..]).is_ok(),
            "control: the tcp invocation without the flag must parse"
        );
        for argv in [
            &["--api-timeout", "1s"][..],
            &["verify", "--api-timeout=1s", "-c", "x.toml"][..],
            &["verify", "--api_timeout=1s", "-c", "x.toml"][..],
            &[
                "tcp",
                "--api-timeout=1s",
                "--local-port",
                "1",
                "--remote-port",
                "2",
            ][..],
        ] {
            assert!(
                frpc_parser().to_options().run_inner(argv).is_err(),
                "{argv:?} must be rejected"
            );
        }
    }

    #[test]
    fn api_timeout_underscore_spelling_matches_go() {
        // Go v0.71.0 accepts `--api_timeout` on these three subcommands as it
        // accepts every hyphen spelling (measured: `frpc stop
        // --api_timeout=abc` fails on `--api-timeout`, so the alias reaches the
        // same flag, while `--api_timeoutt` is `unknown flag`;
        // `docs/deployment.md` carries the mechanism). frp-rs registers both
        // spellings here and must enforce the same grammar on each.
        assert_eq!(
            admin_api_timeout(&["stop", "--api_timeout=500ms"]),
            Duration::from_millis(500)
        );
        assert_eq!(
            admin_api_timeout(&["reload", "--api_timeout", "2s"]),
            Duration::from_secs(2)
        );
        assert!(
            parse_frpc_status(&["status", "--api_timeout=abc"]).is_err(),
            "the alias must enforce the same grammar as the hyphen spelling"
        );
    }

    #[test]
    fn stop_accepts_the_shared_admin_flags_and_defaults_strict() {
        let args = parse_frpc_stop(&[
            "stop",
            "-c",
            "x.toml",
            "--strict-config=false",
            "--admin-addr",
            "10.0.0.1",
            "--admin-port",
            "7401",
            "--admin-user",
            "u",
            "--admin-pwd",
            "p",
        ])
        .unwrap();
        assert_eq!(args.config.as_deref(), Some("x.toml"));
        assert!(!args.strict_config);
        assert_eq!(args.admin_addr.as_deref(), Some("10.0.0.1"));
        assert_eq!(args.admin_port, Some(7401));
        assert_eq!(args.admin_user.as_deref(), Some("u"));
        assert_eq!(args.admin_pwd.as_deref(), Some("p"));
        assert_eq!(args.api_timeout, DEFAULT_ADMIN_API_TIMEOUT);
        // `--strict-config` is a persistent rootCmd flag (default true), so
        // stop inherits run-mode semantics like reload/status.
        assert!(parse_frpc_stop(&["stop"]).unwrap().strict_config);
        assert!(
            parse_frpc_stop(&["stop", "--strict_config"])
                .unwrap()
                .strict_config
        );
        assert!(
            !parse_frpc_stop(&["stop", "--strict_config", "false"])
                .unwrap()
                .strict_config
        );
    }

    #[test]
    fn stop_help_is_go_short_text() {
        // Go v0.71.0 `cmd/frpc/sub/admin.go:42` registers the short text
        // `Stop the running frpc`, and `frpc --help` lists it under
        // `Available Commands`. bpaf renders the per-command `.help()` string
        // in the parent's command list, which is where frp-rs prints it:
        // `frpc --help` shows `stop` with this text.
        let failure = frpc_parser()
            .to_options()
            .run_inner(&["--help"][..])
            .expect_err("--help is reported as a ParseFailure");
        match failure {
            bpaf::ParseFailure::Stdout(doc, _) => {
                let text = doc.to_string();
                assert!(text.contains("Stop the running frpc"), "help={text}");
            }
            other => panic!("expected help on stdout, got {other:?}"),
        }
    }

    // ── `-c`/`--config` is last-wins, like Go's pflag StringVarP ──────────
    //
    // Go registers `-c` with `StringVarP` in a package-level initializer
    // (`cmd/frpc/sub/root.go`), so a repeated flag is never an error and the
    // last value wins. Measured on Go v0.71.0 darwin/arm64:
    // `frpc status -c noweb.toml -c p7499.toml` dials `127.0.0.1:7499` and
    // `-c p7499.toml -c noweb.toml` prints Go's port refusal (see
    // `frpc/tests/cli_inputs.rs` for the end-to-end form). bpaf failed the
    // second occurrence with
    // ``argument `-c` cannot be used multiple times in this context`` before
    // every frpc parser was routed through `config_arg`.

    #[test]
    fn run_mode_config_is_last_wins() {
        let args = parse_frpc_run(&["-c", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config, "b.toml");
        // Mixed spellings are the same pflag variable.
        let args = parse_frpc_run(&["--config", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config, "b.toml");
        // Three occurrences: still the last.
        let args = parse_frpc_run(&["-c", "a.toml", "-c", "b.toml", "-c", "c.toml"]).unwrap();
        assert_eq!(args.config, "c.toml");
        // Absent keeps the frp-rs default; one occurrence is unchanged.
        assert_eq!(parse_frpc_run(&[]).unwrap().config, "frpc.toml");
        assert_eq!(
            parse_frpc_run(&["-c", "only.toml"]).unwrap().config,
            "only.toml"
        );
        // The flag still needs a value.
        assert!(parse_frpc_run(&["-c"]).is_err());
    }

    #[test]
    fn verify_config_is_last_wins_and_still_required() {
        let args = parse_frpc_verify(&["verify", "-c", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config, "b.toml");
        assert_eq!(
            parse_frpc_verify(&["verify", "-c", "only.toml"])
                .unwrap()
                .config,
            "only.toml"
        );
        // No fallback here: `verify` refuses a missing `-c`, as before.
        assert!(parse_frpc_verify(&["verify"]).is_err());
        assert!(parse_frpc_verify(&["verify", "-c"]).is_err());
    }

    #[test]
    fn admin_config_is_last_wins_and_still_optional() {
        // The subcommand name is part of the argv: without it bpaf falls back
        // to run mode (the last branch of the `construct!` alternation).
        let args = parse_frpc_reload(&["reload", "-c", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config.as_deref(), Some("b.toml"));
        let args = parse_frpc_status(&["status", "-c", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config.as_deref(), Some("b.toml"));
        let args = parse_frpc_stop(&["stop", "-c", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config.as_deref(), Some("b.toml"));
        // Absent stays `None` for all three (the frp-rs `127.0.0.1:7400`
        // default path, a recorded divergence).
        assert_eq!(parse_frpc_reload(&["reload"]).unwrap().config, None);
        assert_eq!(parse_frpc_status(&["status"]).unwrap().config, None);
        assert_eq!(parse_frpc_stop(&["stop"]).unwrap().config, None);
        assert!(parse_frpc_reload(&["reload", "-c"]).is_err());
        assert!(parse_frpc_status(&["status", "-c"]).is_err());
        assert!(parse_frpc_stop(&["stop", "-c"]).is_err());
    }

    #[test]
    fn config_help_says_the_flag_may_repeat() {
        // bpaf renders `last()` as a repeatable option (`-c=FILE...`), which is
        // accurate for pflag. Pinned so the help cannot drift back to a
        // single-use spelling while the parser stays last-wins.
        let failure = frpc_parser()
            .to_options()
            .run_inner(&["--help"][..])
            .expect_err("--help is reported as a ParseFailure");
        match failure {
            bpaf::ParseFailure::Stdout(doc, _) => {
                let text = doc.to_string();
                assert!(text.contains("[-c=FILE...]"), "help={text}");
            }
            other => panic!("expected help on stdout, got {other:?}"),
        }
        let failure = frpc_parser()
            .to_options()
            .run_inner(&["verify", "--help"][..])
            .expect_err("verify --help is reported as a ParseFailure");
        match failure {
            bpaf::ParseFailure::Stdout(doc, _) => {
                let text = doc.to_string();
                assert!(text.contains("verify -c=FILE..."), "help={text}");
            }
            other => panic!("expected help on stdout, got {other:?}"),
        }
    }
}
