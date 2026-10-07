//! SSH remote-command argument parsing (Go frp `pkg/ssh` flag-spelling parity).
//!
//! Split out of `ssh_gateway.rs` as a pure text move; the parent re-imports the
//! parsed-args type and entry point its session handler uses, and the sibling
//! test module re-imports the shell splitter and valid-type table.

/// Parsed result from an SSH remote command string.
#[derive(Debug, PartialEq)]
pub(super) struct ParsedProxyArgs {
    pub(super) proxy_type: String,
    pub(super) proxy_name: String,
    pub(super) remote_port: u16,
    pub(super) local_ip: String,
    pub(super) local_port: u16,
    pub(super) custom_domains: Vec<String>,
    pub(super) subdomain: String,
    pub(super) sk: String,
    pub(super) multiplexer: String,
    pub(super) use_encryption: bool,
    pub(super) use_compression: bool,
    pub(super) group: String,
    pub(super) group_key: String,
    pub(super) http_user: String,
    pub(super) http_pwd: String,
    pub(super) host_header_rewrite: String,
    pub(super) locations: Vec<String>,
    /// Go `--metadatas` k=v pairs (pkg/config/flags.go
    /// registerProxyBaseConfigFlags, pflag StringToString): comma-separated,
    /// accumulating across repeated occurrences; later same-key pairs win.
    pub(super) metadatas: Vec<(String, String)>,
    /// Go `--annotations` k=v pairs — same StringToString semantics.
    pub(super) annotations: Vec<(String, String)>,
    /// Go `--allow_users` (STCP only, pflag StringSlice): comma-separated,
    /// accumulating across repeated occurrences.
    pub(super) allow_users: Vec<String>,
    /// Go persistent `--user` / `-u` (RegisterClientCommonConfigFlags,
    /// pkg/ssh/server.go consumes it at virtual-client login).
    pub(super) user: String,
    /// Go persistent `--token` / `-t`.
    pub(super) token: String,
    /// Go persistent `--client-id` (no shorthand).
    pub(super) client_id: String,
}

/// Parse SSH remote command args like:
///   "tcp --proxy_name \"web\" --remote_port 9090"
///   "http --proxy_name \"blog\" --custom_domain \"a,b\""
pub(super) fn parse_ssh_args(cmd: &str) -> Result<ParsedProxyArgs, String> {
    // FIX 4 (Go parity, pkg/ssh/server.go parseClientAndProxyConfigurer):
    // the type token is matched EXACTLY after TrimSpace — no case folding —
    // against Go's support-types order [tcp http https tcpmux stcp]; a
    // mismatch is the verbatim Go error (server.go:273-277), written to the
    // client before the connection closes. (`TCP`, `Tcp`, trailing garbage
    // inside a quoted token all land here.)
    //
    // A whitespace-only command answers the same error with a blank type:
    // Go has no empty-command special case — strings.Split("   ", " ")
    // yields ["", "", "", ""] and args[0]="" fails the support-types
    // Contains check (server.go:267-277), so the whitespace-only path is
    // genuine Go parity. A truly EMPTY payload, by contrast, never reaches
    // Go's parse at all: the gateway's addr+payload wait loop breaks only
    // on extraPayload != "" (server.go:253), so an empty exec payload
    // stalls the full 3s window and dies server-side with "get addr and
    // extra payload timeout" (server.go:251) — no client text. frp-rs's
    // exec handler intercepts the empty (post-trim) payload with the usage
    // text before parse_ssh_args is reached; the blank-type text below is
    // thus a direct-call-only invariant here (see exec_request).
    let parts = shell_split(cmd);
    let proxy_type = parts.first().map_or("", |p| p.trim()).to_string();
    if !VALID_PROXY_TYPES.contains(&proxy_type.as_str()) {
        return Err(format!(
            "invalid proxy type: {proxy_type}, support types: [{}]",
            VALID_PROXY_TYPES.join(" ")
        ));
    }

    let mut args = ParsedProxyArgs {
        proxy_type,
        proxy_name: String::new(),
        remote_port: 0,
        local_ip: String::new(),
        local_port: 0,
        custom_domains: Vec::new(),
        subdomain: String::new(),
        sk: String::new(),
        multiplexer: String::new(),
        use_encryption: false,
        use_compression: false,
        group: String::new(),
        group_key: String::new(),
        http_user: String::new(),
        http_pwd: String::new(),
        host_header_rewrite: String::new(),
        locations: Vec::new(),
        metadatas: Vec::new(),
        annotations: Vec::new(),
        allow_users: Vec::new(),
        user: String::new(),
        token: String::new(),
        client_id: String::new(),
    };

    let mut i = 1;
    while i < parts.len() {
        let tok = parts[i].as_str();
        if tok == "--" {
            // pflag "--" terminator: everything after it is positional and
            // ignored (no positional args are registered beyond the type).
            break;
        }
        i = if let Some(raw) = tok.strip_prefix("--") {
            parse_long_flag(&mut args, raw, &parts, i)?
        } else if tok.len() > 1 && tok.starts_with('-') {
            parse_short_flags(&mut args, &tok[1..], &parts, i)?
        } else {
            // Non-flag positional token — ignored (the type was already
            // parsed from parts[0]).
            i
        };
        i += 1;
    }

    if args.proxy_name.is_empty() {
        // Go parity (pkg/ssh server.go): an SSH-mode proxy without an
        // explicit name registers under a generated one. Registering the
        // empty name (the old behavior) is unreadable in logs/dashboard and
        // collides with every other unnamed registration.
        args.proxy_name = default_proxy_name(&args.proxy_type);
    }

    Ok(args)
}

/// Parse a single `--name` or `--name=value` long-flag token. `raw` is the
/// text after the leading `--`. Returns the index of the last consumed token,
/// so the caller's trailing `i += 1` skips past it (and its value token).
fn parse_long_flag(
    args: &mut ParsedProxyArgs,
    raw: &str,
    parts: &[String],
    i: usize,
) -> Result<usize, String> {
    // pflag "bad flag syntax" cases: `--`, `--=x`, `---x`.
    if raw.is_empty() || raw.starts_with('-') || raw.starts_with('=') {
        return Err(format!("bad flag syntax: --{raw}"));
    }
    let (name, inline_value) = match raw.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (raw, None),
    };
    let Some(entry) = flag_spelling(name) else {
        if name == "help" {
            // pflag: an unregistered `--help` prints the usage (ErrHelp).
            return Err(ssh_gateway_usage());
        }
        return Err(format!("unknown flag: --{name}"));
    };
    // Per-type gate (FIX 2c): a Go flag registered only for other proxy
    // types is reported exactly like an unknown flag — Go never registers
    // it for this type (pflag parseLongArg unknown-flag arm). The error
    // shows the TYPED spelling, dash separators and all.
    if !entry.scope.allows(&args.proxy_type) {
        return Err(format!("unknown flag: --{name}"));
    }
    let canon = entry.canon;
    match inline_value {
        // `--flag=value`. An explicitly empty value IS applied (and can
        // fail) — Go runs strconv on it too.
        Some(value) => {
            apply_flag_value(args, canon, value)?;
            Ok(i)
        }
        None if is_bool_flag(canon) => {
            // FIX 3 (Go pflag bool NoOptDefVal="true"): a bare bool applies
            // true and NEVER consumes the next token — `--use_encryption
            // --proxy_name x` parses as use_encryption=true plus the proxy
            // flag, and `--use_encryption false` leaves "false" as an
            // ignored positional (use_encryption stays TRUE, exactly as Go
            // parses it — the only way to pass false is `--use_encryption
            // =false`/`--use_encryption=false`).
            apply_flag_value(args, canon, "true")?;
            Ok(i)
        }
        None => {
            // Value from the next token. A flag-like next token leaves the
            // field at its default — a deliberate divergence from Go/pflag,
            // which consumes the next token as the value unconditionally
            // (flag.go:990-993: a `--proxy_name --sk` command would
            // register a proxy literally named "--sk"). Go reaches the
            // needs-argument arm only when the value-less flag is genuinely
            // the LAST token: an earlier value-flag in the chain may have
            // swallowed the flag-like token instead, so a chained shape like
            // `stcp --sk --allow_users` parses SK="--allow_users" and
            // SUCCEEDS in Go, where frp-rs skips `--allow_users` as
            // flag-like, then rejects the orphaned end-of-command flag with
            // `flag needs an argument: --allow_users`. Both arms fail-safe.
            // A value-less flag at the very END answers pflag's
            // needs-argument error (flag.go:996) in both implementations,
            // echoing the typed token.
            match parts.get(i + 1) {
                Some(value) if !value.starts_with("--") => {
                    apply_flag_value(args, canon, value)?;
                    Ok(i + 1)
                }
                Some(_) => Ok(i),
                None => Err(format!("flag needs an argument: --{name}")),
            }
        }
    }
}

/// Parse a run of shorthand flags (`-n`, `-n=web`, `-nweb`, `-n web`),
/// mirroring pflag's cluster semantics: a value-taking shorthand consumes the
/// rest of the cluster, or the next token. Returns the index of the last
/// consumed token (see parse_long_flag).
fn parse_short_flags(
    args: &mut ParsedProxyArgs,
    cluster: &str,
    parts: &[String],
    i: usize,
) -> Result<usize, String> {
    let Some(c) = cluster.chars().next() else {
        return Ok(i);
    };
    let rest = &cluster[c.len_utf8()..];
    let Some(entry) = short_flag_target(c) else {
        if c == 'h' {
            // pflag: an unregistered `-h` prints the usage (ErrHelp).
            return Err(ssh_gateway_usage());
        }
        // pflag reports the full remaining cluster (`in -%s`), not just the
        // remainder after the unknown letter (parseSingleShortArg).
        return Err(format!("unknown shorthand flag: '{c}' in -{cluster}"));
    };
    // Per-type gate (FIX 2c): a Go shorthand registered only for other
    // proxy types is reported exactly like an unknown shorthand — Go never
    // registers it for this type (pflag parseShortArg unknown arm).
    if !entry.scope.allows(&args.proxy_type) {
        return Err(format!("unknown shorthand flag: '{c}' in -{cluster}"));
    }
    let canon = entry.canon;
    if let Some(value) = rest.strip_prefix('=') {
        // `-n=web`. Documented-class divergence for the BARE `-x=` shape:
        // pflag treats `=` as an inline-value separator only when the
        // cluster is LONGER than the flag plus `=` (parseSingleShortArg,
        // flag.go:1041-1044 `len(shorthands) > 2 && shorthands[1] == '='`),
        // so a Go `-n=` never splits — the literal "=" falls through to the
        // `-farg` arm (flag.go:1048-1051) and becomes the VALUE (`-n=` sets
        // proxy_name "=", `-r=` fails strconv on "="). frp-rs splits and
        // yields the empty value (matching what the LONG form `--name=`
        // produces in both implementations). Same-split agreement holds for
        // every other cluster (`-n=x` → "x" in both).
        apply_flag_value(args, canon, value)?;
        return Ok(i);
    }
    if !rest.is_empty() {
        // `-nweb`: the rest of the cluster is the value.
        apply_flag_value(args, canon, rest)?;
        return Ok(i);
    }
    // `-n web`: value from the next token, or pflag's needs-argument error
    // when the bare cluster ends the command (flag.go:1058 — `%q` quotes
    // the shorthand, `-%s` echoes the typed cluster). A flag-like next
    // token leaves the field at its default (see parse_long_flag).
    match parts.get(i + 1) {
        Some(value) if !value.starts_with("--") => {
            apply_flag_value(args, canon, value)?;
            Ok(i + 1)
        }
        Some(_) => Ok(i),
        None => Err(format!("flag needs an argument: {c:?} in -{cluster}")),
    }
}

/// Scope of a long-flag spelling — which proxy types Go frp registers it
/// for in SSH mode (FIX 2, pkg/config/flags.go RegisterProxyFlags +
/// RegisterClientCommonConfigFlags + registerProxyDomainConfigFlags).
/// A Go type-specific flag used on another type errors as pflag's
/// `unknown flag: --x` — the flag is simply not registered for that type.
/// [`FlagScope::Any`] covers both the Go base/common flags (registered for
/// every type: proxy_name/metadatas/annotations and the persistent
/// user/token/client-id) and the frp-rs extension spellings below, which
/// Go's SSH mode does NOT register (registerProxyBaseConfigFlags gates
/// local_ip/local_port/use_encryption/use_compression/bandwidth_* behind
/// `!options.sshMode`; group/group_key/subdomain/multiplexer are never
/// SSH flags in Go). frp-rs keeps them as a documented superset: a Go frps
/// rejects each with the same `unknown flag` error, so no command written
/// for Go frp relies on them.
#[derive(Clone, Copy)]
enum FlagScope {
    Any,
    Types(&'static [&'static str]),
}

impl FlagScope {
    fn allows(self, proxy_type: &str) -> bool {
        match self {
            FlagScope::Any => true,
            FlagScope::Types(types) => types.contains(&proxy_type),
        }
    }
}

/// A registered long-flag spelling.
struct FlagSpelling {
    /// Separator-folded spelling used for lookup: `_` and `-` are treated as
    /// equivalent separators (the intent of Go's pflag
    /// `WordSepNormalizeFunc`, pkg/config/flags.go:31-36 — Go folds `_` to
    /// `-` on registration AND lookup, so every separator mix resolves to
    /// the registered name; folding every separator is the frp-rs
    /// equivalent). Folded form must stay unique — the typed name is what
    /// the per-type gate and the `unknown flag: --x` error report.
    /// No PLURAL spellings are registered where Go registers a singular:
    /// frp's WordSepNormalizeFunc folds `_` → `-` on the typed name, so a
    /// typed `--custom_domains` looks up `custom-domains` against Go's
    /// registered `custom-domain` (`custom_domain` at AddFlag time) and
    /// misses — Go SSH mode answers `unknown flag: --custom_domains`
    /// (echoing the TYPED token, pflag flag.go:978). Leaving the plural out
    /// of this table reproduces that rejection through the unknown-flag
    /// gate instead of accepting a spelling Go would refuse.
    folded: &'static str,
    /// Canonical field name passed to `apply_flag_value` (also the
    /// registered-flag name Go quotes in `invalid argument` errors).
    canon: &'static str,
    /// Proxy types this spelling is registered for (Go registration set).
    scope: FlagScope,
}

/// Go frp SSH-mode flag surface (pkg/config/flags.go + pkg/ssh/server.go),
/// plus the documented frp-rs extension spellings. Bandwidth flags are
/// deliberately ABSENT: Go gates `bandwidth_limit`/`bandwidth_limit_mode`
/// behind `!options.sshMode` (flags.go:112-119), so an SSH-mode frps
/// answers `--bandwidth_limit` with `unknown flag: --bandwidth_limit` —
/// exactly what the missing table entry produces.
const FLAG_SPELLINGS: &[FlagSpelling] = &[
    // Go base flags (registerProxyBaseConfigFlags) — every proxy type.
    FlagSpelling {
        folded: "proxy_name",
        canon: "proxy_name",
        scope: FlagScope::Any,
    },
    FlagSpelling {
        folded: "metadatas",
        canon: "metadatas",
        scope: FlagScope::Any,
    },
    FlagSpelling {
        folded: "annotations",
        canon: "annotations",
        scope: FlagScope::Any,
    },
    // Go persistent client-common flags (RegisterClientCommonConfigFlags,
    // always registered, incl. SSH mode).
    FlagSpelling {
        folded: "user",
        canon: "user",
        scope: FlagScope::Any,
    },
    FlagSpelling {
        folded: "token",
        canon: "token",
        scope: FlagScope::Any,
    },
    FlagSpelling {
        folded: "client_id",
        canon: "client_id",
        scope: FlagScope::Any,
    },
    // Go per-type flags (RegisterProxyFlags switch).
    FlagSpelling {
        folded: "remote_port",
        canon: "remote_port",
        scope: FlagScope::Types(&["tcp"]),
    },
    // Domain flags (registerProxyDomainConfigFlags): http/https/tcpmux.
    FlagSpelling {
        folded: "custom_domain",
        canon: "custom_domains",
        scope: FlagScope::Types(&["http", "https", "tcpmux"]),
    },
    FlagSpelling {
        folded: "sd",
        canon: "subdomain",
        scope: FlagScope::Types(&["http", "https", "tcpmux"]),
    },
    FlagSpelling {
        folded: "locations",
        canon: "locations",
        scope: FlagScope::Types(&["http"]),
    },
    FlagSpelling {
        folded: "http_user",
        canon: "http_user",
        scope: FlagScope::Types(&["http", "tcpmux"]),
    },
    FlagSpelling {
        folded: "http_pwd",
        canon: "http_pwd",
        scope: FlagScope::Types(&["http", "tcpmux"]),
    },
    FlagSpelling {
        folded: "host_header_rewrite",
        canon: "host_header_rewrite",
        scope: FlagScope::Types(&["http"]),
    },
    FlagSpelling {
        folded: "mux",
        canon: "multiplexer",
        scope: FlagScope::Types(&["tcpmux"]),
    },
    FlagSpelling {
        folded: "sk",
        canon: "sk",
        scope: FlagScope::Types(&["stcp"]),
    },
    FlagSpelling {
        folded: "allow_users",
        canon: "allow_users",
        scope: FlagScope::Types(&["stcp"]),
    },
    // frp-rs extension spellings (ungated superset — Go SSH mode rejects
    // every one of these with `unknown flag`, see FlagScope::Any doc).
    FlagSpelling {
        folded: "local_ip",
        canon: "local_ip",
        scope: FlagScope::Any,
    },
    FlagSpelling {
        folded: "local_port",
        canon: "local_port",
        scope: FlagScope::Any,
    },
    // NOTE: no `custom_domains` (plural) entry — Go registers the singular
    // `custom_domain` only (pkg/config/flags.go:126), so the typed plural is
    // an unknown flag in Go (`--custom_domains` normalizes to
    // `custom-domains` ≠ registered `custom-domain`) and must hit the same
    // gate here. All plural Go registrations (metadatas/annotations/
    // locations/allow_users) ARE in the table, verbatim.
    FlagSpelling {
        folded: "subdomain",
        canon: "subdomain",
        scope: FlagScope::Any,
    },
    FlagSpelling {
        folded: "multiplexer",
        canon: "multiplexer",
        scope: FlagScope::Any,
    },
    FlagSpelling {
        folded: "use_encryption",
        canon: "use_encryption",
        scope: FlagScope::Any,
    },
    FlagSpelling {
        folded: "use_compression",
        canon: "use_compression",
        scope: FlagScope::Any,
    },
    FlagSpelling {
        folded: "group",
        canon: "group",
        scope: FlagScope::Any,
    },
    FlagSpelling {
        folded: "group_key",
        canon: "group_key",
        scope: FlagScope::Any,
    },
];

fn flag_spelling(raw: &str) -> Option<&'static FlagSpelling> {
    let folded = raw.replace('-', "_");
    FLAG_SPELLINGS.iter().find(|s| folded == s.folded)
}

/// Short-flag targets (Go pkg/config/flags.go shorthand letters): `-n`
/// proxy_name, `-r` remote_port, `-d` custom_domain, `-u` user, `-t`
/// token. Each shorthand resolves to the spelling Go registered it under,
/// so the per-type gate applies to shorthands too (`-d` is a
/// custom_domain registration: domain types only; `-r` is tcp only; `-u`/
/// `-t` are the persistent user/token: all types).
fn short_flag_target(c: char) -> Option<&'static FlagSpelling> {
    match c {
        'n' => flag_spelling("proxy_name"),
        'r' => flag_spelling("remote_port"),
        'd' => flag_spelling("custom_domain"),
        'u' => flag_spelling("user"),
        't' => flag_spelling("token"),
        _ => None,
    }
}

/// True for bool-typed flags. Go registers no bool flags in SSH mode
/// (use_encryption/use_compression are `!options.sshMode`-gated); the two
/// frp-rs extension bools keep pflag's bool grammar (FIX 3): NoOptDefVal
/// "true" — a bare `--use_encryption` applies true and NEVER consumes the
/// next token — and the full strconv.ParseBool value set.
fn is_bool_flag(canon: &str) -> bool {
    matches!(canon, "use_encryption" | "use_compression")
}

/// Apply a parsed flag value to `args`. Value parse failures produce the
/// pflag-shaped `invalid argument` error Go surfaces from FlagSet.Set:
/// `invalid argument "{value}" for "{flag}" flag: {set error}` where
/// "{flag}" is the registered name Go quotes (dash-folded through frp's
/// WordSepNormalizeFunc — `-r, --remote-port` for the shorthand form,
/// `--name` otherwise) and {set error} is the strconv/type message
/// verbatim.
fn apply_flag_value(args: &mut ParsedProxyArgs, canon: &str, value: &str) -> Result<(), String> {
    match canon {
        "proxy_name" => args.proxy_name = value.to_string(),
        "remote_port" => args.remote_port = parse_port_value(value, "-r, --remote-port")?,
        "local_ip" => args.local_ip = value.to_string(),
        "local_port" => args.local_port = parse_port_value(value, "--local_port")?,
        // pflag stringSliceValue.Set APPENDS after the first Set
        // (pflag/string_slice.go readAsCSV + changed flag) — a repeated
        // occurrence of the SAME Go registration accumulates, it does not
        // replace. Go registers the singular `custom_domain` only
        // (pkg/config/flags.go:126, StringSliceVarP(&c.CustomDomains,
        // "custom_domain", "d", ...)); every separator mix of it
        // (`--custom_domain` / `--custom-domain` / `-d`) is ONE registration
        // via WordSepNormalizeFunc, so an interleaved repeat across those
        // spellings accumulates. The plural `--custom_domains` has no
        // registration in Go (or this table) and errors as an unknown flag.
        // The field starts empty per parse, so extend == replace for a
        // single occurrence.
        "custom_domains" => args.custom_domains.extend(split_csv(value)),
        "subdomain" => args.subdomain = value.to_string(),
        "sk" => args.sk = value.to_string(),
        "multiplexer" => args.multiplexer = value.to_string(),
        "use_encryption" => args.use_encryption = parse_bool_value(value, "--use_encryption")?,
        "use_compression" => args.use_compression = parse_bool_value(value, "--use_compression")?,
        "group" => args.group = value.to_string(),
        "group_key" => args.group_key = value.to_string(),
        "http_user" => args.http_user = value.to_string(),
        "http_pwd" => args.http_pwd = value.to_string(),
        "host_header_rewrite" => args.host_header_rewrite = value.to_string(),
        // Same pflag stringSlice accumulation as custom_domains.
        "locations" => args.locations.extend(split_csv(value)),
        "metadatas" => {
            // pflag wraps the Set error with the flag name (same shape as
            // parse_bool_value/parse_port_value).
            for (k, v) in parse_kv_pairs(value).map_err(|e| {
                format!("invalid argument \"{value}\" for \"--metadatas\" flag: {e}")
            })? {
                if let Some(slot) = args.metadatas.iter_mut().find(|(ek, _)| ek == &k) {
                    // Later same-key pairs win (Go StringToString map Set).
                    slot.1 = v;
                } else {
                    args.metadatas.push((k, v));
                }
            }
        }
        "annotations" => {
            for (k, v) in parse_kv_pairs(value).map_err(|e| {
                format!("invalid argument \"{value}\" for \"--annotations\" flag: {e}")
            })? {
                if let Some(slot) = args.annotations.iter_mut().find(|(ek, _)| ek == &k) {
                    slot.1 = v;
                } else {
                    args.annotations.push((k, v));
                }
            }
        }
        "allow_users" => args.allow_users.extend(split_csv(value)),
        "user" => args.user = value.to_string(),
        "token" => args.token = value.to_string(),
        "client_id" => args.client_id = value.to_string(),
        other => {
            // Defensive: every canonical name is handled above; a future
            // table/arm drift must error, not silently no-op.
            return Err(format!("internal error: unhandled flag {other}"));
        }
    }
    Ok(())
}

/// Go strconv.ParseBool parity (FIX 3) — the exact value set Go accepts
/// for bool flags: 1,t,T,TRUE,true,True,0,f,F,FALSE,false,False. Anything
/// else is rejected with pflag's error text, whose tail embeds strconv's
/// message verbatim (`invalid syntax` for every non-bool value; the value
/// is quoted once for `invalid argument` and once inside `parsing`).
fn parse_bool_value(value: &str, display: &str) -> Result<bool, String> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        other => Err(format!(
            "invalid argument \"{value}\" for \"{display}\" flag: strconv.ParseBool: parsing \"{other}\": invalid syntax"
        )),
    }
}

/// Go pflag StringToString parity for `--metadatas`/`--annotations`
/// (pflag/string_to_string.go): the value is a comma-separated k=v list.
/// Go's shape rules, mirrored here:
/// - no `=` at all → `{value} must be formatted as key=value`;
/// - exactly one `=` → ONE pair, commas included (so a value like `k=v,w`
///   stores "v,w" — commas need a second `=` elsewhere in the value before
///   they separate pairs);
/// - two or more `=` → comma-separated fields, each split on its FIRST `=`;
///   a field without `=` → `{field} must be formatted as key=value`.
///
/// (pflag additionally csv-parses quoted fields in the multi-`=` arm and
/// trims a fully quoted value in the single-`=` arm; frp-rs strips
/// surrounding double quotes per field — a documented simplification that
/// matches Go for every unquoted value.)
fn parse_kv_pairs(value: &str) -> Result<Vec<(String, String)>, String> {
    let eq_count = value.matches('=').count();
    let fields: Vec<&str> = match eq_count {
        0 => return Err(format!("{value} must be formatted as key=value")),
        1 => vec![value],
        _ => value.split(',').collect(),
    };
    let mut out = Vec::with_capacity(fields.len());
    for field in fields {
        let field = field.trim_matches('"');
        let Some((k, v)) = field.split_once('=') else {
            return Err(format!("{field} must be formatted as key=value"));
        };
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

/// Parse a port value (`--remote_port` / `--local_port`, 0 = auto-assign).
/// The pflag-shaped error carries the flag's canonical display name. Go's
/// pflag normalizes registered names through frp's WordSepNormalizeFunc
/// (`_` → `-`) before quoting them in errors, so a shorthand flag displays
/// as "-r, --remote-port" — the dash-folded spelling is what a Go peer
/// would see. The underscore-free Rust-only names (`--use_encryption`,
/// `--local_port`, ...) have no Go oracle text and display as registered.
fn parse_port_value(value: &str, display: &str) -> Result<u16, String> {
    value.parse::<u16>().map_err(|_| {
        format!(
            "invalid argument \"{value}\" for \"{display}\" flag: port must be an integer between 0 and 65535"
        )
    })
}

/// Split a comma-separated flag value, dropping empty entries.
fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter(|d| !d.is_empty())
        .map(|d| d.trim().to_string())
        .collect()
}

/// Generate the default SSH-mode proxy name — Go parity: `sshtunnel-` +
/// proxy type + RandIDWithLen(8) (pkg/util/util.go, random bytes as 8
/// lowercase hex chars).
fn default_proxy_name(proxy_type: &str) -> String {
    use rand::TryRng;
    let mut buf = [0u8; 4];
    // SysRng (getrandom) failure is unreachable on supported platforms; a
    // zero-filled name would still be valid and effectively unique.
    let _ = rand::rngs::SysRng.try_fill_bytes(&mut buf);
    format!("sshtunnel-{}-{}", proxy_type, frp_core::hex_encode(&buf))
}

/// Usage text for `--help` / `-h` and the empty command. Go frp writes the
/// cobra command usage to the SSH client on ErrHelp and closes; this is the
/// frp-rs equivalent listing the flags parse_ssh_args accepts. The parenthesized
/// type list after each flag is Go's registration scope (pkg/config/flags.go);
/// lines marked [frp-rs] are the extension spellings Go's SSH mode does not
/// register (see the FlagScope::Any doc) — kept so frp-rs commands that used
/// them keep working, rejected by a Go frps with `unknown flag`.
pub(super) fn ssh_gateway_usage() -> String {
    format!(
        concat!(
            "frp-rs SSH tunnel gateway\n",
            "\n",
            "Usage: ssh ... <proxy_type> [flags]\n",
            "Example: ssh -R :9090:127.0.0.1:8080 v0@server -p 2200 tcp --proxy_name web\n",
            "\n",
            "Proxy types: {types}\n",
            "\n",
            "Flags:\n",
            "  -n, --proxy_name string            proxy name (empty = auto: sshtunnel-<type>-<random>)\n",
            "  -u, --user string                  frpc user (accepted; the SSH virtual client logs in as the ssh user)\n",
            "  -t, --token string                 frpc auth token (accepted; the gateway authenticates with its own token)\n",
            "      --client-id string             unique frpc instance id (accepted; unused by the gateway)\n",
            "      --metadatas stringToString     metadata key=value pairs, comma-separated\n",
            "      --annotations stringToString   annotation key=value pairs, comma-separated\n",
            "  -r, --remote_port uint16           server listen port, 0 = auto-assign (tcp)\n",
            "  -d, --custom_domain stringList     custom domains, comma-separated (http/https/tcpmux)\n",
            "      --sd string                    subdomain on the vhost server (http/https/tcpmux)\n",
            "      --locations stringList         vhost locations, comma-separated (http)\n",
            "      --http_user string             HTTP basic-auth user (http/tcpmux)\n",
            "      --http_pwd string              HTTP basic-auth password (http/tcpmux)\n",
            "      --host_header_rewrite string   rewrite the Host header (http)\n",
            "      --mux string                   multiplexer name (tcpmux)\n",
            "      --sk string                    secret key (stcp)\n",
            "      --allow_users stringList       allowed visitor users, comma-separated (stcp)\n",
            "      --local_ip string              local service IP [frp-rs]\n",
            "      --local_port uint16            local service port [frp-rs]\n",
            "      --subdomain string             alias of --sd [frp-rs]\n",
            "      --multiplexer string           alias of --mux [frp-rs]\n",
            "      --use_encryption               enable encryption (bare = true) [frp-rs]\n",
            "      --use_compression              enable compression (bare = true) [frp-rs]\n",
            "      --group string                 group name [frp-rs]\n",
            "      --group_key string             group key [frp-rs]\n",
            "  -h, --help                         show this help and exit\n"
        ),
        types = VALID_PROXY_TYPES.join(" ")
    )
}

/// Go frp SSH-mode support types, in Go's list order
/// (pkg/ssh/server.go:274 — the error text below prints this exact order).
pub(super) const VALID_PROXY_TYPES: &[&str] = &["tcp", "http", "https", "tcpmux", "stcp"];

/// Split a command string into shell-like tokens, respecting double quotes.
pub(super) fn shell_split(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == ' ' && !in_quotes {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
        } else {
            current.push(c);
        }
        i += 1;
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}
