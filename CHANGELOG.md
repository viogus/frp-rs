# Changelog

User-facing release notes for frp-rs.

> **Scope.** This file is for users: what changed and why it matters, a few lines
> per item. The round-by-round record — findings, review outcomes, gate results,
> commit hashes — lives in
> [`docs/history/development-log.md`](docs/history/development-log.md). Do not
> write the same detail in both; see the
> [docs conventions](docs/README.md#conventions-for-these-docs).

## Unreleased

### Features
- **Every `--help` surface now renders cobra's document, not bpaf's.** The help documents were
  different *documents* from Go's, not merely laid out differently: wrong first line, different section
  names, a different flag grid, bpaf's `-h, --help  Prints help information`, and two rows for every
  `--flag=<bool>` where cobra prints one. One rendering layer (`render_cobra_help` in
  `frp-core/src/cli.rs`, wired into `run_cli` on `bpaf::ParseFailure::Stdout` only) rebuilds cobra's
  shape from the flag surface read back out of bpaf's own rendering, so the document follows the parser
  rather than a hand-maintained list. `frps verify --help` (**2103 B**) and `frpc verify --help`
  (**543 B**) are Go v0.71.0's documents byte-for-byte; the nine surfaces of `TODO.md:253` all move and
  are pinned whole-text and by byte count (`frps` 2467, `frpc` 1517, `frpc status` 859, `frpc tcp` 992,
  `frpc reload` 801, `frpc stop` 789, `frpc https` 979), plus six further surfaces. Error text,
  streams and exit codes are untouched.
- **`frps --config-dir` now honours `SIGUSR1`, like `frps -c` does.** The directory lane returned
  before installing the reload handler, so the signal kept its default disposition and **killed the
  server** (`unix_wait_status(158)`, 128 + 30) where the single-config lane reloads in place. It now
  installs the same handler: one task holds the live services and every `SIGUSR1` reloads every
  registered service from its own config file, one `SIGUSR1: <summary>` record per service with a `path=` field
  naming the file it came from. `SIGTERM`/`SIGINT` still shut the lane down cleanly (rc 0). This is
  an frp-rs extension flag — Go's `frps` rejects `--config-dir` outright — so the comparison is
  against frp-rs's own `-c` lane.
- **`frps` now registers Go's `--vhost-http-timeout` (default 60, both spellings).**
  Go's `frps` reads the flag and frp-rs refused it on both paths with
  `` `--vhost-http-timeout` is not expected in this context ``. It is registered on the
  shared transport builder, so `frps --vhost-http-timeout 30 -c <cfg>` and
  `frps verify --vhost-http-timeout 30 -c <cfg>` are both accepted; the value is applied
  on the flags-only lane, and `ServerConfig::default()` already carries Go's 60, so an
  absent flag keeps 60 and with `-c` the file stays authoritative. With this the rendered
  `--help` flag diff against Go v0.71.0 has **no Go-only flags**; frp-rs-only remain
  `config-dir` and `log-format`. `--vhost_http_timeout` is accepted too, as Go normalizes
  `_` to `-`.
- **`frps verify` now exists**, so a script that validates a server config can
  use frp-rs at all. Go has had the subcommand all along; frp-rs's server CLI
  registered only the run path, so `frps verify -c frps.toml` on a **valid**
  config exited 1 with ``Error: `verify` is not expected in this context`` — the
  one command whose job is to say whether a config is valid reported a good
  config as bad, and there was no way to ask frp-rs to check a server config. It
  now mirrors Go's `verifyCmd`: `frps: the configuration file <path> syntax is
  ok` on **stdout** with exit **0** for a valid config, one bare stdout line and
  exit **1** for a bad or missing one, and `--strict-config`/`--strict_config`
  honoured in every flag position Go accepts (`--strict-config=false` is the
  Go-faithful spelling; the space-separated `--strict-config false` stays the
  documented frp-rs extension and still warns on stderr). `frps verify` with no
  `-c` prints `frps: the configuration file is not specified` and exits 0, which
  is Go's own behaviour for frps's empty `-c` default. As on Go, the command
  reads only the config path, the strict flag and `--allow-unsafe`, and
  accepts-and-ignores every other root flag **frp-rs models** (`--bind-port`,
  `--version`, …) — the qualifier is the precise claim, because a flag frp-rs
  models as a different *kind* is still not inert: the bare `--dashboard-tls-mode`
  spelling is read as `true` here where Go needs an argument (recorded in
  `docs/developing.md` § CLI inputs). Go's `--vhost-http-timeout`, which this
  paragraph used to name as the unmodelled flag, is registered now — see the
  Features entry above.
  Three things it deliberately does **not** do, all recorded in
  `docs/developing.md` § CLI inputs: it refuses the two frp-rs-only root flags
  `--config-dir` and `--log-format` (Go's `frps` has neither, and accepting them
  would make an argv Go rejects — `unknown flag: …`, exit 1 — exit **0**, i.e. a
  validation command reporting success for a config it never looked at; the run
  path keeps both as documented extensions), and — at the time of this round —
  it stopped at the config loader, so the post-load `--allow-unsafe` gate for an
  `exec` token source was not applied, the same pre-existing gap `frpc verify`
  had; it was left alone here so the two verifies kept agreeing with each other,
  and filed in `TODO.md`. That gap is closed in this same Unreleased section (see
  **Fixed**): `verify` now runs the gate and refuses what the daemon refuses.
- **`frps` now resolves a subcommand that follows leading root flags, as Go's
  cobra does — and the claim that it did not need to was false.** The previous
  round's note here said `frps` was untouched because "Go's `frps` has no
  subcommands to resolve". Go's `frps` registers `verify` on its root command
  (`cmd/frps/verify.go`) beside cobra's `completion`/`help`, and `frps --help`
  lists all three, so `frps -c frps.toml verify` and
  `frps --strict-config=false verify -c frps.toml` ran the verify command on Go
  and exited **1** here with an unexpected-token refusal. `frps` now runs the
  same resolution as `frpc`, with its own flag classification: Go's server root
  registers five pflag bools (`--version`, `--strict_config`,
  `--enable-prometheus`, `--disable-log-color`, `--tls-only`) against the
  client's two, and — the row that decides it — `--dashboard-tls-mode` looks
  like the others but is *not* a pflag bool, so on Go it swallows `verify` as its
  value and starts the server instead of verifying. That asymmetry is why the
  bool set is per binary rather than shared, and both directions are pinned by
  tests.
- **`frpc` now accepts a subcommand after leading root flags, as Go's cobra
  does.** Go resolves the command after stripping flags, so
  `frpc -c frpc.toml status` ran the `status` admin command and dialled the
  config's `[webServer] port`, and `frpc -c missing.toml tcp --local-port 5 …`
  started the single tcp proxy; bpaf picked a branch before dispatch, so frp-rs
  fell through to run mode and exited 1 with ``Error: no such command or
  positional: `status`, did you mean `https`?``. The interleavings that now work
  are the ones Go accepts: a leading root flag before the subcommand — `-c FILE`,
  `--config=FILE`, `-cFILE`, `--config-dir DIR`, a bare
  `--strict-config`/`--strict_config`, `--strict-config=BOOL`,
  `--allow-unsafe F`, `-v`/`--version` — in any order, repeated, and with the
  subcommand also split from the flags by further root flags —
  `-c a.toml status`, `--strict-config=false status -c a.toml`,
  `-c a.toml --strict-config=false status`, `--strict-config status -c a.toml`,
  `-c a.toml -c a.toml status`, `-c a.toml tcp --local-port …` and the
  `reload`/`stop`/`verify` equivalents. The already-supported order
  `frpc <subcommand> [flags]` is unchanged. The bool rule's blast radius was
  measured across every command: before this fix the over-consuming version
  resolved the command after the bare flag on **all eight** single-proxy
  commands and the three admin commands, so each of those eleven now follows
  Go's refusal instead.
  Two boundaries follow Go exactly and are worth naming, because they are what
  distinguishes a flag **value** from the command word: `--strict-config` is a
  pflag *bool*, so it never consumes the token after it — a bare
  `--strict-config` immediately before a command word leaves that word as the
  command (`frpc --strict-config status -c frpc.toml` resolves `status` and
  dials, as Go does), whereas `frpc --strict-config true status -c frpc.toml`
  exits 1 on both binaries and runs neither `status` nor any other command: Go
  refuses the word (`unknown command "true" for "frpc"`), frp-rs refuses it as
  an unexpected positional, and the **outcome** — exit 1, no admin request, no
  proxy dialled — is what matches; the message text is the pre-existing
  output-shape item. Values are never mistaken for commands: a config file literally named
  `status` (`-c status`, `--config=status`, `-c=status`, `-cstatus`), a value
  after a real `--`, and a `--proxy-name status` all stay values, because the
  hoist skips the value of every value-taking flag. `frps` was left alone by
  *that* change, and the parenthetical it carried here — that Go's `frps` has no
  subcommands to resolve — was **wrong**; the `frps` entries above are the
  correction (Go's `frps` declares `verify`, and `frps` now runs the same
  resolution over its own flag and command sets), and a non-command word in front of a
  command still refuses the argv on both binaries — Go as `unknown command
  "…" for "frpc"`, frp-rs as an unexpected-token error naming the token it could
  not place. The full
  Go-vs-frp-rs table, including the `--strict-config <bool>` rows and the cases
  that remain divergent, is in `docs/developing.md` § CLI inputs.
- **Bool flags now accept Go's `--flag=<bool>` spelling — ten flags on both
  binaries.** Go registers eight of them with pflag's bool machinery, which takes
  the bare `--flag` (true), `--flag=true`/`--flag=false`, and any value
  `strconv.ParseBool` accepts (`1`, `0`, `t`, `f`, `TRUE`, `False`, …); frp-rs
  registered them as bpaf switches that took no value, so
  `frps --tls-only=false -c frps.toml` **started and listened on Go** and exited
  `1` here with ``Error: `false` is not expected in this context``. The flags
  are `frps --tls-only`, `--enable-prometheus`, `--disable-log-color`,
  `--dashboard-tls-mode`, `-v`/`--version`; `frpc --disable-log-color`,
  `-v`/`--version`; `frpc tcp --use-encryption`, `--use-compression`; and
  `frpc status --json` (an frp-rs-only flag — Go has no `--json`, so its value
  form is an frp-rs extension). A non-bool value exits 1 exactly as Go's
  `strconv.ParseBool` refusal does, and the **short** spelling `-v=<bool>` is
  accepted as well (Go's pflag treats it as `--version=<bool>`; frp-rs expands
  it before parsing, and never after a `--`). Short-hand clusters keep working
  and now match Go on both binaries: `frps -vtrue`/`-vh`/`-vtok`/`-vp7000` set
  `-v` and re-parse the rest, exactly as before; on `frpc` the same cluster no
  longer prints the version where Go refuses it (`frpc -vtrue` is rc 1 on both,
  was 0 here) and `frpc -vh` prints **help** as Go does (the previous release
  printed the version there — both are fixes toward Go); `-vfoo`/`-v0` stay rc 1
  on both binaries. Three caveats, all measured and recorded in
  `docs/developing.md`: the space-separated `--flag false` is still refused
  (Go's pflag never consumes that token either, and Go's own behaviour differs
  per command — `frps` answers `unknown command "false"`, `frpc tcp` ignores the
  token); `--dashboard-tls-mode` is a **string** flag on Go, so Go also accepts
  `=auto`/`=disable`/any value there, which frp-rs's bool model does not; and Go
  flags frp-rs does not register at all (`frpc tcp --ue`/`--uc` and
  `--tls-enable`) stay unimplemented. A repeated bool flag is still refused
  rather than last-wins.
- **`frpc stop` and `--api-timeout` — Go parity.** `frpc stop -c frpc.toml`
  POSTs `/api/stop` with an empty body and prints `stop success` on 200,
  matching Go frp's third admin command. `reload`, `status` and `stop` accept
  `--api-timeout DURATION` (default 30 s, Go's `adminAPITimeout`) with Go's
  `time.ParseDuration` grammar (`1m`, `500ms`, `1h2m3.5s`, …; a zero or
  negative value is accepted and means the deadline has already passed).

### Changed
- **The compat lanes no longer install a Go toolchain nothing uses.** `compat.yml`
  and `xtcp-compat.yml` ran `actions/setup-go` with a floating `>=1.22.0` range,
  so which Go was present was a runner-image property, and nothing invoked it:
  `git ls-files '*.go'` is empty and `scripts/download-go-frp.sh` fetches the
  prebuilt release tarball. The `/tmp/frp-source-build/` cache path also survived
  the removed builder it belonged to (`build_go_frp_v2()` exists nowhere). The
  step and the orphaned path are gone, and the cache step is named `Cache cargo`
  again. TODO.md:6410.
- **`auth.method` is now compared exactly, and a typo is a config-load error
  instead of silently selecting token auth.** Go accepts exactly `"token"` and
  `"oidc"` (`pkg/config/v1/validation/validation.go:37-40`, compared with
  `slices.Contains` at `validation/server.go:31` and `client.go:101`) after
  `Auth.Complete()` has filled an *empty* method with `token`
  (`pkg/config/v1/server.go:136-139`, `client.go:206-209`), so on Go
  `method = "OIDC"` exits **1** with
  `invalid auth method, optional values are [token oidc]` on stdout and 0 bytes
  on stderr, while `method = ""` starts as token auth. frp-rs did neither
  consistently: the **server** lower-cased the method (so `"OIDC"` selected
  OIDC, where Go errors) and sent everything else — `" oidc"`, `"oidc "`,
  `"tokenn"` — to **token**; the **client** compared `== "oidc"` exactly, so
  `"OIDC"` selected **token** *and* skipped the OIDC client-credentials
  validation, and `frpc verify` reported such a config **valid**. An operator
  who wrote a near-miss spelling could therefore get token auth against a token
  they had set, with no diagnostic. All four sites now share one policy
  (`frp_core::auth::{complete_auth_method, parse_auth_method}`) called from the
  config loader and kept as a construction-time backstop: an empty method
  completes to `token`, anything else that is not exactly `token`/`oidc` is a
  load error with Go's text on stdout and exit **1**, and the
  `oidc`-without-the-feature refusal is keyed off the validated method (so
  `"OIDC"` is now Go's error rather than a feature error). No `to_lowercase` and
  no trimming: adding either would make frp-rs *accept* configs Go rejects. One
  recorded divergence: frp-rs prefixes the loader's line with `<path>: ` where
  Go prints the bare decoder text.
- **A reload that changes `[auth]` is now refused instead of reported as
  success.** `frpc reload` / SIGUSR1 re-read the config file, and
  `reload_from_sources` diffed only proxies and visitors, so changing
  `auth.method` (or the token, or any `[auth.oidc]` field) returned
  `reload success: reload success: no changes detected` and logged nothing about
  auth. Auth is built once at client start (`Service::auth_cfg` and the bridge
  `encryption_key`, which is copied by value into the live control connection),
  and Go's `frpc` reload has the same shape — it re-reads proxies and visitors
  only (`client/service.go:494-525`) — so the honest answer is "restart". A
  reload whose `[auth]` differs from the running one now fails with a message
  naming the changed field(s) (never their values) and saying a restart is
  needed, and **applies nothing** from the new config. Unchanged `[auth]` — by
  content, including `method = ""` vs `method = "token"` — reloads exactly as
  before.
- **The server's `SIGUSR1` reload now reports an `auth.method` change and never
  installs a method it cannot serve.** `frps`'s reload compared the token and
  the OIDC fields but never `auth.method`, so flipping `method = "token"` to
  `"oidc"` with the OIDC fields already present **and unchanged** answered
  `config reloaded: no changes detected` while the file on disk said `oidc`; with
  a token change alongside it, it printed `auth token updated` and committed the
  whole freshly parsed `[auth]` section, leaving the live `auth_cfg.method` on
  `oidc` while the OIDC verifier — built once, at startup — was still absent.
  Logins then took the token path and failed closed (`OIDC auth requires
  server-side verifier (not configured)`), so the server and its config
  disagreed. Measured on that shape, the lockout was **total**: after the reload
  neither the new token nor the previously-working one could log in, because the
  token path rejects every attempt while the live method says `oidc`.
  A reload now applies the settings it can re-key in place — the credential
  (`auth.token` / `auth.tokenSource`), `auth.additionalAuthScopes`, and
  `auth.authenticationTimeout` / `auth.tokenAuthTimeout`, both of which the login,
  scoped-message and nathole paths read from the live config — and **reports**
  every remaining `[auth]` difference as restart-required (`auth.method: token ->
  oidc (restart required)`, `OIDC settings changed (restart required)`); neither
  is ever committed, so the live `auth.method` is always the method the running
  verifier was built for. The classified field list is a compiler-enforced
  destructure of `AuthServerConfig`, so the next `[auth]` field cannot rejoin the
  silent class by default. Fields the old code never compared at all are closed
  with it: `auth.tokenSource`, `auth.additionalAuthScopes`,
  `authenticationTimeout`, `tokenAuthTimeout`, `oidcSkipNbf`, `oidcProxyURL` and
  `oidcTokenEndpointURL`. For `auth.tokenSource` the old behaviour was not always
  silent — the reload compared the *resolved* token, so a source rewrite that
  resolved to a different value did report `auth token updated` (while a rewrite
  resolving to the same value reported nothing, and the source itself was never
  applied); it is now compared as the source it is and applied with the
  credential. `auth.useEncryption` is deliberately **not** reported: the server
  parses it but reads it nowhere (Go's `AuthServerConfig` has no such field), so
  neither a reload nor a restart can make a change to it take effect.
- **The server's `SIGUSR1` reload now names every restart-only setting it cannot
  apply, instead of answering `config reloaded: no changes detected`.** The
  reload compared `allow_ports`, `[auth]`, `bind_port`, `bind_addr`,
  `tls_enable` and the TLS file paths, and nothing else — so a rewrite of any
  other setting was reported as a no-op while the file on disk disagreed with
  the running process. Measured on a real `frps`: `transport.heartbeat_timeout`
  `30 -> 60` plus `max_ports_per_client` `0 -> 7` with `kill -USR1` printed
  `config reloaded: no changes detected` and named neither field. Every
  restart-only difference that some code reads is now reported as
  `name: old -> new (restart required)` — the whole `[transport]` section, the
  listener ports and addresses, `[log]` (read once in `init_logging`, before the
  reload path exists), `[web_server]`, `http_plugins`, the
  per-client/per-proxy registration caps, the connection and drain timeouts,
  `[ssh_tunnel_gateway]`, `[observability]` and the rest. Nothing new is
  **applied**: this changes what the reload says, not what it does.
  Three deliberate silences, so the summary does not claim a restart that would
  change nothing: settings no code reads (`auth.useEncryption`,
  `tls_server_name`, `web_server.pprof_enable`, `[featureGates]`, …), fields
  whose only reader is behind a build feature (`web_server.*` beyond
  `custom_404_page` without `dashboard`, `[ssh_tunnel_gateway]` without `ssh`,
  the QUIC options without `quic`, the three listener ports `kcp_bind_port` /
  `quic_bind_port` / `websocket_port` without their own listener — the dashboard
  is not a reader for them, because it prints those two keys only where the
  listener is already compiled — and `[observability]` without `otel`), and
  `includes`, which the reload's own config load already resolves.
  Credential-shaped values are named without their values (`web_server.password`,
  `http_plugins`). A field is compared as the value the server **runs with**, not
  as its spelling in the file: an absent `max_connections` and
  `max_connections = 512` are the same 512-permit semaphore, and an absent
  `max_accept_rate` and `max_accept_rate = 0` are both "no limit", so neither pair
  is reported (`max_connections = 0` is *unlimited* — a different setting, and it
  is). The classified field list is a compiler-enforced destructure of
  `ServerConfig`, so a newly added field is a compile error until it is classified
  rather than silently silent.
- **The server's `SIGUSR1` reload no longer reports `tls_enable` as
  `(restart required)`.** Nothing in `frp-server`/`frps` reads
  `ServerConfig::tls_enable` — a field with no counterpart in Go v0.71.0's
  *server* config, which frp-rs's own `[transport.tls]` flatten inserts as `true`
  when that Go-shaped section carries `force = true`, `certFile` or `keyFile`
  (`frp-core/src/config/normalize.rs:865-884`) — so
  neither a reload nor a restart can make a change to it take effect,
  and the line claimed one. It now has the same disposition `auth.useEncryption`
  already has (deliberately unreported). Not a parity gap: Go v0.71.0's
  `ServerConfig` has no such field at all, its `TLS.Enable` is a *client* field,
  and the server's own switch is `tls_only` (`TLS.Force`).
- **A config-load failure now prints a bare line on stdout, and `frpc verify`
  prints its refusal there instead of on stderr — a user-visible output change,
  and Go parity on the stream and the shape of each line.** Go frp v0.71.0 does
  `fmt.Println(err); os.Exit(1)` on all of these paths (`cmd/frpc/sub/root.go`,
  `cmd/frpc/sub/verify.go`, `cmd/frps/root.go`); frp-rs printed the daemon's
  start-up load error inside an ANSI-coloured `tracing` record on stdout —
  timestamp, level, `frpc:` target, and the message repeated in a trailing
  `error=` field — and `frpc verify -c <bad>` wrote `Config file … is invalid: …`
  to **stderr**, so a script that captured stdout saw nothing. Both `frpc` and
  `frps` now `println!` the error on stdout with an empty stderr, for
  `frpc -c <bad>`, `frps -c <bad>`, `frpc verify -c <bad>` and
  `frpc verify -c <missing>`; the exit codes are unchanged (1 everywhere). The
  output is **one line per rejected key**, and with two or more unknown keys
  that is a deliberate divergence rather than a match: frp-rs lists **all** of
  them (`run_strict_check` joins every refusal with `\n`), while Go's
  `DisallowUnknownFields` decoder stops at the first — three unknown keys are
  three lines here and one line there, both naming the same first key and both
  ordering by key name, not document position. **What else did not change:** the
  wording. frp-rs still names the config file and can append a
  `did you mean 'x'?` suggestion, where Go prints the codec's
  `json: unknown field "x"` with no path — matching that byte-for-byte would mean
  a literal `json: ` prefix on a message also emitted for TOML/YAML/INI and the
  loss of the file identity in `--config-dir` mode. `frpc verify`'s success line now
  prints Go's `frpc: the configuration file … syntax is ok`; the three summary
  lines that follow it are a frp-rs addition Go does not print (kept because the
  vendored legacy-`.ini` fixture test observes its proxy/visitor counts through
  them). `--strict-config=foo` is
  untouched: both binaries already write that refusal to stderr. The
  `--config-dir` extension keeps its `tracing` output — Go's counterpart there is
  a different line and a different exit code (0). Measured on Go v0.71.0 with
  stdout and stderr captured separately.
- **Strict mode now rejects unknown keys inside `[[proxies]]` / `[[visitors]]` /
  `[[httpPlugins]]` elements — a behaviour change, and Go parity.** The key set
  used to be per *section*, so an unknown field inside an array element was
  accepted and silently dropped even in strict mode (Go's default), where Go frp
  v0.71.0 exits 1 with `decode proxy at index 0: unmarshal ProxyConfig error:
  json: unknown field "notAKnownProxyKey"`. frp-rs now reports
  `unknown field "proxies[0].notAKnownProxyKey" in config file …` and exits 1.
  Checked positions: every `[[proxies]]` / `[[visitors]]` element, the
  `[proxies.plugin]` / `[visitors.plugin]` tables, a proxy's
  `health_check_http_headers` elements (under both the canonical name and the
  `healthCheckHttpHeaders` alias), and every `[[httpPlugins]]` entry. The
  key sets are the serde surface of `ProxyConfig` / `VisitorConfig` /
  `PluginConfig` / `VisitorPluginConfig` / `HttpPluginConfig` — every field name
  **and** every camelCase alias — so a Go-authored config that uses Go's
  spellings (`localPort`, `customDomains`, `useEncryption`, …) keeps loading; a
  drift guard extracts those names from the structs and fails in both directions
  when a field or alias is added, removed or renamed (it refuses to guess on a
  container `#[serde(rename_all)]`, a `flatten` field or an unrecognised serde
  attribute). **What now fails that used to load:** a genuinely unknown key in
  one of those blocks (`remote_portt`, `notAKnownProxyKey`) and a mis-cased key
  Go's case-insensitive JSON decoder reads and applies (`RemotePort` — see the
  case-sensitivity entry below; use `remotePort` or `remote_port`).
  `--strict-config=false` still drops such keys silently, as before.
  **Legacy-shaped top-level sections (any format — the collector keys on a
  top-level mapping carrying a `type`, not on the `.ini` extension) keep Go's
  accept-and-ignore INI semantics for the strict check**: the legacy collector folds the prefix mechanisms Go reads (`meta_*` →
  `metadatas`, `header_*` → `headers` on an `http` proxy, `plugin_header_*` →
  the plugin's `request_headers`) and then drops the keys Go's INI path ignores
  (`[common]`-only keys misplaced into a proxy section, a stray `plugin_*`
  parameter, a visitor's `meta_*`/`header_*`, an unknown key in a legacy
  `[plugin.xxx]` server section). Go v0.71.0's own
  `conf/legacy/frpc_legacy_full.ini` therefore draws no unknown-field refusal
  here either (it is vendored and pinned in `frp-core/src/config/fixtures/`),
  though it still does not load end to end: the INI reader infers an integer
  where INI has only strings, so `token = 12345678` fails serde on both this and
  the previous release; a separate pre-existing class, comma-splitting, drops a
  `[range:…]` template whose `local_port` is a list (and `allow_ports` on the
  server). Both are open items in `TODO.md`; see the fixture README. Two measured gaps
  remain: an unknown key inside `[proxies.requestHeaders]` /
  `[proxies.responseHeaders]` is still accepted (normalization consumes those
  tables before the check, where Go rejects it), and the v1 spellings
  `healthCheckType` / `healthCheckURL` / `healthCheckHTTPHeaders` /
  `healthCheckIntervalS` / `healthCheckTimeoutS` / `healthCheckMaxFailed`
  advertised in `docs/config.md` are not Go names — strict mode now refuses
  them (they were silently dropped before, leaving the health check
  unconfigured), as Go does; the Go v1 spelling is the nested
  `[proxies.healthCheck]` table. Per-depth Go-vs-frp-rs measurements are in
  `docs/deployment.md`.
- **A CLI config failure now exits 1, not 2 — a behaviour change.**
  `frpc -c <bad or missing or unparsable>`, `frpc verify -c <…>` and
  `frps -c <…>` exited `2` (`EXIT_CONFIG`), while the admin subcommands
  (`frpc reload`/`status`/`stop`) already exited `1` for the identical load
  error. Go frp v0.71.0 exits `1` on every one of those, so the per-class code
  is gone and the paths now agree. (An invalid `--strict-config` value was
  already `1` at the base — only its message differs from Go's.) The unused
  `frp_core::Error::exit_code()` mapping was removed with it, and the remaining
  `3`/`4` codes are now documented as frp-rs extensions with no Go counterpart,
  tracked in `TODO.md` — for example, an unresolvable `auth.tokenSource`, or (on
  the client) a malformed `[store]` file, each of which exits `1` in Go; the
  examples are not an exhaustive list of what can reach them.
- **Config keys are still matched case-sensitively — a known divergence from
  Go, recorded rather than half-fixed.** Go decodes the config with
  `encoding/json`, whose field and table matching is case-insensitive
  *everywhere*, including inside `[[proxies]]`. frp-rs matches exactly (plus the
  documented camelCase aliases), and the two diverge differently depending on
  the key's position:
  - In the walked sections — the top level and `[auth]`/`[log]`/`[webServer]`/
    `[transport]` — strict mode (the default) refuses the mis-cased key:
    `[webServer] Port = 7499` gives `unknown field "web_server.Port" … did you
    mean 'port'?`, exit 1.
  - Inside a `[[proxies]]`/`[[visitors]]` (or `[[httpPlugins]]`) element the key
    is now **refused in strict mode too** (`unknown field "proxies[0].RemotePort"
    … did you mean 'remotePort'?`, exit 1) — stricter than Go, which reads and
    honours the key, but the previous behaviour dropped its value silently while
    the command exited 0. With `--strict-config=false` it is still dropped, and
    the array's key sets are still exact-match otherwise (see the entry above).
  - With `--strict-config=false` the key is dropped everywhere and the command
    may succeed on a different value than Go used (`ServerAddr`/`ServerPort`
    fall back to `0.0.0.0:7000`) or fail later with a missing-value error.
  The measurements, the reason no bounded alias set closes the remaining
  top-level arms, and the covered vs uncovered scope are in
  `docs/developing.md` § CLI inputs; the array recursion's own consequences are
  in `docs/deployment.md`.
- **`--config-dir` mode keeps its own refusal code — unchanged, and a
  divergence.** A directory that does not exist, is empty, or holds a config
  that fails to parse still exits **2** on the frp-rs side, where Go's own
  directory mode exits **0** for all three (a silent success frp-rs does not
  adopt; it is the only thing in the CLI that still exits 2). The divergence and
  its reason are stated in `docs/developing.md` § CLI exit codes, and it is
  pinned by a test. Scripts that branched on a config failure should branch on
  `1`; a `--config-dir` refusal is the one case still on `2`.
- **A build without the `oidc` feature now refuses `auth.method = "oidc"` — a
  behaviour change.** `frps-tiny` / `frpc-tiny` (and any build compiled
  without the `oidc` feature) previously fell through to `Token`, so a config
  that asked for OIDC silently ran token auth: an frps with `auth.token` set
  started as a token server and accepted token logins. It now fails — at server
  startup and on the server's reload, and in `frpc run` / `frpc verify` — with
  `auth.method = "oidc" requires the "oidc" feature, which this build was
  compiled without — rebuild with it or set auth.method = "token"`. Rebuild with
  the `oidc` feature if you meant OIDC, or set `auth.method = "token"`
  explicitly.
- **`frpc reload` and `frpc status` are now bounded by a 30 s admin deadline —
  a behaviour change.** Their admin HTTP call previously had no timeout at all,
  so a daemon that accepted the connection and never answered hung the command
  forever; it now fails after `--api-timeout` (default 30 s) with
  `admin request timed out after <duration>` on stderr, exit 1. Where Go prints
  `context deadline exceeded` on stdout, frp-rs keeps its own message and
  stream.
- **`frpc reload` now honours `--strict-config` — a behaviour change.** The
  reload subcommand parses the flag like `run`/`verify`: absent and bare
  `--strict_config` are strict (`true`, matching Go frp's persistent
  `rootCmd` flag), `--strict_config=false` is non-strict. Previously the
  flag was silently ignored on `reload`, so every reload ran non-strict. A
  reload of a config containing unknown fields therefore now **fails** (the
  running proxies are left as they were) where it used to succeed; pass
  `--strict-config=false` to keep the old lenient behaviour.

### Fixed
- **A `--dashboard-port`-style CLI override of a reader-gated listener port is now reported in the same shapes the file key is.** `FrpsArgs::override_server_config` runs *after* the load that fills `ConfigPresence` from the normalized file, so a port it wrote could not re-enter the presence record: in a build without `frp-server/dashboard`, `frps --dashboard-port 7500` (no `-c`, no `--config-dir`) parsed the flag, applied it to `cfg.web_server.port`, opened no listener and printed **zero** records, where the same value in the file printed one. `override_server_config` now returns an `AppliedReaderGatedPorts` naming the reader-gated ports it actually wrote (`frp-core/src/config/loader.rs`), and its only production caller merges that into the presence record before the warn block (`frps/src/main.rs`), so the flag emits the existing record (`web_server.port has no effect: this build has no dashboard support, …`) exactly where the file key does — one record per load, and none when the build honours the port. The two paths that apply no overlay stay silent and are recorded as precedence rather than gates: `--config-dir` (a named config source is authoritative) and `frps verify`, which accepts `--dashboard-port` and ignores it while a file that requests the port prints its record before `syntax is ok`. A hand-named inner feature (`--features tiny,frp-core/kcp`) is the one shape still advertised without a reader, and is filed as its own item. Closes `TODO.md:10577`.
- **A server config that names `web_server.port` without `frp-server/dashboard`, or `ssh_tunnel_gateway.bind_port` without `frp-server/ssh`, is now reported instead of silently ignored.** These two are ordinary `u16` fields, so every build deserializes them and `--strict-config` accepts them, but their only *reader* is `#[cfg(feature = "dashboard")]` / `#[cfg(feature = "ssh")]` (`frp-server/src/service.rs`): in the default `frps`, in `tiny` and in `micro` the port was parsed, accepted and never opened. A `-c` or `--config-dir` startup now warns once per load and a `SIGUSR1` reload warns again — one record per load, and nothing when the build honours the port: `web_server.port has no effect: this build has no dashboard support, so nothing reads the key and no dashboard listener is bound` (with the `ssh_tunnel_gateway.bind_port` twin). `frps verify` prints the same record to **stdout** in front of its byte-exact `frps: the configuration file <path> syntax is ok` line, so `verify` sees a class it was blind to without disturbing the Go-compatible output. Both spellings (`webServer.port`, `sshTunnelGateway.bindPort`) and the older `dashboard_port` alias are caught, because the check reads the normalized config. The legacy-`.ini` zero spellings (`"0"`, `+0`, `00`) are not a request in any build and stay silent — the gated-port detector and these two new checks now share one value-level rule, so `007` / `+5` still warn — and the two `docs/config.md` rows record the gap and quote the record. Closes `TODO.md:10033`, `:10082` and `:10115`; the strict-allow-list half is recorded separately (`TODO.md:10355`).
- **A server config that writes `kcp_bind_port` / `quic_bind_port` / `websocket_port` without the feature that compiles the field is now reported instead of silently ignored.** `kcp_bind_port` / `quic_bind_port` / `websocket_port` (and their `kcpBindPort` / `quicBindPort` / `websocketPort` aliases) compile only with the `kcp` / `quic` / `websocket` features, so a build without one drops the key in serde while the strict parser still lists it — `frps verify --strict-config` accepted `websocketPort = 7500` in a micro build, and the run path then bound neither port and said nothing. A non-zero value for an unavailable port now emits one warning per load at every server load site that has a log sink (the two `frps` startup paths and the SIGUSR1 reload): `websocket_port has no effect in this build: frp-core's \`websocket\` feature is off, so ServerConfig has no such field and frp-server never creates the WebSocket listener the port names. Write \`websocket_port = 0\` (the documented "disabled" value) to say so in the file, or rebuild frps with the \`websocket\` feature to listen on it.` `= 0` (the documented "disabled" value) and an absent key stay silent in TOML/JSON/YAML, because every build shape honours them; in the legacy `.ini` dialect the quoted/`+0`/`00` spellings the reader only parses later are still reported (`TODO.md:9229`). **Not closed by this entry:** a port whose *reader* is compiled out in `frp-server` — `web_server.port` without `dashboard`, `ssh_tunnel_gateway.bind_port` without `ssh` — is accepted and silently ignored in the same way (`TODO.md:9238`). The key stays **accepted**: rejecting it would refuse the repo's own documented `frps.toml` in micro/tiny builds. `frps verify` is deliberately untouched, exactly like the `tls_enable` diagnostic (`TODO.md:9246`).
- **On the `-c`-only lane `frps` now lets the config file's whole `[log]` section govern, discarding a non-empty `--log-level`/`--log-file`/`--log-max-days`/`--log-format` exactly as Go's `-c` lane discards the pflag-bound struct.**
  `cli_log_flags_apply` (`frps/src/main.rs:413` — no `-c`, or `--config-dir`) masks all four values before `init_logging`, where the raw CLI values previously reached it, so `frps -c frps.toml --log-level info` emitted 11 `INFO` records where Go emits 0. Pinned by `cli_file_retention_and_format_flags_do_not_override_the_config_file` (`frps/tests/log_completion.rs:1186`) with three independently-red arm mutants, and the `--list` count guard moved to `expected=11` (`.github/workflows/ci.yml:1238`). The five adjacent R2–R6 residues (the implicit `./frps.toml` lane, `--log-format ""` writing through, the out-of-range `--vhost-http-timeout` wording, the absent `-l` shorthand, and the 24 h cap) are measured, recorded in `docs/config.md`, `docs/developing.md` and `frp-core/src/cli.rs`, and pinned rc-only where a pin is possible.
- **The proxy commands now accept Go's flag names and its shorthands.** `frpc tcp|udp|http|https|stcp|xtcp|sudp|tcpmux` rejected Go v0.71.0's own spellings — `--custom-domain` (`-d`), `--sd`, `--sk`, `--mux`, `--uc`/`--ue`, `--tls-server-name`, `-n`/`--proxy-name` — and every proxy shorthand Go registers (`-i`, `-l`, `-r`, `-s`, `-P`, `-n`), so a Go command line either failed to parse or set nothing. Go's spelling is now each flag's primary long, the rendered `--help` row shows Go's name, and the old frp-rs spellings (`--custom-domains`, `--subdomain`, `--server-name`, `--use-compression`, `--use-encryption`) stay accepted as aliases, as does frp-rs's own `--mux-port` — not a Go name (Go v0.71.0 answers `unknown flag: --mux-port`), and the sole frp-rs-only row the extension table kept. Two Go flags remain unimplemented and are recorded rather than silently dropped: `--allow-users` (no per-proxy allow-list field) and `--tls-server-name` on the six surfaces with no per-proxy TLS SNI field. `frpc sudp`'s required `--remote-port` stays long-only — Go's `frpc sudp` registers no `remote-port` at all. The help-document pins gained per-surface Go-row/shorthand expectations and a CI count guard; see `TODO.md:295`.
- **A legacy `.ini` `[common] includes` is expanded as Go expands it, and the five remaining legacy-`.ini` spellings are measured and pinned rather than left to prose.** `process_includes` ran before the `[common]` hoist, so `[common] includes = "<file>"` was silently dropped: with a valid included proxy Go loaded it (rc 0) while frp-rs loaded nothing, and an include under a nonexistent directory was Go rc 1 (`include: directory of … not exist`) against frp-rs rc 0. The client `.ini` loader now takes that string key out of the raw `[common]` table while it is still visible (`frp-core/src/config/file.rs:339-346`) and appends it to the include walk (`:368`), measured in both loader modes as rc 0 with `Proxies: 1` where it was 0, and rc 1 where it was 0 (`legacy_ini_common_include_is_expanded_like_go`, `legacy_ini_common_include_missing_dir_refuses_like_go`); a top-level `includes` beside `[common]`, a `[common]`-less string scalar `includes`, and `text/template` rendering stay deliberately different. The reserved-root, detector, `[common] start`, `[DEFAULT]`/range and merged-unknown-key shapes are recorded as deliberate divergences with their per-mode measurements in `docs/config.md`, each pinned (`legacy_ini_reserved_root_type_only_section_is_not_collected_both_modes`, `legacy_ini_server_side_dotted_and_reserved_roots_stay_v1_both_modes`, `dotted_common_only_section_is_legacy_for_the_collector_both_modes`, `legacy_ini_start_comes_from_the_common_section_only`, `legacy_ini_without_common_start_scalar_is_a_v1_shape`, `legacy_ini_common_unknown_key_residual_both_modes`).
- **The three zero-valued `[log]` CLI flags are pinned by record assertions on both binaries (three on `frps`, the level control on `frpc`), and the `[log]` reference rows now state the measured behaviour.** `--log-level ""`, `--log-file ""` and `--log-max-days 0` mean "not supplied", so the file's `[log] level`/`to`/`max_days` survive on `frps` (the overlay skip) and on `frpc` (the resolver filter).
  New spawn pins: empty `--log-level` keeps `warn` on both binaries (on `frps` the inert-key `WARN` is present while the banner `INFO` is absent; on `frpc` the pin waits on the `Login failed (attempt 1)` record),
  `--log-file ""` keeps the configured `logs/frps.log.<date>` with 0 B on stdout, and `--log-max-days 0` keeps a five-day-old rotation file alive
  under `[log] max_days = 7` while `--log-max-days 3` deletes it. `docs/config.md`'s `[log]` rows are rewritten to Go's two lanes (the `-c` lane
  discards every CLI log flag; the flags-only lane completes the empty values via `util.EmptyOr`), and both `log_completion` targets now carry
  the count guard that a cfg-disabled file would otherwise pass with `ok. 0 passed; 0 failed` — the `frpc` step is new (`.github/workflows/ci.yml:712`,
  `expected=1`) because this change adds that file, while the `frps` step's existing literal is hoisted to the single `expected=9` and moved 6 → 9 for the pins it adds (`:921`).
- **The `frps` TLS-enable warning capture now pins the record instead of counting it.** `frps/tests/warn_delivery.rs`
  asserted only `occurrences(&out, SERVER_KEY)`, so an emit site that appended a clause
  (`frp-core/src/config/loader.rs:680`) red the `frp-core` captures while `cargo test -p frps --test warn_delivery`
  stayed 17 passed / 0 failed. The file now carries a local port of the `frp-core` byte pin and the same mutant
  gives `13 passed; 4 failed` at `frps/tests/warn_delivery.rs:633:5`. The dashboard `KEY` captures and two
  weaknesses in the ported helper (a `contains("WARN")` level check and `.lines()` blinding the port to
  following-line bytes) are filed as one residue row rather than silently inherited.
- **`frps --config-dir` no longer loses a `SIGTERM` that arrives while the first service is still starting.** The signal was installed per service, so one landing before that install killed the process by the signal (`ExitStatus::code() == None`; shell `rc 143`, `Terminated: 15`) — exactly when a directory of slow or wedged files most needs to be stoppable. The main task now owns the handler: it records an early `SIGTERM`/`SIGINT` and hands the request to every service as it registers, and a repeat signal with nothing registered forces exit `143` so a lane wedged on a FIFO can still be stopped.
- **A `--config-dir` entry that is not a regular file is still admitted, now deliberately.** A FIFO named `*.toml` hangs the file read forever; Go's `frpc` hangs identically and Go's `frps` has no `--config-dir` at all, so the parity-bound behaviour is pinned by tests instead of "fixed" into a divergence.
- **Two test-precision residues pin what their names claim, and one snapshot wait is no longer a
  guess.** The `frp-server` OIDC mock's deadline accessor was only ever exercised through its 5 s
  default, so a lying accessor kept every test green: `mock_handle_reports_the_override_it_was_built_with`
  (`frp-server/src/control/login.rs:2377`) now drives three overrides (`125 ms`, `60 s`, and a non-round
  `31.337 ms`) and asserts the stored field, so an accessor that special-cases a round threshold or
  hardcodes the two original values is red too. `frpc/tests/admin_config_get_warning.rs` released its
  probe port between spawns, so a re-taken port failed the fixture once
  (`frpc admin server failed: Address already in use`): every admin test now spawns through a retry loop
  that writes the config with **that attempt's** freshly leased port (`PortLease`, `:170`, released
  immediately before the spawn) and `spawn_admin_ready` retries `MAX_ADMIN_PORT_ATTEMPTS` (`:116`)
  attempts, each lost port detected from the child's own stdout record (`ADMIN_PORT_HELD`, `:112`) inside
  a 250 ms `FAST_FAIL_WINDOW` (`:107`) instead of waiting out the 20 s readiness window.
  `frpc/tests/warn_delivery.rs` no longer sleeps a fixed 500 ms `SETTLE` before freezing its counts:
  `wait_for_record` (`:270`) returns only once the count has reached the wanted value **and** the capture
  has been quiet for `QUIET_PERIOD` (`:110`, 500 ms; `RECORD_TIMEOUT = 10 s` at `:101`), so a loaded host
  can no longer snapshot a record still in flight — and a second emit 150 ms behind the first, which the
  removed settle missed, now reds the test.
- **The `tls_enable` warning pins now fail when the warning they pin changes.** `frp-core/tests/common/mod.rs:132`
  compared the tracing **level** after `trim()`, which erased exactly the bytes it was meant to detect; the whole
  untrimmed `" WARN"` field is compared now, so an emit site that rewrites the target
  (`x frp_core::config::loader`) or inserts a space, `\n` or `\t` in front of it reds
  (`frp-core/tests/common/mod.rs:132:5`, `4 passed; 2 failed`) instead of leaving the web-server capture green.
  `frp-server/src/service.rs:420`'s `web_server_tls_enable_reader()` was unwitnessed — every `frps` lane links
  `frp-server` with `tls` on, so replacing its `cfg!(feature = "tls")` with `true` stayed green while a
  dashboard-on/tls-off build would have named a switch it cannot honour; the new name-filtered lane
  (`.github/workflows/ci.yml:460-514`, `cargo test -p frp-server --no-default-features --features dashboard`)
  runs `web_server_tls_enable_reader_answers_from_this_build` (`frp-server/src/service.rs:2621`) in exactly that
  shape and requires its completion marker. Both warning pins now carry `-- --list`-derived count guards
  (`.github/workflows/ci.yml:551-583` and `:584-613`, expecting 8 and 6), so an added `#[ignore]` or a deleted
  test reds the lane instead of passing quietly, and the `expected_warning` arm no test read (`NoWebServer`) is
  exercised by the reader loop.
- **The `web_server.tls.enable` warning no longer names a TLS acceptor a build does not have.** The text
  was chosen from the caller's `cfg!`, so `cargo build -p frpc --no-default-features --features micro,admin`
  — an `admin` build **without** `tls`, where the configured `cert_file`/`key_file` pair is discarded
  (`frp-client/src/admin.rs:1164`) — told the user the dashboard HTTPS server was enabled by that pair while
  its listener served plaintext HTTP. `frp-core` now exposes a three-valued reader
  (`WebServerTlsEnableReader`, `frp-core/src/config/loader.rs:257`) and every load path asks the crate that
  owns both features: `frp_client::web_server_tls_enable_reader()` (its `admin` + `tls`) and
  `frp_server::service::web_server_tls_enable_reader()` (its `dashboard` + `tls`). A build without the
  acceptor now says "nothing reads the key, and this build has no TLS support, so the dashboard/admin HTTPS
  server is never built", so the three states — a server with `tls`, a server without `tls`, and no server at
  all — each name their own build. The emitted record is pinned byte-exactly rather than by substring, and a
  new count-guarded CI lane runs the `micro,admin` shape.
- `--allow-unsafe` now reads its value with pflag's CSV grammar: quotes and a doubled `""` are
  syntax, leading spaces and tabs are significant (not trimmed), repeated flags append, and the
  ignored-flag twin parses the same record instead of one opaque value. A blank-only value reports
  Go's `EOF` flag error instead of failing later at the semantic gate, and a malformed value carries
  Go's line number and 1-based byte column.
- **`frpc`'s legacy `.ini` reader now follows Go on five shapes it used to refuse or drop.** An
  unknown key *inside* a legacy `.ini` section is accepted in both loader modes (Go never passes
  `strict_config` to its legacy reader; the top level of an `.ini` and every v1 format keep the
  full check); an explicitly empty `type = ""` defaults to `tcp` exactly as a missing one does; a
  typeless `role = "visitor"` section is refused with Go's `failed to parse visitor v, err: type
  shouldn't be empty` in both modes instead of being dropped silently in lenient mode and refused
  with a v1 message in strict mode; a section named exactly a reserved settings root (`[web_server]`,
  `[transport]`) that carries `local_port`/`remote_port` is a legacy proxy again, as Go registers
  it; and `[visitors.NAME]`/`[proxies.NAME]` are read as flat legacy sections instead of being
  expanded into a v1 sub-table and refused with `invalid type: map, expected a sequence`. The
  section-level strict exception is `.ini`-only and documented in `docs/config.md`. TODO.md:8081,
  :8084, :8107, :8164, :8191.
- **`frps --config-dir`: a panicking service task is now counted.** A task that panicked was logged and
  dropped, so a directory in which every task panicked still exited 0 with nothing served. The panic now
  joins the same all-failed decision as the typed failures, and the lane exits non-zero.
- **`frps --config-dir`: a directory where every file fails to load now exits with `-c`'s code.** A load
  failure never becomes a task, so the lane could not see it and answered `2` where `-c` on the same file
  answers `1`; a mixed load/construction failure now exits with the first file's code in file order.
- **`frpc --config-dir`: a directory whose service cannot run now exits 1, not 0.** The client lane
  reported success while nothing was served, and the two `--config-dir` lanes disagreed for the same
  failure. Go keeps its historical `0`; the divergence is recorded in `docs/developing.md`.
- **`frps --config-dir`: the `SIGUSR1 reload ready` marker is printed only after every service has
  registered.** A signal arriving between the marker and a registration reloaded only the registered
  subset and said nothing about it; the reload now fans out over a registry that is complete when the
  marker appears.
- **`frps --config-dir` no longer exits 0 when no service started.** The directory lane pushed each
  task handle before its service was constructed, so the "no services started" guard never fired:
  with **every** config file failing, the process reported success while nothing was served — a
  supervisor saw exit 0 and no listener. Each spawned task now reports its typed exit code (the
  construction code, or `EXIT_RUNTIME` when `run()` failed), and when every spawned task failed the
  process exits with the first **spawned** failure's code — the same value `frps -c` exits on for that file. A
  directory that still has one running (or gracefully shut down) service keeps the previous
  log-and-keep-serving behaviour.
- **The Docker source build now compiles with the pinned toolchain, not the base
  image's default.** `docker/Dockerfile.source` never copied `rust-toolchain.toml`
  into the build context, and its `RUN rustup target add …` installed the musl
  target into the base image's toolchain, so a naive `COPY` alone would have
  produced a pinned compiler without that `rust-std` (E0463 `can't find crate for
  std`). The context now carries the file, the install happens before the target
  setup, and a fail-closed assertion refuses the build when the active toolchain
  is not the file's channel or when `RUSTUP_TOOLCHAIN` overrode it. Measured:
  dropping the `COPY` or a stray `RUSTUP_TOOLCHAIN=stable` each fail the stage
  (rc 1), and a full uncached `docker buildx build` of the image succeeds and logs
  the pinned toolchain. TODO.md:6449.
- **`frpc verify` prints Go's exact success sentence.** It printed
  `Config file <path> is valid` where Go prints `frpc: the configuration file <path>
  syntax is ok`, so the client and server verify subcommands disagreed with each other. The
  first line is now Go's; the three indented summary lines that follow it stay (Go prints
  none) because the vendored legacy-`.ini` fixture test observes its proxy/visitor counts
  through them.
- **A typeless legacy `.ini` proxy section now loads as a `tcp` proxy, as Go's legacy
  reader does.** `[myproxy]` carrying only `local_port`/`remote_port` was dropped silently
  (rc 0, `Proxies: 0`) in non-strict mode and refused as `unknown field "myproxy"` in
  strict mode, while Go registers it as a `tcp` proxy. The rule is `.ini`-only — a typeless
  top-level table in TOML/JSON/YAML is still refused by the strict check, as Go's v1
  decoder refuses it — a typeless `role = "visitor"` section is deliberately *not*
  defaulted, because Go refuses that shape, and a dotted header under a v1 root
  (`[auth.foo]`) counts as a legacy proxy only when its section carries
  `local_port`/`remote_port`. The collector's known-section filter stays snake_case-only, so
  a header that names a v1 root is still read as that root even in the camelCase spelling —
  `[webServer] type = "tcp"` stays a proxy, as at base — and only a section with no `type`
  that names `local_port`/`remote_port` is collected as one.
- **`frps verify` and `frpc verify` now run the post-load `--allow-unsafe`
  gate, so a config the daemon refuses for its token source is no longer
  reported as valid.** Scoped deliberately: `verify` still does not run every
  daemon-side check — an OIDC config whose issuer is unreachable is rc 3 under
  `frpc -c` but rc 0 under `frpc verify` — so the claim covers the
  unsafe-feature gate only. Both
  verifies stopped at the config loader, while the daemon reaches
  `validate_token_source_unsafe` during service construction — so
  `[auth.tokenSource] type = "exec"` (and the `auth.oidc.tokenSource` spelling)
  verified rc 0 here but rc 1 on Go, whose `ValidateServerConfig` runs the check
  on the load/validate path that its verify shares. `run_verify` now loads
  through `load_server_config_checked` / `load_client_config_with_presence_checked`
  (`frp-core/src/config/file.rs`), which call `check_server_unsafe_features` /
  `check_client_unsafe_features` on top of the daemons' own predicate, and
  `--allow-unsafe` is read on both verify subcommands instead of ignored. The
  gate is fail-closed — `--allow-unsafe WrongFeature` is rc 1, not rc 0 — and the
  daemon path is unchanged, still exiting 3 `EXIT_AUTH` on the same config (the
  documented frp-rs extension over Go's rc 1). Pinned by
  `verify_runs_the_post_load_allow_unsafe_gate_like_go` in
  `frps/tests/cli_exit_codes.rs` and `frpc/tests/cli_exit_codes.rs`, and by
  `check_client_unsafe_features_gates_both_token_source_spellings` in
  `frp-core/src/config/tests.rs`; closes TODO.md:5177.
- **The `web_server.tls.enable` warning is now build-aware: in a build with no
  dashboard it no longer claims the dashboard serves plaintext HTTP.** The key is
  read behind `frp-server`'s `dashboard` feature (and `frpc`'s `admin`), but the
  warning was not, so every tier that cannot build a dashboard — the default
  `frps` (`full` does not include `frp-server/dashboard`), `frps-tiny`,
  `frps-micro` and a default `frpc` — still told the user what the dashboard does
  with `cert_file`/`key_file`. `frp-core` has neither feature, so the two texts
  now live in `WEB_SERVER_TLS_ENABLE_INERT_WARNING` (unchanged, for a build that
  compiles a dashboard) and the new
  `WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD` ("web_server.tls.enable has
  no effect: this build has no dashboard support, so nothing reads the key and no
  dashboard HTTPS server is built"), with
  `warn_inert_web_server_tls_enable(has_dashboard: bool)` picking between them;
  each call site passes its own `cfg!`. Measured on the real binaries:
  `frps-micro` and `frps-tiny` print the no-dashboard sentence and leave
  `web_server.port` closed, the default `frps` prints it too, and
  `frps --features dashboard` keeps the pair clause and listens.
  Round 2 closed the gap that fix left: the two texts were told apart only by a test
  that passed `has_dashboard` as a literal, so nothing checked what a real build
  answered — a call site hardcoding the other variant compiled clean and stayed green.
  The clause is now asserted by `cfg!`-keyed checks inside the existing `frps` and
  `frpc` warning-delivery tests, and by `frpc`'s admin-config test — gated whole-file
  on `admin`, so it asserts the dashboard text unconditionally — keyed on
  `plaintext HTTP` versus `no dashboard support`. Round 3 finished that job: three of
  the eight call sites were still unwitnessed — `frpc verify` (`frpc/src/main.rs:776`,
  whose test wrote no nested key so the record never fired), the client reload
  (`frp-client/src/service.rs:4489`, which had no clause assertion) and the
  `frpc --config-dir` site (`frpc/src/main.rs:527`, whose pin no CI lane ran). The
  clause is now asserted on all three, a new count-guarded `frpc --features admin`
  `warn_delivery` step runs the configuration that witnesses `:527`, and the two
  existing `frp-client` reload lanes (admin on and off) pin one branch each.
  `docs/config.md` also no longer states the `cert_file`/`key_file` pair rule
  unconditionally: an `admin`-without-`tls` client build has no TLS acceptor to hand
  the pair to, which is filed as its own item. (Superseded later in the same release:
  the text no longer depends on any caller's `cfg!` — `frp-core` exposes a three-valued
  reader and the crate that owns the `dashboard`/`admin` **and** `tls` pair resolves it,
  which adds the `admin`-without-`tls` text; see the entry at the head of this section.)
- **The server `tls_enable` warning now describes what actually happens to the
  certificate pair, in every build, and no longer fires for a
  `[common.transport.tls] tls_enable` that never reaches the loader.** With only
  `tls_cert_file` (or only `tls_key_file`) written, `frps` exits 1 with `TLS
  requires both cert_file and key_file to be set; got only one`, and a pair whose
  files cannot be read exits 1 with `open cert file: …`; the warning printed just
  before either described only what happens with *neither* file set, so it now
  names both refusals and adds that a SIGUSR1 reload introducing one keeps the
  server running with `TLS certificate reload FAILED: … (keeping old config)`
  instead. In a build without the `tls` feature — the shipped `frps-micro` tier —
  no acceptor is ever built, so the same key now emits a variant that says only
  that (the previous text claimed a startup refusal micro never performs).
  Separately, a literal `tls_enable` under `[common.transport.tls]` used to warn
  even when a top-level `[transport]` table made `[common]`'s flatten drop the
  sub-table whole before the lift could hoist anything; the detector now mirrors
  that drop (as the dashboard's sibling detector already did) and stays silent,
  while `[common.transport.tls] tls_enable` on its own and a flat `[common]
  tls_enable` still warn. The warning's documentation also said the
  `[transport.tls]` lift renamed "only four Go keys" while it renames five
  (`serverName` → `tls_server_name`); the count is corrected there, in the test
  docs and in `docs/config.md`.
- **`[webServer]` and `[web_server]` are now the same section, merged per key.**
  A file that wrote both used to have the camelCase table discarded **whole** —
  so a nested `[webServer.tls]` never reached the loader and a flat
  `[web_server] tls_cert_file` won in silence, while any key written only under
  `[webServer]` (`user`, `port`, …) simply vanished. The two sections now merge
  key by key, with `[web_server]` winning every key both define (the same winner
  as before, not an inversion) and nested `tls` tables merging the same way.
  Pinned in both loader modes, server and client, TOML and YAML.
- **`.ini` files can use the nested `[webServer.tls]` / `[web_server.tls]`
  section.** The INI reader stored the bracket text verbatim, so
  `[webServer.tls]` became a top-level key named `webServer.tls`: the values were
  dropped in non-strict mode and the file was refused with
  `unknown field "webServer.tls"` in strict mode. A dotted header whose first
  segment is a v1 section name (`web_server`, `auth`, `transport`, …) is now
  expanded into nested tables, exactly as TOML/YAML/JSON write it. Two kinds of
  section are deliberately **not** split, and both stay exactly as they were: a
  legacy proxy section that carries a `type` key (`[auth.foo]`, `[store.frontend]`,
  `[log.svc]`), and anything whose first segment is not a v1 root
  (`[plugin.NAME]`). The first is needed because a legacy proxy's name is a flat,
  user-chosen identifier — that is **Go's** `.ini` dialect, where every
  non-`[common]` section is a proxy (`pkg/config/legacy/client.go`); frp-rs's own
  `collect_legacy_ini_proxy_sections` used to require the `type` key, so a
  typeless proxy section was dropped where Go registers it as a `tcp` proxy; that
  parity gap is closed (see the Fixed entry above), and the section-level strict
  difference it leaves behind is filed in `TODO.md`. A genuine
  conflict is reported instead of silently clobbered **when the containing section
  comes first** (`[webServer] tls = 1` before `[webServer.tls]` → rc 1); in the
  reverse order the later section's scalar wins and the nested table is dropped
  with the file loading rc 0 (both orders pinned, both loader modes). The one
  shape the expansion still cannot express is a v1 nested table that itself
  carries `type` (a `[visitors.plugin]`-style table): it stays flat, so on the
  client the legacy collector reads it as a proxy named after the header and
  proxy validation refuses it. This is a frp-rs extension: Go's `.ini` path is the legacy
  loader and never reads these sections at all.
- **A nested `[web_server.tls]` key can no longer silently become a real
  `[web_server]` field.** The hoist re-inserted every unmapped nested key at the
  parent level, so `[web_server.tls] user = "nested-user"` *became* the
  dashboard Basic Auth username — and the same for `password`, `addr`, `port`,
  `assets_dir`, `pprof_enable`, `enable_prometheus`, `custom_404_page` and the
  flat `tls_*` spellings. The residue now stays inside `tls`, so strict mode
  reports it at the path the user actually wrote (`unknown field
  "web_server.tls.user"` — previously the fabricated `web_server.user`) and
  non-strict drops it like any other unknown key. Go refuses these keys
  outright.
- **A parent-level `certFile` beside the canonical `tls_cert_file` is no longer
  a `duplicate field` error.** serde binds the camelCase name as an `alias` of
  the canonical field, so writing both at the parent level failed to load in
  **both** modes with `config validation error: duplicate field
  \`tls_cert_file\``, with no nested section involved at all. The four-value
  group is now canonicalized down to one key whenever the section is seen:
  nested snake → nested camel → parent canonical → parent alias, first
  non-empty wins.
- **An empty nested TLS value no longer clears a configured certificate.**
  `[web_server.tls] cert_file = ""` beside `[web_server] certFile = "/p.pem"`
  loaded with `tls_cert() == ""` — the certificate was silently dropped and the
  dashboard served plaintext HTTP, because emptiness is how these fields say
  *disabled*. An explicitly empty nested value is now read as *unset* and falls
  through to the flat/alias spelling; `docs/config.md` states the implemented
  rule.
- **The `frpc` admin API's config GET delivers the inert
  `[web_server.tls] enable` warning again.** `config_from_file` — the load both
  `/api/proxy/{name}/config` and `/api/visitor/{name}/config` perform on every
  request — went through the silent file API, so three GETs added zero records
  while three PUTs added three. It now emits, **once per state change** rather
  than once per request: the route is polled, and the fact is a property of the
  file, not of the request. The cell is seeded from the file when the admin server
  starts, so the endpoint never repeats the startup record while a hand-edit that
  adds the key **after the admin server has started** is still reported (an edit
  landing between the startup load and the spawn is baselined — the seed reads the
  file at spawn); a PUT's reload resets the cell, so a following GET does not
  repeat that record either.
- **A server config that writes `tls_enable` now says so instead of loading in
  silence.** The field is inert on the server — nothing in `frp-server` / `frps`
  reads it — so a `tls_enable = true` in `frps.toml` bought neither an effect nor
  a word of explanation. It now emits one warning per load at every server load
  site that has a log sink (the two `frps` startup paths and the SIGUSR1 reload):
  `tls_enable has no effect on the server: …`, naming the real switch
  (`tls_only`) and how the acceptor's certificate is really obtained
  (`tls_cert_file` + `tls_key_file`, or the self-signed pair the server
  auto-generates when both are empty). Only a value the **user wrote** warns — a
  flat `tls_enable`, one under `[common]`, or a literal `tls_enable` inside
  `[transport.tls]` — not the `tls_enable = true` the loader synthesizes from the
  legacy `[transport.tls] force` / `certFile` / `keyFile`, so an existing Go-style
  config stays quiet. `frpc` is deliberately untouched: the client's own
  `tls_enable` *is* live, so warning there would be a false claim.
- **`[web_server.tls] cert_file` / `key_file` / `trusted_ca_file` / `server_name`
  — the nested section's own canonical spellings — are no longer dropped, and the
  nested section now wins over the flat keys the way the docs always said.**
  Only Go's camelCase spellings were mapped onto the flat
  `web_server.tls_cert_file` / `tls_key_file` / `tls_ca_file` / `tls_server_name`
  fields, so the snake_case names reached `web_server.cert_file` — not a field.
  With `--strict-config=false` (the SIGUSR1 reload's mode) the value vanished:
  `[web_server.tls] cert_file = "/c.pem"` loaded with `tls_cert() == ""` and the
  dashboard came up without TLS, while a file that also set the flat key behaved
  as if the nested one were not there. With strict mode (frps's default) the same
  file was **refused** with `unknown field "web_server.cert_file" … did you mean
  'certFile'?` — a path the user never wrote, pointing at the other spelling of
  the same field. Both spellings now map, and the nested value **overwrites** a
  flat key that is already set (documents and code disagreed here: the struct
  comment claimed nested-wins while `or_insert` made flat win, order-dependently).
  `[web_server.tls] enable` was in the same bucket — re-inserted as the unknown
  `web_server.enable` — and is now accepted and ignored in **both** loader modes.
  Go **refuses** the key rather than ignoring it: its `TLSConfig` has no `Enable`
  field, so `frps verify` exits 1 with `json: unknown field "enable"`. Accepting
  it is therefore a deliberate divergence — refusing it would reject a file frp-rs
  can serve correctly, and would split strict from non-strict exactly as the
  `cert_file` key did — and it comes with a startup warning, because the value
  is inert while the dashboard TLS is switched by a non-empty cert/key pair (the
  rule both implementations use): `enable = true` with no pair serves the
  dashboard as plaintext HTTP, and the warning is what says so. Scope of that
  warning, measured on the v0.71.0 binaries before and after: it used to be
  delivered only where the log sink was installed before the config load
  (`frps --config-dir`, 1 warning; `frpc --config-dir`, 1) and **not** on the
  `-c` path (`frps -c` and `frpc -c`, 0 warnings — with `RUST_LOG=debug`
  included), where the load deliberately precedes `init_logging` (the
  single-config branch of `frps/src/main.rs` and of `frpc/src/main.rs`), so the
  common path served the dashboard as plaintext HTTP in silence. The warning now
  reaches every load site that has a log sink: the loader no longer emits it (a
  `tracing::warn` there reached no subscriber on `-c`), it carries the fact out on
  a presence flag, and each site emits the one record — the two startup paths,
  `frpc verify`, and the `frps`/`frpc` SIGUSR1 reload. Measured on
  stdout / stderr: `frps -c` 1/0, `frps --config-dir` 1/0, `frpc -c` 1/0,
  `frpc --config-dir` 1/0, the same four with the `[common]`-flattened spelling
  1/0, `frps -c` reload +1, and 0/0 without the key. The admin PUT is also not
  silent — it validates through the string loader and then triggers a reload,
  which emits once per request (measured: 3 GETs → +0, 3 PUTs → +3,
  `/tmp/enable-warn-probe/run-admin-probe.sh` at the time). The Go-parity load
  ordering is unchanged; only the emission moved. A genuinely unknown nested key
  is still refused, named at the path the user actually wrote
  (`web_server.tls.<key>`). The gaps this bullet originally recorded — a `.ini`
  file, the `[web_server]` + `[webServer.tls]` pair, and the admin config GET —
  are all closed in this release: see the `.ini`, section-merge, nested-residue
  and admin-GET bullets above. What remains silent is `frps verify` (logging is
  never initialised) and the `[common]`-flattened spelling when a top-level section
  of the **same** spelling is also present (the `[common]` flatten discards that
  one key whole; the other spelling is a different key, merges in, and does warn).
- **An empty `--log-level` / `--log-file`, and a zero `max_days`, no longer
  silence `frps` or `frpc` — or silently switch off log retention.** Go fills
  each in `LogConfig.Complete()` (`pkg/config/v1/common.go:119-123`: empty →
  `console`, empty → `info`, zero → `3`), and an explicit empty value is Go's
  zero value, so `util.EmptyOr` fills it exactly like an absent key. frp-rs had
  no log completion and its serde defaults fire only when a key is **absent**,
  which produced three distinct defects:
  - `frps --log-level ""` (or `level = ""` in the config file) brought the
    listener up while emitting **0 bytes on stdout and 0 on stderr** — an empty
    level is parsed as `error`, and every startup record is `INFO`;
  - `frps --log-file ""` did the same *and* wrote a `frps.log.<date>` rotation
    file in the working directory instead of logging to the console;
  - `--log-max-days 0`, and `max_days = 0` in the config file, kept logging but
    silently disabled log retention, where Go retains 3 days (the observable is
    startup cleanup: an expired `frps.log.<date>` was left in place).

  Both configs now complete their `[log]` section the way Go does — `frpc` too,
  since Go calls the same `c.Log.Complete()` from `ClientCommonConfig.Complete()`
  (`pkg/config/v1/client.go:94`) and `frpc` had the identical hole — and an
  empty CLI value is treated as "not supplied" rather than as a literal level or
  path, which is Go's value-level semantics for a flag bound to its own default.
  That rule now also covers `--log-max-days 0`, which is Go's zero value and
  therefore means **3**, not "keep logs forever". Absent keys still take the
  serde default, and genuinely explicit values pass through unchanged — a
  negative `max_days` still disables cleanup, as it does on Go. The frp-rs-only
  `--log-format` is deliberately **not** completed: Go v0.71.0 has no such flag
  (`unknown flag: --log-format`) or config key.
- **`frpc --help=<bool>` no longer hides the command it names, and a `-hc`
  shorthand cluster is a parse error again.** Go registers `--help`/`-h` as a
  pflag bool, so `frpc --help=false status -c frpc.toml` **runs** `status` (it
  dials the config's `[webServer] port`; measured rc 1 and **1 connection** on Go
  v0.71.0, with the connection counted by `accept` on a fresh listening socket),
  while `--help=true status` prints `status`'s own help. frp-rs's bpaf parser
  treats `--help=<anything>` as its built-in help trigger and short-circuits, so
  both printed bpaf's usage with rc 0 and `status` never ran — a script that
  passed a bool-valued help flag saw success and no request. Now:
  - `--help=false <sub>` drops the flag and runs the subcommand (rc and the
    dial match Go);
  - `--help=true <sub>` prints the **subcommand's** help on stdout with rc 0, as
    `frpc <sub> --help` does — the same *shape* Go prints for `--help=true
    <sub>`, though not yet the same document (below);
  - `--help=<not a bool>` is refused with pflag's grammar and rc 1
    (`--help=foo`, `--help=yes`, `--help=`) instead of printing help;
  - `frpc -hc status` (pflag's shorthand cluster, `-h` then `-c` with no value)
    is rc 1 with `Error: flag needs an argument: 'c' in -c` on **stderr** and
    0 B on stdout, as on Go, where frp-rs used to print help on stdout with rc 0.
    The split spellings are covered too: `-c -h` was already `-c` taking `-h`
    (`open -h: no such file or directory` on Go, rc 1, 35 B on stdout), and the
    `-h -c` order is now rc 1 with `flag needs an argument: 'c' in -c` on **stderr**
    and 0 B on stdout, as Go, where it used to print help with rc 0. The **trailing
    usage block** cobra adds after that line is not reproduced (frp-rs parse
    failures print no usage block), so the stderr byte count is 41 where Go's is
    **637 B** for `frpc -h -c status` and `frpc status -h -c` (the two rows that
    carry a command word) and **1351 B** for bare `frpc -h -c` — recorded in
    `docs/developing.md` § `--help=<bool>`.
  Deliberately unchanged: `frpc --help`, `frpc -h`, `frpc --help=true`,
  `frpc <sub> --help`/`-h`, `frpc --help <word>` and the root
  `frpc --help=false -c cfg` divergence. Two residual differences are recorded,
  not papered over: the help **document** is still bpaf's (1604 B of usage for
  `frpc status --help` where Go prints cobra's 627 B `Overview of all proxies
  status` — a flag-surface-wide row that also covers `frpc --help`, 2405 B vs
  1370 B), and the shorthand refusal prints pflag's line without cobra's trailing
  usage block (41 B of stderr where Go's is 637 B). Full table and per-argv
  residuals: `docs/developing.md` § `--help=<bool>`.
- **`frps` now completes the config *after* the CLI flags are applied, as Go
  does — four argv/config shapes change behaviour, including the proxy listen
  address.** `frps` reads
  `./frps.toml` (or `-c <file>`) and overlays the CLI flags when no `-c` is
  given, but it completed the file first and wrote the flags afterwards, so an
  **empty** flag value bypassed the completion that fills it. Go completes a
  flag-populated struct on its flags-only path only (`cmd/frps/root.go:77-83`):
  its `-c` path loads a fresh struct from the file and completes that
  (`pkg/config/load.go:313`, `:318-321`), so the flags are ignored there — which is
  what frp-rs does on `-c` too. Measured
  against Go frp v0.71.0 with the same config file, a free control port and a
  free dashboard port per row, address read back with `lsof`:
  - `--dashboard-addr ""` with `[webServer] user`/`password` set and
    `[webServer] port` in the file: frp-rs logged
    `Dashboard web UI starting on :<port>` and then
    `Dashboard server failed: failed to lookup address information`, leaving the
    dashboard port **unbound** while the control listener stayed up; it now
    binds `127.0.0.1:<port>` like Go (`WebServer.Complete()` fills the empty
    string with `127.0.0.1`). Without credentials this was masked by the
    no-auth force-bind, which is unchanged and still applies.
  - `--bind-addr ""`: the empty address reached `TcpListener::bind`, so frp-rs
    exited **1** with `failed to lookup address information` and bound nothing;
    it now binds `0.0.0.0:<port>` like Go
    (`c.BindAddr = util.EmptyOr(c.BindAddr, "0.0.0.0")`,
    `pkg/config/v1/server.go:110`). The same fill now also covers
    `bindAddr = ""` written in the config file — including under
    `--config-dir`, where the same config used to exit **0 with nothing bound**.
  - `--bind-port 0`: it bound an OS-chosen ephemeral port; it is now completed
    to the default **7000**, like `bindPort = 0` in a file and like Go.
  - **The proxy listeners now follow `--bind-addr`.** Go's `ProxyBindAddr`
    inherits the final `BindAddr` inside `Complete()`, so frp-rs now does that
    too; before, the inheritance had already happened against the file's value,
    so `--bind-addr 0.0.0.0` over a file that said `bind_addr = "127.0.0.1"`
    moved the control listener to every interface while the registered proxy
    ports stayed loopback-only. If you pass `--bind-addr`, the proxy ports bind
    the same address as the control listener (and if you pass a narrower
    address, they narrow with it). Per-proxy pinning via an explicit
    `proxyBindAddr` is unchanged and still wins.
  Absent flags are unaffected — the configured value is still what binds — and
  so is `-c`, which keeps the file authoritative (flags ignored). Also
  unchanged: frp-rs still needs `./frps.toml` to exist where Go's flags-only mode
  needs no file at all.
- **`frpc` no longer crashes at shutdown when two or more visitors share a
  `bind_port`.** Both the explicit multi-visitor config (`[v1]`/`[v2]`/`[v3]` with
  one `bind_port`) and the legacy `[range:...] … role = visitor` template form
  started normally and then panicked on `SIGTERM`
  (`panicked at tokio-1.53.1/src/runtime/task/core.rs:427: JoinHandle polled after
  completion`), exiting **101** in the debug profile — and the release profile is
  built with `panic = "abort"`, so the same panic aborts the process instead of
  shutting it down. The visitors that lose the bind race finish their listener
  task immediately while the winner stays parked in `accept()`; the visitor
  teardown then awaited the finished tasks' join handles a second time, which
  tokio panics on. Shutdown now skips handles that are already finished, so each
  handle is awaited at most once. Measured before/after (Rust `frps` + `frpc`,
  free ports, children reaped): explicit three visitors on one `bind_port` 3/3
  panics (rc 101) → **0/5 (rc 0)**; the `[range:rv] … role = visitor` form 3/3 →
  **0/5 (rc 0)**; and the same defect without a shared port — two visitors on
  distinct `bind_port`s with one port already held — 3/3 → **0/3**. Single-visitor
  shutdown and visitor sets on distinct ports were already clean and stay clean
  (rc 0), the 500 ms shutdown grace is unchanged, and each run still logs exactly
  the two `Address already in use` lines for the visitors that lose the bind race,
  the shape Go frp v0.71.0 produces. Go parity note: on the default TCP transport
  Go is killed by `SIGTERM` (rc 143 — its handler is installed only for kcp/quic,
  `cmd/frpc/sub/root.go:206-209`) while logging those same two lines; with
  `protocol = kcp` the same config exits 0. frp-rs now exits 0 on both.
- **The five persistent rootCmd flags are now accepted — and ignored — on every
  `frpc` subcommand — a behaviour change.** Go registers `-c`/`--config`,
  `--config-dir`, `--strict-config`, `--allow-unsafe` and `-v`/`--version` on
  `rootCmd`, so pflag parses all five for every subcommand, while the eight
  single-proxy commands never read any of them. frp-rs's bpaf parsers did not
  define them, so `frpc tcp --local-port 5 --remote-port 6 --proxy-name x -c
  noweb.toml` started the proxy on Go and exited **1** here with ``Error: `-c`
  is not expected in this context``; `--config-dir` and the other three behaved
  the same way. All twelve `frpc` subcommands now accept them and drop all but
  `--allow-unsafe` on `verify`, which reads it and decides that command's verdict
  (the four admin commands already declared `-c` and `--strict-config`). Two pflag
  spellings come with it: a repeated flag is last-wins (or appending for
  `--allow-unsafe`) and never an error, and a `-`-prefixed token after `-c` is
  consumed as that flag's **value** — `frpc status -c --strict-config=false -c
  p7498.toml` dials p7498, as Go does. bpaf already took some `-`-prefixed values
  (an unknown multi-character token such as `-foo.toml`), but not a token it
  classifies as a flag (`--long`, `-x`, `-c`, `-a=b`), so those config-flag
  occurrences are rewritten to `-c=VALUE` before parsing.
  Three user-visible consequences of taking pflag's value rule:
  `frpc -c --help` and `frpc --config --help` no longer print help — the token is
  the config path, so they read a file called `--help` and exit 1, as Go does;
  on a single-proxy command `frpc tcp … -c --help` now starts the proxy instead
  of printing help, again as Go; and `frpc --config-dir --help` (or
  `--config-dir -x`) now reaches frp-rs's pre-existing `--config-dir` refusal,
  **exit 2**, where Go swallows the directory error and exits 0 — the recorded
  deliberate divergence, not a new one.
  Unchanged: a dangling `-c` is still an error and the single-proxy commands
  still do not read the config file. Still refused, where Go ignores it:
  **positional arguments**, with or without `--` (`frpc status -c a.toml -- -c
  b.toml`, `frpc status extra`, `frpc tcp … extra`), including the leftover
  argument of a flag-shaped `-c` value (`frpc tcp … -c --config-dir cDir` starts
  on Go, is rc 1 here) — the residual shapes, each with its measurement in
  `docs/developing.md` § CLI inputs. The `frps` command behaved the same way at
  that head — Go's pflag consumes `-`-prefixed values for `frps -c` too and
  frp-rs refused them — and the shared pre-parse pass now covers it; see the next
  entry.
- **`frps` now takes a `-`-prefixed value after `-c`/`--config` too, exactly as
  `frpc` does — a behaviour change.** The pflag value rule in the entry above was
  wired to the `frpc` entry point only, so Go's
  `frps -c --strict-config=false` (which is `open --strict-config=false: no such
  file or directory`, exit 1 — the token is `-c`'s **value**) exited 1 here with
  ``Error: `-c` requires an argument `FILE```, and `frps -c -x` exited 1 with
  the "got a flag `-x`, try `-c=-x`" refusal. Both binaries now run the same
  pre-parse pass, so these argv shapes work on `frps`: `frps -c
  --strict-config=false`, `-c -x`, `-c --bind-port` and `--config -x` all read
  the flag-shaped token as the config path and fail on the missing file with
  exit 1, as Go does; `frps -c --` reads a file named `--` (Go: `open --: …`);
  and `frps -c --help` now reads `--help` as the config path (exit 1, as Go)
  instead of printing help with exit 0 — the same rule, and a deliberate loss of
  the old frp-rs convenience. Not changed: a dangling `-c` is still an error, and
  a `--` that is a real separator still ends flag parsing (`frps --
  --strict-config=false` and `frps -- -c p.toml` are refused here, while Go
  **starts the server** — it takes everything after `--` as positional args and
  ignores them; `unknown command "…"` fires only for a positional *without* `--`,
  which is the pre-existing positional divergence, not a new one). Also not
  changed, and stated so it is not read into this note: **`frps` has no `-c`
  last-wins** — `frps -c a.toml -c b.toml` is refused on both trees where Go
  opens `b.toml`; only the rewrite's dash-value attachment is shared with frpc.
  One row moves
  the other way and is deliberate: `frps --config-dir -x` (or
  `--config-dir --strict-config=false`) now reaches frp-rs's pre-existing
  `--config-dir` refusal, **exit 2**, where the parser used to answer exit 1
  ``--config-dir` requires an argument `DIR`` — `--config-dir` is one of the
  four flags the pass covers on both binaries. Go `frps` has no `--config-dir`
  at all (`unknown flag`, exit 1), so that row is a documented divergence either
  way. `frps verify -c <dash-value>` also reported a different error at that
  head: `verify` was not a subcommand then, so the unknown subcommand was the
  first error instead of the `-c` refusal (Go has `frps verify`; the row's Go
  error is pinned in `docs/developing.md` § CLI inputs). **Superseded by the
  `frps verify` entry above**: the subcommand now exists, so that argv reaches
  the loader and fails there, as Go does.
- **`frpc --version` no longer short-circuits an argv that is going to fail — a
  behaviour change.** The version check lived in a closure on the run-mode
  branch of `frpc`'s argument parser, and bpaf evaluates every alternative while
  choosing one, so the closure printed `frpc 0.71.0 (Rust)` and exited **0**
  before the rest of the argv was judged: `frpc --nope=1 --version` and
  `frpc verify --version` both exited 0, where Go exits 1 (`unknown flag:
  --nope`) and 0-with-`verify`-actually-running respectively. The check now runs
  after the parse, exactly as `frps`'s already did, so
  `frpc --version=foo` exits 1 like Go's `strconv.ParseBool` refusal and an
  invalid flag wins. One row moved the other way at that head and is repaired in
  this same unreleased section (see the persistent-rootCmd-flags entry above):
  `frpc verify --version` was rc 1 because frp-rs did not register Go's
  persistent root flags on its subcommands (`TODO.md:2226`); it now parses the
  flag, ignores it and verifies, as Go does.
- **A repeated `-c`/`--config` is now last-wins on the five `frpc` commands that
  read a config file — a behaviour change.** Go registers `-c` with pflag
  `StringVarP`, so `frpc status -c a.toml -c b.toml` loads `b.toml` and is never
  an error; frp-rs rejected the second occurrence with ``argument `-c` cannot be
  used multiple times in this context`` before loading anything. `run`,
  `verify`, `reload`, `status` and `stop` now all take the **last** config,
  mixing `-c`, `--config`, `-cPATH` and `-c=PATH` freely (they are one variable,
  as in Go). An absent `-c` keeps its previous meaning on each command (`run` →
  `frpc.toml`, the admin subcommands → the frp-rs default address), and a `-c`
  with no value is still a parse error. The eight single-proxy subcommands
  (`tcp`, `udp`, `http`, `https`, `stcp`, `xtcp`, `sudp`, `tcpmux`) still
  rejected `-c` at that point (``Error: `-c` is not expected in this context``,
  where Go accepts and ignores the persistent flag); that is fixed later in this
  same unreleased section — see **the five persistent rootCmd flags** above —
  and the `frps` CLI is untouched.
- **An empty `webServer.addr` is now completed to `127.0.0.1` — a behaviour
  change.** Go's `WebServerConfig.Complete()` is
  `c.Addr = util.EmptyOr(c.Addr, "127.0.0.1")`, so a client config with
  `[webServer] addr = ""` and a port dials loopback. frp-rs used the empty
  string literally and failed with `connect :<port>: failed to lookup address
  information`, which broke `frpc reload`/`status`/`stop` on such a config. The
  client's own `[webServer]` admin listener was **not** binding the empty host.
  Measured at the base with `--features admin` and a live frps: with credentials
  it logged `admin server starting on :7597` and then
  `admin server failed: failed to lookup address information …`, so nothing
  listened; without credentials it logged `refusing to bind admin API to
  non-loopback address :7597` and listened on `127.0.0.1:7597` through the
  pre-existing force. The completion removes that failure and makes the
  configured address explicit; where an unauthenticated listener binds is
  unchanged.
  Only the empty string is completed: `" "`, `"0.0.0.0"`, `"::1"` and
  `"localhost"` are still passed through to the dialer verbatim, as in Go.
  The server's own `[webServer] addr` is a separate, also-fixed surface — see
  the entry below.
- **An empty `webServer.addr` no longer puts the `frps` dashboard on every
  interface — a behaviour change, and a hardening fix.** Found while closing the
  client-side item above, where it was recorded as an unchanged divergence. Go's
  `ServerConfig.Complete()` calls `c.WebServer.Complete()` at
  `pkg/config/v1/server.go:107` — `Addr = util.EmptyOr(Addr, "127.0.0.1")`
  (`pkg/config/v1/common.go:71-72`) — **before** the
  `if c.WebServer.Port > 0 { c.WebServer.Addr = util.EmptyOr(c.WebServer.Addr,
  "0.0.0.0") }` branch at `:116-117`, so that branch is dead on Go and an
  explicit `addr = ""` with a set port stays loopback. frp-rs implemented only
  the second half: it rewrote an empty address to `0.0.0.0` whenever the
  dashboard port was set, so with `[webServer] addr = ""` plus credentials the
  dashboard and `/metrics` listened on **all** interfaces where Go listens on
  `127.0.0.1`. Measured, same config for both binaries (dashboard port 17701),
  `lsof -nP -iTCP:17701 -sTCP:LISTEN`: Go `TCP 127.0.0.1:17701 (LISTEN)`,
  frp-rs (before) `TCP *:17701 (LISTEN)`, frp-rs (now)
  `TCP 127.0.0.1:17701 (LISTEN)`. An *absent* `addr` key was already
  `127.0.0.1` on both (the serde default supplies it) and every explicit
  address is still used verbatim — `"0.0.0.0"` keeps binding all interfaces,
  `"::1"` stays `[::1]`. The completion now follows Go's order and the dead
  wildcard branch is gone; the bound address is pinned by tests that spawn the
  real binary (`frp-server/tests/dashboard_integration.rs`). Operators who
  relied on `addr = ""` meaning "all interfaces" must now write
  `addr = "0.0.0.0"`.
- **`frp-server` builds with only the `dashboard` feature compile again.** A
  downstream workspace (or `cargo check -p frp-server --no-default-features
  --features dashboard --all-targets`) that had frp-core's `oidc` on while
  frp-server's was off failed with `AuthMethod::Oidc` not covered plus four
  unrelated errors (`TcpListener`, `TcpStream`, `io`, unused `AtomicU64`). The
  variant is now exhaustive by construction and the imports are gated on what
  actually uses them; the configuration is gated in CI.
- **Legacy `.ini` configs now load where Go's do: a bare numeric or a comma list
  reaches a string field as the string Go gives it, and a `[range:...]`
  template with a comma list or `role = visitor` behaves like Go's.** Three
  measured divergences, all pre-existing:
  `token = 12345678` (Go's own `conf/legacy/frpc_legacy_full.ini`) was inferred
  as a TOML integer and refused with ``invalid type: integer `12345678`,
  expected a string`` where Go's `frpc verify -c` exits 0 with the token as the
  string; `allow_ports = 2000-3000,3001,3003,4000-50000` (Go's
  `frps_legacy_full.ini`) was refused as ``invalid type: sequence``;
  `[range:x] local_port = 6010-6012,6020` was **silently dropped** — Go
  registers 4 proxies, frp-rs reported `Proxies: 0` and logged
  `WARN … missing or invalid local_port; skipped` — so the 17
  `[range:tcp_port]` proxies of Go's shipped client fixture were lost; and a
  `[range:...]` template with `role = visitor` was misrouted to proxies (Go
  builds visitors, `pkg/config/legacy/client.go:252-285`), with the
  visitor-only keys stripped with them. `.ini` values are now read by the target
  field's type (the inference is lossless through both renderers, so `token = 007`
  stays `"007"` and an extreme magnitude such as `token = 10000000000000000000`
  or `token = 0.0000001` is passed through as the file's text instead of a
  re-rendering like `1e+19`/`1e-7`), a slice value is split the way Go's
  `Key.Strings(",")` does (`custom_domains = a\,b` → `["a,b"]`, a trailing empty
  element dropped), `[range:...]`'s port lists accept the split array, and a
  visitor template builds visitors. Go's wider legacy boolean spellings
  (`authenticate_heartbeats = 1`/`yes`) are honoured for `.ini` only: a
  TOML/JSON/YAML `1`/`"yes"` keeps being ignored exactly as before. Both of Go's shipped `conf/legacy/{frpc,frps}_legacy_full.ini`
  fixtures are vendored byte-identically and now load end to end — 43 proxies
  and 2 visitors for the client file, exactly the names and counts Go frpc
  v0.71.0 itself reports for it (`proxy added: […]`, `visitor added: […]`).
  Scope: the type-directed reader above **and** the wider legacy boolean
  spellings are `.ini`-only — TOML/JSON/YAML keep strict serde typing, so a
  numeric `token` is still refused there — while `[range:...]`'s array arm
  belongs to the shape-based legacy collector and therefore applies in **every**
  format (it only adds acceptance: such an array was dropped with a warning
  before). See
  [docs/config.md § Legacy `.ini` values](docs/config.md#legacy-ini-values-are-read-by-the-target-fields-type).
- **`/api/reload` now reads `?strictConfig=` the way Go frp does — two behaviour changes.**
  A repeated parameter (`?strictConfig=true&strictConfig=false`) reloads with the first value
  (Go's `url.Values.Get`); it previously failed serde deserialization and answered 400. And a
  parameter whose percent-escape is malformed (`?strictConfig=%zz`) is now treated as
  *absent*, so a `POST` body (`{"strict_config": true}`) takes effect where the old handling
  kept the broken value and ignored the body. Malformed escapes without a body are unchanged
  (still a non-strict 200), as is every other endpoint.
- **The exit code on a service-construction failure no longer depends on the
  error text — two input families change code, in opposite directions.**
  `frpc`/`frps` used to pick between `EXIT_AUTH`/3 and `EXIT_BIND`/4 with
  `msg.contains("token") || msg.contains("auth")` over the formatted error, which
  embeds the config path and any URL from the config. The kind is now a typed
  value chosen where the constructor raises the error (`frp_core::init_error`).
  Measured base-vs-head, one fresh config and one fresh closed port per row, rc
  captured directly from the child:
  - **`frpc` `[store] path` → a file that is not JSON: 3 → 4** when the path
    contains `auth` or `token` (it was 3 for `authstore.json` and 4 for
    `plainstore.json` — the same failure class, two codes). Now 4 for either
    name.
  - **`frpc` client-OIDC construction failure: 4 → 3** at an **auth-free** issuer
    URL. The discovery fetch (only when `oidc.token_endpoint` is unset **and**
    `oidc.token_source` is unset **and** the issuer is set — `frp-core/src/auth.rs`)
    embeds the issuer URL in its error, so an issuer path
    containing `auth` gave 3 and an auth-free one gave 4. Every issuer path is
    now 3 — e.g. `…/zzz` and `…/plain` were 4 and are now 3, `…/authz` is 3
    either way. The same family covers a missing `oidc.trustedCaFile`
    (`OIDC client: failed to read CA cert …`: 4 → 3 at an auth-free path).
  - **`frps` changes no code at all:** every reachable server construction
    failure already carried `auth` or `token` in its message, so base and head
    are 3 for `/authz`, `/zzz`, a missing `tokenSource`, an empty token, a
    missing OIDC CA file, an empty issuer and an empty audience — **4 was
    unreachable on `frps`**. The typed arm fixes the text dependency there
    without moving a code.
  **Go's behaviour is not one code across all of this**, measured on v0.71.0
  (darwin/arm64), and it is worth spelling out because both frp-rs codes are
  extensions either way. On the two **`frpc`** families Go **exits 1**:
  `failed to create store source: … failed to parse JSON: …` for the `[store]`
  pair, and `json: unknown field "issuer"` for the client OIDC inputs — Go's
  *client* OIDC config has no `issuer` key at all. On the **`frps`** rows it does
  not: an empty `token` with `method = "token"` **does not exit** (it prints
  `frps started successfully` and keeps running), the two OIDC rows **panic and
  the runtime exits 2**, and a missing `auth.oidc.trustedCaFile` is not a
  comparable input — Go's *server* OIDC config has no such key
  (`json: unknown field "trustedCaFile"`, rc 1). Other inputs
  keep their codes: `auth.tokenSource` on a missing file is still 3 on both
  binaries, the empty-token refusal is still 3, and an occupied `bindPort` is
  still 1 on both sides. There is deliberately **no** `EXIT_AUTH`/`EXIT_BIND`
  collapse to Go's 1 here — see `docs/developing.md` § CLI exit codes for the
  argument.
- **Library API (`frp-core`, `frp-client`, `frp-server`): two breaking changes**
  on top of the user-visible one above. `frp_core::logging::is_token_error` was
  `pub` and is **deleted** (it classified a failure by matching `token`/`auth` in
  a message; use `frp_core::init_error::InitErrorKind` instead). And
  `Service::new` / `Service::with_unsafe_features` now return
  `Result<_, frp_core::init_error::ConstructError>` — it was
  `Box<dyn std::error::Error>` in `frp-client` and `String` in `frp-server`.
  `ConstructError` implements `Display`/`Error`, so `?`-based callers that only
  print or propagate keep working; callers that matched on `String` or compared
  the error text need the `kind()` method.
- **An explicitly empty log flag no longer raises the config file's level on `frps`.** `frps`
  overlaid every log CLI value onto the loaded config, so `--log-level ""` wrote `""` into
  `[log] level` and the Go-compatible completion then filled it with `info` — a file's `warn`
  produced 11 `INFO` records where Go's `-c` lane emits none. An empty `--log-level`/`--log-file`
  and `--log-max-days 0` are now "not supplied": the file's value survives, matching `frpc` and
  Go's `-c` lane. `--log-format` still writes through, because it is an frp-rs-only flag with no
  Go completion to mirror; the two adjacent divergences (`-c` plus a non-empty log flag, and the
  implicit-config lane) are recorded in `TODO.md`.
- **`--vhost-http-timeout` is now Go's signed `int64`.** It was `u64` here, so
  `--vhost-http-timeout -1` was refused where Go accepts it and a value above `i64::MAX` was
  accepted where Go refuses it. The flag and `ServerConfig::vhost_http_timeout` are `i64`; the
  internal clamp still treats a non-positive value as "no timeout". The refusal *text* for an
  out-of-range value is still Rust's rather than Go's `strconv.ParseInt` wording (recorded in
  `TODO.md`).
- **`frpc` ran an `auth.tokenSource` `exec` command twice per successful login; it now runs it
  once, as Go does.** `frp-client/src/service.rs:957` already resolved the source, but `:952` at pre-fix `084f7865`; the
  post-fix `None` is `:983`) also stored the same `ValueSource` in `AuthConfig.token_source`, so every Login, Ping and NewWorkConn
  re-executed it; Go resolves once in `NewService` (`client/service.go:168`). The stored source is
  dropped and the behaviour is pinned by `frp-client/tests/token_source_single_exec.rs` (one
  execution after construction, after two logins, and after three reloads — including a refused
  `[auth]` change) and by the restored ping re-arm oracle
  `frp-client/tests/heartbeat_wire_order.rs:669`. Measured with real binaries, one login:
  pre-fix **2** executions, fixed **1**, Go **1**.

### Changed
- **The space-separated `--strict-config <bool>` extension now prints a warning
  on stderr — new output on that path only.** `--strict-config false` (two argv
  tokens) has always been consumed as the value by frp-rs, while Go frp
  v0.71.0's pflag bool does **not** consume it: the same argv stays strict there
  (`json: unknown field …`, exit 1) and is lenient here — a silent difference
  that can change which config is loaded (`frpc verify` exits 0 here and 1
  there) or which port an admin command dials. Every parser that can consume the
  form (`frps` and `frpc`'s `run`/`verify`/`reload`/`status`/`stop`) now prints
  exactly one line before doing anything:
  `warning: --strict-config <bool> is an frp-rs extension; Go's pflag does not
  consume the token and stays strict. Use --strict-config=<bool> for identical
  behaviour.` The `=`, bare and absent spellings stay silent, and nothing else
  about the parsing changed — the extension is kept, because dropping it would
  turn argv Go accepts into an frp-rs argv error.

### Docs
- **Six comment cites across four files now name the line that actually supports their claim.** The cites had rotted
  independently of any code change: two named `frp-server/src/service.rs:2281` (past EOF) for the graceful-shutdown
  `Ok(())` tail, one named a doc comment as "the `tracing::warn!`" where the call is 130 lines below it, one named a
  micro/no-TLS doc block as the top-level-then-`[common]` fallback, and one sentence carried three at once — a past-EOF
  `service.rs:2048` plus two `frps/src/main.rs` numbers that were stale rather than swapped (at the pre-#455 base each
  still sat on the path its label named). Comments only: no behaviour, test or assertion changed. Closes `TODO.md:10314`.
- **Strict mode's acceptance of a feature-gated server port is recorded as a deliberate divergence, with a measurement in both build shapes.** `known_server_keys()` keeps `kcp_bind_port` / `quic_bind_port` / `websocket_port` (and their camel spellings) accepted in **every** build shape even though `frp-core/src/config/server.rs` compiles the matching serde field out, so `--strict-config` accepts a key a `micro`/`tiny` build then ignores. Refusing it would be the "false 400" direction `docs/deployment.md` rules out, and the repo's own `frps.toml` writes `kcp_bind_port` / `quic_bind_port`, so rejection would stop those builds from loading the documented example. The `websocket_port` row of `docs/config.md` now says so, `known_server_keys()` carries the same statement in its own doc, and `frp-core/src/config/tests.rs` pins both halves in both shapes: strict mode accepts the snake and the camel spelling, `serde_json::to_value(&cfg)` carries the field exactly when the feature is compiled in, and a feature-off load instead records the key as accepted-but-unhonoured (the run path warns about it; the key stays accepted). **No runtime behaviour changed.**
- **`docs/config.md` no longer advertises four camelCase client TLS aliases that
  no loader accepts.** The four client rows named `tlsEnable`, `tlsCertFile`,
  `tlsKeyFile` and `tlsCaFile` / `tlsTrustedCaFile` in their "Go frp Equivalent"
  column — the same defect the server rows had, in the other half of the
  table. Every one of the five is silently ignored by the non-strict loader (the
  SIGUSR1 reload path) and **refused** in strict mode (`unknown field "tlsEnable"
  … — did you mean 'tls_enable'?`) — and flat camelCase is not a Go client
  spelling either: Go v0.71.0 carries these fields under the nested
  `[transport.tls]` section. The rows now name `transport.tls.enable` /
  `certFile` / `keyFile` / `trustedCaFile` (the keys frp-rs maps at load), and
  the client flatten block gains the same Exception sentence the server block
  has, keeping the two flat aliases that **do** work — `tlsServerName` (→
  `tls_server_name`) and `disableCustomTLSFirstByte` (→
  `disable_custom_tls_first_byte`). A new test pins all five spellings as
  rejected in both loader modes, the nested spellings and both real aliases as
  accepted in both, and the `known_client_keys()` list the docs must agree with.
- **`docs/config.md` no longer advertises four camelCase server TLS aliases that
  no loader accepts.** The `tls_only`, `tls_cert_file`, `tls_key_file` and
  `tls_ca_file` rows named `tlsOnly`, `tlsCertFile`, `tlsKeyFile` and
  `tlsCaFile` in their "Go frp Equivalent" column, but every one of the four is
  silently ignored by the non-strict loader (the SIGUSR1 reload path) and
  **refused** in strict mode (`unknown field "tlsOnly" … — did you mean
  'tls_only'?`) — and flat camelCase is not a Go server spelling either: Go
  v0.71.0 carries these fields under the nested `[transport.tls]` section. The
  rows now name `transport.tls.force` / `certFile` / `keyFile` /
  `trustedCaFile` (the keys frp-rs maps at load), the Exception sentence under
  the alias list now names `tls_only` alongside the three fields it already
  covered, and it keeps the two flat aliases that **do** work —
  `tls_trusted_ca_file` (→ `tls_ca_file`) and `tlsServerName` (→
  `tls_server_name`). A new test pins all four spellings as rejected in both
  loader modes, both real aliases as accepted in both, and the
  `known_server_keys()` list the docs must agree with.
- **The space-separated `--strict-config <bool>` form is documented as an
  frp-rs extension.** It is now stated in the `--strict-config` help of every
  parser that takes the flag (both entries are pinned separately by a test), so
  the flag is no longer presented as Go pflag semantics.
  `--strict-config=<bool>` is named as the Go-faithful spelling — **for a single
  occurrence**: a repeated flag is last-wins in Go but refused by frp-rs, and
  that row, the empty-value rows, the position row and the measured drop branch
  are in `docs/developing.md` § `--strict-config`: the space-separated value
  form.
- **The `frps` `-c` run path's loader doc link now names the loader it calls.** The sentence at
  `frps/src/main.rs:332` named `load_server_config_uncompleted` where the run path calls
  `load_server_config_uncompleted_with_presence` (`frps/src/main.rs:967`); it now states the relationship
  (the presence-carrying form of the plain loader, i.e. the completing loader minus
  `ServerConfig::complete`).
- **`docs/developing.md` § 2 is now an end-to-end contributor path for a new proxy type.** It walks
  the whole path — reading order and what to skip, the six config allow-lists, the registration and
  port-accounting sites, the listener/bridge split, the test ladder, the cross-compat scenario and
  the records a contributor does not own — with one worked `mytcp` example, plus a § 2.8 for a client
  plugin and a § 2.9 entry point for a new maintainer. It is validated rather than merely written:
  the round-1 review followed only the document and landed a working TCP-like type (config gate with
  the real binary, unit test red → green, in-process e2e, real `frps` + `frpc` round trip) before the
  defects that walk turned up were fixed. It also corrects two load-bearing claims: `[transport]
  tcpMux` is *normalized* (only a **top-level** camelCase `tcpMux` is silently dropped), and a
  TCP-group-capable type touches seven more predicate sites.

### CI & Tooling

- **The A/B throughput gate now skips a delta with nothing measurable, publishes the median of every sample, and is informational unless enforcement is requested.**
  A scheduled `main~1` vs `main` run (run `36996762744`, head `ae7bf50d`) failed with `encrypt_compress 18.0 -> 15.2 = -15.6% REGRESSED` in the same table that reported `+58.8%` on another configuration, while no executed line changed: its ten `.rs` files carry only `TODO.md:` citation re-points, and its remaining edits are dev tooling (`scripts/large-functions.sh` and its new `scripts/tests/large-functions-classifier.sh`, `scripts/compat-test.sh`, `scripts/tests/*`, `.github/workflows/ci.yml`) — the 5% threshold sits below the gate's own measured noise floor (identical binaries: `-35.1% / -27.9% / +24.5%`). A new classifier (`scripts/ab-measurable-delta.sh`) skips a delta whose changed paths cannot move the measured numbers (the workflow classifies before the VPS secrets check and the base checkout, so a skip costs one `git diff`), the gate reports the median of every sample instead of the most negative one, and a beyond-gate median warns, annotates and exits 0 unless `AB_GATE_ENFORCE=1` restores the hard failure. Closes `TODO.md:10569`.
- **The `frp-server` dashboard-only lib lane now runs unfiltered, so a test that shape cannot run can no longer hide behind a name filter.**
  The lane compiled `dashboard::v2::tests::test_serverinfo_go_shape`, which demanded the Go keys `kcpBindPort`/`quicBindPort` that a build without those transports structurally cannot produce (the response fields carrying them are `#[cfg]`-gated), and every job using that shape filtered on `web_server_tls_enable_reader` — so the lane was red at the base (`FAILED. 361 passed; 1 failed`) and no job ran it whole. Both demand sites now gate the two keys on the features the build compiles, while the default-feature lane still checks the full Go set (un-gating the key again leaves that lane green and reds only the shape without the listener); a new step runs the entire `--lib` target with no filter and pins the exact listed/passed counts (`n_expected=363`), reading the pipeline's status before failing so a failing row still prints its `::error::` and the log tail. The step inserts 44 lines, so every live `ci.yml` cite below it moved; the nine in `frp-core/tests/server_tls_enable_warning.rs`, `frp-core/src/config/loader.rs`, `frp-server/src/service.rs` and `frp-server/tests/server_reload_restart_only.rs` were re-pointed by content (each was already stale at the base). Closes `TODO.md:10552`.
- **`scripts/compat-test.sh` now fails closed on a `--test` value that matches nothing, and a compat
  scenario can no longer hand two of its own listeners the same port.**
  The selector compared display names while `--list` printed `run_test` function names, so a name copied
  from `--list` exited 0 with ` RESULTS: 0 passed, 0 failed`; an unmatched name now exits 2 naming the
  selector, prints no summary line, and a name whose phase was skipped is reported separately. The
  protocol matrix's `wait_for_listen` accepted any process's LISTEN socket, so a foreign listener greened
  a row; it now requires the pid the row launched. `random_port()` could return a port an earlier listener
  in the same scenario still held and the readiness probe was a bare connect; each port is now reserved
  for the life of the scenario and readiness verifies the owner, with a 61-check fixture suite (51 when the
  suite landed in round 1, 61 at this head) proving the collisions, the foreign-listener refusal and the hermeticity of its own stub seam.

- **`docs/config.md`'s Go column is now checked row by row against a measured Go frp key set, so a real-but-wrong Go key reds.**
  The gate proved each cell was *a* Go frp v0.71.0 spelling, not that it was *the* spelling for that row: swapping
  `bindPort` for the equally real `quicBindPort` on the `bind_port` row left it green. The expected cell is now recorded for
  every one of the 192 rows (`ROW_GO_PATHS`, keyed by table and field so a line shift cannot silently re-point it), every
  recorded path must exist in the key set, and a row with no entry or an entry with no row reds. The 261-spelling `GO` table
  itself is no longer trusted: it is diffed against a committed, byte-stable derivation artifact
  (`scripts/tests/docs-go-column-go-keys.txt`, 261 = 108 dotted `json` paths + 153 bare field names) whose provenance is the
  `v0.71.0` tag object `40adeed7…` → commit `4a23aa18…`, and a new offline-safe script re-derives it from that tag or from a
  checkout (`--fetch` / `--source`, skipping cleanly when no source is given, failing when an explicit source yields no keys).
  The 41 recorded aliases are resolved — 28 repointed to their true Go `json` paths and 13 recorded in the document as
  extensions whose marker names the spelling the key set proves absent — so the alias table is empty and each resolution is
  checked against the rows that carried it. The page's opening sentence now says what the column actually asserts, and the
  suite grows 204 → **257** checks with two new mutants (M6/M7) covering the mapping and the membership paths.
- **The large-function report now credits a test module whose `#[cfg(test)]` predicate wraps across lines, or whose `#[path]` is packed
  before the gate on the same line.** `scripts/large-functions.sh` located gated regions from a one-line, start-anchored `#[cfg(test)]`
  match, so a `#[cfg(all(` … `test))]` predicate and a `#[path = "x.rs"] #[cfg(test)]` pair were charged to production. Both gate now,
  through a cross-line attribute span whose text is collapsed before the predicate is parsed; a span that would run through a
  multi-line raw string, a line-spanning block comment or a backslash-continued ordinary string is declined and stays production, so no
  production item can be swallowed by the new reach.
  Measured in one tree: the wrapped predicate `10 10 0` → **1 10 9**, the packed shape `3 3 0` (helper `4 4 0`) → **1 3 2** (`0 4 4`).
  An infinite loop in the backward attribute walk — pre-existing (the batch's base commit `5682fe6c` hangs on plain same-line shapes too) and widened by
  the newly gated shapes, with no in-tree trigger — is fixed by forcing the walk to advance. The classifier fixture suite grows 118 → **166** checks, and the step now pins
  `scripts/large-functions.sh` by sha256 beside the classifier, so the script's own regressions move a guard.
- **The large-function report no longer charges a whole file to tests when a `#[cfg(test)]` decorates a `use`, a
  `const` or a `fn`.** `scripts/large-functions.sh` attached such an attribute to the next `mod` anywhere below it,
  so `frp-core/src/bridge.rs` read 4 production lines and `frp-core/src/logging.rs` 737. The region is now the
  attribute plus the item it actually decorates, found by a structural `#[cfg(…)]` locator (depth-counted
  brackets, string/comment aware) whose predicate is parsed — bare `test` gates, `all(…)` gates when any argument
  does, `any(…)` only when every argument does, `not(…)` never — and the region's extent comes from the careful
  string/comment-aware scan, so a brace inside a literal no longer closes a test module early. Measured:
  `frp-core/src/bridge.rs` 4 → **1082** production and `frp-core/src/logging.rs` 737 → **689**; the per-file rows
  move, but the default table's `Largest production functions` section is byte-identical to the base run and the
  name / `mod X;`-sibling rules are unchanged. The fixture suite grows 42 → **118** checks.
- **`docs/config.md`'s "Go frp Equivalent" column is now gated, so a wrong Go spelling reds instead of waiting for a
  reviewer.** A new offline, deterministic fixture suite (`scripts/tests/docs-go-column.sh`, run by the `health` job)
  parses every table whose 4th header cell is `Go frp Equivalent` and requires each row's Go cell to be an exact Go frp
  v0.71.0 spelling, a recorded doc alias, a qualified spelling, an explicit divergence marker, or one of four documented
  non-token shapes — anything else fails. The curated set is 261 Go v0.71.0 spellings (108 dotted JSON paths + 153 bare
  field names) derived from Go frp's `v0.71.0` tag (commit `4a23aa18`), and the 49 rows that legitimately name something
  other than a Go key are recorded with a reason rather than exempted silently. The two known-divergent rows,
  `websocket_port` and `tls_enable`, are pinned by field name and by their "no Go server field" prose, so rewording one
  back into a bare Go spelling reds; five mutation witnesses (one of them the CI canary) prove each check has teeth, and a
  204-check floor reds a run that stops early. Before it existed, breaking row 22 still left `scripts/repo-health.sh`
  reporting `RESULT: invariants hold` — that gate resolves backticked repo paths only and is blind to this column. What the
  new gate does *not* prove (a wrong-but-real Go key in a cell still passes; the alias reasons are recorded, not each
  validated against Go) is filed as residue in `TODO.md`. Closes `TODO.md:7024`.

- **The `compat` compatibility gate stops hiding its own flakes.** Every recorded red run of the `compat` job (3 of the last 100, all `RESULTS: 85 passed, 1 failed`, all left red on attempt 1) failed in a readiness gate that expired 0.5–0.7 s past its deadline, and a red run printed no logs at all: `scripts/compat-test.sh` gated its log dump on `--verbose`, while CI passes neither `--verbose` nor `--keep-tmp` and the EXIT trap deletes `TEST_DIR` immediately afterwards. Readiness timeouts are now floored at `FRP_COMPAT_READY_MIN` (default 20 s; `0` restores the previous per-call values byte for byte) and the dump also runs when `$CI` is set. `scripts/protocol-matrix.sh` compounded its own failures: rows were torn down with SIGTERM only, and the four-port blocks advanced by one port per row, so they overlapped by three and a straggler was read as the next row's own listener — a stale echo could turn a row's readiness probe green against a non-frp server, then make the next real `frps` fail to bind. Rows now drain (SIGTERM → 3 s → SIGKILL → 2 s), use disjoint `19000 + 4 * (PASS + FAIL)` blocks, probe server and proxy ports for a LISTEN socket instead of opening a real connection (the phantom-`ProxyUserConn` hazard `scripts/compat-test.sh:222-224` documents), and always print the failing row's log tails. Verified before/after on this host: 120/120 compat scenario runs and 20/20 full matrix repeats (220 row-runs) green on both sides, with deterministic mutation proofs for each fix (a SIGTERM-ignoring child is now reaped; a Go `frpc` delayed 17 s fails the old gate and passes the new one). The CI red rate itself is unmeasured and the parent item stays open.

- **The Health job's citation-gate literal now tracks this branch's five new test cites (93 at this head).** The three
  test commits added five live `TODO.md` cites across four files (`frp-client/tests/req_work_conn_token_source.rs:6`,
  `frp-server/src/control/login.rs:2945`/`:3153`, `frp-server/tests/login_run_id_and_pool_count.rs:244`,
  `frp-server/tests/http_plugin.rs:293`); `frp-client/tests/heartbeat_wire_order.rs:713` is not one of them — it was
  already a live cite at the base and only moved 1→1. The gate reports 93
  checked cites while the step's declared `guard_cites`/`guard_cites_floor` still said 88 — the exact-match arm never
  fired and the "TODO.md cross-file citation gate" step failed with "did not report 88 checked cites", which running the
  bare script locally had masked. Both literals move to 93 together; the gate script and its `guard_pin` are unchanged.
  93 is the count *at this head*, not an invariant — it was re-measured after the rebase onto `e0ebdc91`, where main's
  literal is 88 again and this branch again measures 93.
- **The re-arm e2e oracle now sees a second consecutive failed ping, so a constant-returning call site can no longer
  pass.** `frp-client/tests/heartbeat_wire_order.rs`'s oracle only ever observed the *first* failed tick, and the
  first re-arm and `PING_FIRST_BACKOFF` are both 2 s — so `let delay = PING_FIRST_BACKOFF;` in
  `frp-client/src/service.rs:3539` stayed green. The fixture now fails exec invocations **#3 and #4** (not #3 and #5:
  the successful ping at #4 clears the streak at `frp-client/src/service.rs:3557`), which is what makes the failures
  consecutive and moves the oracle onto the pinned 2 s → 4 s progression (`Ping#2 − tick#3 ∈ [3000, 5000] ms`, nominal
  4 s). A constant `delay`, or deleting the `ctx.ping_retry_backoff = Some(delay);` write, now reds it (`Ping#2
  arrived 1998 ms` / `2013 ms`), and deleting the `ctx.ping_retry_backoff = None;` reset reds the new `Ping#3 arrived
  8020 ms` assertion (window `[1000, 3000] ms`). Test-only; no user-visible behaviour changes.
- **The NewWorkConn token path is driven end-to-end through the service's own wiring, not the `spawn_work_conn` seam.**
  `frp-client/tests/req_work_conn_token_source.rs` has the mock server answer a `ReqWorkConn` with a `NewWorkConn`
  that carries the raw token from an `exec://` source and no timestamp, over the real `handle_req_work_conn` path, and
  pins the two scope threadings separately: `server_auth_scopes: Vec::new()` at `frp-client/src/service.rs:4225` reds
  only the server-advertised case and `client_auth_scopes: Vec::new()` at `:4224` only the client-declared one, while
  `oidc_client: None` at `:4221` reds both (`read V1 header: early eof`). Test-only; no user-visible behaviour changes.
- **The PR #454 login auth-method ordering invariants are pinned, and where the pre-auth gate sits is now written
  down.** Four new pins in `frp-server/src/control/login.rs` plus one in
  `frp-server/tests/login_run_id_and_pool_count.rs` red on: OIDC dispatch hoisted above the `is_auth_bypass`
  short-circuit; run_id validation moved below `auth_fut.await?` (caught both by the replay-table observable and by
  the wrong-credential one); `drop(used);` moved inside the replay-reject branch, after the write; and a reworded
  `throttled_login_error` detail literal — while `--test login_replay_throttle` stays green under that mutant, so the
  new pin owns the producer that lane does not. Recorded with the pins: the gate's *position* is not observable in any
  response text — the invalid-run_id branch itself calls `throttled_login_error` at
  `frp-server/src/control/login.rs:460`, so an already-throttled IP with an invalid run_id sees the throttled message
  in either order. What flips is the plugin-invocation count in `frp-server/tests/http_plugin.rs`, which now carries a
  doc note that a mutant campaign over `login.rs` must include `--test http_plugin`. Test-only; no user-visible
  behaviour changes (`--test oidc_integration` was not run: it needs an all-features `frps` binary).
- **The `warning-pin` CI guards now witness assertions rather than runs.** The resolver step pins the
  exact `-- --list` entry, uses a variant-free completion marker, and runs the witness a second time with
  `FRP_WARNING_PIN_SABOTAGE=1` requiring that run to fail; both count guards also require the run's own
  `N passed; 0 failed` summary to equal the `-- --list` count, and the removal diagnostics are keyed on
  the marker so a stripped `println!` is reported apart from deleted assertions.
- **Two `frpc` test pitfalls are closed, and the lane that would have caught one of them now runs.** `frpc/tests/warn_delivery.rs` no longer decides a record count from a quiet window: it waits for the child to exit and joins both pipe drains, so the capture is final at EOF, and a duplicate `--config-dir` record emitted 700 ms behind the first — which the previous 500 ms quiet period let pass — now fails the test. `frpc/tests/cli_inputs.rs`'s config-file-named-after-a-subcommand test dropped an assertion that could not tell the child's own admin listener (`frpc admin server starting on 127.0.0.1:<port>`) from a dial, and a count-guarded `tests-unit` step now runs that file with the `admin` feature on.
- **The CLI exit-code pins run in the release profile now.** `cargo test --release -p frps --test cli_exit_codes` used to fail in every release build (`41 passed; 3 failed`) because three pins drive hooks only compiled under `debug_assertions`; they now carry `#[cfg_attr(not(debug_assertions), ignore = "<reason>")]`, and a new `Tests (release profile)` job runs that file in the same release profile the `build` job uses, asserting the exact `41 passed; 0 failed; 3 ignored` summary, the three ignored names, and the 44-test list — so the release lane cannot widen its own skip set, drop a test, or lose the target and still pass.
- **RSS soak harness and a published head-to-head series**: `scripts/rss-soak.sh` runs a 3-hour,
  45-second-interval RSS comparison of frp-rs and Go frp over an identical proxy set and traffic,
  guards its run directory (`scripts/lib/rss-soak-run-dir.sh`), writes a machine-readable summary
  (`scripts/lib/rss-soak-summary.py`), and is covered by a fixture suite
  (`scripts/tests/rss-soak-run-dir.sh`, 269 checks) in the `health` CI job. The first published
  series is `scripts/frp-stress/baselines/rss-soak-Mac.jsonl`; the measured numbers and their
  caveats are recorded in `TODO.md`.
- **Four test-precision residues are closed, and the `frps` dashboard warning pins now witness the
  record bytes rather than a count plus a clause.** `frpc/tests/warn_delivery.rs`'s `drain` returns an
  `io::Result` — EOF only on `Ok(0)`, `ErrorKind::Interrupted` retried, any other read error surfaced as a
  truncated capture instead of being folded into EOF — so a transport error can no longer make a joined
  capture look final. The `frps` dashboard captures share a record extractor that keeps each record's
  terminating newline and byte-pins it, compare the level untrimmed (`" WARN"`), and reject bytes after a
  record that do not begin a fresh `tracing` record, so an appended clause, a renamed target, a bare extra
  newline and an extra following line each red the `frps` lane itself. The `health` job's comment now names
  the three fixture scripts it runs (not two), and the fixture suite no longer carries an unreachable
  empty-root guard; its case-insensitive-volume limit is recorded where the containment check lives.
- **Both fixture suites now fail closed, and the XTCP shard no longer sweeps by argument pattern.**
  `scripts/compat-test.sh`'s XTCP helper reaps through the pid-exact sweep the compat-leak fix added
  (`cleanup_pids` + `reap_scoped_strays`) instead of `pkill -f`, and the stray-guard fixtures read that helper's
  body and drive the sweep against live synthetics. `scripts/tests/repo-health-fixtures.sh` installs a
  `MIN_CHECKS=32` floor trap before its first check and asserts its own substance, and
  `scripts/tests/compat-stray-guard.sh` closed four further ways it could report green while doing less: a failed
  `ps` can no longer forgive a live synthetic, a symlinked invocation can no longer defeat `wait_exec`, an empty
  `ps` is an error rather than "the image changed", and the total is supplemented by an ordered per-scenario shape
  assertion.
- **Every count guard in `ci.yml` asserts an absolute floor now, and two fixture lanes that ran nowhere run and
  count.** The CLI-lane and `health`-fixture count literals were `=`-only, so deleting a test and lowering the
  matching literal stayed green; each now carries a `*_FLOOR` twin (or a `guard_exact`/`guard_floor` pair) that a
  removal has to move deliberately, and keeps the exact count *plus* the run's own `N passed; 0 failed` summary —
  plus a `Running …` witness per target on the lanes where a target can silently compile to zero tests. The full
  `cargo test -p frpc` lane, which counted nothing before, now pins 111 tests across its nine targets;
  `scripts/tests/large-functions-classifier.sh` (42 checks) and `scripts/tests/remote-frps-reap.sh` (37) gained
  pinned `health` steps, and `frp-server`'s `vhost::tests` (61) gained a count guard in the server job. The
  release-profile job gained a second target, `frps/tests/warn_delivery.rs`, which immediately found two tests
  that cannot pass in release (they drive `debug_assertions`-only hooks); they now carry the same
  `cfg_attr(not(debug_assertions), ignore = "…")` shape as the `cli_exit_codes` pins, and the lane pins the
  28-listed / 26-passed / 2-ignored shape by name. A cold `--release --workspace --all-targets` build measured
  35m 55s at `-j 2` — over that job's 30-minute budget — so the decision to cover the pinned targets rather than
  every target is recorded, with the measurement, in the workflow comment. The citation gate's expected count is now
  declared once (`guard_cites` / `guard_cites_floor`) instead of three copies that had gone stale — three copies of
  `84` left `health` red while the gate checked 87 — and the release `cli_exit_codes` lane gained the last missing
  floor, so every count guard in the file now asserts an absolute floor beside its exact count.

## v0.71.0 — re-release (2026-09-13)

Supersedes the 2026-08-16 v0.71.0 build (PR #246 era). Same version number,
per the Go-alignment rule — Go frp has not released a newer number. All
assets re-built and re-published from commit `41c3ad6`.

205 commits, PRs #248–#322: five full code reviews (4 finders + adversarial
verifiers), 18 pre-release hardening rounds, 4-dimension audit rounds 3–5,
plugin-face audit rounds 6–18, 2 data-corruption BLOCKERs, 2 leak-fix
batches, Go frp v0.71.0 divergence closure, yamux vendor patches, dependency
pruning, and +929 tests (1149 → 2078, 0 failed). Version stays aligned at
0.71.0.

### Features
- **SUDP wire protocol v2 + mixed-codec message bridge** (Go frp v0.71.0
  `joinSUDPMessageBridge` parity, PR #248): SUDP work-conn data planes
  negotiate the V2 binary UDP codec (`binary-v1`, frame type 19) per
  session; a mixed-codec bridge relays `UDPPacket` frames between V1 and
  V2 peers so a binary-codec sender can reach a JSON-codec receiver and
  vice versa. Cross-implementation V2 SUDP compat scenarios added.
- **HTTP/HTTPS group load balancing** (Go frp v0.71.0 `HTTPGroupController`
  parity): same-domain HTTP/HTTPS proxies sharing `group`/`group_key`
  distribute requests across group members; dashboard proxy-delete paths
  honor group route ownership.
- **Legacy INI proxy/visitor sections** (PR #250): `[web]`, `[ssh]`,
  `[range:*]`, `[plugin:*]` INI sections load as typed proxies/visitors
  (Go frp INI parity), incl. the `authentication_method` legacy mapping
  (BLOCKER: previously ignored silently) and `webServer` keys after
  `[common]` merge.
- **Control idle watchdog** (PR #276): `CONTROL_IDLE_TIMEOUT` 90s on the
  main control read, active only when `heartbeat_timeout <= 0`
  (Go keepTunnelOpenWorker-style guard); ProgressRead counts decrypted +
  raw wire bytes.
- **Full-matrix A/B throughput gate** (`scripts/ab-matrix.sh` + CI): VPS-
  measured A/B comparisons for data-plane changes, server-side flock
  serialization, SSH keepalive, shared-runner noise filtering.

### Fixes (Go parity & hardening)
- **2 data-corruption BLOCKERs (round 13)**: AEAD `claimed` /
  CipherWriter `first_write_data_len` stashed a mid-frame flush claim
  across polls — a re-poll re-encrypted the same buffer into a duplicate
  frame (multi-chunk `write_all` could loop forever); XTCP raw-KCP HWM-park
  select stored as a struct field (`hwm_wait_fut`) — the old
  select-inside-`poll_write` dropped both wakers on future drop, a
  permanent high-water deadlock with tcp-mux off.
- **yamux lost-wakeup deadlock (vendor patch #2)**: `tokio::io::split`
  read+write halves polled the same `futures::channel::mpsc` Sender,
  violating its one-poller contract — a `poll_read` window update
  overwrote a parked writer's waker and the writer was orphaned forever
  (~7.5% intermittent on the 2 MiB bidirectional byte-exact test). Fixed
  with a dedicated `sender_wu` clone for the read path.
- **yamux stream-cap semantics (round 11, vendor patch #1)**: crates.io
  yamux 0.14 closes the ENTIRE mux session when the stream cap is hit
  (Go frp's fork survives, per-open reject); frp-rs now vendored at
  `vendor/yamux` with per-stream RST on inbound SYN at the 1024-stream
  cap + asymmetric-cap regression test. (An earlier Aug 18 experiment —
  vendoring a batched-build yamux — measured 114 vs 150.1 MB/s and was
  reverted; the round-11 vendored copy uses different patches.)
- **Go frp v0.71.0 audit closures (PRs #249, #252, #253, #260, #272)**:
  strict config whitelists (auth token_source snake_case, camelCase OIDC
  keys, top-level oidc_skip_* flatten), `oidc_token_endpoint_url` server
  alias, strict `subDomainHost`, Go explicit-0 defaults, crypto-less
  ClientHello reject, control-send timeouts, plugin hook ordering parity
  (mutating hook runs BEFORE auth on NewWorkConn, Go service.go parity),
  visitor comment/scope fixes, dashboard_tls_mode no-op documented.
- **15-item code review (PR #260)**: wedge/cipher/splice/metrics/dedup
  fixes across core+server.
- **WS-over-TLS data-plane stall recovery (PR #258)**: wake after partial
  reads (lost-wakeup on the TLS→WS handoff).
- **3 LOW data-path fixes (PR #257)**: single-spawn bridge, lock-free UDP
  liveness, WS server writev.
- **High-leak fixes (PR #267)**: server bridge cancel via per-control
  CancellationToken; KCP dial-driver self-exit via alive-streams counter;
  client work-conn abort + bounded join; XTCP/STCP bridge cancellation on
  teardown and proxy deletion (per-proxy `p2p_bridge_tokens` cancelled by
  CloseProxy/HealthEvent::Close/reload); frpc SIGINT/SIGTERM incl.
  config-dir mode; case-insensitive vhost/tcpmux/SNI routing (Go parity).
- **Pre-release hardening rounds 8-16 (PR #273)**, incl.: h2c slowloris
  handshake+first-accept under one absolute `vhost_http_timeout` deadline
  + `max_header_list_size(4096)` on the server vhost surface; ini
  lone-quote panic (abort under `panic=abort`, startup + reload); login
  backoff shutdown race; header-scan byte-slice panics on multibyte UTF-8
  straddling fixed-offset cuts (4 sites, unauthenticated abort under
  `panic=abort`); Go origin-form/empty-port/CONNECT status-line parity
  (3 oracles flipped in vhost + h2c); h2c origin-form auth split
  (absolute-form → Proxy-Authorization 407, path-form → Authorization
  401); vhost scheme partition (HTTP+HTTPS same-domain both register,
  lookups match scheme — no-auth HTTP can no longer land on the HTTPS
  backend); `keepTunnelOpenWorker` persistent XTCP tunnel session
  (one hole-punched QUIC/yamux session reused across user connections);
  NewWorkConn plugin order; ReplayTable + per-IP login throttle gate
  (pre-auth, invalid-run_id logins consume throttle slots); run_id
  validation on ALL auth paths + `Some("")` normalized to UUID;
  3600s heartbeat clamps REMOVED both sides (Go frpc's 7200 disconnected
  in a reconnect loop vs Rust frps — watchdog overflows degrade to
  never-fire); control-loop half-frame loss (read future persisted in a
  loop-outer Option, deterministic regression test); generation-guarded
  cleanup (`remove_if_control_id` closes a get-then-remove TOCTOU);
  CONNECT routes on request-line authority first (RFC 7230 §5.3);
  PROXY header only when src_addr non-empty AND src_port != 0;
  X-Forwarded-For appended unconditionally + preserved in
  https2http/https2https; WS control frames masked client-side
  (RFC 6455 §5.3) + protocol errors on FIN=0 / 126-127 encodings /
  stray continuations; static_file 64 KiB streaming (was `read_to_end`
  truncated at 64 MiB with a lying Content-Length); vnet default-net
  membership null normalization + 64-route per-client cap + route
  advertise membership guard + `/2` prefix-split bypass fixed
  (threshold `len <= 6`); `udp_packet_size` clamp [0, 65507];
  negative poolCount → config error at load (fail-fast, documented
  divergence); KCP hostile-ACK RTT clamped to KCP_RTO_MAX (u32 overflow
  = one-packet session kill); mux `MAX_PENDING_OPEN_REQUESTS=64` +
  driver drain cap; yamux per-stream receive-window cap + send-side
  body-buffer pool (ArrayQueue cap 16); heartbeat clamp 3600s→removed;
  TLS connector-key cache carries (mtime, size) stamps (certbot in-place
  rotation re-detected); snappy CRC32C verified on decompress;
  `--config-dir` symlink-cycle guard (stack overflow SIGSEGV under
  `panic=abort`); INI range expansion cap 4096; levenshtein skipped for
  >256-char keys; unknown visitor types rejected at load; token-exec
  bounded 10s both arms; ssh_gateway bridge head+payload reads bounded
  30s; vnet >MTU pre-reject + rate-limited warnings; h2c declared-
  Content-Length enforcement (excess body → RST_STREAM PROTOCOL_ERROR —
  request smuggling closed); vendor yamux patch #4: O(1)
  `outbound_unacked` counter replaces per-frame ack_backlog scans.
- **Round-17/18 review fixes (PR #276)**: vnet prefix-split bypass (S2,
  threshold `len <= 1` → `len <= 6`, 64×/6 covers 2^32 v4 / 2^128 v6,
  legal prefixes ≥/8 unaffected — nathole + frp-client vnet both sides);
  `write_v1_frame` vectored partial progress (TrickleWriter, byte-exact)
  + zero-write loop guard (ZeroWriter); client proxy cap + custom-domain
  cap rejected at handler level + `user_conn_sem` permit on listener side
  (M5 mirror); yamux outbound refuses at the production 256 boundary and
  survives (old CAP=4 test bypassed ACK-backlog=256 collision); mid-stall
  completed frame resets reaper timer; socks5 handshake under one 60s
  absolute deadline (handler released, paused-time pin); group
  create-bind-race timing fix for slow CI; rustc 1.96 clippy
  `-D warnings` compat.

### Performance
- **KCP**: chunk pool (lock-free ArrayQueue cap 8, socket/session/
  listener shared — `write()` pop+clear+extend replaces `buf.to_vec()`);
  `snd_data_pool` freelist (cap 64, ACKed segments recycle data);
  single-copy send segmentation (offset walk, no `split_off` tail chain —
  every byte copied exactly once); batch user→work compressed flushes;
  skip pool-miss memset.
- **Snappy**: zero-copy compress/decompress hot paths, CRC-32C
  slice-by-8, buffer reuse (zero alloc per bridge iteration).
- **Bridge**: pool-backed `PoolGuard` buffers, dead-buffer gating,
  enlarged splice(2) pipe (Linux zero-copy relay).
- **V2 frames**: single `writev` frame write + zero-alloc binary UDP
  encode (PR #263).
- **CFB cipher**: u128 XOR block path (~16x encrypt throughput, from the
  PR #260 review cycle).

### Tests
- **1149 → 2078 (+929, 0 failed)**: round-9 test-gap filling alone added
  114 (incl. yamux work-conn auth-chain e2e regression for the round-8
  auth-bypass fix, login replay × throttle interaction, h2c preface
  determinism, pool replenishment, relay integrity); rounds 13-18 added
  login retry cadence, yamux RST wire shape, reload virtual_net survival,
  in-process Rust↔Rust KCP/QUIC e2e, 2 MiB bidirectional byte-exact +
  window-exhaustion stall, kcp 512 KiB volume, raw-KCP HWM recover,
  SNI no-hijack, tcpmux negative-window, h2c 431/407/slow-drip, CONNECT
  9-case Go matrix, multibyte panic-proof header scans, cross-instance
  TCP auto-assign port flake (flock-serialized `allocate_port()`).
- **Protocol matrix**: 11/11 rows green (tcp/ws/wss/kcp/quic × tls ×
  tcp_mux).
- **Cross-compat**: 86/86 vs Go frp v0.71.0 + 17 XTCP pairwise
  (re-verified 2026-08-30).

### CI & Tooling
- **Stress workflow repair (PRs #274/#275)**: 3 stacked breakages —
  duplicate `[profile.release]` TOML key (9 consecutive weekly reds),
  proxy pointed at ssh port 22 instead of the echo backend, memory
  scenario mode collision (`--mode` shared by latency/memory). All
  scenarios validated locally: 6/6 PASS, 283 MB/s real echo data.
- **ab-matrix**: private temp dir, REF worktree cleanup, macOS Bash 3.2
  compat, VPS-side flock, confirm-retry noise filter.
- **CI gate repair (round 16)**: tiny/micro feature-set builds restored
  (missing `MAX_HOLE_PUNCH_TIMEOUT_MS` stub in the no-kcp xtcp_p2p
  stub); Dockerfile `|| true` scoped to strip only (zigbuild/cp failures
  loud again); tests job timeout 25 → 35 min; check job split into
  lint/tests/verify lanes; rust 1.97/1.98 clippy fixes.

### Dependencies
- `cargo update` (latest patch/minor pins, PR #261).
- **yamux** → vendored at `vendor/yamux` (`[patch.crates-io]`) with 4
  patches: per-stream RST at cap, lost-wakeup `sender_wu`, receive-window
  cap, body-buffer pool + O(1) outbound_unacked.
- Removed as direct deps (banned): `hex`, `data-encoding`, `base64`,
  `lazy_static`, `sha2`, `aes-gcm`, `hkdf`, `hickory-resolver`,
  `aws-lc-rs`, `hmac`, `tokio-tungstenite` (manual RFC 6455 framing).
- **rand 0.8 → 0.10** (PR #279): unified with russh's rand; `OsRng` →
  `SysRng`/`TryRng`, `thread_rng` → `rng`, `Rng` → `RngExt`. rand 0.8.7
  remains in the lock only via the opt-in otel chain
  (opentelemetry_sdk → tonic → tower, third-party pins).

### Docs
- Full sync to post-0.71.0 state (PRs #277/#278): CHANGELOG, README,
  CLAUDE.md Current Health + round 17/18 history, developing.md dep
  tables; optional UPX compression section added to deployment.md
  (measured, not recommended by default).
- **Documentation restructure**: `CLAUDE.md` was 143 KB with 76% of it a
  single-line round-history table, so it exceeded its 64 KB agent-instruction
  budget and was silently truncated on load. The history moved verbatim to
  `docs/history/development-log.md` and the architecture chapters to
  `docs/architecture.md` (no content removed); `CLAUDE.md` is now a ~20 KB
  rules-and-invariants file with a scope table and a "do not append history
  here" rule. Added `docs/README.md` (docs index, marks `docs/superpowers/`
  as archived artifacts), documented the three vendored crates' exit
  conditions in the new README "Vendored crates" section, and added the
  missing `vendor/rustls/README-FRP-RS.md` for the TLS SNI patch.
- **Archive rename**: `docs/superpowers/` → `docs/archive/`, so 81 dated
  plan/spec/note/audit artifacts (1.7 MB) are marked as historical by their
  path instead of only by a note in `docs/README.md`. All links into the
  archive from live docs were updated; paths *inside* the archived documents
  were deliberately left as written (they are historical records), and
  `docs/archive/README.md` documents the translation.

### Post-#279: 4-dimension audit rounds 3–5 + plugin-face rounds 6–18
- **4-dimension audit round 3 (PR #284)**: per-proxy `SharedBandwidthLimiter`
  (Go parity — single bucket shared bidirectionally and across concurrent
  connections); vhost forwarded-header injection (X-Forwarded-Host/Proto +
  XFF chaining, request-header overrides after forwarded); UDP session idle
  timeout 60s→30s; TCP group param-mismatch rejection (Go `ErrGroup*` text);
  unknown multiplexer rejection; SSH gateway per-IP login throttle
  (Rust-only hardening); OIDC jti replay precheck moved before `verify_login`.
- **4-dimension audit round 4 (PR #288)**: tcpmux group fan-out teardown order;
  vnet NewProxy admission + route-cap enforcement at registration; reload
  `config_snapshot` covers all 9 NewProxy wire fields (deterministic
  BTreeMap/serde_json ordering); socks5 auth AND→OR (Go parity); XFF real
  tunnel peer (`real_tunnel_peer_map`, https2http/https2https only);
  dashboard/admin field redaction; nathole clamps.
- **4-dimension audit round 5 (PR #290)**: 52 CONFIRMED findings in 4 waves —
  vhost/vhost_h2c deadline clamp (hostile `<=0`/`u64::MAX` no longer
  `panic=abort`; 60s floor + 24h cap) + OIDC `sanitize_expires_in`; client
  control-loop half-frame mirror of the round-14 server fix; dashboard DELETE
  vs CloseProxy double-decrement race; SSH gateway exec_request + Go
  `createSuccessInfo` banner + pflag-style parser; Go port-error text parity
  (`PortError` enum); UDP work-conn keepalive 30s; health probe origin-form +
  ≤10 redirect hops; `PluginPeerGuard` paired cleanup; UDP session table 1024
  cap (documented divergence); `/api/serverinfo` Go 18-key camelCase; KCP
  read-side buffer pool; configured XFF single-line canonical; prom
  `LAST_TRAFFIC` stale-baseline fix; tcpmux `extract_proxy_auth` verbatim;
  XFF registry guard lifecycle hoist; `xtcp_pair_e2e` (first frp-client
  service-layer XTCP e2e).
- **Plugin-face audit rounds 6–18 (PRs #292–#322)**: Go conn.readRequest
  ladder, textproto head-end semantics, injector terminal drain +
  declared-body discard, h2c no-body/404 family, absolute response-head
  parsing, vhost X-Forwarded strip parity, http-leg nil dst parity, SSH
  throttle deny, work-conn auth, KCP FEC panic fix, https-group SNI fan-out,
  plugin readLimit/505/escape/static_file hardening, h2 egress + vhost
  head-validation Go parity.
- **`tcp_mux_keepalive_timeout` (PR #319)**: tune/disable the yamux
  dead-session reaper.

### Dependencies (post-#279)
- russh dead features dropped (ssh-key encryption/ppk, pkcs8/scrypt/salsa20/
  sha3); RustCrypto generation unified; tracing-subscriber env-filter removed
  (drops matchers/regex); rand 0.8 → 0.10 unified with russh.

### CI & Tooling (post-#279)
- tests job split into unit / server / client lanes (#320); protocol-matrix
  runner-contention hardening; TCP auto-assign port-flake elimination.

## v0.71.0 (2026-08-16)

### Features
- **UDP packet binary codec (Go frp v0.71.0 parity)**: under wire protocol
  v2, `UDPPacket` payloads now use a compact binary codec (`binary-v1`,
  frame type 19) when negotiated via the V2 handshake's `udpPacketCodecs`
  capability — mirroring Go frp v0.71.0 (`pkg/msg/udp_binary.go`). V1 stays
  JSON; V2 falls back to JSON `UDPPacket` (type 13) when the peer did not
  negotiate the capability. Codec lives in `frp-core/src/udp_binary.rs`
  (IPv4/IPv6+zone addresses, 65507-byte payload cap, strict validation);
  negotiation in `v2_handshake.rs`; the V2 UDP/SUDP work-conn data planes
  select the codec per session (`read_msg_v2_with_udp_codec` /
  `write_msg_v2_with_udp_codec`). Cross-verified both directions against the
  Go frp v0.71.0 pre-built binary.
- **Version alignment**: frp-rs now tracks Go frp **v0.71.0** (all crates
  `0.71.0`, `frp-core::VERSION`, download script default, README/CLAUDE.md).
- The Rust-only V2 extension message types were renumbered **19/20 → 21/22**
  to stay clear of Go frp v0.71.0's new `V2TypeUDPPacketBinary` (19).

### Fixes
- **Negative `pool_count` rejected at login** (Go frp v0.71.0 server DoS
  fix): a client sending a negative pool_count is now rejected before
  work-connection pool resources are allocated (previously clamped to 1).
- **Case-insensitive `customDomains` vs `subDomainHost` check** (Go frp
  v0.71.0 validation fix): mixed-case domains under the configured
  subDomainHost can no longer bypass the conflict check.
- **`run_id` validation at login** (Go frp v0.71.0 `ValidateRunID` parity):
  client-supplied run ids longer than 64 bytes or with control characters
  are rejected; a missing run_id still falls back to a generated UUID.
- **plugin_h2 https2https flaky test**: the test's TLS capture backend now
  closes with an explicit `tls.shutdown()` instead of dropping the
  TlsStream (tokio-rustls buffers plaintext on the write side; dropping
  after `flush()` could leave the peer reading a bare FIN without
  close_notify, producing ~50% spurious 502s).
- **SUDP under wire protocol v2** (Go frp v0.71.0 `joinSUDPMessageBridge`
  parity): the SUDP visitor data plane now speaks the negotiated wire
  protocol (V2 magic + `binary-v1` codec) instead of being hard-coded to
  V1/JSON. When the visitor and provider segments negotiate different
  packet encodings (e.g. a V1/JSON visitor talking to a V2/binary provider
  during an upgrade), the server routes the pair through a message-level
  bridge that decodes and re-encodes every `UDPPacket` per side; identical
  encodings keep the zero-copy byte-stream relay. Previously a V2 provider
  misparsed the V1 visitor's frames ("unexpected V2 frame type"), breaking
  the tunnel.
- **HTTP/HTTPS group load balancing** (Go frp v0.71.0
  `HTTPGroupController` parity): http/https proxies sharing the same
  `group`/`groupKey` and domain now register one shared vhost route and
  dispatch requests round-robin across the members (previously the second
  member was rejected with a vhost route conflict). groupKey mismatches
  and routing-param mismatches are rejected (Go `ErrGroupAuthFailed` /
  `ErrGroupParamsInvalid`). Members may live on different frpc controls.
  TCP-group load balancing is unaffected (its group LB is restricted to
  tcp proxies — http groups are selected by the vhost router).

### Changed
- **Health-checked proxies register only after the first healthy probe**
  (Go frp `proxy_wrapper` parity): a proxy with `health_check_type`
  configured is no longer registered immediately at startup — the client
  waits until the first successful health check (or a subsequent recovery)
  before sending `NewProxy`. A persistently-unhealthy proxy therefore never
  registers. Previously the proxy registered immediately and was only
  unregistered after `max_failed` consecutive failures.

### Changed
- **TCP keepalive defaults aligned with Go frp**: `dial_server_keepalive`
  and `transport.tcpKeepalive` now default to **7200s** (was 300s). Dead-peer
  fd release now follows the OS/Go cadence instead of the former aggressive
  300s idle probe.
- **XTCP visitor `protocol` defaults to `quic`** (Go frp v0.70.1 parity;
  was `kcp`). Explicitly configured `protocol = "kcp"` is unchanged.
- **`bandwidthLimit` parsing now matches Go `types.BandwidthQuantity`**:
  the `KB`/`MB` suffix is case-sensitive (`kb`/`mb` rejected), and a `0` or
  negative value means no limit (previously rejected).
- **Legacy INI keys**: `authenticate_heartbeats`/`authenticate_new_work_conns`
  → `[auth] additional_scopes`, `http_proxy` → `[transport] proxy_url`,
  `disable_log_color` → `[log] disable_print_color`, server `pprof_enable`,
  `dashboard_tls_mode` (no-op — frp-rs drives dashboard TLS from non-empty
  cert/key; the key is accepted and consumed to keep strict mode green),
  `oidc_additional_*` → `[auth.oidc] additional_endpoint_params`.

### Compatibility
- `compat-test.sh` now targets the **Go frp v0.71.0** pre-built binaries by
  default (was 0.70.1); full cross-compat suite green (77 scenarios).

## v0.70.1 (2026-08-11)

### Features
- **UDP bandwidth limiting (frp-rs extension)**: `bandwidthLimit` /
  `bandwidthLimitMode` now throttle the UDP data plane (`proxy_type = "udp"`,
  incl. the SUDP provider side) with the same direction semantics as the TCP
  bridge — "server" applies a two-direction limiter on frps, "client" limits
  upload on frpc, "both"/empty apply both on the client (server does not
  recognize "both", same as TCP). Default stays
  unlimited: a limiter is only instantiated when a rate is explicitly
  configured. Go frp v0.70.1's UDP forwarder has no limiter, so this is a
  deliberate frp-rs lead over Go. E2e coverage in
  `frp-client/tests/udp_bandwidth.rs` (unlimited default + server-mode
  throttling).

### Performance
- **TCP keepalive hardening**: `dial_server_keepalive` / `tcp_keepalive`
  default to **300s** (Go frp's 7200 is deliberately not followed), and
  `set_keepalive` additionally sets a short probe interval (`secs/10`,
  clamped 1-60s) + 3 retries so dead peers release fds in minutes instead
  of hours. Client dial path now uses the same `set_keepalive` (probe
  hardening on both sides; failures debug-logged, matching `set_nodelay`).
- **`[profile.release-perf]`**: same LTO/strip/abort discipline as
  `release` with `opt-level = 3` for the hot data plane
  (`cargo build --profile release-perf`).
- **Plugin relay**: visitor plugin relays via a `Duplex` (recombined
  split halves) + `copy_bidirectional_with_sizes`; `copy_stream_large`
  uses a 32 KiB buffered copy.
- **Client control writer lock-free funnel (P1, audit A1)**: control messages
  are no longer serialized behind a `Mutex<BoxedWriteHalf>` held across
  `write_msg().await`. A new `ControlWriter` funnels every control message
  (Ping / NewProxy / CloseProxy / NatHole* / reload / vnet routes) through a
  bounded mpsc channel to a single dedicated writer task — producers never
  block on a slow peer, ordering is FIFO, and a write failure wakes the
  control loop to reconnect. `frp-core::ControlSink` trait lets `frp-vnet`
  emit control messages without depending on the concrete write half.
- **HTTP client CONNECT tunnels use 32 KiB buffers (P3, audit A5)** (test
  paths; production CONNECT rides hyper's internal connector).

### Security & Robustness
- **`max_connections` docs corrected (P2, audit A2)**: the default was
  already bounded (`None` → 512); the stale "default (10000)" doc is fixed.
- **`h2` moved to a dedicated `http2http` feature (P2, audit A3)**: the
  frp-client `tls` feature no longer drags `h2`/`indexmap`/`hashbrown`/`fnv`
  into tiny builds (`http2http` implies `tls`; default features unchanged).
  Verified: `h2` absent from the tiny dependency tree.
- **Dead `ring` direct dep removed from frp-server (P2, audit A4)**: zero
  `ring::` uses in the crate (rustls pulls it transitively where needed).
- **`http_client.rs` missing SAFETY comment added (P4, audit A8)**.
- **Login-throttle nested lock removed (MEDIUM, audit 3.1)**: `check_login_throttle`
  now drops the main-table guard before acquiring the overflow lock — the nested
  acquisition was safe but fragile to future refactoring.
- **nathole.rs error discards commented (MEDIUM, audit 4.1)**: all 12
  `let _ = write_ctl_msg(...)` sites now carry a comment explaining why the
  write failure is non-recoverable (client rejected / accept-loop writer
  broken), closing the last gap in the "all discards commented" rule.
- **Proxy-listener bind retries EADDRINUSE (MEDIUM, audit 4.2)**: on
  supersession the old handler's abort does not wait for socket release, so
  the new handler now retries the bind 3× with 100ms backoff instead of
  failing once and relying on the next client reconnect.
- **UDP work-conn keepalive honors config (MEDIUM, audit 2.2)**: the
  application-level Ping interval was hardcoded at 30s; it now uses
  `transport.keepalive` (0 keeps the 30s default).
- **WebSocket pong uses a 128-byte stack buffer (LOW, audit 1.2)**: per-frame
  heap alloc removed from the control-frame path (RFC 6455 caps control
  payloads at 125 bytes).
- **KcpListener driver JoinHandle stored (LOW, audit 2.3)**: the listener's
  UDP event-loop task is now held on the struct and aborted on drop. The
  dial-path driver is deliberately NOT aborted on stream drop — dial returns
  before the KCP handshake completes, and aborting would kill the connection
  before its first probe (verified: broke dial→accept in kcp.rs).
- **OIDC JWKS background refresh is cancellable (LOW, audit 2.4)**: the
  refresh task's JoinHandle is stored on the verifier; new
  `stop_background_refresh()` aborts it.
- **`futures-util` `sink` feature dropped (LOW, audit 5.3)**: zero uses of
  `Sink`/`SinkExt`; saves the sink machinery from every build.
- **`strip = true` release profile (LOW, audit 5.4)**: removes debuginfo
  sections too (was `strip = "symbols"`).
- **`criterion` moved out of workspace deps (LOW, audit 5.5)**: declared
  per-crate in dev-dependencies (frp-core, frp-server).
- **`pending_requests` bounded queue (MEDIUM, audit round 5)**: within the 10s
  expiry window a burst of user connections with no work conns could pile up live
  sockets; the queue now caps at 256 entries and evicts the oldest (closing that
  user connection) instead of holding fds until expiry.
- **Bridge-task panic logging (MEDIUM, audit round 5)**: TCP/UDP bridge tasks
  were spawned fire-and-forget with the JoinHandle dropped, so a panic was
  silently swallowed by Tokio (the RAII `ConnGuard` still released the slot).
  The JoinHandles are now awaited and panics logged with proxy name + payload.
- **`h2` gated behind `http-proxy` (MEDIUM, audit round 5)**: `vhost_h2c.rs` and
  the `h2` dependency tree (indexmap/hashbrown/fnv) were compiled into every
  binary including micro/tiny builds that never serve vhosts. `h2` is now
  optional and `vhost_h2c` is `#[cfg(feature = "http-proxy")]`; the h2c preface
  detection block is gated likewise. Verified: `h2` absent from the micro
  dependency tree (0 occurrences vs 1 in default).
- **XTCP probe decode integer overflow fixed (HIGH, audit H1)**: `decode_detect_msg`
  computed `9 + json_len` from an attacker-controlled network length field; a
  `u64::MAX` value wrapped (release build) past the length check and panicked on the
  `frame[9..8]` slice. Now `checked_add` rejects overflow before slicing.
- **SIGTERM graceful shutdown (HIGH, audit H2)**: `tokio::signal::ctrl_c()` only
  catches SIGINT — `docker stop`/`systemctl stop`/`kill` (SIGTERM) killed frps
  instantly and the drain phase never ran. frps now listens for SIGTERM on Unix
  (separate `#[cfg]` blocks for the select); frpc gained a `request_stop()` channel
  + SIGTERM handler mirroring the reload pattern.
- **Bridge/plugin/vhost error visibility (HIGH, audits H3/H4/H5)**: I/O errors
  previously swallowed by `let _ =` in `frp-core/src/bridge.rs`, all
  `frp-client/src/plugin/*` relays, and HTTP error-response writes in
  `tcpmux.rs`/`vhost.rs` are now logged at debug level (no behavior change).
- **XTCP fallback + HTTP plugin panic removal (HIGH, audits H6/H7)**: visitor STCP
  fallback no longer `.expect()`s a moved `Option`; the HTTP plugin manager degrades
  to `None` client (notify skipped) instead of panicking when client build fails.
- **SO_KEEPALIVE on six accept paths (HIGH, audit H8)**: `ssh_gateway`, vhost
  HTTP/HTTPS, tcpmux, per-proxy TCP listener and TCP-group listener now set
  keepalive alongside nodelay, so dead clients release fds/tasks/semaphore permits
  within `tcpKeepalive` instead of ~2h.
- **VHost/tcpmux connection limits (HIGH, audit H9)**: vhost HTTP/HTTPS and tcpmux
  accept loops now enforce `maxConnsPerProxy`-style `conn_semaphore` + the shared
  accept rate limiter (permit released before the rate-limit sleep).
- **frpc heartbeat watchdog event-driven (HIGH, audit H10)**: replaced 1s polling
  with `sleep(hb_timeout_dur.saturating_sub(last_pong.elapsed()))`.
- **Stale control-entry reaper (HIGH, audit H11)**: 60s sweep removes
  `run_id_to_ctl_tx` entries whose receiver was dropped without
  `unregister_control` (handler panic), using DashMap `remove_if` with a
  generation check so a superseding control is never removed.
- **`proxy_manager.proxies` migrated to DashMap (HIGH, audit H12)**: the global
  `RwLock<HashMap>` read lock on every work-conn dispatch is gone; `is_responsive`
  now constant-true (DashMap has no global lock to probe).
- **Lock-free accept rate limiter (HIGH, audit H13)**: `RateLimiter` is now an
  `AtomicU64` fixed-point token bucket (ms-resolution wrapping timestamps, CAS
  loop) instead of a shared `Mutex`.
- **frp-vnet drops serde from production deps (HIGH, audit H14)**: `serde`/
  `serde_json` moved to dev-dependencies (tests only).

  `handle_new_proxy` held `used_ports.write()` across
  `handle_tcp_group_member_registration`, which writes the same
  `tokio::sync::RwLock` again (non-reentrant) — a TCP-group name conflict or
  dashboard-delete race hung the control select loop forever. The write lock
  is now scoped to the insert.
- **Per-proxy user-connection cap (audit D2-2)**: new server config
  `maxConnsPerProxy` (default 0 = unlimited, Go parity). When set, a
  `Semaphore` permit is acquired per user connection and held for the
  connection's full lifetime (via `PendingRequest`), bounding floods that
  previously grew `pending_requests` + fds without limit.
- Pending-request expiry is now **timer-driven** (audit D2-1): with
  `tcp_mux` on (default) the select had no timer arm, so a silent client
  could pin pending-request entries + user fds indefinitely. A
  `sleep_until(earliest deadline)` branch wakes the select; loop-top does
  the cleanup.
- `run_id_to_ctl_tx` switched from `RwLock<HashMap>` to **`DashMap`**
  (audit D3-3) — every work-conn dispatch previously took the global read
  lock; DashMap reads are lock-free per shard.
- TLS connector cache: `Mutex` → `RwLock` (audit D3-4) — concurrent TLS
  dials no longer serialize on the cache-hit path.
- Splice(2) relay failures now log at `warn` (audit D1-10); a fallback copy
  is not possible because splice consumes the streams (partially-moved
  bytes would be lost).
- Bridge tasks now select against the server shutdown token (audit D2-4):
  graceful shutdown interrupts half-open idle bridges instead of waiting on
  2h TCP keepalive.

### Performance
- UDP data plane per-packet allocations removed (audits D1-4/D1-5): server
  relay reuses a spare `Vec` for packet content (allocation removed, memcpy
  stays); client relay pre-parses the loop-invariant local `UdpAddr` once
  instead of re-parsing the address string per packet.

### Fixes
- Dead code removed: pooled work-conn idle-expiry branch (audit D2-3,
  `idle_timeout` is never configured — Go parity keeps pooled conns alive);
  the `pooled_at` field it used.
- `login_throttle`/replay-table doc comment corrected (audit D3-5): cleanup
  is an O(n) `retain` (two precision domains), not the claimed
  `BTreeMap::split_off`; bounded by 100k total / 100 per timestamp.
- 24h port-reservation lookup no longer runs the blocking bind probe under
  the `port_reservations` write lock (audit D3-6).
- Doc figures corrected: local/CI builds with `lto=false opt-level=2` come
  out **~70% larger** (9.1MB vs 5.3MB), not ~40% (audit D5-2).

### Dependencies
- **`cargo update` (2026-08-10)**: 16 patch-level upgrades, lockfile-only
  (no code changes) — async-trait 0.1.91→0.1.92, cc 1.4.0→1.4.2,
  clap 4.6.5→4.6.6, thiserror 2.0.19→2.0.20, wasm-bindgen 0.2.126→0.2.127
  (+ macro/macro-support/shared, futures), web-sys 0.3.103→0.3.104,
  js-sys 0.3.103→0.3.104, zerocopy 0.8.55→0.8.56, find-msvc-tools
  0.1.9→0.1.10. Verified: workspace tests 928 passed / 0 failed,
  clippy `-D warnings` and fmt clean.

### Changed
- **frpc `admin` is now opt-in** (was in the default feature set): build with
  `--features admin` to include the axum-based admin API (~0.5 MB smaller
  default frpc). `frpc reload`/`status` require a running frpc built with
  `admin` and `web_server.port > 0`.
- WebSocket transport no longer links `tokio-tungstenite`: the tungstenite
  variant had no callers (all paths use the manual RFC 6455 upgrade); the
  dependency and its dead code were removed.
- Local `.cargo/config.toml` release override (`lto=false opt-level=2`)
  removed — local `cargo build --release` uses the declared profile
  (fat-LTO + opt-level=z). CI still writes the override on runners for speed.

### Performance
- WebSocket raw path: per-frame payload allocation replaced with a reused
  per-connection buffer; frame building writes into a reused `write_buf` (no
  per-chunk alloc on the bridge hot path).
- Bridge buffer pool: `std::sync::Mutex` → lock-free `crossbeam-queue`
  `ArrayQueue`; pool cap raised 32 → 128 (env `FRP_BRIDGE_POOL_MAX`, cap
  4096). Pre-sized compression/decompression buffers.
- UDP proxy: session table sharded 8 ways (per-remote locks instead of one
  global mutex per packet).
- TCP port allocation: OS bind probe moved out of the `used_ports` write
  lock (three-phase pick/probe/commit) — registrations no longer serialize
  behind socket-bind latency.

### Fixes
- **KCP fast-retransmit deadlock (reliability)**: the fast-retransmit branch
  no longer carries the C-kcp `xmit <= fastlimit` cap (kcp-go v5.6.13 has no
  such cap). Combined with kcp-go's branch order (fast → early → RTO), the
  cap could permanently wedge a segment: `fastack >= resent` but
  `xmit > fastlimit` entered the branch without sending, and the else-if
  chain then skipped the RTO fallback — the segment was never retransmitted
  and the connection froze under sustained packet loss (surfaced by the
  `link_massive_loss_fast` KCP test failing CI's convergence guard ~1/50
  runs). Retransmission now matches kcp-go v5.6.13 exactly; the dead
  `fastlimit` field and `KCP_FASTACK_LIMIT` const were removed.
- `webpki-roots` bumped to 1.0 (drops the 0.26 shim layer).
- `frp-vnet` controller: poisoned-lock `.unwrap()` unified to recovery.
- `mem_profile.rs`: added `// SAFETY:` documentation for the `GlobalAlloc` impl.

- **OIDC `proxyUrl` supported (Go frp parity)**: `auth.oidcProxyUrl` on
  server and client now routes OIDC HTTP requests (well-known config, JWKS,
  token endpoint) through an HTTP CONNECT or SOCKS5 proxy — previously the
  config parsed but the verifier/client rejected non-empty values at
  startup. The OIDC HTTP client's hyper connector was rewritten to dial
  through `transport::connect_via_proxy` (same proxy path as frpc↔frps
  connections) when configured; direct connections are unchanged. Adds a
  `tower-service` optional dependency (already in the tree via axum/hyper,
  zero size) and end-to-end HTTP-CONNECT and HTTPS-in-tunnel proxy tests.

- **Dashboard `assetsDir` served (Go frp parity)**: when `web_server.assetsDir`
  is set and contains an `index.html`, the dashboard root serves that custom
  page instead of the built-in one; missing/unreadable file falls back to
  the built-in page with a warning. Previously the config parsed but was
  never used.

- **UDP proxy per-remote sessions (Go frp parity)**: each distinct remote
  visitor now gets its own ephemeral local UDP socket (bound on the local
  IP), so the local service sees a different source address per remote and
  replies to the right one — the old single shared socket + single
  `last_remote` misrouted responses when multiple remotes were active
  concurrently. PROXY protocol headers are prepended per remote session
  (first packet), idle sessions are reaped after 60 s, and the session
  aggregation keeps a single work-conn writer. The session-scoped shared
  socket map (`udp_sockets`/`udp_enc_cfg`) and its reload-rebind logic are
  gone — reload changes to local_addr/encryption apply on the next work conn
  naturally.

- **Audit round fixes (2026-08)**: full review-driven hardening across
  frp-core / frp-server / frp-client —

  - *Reliability*: supersession handoff barrier can no longer hang forever
    (old handler always extracts a queued `Shutdown`'s `done` on exit; the
    new login's barrier has a 10 s defense-in-depth timeout); idle STCP/XTCP
    visitor listeners are force-aborted after a 500 ms grace period so their
    bind ports are released on reconnect/reload instead of failing with
    AddrInUse forever; XTCP pre_check timeout cut 15 s → 1 s; reconnect
    backoff resets after a ≥5 min healthy session; plugin restart failure on
    reload now aborts the reload (old plugin keeps running) instead of
    silently killing the old plugin and falling back to a dead address;
    CloseProxy during reload uses the original registered wire name
    (changing `user` no longer orphans the server-side proxy); health-check
    events use `try_send` so a reconnecting control loop cannot stall
    probing.
  - *Security*: `authenticationTimeout` default is now 90 s (replay
    protection on by default; set `authenticationTimeout = 0` to restore Go
    behaviour); timestamp freshness accepts seconds or milliseconds (frpc now
    sends ms so same-second reconnects don't false-positive replay
    detection) and uses saturating arithmetic (no debug-build panic on
    attacker-controlled timestamps); replay-detection table has a global
    entry cap and prunes both ms and s keys; STCP/XTCP proxies with no `sk`
    and no visitor authorization warn loudly per connection (Go frp parity
    preserved), and token verification now precedes the freshness check (no
    probing the timestamp window unauthenticated); SSH gateway fails closed
    at startup without credentials unless `allowNoneAuth = true`; frpc admin
    API refuses to bind a non-loopback address without admin auth;
    custom_domains/subdomain validation (RFC 1123 labels, no wildcards, no
    control chars, proxy_name rejects CR/LF); vhost request-header injection
    and HTTP plugin header CR/LF filtering; vhost headers over 4096 B get a
    431 response instead of a truncated forward; login throttle table falls
    back to allowing untracked IPs when full (no 90 s DoS of new clients);
    QUIC default max_incoming_streams 100 000 → 4096; `store.rs` re-applies
    0600 after atomic rename; TLS/QUIC InsecureSkipVerify upgraded to a loud
    error log.
  - *Performance*: KCP send path takes ownership of the buffer and segments
    via `Vec::split_off` (one copy instead of one per MSS fragment); ACK
    parsing fast path (O(1) `pop_front` for in-order ACKs); the KCP driver no
    longer blocks on `send_to().await` — `try_send_to` with a bounded pending
    queue drained on the 10 ms tick; WebSocket masking is u32-chunked;
    yamux stream accept uses `try_send` with a 500 ms bounded fallback
    instead of a 5 s stall; dashboard proxy deletion now reuses the full
    CloseProxy lifecycle (TCP-group last-member semantics, per-client port
    quota decrement, group listener stop); mux/splice/backoff cleanups.

- **UDP proxy zero-alloc data path**: per-packet encrypt/decrypt/compress/
  decompress now reuse session-scoped scratch buffers (frp-core `*_into`
  variants, byte-identical wire output) instead of allocating up to 4 Vecs
  per packet; snap's FrameEncoder/Decoder stay per-packet because UDP
  packets are independent snappy streams on the Go wire.
- **TLS client connector cached** per (path, mtime): every dial previously
  re-read + re-parsed the PEM files and rebuilt the rustls verifier; the
  last connector is now shared (Arc) until a CA/cert file changes.
- **XTCP QUIC Go-visitor interop**: vendored rustls 0.23.41
  (`vendor/rustls`, `[patch.crates-io]`) with a one-line server-side patch
  that treats an invalid TLS SNI as "no SNI" — Go frp v0.70.1 QUIC visitors
  send `"ip:port"` as the SNI, which upstream rustls 0.23 rejected with a
  fatal alert (see `docs/superpowers/notes/2026-08-04-mimalloc-throughput-ab.md` §6;
  drop the patch when the workspace moves past rustls 0.23).
- **HTTP plugin `enableHTTP2` honored** on `https2http` / `https2https`:
  ALPN h2 inbound (default true), inbound h2 decoded and forwarded to the
  backend as HTTP/1.1, matching Go frp semantics.
- **Baseline tooling**: `throughput-baseline.sh` / `latency-baseline.sh`
  now probe proxy registration before measuring and export `RUST_LOG=warn`
  (yamux per-frame INFO logs throttled the bridge); baselines re-committed.
- **KCP robustness + compat expansion**: the in-tree KCP state machine gains
  a proptest fuzz suite (random/truncated/mutated/multi-segment inputs never
  panic; conv-mismatch and oversized-PUSH invariants), and the FEC shard
  grouping now implements kcp-go's 60 s continuity expiry
  (`FEC_GROUP_EXPIRE_MS`, pruned alongside the 3-group cap). Zero-length PUSH
  frames are consumed without forwarding — a malicious peer can no longer
  force an EOF via an empty frame. Four previously commented-out Go↔Rust
  compat scenarios are now enabled and green: KCP+TLS and KCP+tcpMux in both
  directions (Go frp v0.70.1 supports these combinations — KCP only replaces
  the underlying transport, TLS/yamux stack on top). Compat suite is now
  72 run_test scenarios + 17 XTCP pairwise.
- **KCP self-implementation (in-tree protocol core)**: replaced the vendored
  `kcp` crate (~1.6k lines) with an in-tree KCP state machine
  (`frp-core/src/kcp/protocol.rs`, aligned with kcp-go v5.6.13 wire behavior).
  Preserves the 3 kcp-go compat patches (linear RTO backoff, flush ordering,
  early retransmit) and RFC 6298 RTO calc; removes the `[patch.crates-io]` kcp
  entry and the external dependency entirely. The socket/session/stream
  wrapper and the FEC/GF(2^8) layer are unchanged. New tests: header codec,
  fragmentation, lossy-link model, retransmit patch coverage, window probes,
  oversized-PUSH guard. Interop verified against Go frp v0.70.1 — 4 KCP compat
  scenarios + 4 XTCP KCP scenarios, both directions.
- **VirtualNet full reload cleanup + isolation enforcement**: removing or
  updating a vnet proxy now removes its OS routes and sends `VnetRouteRemove`
  to the server; the server scopes `VnetRouteAdvertise`/`VnetRouteRemove`
  broadcasts to controls on the same virtual net, broadcasts route removals on
  proxy close, and drops `VnetPacket`s whose source run_id is not in the target
  route's virtual net; clients ignore route advertisements for virtual nets
  they do not participate in. `frp-vnet::router::RouteTable` is partitioned per
  virtual net — the same subnet may coexist in different vnets and lookups are
  vnet-scoped — with isolation/broadcast/close/packet tests in `frp-vnet` and
  `frp-server`.
- **OIDC JWT jti replay protection (frp-rs enhancement)**: the server now
  tracks seen `jti` claims on login. Same jti + same subject is allowed
  (frpc reuses its cached token on reconnect); same jti + different subject
  is rejected as a cross-identity replay. Tokens without a `jti` claim pass
  (documented limitation — they cannot be tracked). Cache entries live until
  `exp + leeway` (60s, capped at 24h; fixed 1h TTL without `exp`) and are
  pruned lazily. Go frp v0.70.1 has no jti check — this is defense-in-depth;
  the primary defenses remain TLS + short-lived tokens. Tests: 4 unit tests
  in `frp-core` (`check_replay_*`) + 2 integration tests in
  `frp-server/tests/oidc_integration.rs`.

- **HTTP vhost 504 Gateway Timeout (Go v0.70.1 compat)**: when the backend
  (work conn) produces no response headers within `vhost_http_timeout`
  (Go `VhostHTTPTimeout`, default 60s), the byte-level bridge now writes
  `HTTP/1.1 504 Gateway Timeout` and closes — matching Go's
  `httputil.ReverseProxy.ResponseHeaderTimeout`. Covered by
  `tests/vhost_http_timeout.rs`.

- **HTTP vhost h2c (HTTP/2 cleartext) support (Go v0.70.1 compat)**: the HTTP
  vhost listener detects the HTTP/2 prior-knowledge preface
  (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and decodes the connection with the
  `h2` crate (tokio's official HTTP/2 implementation; Go uses net/http's
  built-in h2c). Each stream is routed through the shared
  `resolve_vhost_request` (domain/wildcard/path + httpUser lookup, Basic
  Auth, host_header_rewrite, X-Forwarded-For/requestHeaders injection),
  forwarded to the provider as plain HTTP/1.1 (`Host` from `:authority`,
  unknown-length bodies chunked-framed — Go http.Transport behavior), and
  the backend HTTP/1.1 response (status line + headers + chunked decoding)
  is re-encoded as HTTP/2 frames — including `504 Gateway Timeout` on
  `vhost_http_timeout`, 404/401/502 errors, and a custom 404 page. HTTP/1.1
  clients keep the existing byte-level path unchanged. Covered by
  `tests/vhost_h2c.rs` (GET forward, chunked backend, POST body,
  unmapped-host 404).

- **Binary profile audit**: fixed two `tiny`/`micro` build regressions — the
  `detect_behavior` field on `InternalMsg::WriteNatHoleResp` referenced
  `msg::NatHoleDetectBehavior` behind a vnet-gated import (`frp-server/src/
  state.rs`), and the no-kcp `xtcp_p2p` stub lacked the `P2pStream` trait that
  `frp-client` boxes at its data-plane dispatch. Both `tiny` (frps-tiny
  ~3.2MB / frpc-tiny ~2.7MB) and `micro` (frps-micro ~1.9MB / frpc-micro
  ~2.0MB) now build with **zero warnings** across all four profiles
  (default/full/tiny/micro) — the remaining dead-code warnings were
  feature-gated utility code (snappy stub `has_pending`, `is_v1_type_byte`,
  vhost `read_client_hello_prefix`, an unused import). Doc size tables
  updated to measured sizes (default ~5.0/4.5MB incl. QUIC; full ~5.3/4.5MB).

- **QUIC transport is now default ON**: the `quic` feature joined the default
  feature set of `frp-core`, `frp-client` and `frp-server`, so a plain
  `cargo build --release -p frps -p frpc` includes the QUIC transport and the
  XTCP QUIC data plane (frps ~5.0MB, frpc ~4.5MB). Dashboard remains opt-in;
  `--no-default-features --features tiny/micro` builds are unchanged (no
  QUIC). This also removes the "protocol=quic requires the quic feature"
  failure path from the default build — `"quic"` now just works.

- **XTCP QUIC data plane (Go v0.70.1 `protocol=quic` compat)**: `resp.protocol`
  is now honored — `"quic"` runs the hole-punched UDP socket straight into
  quinn (`quic_dial_on_socket` / `quic_accept_on_socket` in
  `frp-core/src/quic.rs`, shared `build_quic_transport_config` helper, and
  `accept_bi_owned` so the returned stream keeps the connection alive). The
  visitor is the QUIC client (dials + opens the stream), the provider the
  QUIC server (accepts + accepts); TLS is a runtime self-signed cert +
  InsecureSkipVerify with ALPN `frp`, and QUIC multiplexes streams so no
  yamux is used. `xtcp_p2p_connect_quic` in `frp-core/src/xtcp_p2p.rs` does
  punch → QUIC → first stream. Both the visitor (`visitor.rs` dispatch on
  `p2p_protocol == "quic"`) and the provider (`handle_nat_hole_resp` dispatch
  on `resp.protocol == "quic"`) select it; when the `quic` feature is
  disabled they warn + fail instead of silently falling back to KCP. Covered
  by `test_quic_roundtrip_loopback` and the `xtcp-go-frps-go-prov-rust-vis-quic`
  compat scenario (Rust visitor → Go provider).
  **Known limitation**: the reverse direction (Go visitor with the default
  `protocol = "quic"` → Rust provider) does not work — Go frp v0.70.1's
  `hostnameInSNI` (Go 1.25) no longer strips the port, so the QUIC ClientHello
  carries an SNI of `"ip:port"` (`raddr.String()`), which rustls rejects
  (`ServerNameMustContainOneHostName`); rewriting the ClientHello would break
  the TLS 1.3 handshake transcript. A Go visitor targeting a Rust provider
  must set `protocol = "kcp"` (the compat matrix's kcp scenarios cover this).

- **XTCP MakeHole executed on the provider side + Go v0.70.1 punch semantics**:
  the provider previously called `xtcp_p2p_connect_yamux` with
  `candidates=&[]`, `behavior=None`, and the peer addresses stuffed into
  `assisted`, so the simplified punch always failed with "no candidate
  addresses" and XTCP provider-side hole punching never actually ran. Both
  provider paths (`handle_nat_hole_resp` and the legacy `handle_nat_hole_client`)
  now pass `candidates`/`assisted`/`detect_behavior` per Go semantics.
  `punch_udp_hole_makehole_owned` in `frp-core/src/xtcp_p2p.rs` was aligned with Go
  `pkg/nathole/nathole.go` MakeHole: the winning socket (the one the peer's
  detect reply arrived on) is now returned and used for the KCP data plane
  (`result.lConn` semantics); probe TTL is set for the detect phase and
  restored afterwards (`ttl<=0` leaves it untouched); `send_random_ports`
  probes that many distinct random ports in [1024, 65535] concurrently (15 ms
  apart, Go `sendSidMessageToRandomPorts`) instead of a clamped 8-port window;
  `candidate_ports` range scanning now sleeps 2 ms per port (Go
  `sendSidMessageToRangePorts`); and NatHoleSid `nonce` is a random 0-19 '0'
  string like Go (`strings.Repeat("0", rand.IntN(20))`).

- **Rust frps XTCP coordination fix**: `detect_behavior` (role/ttl/send_delay/
  read_timeout chosen by the 5-mode analyzer) was computed but dropped when
  NatHoleResp was forwarded through `InternalMsg::WriteNatHoleResp`, so Go
  peers received a zero-valued DetectBehavior with an empty Role and their
  MakeHole could not tell sender from receiver — every rust-frps XTCP scenario
  with a Go peer failed. The internal message now carries `detect_behavior`
  and all construction sites fill it. Verified: XTCP pairwise compat went
  from 4/16 (main) / 10/16 (MakeHole work) to **16/16**, and the full
  68-scenario suite is green.

- **V2 post-handshake Login read timeout**: after a V2 ClientHello handshake,
  the read of the next frame (the Login message) is now bounded by the same
  10s `V2_HANDSHAKE_TIMEOUT` as the handshake itself, closing a gap where a
  peer that completed ClientHello but never sent Login could pin a server
  task / file descriptor forever. All server-side V2 accept paths (TCP,
  TCP+yamux, TLS, WebSocket, KCP, KCP+yamux, QUIC) now align with Go frp
  v0.70.1's single `connReadTimeout = 10s` deadline covering magic read +
  ClientHello/ServerHello exchange + first message.

- **Connection read timeout parity**: the new-connection read timeout now
  matches Go frp's compile-time `connReadTimeout = 10s` constant
  (`server/service.go`, not configurable). Removed the inner 5s timeout in
  `detect_and_strip_magic` so the caller's 10s wrapper governs; raised the V2
  handshake read timeout from 5s to 10s; aligned the TLS SNI peek and the
  TLS-encrypted WebSocket first-byte peek to 10s. Corrected the
  `detect_and_strip_magic` doc comment that wrongly claimed Go frp exposes
  `connReadTimeout` as configurable `ServerConfig.Transport.connReadTimeout`.

- **Config formats & templating (Go parity)**: `.yaml`/`.yml`/`.json`/`.ini`
  config files are now supported alongside TOML (auto-detected by extension);
  `${ENV_VAR}` expansion and the `{{ parseNumberRange "..." }}` template
  function in config values (Viper/Go template parity); DNS resolution for
  control/server hosts now does concurrent A/AAAA with IPv4 preference.
  Adds a `serde_yaml_ng` dependency.

- **Dashboard v2 API + OIDC verifier options**: `GET /api/v2/config` and
  `PUT /api/v2/proxy/{name}/update` (live bandwidthLimit/bandwidthLimitMode
  updates); OIDC `skipAudience`/`additionalAudience` and a custom TLS CA for
  the provider's discovery/JWKS fetches; `log.max_days` expiry cleanup and
  `log.format = "json"` structured logs.

- **SUDP visitor + three-stage data-plane encryption**: Go-compatible SUDP
  visitor (lazy connect/reconnect, UDPPacket message plane, 60 s idle
  timeout) and per-segment encryption matching Go frp's model — visitor↔server
  and provider↔server UDP bridges are encrypted with `derive_key(visitor sk)`
  / `derive_key(auth token)` respectively. Ordinary UDP proxies also gained
  `use_encryption` (previously plaintext only).

- **KCP session-creation rate limiting**: UDP flood of KCP headers can no
  longer fill the accept queue in one burst — global 256 new sessions / 10 s
  and 32 per IP / 10 s (on top of the existing total/per-IP caps); per-IP
  rate-window logs are reaped so a many-IP flood cannot accumulate map
  entries. Also fixes vnet TUN routing for multiple vnet proxies (route
  lookup now uses the advertising proxy's TUN, not an arbitrary one).

## v0.7.1 — Go frp v0.70.1 Source-Level Compatibility Audit

Full-source audit of Go frp v0.70.1 (fatedier/frp) against frp-rs. 106 findings
from 6 parallel subagent audits, 60+ fixes across 37 files. Every fix references
the exact Go frp source location that mandates the behavior.

### Post-Release Review Fixes (2026-08-01)

Second parallel audit pass focused on the staged 0.7.1 review-fix wave:

- **yamux liveness**: dead-peer retention is bounded by transport I/O while
  healthy idle sessions stay open; zero keepalive intervals are normalized.
- **Work-conn admission**: removed the client-side 64-inflight/128-queue cap
  that diverged from Go frp and could tear down the control session; each
  `ReqWorkConn` is spawned directly, matching Go v0.70.1.
- **Heartbeat defaults**: application heartbeats are disabled under `tcp_mux`
  by default (Go parity) while explicit values are preserved; `dialServerTimeout`
  zero means default, and explicit server heartbeat timeouts are kept.
- **QUIC**: zero option values normalize to Go defaults; pre-auth timeout/error
  paths close the connection; first-frame deadline starts after stream accept;
  preauth stream admission is bounded after acceptance.
- **OIDC**: authorization keeps the claimed `login.user` (Go parity); subject
  generation-scoped cleanup prevents supersession clobbering.
- **STCP/XTCP visitors**: legacy visitors without `run_id` and fresh-TCP NAT
  visitors use Go owner/allow-list admission instead of failing closed.
- **SSH gateway**: raw exec commands are no longer logged; reverse forwarding
  (`-R`) is disabled until a safe listener implementation lands.
- **mTLS**: `trustedCaFile` always requires and verifies client certificates;
  partial cert/key configs fail startup.
- **Log sanitization**: client/server control logs no longer emit full JSON
  payloads, STCP secrets, or V1 payload text.
- **Config**: Go `[transport.tls]`, server `[transport] tcpMux`, and related
  camelCase keys are normalized; WebSocket raw frames allow V2 payloads.
- **Client plugins**: Go-style flat plugin configs (`plugin = "unix_domain_socket"`
  with `plugin_local_addr`, `plugin_http_user`, etc.) are normalized to the
  nested plugin shape, fixing Docker socket and other Go frp plugin configs.
- **Config aliases**: proxy `localIP` / `localPort` camelCase fields are now
  parsed, matching Go frp configs that previously left `local_port` at 0 and
  made frpc dial `127.0.0.1:0`.
- **Config audit**: additional Go camelCase mappings added for `webServer`,
  `httpPlugins`, `featureGates`, `allowPorts` arrays, `customDomains`,
  proxy/visitor `metadatas`, `subDomainHost`, `tcpmuxPassthrough`,
  `detailedErrorsToClient`, `enablePrometheus`, `poolCount`,
  `additionalScopes`, OIDC `skipExpiryCheck`/`skipIssuerCheck`, visitor
  `[transport]`/`[natTraversal]`, plugin `unixPath`/`crtPath`/`keyPath`, and
  legacy flat `plugin_*` fields.
- **Config audit phase 2**: parse `healthCheck.httpHeaders` Go arrays,
  `webServer.assetsDir`/`pprofEnable`/`webServer.tls`, `log.disablePrintColor`,
  `httpPlugins.tlsVerify`, plugin `requestHeaders`/`enableHTTP2`, visitor
  `enabled`, and proxy `natTraversal`.
- **Store**: implement Go frp `[store] path` file-backed proxy/visitor store
  with admin API CRUD at `/api/store/proxies` and `/api/store/visitors`, plus
  config+store merging and `start` allowlist filtering.
- **Auth tokenSource**: implement Go frp `auth.tokenSource` file/exec dynamic
  token sources for client Login/Ping/NewWorkConn and server validation.
- **VirtualNet**: add `[virtualNet] address`, `virtual_net` proxy plugin, and
  `virtual_net` visitor plugin with route advertisement and bidirectional
  packet delivery. vnet routing is dual-stack (IPv4/IPv6), tunnel bytes honor
  `use_encryption`/`use_compression`, reload re-creates plugin TUNs, visitor
  return traffic is targeted to the owning TUN subnet instead of broadcast,
  and frps broadcasts vnet route advertisements/removals to peers with
  disconnect cleanup.
- **PR review fixes**: `start` allowlist now also filters visitors; vnet OS
  routes injected from peer advertisements are removed on route removal and
  disconnect; vnet tunnels use Go-compatible `[u32 LE length][packet]`
  framing even without compression; `auth.tokenSource` exec commands have a
  10s timeout and kill on expiry; server vnet route removal is guarded by the
  advertising run_id; store files persist with `0600` and validate entries on
  load; `/api/store/*` is documented as a frp-rs-native contract.
- **Concurrency**: per-run_id lifecycle mutexes are reclaimed; ClientRegistry
  lock order is canonical; post-login AEAD failure cleanup is generation-safe.
- **KCP**: login throttling uses the real peer address instead of a shared key.

### Config (19 fixes)

- **QUICOptions**: add `QuicOptions` struct with `keepalive_period` (10s), `max_idle_timeout` (30s), `max_incoming_streams` (100000). Added as `quic_options` field to `ServerTransportConfig` and `ClientConfig` (serde alias "quic").
- **TCPKeepAlive**: add `tcp_keepalive` (default 7200) to `ServerTransportConfig` with alias `tcpKeepAlive`.
- **DialServerTimeout**: add `dial_server_timeout` (default 10) to `ClientConfig` with alias `dialServerTimeout`. Now properly threaded through `ControlConnection` and `WorkConnConfig` to `DialOptions`.
- **WebServer.Addr override**: when `web_server.port > 0 && addr.is_empty()`, set addr to `"0.0.0.0"` in `ServerConfig::complete()`.
- **XTCP visitor protocol**: add `protocol` field (default "quic") to `VisitorConfig` with alias "protocol".
- **pool_count serde default**: changed from `0` to `1` via `default_pool_count()` function.
- **health_check_url default**: changed from `"/"` to `""` (empty string, matching Go frp).
- **tcp_mux (server)**: changed from `bool` to `Option<bool>` to distinguish "not set" from explicit `false`.
- **flatten_to_table overwrite semantics**: change `or_insert` to `insert` so legacy flat fields overwrite v1 nested fields (Go compat).
- **Serde aliases**: add `alias = "clientID"`, `alias = "tlsServerName"`, `alias = "tlsServerName"` on server transport, `alias = "keepalivePeriod"` on `QuicOptions`.
- **allow_port_start default 0→1**: port 0 caused OS-assigned port mismatch (server advertised port 0 but listener was on kernel-chosen port).
- **allow_port_end default 50000→65535**: full port range allowed by default, matching Go frp empty AllowPorts.
- **disable_custom_tls_first_byte serde default**: changed from `#[serde(default)]` (false) to `#[serde(default = "default_true")]` — config-file and programmatic users now get the same default (true).
- **udp_packet_size serde alias**: add `alias = "udpPacketSize"` on `udp_packet_size` field for Go frp config compat.
- **login_fail_exit serde alias**: add `alias = "loginFailExit"` on `login_fail_exit` field for Go frp config compat.
- **dns_server serde alias**: add `alias = "dnsServer"` on `dns_server` field for Go frp config compat.
- **Health check path → url mapping**: `normalize_proxies()` maps `health_check.path` to `health_check_url` (Go frp v0.70.1 aliases `path` as `url` in health check config).
- **Bandwidth_limit GB hint**: validation error message now mentions GB suffix alongside KB/MB (was missing).

### Messages (1 fix)

- **NatHoleReport.success**: changed from `Option<bool>` to `bool` (Go frp v0.70.1 always sends the field).

### Client (13 fixes)

- **V2 handshake pipelining**: split `v2_handshake_client` into `send_hello` / `recv_hello` so Login is sent between ClientHello and ServerHello, matching Go frp's `control_session.go:140-203`.
- **Health check monotonic counter**: `failures` is now a monotonic u64 that never resets on success (matching Go frp behavior). Counter inspected at `/healthz?probe=health`.
- **Health check 500ms startup delay**: first health check delayed by 500ms (matching Go frp).
- **Ping auth always set**: removed `scope_requires_auth` gate so Ping always carries auth credentials.
- **GracefulClose ordering**: signal visitors → drop yamux → wait (three-step sequence matching Go frp's `closeSession()`).
- **Visitor graceful shutdown**: `Arc<AtomicBool>` shutdown signal instead of `handle.abort()` — visitors exit cleanly.
- **STUN default**: changed from empty to `stun.easyvoip.com:3478`.
- **Unique transaction_id per request**: `uuid::Uuid::new_v4()` per message instead of static constant.
- **UDP bind before NatHoleSid**: fix race where NatHoleSid was sent before the UDP socket bind completed (Go frp binds first, then sends).
- **client_spec in Login**: `ClientSpec { client_type: "frpc", always_auth_pass: None }` sent in every Login message (Go frp compat).
- **NewVisitorConn proxy_name**: follows Go frp v0.70.1 `BuildTargetServerProxyName` — prefixes with `server_user` if non-empty, else with client `user` if non-empty, else bare `server_name`. Previously only supported `server_user` prefix.
- **NewVisitorConn run_id**: passes client `run_id` in NewVisitorConn message for server-side session tracking (Go frp compat).
- **UDP work conn keepalive**: sends `Ping` every 30s on UDP work connections to prevent server idle timeout from closing the connection (Go frp `udpWorkConnKeepalive`).

### Server (9 fixes)

- **VHost multi-proxy per domain**: changed from `HashMap<String, VhostRoute>` to `HashMap<String, Vec<VhostRoute>>` with longest location prefix match — multiple proxies can serve the same domain at different locations, matching Go frp's `routerByHTTPUser`.
- **Separate TCP/UDP port managers**: `used_udp_ports` tracking separate from `used_ports`. UDP/SuDP proxies allocate from UDP pool, TCP proxies from TCP pool with OS-level bind probe.
- **Pool pre-filling at startup**: work connection pool is pre-filled during control handler initialization, with replacement after use (matching Go frp).
- **StartWorkConn addr metadata**: always sends `src_addr` and `dst_addr` (removed `proxy_protocol_version` guard).
- **Dashboard API endpoints**: added `/api/traffic/{name}`, `/api/proxy/{type}`, `/api/proxy/{type}/{name}` with type validation and 404 for unknown types.
- **Dashboard healthz**: returns empty body for Go compat (was "ok"); `/healthz?probe=readiness` returns "ok".
- **TCP keepalive**: applied via `socket2` in server accept loop on every raw `TcpStream`.
- **TLS force handling**: proper detection and handling of `tls_only` mode on the server side.
- **NewWorkConn auth simplification**: removed Go frp compat workaround that skipped auth when `privilege_key` was present but timestamp missing — Go frp v0.70.1 always sends timestamp on NewWorkConn messages.

### XTCP / NAT Hole Punch (13 fixes)

- **Mode 3 PortsRangeNumber**: changed from `sender(0,0,0,0,0)` to `sender(0,0,10,0,0)` (was 0, Go frp uses 10).
- **Score bias**: non-fallback entries now score 0 instead of 1 (matching Go frp — entries only selected after `report_success` boosts them).
- **lastUpdateTime unconditional**: moved before the analysis loop — analyst update time always recorded.
- **IPv6 support**: removed `!ip.contains(':')` filter from `parse_ips()` — IPv6 addresses now parsed correctly.
- **Visitor read_timeout_ms**: extracted from `NatHoleResp.detect_behavior` instead of hardcoded value.
- **Configurable p2p_protocol**: visitor uses `p2p_protocol` from config instead of hardcoded "kcp".
- **Analysis key MD5 format**: `gen_analysis_key()` rewritten to produce MD5 hex string matching Go frp format.
- **NatHoleReport success tracking**: `send_nat_hole_report()` takes `success: bool` parameter, forwarded through the analysis pipeline.
- **5-mode behavior table**: full implementation matching Go frp's NAT classification state machine.
- **STUN OTHER-ADDRESS parsing**: 0x802c attribute for dual-server NAT probing.
- **Classify NAT feature**: `parse_ips` handles all address formats from Go frp's STUN library.
- **Controller session management**: session creation with timeout, provider registration, bidirectional NatHoleResp delivery.
- **Analysis scoring**: incremental `report_success` boosts, proper fallback mode initialization with score=1.

### Transports (8 fixes)

- **DialOptions default**: `disable_custom_tls_first_byte` changed from `false` to `true` in `DialOptions::default()`.
- **Server TCP keepalive**: `set_keepalive()` public function via `socket2` for outbound connections.
- **IoStream::Tls peer_addr**: TLS variant now carries `SocketAddr` for peer address tracking.
- **TLS force**: server handles `tls_only` mode correctly on the accept path.
- **Tiny/micro build fix**: removed `#[cfg(feature = "websocket")]` gate from `use std::time::Duration` (was breaking `set_keepalive`).
- **QUIC ECN doc note**: documented gap — Go frp sets `QUIC_GO_DISABLE_ECN=true`, quinn doesn't expose ECN control.
- **WebSocket comments**: clarify frame boundary handling and dispatch order.
- **KCP ACKNoDelay comment**: verify Rust kcp crate default (batched ACKs) matches Go frp's `SetACKNoDelay(false)`.

### Upgrade Notes: v0.7.0 → v0.7.1

This release aligns config defaults with Go frp v0.70.1. Existing configs that
relied on previous defaults may need updating.

#### Client defaults changed

- **`tls_enable`**: changed from `false` to `true`. If your frps does not
  have TLS configured, set `tls_enable = false` explicitly in frpc.toml.
- **`disable_custom_tls_first_byte`**: changed from `false` to `true`.
  Go frp v0.70.1 no longer sends the FRPTLSHeadByte before TLS handshake.
  If connecting to older frps (< v0.70.1), set this to `false`.
- **`tcp_mux`**: changed from feature-gated (`--features tcp-mux`) to
  always-on (`true`). If you do not want yamux multiplexing, set
  `tcp_mux = false` explicitly. When `tcp_mux` is enabled, heartbeats
  are disabled automatically (yamux provides keepalive).
- **`nat_hole_stun_server`**: changed from empty (`""`) to
  `"stun.easyvoip.com:3478"`. If you need a different STUN server,
  set it explicitly.
- **`tcp_mux_keepalive_interval`**: new field, defaults to `30`
  (seconds). Controls yamux keepalive ping interval.
- **`heartbeat_timeout`**: new field, defaults to `90` (seconds).
  Set to `-1` when `tcp_mux = true` (yamux provides keepalive).

#### Server defaults changed

- **`max_ports_per_client`**: changed from `50` to `0` (unlimited).
  To restore the old limit, set `max_ports_per_client = 50`.
- **`auth.authentication_timeout`**: changed from `15` to `0`.
- **`graceful_timeout`**: changed from `15` to `0`.
- **`web_server.addr`**: changed from `""` (bind all interfaces) to
  `"127.0.0.1"` (localhost only). This is a security hardening change.
  If the dashboard/admin API must be reachable from remote hosts, set
  `web_server.addr = "0.0.0.0"`.

#### Proxy defaults changed

- **`local_ip`**: changed from `""` (empty) to `"127.0.0.1"`.
  If your local service binds a different address, set `local_ip`
  explicitly.
- **`bandwidth_limit_mode`**: changed from `""` (both directions) to
  `"client"` (upload only). If you explicitly set `bandwidth_limit` and
  want to throttle both upload and download, set
  `bandwidth_limit_mode = ""`.

#### Bandwidth limit parsing tightened

The `bandwidth_limit` field now requires a "KB", "MB", or "GB" suffix
(case-insensitive). Bare numbers (e.g., `"500"`) and single-letter
suffixes (e.g., `"500K"`) are rejected. Use the full suffix: `"500KB"`,
`"10MB"`, `"1GB"`. Empty `bandwidth_limit` means "no limit" (matching
Go frp behavior).

#### Port range defaults expanded

`allow_port_start` changed from 10000 to 1, `allow_port_end` from 50000 to 65535.
All ports are now allowed by default (matching Go frp empty AllowPorts).

### Binary Size Optimization

Three-phase binary size reduction: frps -36% (8.18→5.20 MB), frpc -13% (6.24→5.42 MB)
in the default build. Full-feature build (`--features "ssh,quic,dashboard"`) unchanged.

#### Feature Flags: QUIC/Dashboard Opt-In, SSH Default

- **SSH** (russh + rand010, ~407 KB) → enabled by default.
- **QUIC** (quinn, ~280 KB) → opt-in. Enable with `--features quic`.
- **Dashboard** (prometheus + axum, ~181 KB) → opt-in. Enable with `--features dashboard`.
- QUIC/dashboard removed from default features; SSH remains default. Transitive dependencies for QUIC/dashboard eliminated wholesale.
- Feature forwarding added in frps/frpc Cargo.toml for all optional features.
- `toml_edit` already removed in favor of `toml` 0.8.

#### Code-Level Optimizations

- **Type erasure for authenticate**: Changed from generic to `Box<dyn AsyncReadWriteUnpin>` with `#[inline(never)]`. Eliminates dual monomorphization. Saved ~37 KB.
- **Box large async futures**: Added `spawn_boxed()` helper using unsizing coercion to erase concrete future types. Boxed dispatch match block in main accept handler. Saved ~36 KB.
- **Dispatch split**: Non-async match functions returning `Pin<Box<dyn Future + Send>>` replace N-variant async state machines. `dispatch_frp_message` reduced from 43 KB to 206 bytes.
- **Validation extraction**: `validate_new_proxy()` pure function removes 5 `.await` points from `handle_new_proxy`.
- **anyhow backtrace disabled**: Changed to `default-features = false, features = ["std"]`. Added minimal panic hooks.
- **Nightly infrastructure**: Added `nightly = []` feature placeholder.

#### Binary Sizes

| Build | frps | frpc |
|-------|------|------|
| Default | ~5.6 MB | ~5.4 MB |
| Full (`--features "ssh,quic,dashboard"`) | ~7.8 MB | ~6.0 MB |
| Tiny (`--no-default-features --features tiny`) | ~4.4 MB | ~3.8 MB |
| Micro (`--no-default-features --features micro`) | ~2.6 MB | ~2.7 MB |

#### Upgrade Notes

- **QUIC and dashboard are now opt-in.** If you use QUIC transport or the
  dashboard/metrics API, add `--features "quic,dashboard"` to your build.
  SSH is enabled by default.
- **Config files unchanged.** All config parsing and defaults are identical.
- **No wire protocol changes.** Compatible with Go frp v0.70.1.

## v0.7.0 (2026-07-21)

### Go frp dev HEAD Full Audit (d486018)

Full-source audit of Go frp dev branch against frp-rs, fixing 18 findings (7 CRITICAL, 11 MEDIUM).

**Server control plane (3 critical):**
- Two-phase login: Admit → Handoff Wait → Activate/LoginResp matching Go frp dev's ControlManager lifecycle
- ClientRegistry with `control_id`-aware `register_with_control_id()` and `mark_offline_by_run_id_and_control_id()` — prevents stale handler mutations
- Generation-aware control replacement: per-runID handoff barrier ensures old handler is fully shut down before new one activates

**XTCP/NAT hole punch (3 critical):**
- PublicNetwork detection: pass assisted_addrs as local_ips to classify_nat_feature (was always false with empty slice)
- STUN OTHER-ADDRESS (0x802c) attribute parsing for dual-server NAT probing matching Go discovery.go
- Visitor assisted_addrs: build local-IP-based addresses (ListLocalIPsForNatHole) instead of sending STUN mapped addresses

**Auth/Config (1 critical, 4 medium):**
- Token auth: no timestamp freshness check by default (matching Go's MD5-only VerifyLogin)
- heartbeat_interval = -1 when tcp_mux enabled (yamux provides keepalive)
- nat_hole_stun_server defaults to "stun.easyvoip.com:3478"
- tcp_mux unconditionally defaults to true (not feature-gated)
- proxy_bind_addr inherits from bind_addr when empty

**Client (2 medium):**
- Heartbeat timeout detection: track last_pong, trigger reconnect on timeout
- Proxy phase state machine foundation: New → WaitStart → StartErr → Running → CheckFailed → Closed enum with phase field (currently transitions New/Running/StartErr; WaitStart/CheckFailed/Closed reserved for future retry worker)

**Server misc (5 medium):**
- TCP group shared listener per group with round-robin dispatch
- HTTP group health-check-aware backend selection (skip unhealthy, 30s recovery)
- Bandwidth limit mode: server-side limiters only for `mode == "server"` (matching Go)
- AlwaysAuthPass for internal SSH gateway connections
- ServerAdditionalAuthScopes defaults to empty (Go compat)

**Docs:**
- Clarify KCP XOR encryption is not needed for Go compat (Go passes nil blockCrypt)
- Clarify group health checks are not a Go compat gap (Go only accepts "", "tcp", "http")

### Security

- Constant-time comparison for HTTP Basic Auth and proxy credentials
- Auth hardening: `check_startup()` rejects empty tokens at startup, dynamic token resolution with zeroize on Drop
- Login throttle: split check/record to close race window, memory leak cleanup, throttle check before authentication
- Connection limits: `max_connections` in ServerConfig (was hardcoded 10000), per-IP rate limiting
- OIDC: fix subject leak in error paths, validate proxy name/length
- SSH: host key permissions set to 0600
- Dashboard: bind to localhost when no admin credentials configured
- Remove `unsafe` from ResponseHeaderInjector (safe slice manipulation)
- Fix async mutex held across await in NAT hole handler and session read lock
- Client: fix TOCTOU race in static file serving, secure admin API endpoints, hash secret key in config snapshot
- Client: redact secret key in STCP visitor auth debug log
- Client: split HTTP buffer on header terminator to prevent request smuggling
- Client: handle IPv6 bracket notation in host:port parsing
- Cipher: fix partial-write re-encrypt bug — buffer encrypted output on subsequent writes
- Server: RwLock poison recovery via `RwLockExt` trait (26 sites) — single panicked task no longer cascades
- Deps: drop unmaintained `rustls-pemfile` (RUSTSEC-2025-0134), migrate cert/key parsing to `rustls::pki_types::pem::PemObject`
- Deps: remove `hex` crate — replaced with inline `hex_encode` in frp-core (saves ~30-50KB)
- Box 5 largest `FrpMessage` variants (NewProxy, Login, NatHoleResp, StartWorkConn, NatHoleClient) to reduce stack size
- V1 payload buffer pooling: reuse `BufferPool` for V1 message deserialization
- Snappy decompression bomb guard: 128KB per-chunk output limit
- Dashboard: security response headers (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy)
- Accept-loop timer cleanup: expire stale `pending_udp` entries (10s timeout)
- Accept-loop: replace fragile `front()+pop_front().unwrap()` patterns with `while let Some(...)` in pool
- Accept-loop: add graceful shutdown via CancellationToken to VHost, TCPMux, SSH listeners
- Accept-loop: replace 26 `Mutex::lock().unwrap()` with poison recovery `unwrap_or_else(|e| e.into_inner())`
- OIDC: JWT algorithm allowlist (RS256/384/512, ES256/384, PS256/384/512, HS256/384/512)
- OIDC: add `oidc_skip_nbf` flag to skip `nbf` validation
- HTTP: sanitize CR/LF from `host_header_rewrite` and `response_headers` to prevent header injection
- Dashboard: `DELETE /api/proxy/{name}` sends `CloseProxy` to client for proper cleanup
- Remove dead code: KCP peer_addr, splice zero-copy (165 lines)
- Known config keys: add `max_connections`, `graceful_shutdown_timeout` to type checker
- Remove unused deps: `bytes`, `libc` (dead direct dependencies)
- Security: constant-time comparison for admin auth (`constant_time_eq_str`)
- Login replay protection: timestamp freshness validation + (run_id, timestamp) duplicate detection with UUID fallback
- Login throttle: count ALL attempts atomically in single operation (fix TOCTOU-prone two-phase check)
- HTTP proxy CONNECT: per-line read limit (16KB), total header limit (64KB) to prevent request smuggling
- Doc: document `simple_glob` single-`*` limitation, sequential proxy registration, test coverage gaps
- Config defaults aligned with Go frp v0.70.0: `pool_count` (0→1), `dial_server_keepalive` (0→7200), `fallback_timeout_ms` (5000→1000), `min_retry_interval` (30→90), visitor `bind_addr` (0.0.0.0→127.0.0.1), `detailed_errors_to_client` (false→true), `nat_hole_analysis_data_reserve_hours` (1→168)
- Config defaults aligned with Go frp dev (fe79598): `tls_enable` (false→true), `disable_custom_tls_first_byte` (false→true), `local_ip` (""→"127.0.0.1"), `bandwidth_limit_mode` (""→"client"), health check defaults (timeout=3, max_failed=1, interval=10)
- ⚠️ **Migration:** `tls_enable` now defaults to `true` (matches Go frp dev). Existing non-TLS deployments must explicitly set `tls_enable = false` in their config, or connections will fail with TLS negotiation errors.
- Token auth: remove timestamp freshness check (Go only checks hash equality), `authentication_timeout` 15→300 (OIDC only)
- XTCP: wire `disable_assisted_addrs` — visitor sends STUN addresses as assisted_addrs for NAT classification
- HTTP: wire `route_by_http_user` — flows through ProxyInfo→VhostRoute→serve_vhost_request, matching Go behavior
- Server: wire `bandwidth_limit` in bridge + dashboard_v2; wire `response_headers` via ResponseHeaderInjector for HTTP/HTTPS
- DNS resolved IP now used for KCP/QUIC dials
- XTCP PreCheck: two-phase `NatHoleVisitor` validates before STUN
- `bandwidth_limit_mode`: empty/unspecified applies both directions (client+server gates)
- `frpc --log-file`: add CLI flag with CLI-overrides-config pattern
- KCP XOR: documented as unimplemented (KcpConfig lacks crypt field in Go frp)
- Group health checks: documented compat gap (TODO)

### Added

- Virtual Net L3 VPN: new `type = "vnet"` proxy with TUN device routing
- New `frp-vnet` crate: cross-platform TUN (Linux/macOS), CIDR routing table, VnetController
- Server-side vnet route management with subnet conflict detection
- Client-side VnetController: TUN↔work_conn bidirectional packet loop
- OS route injection for peer subnet reachability (Linux, macOS)
- Feature-gated behind `vnet` flag (full=on, tiny/micro=off)
- KCP: removed vendored `rust_tokio_kcp` (~5900 lines), replaced with 1502-line direct tokio-KCP module (`frp-core/src/kcp/`)

### Performance

- Replace `Box<dyn>` with `ReadHalf`/`WriteHalf` enums in `into_split()` — zero heap allocs per split, static dispatch (#161)
- Remove `.into_boxed()` in client control writer hot path — zero alloc in send path
- ReqWorkConn pre-warming for both V1 and V2+AEAD paths (reduces proxy connection latency)
- Pool replenishment for XTCP work connections (Go frp v0.70 compat — prevents pool exhaustion under XTCP load)
- `used_timestamps`: BTreeMap `split_off` O(log n) cleanup (was O(n) retain scan)
- ProxyManager: return `Arc<ProxyInfo>` to avoid expensive clones in hot path

### Fixed

- KCP FEC: wire format now matches Go kcp-go (6-byte header + inter-packet FEC encoding)
- KCP: proper poll_flush via force_flush in driver loop, fix busy-spin on idle connections
- KCP: Go↔Rust cross-compat FEC defaults + session routing
- WebSocket: fix pipelined-data framing (partial frame boundary handling)
- Cipher: buffer encrypted output on subsequent partial writes (re-encrypt on split writes)
- STCP: apply encryption to pure-relay visitor path, use configured encryption in fallback relay
- Client: cancel old visitor tasks on reconnect (no more orphaned tasks), exponential backoff
- Client: restore health check cancellation (no more leaked health check tasks)
- Accept empty token at login for backward compatibility (startup check still guards)
- Bridge diagnostic logs downgraded from ERROR to debug/trace/warn
- Clippy: fix warnings for Rust 1.96.0 (manual_inspect, io_other_error, manual_div_ceil, vec_init_then_push, collapsible_if)
- VNet: fix missing IntoRawFd import, remove stale `#[cfg(vnet)]` gates from NewProxy
- Server `udp_packet_size`: default 1500 (matches Go's `DefaultUDPPacketSize`; earlier commits had mistakenly applied 65535)
- Remove unused `collapsible_match` allow attributes (#163)
- Remove dead code, replace `into_boxed()` with `From` impl
- Support pre-built frps/frpc in integration tests (honor `FRPS_BIN`/`FRPC_BIN` env vars)
- XTCP P2P: KCP conv=1 for Go kcp-go cross-language compat (root cause of 8/16 failing XTCP compat; now 16/16 PASS)
- XTCP P2P: yamux background driver — poll_read after poll_flush no longer drops accepted streams
- XTCP P2P: Go-compatible KCP config (nodelay, window 128→256, MTU 1350→1400, FEC defaults)
- XTCP P2P: Go↔Rust hole-punch deadlock and yamux 30s timeout fix
- XTCP P2P: remove STUN address dedup (Go frp sends raw STUN results without dedup)
- XTCP P2P: MD5 hash for KCP conv derivation (was DefaultHasher; matches Go kcp-go)
- XTCP P2P: pre_check before sign_key dispatch order (matches Go frp handler.go)
- Micro/tiny: add `default_kcp_config` to no-kcp fallback module (fix build for frp-client NAT hole handlers)
- Supersession safety: old handler cleanup captures proxy names before removing from registry
- KCP/QUIC accept errors: continue with backoff instead of breaking accept loop
- Listener bind: report success/failure via oneshot channels (no more silent failures)
- OTel layer ordering: bare Registry before EnvFilter (fix log level propagation)
- UDP reader/writer: check `session_alive` to prevent indefinite hangs after session close
- Shared logging: extract to `frp-core::logging` (~300 lines deduplicated across frps/frpc)
- VhostManager: single RwLock consolidation (eliminates TOCTOU between table operations)
- `IoStream::into_split()`: return `Result` instead of panicking on unsupported stream type
- Test: replace 300ms sleep with /healthz polling in `FrpsHandle::start` (faster, more reliable)
- Wire compat: `NatHoleSid` — add `transaction_id`, `response`, `nonce` fields matching Go frp v0.70.0 (Go uses these for MakeHole UDP detection)
- Wire compat: `NatHoleReport` — add `success: Option<bool>` field matching Go `msg.NatHoleReport`
- Go compat: pre-check remove extra `mapped_addrs.is_none()` condition (Go frp only checks `PreCheck` boolean)
- Go compat: Fresh-TCP pre_check validate `allow_users` before returning OK
- Go frp dev compat: V2 max frame payload 64 KiB (was 1 MiB), reject non-zero V2 frame flags
- Go frp dev compat: `read_timeout_ms` JSON key → `read_timeout` (matches Go `NatHoleDetectBehavior`)
- Go frp dev compat: client two-phase fast-backoff reconnect (200ms phase 1, 1s×2ⁿ phase 2)
- Go frp dev compat: 60s sliding window for fast-retry counter (matches `FastBackoffManager.FastRetryWindow`)
- Go frp dev compat: 1s sender delay before NatHoleResp when role is "sender"
- Go frp dev compat: VHost wildcard domain routing (progressive `*` label widening)
- Go frp dev compat: SNI HTTPS routing via `lookup_wildcard` (was exact match)
- Go frp dev compat: gate analyzer `report_success` on `NatHoleReport.success == Some(true)`
- Compat tests: `wait_for_port_safe` falls back to `nc -z` when `lsof` is unavailable
- Compat tests: Rust frpc non-TLS configs explicitly set `tls_enable = false`
- Go compat: `handle_report` only report success to analyzer when `success != Some(false)`
- Go compat: NatHoleReport forwarding pass through `success` field
- XTCP: replace `try_into().unwrap()` with `.map_err()` on untrusted UDP frames (no panics on malformed packets)
- XTCP: log all `send_to` failures instead of silently dropping UDP send errors
- Buffer pool: recover poisoned mutex instead of panicking
- Feature stubs: return defaults instead of panicking when features disabled
- Cleanup: remove `#[allow(unused_mut)]` in v2_handshake and dashboard_v2

### Compat Tests

- Phase 2: 5 transport combo tests enabled (STCP+enc, QUIC+enc, WSS+mux)
- KCP Go↔Rust cross-compat: all transport combos verified (plain/yamux/TLS/TLS+yamux)
- WSS Go↔Rust cross-compat: uncommented g2r WSS tests
- SSH Go frps gateway test: re-enabled
- Fix flaky `go-to-rust-tcp-tls-encrypt`: retry on empty reply in send_and_expect
- Add 100ms delay to echo server before close (reduces timing races)
- Default test suite: 40 passing + 2 guarded (XTCP 16-test matrix, V2 protocol)
- Integration tests: add auth tokens to all server tests
- HTTP compat: 3 new Go→Rust tests (basic auth, host_header_rewrite, subdomain) — 60/60 total
- Reload: new integration test (reload_integration.rs) — SIGUSR1 client-side config reload e2e

## [0.3.2] - 2026-06-30

### Added
- File-backed persistence for proxy config store (#46) — dashboard CRUD survives restarts via atomic JSON file (`frps_store.json`)
- Dashboard TLS CLI flags and config normalization (#61) — `--dashboard-tls-cert-file`, `--dashboard-tls-key-file` wired to WebServerConfig
- Property-based tests for config TOML→JSON normalization (#56) — proptest idempotency, flat↔nested equivalence, camelCase→snake_case
- Fuzz/property-based tests for V1/V2 protocol frame parsing (#55) — all 256 type bytes, arbitrary payloads, truncated frames
- Benchmark suite (#60) — expanded from 6 to 10 groups: V2 protocol roundtrip (20 types × 5 benches), bridge plain/encrypted/compressed (1K–1MB), bandwidth limiter accuracy, NAT hole-punch classify+analysis
- CI: benchmark compile check — `cargo bench --workspace --no-run` in CI to catch bench rot

### Changed
- frp-server: criterion dev-dep + `[[bench]]` harness for nathole benchmarks
- frp-core: `deserialize_v1` made public for bench access

## [0.3.1] - 2026-06-28

### Added
- V2 compat test auto-build: `build_go_frp_v2()` clones Go frp v0.69.1 + `go build` when Go compiler available, caches to `/tmp/frp-source-build/`
- CI: `setup-go@v5` + cache `/tmp/frp-source-build/` for V2 test source builds
- XTCP e2e test: full NatHole message routing test (visitor↔provider via server relay)

### Fixed
- g2r V2 test: removed duplicate `transport.tls.enable=false` causing Go frpc TOML parse error
- r2g V2 test: added missing Rust frpc launch (test wrote config but never started frpc)
- g2r_quic test: enabled by default (was guarded behind `RUN_QUIC_G2R=1`); root cause was stale debug build, release build works
- XTCP message routing: server now matches Go frp v0.69.1 architecture exactly:
  - Provider notification via `NatHoleSid` on **work connection** (prefixed with `StartWorkConn` for routing)
  - `NatHoleClient` direction reversed: **provider→server** (not server→provider)
  - Address crossover corrected: visitor gets provider's STUN addresses, provider gets visitor's
  - PreCheck: stateless validation returns `NatHoleResp(OK)` without session creation
  - Server NEVER does STUN — pure relay (Go frp compat)
- STUN discovery: use `tokio::net::lookup_host` for DNS resolution of STUN server hostnames
- `pending_nat_hole_sids` queue: added 10s timeout eviction (matches other pending queues)
- xtcp_hole_punch test: fixed `NewWorkConn` Default compile error

### Changed
- XTCP tests guarded behind `RUN_XTCP=1` (requires public internet for actual QUIC/UDP hole punching)
- V2 tests: enabled locally (auto-detect Go), skipped in CI by default due to known V2 frame parsing bug (`V2 frame payload too large: 34408960`). Set `GO_FRP_V2=1` to enable in CI
- Compat test suite: 40 default tests pass, 2 guarded (was 39 default, 5 guarded)
- `InternalMsg::NatHoleClient` deprecated — Go frp compat uses `NatHoleSidOnWorkConn` on work connections

## [0.3.0] - 2026-06-28

### Added
- V2 AEAD encryption + capability negotiation (Login plaintext, AEAD after LoginResp, crypto negotiation in handshake)
- XTCP Go↔Rust cross-compat (NAT hole punch coordination with STUN discovery)
- QUIC Go↔Rust cross-compat (multi-stream QuicConnection wrapper for quic-go interop)
- XTCP compat tests (g2r_xtcp, r2g_xtcp) — guarded behind `RUN_XTCP=1` (requires public internet)
- V2 compat tests (g2r_v2_tcp, r2g_v2_tcp) — guarded behind `GO_FRP_V2=1` (requires source-built Go frp)

### Fixed
- Compat test retry logic: `send_and_expect` and `send_and_expect_udp` now use short per-attempt timeout (min 3s) with proper retry loop, instead of consuming the full deadline on a single attempt
- Compat test timing races: added startup delays for UDP (1s), tcpmux (2s), XTCP (2s), QUIC (2s) tests to allow work connection assignment and routing propagation
- QUIC g2r test guarded behind `RUN_QUIC_G2R=1` (Go frpc v0.69.1 pre-built binary QUIC work-connection limitation)
- g2r_udp, g2r_tcpmux tests now stable (39/39 default tests pass)

### Changed
- 100% feature parity with Go frp v0.69.1 (was ~98-99%)
- Compat test suite: 39 default tests + 5 guarded (was 31 tests)
- Updated README, audit doc, and CLAUDE.md to reflect parity status

## [0.2.1] - 2026-06-27

### Added
- SSH Tunnel Gateway (full ssh -R support, auto-gen Ed25519 keys)
- Reconnect backoff: min(24s×n, 720s) × jitter[0.8, 1.2] — matches Go frp v0.69.1
- Group load balancing: true round-robin with per-group atomic counter
- Admin `/api/status`: reports actual plugin, remote_addr, err; reflects registration state
- Config reload: CloseProxy+NewProxy cycle handles add/remove/modify (config_snapshot hash diff)
- KCP parameters: window 1024, MTU 1350 — matches Go frp
- XTCP NAT hole punch: full controller + analysis engine + STUN discovery
- QUIC Go↔Rust cross-compat: multi-stream QuicConnection wrapper
- Client `/api/metrics`: Prometheus-format endpoint
- Dynamic token sourcing (file://, exec://)
- OIDC custom TLS (TrustedCaFile, insecure_skip_verify)
- OIDC non-caching token source fallback (60s refresh buffer)

### Changed
- ~98-99% feature parity with Go frp v0.69.1 (was ~90%)
- Compat test suite: 31 tests (was 18)

### SSH Added to Default Features

SSH gateway (russh + rand010) added to default features. Default frps now
includes SSH support (~4.1 MB). Tiny and micro profiles unchanged.
