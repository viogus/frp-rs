#!/usr/bin/env bash
# docs-go-column.sh — fixture checks for the `Go frp Equivalent` column of docs/config.md.
#
# Why this exists: `docs/config.md:3-4` claims "Every field maps 1:1 to a Go frp v0.71.0
# equivalent", but nothing measured that column. Two rows had already rotted by hand: PR #448
# fixed a row naming a Go spelling `frps` does not accept, and PR #455 found a second row naming
# a Go field `frps` does not read. A reader who trusts the column cannot tell a mapped row from a
# divergence, and a wrong spelling is invisible to every other guard in the tree.
#
# Provenance of the curated Go-key table (recorded so a reviewer can re-derive it)
#   Go frp v0.71.0. The annotated tag `v0.71.0` is object 40adeed73b51e7ee1766d7cfb15d02ba9431ba2b,
#   which points at commit 4a23aa181c1d7e28eecaa8216024ed753b9d27c8.
#   Source files read: pkg/config/v1/{server,client,common,proxy,visitor,proxy_plugin,
#   visitor_plugin,value_source}.go (plus api.go / store.go, which hold no config fields).
#   `pkg/config/v1/decode.go` carries no alias or legacy table — it dispatches on the `type` key
#   straight into `jsonx.UnmarshalWithOptions` — so Go accepts only the exact `json:"..."` spellings.
#   Accept set = every dotted `json` path reachable from `ServerConfig`, `ClientConfig` and the
#   `*ProxyConfig` / `*VisitorConfig` / `*PluginOptions` structs (embedded structs followed,
#   `json:"-"` ignored), plus every bare `json` field name in those structs:
#   194 dotted paths + 153 bare names = 261 distinct spellings, embedded below as `GO`.
#   (The files were fetched through the cdn.jsdelivr.net mirror of the tag because
#   raw.githubusercontent.com is unreachable from this development box; the fetched
#   `server.go` is 9334 bytes, matching the GitHub contents API listing for the tag.)
#
# A data row passes when its Go cell is one of
#   go         the token is one of the 261 Go frp v0.71.0 spellings in `GO`
#   alias      the token is one of the 41 recorded doc spellings in `ALIASES` that Go does not carry
#   qualified  `` `tok` (start|end|nested) `` with `tok` a Go frp v0.71.0 spelling
#   divergent  an em-dash divergence marker (`—`, `` `—` ``, optionally followed by prose)
#   nontoken   one of the four documented non-token shapes: `**Required.**`,
#              `` `sk` / `secretKey` ``, `` `transport.wireProtocol = "v2"` ``
# Anything else is a violation. The `ALIASES` table is the recorded exemption: those spellings are
# the rows a human must still check against the real Go binary or structs, and the fixture names
# each one's divergence in the failure/success message rather than hiding it.
#
# The two rows that name a Go spelling `frps` does not read are additionally pinned by line, field
# name and prose (`websocket_port` at docs/config.md:22, `tls_enable` at docs/config.md:25), so
# re-wording either back into a bare Go spelling reds even if someone later adds that spelling to
# `ALIASES` or to `GO`.
#
# The inventory counts are deliberate: this is a curated table of the mapped rows, so a table
# appearing, a row being added, or a bare `—` being swapped for a token has to be recorded here in
# the same commit instead of passing silently.
#
# Scenarios
#   1  the row-by-row scan of `$DOCS_CONFIG` (default docs/config.md): 17 Go-column tables,
#      192 data rows, 10 divergence markers, 49 alias rows, then one check per data row and one
#      per pinned row.
#   2  five mutations of a copy of the repository's own docs/config.md, each of which must red —
#      M1 reword the `websocket_port` divergence to `websocketPort`, M2 reword `tls_enable` to
#      `tlsEnable`, M3 misspell a curated token (`bindAddr` -> `bindAddress`), M4 drop every table,
#      M5 strip the `websocket_port` divergence prose. A green suite on any mutant would mean the
#      fixture does not drive the scan it claims to.
#
# Usage: bash scripts/tests/docs-go-column.sh
#        DOCS_CONFIG=/tmp/mutated-config.md bash scripts/tests/docs-go-column.sh
# `DOCS_CONFIG` points the scenario-1 scan at a mutated copy; the scenario-2 mutations are always
# taken from the repository's own docs/config.md, so the seam cannot switch them off.
set -uo pipefail

# --- self-defence: assert a floor on every exit path --------------------------
# A suite that silently stops checking must not exit green. The trap is installed before the path
# resolution and the first check, so an early `exit 0` anywhere below it still has to answer to the
# floor. `MIN_CHECKS` is the measured check count of a green run.
MIN_CHECKS=204
checks=0
fails=0
WORK=""

# shellcheck disable=SC2329  # invoked by the EXIT trap below, not directly
cleanup() {
  local rc=$?
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
  if [ "$rc" -eq 0 ] && [ "$checks" -lt "$MIN_CHECKS" ]; then
    printf 'docs-go-column: only %d check(s) ran, floor %d — the suite was cut short\n' \
      "$checks" "$MIN_CHECKS" >&2
    exit 1
  fi
  exit "$rc"
}
trap cleanup EXIT

ok() {
  checks=$((checks + 1))
  printf '  ok    %s\n' "$1"
}

bad() {
  checks=$((checks + 1))
  fails=$((fails + 1))
  printf '  FAIL  %s\n' "$1"
}

# --- locate the repository even through a symlink -----------------------------
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  case "$SOURCE" in
    /*) ;;
    *) SOURCE="$DIR/$SOURCE" ;;
  esac
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PRISTINE="$REPO_ROOT/docs/config.md"

DOCS_CONFIG="${DOCS_CONFIG:-docs/config.md}"
case "$DOCS_CONFIG" in
  /*) ;;
  *) DOCS_CONFIG="$REPO_ROOT/$DOCS_CONFIG" ;;
esac

if [ ! -f "$PRISTINE" ]; then
  printf 'FAIL  cannot locate docs/config.md from %s\n' "$SCRIPT_DIR" >&2
  exit 1
fi
if [ ! -f "$DOCS_CONFIG" ]; then
  printf 'FAIL  cannot read DOCS_CONFIG=%s\n' "$DOCS_CONFIG" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf 'FAIL  python3 not found — the Go frp equivalent column cannot be scanned\n' >&2
  exit 1
fi

WORK="$(mktemp -d)"

# --- the scan: one `ok`/`bad` line per check, ordered -------------------------
# Emitted messages already carry the canonical `docs/config.md:<line>` label, so a scan of a
# mutated copy still names the row it is talking about rather than the copy's temporary path.
scan() {
  python3 -B - "$1" <<'PY'
import re
import sys

HDR = "| Field | Type | Default | Go frp Equivalent | Description |"
EXPECTED_TABLES = 17
EXPECTED_ROWS = 192
EXPECTED_DIVERGENT = 10
EXPECTED_ALIAS_ROWS = 49

# --- curated Go frp v0.71.0 spellings: dotted json paths + bare json field names ---
GO = {
    "additionalEndpointParams",
    "additionalScopes",
    "addr",
    "address",
    "allowPorts",
    "allowUsers",
    "annotations",
    "args",
    "assetsDir",
    "audience",
    "auth",
    "auth.additionalScopes",
    "auth.method",
    "auth.oidc",
    "auth.oidc.additionalEndpointParams",
    "auth.oidc.audience",
    "auth.oidc.clientID",
    "auth.oidc.clientSecret",
    "auth.oidc.insecureSkipVerify",
    "auth.oidc.issuer",
    "auth.oidc.proxyURL",
    "auth.oidc.scope",
    "auth.oidc.skipExpiryCheck",
    "auth.oidc.skipIssuerCheck",
    "auth.oidc.tokenEndpointURL",
    "auth.oidc.tokenSource",
    "auth.oidc.tokenSource.exec",
    "auth.oidc.tokenSource.exec.args",
    "auth.oidc.tokenSource.exec.command",
    "auth.oidc.tokenSource.exec.env",
    "auth.oidc.tokenSource.exec.env.name",
    "auth.oidc.tokenSource.exec.env.value",
    "auth.oidc.tokenSource.file",
    "auth.oidc.tokenSource.file.path",
    "auth.oidc.tokenSource.type",
    "auth.oidc.trustedCaFile",
    "auth.token",
    "auth.tokenSource",
    "auth.tokenSource.exec",
    "auth.tokenSource.exec.args",
    "auth.tokenSource.exec.command",
    "auth.tokenSource.exec.env",
    "auth.tokenSource.exec.env.name",
    "auth.tokenSource.exec.env.value",
    "auth.tokenSource.file",
    "auth.tokenSource.file.path",
    "auth.tokenSource.type",
    "authorizedKeysFile",
    "autoGenPrivateKeyPath",
    "bandwidthLimit",
    "bandwidthLimitMode",
    "bindAddr",
    "bindPort",
    "certFile",
    "clientID",
    "clientSecret",
    "command",
    "connectServerLocalIP",
    "crtPath",
    "custom404Page",
    "customDomains",
    "destinationIP",
    "detailedErrorsToClient",
    "dialServerKeepalive",
    "dialServerTimeout",
    "disableAssistedAddrs",
    "disableCustomTLSFirstByte",
    "disablePrintColor",
    "dnsServer",
    "enable",
    "enableHTTP2",
    "enablePrometheus",
    "enabled",
    "env",
    "exec",
    "fallbackTimeoutMs",
    "fallbackTo",
    "featureGates",
    "file",
    "force",
    "group",
    "groupKey",
    "healthCheck",
    "healthCheck.httpHeaders",
    "healthCheck.httpHeaders.name",
    "healthCheck.httpHeaders.value",
    "healthCheck.intervalSeconds",
    "healthCheck.maxFailed",
    "healthCheck.path",
    "healthCheck.timeoutSeconds",
    "healthCheck.type",
    "heartbeatInterval",
    "heartbeatTimeout",
    "hostHeaderRewrite",
    "httpHeaders",
    "httpPassword",
    "httpPlugins",
    "httpPlugins.addr",
    "httpPlugins.name",
    "httpPlugins.ops",
    "httpPlugins.path",
    "httpPlugins.tlsVerify",
    "httpUser",
    "includes",
    "insecureSkipVerify",
    "intervalSeconds",
    "issuer",
    "kcpBindPort",
    "keepTunnelOpen",
    "keepalivePeriod",
    "keyFile",
    "keyPath",
    "level",
    "loadBalancer",
    "loadBalancer.group",
    "loadBalancer.groupKey",
    "localAddr",
    "localIP",
    "localPath",
    "localPort",
    "locations",
    "log",
    "log.disablePrintColor",
    "log.level",
    "log.maxDays",
    "log.to",
    "loginFailExit",
    "maxDays",
    "maxFailed",
    "maxIdleTimeout",
    "maxIncomingStreams",
    "maxPoolCount",
    "maxPortsPerClient",
    "maxRetriesAnHour",
    "metadatas",
    "method",
    "minRetryInterval",
    "multiplexer",
    "name",
    "natHoleStunServer",
    "natTraversal",
    "natTraversal.disableAssistedAddrs",
    "natholeAnalysisDataReserveHours",
    "oidc",
    "ops",
    "password",
    "path",
    "plugin",
    "plugin.type",
    "poolCount",
    "port",
    "pprofEnable",
    "privateKeyFile",
    "protocol",
    "proxies",
    "proxies.type",
    "proxyBindAddr",
    "proxyProtocolVersion",
    "proxyURL",
    "quic",
    "quicBindPort",
    "remotePort",
    "requestHeaders",
    "requestHeaders.set",
    "responseHeaders",
    "responseHeaders.set",
    "routeByHTTPUser",
    "scope",
    "secretKey",
    "serverAddr",
    "serverName",
    "serverPort",
    "serverUser",
    "set",
    "skipExpiryCheck",
    "skipIssuerCheck",
    "sshTunnelGateway",
    "sshTunnelGateway.authorizedKeysFile",
    "sshTunnelGateway.autoGenPrivateKeyPath",
    "sshTunnelGateway.bindPort",
    "sshTunnelGateway.privateKeyFile",
    "start",
    "store",
    "store.path",
    "stripPrefix",
    "subDomainHost",
    "subdomain",
    "tcpKeepalive",
    "tcpMux",
    "tcpMuxKeepaliveInterval",
    "tcpmuxHTTPConnectPort",
    "tcpmuxPassthrough",
    "timeoutSeconds",
    "tls",
    "tlsVerify",
    "to",
    "token",
    "tokenEndpointURL",
    "tokenSource",
    "transport",
    "transport.bandwidthLimit",
    "transport.bandwidthLimitMode",
    "transport.connectServerLocalIP",
    "transport.dialServerKeepalive",
    "transport.dialServerTimeout",
    "transport.heartbeatInterval",
    "transport.heartbeatTimeout",
    "transport.maxPoolCount",
    "transport.poolCount",
    "transport.protocol",
    "transport.proxyProtocolVersion",
    "transport.proxyURL",
    "transport.quic",
    "transport.quic.keepalivePeriod",
    "transport.quic.maxIdleTimeout",
    "transport.quic.maxIncomingStreams",
    "transport.tcpKeepalive",
    "transport.tcpMux",
    "transport.tcpMuxKeepaliveInterval",
    "transport.tls",
    "transport.tls.certFile",
    "transport.tls.disableCustomTLSFirstByte",
    "transport.tls.enable",
    "transport.tls.force",
    "transport.tls.keyFile",
    "transport.tls.serverName",
    "transport.tls.trustedCaFile",
    "transport.useCompression",
    "transport.useEncryption",
    "transport.wireProtocol",
    "trustedCaFile",
    "type",
    "udpPacketSize",
    "unixPath",
    "useCompression",
    "useEncryption",
    "user",
    "userConnTimeout",
    "username",
    "value",
    "version",
    "vhostHTTPPort",
    "vhostHTTPSPort",
    "vhostHTTPTimeout",
    "virtualNet",
    "virtualNet.address",
    "visitors",
    "visitors.type",
    "webServer",
    "webServer.addr",
    "webServer.assetsDir",
    "webServer.password",
    "webServer.port",
    "webServer.pprofEnable",
    "webServer.tls",
    "webServer.tls.certFile",
    "webServer.tls.keyFile",
    "webServer.tls.serverName",
    "webServer.tls.trustedCaFile",
    "webServer.user",
    "wireProtocol",
}

# --- recorded doc spellings that are NOT Go frp v0.71.0 json keys -------------------
ALIASES = {
    "auth.additionalAuthScopes": "flattened: Go's server auth key is auth.additionalScopes",
    "auth.additionalEndpointParams": "flattened: Go's client OIDC nests it under auth.oidc",
    "auth.authenticationTimeout": "flattened: not a Go v0.71.0 auth key",
    "auth.insecureSkipVerify": "wrong nesting: Go's client OIDC nests it under auth.oidc",
    "auth.oidcAdditionalAudience": "no Go v0.71.0 counterpart",
    "auth.oidcAudience": "flattened: Go nests it as auth.oidc.audience",
    "auth.oidcClientId": "flattened and case mismatch: Go's client OIDC spells it auth.oidc.clientID",
    "auth.oidcClientSecret": "flattened: Go's client OIDC nests it under auth.oidc",
    "auth.oidcIssuer": "flattened: Go nests it as auth.oidc.issuer",
    "auth.oidcProxyURL": "flattened: Go nests it as auth.oidc.proxyURL",
    "auth.oidcScope": "flattened: Go's client OIDC nests it under auth.oidc",
    "auth.oidcSkipAudience": "no Go v0.71.0 counterpart: Go's server OIDC has no audience skip",
    "auth.oidcSkipExpiry": "flattened: Go's server OIDC spells it auth.oidc.skipExpiryCheck",
    "auth.oidcSkipIssuer": "flattened: Go's server OIDC spells it auth.oidc.skipIssuerCheck",
    "auth.oidcSkipNbf": "no Go v0.71.0 counterpart",
    "auth.oidcTLSTrustedCAFile": "flattened and renamed: Go's client OIDC uses auth.oidc.trustedCaFile",
    "auth.oidcTokenEndpoint": "flattened: Go nests it as auth.oidc.tokenEndpointURL",
    "auth.oidcTokenSource": "flattened: Go's client OIDC nests it under auth.oidc",
    "auth.tlsTrustedCaFile": "wrong nesting: Go's client OIDC nests it under auth.oidc",
    "auth.tokenAuthTimeout": "flattened: not a Go v0.71.0 auth key",
    "clientId": "case mismatch: Go spells the key clientID",
    "enableControl": "frp-rs extension: not a Go v0.71.0 config key",
    "headers": "renamed: Go has requestHeaders / responseHeaders, no bare headers",
    "httpPwd": "renamed: Go's HTTPProxyConfig spells it httpPassword",
    "localIp": "case mismatch: Go spells the key localIP",
    "maxConnsPerProxy": "frp-rs extension: no Go v0.71.0 config field (Go has maxPortsPerClient only)",
    "maxProxiesPerClient": "frp-rs extension: no Go v0.71.0 config field",
    "metas": "renamed: Go's ProxyBaseConfig spells it metadatas",
    "pluginCrtPath": "flattened: Go's plugin option is crtPath, inside the plugin table",
    "pluginKeyPath": "flattened: Go's plugin option is keyPath, inside the plugin table",
    "sk": "renamed: Go's proxy/visitor key is secretKey",
    "sshTunnelGateway.bindAddr": "frp-rs extension: Go's SSHTunnelGateway has no bind address",
    "sudpPort": "frp-rs extension: Go v0.71.0's server config names no SUDP port",
    "tcpMuxPassthrough": "case mismatch: Go spells the key tcpmuxPassthrough",
    "timeout": "frp-rs extension: not a Go v0.71.0 config key",
    "tlsServerName": "qualified: Go nests it as transport.tls.serverName",
    "url": "frp-rs extension: not a Go v0.71.0 config key",
    "webServer.custom404Page": "wrong nesting: Go's ServerConfig carries custom404Page at the top level",
    "webServer.enablePrometheus": "wrong nesting: Go's ServerConfig carries enablePrometheus at the top level",
    "webServer.tlsCertFile": "wrong nesting: Go nests TLS as webServer.tls.certFile",
    "webServer.tlsKeyFile": "wrong nesting: Go nests TLS as webServer.tls.keyFile",
}

TOK = re.compile(r'^`([A-Za-z][A-Za-z0-9_.]*)`$')
QUAL = re.compile(r'^`([A-Za-z][A-Za-z0-9_.]*)`\s+\((start|end|nested)\)$')
DIVERGENT = re.compile(r'^`?—')
NONTOKEN = ('**Required.**', '`sk` / `secretKey`', '`transport.wireProtocol = "v2"`')
PINS = ((22, 'websocket_port'), (25, 'tls_enable'))
PHRASE = 'no Go server field'


def emit(kind, msg):
    sys.stdout.write('%s %s\n' % (kind, msg))


def short(text):
    text = text.replace('\n', ' ')
    if len(text) > 72:
        text = text[:69] + '...'
    return text


try:
    raw = open(sys.argv[1], encoding='utf-8').read()
except OSError as exc:
    emit('bad', 'inventory: cannot read the file under test (%s)' % exc)
    sys.exit(0)

lines = raw.split('\n')

tables = []
rows = []
i = 0
while i < len(lines):
    if lines[i].strip() == HDR:
        tables.append(i + 1)
        j = i + 2
        while j < len(lines) and lines[j].startswith('|'):
            cells = re.split(r'(?<!\\)\|', lines[j].strip().strip('|'))
            if len(cells) >= 4:
                rows.append((j + 1, cells[0].strip(), cells[3].strip()))
            j += 1
        i = j
    else:
        i += 1

# (line, field cell, go cell, class, message, token-or-None)
classified = []
for ln, field, cell in rows:
    m = TOK.match(cell)
    if m:
        tok = m.group(1)
        if tok in GO:
            classified.append((ln, field, cell, 'go', '`%s` is a Go frp v0.71.0 json spelling' % tok, tok))
        elif tok in ALIASES:
            classified.append((ln, field, cell, 'alias',
                               '`%s` is a recorded doc spelling, not a Go frp v0.71.0 json key (%s)'
                               % (tok, ALIASES[tok]), tok))
        else:
            classified.append((ln, field, cell, 'unknown',
                               'Go cell `%s` is not a Go frp v0.71.0 json spelling, a recorded doc '
                               'alias, a divergence marker or a documented non-token shape' % short(tok), tok))
        continue
    q = QUAL.match(cell)
    if q:
        tok, shape = q.group(1), q.group(2)
        if tok in GO:
            classified.append((ln, field, cell, 'qualified',
                               'Go cell `%s` (%s) names the Go frp v0.71.0 json spelling `%s`'
                               % (tok, shape, tok), tok))
        else:
            classified.append((ln, field, cell, 'unknown',
                               'Go cell `%s` (%s) is not a Go frp v0.71.0 json spelling' % (tok, shape), tok))
        continue
    if DIVERGENT.match(cell):
        classified.append((ln, field, cell, 'divergent',
                           '%s records a divergence marker (%s)' % (field, short(cell)), None))
        continue
    if cell in NONTOKEN:
        classified.append((ln, field, cell, 'nontoken',
                           '%s carries the documented non-token shape %s' % (field, cell), None))
        continue
    classified.append((ln, field, cell, 'unknown',
                       'Go cell %s is not a Go frp v0.71.0 json spelling, a recorded doc alias, '
                       'a divergence marker or a documented non-token shape (%s)'
                       % (short(cell) if cell else '<empty>', field), None))

divergent = [c for c in classified if c[3] == 'divergent']
alias_rows = [c for c in classified if c[3] == 'alias']
alias_used = set(c[5] for c in alias_rows)


def count_check(what, got, want):
    if got == want:
        emit('ok', 'inventory: %d %s' % (got, what))
    else:
        emit('bad', 'inventory: the file under test carries %d %s, expected %d' % (got, what, want))


count_check('Go-column table(s)', len(tables), EXPECTED_TABLES)
count_check('data row(s)', len(rows), EXPECTED_ROWS)
count_check('divergence marker row(s)', len(divergent), EXPECTED_DIVERGENT)
count_check('recorded doc-alias row(s)', len(alias_rows), EXPECTED_ALIAS_ROWS)

unused = sorted(set(ALIASES) - alias_used)
if not unused:
    emit('ok', 'inventory: all %d recorded doc-alias spelling(s) are used by the file under test' % len(ALIASES))
else:
    emit('bad', 'inventory: %d recorded doc-alias spelling(s) are unused by the file under test: %s'
         % (len(unused), ', '.join('`%s`' % u for u in unused[:6])))

for ln, field, cell, cls, msg, tok in classified:
    emit('bad' if cls == 'unknown' else 'ok', 'docs/config.md:%d %s' % (ln, msg))

by_line = dict((c[0], c) for c in classified)
for ln, field in PINS:
    want_field = '`%s`' % field
    c = by_line.get(ln)
    if c is None:
        emit('bad', 'docs/config.md:%d pinned row %s is absent from the file under test' % (ln, field))
    elif c[1] != want_field:
        emit('bad', 'docs/config.md:%d pinned row %s is at a different line (found %s)'
             % (ln, field, short(c[1])))
    elif c[3] != 'divergent' or PHRASE not in c[2]:
        emit('bad', 'docs/config.md:%d pinned row %s no longer records the "%s" divergence marker '
                    '(Go cell: %s)' % (ln, field, PHRASE, short(c[2])))
    else:
        emit('ok', 'docs/config.md:%d pinned row %s records the "%s" divergence marker'
             % (ln, field, PHRASE))
PY
}

# --- scenario 2: mutate a throwaway copy of the Go cell on a given line -------
mutate_go_cell() { # <src> <dst> <line> <new-go-cell>
  python3 -B - "$1" "$2" "$3" "$4" <<'PY'
import re
import sys

src, dst, ln, new = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
lines = open(src, encoding='utf-8').read().split('\n')
cells = re.split(r'(?<!\\)\|', lines[ln - 1].strip().strip('|'))
cells[3] = ' ' + new + ' '
lines[ln - 1] = '|' + '|'.join(cells) + '|'
open(dst, 'w', encoding='utf-8').write('\n'.join(lines))
PY
}

expect_red() { # <name> <doc> <needle> <needle>
  local name=$1 doc=$2 first=$3 second=$4 out
  out="$(scan "$doc")"
  if printf '%s\n' "$out" | grep -Fq "$first" && printf '%s\n' "$out" | grep -Fq "$second"; then
    ok "$name"
  else
    bad "$name — the mutant did not red as expected (want '$first' + '$second'); the check would be vacuous"
  fi
}

# --- scenario 1: the scan of $DOCS_CONFIG ------------------------------------
report="$(scan "$DOCS_CONFIG")"
while IFS= read -r line; do
  case "$line" in
    "ok "*) ok "${line#ok }" ;;
    "bad "*) bad "${line#bad }" ;;
  esac
done <<<"$report"

# --- scenario 2: each mutation must red --------------------------------------
M1="$WORK/m1.md"
if mutate_go_cell "$PRISTINE" "$M1" 22 '`websocketPort`' && grep -Fq '`websocketPort`' "$M1"; then
  expect_red 'M1 (websocket_port reworded to the Go spelling `websocketPort`): docs/config.md:22 reds' \
    "$M1" 'bad docs/config.md:22' '`websocketPort` is not a Go frp v0.71.0'
else
  bad 'M1 mutation did not apply — anchor missing, the check would be vacuous'
fi

M2="$WORK/m2.md"
if mutate_go_cell "$PRISTINE" "$M2" 25 '`tlsEnable`' && grep -Fq '`tlsEnable`' "$M2"; then
  expect_red 'M2 (tls_enable reworded to the Go spelling `tlsEnable`): docs/config.md:25 reds' \
    "$M2" 'bad docs/config.md:25' '`tlsEnable` is not a Go frp v0.71.0'
else
  bad 'M2 mutation did not apply — anchor missing, the check would be vacuous'
fi

M3="$WORK/m3.md"
if mutate_go_cell "$PRISTINE" "$M3" 14 '`bindAddress`' && grep -Fq '`bindAddress`' "$M3"; then
  expect_red 'M3 (a curated token misspelled, `bindAddr` -> `bindAddress`): docs/config.md:14 reds' \
    "$M3" 'bad docs/config.md:14' '`bindAddress` is not a Go frp v0.71.0'
else
  bad 'M3 mutation did not apply — anchor missing, the check would be vacuous'
fi

M4="$WORK/m4.md"
printf '# Configuration Reference\n\nNo tables here.\n' >"$M4"
expect_red 'M4 (every Go-column table dropped): the row floor reds' \
  "$M4" 'bad inventory:' '0 Go-column table(s)'

M5="$WORK/m5.md"
if mutate_go_cell "$PRISTINE" "$M5" 22 '—' && grep -Fq '| — |' "$M5"; then
  expect_red 'M5 (websocket_port’s divergence prose stripped): the pinned row reds' \
    "$M5" 'bad docs/config.md:22' 'no longer records'
else
  bad 'M5 mutation did not apply — anchor missing, the check would be vacuous'
fi

# ---------------------------------------------------------------- summary
printf '\n'
if [ "$fails" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
  exit 0
fi
printf 'RESULT: %d fixture check(s), %d failure(s) above\n' "$checks" "$fails"
exit 1
