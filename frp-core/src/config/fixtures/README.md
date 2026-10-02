# Config fixtures

## `frpc_legacy_full.ini`

Byte-identical copy of `conf/legacy/frpc_legacy_full.ini` from Go frp
**v0.71.0** (<https://github.com/fatedier/frp>), which is Apache-2.0 licensed.
It is vendored as a test fixture only; nothing at runtime reads it.

Two tests use it, in `frp-core/src/config/tests.rs`:

* `legacy_ini_go_shipped_fixture_passes_strict_mode` pins the strict-mode
  regression the file was vendored for: every legacy-shaped prefix mechanism Go
  reads (`meta_*`, `header_*`, `plugin_header_*`) must not draw an unknown-field
  refusal, because Go's legacy path ignores a key its typed struct does not name
  rather than erroring.
* `legacy_ini_go_shipped_frpc_fixture_loads_end_to_end` loads the file through
  the real client config path (`load_client_config`, strict) and asserts the
  names and counts **Go frpc v0.71.0 itself reports** for it
  (`proxy added: [43 names]`, `visitor added: [2 names]`): 43 proxies —
  `[range:tcp_port]`'s `local_port = 6010-6020,6022,6024-6028` is 17 numbers
  (`pkg/util/util/util.go:71` splits on `,`,
  `pkg/config/legacy/client.go:314-336` renders one proxy per number) and
  `[range:udp_port]` adds 11 — plus the two `role = visitor` sections. The
  same file is verified through the CLI by
  `frpc/tests/legacy_ini_fixture.rs` (`frpc verify -c` → rc 0, `Proxies: 43`,
  `Visitors: 2`).

  The pinned counts are **config-level** — what Go's own loader reports for the
  file. How many of those 43 a *server* actually accepts varies with the server
  configuration and the host. Measured once on Go v0.71.0 with a frps that had
  `vhostHTTPPort`/`vhostHTTPSPort` but no `tcpmuxHTTPConnectPort`: 38 registered,
  and Go's own frpc log names the failures — `ssh` and `web01` fail their first
  health check against a dead local `:22`/`:80`, one of the two https plugins
  fails `open ./server.crt: no such file or directory` while the other hits
  `router config conflict` (which of the two loses varies between runs), `web02`
  is `subdomain is not supported because this feature is not enabled in server`,
  and `tcpmuxhttpconnect` is `tcpmux with multiplexer httpconnect not supported
  …`. So the fixture test asserts the config set, not a registration count; the
  registered-count pin for this item is the `[range:...]` case (4 vs Go's 4).

Edited copies of the file are deliberately avoided: the fixture stays
byte-identical to upstream so a future Go release can be diffed against it
(`cmp` against the file in the Go release tarball).

The two long-standing gaps that used to stop it loading end to end — bare
numeric values inferred as TOML integers, and `[range:...]` comma lists split
into a TOML array that `ini_port_numbers` refused — are fixed
(`TODO.md:1364`): `.ini` values are now read by the target field's type, with a
lossless inference, and the range collector accepts the split array.

## `frps_legacy_full.ini`

The same for the server side: a byte-identical copy of
`conf/legacy/frps_legacy_full.ini` from Go frp **v0.71.0**, Apache-2.0. It used
to fail with `invalid type: sequence, expected a string` on
`allow_ports = 2000-3000,3001,3003,4000-50000` and on the numeric `token`; it is
loaded end to end by `legacy_ini_go_shipped_frps_fixture_loads_end_to_end`.
`frps` had no `verify` subcommand in frp-rs when that test was written (since
implemented), so it uses `load_server_config` — which is still the entry point
`frps -c` **and** `frps verify` use.

To refresh either fixture, download the Go frp release tarball and copy
`conf/legacy/<name>` over the file.
