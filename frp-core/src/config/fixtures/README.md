# Config fixtures

## `frpc_legacy_full.ini`

Byte-identical copy of `conf/legacy/frpc_legacy_full.ini` from Go frp
**v0.71.0** (<https://github.com/fatedier/frp>), which is Apache-2.0 licensed.
It is vendored as a test fixture only; nothing at runtime reads it.

It is used by `legacy_ini_go_shipped_fixture_passes_strict_mode`
(`frp-core/src/config/tests.rs`) as the end-to-end regression check for the
legacy-shaped prefix mechanisms Go reads (`meta_*`, `header_*`,
`plugin_header_*`): the strict-mode array walk must not refuse any of them,
because Go's legacy path ignores a key its typed struct does not name rather
than erroring.

Edited copies of the file are deliberately avoided: the fixture stays
byte-identical to upstream so a future Go release can be diffed against it
(`cmp` against the file in the Go release tarball). Two pre-existing legacy-INI
gaps, both unrelated to strict mode, stop it loading end to end here (each is
recorded in `TODO.md` with its measurement, and together they are why the test
asserts at the strict-check layer):

1. **Numeric values.** `token = 12345678` and `meta_var1 = 123` are inferred as
   TOML integers by the INI reader and rejected by serde, because INI (and Go)
   treats every value as a string.
2. **Comma lists.** `[range:tcp_port]`'s
   `local_port = 6010-6020,6022,6024-6028` is split into a TOML array, which
   `ini_port_numbers` does not accept, so the template is skipped with a
   `WARN … invalid local_port` and the 17 range-expanded proxies Go registers
   are dropped.

The full-load behaviour of the mechanisms this fixture exists to protect is
covered with quoted values by
`legacy_ini_prefix_mechanisms_load_through_strict_mode`.

The server-side counterpart (`conf/legacy/frps_legacy_full.ini`) is **not**
vendored: it fails for the same class of pre-existing gap in the other
direction (`allow_ports = 2000-3000,3001,3003,4000-50000` is comma-split into an
array by the INI reader while `ServerConfig.allow_ports` is a string). The legacy
`[plugin.xxx]` server-section behaviour is covered by
`legacy_ini_ignores_keys_go_ignores` instead.

To refresh it, download the Go frp release tarball and copy
`conf/legacy/frpc_legacy_full.ini` over this file.
