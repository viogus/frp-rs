# Config fixtures

## `frpc_legacy_full.ini`

Byte-identical copy of `conf/legacy/frpc_legacy_full.ini` from Go frp
**v0.71.0** (<https://github.com/fatedier/frp>), which is Apache-2.0 licensed.
It is vendored as a test fixture only; nothing at runtime reads it.

It is used by `legacy_ini_go_shipped_fixture_passes_strict_mode`
(`frp-core/src/config/tests.rs`) as the end-to-end regression check for the
legacy-INI prefix mechanisms Go reads (`meta_*`, `header_*`,
`plugin_header_*`): the strict-mode array walk must not refuse any of them,
because Go's INI path ignores a key its typed struct does not name rather than
erroring.

Edited copies of the file are deliberately avoided: the fixture stays
byte-identical to upstream so a future Go release can be diffed against it
(`cmp` against the file in the Go release tarball). The one thing it cannot do
here is load end to end, because it carries bare numeric values for string
fields (`token = 12345678`, `meta_var1 = 123`) and frp-rs's INI number inference
turns those into TOML integers that serde rejects — a pre-existing legacy-INI
gap, independent of strict mode; the test asserts at the strict-check layer and
the full-load behaviour is covered with quoted values by
`legacy_ini_prefix_mechanisms_load_through_strict_mode`.

To refresh it, download the Go frp release tarball and copy
`conf/legacy/frpc_legacy_full.ini` over this file.
