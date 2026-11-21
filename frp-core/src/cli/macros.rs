/// A Go-parity bool flag: the generalisation of [`strict_config_parser`] to
/// every bool both binaries register.
///
/// Go registers these with pflag's bool machinery, which accepts three
/// spellings of one flag: the bare `--flag` (sets `true`), `--flag=true` and
/// `--flag=false`. The attached value goes through `strconv.ParseBool`
/// ([`parse_go_bool`]), so `1`/`0`/`t`/`f`/`T`/`F`/`TRUE`/`FALSE`/`True`/
/// `False` are accepted and anything else is
/// `Error: invalid argument "…" for "--flag" flag: strconv.ParseBool: …`.
/// A pflag bool **never consumes a following token**, so the space-separated
/// `--flag <bool>` is not a value there.
///
/// bpaf's `.switch()` implements only the first of those three, which is why
/// argv Go accepts exited 1 here with `` `<bool>` is not expected in this
/// context `` (`TODO.md:3498`). This expands to the `=BOOL` spelling with Go's
/// grammar, and deliberately does **not** add the space-separated form:
/// `.adjacent()` makes the value branch accept only `--flag=<value>`, so
/// `--flag <bool>` leaves the token unconsumed and is refused exactly as
/// before. That keeps this change to the spellings Go accepts — see
/// `docs/developing.md` § `--flag=<bool>` for the measured per-command Go
/// behaviour of the space form, which is *not* uniform (`frps --tls-only
/// false` is rc 1 `unknown command "false"`, while `frpc tcp --ue false` is
/// accepted and the token ignored) and is therefore recorded per flag rather
/// than papered over with a second extension.
///
/// The bare form keeps `.switch()`'s meaning: present → `true`, absent →
/// `false`.
///
/// A macro rather than a function because bpaf's `help` wants `&'static str`
/// and `concat!` is the only way to build the per-flag help while keeping the
/// flag name in the rendered text *derived from the name the parser registers*
/// — the help cannot end up naming a different flag.
///
/// `$meaning` is **not** the text a user reads. It feeds the `Doc` bpaf builds,
/// and the only production path that sees a `Doc` replaces it before printing
/// (`frp-core/src/cli/root.rs:36` hands it to [`render_cobra_help`], which takes
/// each flag's description from the `GoFlagRow.usage` cell instead). So there
/// are two copies of every bool's description — this literal, pinned by
/// `frp-core/src/cli/tests.rs`'s
/// `every_go_bool_flag_help_states_its_own_spelling` (which reads it out of
/// bpaf's rendered document), and the row cell, pinned by the `--help` byte
/// documents — and they are **not compared with each other**. Seven of the ten
/// bool sites drift: six differ only in case, the literals being
/// sentence-capitalised (`"Version of frps"`) where the rows keep Go's lowercase
/// (`"version of frps"`); `--dashboard-tls-mode` differs in wording as well — the
/// row carries Go's `"if enable dashboard tls mode"`, the literal says
/// `"Enable dashboard TLS mode"`; and `--ue`/`--uc`/`--json` agree exactly. All
/// of that is harmless for the same reason and would not be if the literal were
/// the text printed. Do not "fix" one side to
/// match the other without knowing which document the change is about: the row
/// is what prints, the literal is only what bpaf's own document would have
/// printed.
macro_rules! go_bool_flag {
    ($name:literal, $alias:expr, $short:expr, $meaning:literal $(,)?) => {
        go_bool_flag_impl!(
            $name,
            $alias,
            $short,
            concat!(
                $meaning,
                ". The Go-faithful value spelling is --",
                $name,
                "=<bool>"
            ),
            concat!($meaning, " (bare form = true)")
        )
    };
}

/// [`go_bool_flag`] for a flag Go registers under a name frp-rs never
/// implemented: `$name` is Go's spelling and becomes the parser's **primary**
/// long (the only one bpaf renders), while `$aliases` are frp-rs's older
/// spellings kept as hidden aliases so existing command lines still parse.
macro_rules! go_bool_flag_with_aliases {
    ($name:literal, $aliases:expr, $short:expr, $meaning:literal $(,)?) => {{
        let value = go_bool_named_with_aliases(
            $name,
            $aliases,
            None,
            concat!(
                $meaning,
                ". The Go-faithful value spelling is --",
                $name,
                "=<bool>"
            ),
        )
        .argument::<String>("BOOL")
        .adjacent()
        .parse(parse_go_bool);
        let switch = go_bool_named_with_aliases(
            $name,
            $aliases,
            $short,
            concat!($meaning, " (bare form = true)"),
        )
        .flag(true, false);
        construct!([value, switch])
    }};
}

/// A flag frp-rs registers as a bool where **Go's flag of the same name is a
/// string**, so the help must not claim a Go bool it does not have. Go's own
/// grammar is wider and is measured in `docs/developing.md`; here only the
/// bool-shaped values are honoured.
macro_rules! go_bool_flag_go_string {
    ($name:literal, $alias:expr, $short:expr, $meaning:literal $(,)?) => {
        go_bool_flag_impl!(
            $name,
            $alias,
            $short,
            concat!(
                $meaning,
                ". frp-rs value spelling: --",
                $name,
                "=<bool>; Go's --",
                $name,
                " is a string flag and accepts any value there"
            ),
            concat!(
                $meaning,
                " (bare form = true); Go's --",
                $name,
                " is a string flag and consumes the next token"
            )
        )
    };
}

/// An frp-rs-only bool flag: same parsing and value grammar, but Go registers
/// no flag of this name, so the help must say so rather than claim parity.
macro_rules! go_bool_flag_rs_only {
    ($name:literal, $alias:expr, $short:expr, $meaning:literal $(,)?) => {
        go_bool_flag_impl!(
            $name,
            $alias,
            $short,
            concat!(
                $meaning,
                ". --",
                $name,
                "=<bool> is an frp-rs extension: Go registers no --",
                $name
            ),
            concat!($meaning, " (bare form = true)")
        )
    };
}

/// The one place the two branches are built; [`go_bool_flag`] and its two
/// siblings differ only in the help they pass.
///
/// The value branch is **long-only on purpose** — `$short` goes to the flag
/// branch and nowhere else. A short in an `.adjacent()` argument makes bpaf's
/// `ParseArgument` push the named argument onto `State::path` as soon as it
/// *attempts* a token, so that branch is reported one level deeper than the flag
/// branch and `this_or_that_picks_first` returns the deeper branch's error even
/// when the flag branch parsed the token successfully. Measured on `frps`:
/// with the short in both branches, `-vtrue`/`-vh`/`-vtok`/`-vp7000` — pflag
/// shorthand clusters that set `-v` and re-parse the rest, rc 0 on Go and rc 0
/// at the base head — all became rc 1. The short's `=` spelling (`-v=false`)
/// is instead expanded to the long form before bpaf sees argv; see
/// [`expand_bool_short_value_form`].
macro_rules! go_bool_flag_impl {
    ($name:literal, $alias:expr, $short:expr, $value_help:expr, $switch_help:expr $(,)?) => {{
        let value = go_bool_named($name, $alias, None, $value_help)
            .argument::<String>("BOOL")
            .adjacent()
            .parse(parse_go_bool);
        let switch = go_bool_named($name, $alias, $short, $switch_help).flag(true, false);
        construct!([value, switch])
    }};
}
