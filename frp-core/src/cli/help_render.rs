use std::ffi::OsString;

use bpaf::*;

use super::*;

// ===========================================================================
// The `--help` document: cobra's, rendered from bpaf's parser metadata
// ===========================================================================
//
// Go frp prints **cobra's** help document; frp-rs printed bpaf's. The measured
// difference (TODO.md:253) is a different *document*, not merely a different
// layout: `frpc status --help` is 627 B of cobra — an `Overview of all proxies
// status` first line, a `Usage: frpc status [flags]` line, `Flags:` and
// `Global Flags:` sections aligned on a 30-column grid, `-h, --help  help for
// status` — against 1604 B of bpaf.
//
// [`render_cobra_help`] rebuilds that document from
//
// 1. the **surface**: `frps`/`frpc` itself, or one of its child commands,
//    derived from the argv [`prepared_cli_argv`] produced (`argv[0]` is the
//    command word cobra's `Find` would resolve, or a flag when the root is what
//    resolved), and
// 2. the **flag surface** of that command, read back out of bpaf's own help
//    rendering (`Doc::monochrome`) — so the rows cannot drift from the flags the
//    parser accepts, and the two-entries-per-bool shape bpaf prints
//    (`--strict-config=BOOL` beside `--strict-config`, the pair
//    [`go_bool_flag_impl`] builds) collapses to cobra's single row.
//
// bpaf cannot supply the flag *texts*: `bpaf::Item` is not nameable outside bpaf
// (`mod item` is private, `bpaf-0.9.27/src/lib.rs:182`) and `Metavar` has no
// public accessor (`bpaf-0.9.27/src/meta_help.rs:12`), so every row's varname and
// usage come from the tables below, measured on the released Go v0.71.0 binary.
//
// Only the two `verify` surfaces render byte-identically to Go's document; the
// other seven are **stated replacements**, because frp-rs's flag surface itself
// differs from Go's (different proxy flags, `frp-rs`-only log/admin flags, no
// `nathole`/`completion`/`help` commands). Printing a row for a flag the binary
// rejects, or hiding a flag it accepts, would be fake parity: the document
// describes what this binary actually parses.
/// Go's row for `long` on this surface, if there is one.
pub(crate) fn go_flag_row(
    tables: &[&'static [GoFlagRow]],
    long: &str,
) -> Option<&'static GoFlagRow> {
    tables
        .iter()
        .find_map(|table| table.iter().find(|row| row.long == long))
}

/// A flag as bpaf's own help rendering exposes it.
///
/// `bool_switch` is true when **any** spelling of the long name is a bare
/// switch: bpaf prints the value entry (`--strict-config=BOOL`) and the switch
/// entry (`--strict-config`) of [`go_bool_flag_impl`]'s pair as two lines, and
/// cobra has one row for the flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BpafFlag {
    long: String,
    short: Option<char>,
    bool_switch: bool,
}

/// A flag row ready to print: the parser's shorthand, plus pflag's varname
/// (`None` for a bool — pflag prints no type word for one) and usage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RenderedFlag {
    long: String,
    short: Option<char>,
    varname: Option<&'static str>,
    usage: String,
}

/// Read a command's flag surface back out of bpaf's own help rendering.
///
/// bpaf emits one option line per *spelling*, so the rows are merged by
/// canonical long name: Go's `WordSepNormalizeFunc` rewrites every `_` to `-`
/// before a lookup (`pkg/config/flags.go:31-36`), which is why `--config_dir`
/// and `--config-dir` are one flag for pflag and one row here. `--help` is
/// dropped, not merged: cobra synthesizes `-h, --help` per command, so it is
/// not part of the surface this function is describing.
///
/// A flag line is recognised positionally, which is how bpaf emits it: the long
/// token begins at column 8 (`    -x, ` or four blanks), while a wrapped usage
/// continuation is indented to the usage column (always > 8) and anything else
/// in the document — `Available commands:` entries, subsection headers,
/// positional items — sits at a different column. Order of first appearance is
/// preserved; the caller sorts.
pub(crate) fn bpaf_help_flags(doc: &Doc) -> Vec<BpafFlag> {
    let mut flags: Vec<BpafFlag> = Vec::new();
    for line in doc.monochrome(true).lines() {
        let Some(head) = line.get(..8) else { continue };
        let short = match head.as_bytes() {
            [b' ', b' ', b' ', b' ', b'-', short, b',', b' '] => Some(*short as char),
            bytes if bytes.iter().all(|byte| *byte == b' ') => None,
            _ => continue,
        };
        let Some(rest) = line.get(8..) else { continue };
        if !rest.starts_with("--") {
            continue;
        }
        // `--long` or `--long=VARNAME`; the usage text follows after a run of
        // blanks, so splitting at the first blank isolates the flag token.
        let word = rest.split(' ').next().unwrap_or(rest);
        let (name, has_varname) = match word.split_once('=') {
            Some((name, _)) => (name, true),
            None => (word, false),
        };
        let long = name.trim_start_matches("--").replace('_', "-");
        if long == "help" {
            continue;
        }
        match flags.iter_mut().find(|flag| flag.long == long) {
            Some(flag) => {
                flag.short = flag.short.or(short);
                flag.bool_switch |= !has_varname;
            }
            None => flags.push(BpafFlag {
                long,
                short,
                bool_switch: !has_varname,
            }),
        }
    }
    flags
}

/// pflag's `FlagUsagesWrapped(0)` line prefix for one flag: `  -x, --long` when
/// the parser has a shorthand, four blanks and `--long` when it does not, then
/// the type word.
pub(crate) fn flag_prefix(flag: &RenderedFlag) -> String {
    let mut prefix = match flag.short {
        Some(short) => format!("  -{short}, --{}", flag.long),
        None => format!("      --{}", flag.long),
    };
    if let Some(varname) = flag.varname {
        prefix.push(' ');
        prefix.push_str(varname);
    }
    prefix
}

/// pflag's `FlagUsagesWrapped(0)`: one line per flag, each prefix padded to one
/// blank past the longest prefix of its block (`maxlen = max(len(prefix) + 1)`
/// in `pflag-1.0.5/flag.go`, printed as `prefix`, `maxlen - len(prefix)` blanks,
/// usage), which is the 30-column grid the measured documents show.
///
/// The caller sorts by long name first: pflag sorts its own list that way
/// (`--tls-only`, `--token`, `--version`, `--vhost-http-port` on `frps --help`),
/// *not* by a union with the shorthands. A row with no usage still gets its
/// blanks, exactly as pflag's `Fprintln` writes them; cobra's
/// `trimTrailingWhitespaces` then trims only the end of the block, which is why
/// the document has no trailing blank line. No measured surface has such a row
/// (module test).
pub(crate) fn flag_usages(flags: &[RenderedFlag]) -> String {
    let prefixes: Vec<String> = flags.iter().map(flag_prefix).collect();
    let longest = prefixes.iter().map(String::len).max().unwrap_or(0);
    let mut out = String::new();
    for (prefix, flag) in prefixes.iter().zip(flags) {
        out.push_str(prefix);
        for _ in 0..(longest - prefix.len() + 3) {
            out.push(' ');
        }
        out.push_str(&flag.usage);
        out.push('\n');
    }
    out
}

/// Render cobra's help document for `command` (the root when `None`) from the
/// `Doc` bpaf produced for that command, in the shape the released Go v0.71.0
/// binary prints.
///
/// The template is cobra's usage template with every branch measured on the
/// oracle: an optional description line and blank line, `Usage:` plus the
/// `UseLine` (and, for a root with commands, a second `<name> [command]` line),
/// `Available Commands:` padded to `max(11, longest name)`, `Flags:` (the
/// surface's own flags plus cobra's synthesized `-h, --help`) and `Global
/// Flags:` (the root's persistent set), and — for a root only — cobra's
/// `Use "… [command] --help"` footer. cobra's `trimTrailingWhitespaces` on the
/// flag blocks is `trim_end` here, and the document ends with exactly one `\n`.
///
/// The rendered document describes **this** binary's surface: a row is printed
/// only for a flag bpaf actually accepted, and a flag with no row prints with an
/// empty usage (a test failure, never a shipped document).
pub(crate) fn render_cobra_help(root: RootCommand, command: Option<&str>, doc: &Doc) -> String {
    let name = root_name(root);
    let flags = bpaf_help_flags(doc);
    let tables = help_flag_tables(root, command);
    let persistent = root_persistent_flags(root);
    let own_name = command.unwrap_or(name);

    let mut local: Vec<RenderedFlag> = Vec::new();
    let mut global: Vec<RenderedFlag> = Vec::new();
    for flag in &flags {
        let row = go_flag_row(&tables, &flag.long);
        // Go's shorthand is an invariant to check, never the value to print.
        // Where the parser has one it must be Go's — that is what keeps the two
        // `verify` documents byte-exact (`frps -c/-p/-t/-v`) — but the converse
        // does not hold: frp-rs never implemented `frpc tcp`'s `-i/-l/-r/-s/-P/-n`,
        // and the document must not advertise a shorthand the parser rejects.
        debug_assert!(
            flag.short.is_none() || row.is_none_or(|row| row.short == flag.short),
            "the parser's shorthand for --{} is {:?}, which is not Go's {:?}",
            flag.long,
            flag.short,
            row.and_then(|row| row.short)
        );
        let rendered = RenderedFlag {
            long: flag.long.clone(),
            short: flag.short,
            varname: if flag.bool_switch {
                None
            } else {
                row.and_then(|row| row.varname)
            },
            usage: row.map_or("", |row| row.usage).to_owned(),
        };
        if command.is_some() && persistent.iter().any(|row| row.long == flag.long) {
            global.push(rendered);
        } else {
            local.push(rendered);
        }
    }
    // cobra's built-in help flag, local to every command and named after the
    // command it describes (`help for frps`, `help for verify`).
    local.push(RenderedFlag {
        long: "help".to_owned(),
        short: Some('h'),
        varname: None,
        usage: format!("help for {own_name}"),
    });
    local.sort_by(|a, b| a.long.cmp(&b.long));
    global.sort_by(|a, b| a.long.cmp(&b.long));

    let mut out = String::new();
    let descr = match command {
        Some(command) => command_short(root, command),
        None => root_descr(root),
    };
    if !descr.is_empty() {
        out.push_str(descr);
        out.push_str("\n\n");
    }
    let path = match command {
        Some(command) => format!("{name} {command}"),
        None => name.to_owned(),
    };
    out.push_str("Usage:\n  ");
    out.push_str(&path);
    out.push_str(" [flags]");

    let mut commands = root.subcommands().to_vec();
    commands.sort_unstable();
    if command.is_none() && !commands.is_empty() {
        out.push_str("\n  ");
        out.push_str(name);
        out.push_str(" [command]");
        out.push_str("\n\nAvailable Commands:");
        let padding = commands
            .iter()
            .map(|name| name.len())
            .max()
            .unwrap_or(0)
            .max(11);
        for command in commands {
            out.push_str(&format!(
                "\n  {command:<padding$} {}",
                command_short(root, command)
            ));
        }
    }
    if !local.is_empty() {
        out.push_str("\n\nFlags:\n");
        out.push_str(flag_usages(&local).trim_end());
    }
    if !global.is_empty() {
        out.push_str("\n\nGlobal Flags:\n");
        out.push_str(flag_usages(&global).trim_end());
    }
    if command.is_none() && !root.subcommands().is_empty() {
        out.push_str(&format!(
            "\n\nUse \"{name} [command] --help\" for more information about a command."
        ));
    }
    out.push('\n');
    out
}

/// What a help request is about: the binary's root command, plus the child
/// command word the prepared argv resolved, if any.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HelpRequest {
    pub(crate) root: RootCommand,
    pub(crate) command: Option<&'static str>,
}

/// The surface [`render_cobra_help`] renders for this argv.
///
/// `argv` is the argv [`prepared_cli_argv`] produced, in which the resolved
/// subcommand — when there is one — is at index 0, exactly the word cobra's
/// `Find` would resolve. `--help <word>` has already been resolved to the root
/// by then (measured: `frpc --help status` prints the *root* document on both
/// Go and frp-rs, while `frpc --help=true status` prints `status`'s).
pub(crate) fn help_request(root: RootCommand, argv: &[OsString]) -> HelpRequest {
    let command = argv
        .first()
        .and_then(|token| token.to_str())
        .and_then(|word| {
            root.subcommands()
                .iter()
                .copied()
                .find(|name| *name == word)
        });
    HelpRequest { root, command }
}
