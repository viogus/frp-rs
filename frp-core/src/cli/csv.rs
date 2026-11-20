use bpaf::Parser;
use bpaf::*;

use super::*;

/// Go's `encoding/csv` message for a quote that is never closed, or for a
/// non-delimiter after a closing quote. Both are `ErrQuote` in Go, and both are
/// refused by pflag's `strings` value.
pub(crate) const CSV_MISSING_QUOTE: &str = "extraneous or missing \" in quoted-field";

/// Go's `encoding/csv` message for a `"` that appears inside an unquoted field.
pub(crate) const CSV_BARE_QUOTE: &str = "bare \" in non-quoted-field";

/// One `--allow-unsafe` occurrence, split the way pflag's `strings` value does.
///
/// Go registers the flag as `StringSliceVarP` (frpc `cmd/frpc/sub/root.go:55`,
/// frps `cmd/frps/root.go:47`), and pflag reads a `strings` value with its
/// `readAsCSV` helper: Go's `encoding/csv` reader with `LazyQuotes=false` and
/// `TrimLeadingSpace=false`, reading **one record**. So the value is CSV —
/// matched quotes are stripped, whitespace is **not** trimmed, leading blank
/// lines are skipped, and a malformed record is a flag error. Exactly one
/// record is read: its terminator ends the read, and the rest of the value is
/// never parsed.
///
/// Measured on Go v0.71.0 with `frpc verify -c <exec tokenSource cfg>
/// --allow-unsafe <value>` (rc 0 means the value enabled `TokenSourceExec`;
/// rc 1 with an `invalid argument … for "--allow-unsafe" flag` line on stderr
/// means pflag refused it; rc 1 with the `unsafe feature … is not enabled` gate
/// line means it parsed but did not carry the feature):
///
/// | value | pflag reads | rc |
/// |---|---|---|
/// | `"TokenSourceExec"` | `TokenSourceExec` (matched quotes stripped) | 0 |
/// | `A, TokenSourceExec` | `A`, ` TokenSourceExec` (space kept) | 1 |
/// | `TokenSourceExec` | `TokenSourceExec` | 0 |
/// | `Ignored,TokenSourceExec` | `Ignored`, `TokenSourceExec` | 0 |
/// | `"a""b"` (doubled quote inside a field) | `a"b` | 1 |
/// | `"a,b"` (comma inside quotes) | `a,b` | 1 |
/// | `a,,b` (empty element) | `a`, ``, `b` | 1 |
/// | `"a""b",TokenSourceExec`, `"a,b",TokenSourceExec`, `a,,b,TokenSourceExec` | those fields plus `TokenSourceExec` | 0 |
/// | `TokenSourceExec\r` | `TokenSourceExec` (trailing CR is a terminator) | 0 |
/// | `"abc` (unclosed quote) | error `extraneous or missing " in quoted-field` | 1 |
/// | `a"b` (bare quote) | error `bare " in non-quoted-field` | 1 |
/// | `"TokenSourceExec"x` (junk after the quote) | error `extraneous or missing "` | 1 |
/// | `"TokenSourceExec"\njunk` | `TokenSourceExec` (later records never read) | 0 |
/// | `\nTokenSourceExec` | `TokenSourceExec` (leading blank lines are skipped) | 0 |
/// | `\n`, `\r\n`, `\r` | error `EOF` (a blank-only value is a flag error) | 1 |
/// | `\n"a` | error `parse error on line 2, column 3: …` (blank line skipped) | 1 |
/// | ` TokenSourceExec`, `'TokenSourceExec'`, `A,\tTokenSourceExec` | kept verbatim | 1 |
///
/// The empty value is pflag's `readAsCSV("")` special case and yields no
/// features rather than one empty one. Error wording is frp-rs's, shaped after
/// Go's `encoding/csv` `ParseError`: a 1-based **byte** column on a 1-based
/// line, with Go's `record on line N; ` prefix when the record started on an
/// earlier line than the error (a quoted field may span lines). What is pinned
/// is the refusal and those numbers, not the sentence around them.
pub(crate) fn split_allow_unsafe_csv(value: &str) -> Result<Vec<String>, String> {
    // pflag's `readAsCSV` returns an empty slice, not `[""]`, for "".
    if value.is_empty() {
        return Ok(Vec::new());
    }
    read_csv_record(value)
}

/// Go's `encoding/csv` `Reader.Read` for one record, with `Comma=','`,
/// `LazyQuotes=false` and `TrimLeadingSpace=false` — the configuration pflag's
/// `readAsCSV` uses. Mirrors `readRecord`/`readLine` from Go 1.27.1's
/// `$GOROOT/src/encoding/csv/reader.go`: blank lines before the record are skipped, a
/// quoted field may span lines, and errors carry Go's `ParseError` numbers.
pub(crate) fn read_csv_record(value: &str) -> Result<Vec<String>, String> {
    // Go's `readLine` normalises `\r\n` to `\n` on every line and drops a
    // trailing `\r` at end of input; both are properties of the byte stream, so
    // they are applied once here and `CsvReader::read_line` stays a plain split.
    let normalized = normalize_csv_input(value);
    let mut reader = CsvReader::new(&normalized);
    // Read the first non-blank line (Go's `readRecord` skip loop; comments are
    // off for pflag's reader, so only the empty-line arm applies).
    let (mut line, eof) = loop {
        let (line, eof) = reader.read_line();
        if !eof && line.len() == length_nl(line) {
            continue;
        }
        break (line, eof);
    };
    // Blank lines only: Go's reader returns `io.EOF`, which pflag reports as
    // `invalid argument … for "--allow-unsafe" flag: EOF`.
    if eof {
        return Err("EOF".to_string());
    }
    let start_line = reader.line;
    let mut record: Vec<u8> = Vec::new();
    let mut fields: Vec<Vec<u8>> = Vec::new();
    let mut pos_line = reader.line;
    let mut pos_col = 1usize;
    'parse_field: loop {
        if line.is_empty() || line[0] != b'"' {
            // Non-quoted field: up to the next comma, or to the end of the line
            // with the terminator removed.
            let comma = line.iter().position(|&b| b == b',');
            let end = comma.unwrap_or_else(|| line.len() - length_nl(line));
            let field = &line[..end];
            if let Some(j) = field.iter().position(|&b| b == b'"') {
                return Err(csv_error(
                    start_line,
                    reader.line,
                    pos_col + j,
                    CSV_BARE_QUOTE,
                ));
            }
            record.extend_from_slice(field);
            fields.push(std::mem::take(&mut record));
            if let Some(i) = comma {
                line = &line[i + 1..];
                pos_col += i + 1;
                continue 'parse_field;
            }
            break 'parse_field;
        }
        // Quoted field: the opening quote is not part of the value.
        line = &line[1..];
        pos_col += 1;
        loop {
            if let Some(i) = line.iter().position(|&b| b == b'"') {
                record.extend_from_slice(&line[..i]);
                line = &line[i + 1..];
                pos_col += i + 1;
                match line.first() {
                    // `""` sequence: one literal quote.
                    Some(b'"') => {
                        record.push(b'"');
                        line = &line[1..];
                        pos_col += 1;
                    }
                    // `",` sequence: end of field.
                    Some(b',') => {
                        line = &line[1..];
                        pos_col += 1;
                        fields.push(std::mem::take(&mut record));
                        continue 'parse_field;
                    }
                    // The closing quote at the end of a line, or of the input,
                    // ends both the field and the record.
                    _ if length_nl(line) == line.len() => {
                        fields.push(std::mem::take(&mut record));
                        break 'parse_field;
                    }
                    // An invalid, non-escaped quote. Go reports `ErrQuote` at
                    // the closing quote's own byte column, not at the offending
                    // rune's (measured: `"TokenSourceExec"x` is column 17, not
                    // 18).
                    _ => {
                        return Err(csv_error(
                            start_line,
                            pos_line,
                            pos_col - 1,
                            CSV_MISSING_QUOTE,
                        ))
                    }
                }
            } else if !line.is_empty() {
                // Hit the end of the line inside a quoted field: the newline is
                // data. Go's `if errRead != nil` arm here is a non-EOF read
                // error, which a `&str` cannot produce.
                record.extend_from_slice(line);
                pos_col += line.len();
                let (next, _) = reader.read_line();
                line = next;
                if !line.is_empty() {
                    pos_line += 1;
                    pos_col = 1;
                }
            } else {
                // Abrupt end of input inside a quoted field. Go has already
                // cleared `readLine`'s `io.EOF` here, so the unterminated quote
                // is always reported at the current position.
                return Err(csv_error(start_line, pos_line, pos_col, CSV_MISSING_QUOTE));
            }
        }
    }
    Ok(fields
        .into_iter()
        .map(|field| String::from_utf8_lossy(&field).into_owned())
        .collect())
}

/// Go's `encoding/csv` input normalisation, applied once so the reader can work
/// on plain `\n`-separated lines: every `\r\n` becomes `\n` (Go's `readLine`
/// rewrites the byte rather than dropping it), and a trailing `\r` with no
/// `\n` after it is dropped ("for backwards compatibility", Go's `readLine`).
/// A `\r` anywhere else is data.
pub(crate) fn normalize_csv_input(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            if i + 1 == bytes.len() {
                // Drop the trailing \r before end of input.
                break;
            }
            if bytes[i + 1] == b'\n' {
                out.push(b'\n');
                i += 2;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// The byte count of a line's trailing `\n`, Go's `lengthNL`.
pub(crate) fn length_nl(line: &[u8]) -> usize {
    usize::from(line.last() == Some(&b'\n'))
}

/// One record's worth of Go's `encoding/csv` input state: the bytes, the
/// current byte offset, and the 1-based number of the last line read.
pub(crate) struct CsvReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    /// Go's `Reader.numLine`.
    line: usize,
}

impl<'a> CsvReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        CsvReader {
            bytes,
            offset: 0,
            line: 0,
        }
    }

    /// Go's `readLine` on already-normalised input: the next line *with* its
    /// `\n` terminator. The bool is Go's `err == io.EOF` — true only when no
    /// bytes were left at all.
    fn read_line(&mut self) -> (&'a [u8], bool) {
        let start = self.offset;
        let mut end = start;
        while end < self.bytes.len() && self.bytes[end] != b'\n' {
            end += 1;
        }
        let had_newline = end < self.bytes.len();
        let raw = &self.bytes[start..if had_newline { end + 1 } else { end }];
        self.offset = start + raw.len();
        self.line += 1;
        (raw, raw.is_empty())
    }
}

/// Go's `encoding/csv` `ParseError.Error` shape: a 1-based byte column on a
/// 1-based line, with the `record on line N; ` prefix when the record started
/// on an earlier line than the error (a quoted field may span lines).
pub(crate) fn csv_error(start_line: usize, line: usize, column: usize, reason: &str) -> String {
    if start_line == line {
        format!("parse error on line {line}, column {column}: {reason}")
    } else {
        format!(
            "record on line {start_line}; parse error on line {line}, column {column}: {reason}"
        )
    }
}

/// Every `--allow-unsafe` occurrence, read in order through
/// [`split_allow_unsafe_csv`] — pflag's `strings` value appends per occurrence.
pub(crate) fn allow_unsafe_values(values: Vec<String>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for value in values {
        out.extend(split_allow_unsafe_csv(&value)?);
    }
    Ok(out)
}

/// `--allow-unsafe`, **read** rather than ignored: Go registers it as a pflag
/// `strings` (CSV, repeatable), and the value feeds
/// [`UnsafeFeatures`](crate::unsafe_features::UnsafeFeatures) on the run paths
/// and on both `verify` commands (Go's own `verify` consults the same persistent
/// flag through `ValidateServerConfig`/`ValidateClientConfig`: measured on
/// v0.71.0, `frps verify -c <exec cfg>` is rc 1 without it and rc 0 with
/// `--allow-unsafe TokenSourceExec`).
///
/// pflag's `strings` value **appends** on repetition and reads every occurrence
/// through [`split_allow_unsafe_csv`], so the parser is `.many()` plus a
/// flatten. Measured on v0.71.0: `frps verify -c <exec cfg> --allow-unsafe
/// WrongFeature --allow-unsafe TokenSourceExec` and the same argv with the two
/// values swapped are both rc 0 (and `--allow-unsafe Ignored,TokenSourceExec`
/// is rc 0), i.e. an unrelated value in any position does not cancel the
/// enabling one. Without `.many()` bpaf refuses the second occurrence with
/// ``argument `--allow-unsafe` cannot be used multiple times in this context``
/// — rc 1 on `frps verify`, `frpc verify` and `frpc -c` alike, which is the
/// divergence the repeated-flag rows of `frps/tests/cli_exit_codes.rs` and
/// `frpc/tests/cli_exit_codes.rs` pin.
pub(crate) fn allow_unsafe_parser() -> impl Parser<Vec<String>> {
    long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .many()
        .parse(allow_unsafe_values)
        .fallback(vec![])
}

/// `--allow-unsafe`, as an ignored persistent root flag. Same spellings as the
/// run-mode flag (hyphen plus the frp-rs underscore alias) and the same pflag
/// `strings` grammar ([`split_allow_unsafe_csv`]): repeats append, each
/// occurrence is read as one CSV record, and a malformed one is a flag error.
///
/// Go parses this persistent flag for **every** subcommand, so the ignored
/// surface must refuse what pflag refuses even though frp-rs drops the value:
/// measured on v0.71.0, `frpc tcp|status|reload -c <cfg> --allow-unsafe '"abc'`
/// is rc 1 `Error: invalid argument "\"abc" for "--allow-unsafe" flag: parse
/// error on line 1, column 5: extraneous or missing " in quoted-field`.
///
/// Only the subcommands that do not read it use this — `verify` reads
/// [`allow_unsafe_parser`] instead (Go's verify *does* consult the value).
pub(crate) fn ignored_allow_unsafe() -> impl Parser<Vec<String>> {
    long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .many()
        .parse(allow_unsafe_values)
}

/// `-v`/`--version`, as an ignored persistent root flag. Go registers it as a
/// persistent **rootCmd bool**, and only the root command's `RunE` prints the
/// version: measured on Go v0.71.0, `frpc tcp … --version` starts the proxy
/// exactly like the same argv without it. The value grammar is the shared
/// Go-bool one, so `--version=foo` is still the pflag value error.
pub(crate) fn ignored_version() -> impl Parser<bool> {
    go_bool_flag!("version", None, Some('v'), "Version of frpc").last()
}

/// The persistent root flags the config-reading subcommands that do not read
/// `--allow-unsafe` (`reload`/`status`/`stop`) did not declare: `-c` and
/// `--strict-config` are already fields of their own parsers.
pub(crate) fn ignored_admin_root_flags() -> impl Parser<()> {
    construct!(
        ignored_config_dir(),
        ignored_allow_unsafe(),
        ignored_version()
    )
    .map(|_| ())
}

/// [`ignored_admin_root_flags`] minus `--allow-unsafe`, for `frpc verify` — the
/// one config-reading subcommand that **reads** it ([`allow_unsafe_parser`],
/// because the load-path gate consults the value). The two parsers cannot
/// coexist in one `construct!`: bpaf would have to consume the same named
/// argument twice.
pub(crate) fn ignored_admin_root_flags_except_allow_unsafe() -> impl Parser<()> {
    construct!(ignored_config_dir(), ignored_version()).map(|_| ())
}

/// All five persistent rootCmd flags, accepted and ignored on the eight
/// single-proxy commands.
///
/// Go registers these on `rootCmd` (`cmd/frpc/sub/root.go`, `func init()`), so
/// pflag parses them for **every** subcommand — `frpc tcp --help` lists them
/// under `Global Flags` beside the command's own flags. The single-proxy
/// commands never read any of them: measured on Go v0.71.0, every shape in
/// `docs/developing.md` § CLI inputs (including `-c missing.toml`,
/// `--config-dir cDir` and a `-`-prefixed value after `-c`) reaches
/// `try to connect to server...` and connects to the probe port exactly like
/// the same argv with the flag removed. Acceptance is the parity, not the
/// value, so all five are dropped here.
///
/// Scalar flags go through [`Parser::last`] because a repeated pflag flag is
/// last-wins and never an error — measured on Go, the proxy still starts with
/// `-c a -c b`, `--config-dir a --config-dir b`, `--strict-config
/// --strict-config=false` and `--version --version`.
pub(crate) fn ignored_proxy_root_flags() -> impl Parser<()> {
    let config = config_arg().optional();
    let config_dir = ignored_config_dir();
    let strict_config = strict_config_parser().last();
    let allow_unsafe = ignored_allow_unsafe();
    let version = ignored_version();
    construct!(config, config_dir, strict_config, allow_unsafe, version).map(|_| ())
}
