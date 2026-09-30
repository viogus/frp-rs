#!/usr/bin/env python3
"""RSS-soak summary reader/close-out.

Prints the human table and computes the closing `summary` record. Kept in
`scripts/lib/` (not inline in `scripts/rss-soak.sh`) so the fixture
`scripts/tests/rss-soak-run-dir.sh` can drive the REAL reader against a
synthetic run directory: the bug that motivated the split is that this reader
cannot tell a traffic row written by this run from one left behind by an earlier
run in the same run directory.

Usage: rss-soak-summary.py <artifact> <aborted> <rs-churn> <go-churn>
                           <rs-steady> <go-steady> [<summary-out>]
Exit:  0 = completed, 3 = aborted (a reason was supplied or found, or the
       artifact does not close out), 2 = the artifact itself is unusable.

TWO MODES, and the difference is whether <summary-out> is given:

  * WITH <summary-out> — the producing run closing itself out. The record is
    written to that path (a file the caller appends to the artifact, see
    scripts/rss-soak.sh) and the artifact is opened READ-ONLY. Nothing this
    reader does can modify the artifact, so a re-read can never erase or forge a
    verdict.
  * WITHOUT <summary-out> — reading a finished artifact. Strictly read-only. The
    artifact MUST end with a parseable `summary` record; without one the run did
    not close out (a `kill -9` never reaches the writer) and the read reports the
    series incomplete (rc 3). Round 6 appended a fresh summary here, so a re-read
    of a killed run's artifact fabricated `"aborted": null` and printed
    "run completed" over an incomplete series, and a truncated trailing summary
    line was invisible to the monotonic rule.

Completeness is decided HERE and nowhere else. A series is aborted when any of
these holds:

  * the caller passed a reason (a process died mid-window, a signal, ...);
  * any of the four RSS columns has ZERO usable readings (a stubbed/unavailable
    `ps` used to yield a full table of zeros printed next to "run completed");
  * an RSS reading is outside 1..SOAK_RSS_CEILING_KB, or a column's readings are
    ALL IDENTICAL across the series — either shape can only come from `ps` not
    reporting real processes, and a fabricated flat line is exactly what this
    artifact must not present as evidence. The identical-values rule is
    deliberately strict: real RSS over a multi-hour series always moves (page
    cache, allocator behaviour), so a legitimately flat short validation is a
    cheap re-run, while a stubbed `ps` printing a constant is otherwise
    indistinguishable from the strongest possible result;
  * either side completed no churn round trips or moved no steady bytes;
  * either side's totals are below the absolute floor (MIN_CHURN_ROUND_TRIPS /
    MIN_STEADY_TOTAL_BYTES): a run that moved almost nothing measured almost
    nothing, even though it did measure it;
  * either side lost a steady stream (`failed_streams` > 0);
  * the two sides' achieved volume differs by more than the traffic tolerance
    (default 0.10) — both are paced identically, so a large gap means one side
    was not handed the same work and the comparison is not head-to-head. A
    tolerance must be a finite number in (0, 1): `nan` compares false against
    everything and used to disable this check while the run still reported
    `"aborted": null`, and a tolerance of 1 or more accepts any spread — because
    the spread is |a - b| / max(a, b), which is in [0, 1) for positive counts,
    `tolerance = 1` can never fail. Like the RSS ceiling, an artifact that
    records its own `traffic_tolerance` is judged by that value and not by the
    ambient `SOAK_TRAFFIC_TOLERANCE`. What counts is that the KEY IS PRESENT: a
    recorded value must be usable, and a recorded `null` (or `true`, a string, 0,
    a list, a 400-digit integer, ...) is present-but-unusable and aborts the run
    rather than falling through to the environment the reader happens to carry;
  * the recorded frp-rs and Go binary sha256 are equal, i.e. one implementation
    was run on both sides;
  * the samples do not cover the recorded window: `duration_s` / `interval_s` are
    read from `meta` and the last `elapsed_s` must be within two intervals of
    `duration_s`, with every gap between consecutive samples no larger than two
    intervals. A hand-written `"duration_s": 10800` next to two samples at 0 s
    and 45 s used to read "run completed".

A NOTE on what this reader refuses rather than guessing: a `meta` line that is
not valid JSON is a hard fault (rc 2), because every `meta` guard — the run dir,
the digests, the ceiling, the ports, the same-binary check — is read from that
single line and skipping it turns a real abort into "run completed". `NaN` and
`Infinity` are not JSON and are refused (json.loads accepts them by default, and
every comparison against a NaN is false, so they defeated every numeric guard).
A field read as a number but written as a string/array/object is a fault in the
artifact (rc 2) naming the field and the line, not a traceback.
"""

import json
import math
import os
import statistics
import sys

COLUMNS = [
    ("frp_rs_frps_kb", "frp-rs frps"),
    ("frp_rs_frpc_kb", "frp-rs frpc"),
    ("go_frps_kb", "Go frps"),
    ("go_frpc_kb", "Go frpc"),
]

# A reading outside this range cannot be a real process RSS here and is treated
# as no reading at all. The generator applies the same bound before writing
# (SOAK_RSS_CEILING_KB), so a well-formed artifact never contains one; the check
# is repeated here because the reader must also be safe against an artifact it
# did not produce.
#
# This is the FALLBACK for an artifact that does not record its own ceiling (an
# older series, or a hand-written one). A `meta` record carrying `rss_ceiling_kb`
# wins over both this and the ambient SOAK_RSS_CEILING_KB, so a published
# artifact is judged by the bound it was produced under and cannot read
# "completed" in one environment and rc 3 in another. That holds by KEY
# PRESENCE: a *recorded* but unusable ceiling (null, true, "0.6", [], {}, 0, -1)
# aborts instead of falling through, because falling through made the verdict a
# property of the reader again (byte-identical artifact: rc 3 under the default,
# "run completed" under SOAK_RSS_CEILING_KB=3000000).
#
# 1 GiB, down from the previous 100 GiB. The committed memory baselines put a
# real reading far below that: scripts/frp-stress/baselines/memory-Mac.jsonl
# records rss_kb_frps / rss_kb_frpc of 17328/16176 (idle, plain), 29776/28880
# (idle, encrypt), 17424/15440 (churn, plain) and 27312/17728 (churn, encrypt)
# — a 15.4-29.8 MB band, i.e. 1 GiB is still ~35x the largest ever observed
# here. It leaves room for a longer window and for a workload heavier than any
# committed baseline while refusing the bands a stub actually produced — a
# fabricated ~99.2 GiB band was accepted under the old default, and a ~84 TiB
# one was accepted with the knob raised to vacuity. See
# scripts/frp-stress/baselines/README.md for the full rationale.
DEFAULT_RSS_CEILING_KB = 1048576  # 1 GiB
# FALLBACK traffic tolerance for an artifact that does not record its own (an
# older series, or a hand-written one). A `meta` record carrying
# `traffic_tolerance` wins over both this and the ambient
# SOAK_TRAFFIC_TOLERANCE, for the same reason as the ceiling above: the allowed
# spread a run was produced under is part of its evidence, and re-reading the
# same artifact under a different SOAK_TRAFFIC_TOLERANCE used to flip its verdict
# (two byte-identical artifacts read "run completed" at 0.6 and rc 3 at 0.10).
# The recorded KEY must be present AND usable — a recorded `null` used to be
# indistinguishable from an absent key, so `{"traffic_tolerance": null}` still
# read "run completed" at 5% spread under an unset environment and rc 3 under
# `SOAK_TRAFFIC_TOLERANCE=0.01`. "Usable" is a finite number in the OPEN interval
# (0, 1): round 6 accepted `<= 1`, and because the spread is
# |a - b| / max(a, b) ∈ [0, 1) for positive counts a recorded `1` could never
# fail — a 90% one-sided gap read "run completed", `traffic tolerance: 1`.
DEFAULT_TRAFFIC_TOLERANCE = 0.10
# Absolute achieved-load floor. Far below what the default recipe produces in the
# shortest allowed window (60 s: ~2400 churn round trips, hundreds of MiB of
# steady traffic per side), so it only fires on a run that moved almost nothing.
MIN_CHURN_ROUND_TRIPS = 10
MIN_STEADY_TOTAL_BYTES = 1048576  # 1 MiB



def reject_constant(token):
    """Refuse `NaN`/`Infinity`/`-Infinity`, which `json.loads` accepts by default.

    Python's parser takes those three tokens; JSON does not have them. A NaN that
    gets into a numeric field defeats EVERY comparison in this file (`a > b`,
    `a < b` and `a == b` are all false against NaN), so `{"round_trips": NaN}`,
    `{"total_bytes": NaN}` and `{"mbps": NaN, ...}` each used to read
    "run completed" — and the record this script then emitted carried a bare
    `NaN`, which is not valid JSON for any strict consumer. Raising ValueError
    puts the line on the same "not valid JSON" path as any other unparseable
    line, which is a hard fault (rc 2), not a skipped row.
    """
    raise ValueError(f"{token} is not a JSON number; JSON has no NaN or Infinity")


def load_json(path):
    """Last non-empty line of a traffic row, or None if unreadable/empty/absent.

    Only an object is a traffic row. A line that is valid JSON but not an object
    (a bare `null`, `123`, `"x"` or `[1, 2]`) returns None, i.e. "MISSING", the
    same as an unreadable file: callers read the result with `.get`, and a
    non-dict would kill the reader with an AttributeError traceback (rc 1)
    instead of reporting the missing measurement as a problem (rc 3).

    A field this reader compares or adds (`round_trips`, `total_bytes`, ...) that
    is written as a string, array or object is NOT a missing measurement: it is a
    corrupt row, and it used to die as a TypeError traceback (rc 1) at
    `d["round_trips"] < MIN_CHURN_ROUND_TRIPS`. It raises ArtifactFieldError
    instead, so the run exits 2 naming the file, the field and its JSON type."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactEncodingError(
            f"{path}: not valid UTF-8 ({exc.reason} at byte offset {exc.start})"
        ) from exc
    lines = [line for line in text.split("\n") if line.strip()]
    if not lines:
        return None
    try:
        row = json.loads(lines[-1], parse_constant=reject_constant)
    except json.JSONDecodeError:
        return None
    except ValueError as exc:
        raise ArtifactFieldError(f"{path}: last line: {exc}") from exc
    if not isinstance(row, dict):
        return None
    require_numbers(row, TRAFFIC_NUMBER_FIELDS, path, "last")
    return row


class ArtifactError(Exception):
    """The artifact file cannot be read as the line-oriented JSON it must be.

    Raised instead of a bare traceback so `main` can exit 2 ("the artifact itself
    is unusable") with a message that names the artifact. Both subclasses below
    are faults in the file, not in this reader.
    """


class ArtifactEncodingError(ArtifactError):
    """A file in the run is not decodable as UTF-8.

    The writer is byte-preserving on purpose (see rss_soak_json_str in
    scripts/lib/rss-soak-run-dir.sh): it never rewrites a path, so a `run_dir`
    that is not valid UTF-8 is passed through raw and the line cannot be decoded.
    Failing here, loudly and with the byte offset, is the alternative to the two
    silent failure modes this module exists to avoid — substituting U+FFFD (a
    path that is not the one on disk) or skipping the line (losing run_dir, the
    digests, the ports and the same-binary guard from a run that still prints
    "run completed").
    """


class ArtifactLineTypeError(ArtifactError):
    """A line is valid JSON but not a JSON object.

    `read_rows` yields rows that `main` reads with `.get`, so a line holding
    `null`, a number, a string or an array used to die as an AttributeError
    traceback with rc 1 — the one outcome this reader must never produce, because
    an unusable artifact has to be visibly unusable (rc 2) and not a crash.
    """


class ArtifactFieldError(ArtifactError):
    """A field this reader consumes has the wrong JSON type (or is not JSON).

    Measured before this check existed: `load1: "3.1"` died in
    `statistics.fmean`, `time_wait: {"a": 1}` the same way, `interval_s: "abc"`
    in `int()`, `bin_sha256: "x"` in `.get`, `round_trips: "600"` in `<`,
    `total_bytes: [1]` in `<`. Every one of those is rc 1 with a traceback, where
    the usage string promises rc 2 for an artifact that cannot be used. The
    message names the file, the line and the field, so the fault is locatable
    without reproducing it.
    """


def json_type_name(value):
    """The word a reader expects for a JSON value's type, not Python's."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


# Fields of a traffic row that this reader compares against a floor or divides.
TRAFFIC_NUMBER_FIELDS = (
    "connections", "round_trips", "bytes", "total_bytes", "mbps", "failed_streams",
)


def type_phrase(value):
    """`a string` / `an array` — for the error messages below."""
    name = json_type_name(value)
    return ("an " if name[0] in "aeiou" else "a ") + name


def require_numbers(row, fields, path, line):
    """Raise ArtifactFieldError for a field that is present but not a number.

    Absent and explicit `null` are left alone: callers treat them as "not
    measured" (`MISSING`, or the `no RSS measurements` abort), which is the
    documented behaviour, not a type fault.
    """
    for field in fields:
        if field not in row or row[field] is None:
            continue
        value = row[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ArtifactFieldError(
                f"{path}: line {line}: field '{field}' is {type_phrase(value)}, "
                "not a number"
            )
    return row


def validate_row(row, path, line):
    """Type-check the fields `main` consumes, per record kind.

    Only the fields that are actually read are checked; the four RSS columns are
    deliberately left to `usable_rss`, whose "implausible reading ignored" abort
    (rc 3) names the column and the count and is the older, tested path for a
    stubbed `ps`.
    """
    kind = row.get("kind")
    if kind == "meta":
        require_numbers(row, ("duration_s", "interval_s"), path, line)
        for field in ("duration_s", "interval_s"):
            value = row.get(field)
            if value is not None and not (isinstance(value, (int, float)) and value > 0):
                raise ArtifactFieldError(
                    f"{path}: line {line}: field '{field}' is {value!r}, not a "
                    "positive number; the recorded window cannot be verified"
                )
        if "bin_sha256" in row and not isinstance(row["bin_sha256"], dict):
            raise ArtifactFieldError(
                f"{path}: line {line}: field 'bin_sha256' is "
                f"{type_phrase(row['bin_sha256'])}, not an object of digests"
            )
        if "run_dir" in row and not isinstance(row["run_dir"], str):
            raise ArtifactFieldError(
                f"{path}: line {line}: field 'run_dir' is "
                f"{type_phrase(row['run_dir'])}, not a string"
            )
    elif kind == "sample":
        for field in ("load1", "time_wait"):
            require_numbers(row, (field,), path, line)
        if row.get("elapsed_s") is None:
            raise ArtifactFieldError(
                f"{path}: line {line}: a sample row has no 'elapsed_s', so its place "
                "in the recorded window cannot be verified"
            )
        require_numbers(row, ("elapsed_s",), path, line)
    elif kind == "summary":
        aborted = row.get("aborted")
        if aborted is not None and not isinstance(aborted, str):
            raise ArtifactFieldError(
                f"{path}: line {line}: field 'aborted' is "
                f"{type_phrase(aborted)}, not a string or null"
            )


def read_rows(path):
    """(parsed rows, unparseable lines) for a JSON Lines artifact.

    A line that is not valid UTF-8 is NOT skipped: it raises
    ArtifactEncodingError naming the artifact and the byte offset, because the
    bytes that cannot be decoded are exactly the string values (run_dir, binary
    paths, host name) whose silent loss this reader must not accept.

    A line that IS valid JSON but not an object is not skipped either: it raises
    ArtifactLineTypeError naming the artifact and the 1-based line number, since
    a file carrying one is corrupt rather than merely noisy.

    A line that is not valid JSON at all is RETURNED to the caller as
    `(number, text, error, is_last)` instead of being skipped: skipping it used to
    drop the whole `meta` record (one BOM turns the meta line — and with it the
    run dir, the digests, the ceiling and the same-binary guard — into an
    unparseable one) and the run still read "run completed". `is_last` marks the
    artifact's final non-empty line, which is where the closing summary record
    belongs: `main` calls an unparseable LAST line an unclosed series (rc 3) and
    any other unparseable line a corrupt artifact (rc 2).
    """
    rows = []
    bad = []
    last_number = 0
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactEncodingError(
            f"{path}: not valid UTF-8 ({exc.reason} at byte offset {exc.start}); "
            "the artifact was written byte-exactly, so a run dir or binary path "
            "in it is not a valid UTF-8 string"
        ) from exc
    # Split on "\n" only. str.splitlines() also breaks on U+000B/U+000C/U+0085/
    # U+2028/U+2029, which are legal unescaped bytes inside a JSON string here
    # (the writer only escapes 0x01..0x1F), so it would shred a line whose run
    # dir contained one.
    for number, line in enumerate(text.split("\n"), start=1):
        line = line.strip()
        if not line:
            continue
        last_number = number
        try:
            row = json.loads(line, parse_constant=reject_constant)
        except (json.JSONDecodeError, ValueError) as exc:
            # (line number, text, error, is it the artifact's LAST line?)
            bad.append((number, line, str(exc), False))
            continue
        if not isinstance(row, dict):
            raise ArtifactLineTypeError(
                f"{path}: line {number} is a JSON {json_type_name(row)}, not an "
                "object; the artifact itself is unusable"
            )
        validate_row(row, path, number)
        rows.append(row)
    # Flag the final line: a run killed while the closing record was being
    # written leaves an unterminated last line, and with `sort_keys=True` the cut
    # can land BEFORE `"kind"` — so "looks like a summary" cannot be the only
    # test. Any unparseable LAST line means the artifact never closed out.
    bad = [b[:3] + (b[0] == last_number,) for b in bad]
    return rows, bad


def block(vals, window):
    if not vals:
        return None
    return {
        "first": vals[0], "last": vals[-1], "min": min(vals), "max": max(vals),
        "mean": round(statistics.fmean(vals), 1),
        "first_hour_mean": round(statistics.fmean(vals[:window]), 1),
        "last_hour_mean": round(statistics.fmean(vals[-window:]), 1),
        "growth_pct_first_to_last": round(100.0 * (vals[-1] - vals[0]) / vals[0], 1) if vals[0] else None,
    }


def trend(rows, key):
    """Least-squares slope + first/last-quarter means, so "no growth" is a
    computed statement about the series rather than an eyeball one."""
    pts = [(r.get("elapsed_s"), r.get(key)) for r in rows if r.get(key) is not None]
    if len(pts) < 3:
        return None
    xs = [float(p[0]) for p in pts]
    ys = [float(p[1]) for p in pts]
    n = len(xs)
    mx = statistics.fmean(xs)
    my = statistics.fmean(ys)
    denom = sum((x - mx) ** 2 for x in xs)
    slope = 0.0 if denom == 0 else sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom
    quarter = max(1, n // 4)
    q_first = statistics.fmean(ys[:quarter])
    q_last = statistics.fmean(ys[-quarter:])
    return {
        "n": n,
        "slope_kb_per_hour": round(slope * 3600.0, 2),
        "first_quarter_mean": round(q_first, 1),
        "last_quarter_mean": round(q_last, 1),
        "last_vs_first_quarter_pct": round(100.0 * (q_last - q_first) / q_first, 1) if q_first else None,
        "monotonic_nondecreasing": all(ys[i] >= ys[i - 1] for i in range(1, n)),
    }


def fmt(value):
    """Never print a fabricated reading: a missing measurement is '-', not 0."""
    return "-" if value is None else str(value)


def write_summary_line(summary_out, summary):
    """Write the closing summary record to a file the CALLER owns.

    Deliberately not the artifact: this reader must never write into an artifact
    it is reading, because the same entry point reads finished artifacts. Round 6
    appended the record here, so re-reading an artifact whose run was killed
    before it closed out (`kill -9` — no summary line at all) added
    `"aborted": null` and printed "run completed" over an incomplete series, and
    re-reading one with a trailing unterminated line glued a second verdict onto
    it. scripts/rss-soak.sh appends this file to the artifact, which is the only
    writer the artifact has.
    """
    with open(summary_out, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(summary, sort_keys=True) + "\n")


def trailing_summary(rows):
    """The last `summary` row in order, or None. Used for the sticky-abort rule
    and to decide whether the artifact closed out at all."""
    for row in reversed(rows):
        if row.get("kind") == "summary":
            return row
    return None


def main(argv):
    path, aborted = argv[1], argv[2]
    traffic_paths = {
        "frp_rs_churn": argv[3],
        "go_churn": argv[4],
        "frp_rs_steady": argv[5],
        "go_steady": argv[6],
    }
    # Close-out mode (the producing run) vs verify mode (reading a finished
    # artifact). See the module docstring: without this the reader cannot tell a
    # run that closed out from one that never did.
    summary_out = argv[7] if len(argv) > 7 else None

    try:
        rows, bad_lines = read_rows(path)
    except ArtifactError as exc:
        print(f"error: cannot read artifact {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot read artifact {path}: {exc}", file=sys.stderr)
        return 2

    # An unparseable line is never skipped. A line that looks like the closing
    # summary is a run that was cut off mid-record (incomplete, rc 3); anything
    # else is a corrupt artifact (rc 2) — notably a BOM, which turns the whole
    # `meta` record into an unparseable line and used to disappear along with
    # every guard read from it.
    # The LAST line is special: it is where the closing summary record lives, so
    # an unparseable one means the artifact never closed out (a `kill -9`
    # mid-write, or a hand-edited tail) and the series is incomplete. Any OTHER
    # unparseable line is a corrupt artifact: a BOM on the `meta` line, a torn
    # sample — those lose guards that must not be lost silently.
    #
    # The test is POSITION, not content: the closing record is written by
    # `json.dumps(summary, sort_keys=True)`, whose field order is alphabetical, so
    # the real line starts `{"aborted": ...` and a shape test for
    # `{"kind":"summary"` would miss every record this harness actually writes.
    # A cut-off record always leaves an unparseable last line, so position is
    # both simpler and stricter.
    unparsed_last = []
    for number, text, error, is_last in bad_lines:
        if is_last:
            unparsed_last.append((number, error))
        else:
            print(
                f"error: cannot read artifact {path}: line {number} is not valid JSON "
                f"({error}); the artifact itself is unusable",
                file=sys.stderr,
            )
            return 2

    samples = [r for r in rows if r.get("kind") == "sample"]
    meta = next((r for r in rows if r.get("kind") == "meta"), {})

    # The artifact's OWN recorded ceiling wins over the ambient environment: the
    # bound a run was produced under is part of its evidence, and re-reading the
    # same artifact under a different SOAK_RSS_CEILING_KB must not flip its
    # verdict (the same file used to read "completed" here and rc 3
    # "implausible RSS reading(s) ignored" there). What counts is that the KEY IS
    # PRESENT, not that its value happens to be usable: a *recorded* unusable
    # ceiling (null, true, "0.6", [], {}, 0, -1) aborts, because falling through
    # to the environment there made the verdict a property of the reader again
    # (byte-identical artifact: rc 3 under the default, "run completed" under
    # SOAK_RSS_CEILING_KB=3000000). Env, then the default, is only the fallback
    # for an artifact that records NO key.
    records_ceiling = "rss_ceiling_kb" in meta

    def usable_ceiling(value):
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    recorded_ceiling = meta.get("rss_ceiling_kb")
    if usable_ceiling(recorded_ceiling):
        rss_ceiling = recorded_ceiling
        ceiling_source = "artifact meta"
    elif records_ceiling:
        rss_ceiling = DEFAULT_RSS_CEILING_KB
        ceiling_source = "artifact meta, unusable"
    else:
        env_ceiling = os.environ.get("SOAK_RSS_CEILING_KB")
        ceiling_source = "environment" if env_ceiling else "default"
        try:
            rss_ceiling = int(env_ceiling or DEFAULT_RSS_CEILING_KB)
        except ValueError:
            rss_ceiling = DEFAULT_RSS_CEILING_KB
            ceiling_source = "default"
        if rss_ceiling <= 0:
            rss_ceiling = DEFAULT_RSS_CEILING_KB
            ceiling_source = "default"

    # Window for the first/last-hour means. max(1, ...) keeps the slice
    # non-empty when the sample interval is itself an hour or longer
    # (fmean([]) would raise). interval_s is type-checked in validate_row, so
    # `int()`/`//` cannot see a string here.
    raw_interval = meta.get("interval_s")
    interval_s = float(raw_interval) if raw_interval is not None else 45.0
    window = max(1, int(3600 // max(1.0, interval_s)))

    def usable_rss(value):
        """A reading that could be a real process RSS, else None. Rejects a bool
        (JSON `true`), a non-integer, and anything outside 1..ceiling: a stubbed
        or misparsing `ps` that prints 0, a constant, or a huge number must not
        end up as published evidence."""
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value if 0 < value <= rss_ceiling else None

    rss_values = {}
    rejected = {}
    data = {}
    for key, _ in COLUMNS:
        vals = []
        bad = 0
        for r in samples:
            raw = r.get(key)
            if raw is None:
                continue
            v = usable_rss(raw)
            if v is None:
                bad += 1
            else:
                vals.append(v)
        rss_values[key] = vals
        rejected[key] = bad
        data[key] = block(vals, window)
    loads = [r.get("load1") for r in samples if r.get("load1") is not None]
    waits = [r.get("time_wait") for r in samples if r.get("time_wait") is not None]

    traffic = {}
    for name, p in traffic_paths.items():
        try:
            d = load_json(p)
        except ArtifactError as exc:
            print(f"error: cannot read artifact {exc}", file=sys.stderr)
            return 2
        if d:
            traffic[name] = {
                "connections": d.get("connections"),
                "round_trips": d.get("round_trips"),
                "bytes": d.get("bytes"),
                "total_bytes": d.get("total_bytes"),
                "mbps": d.get("mbps"),
                "failed_streams": d.get("failed_streams"),
            }
        else:
            traffic[name] = None

    problems = []
    # The verdict is monotonic: an artifact that already carries an aborted
    # summary stays aborted. Without this a later close-out with healthy traffic
    # rows (or with the faulty rows trimmed) would append "run completed" behind
    # the death verdict, and a consumer that takes the last summary is misled.
    # The generator clears $OUT before the window opens, so a normal run sees no
    # prior summary; only a re-read/re-run over a live artifact can see this.
    prior_summary = trailing_summary(rows)
    if prior_summary is not None and prior_summary.get("aborted"):
        problems.append(
            f"a previous summary already aborted this artifact ({prior_summary['aborted']})"
        )
    if aborted:
        problems.append(aborted)

    # Verify mode (no <summary-out>) reads a FINISHED artifact: one that does not
    # end with a parseable summary never closed out, and "no summary" used to be
    # silently repaired by appending a fresh `"aborted": null` record. A trailing
    # line that looks like a summary but does not parse was cut off mid-record by
    # the kill; either way the series is incomplete, not completed.
    if summary_out is None:
        if unparsed_last:
            for number, error in unparsed_last:
                problems.append(
                    f"the artifact's last line is unparseable "
                    f"(line {number}: {error}); the artifact did not close out, "
                    "so the series is incomplete"
                )
        elif prior_summary is None:
            problems.append(
                "the artifact carries no closing summary record; the run did not "
                "close out, so the series is incomplete"
            )
    elif unparsed_last:
        # Close-out mode over an artifact whose last line is an unparseable
        # summary fragment: the previous verdict is unreadable, so a verdict
        # derived now could contradict it silently. Sticky until a human looks.
        for number, error in unparsed_last:
            problems.append(
                f"the artifact's last line is unparseable "
                f"(line {number}: {error}); the artifact did not close out, "
                "so the series is incomplete"
            )

    if records_ceiling and not usable_ceiling(recorded_ceiling):
        problems.append(
            f"the artifact records an unusable RSS ceiling ({recorded_ceiling!r}); "
            "a usable one is a positive integer, so the plausibility bound cannot "
            "be trusted"
        )

    # The recorded window has to match the samples on disk. A hand-written
    # `"duration_s": 10800` beside two samples at 0 s and 45 s used to read "run
    # completed": every per-column check passed because each column had two
    # distinct readings. Both numbers are named so the mismatch is checkable.
    recorded_duration = meta.get("duration_s")
    interval_for_check = meta.get("interval_s")
    if recorded_duration is None or not (isinstance(recorded_duration, (int, float))
                                        and not isinstance(recorded_duration, bool)
                                        and recorded_duration > 0):
        problems.append(
            f"the artifact does not record a usable duration_s "
            f"({meta.get('duration_s')!r}), so its sample coverage cannot be verified"
        )
    elif interval_for_check is None:
        problems.append(
            "the artifact does not record an interval_s, so its sample coverage "
            "cannot be verified"
        )
    elif samples:
        interval = float(interval_for_check)
        elapsed = [s["elapsed_s"] for s in samples]
        last = elapsed[-1]
        if not (recorded_duration - 2 * interval <= last <= recorded_duration + 2 * interval):
            problems.append(
                f"the samples cover {last}s of a recorded {recorded_duration}s window "
                f"(interval {interval_for_check}s); the series is incomplete"
            )
        if elapsed != sorted(elapsed):
            problems.append(
                f"the sample elapsed_s values are not in order (last {last}, "
                f"{len(elapsed)} samples); the series is not a time series"
            )
        gaps = [b - a for a, b in zip(elapsed, elapsed[1:])]
        if any(gap > 2 * interval for gap in gaps):
            problems.append(
                f"the samples are not spaced at the recorded interval_s "
                f"({interval_for_check}s): the largest gap between consecutive samples "
                f"is {max(gaps)}s, so the series has holes"
            )

    # A flat RSS line only means something if it was measured, plausibly, and
    # more than once.
    for key, label in COLUMNS:
        vals = rss_values[key]
        if rejected[key]:
            problems.append(
                f"{label}: {rejected[key]} implausible RSS reading(s) ignored "
                f"(outside 1..{rss_ceiling} KB)"
            )
        if not vals:
            problems.append(f"no RSS measurements for {label}")
        elif len(vals) < 2:
            problems.append(f"{label} has only {len(vals)} RSS reading(s); one reading cannot show stability")
        elif len(set(vals)) == 1:
            problems.append(
                f"{label} reported the identical RSS ({vals[0]} KB) in all {len(vals)} samples; "
                "real RSS moves, so this reads as a column that was not measured"
            )

    # Load was actually delivered on BOTH sides, above an absolute floor: a run
    # that moved almost nothing measured almost nothing.
    for key, label in (("frp_rs_churn", "frp-rs"), ("go_churn", "Go")):
        d = traffic.get(key)
        if not d or not d.get("round_trips"):
            problems.append(f"{label} churn completed no echo round trips")
        elif d["round_trips"] < MIN_CHURN_ROUND_TRIPS:
            problems.append(
                f"{label} churn completed only {d['round_trips']} round trips "
                f"(< {MIN_CHURN_ROUND_TRIPS}); too little traffic to compare"
            )
    for key, label in (("frp_rs_steady", "frp-rs"), ("go_steady", "Go")):
        d = traffic.get(key)
        if not d or not d.get("total_bytes"):
            problems.append(f"{label} steady stream moved no bytes")
        elif d["total_bytes"] < MIN_STEADY_TOTAL_BYTES:
            problems.append(
                f"{label} steady stream moved only {d['total_bytes']} bytes "
                f"(< {MIN_STEADY_TOTAL_BYTES}); too little traffic to compare"
            )
        if d and d.get("failed_streams"):
            problems.append(f"{label} steady path lost {d['failed_streams']} stream(s)")

    # One implementation on both sides is not a comparison. The generator refuses
    # this before the window opens; the check is repeated so a hand-edited
    # artifact cannot present it either.
    bins = meta.get("bin_sha256") or {}
    for rs_key, go_key, rs_label, go_label in (
        ("rs_frps", "go_frps", "frp-rs frps", "Go frps"),
        ("rs_frpc", "go_frpc", "frp-rs frpc", "Go frpc"),
    ):
        a, b = bins.get(rs_key), bins.get(go_key)
        if a and b and a == b:
            problems.append(
                f"{rs_label} and {go_label} are the same binary (sha256 {a}); "
                "this is not a head-to-head comparison"
            )

    # Achieved-volume reconciliation: both sides are offered the same paced
    # recipe, so a large gap means one side was given less work. Exactly like the
    # ceiling above, the artifact's OWN recorded tolerance wins over the ambient
    # environment: the allowed spread a run was produced under is part of its
    # evidence, and a re-read under a different SOAK_TRAFFIC_TOLERANCE must not
    # flip its verdict. What counts is that the KEY IS PRESENT, not that its value
    # is truthy: a recorded tolerance must be usable (a finite number in (0, 1),
    # the same contract the writer enforces), and `null`, `true`, a string, 0, 1
    # or a 400-digit integer is present-but-unusable and aborts — never a
    # fall-through to the ambient environment, which would make the verdict a
    # property of the reader again. Only an artifact that records NO key falls
    # back to the environment, then to the default.
    #
    # The interval is OPEN: the spread is |a - b| / max(a, b) ∈ [0, 1) for
    # positive counts, so a recorded 1 could never fail (a 90% one-sided gap read
    # "run completed", `traffic tolerance: 1`).
    records_tolerance = "traffic_tolerance" in meta
    recorded_tolerance = meta.get("traffic_tolerance")
    # float() rather than the value itself so an integer too large for a float
    # (a 400-digit JSON integer) is "unusable", not an OverflowError traceback.
    recorded_value = None
    if isinstance(recorded_tolerance, (int, float)) and not isinstance(recorded_tolerance, bool):
        try:
            recorded_value = float(recorded_tolerance)
        except OverflowError:
            recorded_value = None
    if recorded_value is not None and math.isfinite(recorded_value) and 0 < recorded_value < 1:
        tolerance = recorded_value
        tolerance_source = "artifact meta"
    elif records_tolerance:
        problems.append(
            f"the artifact records an unusable traffic tolerance "
            f"({recorded_tolerance!r}); a usable one is a finite number in (0, 1), "
            "so the achieved-load reconciliation cannot be trusted"
        )
        # Display/recording fallback only, and deliberately NOT the environment:
        # the run has already aborted, and consulting the ambient variable here
        # would let the reader's environment change which artifact reads aborted
        # and why.
        tolerance = DEFAULT_TRAFFIC_TOLERANCE
        tolerance_source = "artifact meta, unusable"
    else:
        env_tolerance = os.environ.get("SOAK_TRAFFIC_TOLERANCE")
        tolerance_raw = env_tolerance or str(DEFAULT_TRAFFIC_TOLERANCE)
        tolerance_source = "environment" if env_tolerance else "default"
        tolerance = None
        try:
            parsed = float(tolerance_raw)
            if math.isfinite(parsed) and 0 < parsed < 1:
                tolerance = parsed
        except ValueError:
            pass
        if tolerance is None:
            problems.append(
                f"SOAK_TRAFFIC_TOLERANCE is not a finite number in (0, 1) ({tolerance_raw!r}); "
                "the achieved-load reconciliation cannot be trusted"
            )
            tolerance = DEFAULT_TRAFFIC_TOLERANCE  # display/recording fallback only; the run has aborted
    achieved_equality = {}
    for key_rs, key_go, field, label in (
        ("frp_rs_churn", "go_churn", "round_trips", "churn round trips"),
        ("frp_rs_steady", "go_steady", "total_bytes", "steady bytes"),
    ):
        a = (traffic.get(key_rs) or {}).get(field)
        b = (traffic.get(key_go) or {}).get(field)
        if a and b:
            spread = abs(a - b) / max(a, b)
            achieved_equality[label] = {
                "frp_rs": a, "go": b, "spread": round(spread, 4), "tolerance": tolerance,
            }
            if spread > tolerance:
                problems.append(
                    f"achieved {label} differs by {spread * 100:.1f}% "
                    f"(frp-rs {a} vs Go {b}, tolerance {tolerance * 100:.0f}%)"
                )
        else:
            achieved_equality[label] = {"frp_rs": a, "go": b, "spread": None, "tolerance": tolerance}

    aborted = "; ".join(problems)

    summary = {
        "kind": "summary",
        "samples": len(samples),
        "aborted": aborted or None,
        "run_dir": meta.get("run_dir"),
        "rss_ceiling_kb": rss_ceiling,
        "rss_ceiling_source": ceiling_source,
        "traffic_tolerance": tolerance,
        "traffic_tolerance_source": tolerance_source,
        "load1": {"min": min(loads), "max": max(loads), "mean": round(statistics.fmean(loads), 2)} if loads else None,
        "time_wait": {"min": min(waits), "max": max(waits), "mean": round(statistics.fmean(waits), 1)} if waits else None,
        "traffic": traffic,
        "achieved_equality": achieved_equality,
        "rss_kb": data,
        "trend": {key: trend(samples, key) for key, _ in COLUMNS},
    }
    if summary_out is not None:
        try:
            write_summary_line(summary_out, summary)
        except OSError as exc:
            print(f"error: cannot write the summary record to {summary_out}: {exc}",
                  file=sys.stderr)
            return 2

    print("=== RSS soak summary (KB) ===")
    print(f"{'process':<12} {'first':>8} {'last':>8} {'min':>8} {'max':>8} {'mean':>9} {'1st-h mean':>11} {'last-h mean':>12}")
    for key, label in COLUMNS:
        b = data[key]
        if not b:
            print(f"{label:<12} {'-':>8} {'-':>8} {'-':>8} {'-':>8} {'-':>9} {'-':>11} {'-':>12}   NO READINGS")
            continue
        print(f"{label:<12} {fmt(b.get('first')):>8} {fmt(b.get('last')):>8} {fmt(b.get('min')):>8} "
              f"{fmt(b.get('max')):>8} {fmt(b.get('mean')):>9} {fmt(b.get('first_hour_mean')):>11} "
              f"{fmt(b.get('last_hour_mean')):>12}")
    print(f"RSS ceiling: {rss_ceiling} KB (from {ceiling_source})")
    print(f"traffic tolerance: {tolerance:g} (from {tolerance_source})")
    print(f"samples: {len(samples)}; " + (f"ABORTED: {aborted}" if aborted else "run completed"))
    if summary["load1"]:
        print(f"host load1: min {summary['load1']['min']} mean {summary['load1']['mean']} max {summary['load1']['max']}")
    if summary["time_wait"]:
        print(f"TIME_WAIT (host-wide): min {summary['time_wait']['min']} "
              f"mean {summary['time_wait']['mean']} max {summary['time_wait']['max']}")
    for name, d in traffic.items():
        if d:
            print(f"traffic {name}: round_trips={d.get('round_trips')} bytes={d.get('bytes')} "
                  f"total_bytes={d.get('total_bytes')} mbps={d.get('mbps')} "
                  f"failed_streams={d.get('failed_streams')}")
        else:
            print(f"traffic {name}: MISSING")
    for label, e in achieved_equality.items():
        if e["spread"] is None:
            print(f"achieved {label}: frp-rs={e['frp_rs']} go={e['go']} (not comparable)")
        else:
            print(f"achieved {label}: frp-rs={e['frp_rs']} go={e['go']} spread={e['spread'] * 100:.1f}% "
                  f"(tolerance {e['tolerance'] * 100:.0f}%)")
    for key, label in COLUMNS:
        t = summary["trend"][key]
        if t:
            print(f"trend {label}: slope={t['slope_kb_per_hour']} KB/h, "
                  f"first-quarter mean={t['first_quarter_mean']} last-quarter mean={t['last_quarter_mean']} "
                  f"({t['last_vs_first_quarter_pct']}%), monotonic non-decreasing={t['monotonic_nondecreasing']}")
    return 3 if aborted else 0


if __name__ == "__main__":
    if len(sys.argv) not in (7, 8):
        print("usage: rss-soak-summary.py <artifact> <aborted> <rs-churn> <go-churn> "
              "<rs-steady> <go-steady> [<summary-out>]",
              file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv))
