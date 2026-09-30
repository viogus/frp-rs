#!/usr/bin/env python3
"""RSS-soak summary writer.

Appends the closing `summary` record to the soak artifact and prints the human
table. Kept in `scripts/lib/` (not inline in `scripts/rss-soak.sh`) so the
fixture `scripts/tests/rss-soak-run-dir.sh` can drive the REAL reader against a
synthetic run directory: the bug that motivated the split is that this reader
cannot tell a traffic row written by this run from one left behind by an earlier
run in the same run directory.

Usage: rss-soak-summary.py <artifact> <aborted> <rs-churn> <go-churn> <rs-steady> <go-steady>
Exit:  0 = completed, 3 = aborted (a reason was supplied or found),
       2 = the artifact itself is unusable.

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
    was not handed the same work and the comparison is not head-to-head. The
    tolerance must be a finite positive number: `nan` compares false against
    everything and used to disable this check while the run still reported
    `"aborted": null`. Like the RSS ceiling, an artifact that records its own
    `traffic_tolerance` is judged by that value and not by the ambient
    `SOAK_TRAFFIC_TOLERANCE`;
  * the recorded frp-rs and Go binary sha256 are equal, i.e. one implementation
    was run on both sides.

An artifact with no trailing `summary` record is an incomplete run; that is a
convention the READER of the series applies, not something this script tests for
(a run killed by SIGKILL never reaches here at all).
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
# "completed" in one environment and rc 3 in another.
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
DEFAULT_TRAFFIC_TOLERANCE = 0.10
# Absolute achieved-load floor. Far below what the default recipe produces in the
# shortest allowed window (60 s: ~2400 churn round trips, hundreds of MiB of
# steady traffic per side), so it only fires on a run that moved almost nothing.
MIN_CHURN_ROUND_TRIPS = 10
MIN_STEADY_TOTAL_BYTES = 1048576  # 1 MiB



def load_json(path):
    """Last non-empty line of a traffic row, or None if unreadable/empty."""
    try:
        with open(path) as fh:
            lines = [l for l in fh.read().splitlines() if l.strip()]
        return json.loads(lines[-1]) if lines else None
    except Exception:
        return None


class ArtifactEncodingError(Exception):
    """The artifact file is not decodable as UTF-8.

    The writer is byte-preserving on purpose (see rss_soak_json_str in
    scripts/lib/rss-soak-run-dir.sh): it never rewrites a path, so a `run_dir`
    that is not valid UTF-8 is passed through raw and the line cannot be decoded.
    Failing here, loudly and with the byte offset, is the alternative to the two
    silent failure modes this module exists to avoid — substituting U+FFFD (a
    path that is not the one on disk) or skipping the line (losing run_dir, the
    digests, the ports and the same-binary guard from a run that still prints
    "run completed").
    """


def read_rows(path):
    """Parsed JSON lines, skipping lines that are valid UTF-8 but not JSON.

    A line that is not valid UTF-8 is NOT skipped: it raises
    ArtifactEncodingError naming the artifact and the byte offset, because the
    bytes that cannot be decoded are exactly the string values (run_dir, binary
    paths, host name) whose silent loss this reader must not accept.
    """
    rows = []
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
    for line in text.split("\n"):
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


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


def main(argv):
    path, aborted = argv[1], argv[2]
    traffic_paths = {
        "frp_rs_churn": argv[3],
        "go_churn": argv[4],
        "frp_rs_steady": argv[5],
        "go_steady": argv[6],
    }

    try:
        rows = read_rows(path)
    except ArtifactEncodingError as exc:
        print(f"error: cannot read artifact {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot read artifact {path}: {exc}", file=sys.stderr)
        return 2

    samples = [r for r in rows if r.get("kind") == "sample"]
    meta = next((r for r in rows if r.get("kind") == "meta"), {})
    # Window for the first/last-hour means. max(1, ...) keeps the slice
    # non-empty when the sample interval is itself an hour or longer
    # (fmean([]) would raise).
    window = max(1, 3600 // max(1, int(meta.get("interval_s") or 45)))

    # The artifact's OWN recorded ceiling wins over the ambient environment: the
    # bound a run was produced under is part of its evidence, and re-reading the
    # same artifact under a different SOAK_RSS_CEILING_KB must not flip its
    # verdict (the same file used to read "completed" here and rc 3
    # "implausible RSS reading(s) ignored" there). Env, then the default, is only
    # the fallback for an artifact that records none.
    recorded_ceiling = meta.get("rss_ceiling_kb")
    if (isinstance(recorded_ceiling, int) and not isinstance(recorded_ceiling, bool)
            and recorded_ceiling > 0):
        rss_ceiling = recorded_ceiling
        ceiling_source = "artifact meta"
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
        d = load_json(p)
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
    # summary stays aborted. The reader re-derives `aborted` from its inputs and
    # APPENDS a summary, so without this a later invocation with healthy traffic
    # rows (or with the faulty rows trimmed) would append "run completed" behind
    # the death verdict, and a consumer that takes the last summary is misled.
    # The generator clears $OUT before the window opens, so a normal run is
    # unaffected; only a re-read/re-run over a live artifact can see this.
    for prior in rows:
        if prior.get("kind") == "summary" and prior.get("aborted"):
            problems.append(
                f"a previous summary already aborted this artifact ({prior['aborted']})"
            )
    if aborted:
        problems.append(aborted)

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
    # flip its verdict. Env, then the default, is only the fallback for an
    # artifact that records none. A recorded tolerance that is present but
    # unusable is itself an abort rather than a fall-through to the environment —
    # otherwise such an artifact's verdict would again depend on who reads it.
    recorded_tolerance = meta.get("traffic_tolerance")
    # float() rather than the value itself so an integer too large for a float
    # (a 400-digit JSON integer) is "unusable", not an OverflowError traceback.
    recorded_value = None
    if isinstance(recorded_tolerance, (int, float)) and not isinstance(recorded_tolerance, bool):
        try:
            recorded_value = float(recorded_tolerance)
        except OverflowError:
            recorded_value = None
    if recorded_value is not None and math.isfinite(recorded_value) and recorded_value > 0:
        tolerance = recorded_value
        tolerance_source = "artifact meta"
    else:
        if recorded_tolerance is not None:
            problems.append(
                f"the artifact records an unusable traffic tolerance "
                f"({recorded_tolerance!r}); the achieved-load reconciliation "
                "cannot be trusted"
            )
        env_tolerance = os.environ.get("SOAK_TRAFFIC_TOLERANCE")
        tolerance_raw = env_tolerance or str(DEFAULT_TRAFFIC_TOLERANCE)
        tolerance_source = "environment" if env_tolerance else "default"
        tolerance = None
        try:
            parsed = float(tolerance_raw)
            if math.isfinite(parsed) and parsed > 0:
                tolerance = parsed
        except ValueError:
            pass
        if tolerance is None:
            problems.append(
                f"SOAK_TRAFFIC_TOLERANCE is not a finite positive number ({tolerance_raw!r}); "
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
    with open(path, "a") as fh:
        fh.write(json.dumps(summary, sort_keys=True) + "\n")

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
    if len(sys.argv) != 7:
        print("usage: rss-soak-summary.py <artifact> <aborted> <rs-churn> <go-churn> <rs-steady> <go-steady>",
              file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv))
