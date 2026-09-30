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
  * any of the four RSS columns has ZERO readings (a stubbed/unavailable `ps`
    used to yield a full table of zeros printed next to "run completed");
  * either side completed no churn round trips or moved no steady bytes;
  * either side lost a steady stream (`failed_streams` > 0);
  * the two sides' achieved volume differs by more than SOAK_TRAFFIC_TOLERANCE
    (default 0.10) — both are paced identically, so a large gap means one side
    was not handed the same work and the comparison is not head-to-head.

An artifact with no trailing `summary` record is an incomplete run; that is a
convention the READER of the series applies, not something this script tests for
(a run killed by SIGKILL never reaches here at all).
"""

import json
import os
import statistics
import sys

COLUMNS = [
    ("frp_rs_frps_kb", "frp-rs frps"),
    ("frp_rs_frpc_kb", "frp-rs frpc"),
    ("go_frps_kb", "Go frps"),
    ("go_frpc_kb", "Go frpc"),
]


def load_json(path):
    """Last non-empty line of a traffic row, or None if unreadable/empty."""
    try:
        with open(path) as fh:
            lines = [l for l in fh.read().splitlines() if l.strip()]
        return json.loads(lines[-1]) if lines else None
    except Exception:
        return None


def read_rows(path):
    rows = []
    with open(path) as fh:
        for line in fh:
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
    except OSError as exc:
        print(f"error: cannot read artifact {path}: {exc}", file=sys.stderr)
        return 2

    samples = [r for r in rows if r.get("kind") == "sample"]
    meta = next((r for r in rows if r.get("kind") == "meta"), {})
    # Window for the first/last-hour means. max(1, ...) keeps the slice
    # non-empty when the sample interval is itself an hour or longer
    # (fmean([]) would raise).
    window = max(1, 3600 // max(1, int(meta.get("interval_s") or 45)))

    data = {
        key: block([r.get(key) for r in samples if r.get(key) is not None], window)
        for key, _ in COLUMNS
    }
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
    if aborted:
        problems.append(aborted)

    # A flat RSS line only means something if it was measured at all, and if load
    # was actually delivered on BOTH sides.
    for key, label in COLUMNS:
        if not data[key]:
            problems.append(f"no RSS measurements for {label}")
    for key, label in (("frp_rs_churn", "frp-rs"), ("go_churn", "Go")):
        d = traffic.get(key)
        if not d or not d.get("round_trips"):
            problems.append(f"{label} churn completed no echo round trips")
    for key, label in (("frp_rs_steady", "frp-rs"), ("go_steady", "Go")):
        d = traffic.get(key)
        if not d or not d.get("total_bytes"):
            problems.append(f"{label} steady stream moved no bytes")
        if d and d.get("failed_streams"):
            problems.append(f"{label} steady path lost {d['failed_streams']} stream(s)")

    # Achieved-volume reconciliation: both sides are offered the same paced
    # recipe, so a large gap means one side was given less work.
    try:
        tolerance = float(os.environ.get("SOAK_TRAFFIC_TOLERANCE") or "0.10")
    except ValueError:
        tolerance = 0.10
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
