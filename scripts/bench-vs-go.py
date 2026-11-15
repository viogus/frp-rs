#!/usr/bin/env python3
# =============================================================================
# bench-vs-go.py — interleaved throughput comparison of frp-rs against the
# official Go frp release, on one host, with an explicit stability verdict.
#
# Why this exists: matrices that measured all reps of one arm and then all reps
# of the other disagreed with each other by 15-20% on the same tree, and single
# pairs of numbers were quoted to users as wins and losses. Two things fix that
# here: the arms alternate *inside* every block (ABBA, orientation flipped every
# block), and a row is only called a win or a loss when every block ratio lands
# on the same side of 1.0 — otherwise it prints `indistinguishable`, which is a
# result, not a failure.
#
# The run is self-describing: it prints the commit, the sha256 of both
# implementations' binaries and the host, and refuses to run if the two arms
# resolve to the same binary (a self-comparison would read as parity).
#
# WARNING: it `pkill -9`s frps/frpc/abbench between reps. Run it on a dedicated
# bench host, not on a machine serving traffic, and not on a machine where
# something else is using ports 19054/19056/19100/19102/19103.
#
# Usage (on a Linux bench host; loopback, no privileges needed):
#   python3 scripts/bench-vs-go.py                       # full matrix, 512 MiB
#   MIB=1024 BLOCKS=4 python3 scripts/bench-vs-go.py     # slower, tighter
#   SHAPES='tcp true true;kcp true true' python3 scripts/bench-vs-go.py
#   FLOWS='1' python3 scripts/bench-vs-go.py
#
# Environment:
#   RS       dir holding frp-rs `frps`/`frpc`        (default target/release)
#   GO       dir holding Go frp `frps`/`frpc`        (use scripts/download-go-frp.sh)
#   BENCH    the stream generator, default /root/bench/abbench
#            (`abbench stream <port> <MiB> <flows>`, `abbench sink <port>`)
#   MIB      payload per rep, default 512
#   BLOCKS   ABBA blocks per row, default 3 (2 samples per arm per block)
#   FLOWS    flow counts to test, default "1 4"
#   SHAPES   semicolon list of `<proto> <tls> <tcpMux>`, default the matrix below
#   REPO     repo root recorded in the header, default the script's parent
#
# Exit codes: 0 every row measured every block, 1 some samples or rows were
# dropped (the table still prints, with `dropped=`), 2 a required binary or the
# bench client is missing, or the two arms are the same binary.
# =============================================================================
import hashlib
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile

ROOT = os.environ.get("REPO") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RS = os.environ.get("RS", os.path.join(ROOT, "target", "release"))
GO = os.environ.get("GO", "")
BENCH = os.environ.get("BENCH", "/root/bench/abbench")
MIB = int(os.environ.get("MIB", "512"))
BLOCKS = int(os.environ.get("BLOCKS", "3"))
FLOWS = [int(f) for f in os.environ.get("FLOWS", "1 4").split()]
SHAPES = os.environ.get(
    "SHAPES",
    "tcp false false;tcp false true;tcp true false;tcp true true;"
    "websocket false false;websocket true false;websocket true true;"
    "kcp false false;kcp false true;kcp true false;kcp true true;"
    "quic true false",
).split(";")

SINK = 19054
REMOTE = 19056
TCP_BIND = 19100
KCP_BIND = 19102
QUIC_BIND = 19103
TOKEN = "bench-token"
STREAM_TIMEOUT = 300

# Per 2x2 block the arms alternate; the orientation flips between blocks so that
# neither arm systematically occupies the middle slots (a transient spanning two
# adjacent reps would otherwise always land on the same arm's whole block).
ORIENTATIONS = (("rs", "go", "go", "rs"), ("go", "rs", "rs", "go"))


def fail(code, message):
    print(f"bench-vs-go: {message}", file=sys.stderr)
    sys.exit(code)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_binaries():
    resolved = {}
    for label, directory in (("RS", RS), ("GO", GO)):
        for name in ("frps", "frpc"):
            path = os.path.join(directory, name) if directory else ""
            if not path or not os.access(path, os.X_OK):
                fail(2, f"{label}={directory or '<unset>'}: no executable {name}")
            resolved[f"{label}:{name}"] = sha256(path)
    if resolved["RS:frps"] == resolved["GO:frps"] or resolved["RS:frpc"] == resolved["GO:frpc"]:
        fail(2, "RS and GO resolve to the same binaries; a self-comparison would read as parity")
    if not os.access(BENCH, os.X_OK):
        fail(2, f"BENCH={BENCH}: not executable (need `abbench stream`/`abbench sink`)")
    return resolved


def describe_run(resolved):
    commit = subprocess.run(
        ["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True, check=False,
    ).stdout.strip() or "unknown-commit"
    dirty = subprocess.run(
        ["git", "-C", ROOT, "status", "--porcelain"],
        capture_output=True, text=True, check=False,
    ).stdout.strip()
    host = f"{platform.node()} {platform.machine()} {os.cpu_count()} cpus"
    print(f"# commit={commit}{' (dirty)' if dirty else ''} host={host} mib={MIB} blocks={BLOCKS}")
    for key in sorted(resolved):
        print(f"# {key} sha256={resolved[key]}")
    print(f"# bench={BENCH}", flush=True)


def kill(name):
    subprocess.run(["pkill", "-9", "-x", name], capture_output=True, check=False)


def wait_port(port, tries=60):
    for _ in range(tries):
        probe = subprocess.run(
            ["bash", "-c", f"echo > /dev/tcp/127.0.0.1/{port}"],
            capture_output=True, check=False,
        )
        if probe.returncode == 0:
            return True
        subprocess.run(["sleep", "0.1"], check=False)
    return False


def server_port(proto):
    return {"kcp": KCP_BIND, "quic": QUIC_BIND}.get(proto, TCP_BIND)


def write_configs(directory, proto, tls, mux):
    server = os.path.join(directory, "s.toml")
    client = os.path.join(directory, "c.toml")
    # bindPort always stays on the TCP port: a client that ignored
    # `transport.protocol` would otherwise connect over TCP and still produce a
    # number, which is exactly the mis-selection that corrupted earlier tables.
    with open(server, "w") as handle:
        handle.write(
            f'bindAddr = "127.0.0.1"\n'
            f"bindPort = {TCP_BIND}\n"
            f"kcpBindPort = {KCP_BIND}\n"
            f"quicBindPort = {QUIC_BIND}\n"
            f'auth.token = "{TOKEN}"\n'
            f"transport.tcpMux = {mux}\n"
            f'log.level = "warn"\n'
        )
    with open(client, "w") as handle:
        handle.write(
            f'serverAddr = "127.0.0.1"\n'
            f"serverPort = {server_port(proto)}\n"
            f'auth.token = "{TOKEN}"\n'
            f"loginFailExit = true\n"
            f'transport.protocol = "{proto}"\n'
            f"transport.tcpMux = {mux}\n"
            f"transport.tls.enable = {tls}\n"
            f'log.level = "warn"\n'
            f"[[proxies]]\n"
            f'name = "bench"\n'
            f'type = "tcp"\n'
            f'localIP = "127.0.0.1"\n'
            f"localPort = {SINK}\n"
            f"remotePort = {REMOTE}\n"
        )
    return server, client


def measure(impl, proto, tls, mux, flows, directory):
    """One sample in MiB/s, or None when the rep did not produce a valid number."""
    binaries = RS if impl == "rs" else GO
    kill("frps")
    kill("frpc")
    kill(os.path.basename(BENCH))
    subprocess.run(["sleep", "0.4"], check=False)
    server, client = write_configs(directory, proto, tls, mux)
    server_log = open(os.path.join(directory, "frps.log"), "w")
    client_log = open(os.path.join(directory, "frpc.log"), "w")
    frps = subprocess.Popen([os.path.join(binaries, "frps"), "-c", server], stdout=server_log, stderr=server_log)
    subprocess.run(["sleep", "0.6"], check=False)
    frpc = subprocess.Popen([os.path.join(binaries, "frpc"), "-c", client], stdout=client_log, stderr=client_log)
    try:
        if not wait_port(REMOTE):
            print(f"  ! {proto} tls={tls} mux={mux} flows={flows} {impl}: did not come up", file=sys.stderr)
            return None
        sink = subprocess.Popen([BENCH, "sink", str(SINK)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if sink.poll() is not None:
                print(f"  ! sink on {SINK} exited immediately (port busy?)", file=sys.stderr)
                return None
            subprocess.run(["sleep", "0.2"], check=False)
            try:
                run = subprocess.run(
                    [BENCH, "stream", str(REMOTE), str(MIB), str(flows)],
                    capture_output=True, text=True, timeout=STREAM_TIMEOUT, check=False,
                )
            except subprocess.TimeoutExpired:
                print(f"  ! {proto} tls={tls} mux={mux} flows={flows} {impl}: stream timed out", file=sys.stderr)
                return None
            if run.returncode != 0:
                print(f"  ! {proto} tls={tls} mux={mux} flows={flows} {impl}: exit {run.returncode}", file=sys.stderr)
                return None
            if sink.poll() is not None:
                print(f"  ! {proto} tls={tls} mux={mux} flows={flows} {impl}: sink died mid-stream", file=sys.stderr)
                return None
            lines = run.stdout.strip().splitlines()
            if not lines:
                return None
            fields = lines[-1].split()
            if "MiB/s" not in fields:
                return None
            return float(fields[fields.index("MiB/s") - 1])
        finally:
            sink.kill()
            sink.wait()
    finally:
        frpc.kill()
        frps.kill()
        frpc.wait()
        frps.wait()
        server_log.close()
        client_log.close()
        subprocess.run(["sleep", "0.3"], check=False)


def verdict(ratios, blocks):
    if not ratios:
        return "no data"
    if len(ratios) < blocks:
        return f"incomplete ({len(ratios)}/{blocks} blocks)"
    if all(r > 1.0 for r in ratios):
        return "rs faster"
    if all(r < 1.0 for r in ratios):
        return "go faster"
    return "indistinguishable"


def main():
    if not GO:
        fail(2, "GO is unset; fetch the release with scripts/download-go-frp.sh and point GO at it")
    resolved = check_binaries()
    describe_run(resolved)
    rows = []
    dropped = 0
    with tempfile.TemporaryDirectory(prefix="bench-vs-go-") as directory:
        for flows in FLOWS:
            for case in SHAPES:
                proto, tls, mux = case.split()
                rs_values, go_values, ratios = [], [], []
                for block_index in range(BLOCKS):
                    order = ORIENTATIONS[block_index % len(ORIENTATIONS)]
                    block = {"rs": [], "go": []}
                    for impl in order:
                        value = measure(impl, proto, tls, mux, flows, directory)
                        if value is None:
                            dropped += 1
                            continue
                        block[impl].append(value)
                        (rs_values if impl == "rs" else go_values).append(value)
                    if block["rs"] and block["go"]:
                        ratios.append(statistics.median(block["rs"]) / statistics.median(block["go"]))
                verdict_text = verdict(ratios, BLOCKS)
                if not rs_values or not go_values:
                    rows.append((proto, tls, mux, flows, None, None, ratios, verdict_text))
                    print(f"{proto:10s} tls={tls:5s} mux={mux:5s} flows={flows}  {verdict_text}", flush=True)
                    continue
                rs_median = statistics.median(rs_values)
                go_median = statistics.median(go_values)
                spread = (max(rs_values) - min(rs_values)) / rs_median * 100.0
                quotient = rs_median / go_median
                rows.append((proto, tls, mux, flows, rs_median, go_median, ratios, verdict_text))
                print(
                    f"{proto:10s} tls={tls:5s} mux={mux:5s} flows={flows}  "
                    f"rs={rs_median:8.1f} n={len(rs_values)} ({min(rs_values):.1f}-{max(rs_values):.1f}, {spread:.0f}%)  "
                    f"go={go_median:8.1f} n={len(go_values)} ({min(go_values):.1f}-{max(go_values):.1f})  "
                    f"quotient={quotient:.2f}  ratios={[round(r, 2) for r in ratios]}  {verdict_text}",
                    flush=True,
                )

    print("\nSUMMARY  (a row straddling 1.0 is indistinguishable at this rep count)")
    for proto, tls, mux, flows, rs_median, go_median, ratios, verdict_text in rows:
        if rs_median is None:
            print(f"{proto} tls={tls} mux={mux} flows={flows}: {verdict_text}")
            continue
        detail = f", ratios {[round(r, 2) for r in ratios]}" if ratios else ""
        print(
            f"{proto} tls={tls} mux={mux} flows={flows}: "
            f"{rs_median:.1f} vs {go_median:.1f} = {statistics.median(ratios):.2f}x  [{verdict_text}{detail}]"
        )
    print(f"\ndropped={dropped}")
    return 0 if dropped == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
