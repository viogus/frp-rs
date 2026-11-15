#!/usr/bin/env python3
# =============================================================================
# bench-vs-go.py — interleaved throughput comparison of frp-rs against the
# official Go frp release, on one host, with an explicit stability verdict.
#
# Why this exists: two matrices run minutes apart on the same tree disagreed by
# 15-20% on the tcpMux and KCP rows, and both were quoted to users. The causes
# are structural, not mysterious: every prior run measured *all* of one arm and
# then *all* of the other, so host drift lands entirely on whichever arm went
# second, and a row was called a win or a loss from a single pair of numbers.
#
# This harness alternates the arms *inside* every block (ABBA), reports each
# row's per-block ratio, and refuses to call a row a win or a loss unless every
# block ratio lands on the same side of 1.0. A row that straddles 1.0 is
# printed as `indistinguishable` — that is a result, not a failure.
#
# Usage (on a Linux bench host; loopback, no privileges needed):
#   python3 scripts/bench-vs-go.py                       # full matrix, 512 MiB
#   MIB=1024 BLOCKS=5 python3 scripts/bench-vs-go.py     # slower, tighter
#   SHAPES='tcp true true;kcp true true' python3 scripts/bench-vs-go.py
#   FLOWS='1' python3 scripts/bench-vs-go.py
#
# Environment:
#   RS       dir holding frp-rs `frps`/`frpc`        (default target/release)
#   GO       dir holding Go frp `frps`/`frpc`        (use scripts/download-go-frp.sh)
#   BENCH    the stream generator, default /root/bench/abbench
#            (`abbench stream <port> <MiB> <flows>`, `abbench sink <port>`)
#   MIB      payload per rep, default 512
#   BLOCKS   ABBA blocks per row, default 3 (6 samples per arm)
#   FLOWS    flow counts to test, default "1 4"
#   SHAPES   semicolon list of `<proto> <tls> <tcpMux>`, default the matrix below
#
# Exit codes: 0 every row measured, 1 a row could not be measured at all,
# 2 a required binary or the bench client is missing.
# =============================================================================
import os
import shutil
import statistics
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RS = os.environ.get("RS", os.path.join(ROOT, "target", "release"))
GO = os.environ.get("GO", "")
BENCH = os.environ.get("BENCH", "/root/bench/abbench")
MIB = int(os.environ.get("MIB", "512"))
BLOCKS = int(os.environ.get("BLOCKS", "3"))
FLOWS = [int(f) for f in os.environ.get("FLOWS", "1 4").split()]
SHAPES = os.environ.get(
    "SHAPES",
    "tcp false false;tcp false true;tcp true true;"
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

# ABBA: alternating inside every block is what cancels host drift. Do not
# "optimise" this into two consecutive runs per arm.
ORDER = ["rs", "go", "go", "rs"]


def fail(code, message):
    print(f"bench-vs-go: {message}", file=sys.stderr)
    sys.exit(code)


def check_binaries():
    for label, directory in (("RS", RS), ("GO", GO)):
        for name in ("frps", "frpc"):
            path = os.path.join(directory, name) if directory else ""
            if not path or not os.access(path, os.X_OK):
                fail(2, f"{label}={directory or '<unset>'}: no executable {name}")
    if not os.access(BENCH, os.X_OK):
        fail(2, f"BENCH={BENCH}: not executable (need `abbench stream`/`abbench sink`)")


def kill(name):
    subprocess.run(["pkill", "-9", "-x", name], capture_output=True, check=False)


def wait_port(port, tries=60):
    for _ in range(tries):
        probe = subprocess.run(
            ["bash", "-c", f"echo > /dev/tcp/127.0.0.1/{port}"],
            capture_output=True,
            check=False,
        )
        if probe.returncode == 0:
            return True
        subprocess.run(["sleep", "0.1"], check=False)
    return False


def write_configs(directory, proto, tls, mux):
    if proto == "kcp":
        server_port = KCP_BIND
    elif proto == "quic":
        server_port = QUIC_BIND
    else:
        server_port = TCP_BIND
    server = os.path.join(directory, "s.toml")
    client = os.path.join(directory, "c.toml")
    with open(server, "w") as handle:
        handle.write(
            f'bindAddr = "127.0.0.1"\n'
            f"bindPort = {server_port}\n"
            f"kcpBindPort = {KCP_BIND}\n"
            f"quicBindPort = {QUIC_BIND}\n"
            f'auth.token = "{TOKEN}"\n'
            f"transport.tcpMux = {mux}\n"
            f'log.level = "warn"\n'
        )
    with open(client, "w") as handle:
        handle.write(
            f'serverAddr = "127.0.0.1"\n'
            f"serverPort = {server_port}\n"
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
            tail = open(os.path.join(directory, "frpc.log")).read().strip().splitlines()[-1:]
            print(f"  ! {proto} tls={tls} mux={mux} flows={flows} {impl}: did not come up {tail}", file=sys.stderr)
            return None
        sink = subprocess.Popen([BENCH, "sink", str(SINK)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sleep", "0.2"], check=False)
        try:
            out = subprocess.run(
                [BENCH, "stream", str(REMOTE), str(MIB), str(flows)],
                capture_output=True, text=True, timeout=300, check=False,
            ).stdout.strip().splitlines()
        finally:
            sink.kill()
        if not out:
            return None
        fields = out[-1].split()
        if "MiB/s" not in fields:
            return None
        return float(fields[fields.index("MiB/s") - 1])
    finally:
        frpc.kill()
        frps.kill()
        server_log.close()
        client_log.close()
        subprocess.run(["sleep", "0.3"], check=False)


def verdict(ratios):
    if all(r > 1.0 for r in ratios):
        return "rs faster"
    if all(r < 1.0 for r in ratios):
        return "go faster"
    return "indistinguishable"


def main():
    if not GO:
        fail(2, "GO is unset; fetch the release with scripts/download-go-frp.sh and point GO at it")
    check_binaries()
    rows = []
    measured_all = True
    with tempfile.TemporaryDirectory(prefix="bench-vs-go-") as directory:
        for flows in FLOWS:
            for case in SHAPES:
                proto, tls, mux = case.split()
                rs_values, go_values, ratios = [], [], []
                for _ in range(BLOCKS):
                    block = {"rs": [], "go": []}
                    for impl in ORDER:
                        value = measure(impl, proto, tls, mux, flows, directory)
                        if value is None:
                            continue
                        block[impl].append(value)
                        (rs_values if impl == "rs" else go_values).append(value)
                    if block["rs"] and block["go"]:
                        ratios.append(statistics.median(block["rs"]) / statistics.median(block["go"]))
                if not rs_values or not go_values:
                    measured_all = False
                    rows.append((proto, tls, mux, flows, None, None, [], "no data"))
                    print(f"{proto:10s} tls={tls:5s} mux={mux:5s} flows={flows}  no data", flush=True)
                    continue
                rs_median = statistics.median(rs_values)
                go_median = statistics.median(go_values)
                spread = (max(rs_values) - min(rs_values)) / rs_median * 100.0
                rows.append((proto, tls, mux, flows, rs_median, go_median, ratios, verdict(ratios)))
                print(
                    f"{proto:10s} tls={tls:5s} mux={mux:5s} flows={flows}  "
                    f"rs={rs_median:8.1f} ({min(rs_values):.1f}-{max(rs_values):.1f}, {spread:.0f}%)  "
                    f"go={go_median:8.1f} ({min(go_values):.1f}-{max(go_values):.1f})  "
                    f"ratios={[round(r, 2) for r in ratios]}  {rows[-1][7]}",
                    flush=True,
                )

    print("\nSUMMARY  (a row straddling 1.0 is indistinguishable at this rep count)")
    for proto, tls, mux, flows, rs_median, go_median, ratios, line in rows:
        if rs_median is None:
            print(f"{proto} tls={tls} mux={mux} flows={flows}: no data")
            continue
        print(
            f"{proto} tls={tls} mux={mux} flows={flows}: "
            f"{rs_median:.1f} vs {go_median:.1f} = {statistics.median(ratios):.2f}x  [{line}]"
        )
    return 0 if measured_all else 1


if __name__ == "__main__":
    sys.exit(main())
