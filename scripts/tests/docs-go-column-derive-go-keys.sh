#!/usr/bin/env bash
# docs-go-column-derive-go-keys.sh — re-derive the Go frp v0.71.0 json key set
# recorded at scripts/tests/docs-go-column-go-keys.txt.
#
# The gate itself (scripts/tests/docs-go-column.sh) is offline: it diffs its
# embedded `GO` table against the committed artifact, so a transcription error
# in either reds. This script is the re-derivation step behind that artifact and
# is run by hand when the compatibility target moves:
#
#   bash scripts/tests/docs-go-column-derive-go-keys.sh --fetch --write
#   bash scripts/tests/docs-go-column-derive-go-keys.sh --fetch --check
#   bash scripts/tests/docs-go-column-derive-go-keys.sh \
#        --source ~/go/src/github.com/fatedier/frp/pkg/config/v1 --check
#
# Pinned source: Go frp tag `v0.71.0` is annotated object
# 40adeed73b51e7ee1766d7cfb15d02ba9431ba2b, pointing at commit
# 4a23aa181c1d7e28eecaa8216024ed753b9d27c8; `--fetch` pulls the
# pkg/config/v1 files listed in the artifact's provenance header from
# cdn.jsdelivr.net at that commit.
#
# Accept set (the artifact's shape): every dotted `json` path reachable from
# ServerConfig, ClientConfig and the *ProxyConfig / *VisitorConfig /
# *PluginOptions structs (embedded structs followed, `json:"-"` ignored), plus
# every bare `json` field name in those files — 108 + 153 = 261 spellings.
#
# Modes
#   --print   print the derived key set, one per line (default)
#   --check   diff the derived set against the artifact; rc 1 on disagreement
#   --write   rewrite the artifact's key body, keeping its provenance header
# Source (one of)
#   --source DIR            a checkout of pkg/config/v1
#   GO_FRP_CONFIG_V1_DIR=…  the same, via the environment
#   --fetch                 download the pinned commit (needs curl + network)
# Exit codes
#   no source at all (no --source, no GO_FRP_CONFIG_V1_DIR, no --fetch)  SKIP, rc 0
#   a --fetch that cannot download (no curl, no network)                 SKIP, rc 0
#   a source was supplied/fetched but yields no json keys                FAIL, rc 1,
#       naming the directory — an explicit source with no keys is a mistake, not
#       "no source", and --write must not clobber the artifact with an empty set.
set -uo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARTIFACT="$REPO_ROOT/scripts/tests/docs-go-column-go-keys.txt"
PIN_COMMIT=4a23aa181c1d7e28eecaa8216024ed753b9d27c8
PIN_OBJECT=40adeed73b51e7ee1766d7cfb15d02ba9431ba2b
FILES="server client common proxy visitor proxy_plugin visitor_plugin value_source api store decode"

mode=print
source_dir="${GO_FRP_CONFIG_V1_DIR:-}"
do_fetch=0
while [ $# -gt 0 ]; do
  case "$1" in
    --print) mode=print ;;
    --check) mode=check ;;
    --write) mode=write ;;
    --source) shift; source_dir="${1:-}" ;;
    --fetch) do_fetch=1 ;;
    -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

if ! command -v python3 >/dev/null 2>&1; then
  printf 'SKIP  python3 is not available; cannot derive the key set\n'
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

source_kind=''
if [ -n "$source_dir" ]; then
  source_kind='--source/GO_FRP_CONFIG_V1_DIR'
fi

if [ -z "$source_dir" ] && [ "$do_fetch" = 1 ]; then
  if ! command -v curl >/dev/null 2>&1; then
    printf 'SKIP  --fetch needs curl, which is not installed; pass --source DIR instead\n'
    exit 0
  fi
  mkdir -p "$tmp/v1"
  fetched=0
  for f in $FILES; do
    url="https://cdn.jsdelivr.net/gh/fatedier/frp@$PIN_COMMIT/pkg/config/v1/$f.go"
    if curl -fsS --max-time 60 -o "$tmp/v1/$f.go" "$url"; then
      fetched=$((fetched + 1))
    else
      printf 'SKIP  could not fetch %s (no network, or the mirror is unreachable)\n' "$url"
      exit 0
    fi
  done
  source_dir="$tmp/v1"
  source_kind='--fetch'
fi

if [ -z "$source_kind" ]; then
  printf 'SKIP  no Go frp v0.71.0 source; pass --source DIR, set GO_FRP_CONFIG_V1_DIR, or use --fetch\n'
  exit 0
fi
if [ ! -d "$source_dir" ]; then
  printf 'FAIL  the %s directory %s does not exist; nothing to derive from\n' \
    "$source_kind" "$source_dir" >&2
  exit 1
fi

python3 -B - "$source_dir" >"$tmp/derived.txt" <<'PY'
import os
import re
import sys

FIELD = re.compile(r'^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+(?P<type>[^`]+?)\s+`(?P<tags>[^`]*)`\s*(?://.*)?$')
EMBED = re.compile(r'^\s*(?P<type>\*?[A-Za-z_][A-Za-z0-9_.]*)\s*$')
JSONTAG = re.compile(r'json:"(?P<name>[^",]*)(?P<opts>,[^"]*)?"')


def parse(path):
    structs = {}
    cur = None
    for raw in open(path, encoding='utf-8'):
        line = raw.rstrip('\n')
        m = re.match(r'^type\s+([A-Za-z_][A-Za-z0-9_]*)\s+struct\s*\{', line)
        if m:
            cur = m.group(1)
            structs[cur] = []
            continue
        if cur is None:
            continue
        if line.strip() == '}' or line.startswith('}'):
            cur = None
            continue
        s = line.strip()
        if not s or s.startswith('//'):
            continue
        fm = FIELD.match(line)
        if fm:
            jm = JSONTAG.search(fm.group('tags'))
            name = jm.group('name') if jm else None
            if name == '-':
                name = None
            structs[cur].append((name, fm.group('type').strip(), False))
            continue
        em = EMBED.match(line)
        if em:
            structs[cur].append((None, em.group('type'), True))
    return structs


def base_type(t):
    t = t.strip()
    t = re.sub(r'^\[\]', '', t)
    t = re.sub(r'^\*', '', t)
    t = re.sub(r'^map\[[^\]]*\]', '', t)
    return t.split('.')[-1]


d = sys.argv[1]
structs = {}
for name in sorted(os.listdir(d)):
    if name.endswith('.go'):
        structs.update(parse(os.path.join(d, name)))

roots = ['ServerConfig', 'ClientConfig']
for t in structs:
    if (t.endswith('ProxyConfig') or t.endswith('VisitorConfig')
            or t.endswith('PluginOptions')):
        roots.append(t)

paths = set()


def walk(t, prefix, seen):
    if t in seen or t not in structs:
        return
    seen = seen | {t}
    for js, ftype, embedded in structs[t]:
        if embedded:
            walk(base_type(ftype), prefix, seen)
            continue
        if js is None:
            continue
        full = js if not prefix else prefix + '.' + js
        paths.add(full)
        if base_type(ftype) in structs:
            walk(base_type(ftype), full, seen)


for r in roots:
    walk(r, '', frozenset())

bare = set()
for t in structs:
    for js, _ftype, _emb in structs[t]:
        if js is not None:
            bare.add(js)

for k in sorted(paths | bare):
    print(k)
PY

derived_count="$(wc -l <"$tmp/derived.txt" | tr -d ' ')"
if [ "$derived_count" = 0 ]; then
  printf 'FAIL  the %s source %s yielded no json keys — looked for `json:"..."` struct fields in %s/*.go; refusing to check or write an empty key set\n' \
    "$source_kind" "$source_dir" "$source_dir" >&2
  exit 1
fi

case "$mode" in
  print)
    cat "$tmp/derived.txt"
    ;;
  check)
    if [ ! -f "$ARTIFACT" ]; then
      printf 'FAIL  %s is missing\n' "$ARTIFACT" >&2
      exit 1
    fi
    grep -v '^#' "$ARTIFACT" | grep -v '^[[:space:]]*$' >"$tmp/recorded.txt"
    if diff -u "$tmp/recorded.txt" "$tmp/derived.txt" >"$tmp/diff.txt"; then
      printf 'OK  %d derived key(s) match %s\n' "$derived_count" "$ARTIFACT"
      exit 0
    fi
    printf 'FAIL  the recorded key set disagrees with the source at %s:\n' "$source_dir" >&2
    cat "$tmp/diff.txt" >&2
    exit 1
    ;;
  write)
    if [ ! -s "$tmp/derived.txt" ]; then
      printf 'FAIL  refusing to rewrite %s from an empty key set\n' "$ARTIFACT" >&2
      exit 1
    fi
    if [ ! -f "$ARTIFACT" ]; then
      printf 'FAIL  %s is missing; cannot preserve its provenance header\n' "$ARTIFACT" >&2
      exit 1
    fi
    sed -n '/^#/p' "$ARTIFACT" >"$tmp/new.txt"
    printf '\n' >>"$tmp/new.txt"
    cat "$tmp/derived.txt" >>"$tmp/new.txt"
    cp "$tmp/new.txt" "$ARTIFACT"
    printf 'wrote %d derived key(s) to %s\n' "$derived_count" "$ARTIFACT"
    ;;
esac
