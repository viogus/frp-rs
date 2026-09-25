#!/usr/bin/env bash
# repo-health.sh — regenerate the numbers quoted in CLAUDE.md's "Current Health".
#
# Why this exists: those figures (unsafe-block counts, test counts, binary sizes)
# were hand-maintained in prose and had silently drifted — e.g. the table claimed
# 17 unsafe blocks in frp-core while the tree had 21. Anything that can be counted
# should be counted by a script, not typed into a document.
#
# Usage:
#   bash scripts/repo-health.sh           # fast checks (no build)
#   bash scripts/repo-health.sh --sizes   # also build release binaries and measure
#
# Exit code: 0 if the mandatory invariants hold, 1 otherwise. The gates (each of
# which can set the exit code) are: version alignment, every unsafe block having
# a `// SAFETY:` justification, every vendored crate having a
# README-FRP-RS.md, the toolchain pin (exactly one root `rust-toolchain.toml`,
# an exact `channel` inside its `[toolchain]` table, and no `toolchain:` input or
# floating `rustup default` in CI), docs-index reachability, backtick
# repo-path resolution, and the curated doc-figure list. The code-size and
# binary-size sections are pure reports; the archive-path report is not a content
# gate but does fail the run if its scan cannot complete. A path that is not a
# regular file where a source or workflow file is expected (a FIFO, say) is never
# read — it is named and fails the run — so no section claims a complete scan
# over a file set that omitted it.
#
# The doc-figures gate measures expected values from the tree. Measurement
# inputs the tree does not carry, or cannot read (missing, unreadable, not a
# regular file, not UTF-8), are reported together in one run — one `FAIL partial
# tree: …` (or `FAIL vendor manifest …`) line per input — and the gate exits 3,
# "could not measure"; a source walk that cannot complete exits 2. Both are
# mapped to a red run with their own message, so a partial tree is never
# reported as a doc figure the docs got wrong.
set -uo pipefail

# Resolve the *real* script path before deriving the root. Two ways this goes
# wrong: (a) the path bash opened may be a symlink — a link to this script
# dropped into a subtree makes `dirname` the symlink's directory, so the whole
# run scans that subtree as the repo (measured 2026-09-24: a link at
# frp-core/src/rh-link.sh invoked as `bash rh-link.sh` made the root `frp-core/`,
# losing frp-core/Cargo.toml and printing an empty canonical version); (b) for a
# *sourced* script `$0` is the caller's name, not the file — an interactive
# `bash` resolves through `command -v` to /bin/bash and puts the root at `/`,
# walking the whole filesystem. `BASH_SOURCE[0]` names the file bash actually
# opened, so use it first (bash 3.2 has it); `$0` remains the fallback for
# execution paths that do not set it, where a bare name (no `/`) is relative to
# the caller's cwd and `command -v` is the last resort.
rh_self=${BASH_SOURCE[0]:-$0}
case "$rh_self" in
  */*) ;;
  *) if [ -e "$rh_self" ]; then
       rh_self=$PWD/$rh_self
     else
       rh_self=$(command -v -- "$rh_self") || {
         printf '  FAIL  cannot locate the script named on the command line: %s\n' "$0"
         exit 1
       }
     fi ;;
esac
# Follow symlinks portably: `readlink -f` is not POSIX and older macOS/BSD
# releases lack it, so loop on plain `readlink` and resolve each target against
# the link's own directory. Bounded so a symlink cycle cannot hang the run.
rh_n=0
while [ -L "$rh_self" ]; do
  rh_dir=$(cd -P -- "$(dirname -- "$rh_self")" && pwd) || exit 1
  rh_link=$(readlink -- "$rh_self") || exit 1
  case "$rh_link" in
    /*) rh_self=$rh_link ;;
    *)  rh_self=$rh_dir/$rh_link ;;
  esac
  rh_n=$((rh_n + 1))
  if [ "$rh_n" -gt 40 ]; then
    printf '  FAIL  cannot resolve script path (symlink cycle?): %s\n' "$0"
    exit 1
  fi
done
# `cd -P` also resolves any symlinked directory left in the path, so the root is
# the physical tree that really contains the script.
cd -P -- "$(dirname -- "$rh_self")/.." || exit 1

fail=0
# The python3-driven gates are fail-closed: a missing interpreter means the gate
# could not run, which is not the same as "no violations". The `health` CI job's
# runner has python3, so this only bites local/other environments.
have_python=0
command -v python3 >/dev/null 2>&1 && have_python=1
hr() { printf '%s\n' "------------------------------------------------------------"; }
hdr() { hr; printf '%s\n' "$1"; hr; }

# ---------------------------------------------------------------- read guards
# A shell test followed by a reader is more than one process, so a path that
# flips between a regular file and a FIFO between the test and the open defeats
# it — measured 2026-09-25: a symlink at vendor/rustls/Cargo.toml flipping
# regular<->FIFO hung 6 of 20 runs of the vendored loop — and a reader's open()
# on a FIFO blocks forever, before any shell timeout could fire (this host has no
# timeout(1)). One python3 process doing open(O_NONBLOCK) + fstat(fd) + read is
# atomic against the flip and is the only portable refusal without a timeout
# binary. `python3` is already required for a green run (`have_python`), so this
# adds no dependency.
read_regular() { # <path> — prints the text, or prints nothing and returns 3
  python3 -B -c '
import os, stat, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NONBLOCK)
except FileNotFoundError:
    sys.exit(2)                       # missing (or a dangling symlink)
except PermissionError:
    sys.exit(5)
except OSError:
    sys.exit(4)
if not stat.S_ISREG(os.fstat(fd).st_mode):
    os.close(fd)
    sys.exit(3)
with os.fdopen(fd, "r", encoding="utf8", errors="replace") as f:
    sys.stdout.write(f.read())
' "$1"
}

# read_into <label> <path> — sets READ_TEXT/READ_OK. A refusal prints one FAIL
# carrying the *reason* (missing / not a regular file / Permission denied / a
# directory) and never an `ok`: an unreadable source would otherwise extract to
# "" and compare equal to an empty expectation (the false-ok class this closes).
# `python3` missing is named as the cause instead of blaming the file.
READ_TEXT=""
READ_OK=0
read_into() { # <label> <path>
  if [ "$have_python" != 1 ]; then
    READ_TEXT=""
    READ_OK=0
    printf '  FAIL  %s not evaluated — python3 not found (a green run needs it)\n' "$1"
    fail=1
    return
  fi
  READ_TEXT=$(read_regular "$2")
  rc=$?
  if [ "$rc" -eq 0 ]; then
    READ_OK=1
    return
  fi
  READ_TEXT=""
  READ_OK=0
  case "$rc" in
    2) reason=missing ;;
    3) reason='not a regular file' ;;
    5) reason='Permission denied' ;;
    *) reason='unreadable' ;;
  esac
  printf '  FAIL  %s could not be read: %s (%s) — not evaluated\n' "$1" "$2" "$reason"
  fail=1
}

# ---------------------------------------------------------------- versioning
hdr "Version alignment (mandatory — CLAUDE.md)"

# The canonical version is frp-core's Cargo.toml. Every source below is read
# through the guard, so a FIFO/unreadable/absent file is refused with a FAIL
# naming it — never an `ok` from an empty-vs-empty comparison.
extract_ver() { # <text> -> first `version = "..."` value
  printf '%s' "$1" | grep -m1 '^version' | sed -E 's/.*"([^"]+)".*/\1/'
}

read_into "canonical (frp-core/Cargo.toml)" frp-core/Cargo.toml
canon=""
[ "$READ_OK" = 1 ] && canon=$(extract_ver "$READ_TEXT")
printf '  canonical (frp-core/Cargo.toml) : %s\n' "$canon"

check_ver() { # <label> <actual> <path>
  if [ -z "$2" ]; then
    # The file *was* read; it simply carries no extractable version. That is a
    # content failure, not a failure to evaluate the source.
    printf '  FAIL  %-34s no version found in %s — check the wording\n' "$1" "$3"
    fail=1
  elif [ -z "$canon" ]; then
    # The canonical source was refused (or held no version): there is nothing to
    # compare against, and "(expected )" would state an expectation nobody read.
    printf '  FAIL  %-34s %s (canonical version unknown — not compared)\n' "$1" "$2"
    fail=1
  elif [ "$2" = "$canon" ]; then
    printf '  ok    %-34s %s\n' "$1" "$2"
  else
    printf '  FAIL  %-34s %s (expected %s)\n' "$1" "$2" "$canon"
    fail=1
  fi
}

for c in frp-core frp-server frp-client frps frpc; do
  read_into "$c/Cargo.toml" "$c/Cargo.toml"
  [ "$READ_OK" = 1 ] && check_ver "$c/Cargo.toml" "$(extract_ver "$READ_TEXT")" "$c/Cargo.toml"
done
read_into "frp-core/src/lib.rs VERSION" frp-core/src/lib.rs
[ "$READ_OK" = 1 ] && check_ver "frp-core/src/lib.rs VERSION" \
  "$(printf '%s' "$READ_TEXT" | grep -m1 'pub const VERSION' | sed -E 's/.*"([^"]+)".*/\1/')" \
  "frp-core/src/lib.rs"
# `VERSION="${1:-0.71.0}"` — pull the default out of the parameter expansion.
read_into "scripts/download-frp-rs.sh" scripts/download-frp-rs.sh
[ "$READ_OK" = 1 ] && check_ver "scripts/download-frp-rs.sh" \
  "$(printf '%s' "$READ_TEXT" \
     | grep -m1 -oE 'VERSION="\$\{[0-9]+:-v?[0-9]+\.[0-9]+\.[0-9]+\}"' \
     | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')" \
  "scripts/download-frp-rs.sh"
read_into "README.md version" README.md
[ "$READ_OK" = 1 ] && check_ver "README.md version" \
  "$(printf '%s' "$READ_TEXT" | grep -oE 'frp-rs [0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/frp-rs //')" \
  "README.md"

# frp-vnet is deliberately NOT aligned (CLAUDE.md documents this exception). The
# row is suppressed when the manifest was refused (a FAIL already named it) so it
# cannot print an empty version as if it had been read.
read_into "frp-vnet/Cargo.toml" frp-vnet/Cargo.toml
if [ "$READ_OK" = 1 ]; then
  printf '  info  %-34s %s (exception, not aligned)\n' "frp-vnet/Cargo.toml" "$(extract_ver "$READ_TEXT")"
fi

# ------------------------------------------------- source counts (python walk)
# Every printed source count (Code size, Tests, the SAFETY-cmts column) comes
# from one python walk so the printed and gated definitions agree by
# construction. `os.walk(..., followlinks=False)` is what the gated python scans
# use: it does not follow a symlinked *directory* (measured: `find -L` counted
# frp-core 98 files / 120833 lines when `frp-core/src/ext` was a symlink to
# frp-server/src, while the gated scans still saw 21 blocks), so the printed
# numbers return to the gated set. Each `.rs` file is opened with the same
# O_NONBLOCK + fstat guard: a FIFO or an unreadable file is recorded and fails
# the run instead of blocking `find | xargs cat` / `-exec grep` (which stats a
# regular file and then opens a FIFO — measured 13/20 hangs on a flipping
# `frp-core/src/*.rs`). A symlinked `.rs` *file* is still double-counted by both
# the printed and the gated walks (pre-existing, recorded).
TEST_ATTR='^[[:space:]]*#\[(tokio::)?test(\([^]]*\))?\]'
counts=""
if [ "$have_python" = 1 ]; then
  counts=$(python3 -B - <<'PY'
import errno, os, re, stat, sys

CRATES = ('frp-core', 'frp-server', 'frp-client', 'frp-vnet', 'frps', 'frpc')
GATED = ('frp-core', 'frp-server', 'frp-client', 'frp-vnet')
TEST_ATTR = re.compile(r'^[^\S\n]*#\[(tokio::)?test(\([^]]*\))?\]')
errors = []


def note(msg):
    errors.append(msg)


def safe_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, 'not a regular file', path)
        with os.fdopen(fd, 'r', encoding='utf8', errors='ignore') as f:
            fd = -1
            return f.read()
    finally:
        if fd >= 0:
            os.close(fd)


def walk_error(e):
    note('%s: %s' % (getattr(e, 'filename', '?'), e.strerror or e))


def rs_texts(root, top_only=False):
    """Yield the text of every `.rs` file under `root`, reading each with the
    O_NONBLOCK guard. `top_only` matches a `root/*.rs` glob (not a recursive
    grep): only the directory's own entries."""
    if top_only:
        try:
            names = sorted(os.listdir(root))
        except OSError as e:
            note('%s: %s' % (root, e.strerror or e))
            return
        for fn in names:
            if fn.endswith('.rs'):
                yield os.path.join(root, fn)
        return
    for dirpath, _dirs, names in os.walk(root, onerror=walk_error, followlinks=False):
        for fn in names:
            if fn.endswith('.rs'):
                yield os.path.join(dirpath, fn)


files = {c: 0 for c in CRATES}
lines = {c: 0 for c in CRATES}
safety = {c: 0 for c in GATED}
testfuncs = testfiles = proptest = 0
for crate in CRATES:
    # The historical scopes differ: Code size and SAFETY cmts read <crate>/src,
    # while the test-function/proptest greps recursed over the whole crate dir
    # (so `tests/` and `benches/` count). One walk over the crate root serves
    # both, keyed on whether the file is under `<crate>/src/`.
    if not os.path.isdir(crate):
        continue
    srcpfx = os.path.join(crate, 'src') + os.sep
    for p in rs_texts(crate):
        try:
            text = safe_read(p)
        except OSError as e:
            note('%s: %s' % (p, e.strerror or e))
            continue
        if p.startswith(srcpfx):
            files[crate] += 1
            lines[crate] += text.count('\n')
            if crate in safety:
                safety[crate] += text.count('// SAFETY')
        if crate in GATED:
            proptest += text.count('proptest!')
        hits = sum(1 for l in text.split('\n') if TEST_ATTR.match(l))
        testfuncs += hits
        if hits:
            testfiles += 1

srvtest = 0
for p in rs_texts(os.path.join('frp-server', 'tests'), top_only=True):
    try:
        text = safe_read(p)
    except OSError as e:
        note('%s: %s' % (p, e.strerror or e))
        continue
    srvtest += sum(1 for l in text.split('\n') if TEST_ATTR.match(l))

for e in errors:
    print('scan error: %s' % e, file=sys.stderr)
print('F ' + ' '.join(str(files[c]) for c in CRATES))
print('L ' + ' '.join(str(lines[c]) for c in CRATES))
print('S ' + ' '.join(str(safety[c]) for c in GATED))
print('T %d %d %d %d' % (testfuncs, testfiles, srvtest, proptest))
if errors:
    sys.exit(4)
PY
)
  counts_rc=$?
  if [ "$counts_rc" -ne 0 ]; then
    printf '  FAIL  source counts incomplete (see scan errors above) — report not certified\n'
    fail=1
  fi
fi
F=""; L=""; S=""; T=""
if [ -n "$counts" ]; then
  { read -r _k F; read -r _k L; read -r _k S; read -r _k T; } <<EOF
$counts
EOF
fi
crate_files=()
crate_lines=()
crate_safety=()
read -r -a crate_files <<EOF
$F
EOF
read -r -a crate_lines <<EOF
$L
EOF
read -r -a crate_safety <<EOF
$S
EOF
read -r n_testfuncs n_testfiles n_srvtest n_proptest <<EOF
$T
EOF
if [ -z "$F" ] && [ "$have_python" != 1 ]; then
  # No python3: historical find-based counts so the report is not a row of
  # zeros. The run is already red (every python gate fails closed), and a static
  # non-regular file is still excluded by `-type f`; a *flipping* one is not
  # bounded on this path (residual).
  idx=0
  for c in frp-core frp-server frp-client frp-vnet frps frpc; do
    if [ -d "$c/src" ]; then
      crate_files[idx]=$(find -L "$c/src" -type f -name '*.rs' 2>/dev/null | wc -l | tr -d ' ')
      crate_lines[idx]=$(find -L "$c/src" -type f -name '*.rs' -exec cat {} + 2>/dev/null | wc -l | tr -d ' ')
    else
      crate_files[idx]=0
      crate_lines[idx]=0
    fi
    idx=$((idx + 1))
  done
  idx=0
  for c in frp-core frp-server frp-client frp-vnet; do
    if [ -d "$c/src" ]; then
      crate_safety[idx]=$(find -L "$c/src" -type f -name '*.rs' -exec grep -ho '// SAFETY' {} + 2>/dev/null | wc -l | tr -d ' ')
    else
      crate_safety[idx]=0
    fi
    idx=$((idx + 1))
  done
  n_testfuncs=$(find -L frp-core frp-server frp-client frp-vnet frps frpc -type f -name '*.rs' -exec grep -hoE "$TEST_ATTR" {} + 2>/dev/null | wc -l | tr -d ' ')
  n_testfiles=$(find -L frp-core frp-server frp-client frp-vnet frps frpc -type f -name '*.rs' -exec grep -lE "$TEST_ATTR" {} + 2>/dev/null | wc -l | tr -d ' ')
  n_srvtest=$(find -L frp-server/tests -maxdepth 1 -type f -name '*.rs' -exec grep -hoE "$TEST_ATTR" {} + 2>/dev/null | wc -l | tr -d ' ')
  n_proptest=$(find -L frp-core frp-server frp-client frp-vnet -type f -name '*.rs' -exec grep -ho 'proptest!' {} + 2>/dev/null | wc -l | tr -d ' ')
fi

# ---------------------------------------------------------------- code size
hdr "Code size"
printf '  %-14s %8s %8s\n' "crate" "files" "lines"
idx=0
for c in frp-core frp-server frp-client frp-vnet frps frpc; do
  if [ -d "$c/src" ]; then
    printf '  %-14s %8s %8s\n' "$c" "${crate_files[idx]:-0}" "${crate_lines[idx]:-0}"
  fi
  idx=$((idx + 1))
done

# ---------------------------------------------------------------- tests
hdr "Tests"
# Definition of "test function" used by the prints below (and by the python walk
# above):
#   one test attribute that *starts a line* after optional indentation, plain
#   `#[test]` or `#[tokio::test]`, **parameterised or not** (e.g.
#   `#[tokio::test(flavor = "multi_thread")]`). Comment text that merely
#   mentions an attribute is not a function and does not count (three Rust
#   comments do mention `#[tokio::test]`; a raw grep over-counts them).
# These counts are PRINTED, not curated — see the doc-figure note further down.
printf '  test functions      : %s\n' "${n_testfuncs:-0}"
printf '  files with tests    : %s\n' "${n_testfiles:-0}"
printf '  frp-server/tests    : %s\n' "${n_srvtest:-0}"
printf '  proptest blocks     : %s\n' "${n_proptest:-0}"
printf '  integration test dirs: %s\n' \
  "$(find . -path ./target -prune -o -type d -name tests -print 2>/dev/null | grep -vc '^\./\.' || true)"
printf '\n  NOTE: the number of tests that *pass* is a runtime fact, not a static one.\n'
printf '  Run: cargo test --workspace --all-features\n'

# ---------------------------------------------------------------- unsafe
hdr "Unsafe usage"
# SAFETY-cmts lookup for the table below (a function because bash 3.2 mis-parses
# a `case` pattern's `)` inside `$( ... )`).
safety_of() { # <crate>
  case "$1" in
    frp-core)   printf '%s' "${crate_safety[0]:-0}" ;;
    frp-server) printf '%s' "${crate_safety[1]:-0}" ;;
    frp-client) printf '%s' "${crate_safety[2]:-0}" ;;
    frp-vnet)   printf '%s' "${crate_safety[3]:-0}" ;;
    *)          printf '%s' '?' ;;
  esac
}
# Counts are comment-stripped, because a doc comment that merely mentions an
# attribute is not a code occurrence: frp-core/src/mux.rs has a `/// \`unsafe
# impl\` is needed` line that used to inflate the count. The doc-figure gate
# uses the same definition (same strip helper) so the printed table and the
# gated prose cannot diverge. The `SAFETY cmts` column is deliberately comment
# text.
printf '  %-12s %8s %10s %12s %10s\n' "crate" "blocks" "unsafe fn" "unsafe impl" "SAFETY cmts"
if [ "$have_python" = 1 ]; then
  unsafe_table=$(python3 -B - <<'PY'
import errno, os, re, stat, sys
sys.path.insert(0, 'scripts')
from rust_comments import code_only   # shared: comments removed, literals blanked

errors = []


def note(msg):
    errors.append(msg)


def safe_read(path, errors='ignore'):
    """Read a regular file without ever blocking on a FIFO.

    open(O_NONBLOCK) + fstat(fd) is atomic, so a path that flips between a
    regular file and a FIFO cannot slip between the test and the open, and a
    FIFO's open() (which blocks forever) is never reached. A non-regular path
    raises OSError like any other unreadable file, which the callers record."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, 'not a regular file', path)
        with os.fdopen(fd, 'r', encoding='utf8', errors=errors) as f:
            fd = -1
            return f.read()
    finally:
        if fd >= 0:
            os.close(fd)


def walk_error(e):
    note('%s: %s' % (getattr(e, 'filename', '?'), e.strerror or e))


for crate in ('frp-core', 'frp-server', 'frp-client', 'frp-vnet'):
    src = os.path.join(crate, 'src')
    if not os.path.isdir(src):
        # An absent crate source is a hole in the table, not a row of zeros:
        # record it so the section exits non-zero instead of presenting the
        # remaining crates as a complete scan.
        note('%s/src is not a directory — crate not measured' % crate)
        continue
    blocks = fns = impls = 0
    for root, _d, files in os.walk(src, onerror=walk_error):
        for fn in files:
            if fn.endswith('.rs'):
                path = os.path.join(root, fn)
                try:
                    text = code_only(safe_read(path))
                except OSError as e:
                    note('%s: %s' % (path, e.strerror or e))
                    continue
                blocks += len(re.findall(r'unsafe\s*\{', text))
                fns += len(re.findall(r'unsafe fn', text))
                impls += len(re.findall(r'unsafe impl', text))
    # Print every row even when part of its walk failed: the reader sees the
    # count that *was* measurable, and the `scan error:` lines below plus the
    # exit 4 mark it as incomplete rather than silently undercounted (the
    # previous whole-loop try/except exited before printing any rows).
    print('%s %d %d %d' % (crate, blocks, fns, impls))
if errors:
    for e in errors:
        print('scan error: %s' % e, file=sys.stderr)
    sys.exit(4)
PY
)
  unsafe_table_status=$?
  if [ "$unsafe_table_status" -ne 0 ]; then
    printf '  FAIL  unsafe usage counts not evaluated (exit %s) — table incomplete\n' \
      "$unsafe_table_status"
    fail=1
  fi
  while read -r c b f i; do
    [ -n "$c" ] || continue
    # The same python walk that produced the counts above produced this column,
    # so the table and the doc-figure gate cannot diverge. (The lookup is a
    # function, not an inline `case`: bash 3.2 mis-parses a pattern's `)` inside
    # `$( ... )`.)
    s=$(safety_of "$c")
    printf '  %-12s %8s %10s %12s %10s\n' "$c" "$b" "$f" "$i" "$s"
  done <<EOF
$unsafe_table
EOF
else
  printf '  n/a   python3 not found (the SAFETY gate below fails closed)\n'
fi
printf '\n  Convention: every unsafe block carries a `// SAFETY:` comment.\n'

# Gate: an `unsafe {` block with no `// SAFETY:` justification. The convention was
# previously enforced by review alone.
#
# Getting this right matters more than it looks. A first attempt used a fixed
# 3-line look-behind and reported 14 violations on a clean tree — every one a
# false positive, because the justification is usually a multi-line comment block
# (4-9 lines) or sits inside the block. So: walk up over the whole contiguous
# comment/attribute block, and also look a few lines into the block itself.
if [ "$have_python" = 1 ]; then
  unsafe_misses=$(python3 -B - <<'PY'
import errno, os, re, stat, sys
sys.path.insert(0, 'scripts')
from rust_comments import code_only

INNER = 4  # lines into the block to also scan (catches `let n = unsafe {` + comment inside)
MARKER = re.compile(r'//\s*SAFETY')
errors = []


def note(msg):
    errors.append(msg)


def safe_read(path, errors='ignore'):
    """Read a regular file without ever blocking on a FIFO.

    open(O_NONBLOCK) + fstat(fd) is atomic, so a path that flips between a
    regular file and a FIFO cannot slip between the test and the open, and a
    FIFO's open() (which blocks forever) is never reached. A non-regular path
    raises OSError like any other unreadable file, which the caller records."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, 'not a regular file', path)
        with os.fdopen(fd, 'r', encoding='utf8', errors=errors) as f:
            fd = -1
            return f.read()
    finally:
        if fd >= 0:
            os.close(fd)


def justified(lines, i):
    seen = []
    j = i - 1
    while j >= 0:  # contiguous comment / attribute block immediately above
        s = lines[j].strip()
        if s.startswith('//') or s.startswith('#['):
            seen.append(s)
            j -= 1
            continue
        break
    seen.extend(l.strip() for l in lines[i:i + INNER])
    return any(MARKER.search(s) for s in seen)


def walk_error(e):
    note('%s: %s' % (getattr(e, 'filename', '?'), e.strerror or e))


for crate in ('frp-core', 'frp-server', 'frp-client', 'frp-vnet'):
    src = os.path.join(crate, 'src')
    if not os.path.isdir(src):
        # A crate that was not scanned is not "no violations": record it so the
        # section exits non-zero instead of printing the ok line over a file
        # list that was never read (measured: `rm -rf frp-server/src`).
        note('%s/src is not a directory — crate not scanned' % crate)
        continue
    for root, _dirs, files in os.walk(src, onerror=walk_error):
        for fn in files:
            if not fn.endswith('.rs'):
                continue
            path = os.path.join(root, fn)
            try:
                raw = safe_read(path)
            except OSError as e:
                note('%s: %s' % (path, e.strerror or e))
                continue
            lines = raw.split('\n')
            # Detect `unsafe {` on the comment/literal-stripped view, so the
            # gate and the reported "blocks" column use the same definition; the
            # SAFETY justification is still read from the raw lines above/below.
            code_lines = code_only(raw).split('\n')
            for i, line in enumerate(code_lines):
                if re.search(r'unsafe\s*\{', line) and not justified(lines, i):
                    print('%s:%d' % (path, i + 1))
if errors:  # an unreadable file/directory is not "no violations"
    for e in errors:
        print('scan error: %s' % e)
    sys.exit(4)
PY
)
  unsafe_status=$?
  if [ "$unsafe_status" -ne 0 ]; then
    printf '%s\n' "$unsafe_misses"
    printf '  FAIL  unsafe/SAFETY scan failed (exit %s) — gate not evaluated\n' "$unsafe_status"
    fail=1
  elif [ -n "$unsafe_misses" ]; then
    printf '%s\n' "$unsafe_misses" | sed 's/^/    /'
    n=$(printf '%s\n' "$unsafe_misses" | wc -l | tr -d ' ')
    printf '  FAIL  %s unsafe block(s) with no `// SAFETY:` justification\n' "$n"
    fail=1
  else
    printf '  ok    every unsafe block has a `// SAFETY:` justification\n'
  fi
else
  printf '  FAIL  python3 not found — unsafe/SAFETY gate cannot be evaluated\n'
  fail=1
fi

# ---------------------------------------------------------------- vendored
hdr "Vendored crates ([patch.crates-io])"
for v in vendor/*/; do
  n=$(basename "$v")
  man="${v%/}/Cargo.toml"
  # `[ -e ] || [ -L ]` only decides skip-vs-read (a vendor dir without a
  # manifest is not a vendored crate). The manifest itself is read through
  # `read_into`, so a static FIFO or a symlink flipping regular<->FIFO cannot
  # slip between a `[ -f ]` test and the open: it is refused loudly instead.
  [ -e "$man" ] || [ -L "$man" ] || continue
  read_into "vendor/$n/Cargo.toml" "$man"
  if [ "$READ_OK" != 1 ]; then
    continue
  fi
  ver=$(extract_ver "$READ_TEXT")
  readme="MISSING"
  [ -f "$v/README-FRP-RS.md" ] && readme="ok"
  printf '  %-10s %-10s README-FRP-RS.md: %s\n' "$n" "$ver" "$readme"
  [ "$readme" = "MISSING" ] && fail=1
done
printf '\n  Each vendored crate must document WHY and its EXIT CONDITION.\n'
printf '  A vendored copy pins the crate: track upstream advisories by hand.\n'

# ---------------------------------------------------------------- toolchain
hdr "Toolchain pin"

# Gates: the compiler must be pinned to an exact version, by exactly one file,
# and no workflow may select one by another route. Unpinned, the lint gate is a
# function of the runner image — a new rustc/clippy release can add a lint that
# fires on untouched code, so the same commit is green on one image and red on
# the next. The pin is `rust-toolchain.toml`'s `[toolchain] channel`; "stable",
# "nightly" and a floating "1.98" all track new releases and are failures here.
#
# Both directions were exercised when this gate landed. The pass shapes that must
# NOT fail: `- run: cargo build # rustup default stable was removed`,
# `- name: Install Rust stable (rustup default stable)`, a comment mentioning the
# removed command, `channel = '1.98.1'` (single-quoted TOML), and a trailing TOML
# comment after either the `[toolchain]` header or the `channel` value.
TOOLCHAIN_FILE=rust-toolchain.toml

# (a) Exactly one toolchain file, at the repo root, in `.toml` form, present on
# disk, and not shadowed by an untracked one. `git ls-files` because it is
# precise and cheap. The extension-less legacy `rust-toolchain` is still honoured
# by rustup and WINS over the `.toml` when both exist (measured stderr:
# `warn: both .../rust-toolchain and .../rust-toolchain.toml exist; using
# contents of .../rust-toolchain`), so a second file moves the compiler while the
# `.toml` still reads as pinned. A nested file
# (`scripts/frp-stress/rust-toolchain.toml`) does the same from inside its own
# directory. The `find` fallback keeps the gate usable from a source tree with
# no `.git` (the `health` CI job always has one).
# ---- git guard (the whole group of git calls) -------------------------------
# git is not safe to start until its own files are known regular: `git
# rev-parse` reads .git/HEAD and the config, and `git ls-files` reads the index;
# a FIFO at any of them blocks git in open() before it can print anything
# (measured: `git rev-parse --git-dir` hung >20 s against a FIFO .git/config,
# and a flipping index escaped a plain-bash `git ls-files` for 75 s). Resolve
# those paths *without* git and refuse a non-regular one; every git call below
# still runs under a wall-clock bound, so a path that flips after this check
# cannot hang the run either. `git_state`: none = no .git (find fallback),
# ok = safe to run git, bad = refused (already reported by read_into).
git_state=none
if [ -L .git ] || [ -e .git ]; then
  git_dir=""
  if [ -d .git ]; then
    git_dir=.git
  elif [ -f .git ]; then
    # Linked worktree: `.git` is a gitfile whose `gitdir:` is relative to it.
    read_into ".git" .git
    if [ "$READ_OK" = 1 ]; then
      git_dir=$(printf '%s\n' "$READ_TEXT" | sed -n 's/^gitdir:[[:space:]]*//p' | head -1)
    fi
  fi
  if [ -z "$git_dir" ] || [ ! -d "$git_dir" ]; then
    printf '  FAIL  .git is not a directory or a readable gitfile — git-backed scans not evaluated\n'
    fail=1
    git_state=bad
  else
    git_state=ok
    for f in "$git_dir/HEAD" "$git_dir/index"; do
      if [ -e "$f" ] || [ -L "$f" ]; then
        read_into "$f" "$f"
        [ "$READ_OK" = 1 ] || git_state=bad
      fi
    done
    common=$git_dir
    if [ "$git_state" = ok ] && { [ -e "$git_dir/commondir" ] || [ -L "$git_dir/commondir" ]; }; then
      read_into "$git_dir/commondir" "$git_dir/commondir"
      if [ "$READ_OK" = 1 ]; then
        rel=$(printf '%s\n' "$READ_TEXT" | head -1)
        case "$rel" in
          /*) common=$rel ;;
          *)  common="$git_dir/$rel" ;;
        esac
      else
        git_state=bad
      fi
    fi
    if [ "$git_state" = ok ] && { [ -e "$common/config" ] || [ -L "$common/config" ]; }; then
      read_into "$common/config" "$common/config"
      [ "$READ_OK" = 1 ] || git_state=bad
    fi
  fi
fi

# Run git under a wall-clock bound, mirroring the path scan's own git timeout.
# `subprocess.run(timeout=)` cannot reap a process stuck in uninterruptible
# I/O, but a FIFO open() is interruptible — the case this bounds. Needs python3;
# without it the call fails and the toolchain gate says `not evaluated` (the run
# is already red). A real `git ls-files` is sub-second, so 15 s is already a hang.
GIT_BOUND=15
git_bounded() { # <git args...>
  python3 -B -c '
import os, subprocess, sys
bound = int(sys.argv[1])
# Same environment discipline as the path scan: a caller GIT_DIR/GIT_INDEX_FILE/
# GIT_COMMON_DIR would point git at another tree, and GIT_TRACE* would decorate
# stderr; both are dropped here too.
drop = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY")
env = {k: v for k, v in os.environ.items()
       if k not in drop and not k.startswith("GIT_TRACE")}
try:
    r = subprocess.run(["git"] + sys.argv[2:], stdout=subprocess.PIPE,
                       env=env, timeout=bound)
except OSError as e:
    sys.stderr.write("git could not be run: %s\n" % e)
    sys.exit(127)
except subprocess.TimeoutExpired:
    sys.stderr.write("git %s did not finish within %ds\n" % (" ".join(sys.argv[2:]), bound))
    sys.exit(124)
sys.stdout.buffer.write(r.stdout)
sys.exit(r.returncode)
' "$GIT_BOUND" "$@"
}

tc_index_bad=0
tc_files=""
tc_untracked=""
if [ "$git_state" = ok ]; then
  tracked=$(git_bounded ls-files); git_rc=$?
  if [ "$git_rc" -ne 0 ]; then
    printf '  FAIL  git ls-files could not be run (exit %s) — toolchain file list not evaluated\n' "$git_rc"
    fail=1
    tc_index_bad=1
  else
    tc_files=$(printf '%s\n' "$tracked" | grep -E '(^|/)rust-toolchain(\.toml)?$' || true)
    # Untracked-but-not-gitignored shadowing files: they win in rustup exactly like
    # tracked ones, so a pass here would assert more than was checked. Gitignored
    # scratch stays invisible on purpose (`--exclude-standard`), and anything under
    # a `target/` build directory is pruned for the same reason the `find` fallback
    # below prunes it — nothing builds from inside `target/`.
    others=$(git_bounded ls-files --others --exclude-standard); git_rc=$?
    if [ "$git_rc" -ne 0 ]; then
      printf '  FAIL  git ls-files --others could not be run (exit %s) — toolchain file list not evaluated\n' "$git_rc"
      fail=1
      tc_index_bad=1
    else
      tc_untracked=$(printf '%s\n' "$others" \
        | grep -E '(^|/)rust-toolchain(\.toml)?$' | grep -vE '(^|/)target/' || true)
    fi
  fi
elif [ "$git_state" = none ]; then
  tc_files=$(find . -type d -name target -prune -o \
    \( -name rust-toolchain -o -name rust-toolchain.toml \) -print 2>/dev/null \
    | sed 's|^\./||')
  tc_untracked=""
else
  tc_index_bad=1
fi
if [ "$tc_index_bad" = 1 ]; then
  printf '        toolchain file count not evaluated\n'
elif [ ! -e "$TOOLCHAIN_FILE" ] && [ ! -L "$TOOLCHAIN_FILE" ]; then
  printf '  FAIL  %s is missing — the toolchain is not pinned\n' "$TOOLCHAIN_FILE"
  fail=1
elif [ ! -f "$TOOLCHAIN_FILE" ]; then
  printf '  FAIL  %s is not a regular file — the toolchain is not pinned\n' "$TOOLCHAIN_FILE"
  fail=1
elif [ "$tc_files" = "$TOOLCHAIN_FILE" ] && [ -z "$tc_untracked" ]; then
  printf '  ok    exactly one toolchain file: %s (repo root)\n' "$TOOLCHAIN_FILE"
else
  [ -n "$tc_files" ] && printf '%s\n' "$tc_files" | sed 's/^/    /'
  [ -n "$tc_untracked" ] && printf '%s\n' "$tc_untracked" | sed 's/^/    untracked: /'
  printf '  FAIL  expected exactly one `%s` at the repo root and no other `rust-toolchain`/`rust-toolchain.toml`\n' \
    "$TOOLCHAIN_FILE"
  [ -n "$tc_untracked" ] && printf '        (the untracked file(s) still win in rustup — delete them or add them to .gitignore)\n'
  fail=1
fi

# (b) `channel` must be present, inside the `[toolchain]` table, and an exact
# X.Y.Z, optionally followed by a TOML comment. Single and double quotes are both
# valid TOML and both honoured by rustup. Reading only inside the table matters: a
# `channel` key outside it is ignored by rustup, so accepting it would print `ok`
# for a tree that is not pinned at all. The extraction is intentionally a
# three-step bash parse, not a TOML reader: the two other legal spellings rustup
# honours — an inline table (`toolchain = { channel = "1.98.1" }`) and a dotted
# key (`toolchain.channel = "1.98.1"`) — are NOT recognised and fail closed here.
# That is documented in docs/developing.md, not silently tolerated.
if [ -f "$TOOLCHAIN_FILE" ]; then
  # The header may carry a trailing comment; the value's own trailing comment is
  # stripped below, outside the quotes. The content is read through the guard, so
  # a symlink that flips regular<->FIFO between the `[ -f ]` above and the read
  # is refused instead of hanging awkwardly in awk.
  read_into "$TOOLCHAIN_FILE" "$TOOLCHAIN_FILE"
  if [ "$READ_OK" != 1 ]; then
    printf '        channel not evaluated\n'
  else
    tc_line=$(printf '%s\n' "$READ_TEXT" | awk '
      /^[[:space:]]*\[/ { in_table = ($0 ~ /^[[:space:]]*\[toolchain\][[:space:]]*(#.*)?$/); next }
      in_table && /^[[:space:]]*channel[[:space:]]*=/ { print; exit }
    ')
    tc_raw=$(printf '%s' "${tc_line#*=}" | sed -E 's/^[[:space:]]+//')
    case "$tc_raw" in
      \"*\"*) tc_channel=${tc_raw#\"}; tc_channel=${tc_channel%%\"*} ;;
      \'*\'*) tc_channel=${tc_raw#\'}; tc_channel=${tc_channel%%\'*} ;;
      *)      tc_channel=$(printf '%s' "$tc_raw" | sed -E 's/[[:space:]]*#.*$//; s/[[:space:]]//g') ;;
    esac
    if [ -z "$tc_channel" ]; then
      printf '  FAIL  %s has no `channel = ...` key in its [toolchain] table — the toolchain is not pinned\n' \
        "$TOOLCHAIN_FILE"
      fail=1
    elif printf '%s' "$tc_channel" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
      printf '  ok    %s channel = %s (exact version)\n' "$TOOLCHAIN_FILE" "$tc_channel"
    else
      printf '  FAIL  %s channel = "%s" is not an exact X.Y.Z version\n' \
        "$TOOLCHAIN_FILE" "$tc_channel"
      fail=1
    fi
  fi
fi

# (c) No workflow may pass a `toolchain:` input to
# `actions-rust-lang/setup-rust-toolchain@v1`. The action documents that a
# provided `toolchain` makes it ignore the toolchain file and install that value
# instead, and its `override: true` default then beats the file for the rest of
# the job — which would silently unpin every step that relies on the file.
#
# The scan is scoped to the action's own step, not the whole file: a
# `toolchain:` that overrides nothing (`workflow_dispatch.inputs.toolchain`, a
# `matrix.toolchain` entry, a job `env:` mapping, another step's `run: |` body)
# must not fail the gate. Both `*.yml` and `*.yaml` are read.
#
# RECOGNISED STEP FORMS (a closed list — a form not named here is not detected):
#   * `- uses: ...@v1`; `- uses : ...`; `- uses: "...@v1"`;
#   * a named step: `- name: ...` with `uses:` as a mapping key on its own line
#     below it, or below a bare `-`;
#   * the flow form `- {uses: ...@v1, with: {toolchain: stable}}`, whose opening
#     line is scanned as well as its continuation lines.
# The block's base is the indentation of the enclosing `-` list item, not of the
# `uses:` line, so those forms keep their continuation lines in scope. Only a
# `-` at that base (or outside any item) starts a new item: a deeper `-` is item
# content, so a block scalar such as
# `rustflags: |` / `  -D warnings` before `toolchain: stable` keeps the key in
# scope instead of silently closing the block.
#
# Arming the block requires the action in a YAML key position — the start of the
# line's mapping (optional indent, optional `- `, optional quote) or immediately
# after `{`/`,` in a flow mapping. A comment line is skipped before the arming
# test, so a comment, a step `name:` or a `run:` value that merely mentions the
# action URL does not arm it. That is not a guarantee for every spelling though:
# the `{`/`,` alternative cannot tell a flow key from a `{`/`,` inside a quoted
# scalar or an inline comment, so those DO arm it (fail-closed; see the list).
#
# RECOGNISED KEY FORMS (also a closed list): block mapping
# (`toolchain: stable`), flow mapping (`with: {toolchain: stable}` or
# `with: {rustflags: '', toolchain: stable}`) and a quoted key (`"toolchain":`,
# `'toolchain':`) — allowing `{`, `,` or whitespace before it and optional quotes
# around it, in any letter case. The case-insensitivity is on purpose: the runner
# and `@actions/core` are reported to match action input names that way, so an
# uppercase `TOOLCHAIN:` would unpin too. Comment-awareness is deliberate but has
# two halves: a line whose first non-space character is `#` is skipped, and a key
# appearing only after an inline `#` on the same line is skipped too — PROVIDED
# the comment is deeper than the item's indentation, because a comment at or
# below it closes the block before the skip test runs (see the list).
#
# KNOWN NOT COVERED (each measured; this is not a completeness claim and there is
# deliberately no YAML parser here — a pass means only that none of the
# recognised forms above was seen):
#   * an anchor or tag token between `-` and the `uses:` key —
#     `- &step uses: ...@v1` with `toolchain: stable` below it: exit 0. This is a
#     NARROWING introduced by this commit's rewrite: `5bf5270` caught it, and the
#     anchor was lost when the arming test was limited to key position (pre-5bf5270
#     `b8a9bf6` did not catch it either).
#   * a flow *sequence* with no `-` line — `steps: [{uses: ...@v1, with:
#     {toolchain: stable}}]`: exit 0 (pre-existing);
#   * a comment at or below the item's indentation (`<=` the step's `-`) between
#     the action's `uses:` and the key: it closes the item before the comment skip
#     runs, so the key is never scanned: exit 0 (pre-existing);
#   * a `#` inside an *earlier quoted value on the same line*: the guard looks for
#     `#` in the raw prefix, so `with: {rustflags: "a#b", toolchain: stable}`
#     is skipped as if commented out: exit 0;
#   * a YAML anchor/alias on the `with:` block — `x-tc: &tc {toolchain: stable}`
#     at the top level and `with: *tc` on the step: exit 0;
#   * a `toolchain:` key consumed by a *different* action: not scanned at all;
#   * the action URL is matched case-sensitively, so
#     `Actions-Rust-Lang/Setup-Rust-Toolchain@v1` is missed. NOT verified against
#     GitHub: whether Actions resolves a case-different `uses:` was not measured
#     here; owner/repo names are case-insensitive on GitHub, so it is a likely
#     bypass but is not claimed as one;
#   * fail-closed over-catch (the gate fails a workflow that uses no `toolchain:`
#     input): a `{` or `,` inside a quoted scalar or an inline comment arms the
#     block — `run: 'echo "see, uses: ...@v1"'` + `env:` `toolchain: stable`:
#     exit 1; so do `name: "match { uses: ...@v1"` and
#     `run: echo hi # , uses: ...@v1` with that `env:`;
#   * fail-closed over-catch: a nested sequence inside the step
#     (`x-extra:` / `  - toolchain: stable`) is in scope and trips: exit 1;
#   * fail-closed over-catch: a line that reads like a mapping key inside a block
#     scalar of this step (`uses: ...@v1` inside its `run: |`) arms the block, and
#     a later `toolchain: stable` then fails a workflow that never uses the action
#     in a real key position: exit 1.
#
# Read the workflow file set through the guard first. `find -type f` excludes a
# FIFO, but a mode-000 *regular* file passes it and `-exec … 2>/dev/null` fails
# silently — measured: a chmod-000 workflow holding `rustup default stable` left
# the scans printing `ok` with rc=0 and "invariants hold". A mode-000
# `.github/workflows` directory fails its listing just as silently, so that is
# checked too. Any refusal suppresses both scans' `ok` lines.
# The two scans below read the workflow file set through the guarded reader and
# scan the *bytes it read*; they must not re-open the paths. The earlier shape
# guarded each file with `read_into` and then re-opened the same paths with
# `find -exec awk` / `-exec grep`, so a symlink flipping regular<->FIFO between
# the guard and the scan hung the scan (measured 2/12 runs), and a missing `awk`
# made `… || true` swallow the whole scan while the `ok` line still printed.
# One python block walks the set with `os.walk(followlinks=False)` and the same
# O_NONBLOCK + fstat reader, feeds the text to a faithful port of the awk state
# machine and of the floating grep, and prints `C <path:line:line>` / `D <…>`
# hits. The state is per file: `{} +` batching could leak `in_item` across files
# at an ARG_MAX boundary (a latent, unintended behaviour); the port makes the
# intended per-file semantics explicit.
wf_scan_ok=1
wf_scan_reason="a workflow file could not be read"
if [ -d .github/workflows ] && { [ ! -r .github/workflows ] || [ ! -x .github/workflows ]; }; then
  printf '  FAIL  .github/workflows is not readable/searchable — toolchain scan not evaluated\n'
  fail=1
  wf_scan_ok=0
fi
if [ "$have_python" != 1 ]; then
  wf_scan_ok=0
  wf_scan_reason="python3 not found (a green run needs it)"
fi
wf_out=""
# Kept as a function (not `$(python3 - <<'PY' …)`) because bash 3.2 lexes a
# here-document body inside a command substitution as shell text, so the
# scanner's `["']` character classes would open a shell quote and the parse
# would fail. A here-document in a function body is read literally.
wf_scan() {
  python3 -B - <<'PY'
import errno, os, re, stat, sys

SP = r'[ \t\r\v\f]'
SPIN = ' \t\r\v\f'          # the same set without the class brackets, to embed
Q = '["\x27]'
# The closed-form scanner's regexes, one item at a time (a record never holds a
# newline, so POSIX [[:space:]] is SP here):
ARM_REST = re.compile(r'(^|[{,])' + SP + r'*' + Q + r'?[uU][sS][eE][sS]' + Q + r'?'
                      + SP + r'*:' + SP + r'*' + Q + r'?actions-rust-lang/setup-rust-toolchain@')
TOOLKEY = re.compile(r'(^|[{,' + SPIN + r'])' + Q + r'?[tT][oO][oO][lL][cC][hH][aA][iI][nN]'
                     + Q + r'?' + SP + r'*:')
ARM_LINE = re.compile(r'^' + SP + r'*(-' + SP + r'+)?' + Q + r'?[uU][sS][eE][sS]'
                      + Q + r'?' + SP + r'*:' + SP + r'*' + Q + r'?actions-rust-lang/setup-rust-toolchain@')
ARM_FLOW = re.compile(r'[{,]' + SP + r'*' + Q + r'?[uU][sS][eE][sS]' + Q + r'?'
                      + SP + r'*:' + SP + r'*' + Q + r'?actions-rust-lang/setup-rust-toolchain@')
FLOAT1 = re.compile(r'^' + SP + r'*(-' + SP + r'+)?run:' + SP + r'*rustup' + SP + r'+default' + SP)
FLOAT2 = re.compile(r'^' + SP + r'+rustup' + SP + r'+default' + SP)
state = {'bad': False}


def walk_error(e):
    state['bad'] = True
    print('  FAIL  %s: %s — workflow scan not evaluated'
          % (getattr(e, 'filename', '?'), e.strerror or e), file=sys.stderr)


def safe_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, 'not a regular file', path)
        with os.fdopen(fd, 'r', encoding='utf8', errors='ignore') as f:
            fd = -1
            return f.read()
    finally:
        if fd >= 0:
            os.close(fd)


def refusal(e):
    if isinstance(e, FileNotFoundError):
        return 'missing'
    if isinstance(e, PermissionError):
        return 'Permission denied'
    return e.strerror or 'unreadable'


def toolchain_hits(text):
    """Port of the awk step scanner; state is per file."""
    hits = []
    item_indent = -1
    in_item = False
    target = False
    for n, line in enumerate(text.split('\n'), 1):
        ind = re.match(SP + '*', line).end()
        if line[ind:ind + 1] == '-' and (not in_item or ind <= item_indent):
            item_indent = ind
            in_item = True
            target = False
            rest = line[ind + 1:]
            if ARM_REST.search(rest):
                target = True
                k = TOOLKEY.search(rest)
                if k and '#' not in rest[:k.start()]:
                    hits.append((n, line))
            continue
        if not in_item:
            continue
        if re.match(SP + '*$', line):
            continue
        if ind <= item_indent:
            in_item = False
            target = False
            continue
        if re.match(SP + '*#', line):
            continue
        if not target:
            if ARM_LINE.search(line) or ARM_FLOW.search(line):
                target = True
            else:
                continue
        k = TOOLKEY.search(line)
        if k and '#' not in line[:k.start()]:
            hits.append((n, line))
    return hits


def floating_hits(text):
    return [(n, line) for n, line in enumerate(text.split('\n'), 1)
            if FLOAT1.search(line) or FLOAT2.search(line)]


files = []
for dirpath, _dirs, names in os.walk('.github/workflows', onerror=walk_error,
                                     followlinks=False):
    for fn in sorted(names):
        if fn.endswith(('.yml', '.yaml')):
            files.append(os.path.join(dirpath, fn))
files.sort()
top = os.path.join('.github', 'workflows')
for path in files:
    try:
        text = safe_read(path)
    except OSError as e:
        state['bad'] = True
        print('  FAIL  %s could not be read: %s (%s) — not evaluated'
              % (path, path, refusal(e)), file=sys.stderr)
        continue
    if os.path.dirname(path) == top:
        for n, line in toolchain_hits(text):
            print('C %s:%d:%s' % (path, n, line))
    for n, line in floating_hits(text):
        print('D %s:%d:%s' % (path, n, line))
sys.exit(4 if state['bad'] else 0)
PY
}
if [ "$wf_scan_ok" = 1 ]; then
  wf_out=$(wf_scan)
  wf_rc=$?
  if [ "$wf_rc" -ne 0 ]; then
    wf_scan_ok=0
    wf_scan_reason="a workflow file could not be read"
    fail=1
  fi
fi
tc_input=$(printf '%s\n' "$wf_out" | sed -n 's/^C //p')
floating=$(printf '%s\n' "$wf_out" | sed -n 's/^D //p')
if [ "$wf_scan_ok" = 0 ]; then
  # A file the scan could not read, or a scanner that could not start, is named
  # above; an `ok` here would certify a scan that did not happen.
  printf '  FAIL  setup-rust-toolchain toolchain input scan not evaluated — %s\n' "$wf_scan_reason"
  fail=1
elif [ -n "$tc_input" ]; then
  printf '%s\n' "$tc_input" | sed 's/^/    /'
  printf '  FAIL  %s `toolchain:` input(s) on a setup-rust-toolchain step override the toolchain file\n' \
    "$(printf '%s\n' "$tc_input" | grep -c .)"
  fail=1
else
  printf '  ok    no `toolchain:` input on any setup-rust-toolchain step\n'
fi

# (d) No workflow may select a toolchain with `rustup default`. The pattern is
# anchored to a real command — the start of a `run:` value, or the start of a
# line inside a `run: |` block — so a step *name* or an explanatory comment that
# merely mentions the removed command does not trip it (both were false
# positives before; they are the pass cases in the header comment above). That
# anchoring is also what makes the scan comment-aware.
#
# COVERAGE — deliberately narrow, and a pass means only this much:
#   * catches `rustup default <name>` as a leading command in a file under
#     `.github/workflows/`, tolerating extra whitespace
#     (`rustup  default  stable`);
#   * does NOT catch a floating selection that never writes that command as a
#     leading `run:` command. Measured as passing (i.e. missed) when this gate
#     landed: `cargo +stable`, an inline `RUSTUP_TOOLCHAIN=stable cargo ...`,
#     `rustup override set stable`, a `rustc = ...` written into
#     `.cargo/config.toml`, a `rustup default` that is not the first command of
#     its `run:` line (`cd x && rustup default stable`), a **quoted scalar**
#     (`run: "rustup default stable"`), a `rustup default` inside a script or
#     Makefile the job invokes, and a compiler floated by a container base image.
#     The Docker source build is one instance of that last case and has its own
#     TODO.md item; this gate does not cover it.
#   * check (c) above is scoped to the setup-action step and so does not see a
#     `toolchain:` key that some other action might consume.
# `floating` was filled by the python scan above (the `D …` hits), which read the
# same bytes the guard read — no re-open, so no flip can slip in.
if [ "$wf_scan_ok" = 0 ]; then
  printf '  FAIL  floating toolchain selection scan not evaluated — %s\n' "$wf_scan_reason"
  fail=1
elif [ -n "$floating" ]; then
  printf '%s\n' "$floating" | sed 's/^/    /'
  printf '  FAIL  %s floating toolchain selection(s) under .github/workflows/ (rustup default ...)\n' \
    "$(printf '%s\n' "$floating" | grep -c .)"
  fail=1
else
  printf '  ok    no floating toolchain selection under .github/workflows/\n'
fi

# ---------------------------------------------------------------- docs
hdr "Docs"

if [ "$have_python" = 1 ]; then
  # (a) Gate: every doc is reachable from the index. A doc nobody links to is a
  # doc nobody reads, and the index is edited by hand, so it drifts.
  index_misses=$(python3 -B - <<'PY'
import errno, os, stat


def safe_read(path):
    """Read a regular file without blocking on a FIFO (open(O_NONBLOCK) +
    fstat(fd) is atomic; a FIFO's blocking open() is never reached)."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, 'not a regular file')
        with os.fdopen(fd, 'r', encoding='utf8') as f:
            fd = -1
            return f.read()
    finally:
        if fd >= 0:
            os.close(fd)


INDEX = os.path.join('docs', 'README.md')
try:
    index = safe_read(INDEX)
except OSError as e:
    print('docs/README.md could not be read (%s)' % (e.strerror or e))
    raise SystemExit
for name in sorted(os.listdir('docs')):
    if name == 'README.md':
        continue
    path = os.path.join('docs', name)
    if os.path.isfile(path) and name.endswith('.md'):
        if name not in index:
            print('docs/%s' % name)
    elif os.path.isdir(path) and name not in index:
        print('docs/%s/' % name)
PY
)
  index_status=$?
  if [ "$index_status" -ne 0 ]; then
    printf '%s\n' "$index_misses"
    printf '  FAIL  docs-index scan failed (exit %s) — gate not evaluated\n' "$index_status"
    fail=1
  elif [ -n "$index_misses" ]; then
    printf '%s\n' "$index_misses" | sed 's/^/    not in docs\/README.md: /'
    n=$(printf '%s\n' "$index_misses" | wc -l | tr -d ' ')
    printf '  FAIL  %s doc(s)/dir(s) unreachable from the index\n' "$n"
    fail=1
  else
    printf '  ok    every docs/*.md and docs/*/ is reachable from docs/README.md\n'
  fi

  # (b) Report: paths inside docs/archive/** still say `docs/superpowers/...`,
  # deliberately (historical records are not rewritten). Verify the documented
  # translation still holds, so the claim in docs/archive/README.md stays true.
  archive=$(python3 -B - <<'PY'
import errno, os, re, stat, sys

pat = re.compile(r'docs/superpowers/([A-Za-z0-9_./-]+)')
total = resolved = 0
walk_errors = []
read_errors = []


def safe_read(path):
    """Read a regular file without blocking on a FIFO (open(O_NONBLOCK) +
    fstat(fd) is atomic; a FIFO's blocking open() is never reached)."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, 'not a regular file')
        with os.fdopen(fd, 'r', encoding='utf8', errors='ignore') as f:
            fd = -1
            return f.read()
    finally:
        if fd >= 0:
            os.close(fd)


def walk_error(e):
    walk_errors.append('%s: %s' % (getattr(e, 'filename', '?'), e.strerror or e))


for root, _dirs, files in os.walk(os.path.join('docs', 'archive'), onerror=walk_error):
    for fn in files:
        if not fn.endswith(('.md', '.json')):
            continue
        p = os.path.join(root, fn)
        try:
            text = safe_read(p)
        except OSError as e:
            read_errors.append('%s: %s' % (p, e.strerror or e))
            continue
        for line in text.splitlines():
            for m in pat.finditer(line):
                total += 1
                rel = m.group(1).rstrip('.,;:)`')
                if os.path.exists(os.path.join('docs', 'archive', rel)):
                    resolved += 1
for e in read_errors:   # a file that could not be read is not "resolved"
    print('read error: %s' % e)
for e in walk_errors:   # a report whose scan could not complete is not a clean report
    print('walk error: %s' % e)
if read_errors or walk_errors:
    sys.exit(3)
print('%d %d' % (total, resolved))
PY
)
  archive_status=$?
  if [ "$archive_status" -ne 0 ]; then
    printf '%s\n' "$archive"
    printf '  FAIL  archive path scan failed (exit %s) — report not verified\n' "$archive_status"
    fail=1
  else
    set -- $archive
    printf '  info  archive path refs: %s, resolvable via the docs/archive/ prefix: %s\n' "${1:-0}" "${2:-0}"
    printf '        (the remainder point at specs that were never written — pre-existing)\n'
  fi

  # (c) Gate: a *backtick-delimited* path anchored at a known repo root must
  # still open. Coverage is deliberately narrow, and the docs claim exactly this
  # much, no more:
  #   * the scan is TRACKED-FILES-ONLY: the file list comes from the git index
  #     (`git ls-files -z`), i.e. the set a clean checkout tracks — not *exactly*
  #     what a clean checkout contains, because local index state is visible too:
  #     an intent-to-add (`git add -N`) entry is scanned, an unstaged deletion is
  #     a read error, and an unmerged path (listed once per stage) is collapsed by
  #     path. Untracked and gitignored local state — `.worktrees/`,
  #     `.superpowers/`, a nested worktree's point-in-time `TODO.md` /
  #     `docs/archive/…`, editor backups — is never scanned, so this local mirror
  #     agrees with the `health` CI job instead of failing whenever the mandated
  #     worktree workflow is in use. The index supplies the file *list*; content
  #     is read from the worktree, so a tracked file edited locally is gated at
  #     its current content. Consequence: an *untracked* file naming a dead path
  #     is no longer gated — deliberate, because CI runs on a clean checkout where
  #     untracked == absent, so the gate's CI meaning is unchanged. Submodule
  #     *contents* are not scanned either: the index lists only the gitlink (and
  #     CI does not initialise submodules);
  #   * the filesystem walk is used ONLY when `.git` is genuinely absent — not
  #     even a dangling symlink or a gitfile whose gitdir is gone (release
  #     tarball, Docker build context). If any `.git` entry is present but the
  #     index cannot be read, the gate FAILS (exit 3) instead of silently
  #     walking — a walk would scan the gitignored state this gate exists to
  #     avoid. So a sparse checkout, or any worktree missing a tracked path, is
  #     not certified: that path is a read error, not a skip (a partial clone
  #     `--filter=blob:none` materialises every tracked file and does pass);
  #   * only backtick spans are claims; un-backticked prose and tree diagrams are
  #     not scanned. A broad prose sweep was tried and produced hundreds of
  #     misses that were almost all false positives (`frp-core/tls` is a Cargo
  #     feature, not a path; see the 135-hit backlog item in TODO.md);
  #   * the span must start with one of ROOTS (or be a Cargo manifest);
  #   * locator-less spans (`mux.rs`, `control/mod.rs`) have no recoverable base
  #     and are counted, not checked — they are that sweep's false positives.
  # Resolution tries the referencing file's directory first, then the nearest
  # ancestor holding a Cargo.toml (the owning crate root — what makes the
  # crate-relative `src/v2_handshake.rs` in frp-core/tests/ resolve), then the
  # repo root.
  # The scan is fail-closed: an unreadable directory, a tracked-but-unreadable
  # file, a `.git` tree whose index cannot be read, and a file list or span total
  # that comes back empty/implausibly small all exit 3 rather than print "ok 0".
  # The size floors (MIN_FILES/MIN_SPANS) apply to the walk source too, so a
  # partial tarball is not certified either.
  # Hit order is path order, then line number (hits are sorted as (path, line)
  # pairs before printing), instead of the old depth-first walk order
  # (per-directory filename sort); the counts and the hit set are unchanged.
  # Point-in-time documents (history, dated audits, changelog, the refactor
  # proposal, and the backlog that quotes removed paths as evidence) describe an
  # older tree on purpose and are out of scope; the archive has check (b).
  path_report=$(python3 -B - <<'PY'
import errno, os, re, stat, subprocess, sys

# One guarded reader for every file this scan opens. `open()` on a FIFO blocks
# forever; open(O_NONBLOCK) + fstat(fd) on the same descriptor is atomic, so a
# path flipping between a regular file and a FIFO between a test and the read is
# refused, not hung. A non-regular path raises OSError like an unreadable file,
# which `scan()` already records as a read error (exit 3).
def safe_read(path, errors='ignore'):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, 'not a regular file', path)
        with os.fdopen(fd, 'r', encoding='utf8', errors=errors) as f:
            fd = -1
            return f.read()
    finally:
        if fd >= 0:
            os.close(fd)


ROOTS = ('src/', 'tests/', 'benches/', 'examples/',
         'docs/', 'scripts/', 'vendor/', 'docker/', '.github/',
         'frp-core/', 'frp-server/', 'frp-client/', 'frp-vnet/', 'frps/', 'frpc/')
MANIFEST = re.compile(r'^(Cargo\.toml|Cargo\.lock)$')
EXTS = ('.rs', '.toml', '.md', '.sh', '.yml', '.yaml', '.json', '.lock')
SKIP_DIRS = ('docs/archive/', 'docs/history/', 'docs/audit/')
SKIP_FILES = ('CHANGELOG.md', 'TODO.md', 'performance-audit.md',
              'docs/refactor-large-modules.md')
BANNED = ' \t{}*<>|'

# Sanity floors for the scan below. The gate is never-empty: if the file list or
# the span total comes back empty or implausibly small (a broken index, a bogus
# cwd, a git that exits 0 with no output), it must FAIL rather than certify
# "no stale refs". The real tree has hundreds of scannable files and thousands
# of backtick spans, so these floors are far below any real checkout and only
# catch a truncated list. They apply to the walk source as well, so a partial
# tarball / Docker context is not certified either.
MIN_FILES = 50
MIN_SPANS = 100

# Directories the historical walk pruned at any depth. The index does not prune
# them for us, so `wanted()` applies the same rule to keep the two sources in
# agreement (no tracked `.md`/`.rs` lives under `target/`, but verdict parity is
# what makes this change safe to reason about).
PRUNE_DIRS = ('.git', 'target')

# `git ls-files` is run with these variables removed from the environment: with
# them inherited, cwd's tree could be certified against *another* repository's
# index, or a foreign object store could fail an otherwise-clean tree. The tree
# the script cd'd into is the tree it must report on — though git can still
# discover an *enclosing* repository if cwd holds an invalid `.git`, which is why
# `tracked_files()` also requires `git rev-parse --show-toplevel` to equal cwd
# (fail closed otherwise). A repository whose own `.git/objects` is absent and
# which relies on `GIT_OBJECT_DIRECTORY` now fails closed with git's refusal
# (`fatal: not a git repository`): loud and rare, deliberate — one whose
# `objects/` still exists keeps working, because `git ls-files` reads only the
# index (measured). A linked worktree's `.git` gitfile
# resolves without any of these, and `GIT_ALTERNATE_OBJECT_DIRECTORIES` is left
# alone (shared object stores are legitimate). Everything else (PATH, HOME,
# locale, GIT_SSH*) is passed through untouched. `GIT_TRACE*` is dropped by
# prefix so trace output cannot become the first stderr line of a failure
# message.
GIT_ENV_DROP = ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
                'GIT_OBJECT_DIRECTORY')
GIT_ENV_DROP_PREFIX = ('GIT_TRACE',)
GIT_TIMEOUT = 30          # an ordinary hang: subprocess.run(timeout=) cannot reap
                          # a process stuck in uninterruptible (D-state) I/O; a
                          # real `git ls-files` here is sub-second, so 30 s is
                          # already a hang. Bounds a FIFO index that slipped past
                          # the pre-check, together with the toolchain's GIT_BOUND.

def cargo_features(crate):
    path = os.path.join(crate, 'Cargo.toml')
    if not os.path.isfile(path):
        return None
    try:
        text = safe_read(path)
    except OSError as e:
        # An unreadable/non-regular manifest must not silently demote a real
        # `crate/feature` span to "stale" (or vice versa): record it and let the
        # scan exit 3.
        read_errors.append('%s: %s' % (path, e.strerror or e))
        return None
    feats, section = set(), ''
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('['):
            section = line.strip('[]').strip()
            continue
        m = re.match(r'([A-Za-z0-9_-]+)\s*=', line)
        if not m:
            continue
        if section == 'features':
            feats.add(m.group(1))
        elif 'dependencies' in section and re.search(r'optional\s*=\s*true', line):
            feats.add(m.group(1))     # implicit feature of an optional dependency
    return feats

SPAN = re.compile(r'`([^`\n]+)`')

def normalize(span):
    s = span.strip()
    if not s or '...' in s or any(c in s for c in BANNED) or s[0] in '/~$':
        return None
    s = re.sub(r'::[A-Za-z_][A-Za-z0-9_:]*$', '', s)           # file.rs::symbol
    s = re.sub(r'#[A-Za-z0-9_.-]+$', '', s)                    # file.md#anchor
    s = re.sub(r':~?\d+([-\u2013]\d+)?([/,]\d+)*\+?$', '', s)  # file.rs:12-20,30
    return s or None

def nearest_manifest_dir(base):
    """Nearest ancestor of `base` (inclusive) that holds a Cargo.toml, i.e. the
    owning crate root. `frp-core/tests` -> `frp-core`; a root-level file -> `.`."""
    d = os.path.abspath(base or '.')
    while True:
        if os.path.isfile(os.path.join(d, 'Cargo.toml')):
            return os.path.relpath(d)
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent

def classify(span, base, crate_base):
    p = normalize(span)
    if p is None:
        return 'ignore'
    if p.startswith('docs/superpowers'):
        return 'superpowers'      # documented old name of docs/archive/
    has_slash = '/' in p.rstrip('/')
    manifest = bool(MANIFEST.match(os.path.basename(p.rstrip('/'))))
    if not has_slash and not manifest:
        return 'bare' if os.path.splitext(p)[1] in EXTS else 'ignore'
    if not (p.startswith(ROOTS) or manifest):
        return 'shorthand' if os.path.splitext(p)[1] in EXTS else 'ignore'
    if has_slash:             # `crate/feature` (or `dir/crate/feature`) is not a path
        left, right = p.rsplit('/', 1)
        feats = cargo_features(left)
        if feats is not None and right in feats:
            return 'feature'
    candidates = [os.path.normpath(os.path.join(base, p)), os.path.normpath(p)]
    if crate_base is not None:
        candidates.insert(1, os.path.normpath(os.path.join(crate_base, p)))
    for cand in candidates:
        if os.path.exists(cand):
            return 'ok'
    return 'stale'

def spans(lines):
    for lineno, line in lines:
        for m in SPAN.finditer(line):
            yield lineno, m.group(1)

def md(path):
    return enumerate(safe_read(path).splitlines(), 1)

def rs(path):
    return [(i, l) for i, l in enumerate(safe_read(path).splitlines(), 1)
            if l.lstrip().startswith(('//', '/*', '*'))]

counts = {k: 0 for k in ('ok', 'stale', 'feature', 'shorthand', 'bare',
                         'superpowers', 'ignore')}
hits = []
walk_errors = []
read_errors = []


def walk_error(e):
    walk_errors.append('%s: %s' % (getattr(e, 'filename', '?'), e.strerror or e))


def wanted(p):
    """Inclusion rules, unchanged from the historical walk: markdown and Rust
    source only, minus the point-in-time and vendored exclusions, minus any path
    whose *directory* chain holds one of PRUNE_DIRS (the walk pruned those
    directories at any depth; the index does not, so the same rule is applied
    here and the two sources keep identical verdicts). `p` is always
    root-relative, so the SKIP_DIRS/SKIP_FILES patterns stay root-anchored."""
    if any(part in PRUNE_DIRS for part in p.split('/')[:-1]):
        return None
    if p.endswith('.md'):
        if p.startswith(SKIP_DIRS) or p in SKIP_FILES:
            return None
        if p.startswith('vendor/') and os.path.basename(p) != 'README-FRP-RS.md':
            return None    # third-party prose, pinned upstream (our notes stay in scope)
        return 'md'
    if p.endswith('.rs'):
        if p.startswith('vendor/'):   # third-party source, pinned
            return None
        return 'rs'
    return None


class IndexUnavailable(Exception):
    """`.git` exists but the index could not be listed, or it belongs to another
    tree (`git rev-parse --show-toplevel` != cwd)."""


def tracked_files():
    """Root-relative paths from the git index, or None when there is genuinely no
    index to read (`.git` absent, not even a dangling symlink: release tarball /
    Docker build context). Only that case may fall back to the filesystem walk;
    if a `.git` entry is present — including a dangling symlink or a gitfile
    whose gitdir is missing, where `os.path.exists` is False but `lexists` is
    True — but the index cannot be read, raise IndexUnavailable so the caller
    fails the gate: a silent walk would scan the gitignored state this gate
    exists to avoid. Duplicate entries are collapsed by path (an unmerged path is
    listed once per stage). `-z`/NUL splitting keeps paths containing spaces,
    newlines and non-ASCII bytes intact; surrogateescape means a path that is not
    valid UTF-8 is still reported rather than dropped."""
    if not os.path.lexists('.git'):
        return None
    env = {k: v for k, v in os.environ.items()
           if k not in GIT_ENV_DROP and not k.startswith(GIT_ENV_DROP_PREFIX)}
    # git is not safe to start until its own files are regular: `git rev-parse`
    # reads .git/HEAD and the config, and `git ls-files` reads the index; a FIFO
    # at any of them blocks git in open() before it can print anything
    # (measured: `git rev-parse --git-dir` hung >20 s on a FIFO .git/config).
    # Resolve the paths *without* git and refuse a non-regular one; the git calls
    # below are also bounded by GIT_TIMEOUT, so a flip after this check cannot
    # hang the run either.
    if os.path.isdir('.git'):
        gd = '.git'
    elif os.path.isfile('.git'):
        try:
            m = re.search(r'^gitdir:[ \t]*(.+)$', safe_read('.git'), re.M)
        except OSError as e:
            raise IndexUnavailable('.git could not be read: %s' % (e.strerror or e))
        if not m:
            raise IndexUnavailable('.git is a gitfile with no gitdir: line')
        gd = m.group(1).strip()        # a relative gitdir resolves against cwd
    else:
        raise IndexUnavailable('.git is neither a directory nor a regular file')
    if not os.path.isdir(gd):
        raise IndexUnavailable('git dir %s is not a directory' % gd)
    for p in (os.path.join(gd, 'HEAD'), os.path.join(gd, 'index')):
        if os.path.lexists(p) and not os.path.isfile(p):
            raise IndexUnavailable('%s is not a regular file — git would block on it' % p)
    common = gd
    cdfile = os.path.join(gd, 'commondir')
    # A *missing* commondir is legitimate (a normal repo); a present non-regular
    # one would block git exactly like HEAD/config/index, so refuse it too.
    if os.path.lexists(cdfile) and not os.path.isfile(cdfile):
        raise IndexUnavailable('%s is not a regular file — git would block on it' % cdfile)
    if os.path.isfile(cdfile):
        try:
            rel = safe_read(cdfile).strip()
        except OSError as e:
            raise IndexUnavailable('%s could not be read: %s' % (cdfile, e.strerror or e))
        common = rel if os.path.isabs(rel) else os.path.join(gd, rel)
    cfg = os.path.join(common, 'config')
    if os.path.lexists(cfg) and not os.path.isfile(cfg):
        raise IndexUnavailable('%s is not a regular file — git would block on it' % cfg)
    try:
        r = subprocess.run(['git', 'ls-files', '-z', '--full-name', '--cached'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=env, timeout=GIT_TIMEOUT)
    except OSError as e:
        raise IndexUnavailable('git could not be run: %s' % e)
    except subprocess.SubprocessError as e:      # TimeoutExpired is not an OSError
        raise IndexUnavailable('git ls-files did not finish within %ds (%s)'
                               % (GIT_TIMEOUT, e.__class__.__name__))
    if r.returncode != 0:
        detail = r.stderr.decode('utf8', 'replace').strip().splitlines()
        raise IndexUnavailable('git ls-files exited %d%s'
                               % (r.returncode, (': ' + detail[0]) if detail else ''))
    # The file list must belong to *this* tree. git can still discover an
    # enclosing repository when cwd holds an invalid `.git` (an empty directory,
    # say), which would let a foreign non-empty list certify cwd — so the
    # toplevel must equal cwd, compared with realpath on both sides (`/tmp` is
    # `/private/tmp` on macOS, and a symlinked checkout path must not fail).
    try:
        t = subprocess.run(['git', 'rev-parse', '--show-toplevel'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=env, timeout=GIT_TIMEOUT)
    except OSError as e:
        raise IndexUnavailable('git rev-parse --show-toplevel could not be run: %s' % e)
    except subprocess.SubprocessError as e:
        raise IndexUnavailable('git rev-parse --show-toplevel did not finish within '
                               '%ds (%s)' % (GIT_TIMEOUT, e.__class__.__name__))
    if t.returncode != 0:
        detail = t.stderr.decode('utf8', 'replace').strip().splitlines()
        raise IndexUnavailable('git rev-parse --show-toplevel exited %d%s'
                               % (t.returncode, (': ' + detail[0]) if detail else ''))
    toplevel = t.stdout.decode('utf8', 'surrogateescape').rstrip('\r\n')
    cwd = os.path.realpath(os.getcwd())
    if not toplevel or os.path.realpath(toplevel) != cwd:
        raise IndexUnavailable(
            'the index belongs to another tree: git --show-toplevel reports %s, '
            'cwd is %s — refusing to certify this tree from a foreign file list'
            % (toplevel or '<none>', cwd))
    paths = [b.decode('utf8', 'surrogateescape') for b in r.stdout.split(b'\0') if b]
    return list(dict.fromkeys(paths))    # unmerged paths appear once per stage


def walk_files():
    """Fallback for a `.git`-less tree: the historical os.walk, pruning `.git`
    and `target`; an unreadable directory is recorded by walk_error, not ignored."""
    found = []
    for root, dirs, files in os.walk('.', onerror=walk_error):
        dirs[:] = [d for d in dirs if d not in ('.git', 'target')]
        for fn in sorted(files):
            found.append(os.path.join(root, fn)[2:])
    return found


def scan(entries):
    """Classify every backtick span in `entries` ([(root-relative path, kind)]).
    A path that is tracked but cannot be read — deleted in the worktree, a
    submodule gitlink listed as a path, or an unreadable file — is recorded and
    fails the scan (exit 3), never a traceback and never a silent skip."""
    n_files = 0
    for p, kind in entries:
        base = os.path.dirname(p)
        crate_base = nearest_manifest_dir(base)
        try:
            lines = md(p) if kind == 'md' else rs(p)
            for lineno, span in spans(lines):
                verdict = classify(span, base, crate_base)
                counts[verdict] += 1
                if verdict == 'stale':
                    hits.append((p, lineno, normalize(span)))
        except OSError as e:
            read_errors.append('%s: %s' % (p, e.strerror or e))
        else:
            n_files += 1
    return n_files


try:
    index = tracked_files()
except IndexUnavailable as e:
    print('scan error: .git is present but the file list could not be read from '
          'the index (%s) — refusing to fall back to a filesystem walk that '
          'would scan gitignored state; refs not certified' % e)
    sys.exit(3)
if index is None:
    candidates = walk_files()
    source = 'filesystem walk (no .git in this tree)'
else:
    candidates = index
    source = 'git ls-files'
entries = []
for p in candidates:
    kind = wanted(p)
    if kind is not None:
        entries.append((p, kind))

if not entries:
    print('scan error: %s listed no scannable .md/.rs file — refusing to report '
          '"no stale refs"' % source)
    sys.exit(3)
n_files = scan(entries)
n_spans = sum(counts.values())
if read_errors:   # a tracked file we could not read is not "no stale refs"
    for e in read_errors:
        print('read error: %s' % e)
    sys.exit(3)
if walk_errors:   # an unreadable directory is not "no stale refs"
    for e in walk_errors:
        print('walk error: %s' % e)
    sys.exit(3)
if n_files == 0 or n_spans == 0:
    print('scan error: %s examined %d file(s) / %d span(s) — refs not certified'
          % (source, n_files, n_spans))
    sys.exit(3)
if n_files < MIN_FILES or n_spans < MIN_SPANS:
    print('scan error: implausibly small scan from %s (%d file(s), %d span(s); '
          'floor %d/%d) — refs not certified'
          % (source, n_files, n_spans, MIN_FILES, MIN_SPANS))
    sys.exit(3)
hits.sort(key=lambda h: (h[0], h[1]))   # path order, then line number
print('%d %d %d %d %d %d' % (counts['ok'], counts['stale'], counts['feature'],
                             counts['shorthand'], counts['bare'], counts['superpowers']))
for p, lineno, ref in hits:
    print('%s:%d: `%s`' % (p, lineno, ref))
PY
)
  path_status=$?
  summary=$(printf '%s\n' "$path_report" | head -1)
  read -r p_ok p_stale p_feat p_short p_bare _ <<EOF
$summary
EOF
  if [ "$path_status" -ne 0 ] || [ -z "$p_ok" ]; then
    printf '%s\n' "$path_report"
    printf '  FAIL  path-reference scan produced no result (exit %s) — refs not certified\n' "$path_status"
    fail=1
  else
    if [ "$p_stale" -gt 0 ]; then
      printf '%s\n' "$path_report" | tail -n +2 | sed '/^$/d' | sed 's/^/    stale: /'
      printf '  FAIL  %s path reference(s) do not resolve from the referencing file\n' "$p_stale"
      fail=1
    else
      printf '  ok    %s repo path references resolve (file-relative, crate root, then repo root)\n' "$p_ok"
    fi
    printf '  info  skipped %s locator-less bare ref(s) and %s locator-less shorthand(s) (no recoverable base); %s `crate/feature` span(s)\n' \
      "$p_bare" "$p_short" "$p_feat"
    printf '        the locator-less refs are the false positives a naive sweep reports; see TODO.md\n'
  fi

  # (e) Gate: the quantitative claims live docs make, each against the source
  # that actually produces the number. Curated on purpose. A general regex sweep
  # for "numbers in docs" is useless here — it reports every port, version and
  # buffer size in the tree. The rule this enforces is the one docs/README.md
  # states: a countable figure is generated by a script, or it names the source
  # a reviewer can open. Each entry below therefore pins (file, exact claim
  # wording, where the number comes from); expected values are recomputed from
  # that source on every run, so two stale copies can never agree with each
  # other. The witness line for each entry is printed in the inventory below and
  # is what a release reviewer reconciles.
  #
  # LIMIT (the docs say this too): detection is by *enumerated wording*. A pinned
  # quantity restated in words no entry matches, or added to a new doc, is NOT
  # caught — there is no general "numbers in docs" sweep by design. The rule is
  # therefore: when you add or reword a count in a live doc, add/adjust its entry
  # here in the same change (or delete the copy in favour of a pointer).
  doc_claims=$(python3 -B - <<'PY'
import os, re, stat, subprocess, sys

# --- partial-tree guard ------------------------------------------------------
# Every read below that produces an *expected* value is a measurement input: if
# the working tree does not carry it, or cannot read it, the gate must say
# exactly that and exit 3 ("could not measure"), never traceback and never blame
# the docs. Measured 2026-09-24 on a `git sparse-checkout init --cone && git
# sparse-checkout set docs scripts` tree: vendor_version() raised
# FileNotFoundError ('vendor/rustls/Cargo.toml') and the caller then printed
# "a live doc quotes a figure the tree no longer matches" — a statement about
# the docs for a tree that could not be measured at all.
class PartialTree(Exception):
    """A measurement input the tree cannot supply (sparse/partial checkout)."""

    def __init__(self, path, detail=None, reason=None):
        super().__init__(path)
        self.path = path
        self.detail = detail   # ready-made explanation (e.g. a failed subprocess)
        self.reason = reason   # strerror when the path exists but cannot be read


def read_required(path, errors=None):
    """Read a measurement input; a missing/unreadable/non-UTF-8 one is a PartialTree."""
    # Refuse anything that is not a regular file atomically: os.open is done
    # with O_NONBLOCK (so a FIFO never blocks the open) and fstat on the *same*
    # descriptor decides regular-vs-not, so a symlink flipping between a regular
    # file and a FIFO between a stat and the open cannot hang this read. Absent
    # paths (including a dangling symlink) keep the "is missing" wording; a
    # present non-file gets "not a regular file".
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except FileNotFoundError:
        raise PartialTree(path)
    except OSError as e:
        raise PartialTree(path, reason=e.strerror or e.__class__.__name__)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PartialTree(path, reason='not a regular file')
        with os.fdopen(fd, 'r', encoding='utf8', errors=errors) as f:
            fd = -1
            return f.read()
    except UnicodeDecodeError:
        # Only manifests/scripts reach here strict; unsafe_counts deliberately
        # passes errors='ignore' so one stray byte cannot make the Rust counts
        # unmeasurable.
        raise PartialTree(path, reason='not valid UTF-8')
    except OSError as e:
        raise PartialTree(path, reason=e.strerror or e.__class__.__name__)
    finally:
        if fd >= 0:
            os.close(fd)


def preflight(inputs):
    """Classify every measurement input, without opening it (a FIFO must not hang).

    Returning every failure at once is the point: a partial tree is diagnosed in
    one run, not one path per run. stat/access do not block, so a special file is
    reported rather than read forever; read_required remains the net for a
    present-but-unreadable file and for any path added later but not listed here.
    """
    errs = []
    for path, kind in inputs:
        if not os.path.exists(path):          # absent, or a dangling symlink
            errs.append(PartialTree(path))
        elif kind == 'd':
            if not os.path.isdir(path):
                errs.append(PartialTree(path, reason='not a directory'))
            elif not os.access(path, os.R_OK | os.X_OK):
                errs.append(PartialTree(path, reason='Permission denied'))
        elif not os.path.isfile(path):
            errs.append(PartialTree(path, reason='not a regular file'))
        elif not os.access(path, os.R_OK):
            errs.append(PartialTree(path, reason='Permission denied'))
    return errs


def report_partial(errs):
    """Report every unusable measurement input, then exit 3 ('could not measure')."""
    for e in errs:
        vendor = e.path.startswith('vendor/') and e.path.endswith('/Cargo.toml')
        if e.detail:
            print('  FAIL  partial tree: %s — cannot measure the doc figures' % e.detail)
        elif e.reason == 'no .rs files':
            print('  FAIL  partial tree: %s has no .rs files — cannot measure the doc figures'
                  % e.path)
        elif e.reason in (None, 'No such file or directory', 'Not a directory'):
            if vendor:
                print('  FAIL  vendor manifest missing: %s' % e.path)
            else:
                print('  FAIL  partial tree: %s is missing — cannot measure the doc figures (sparse checkout?)'
                      % e.path)
        elif vendor:
            print('  FAIL  vendor manifest unreadable: %s (%s)' % (e.path, e.reason))
        else:
            print('  FAIL  partial tree: %s is unreadable (%s) — cannot measure the doc figures'
                  % (e.path, e.reason))
    sys.exit(3)


# Preflight — the complete set of measurement inputs, checked before the
# `rust_comments` import (a missing scripts/ made that a ModuleNotFoundError
# traceback) and before any read, so a partial tree is diagnosed in ONE run
# rather than one path per run. 'f' = file, 'd' = directory. read_required stays
# as the belt-and-braces net for any path a later change adds but forgets here.
MEASUREMENT_INPUTS = (
    ('scripts/compat-test.sh', 'f'),             # count_compat() --list, n_xtcp, n_v2gated
    ('scripts/protocol-matrix.sh', 'f'),         # n_rows
    ('scripts/rust_comments.py', 'f'),           # imported just below: code_only()
    ('frp-core/Cargo.toml', 'f'),                # canon_version
    ('frp-core/benches/crypto_bridge.rs', 'f'),  # n_group
    ('frp-server/benches/nathole.rs', 'f'),      # n_group
    ('vendor/rustls/Cargo.toml', 'f'),           # vendor_version
    ('vendor/yamux/Cargo.toml', 'f'),
    ('vendor/russh/Cargo.toml', 'f'),
    ('frp-core/src', 'd'),                       # unsafe_counts('frp-core')
    ('frp-vnet/src', 'd'),                       # unsafe_counts('frp-vnet')
)
_partial = preflight(MEASUREMENT_INPUTS)
if _partial:
    report_partial(_partial)

sys.path.insert(0, 'scripts')
from rust_comments import code_only   # shared: comments removed, literals blanked

# The measurable claims the live docs make, with the source that produces each
# number. Only entries whose claim wording is unambiguous live here: adding one
# is a deliberate statement that a human checked it is not a false positive
# against a clean tree. Expected values are recomputed from source on every run,
# so two stale copies can never agree with each other.
#
# The measured quantity behind each entry (and the definition, where a number is
# ambiguous):
#   compat scenarios        entries of `compat-test.sh --list`
#   XTCP scenarios          `test_xtcp*()` definitions in compat-test.sh
#   V2-gated scenarios      `run_test` under `if ensure_go_frp_v2`, plus
#                           scenarios that self-guard `ensure_go_frp_v2 || return 0`
#   transport rows          `run_row` calls in protocol-matrix.sh
#   bench groups            `bench_*` ids inside a file's `criterion_group!`
#   unsafe block/fn/impl    comment/literal-stripped code counts (Unsafe usage)
#   (client plugin types and fuzz targets are NOT curated — see below)
#
# NOTE on the kept structural counts (bench groups, transport rows, scenario
# counts): these are also matched in source text, so they inherit the same
# limit that disqualified the two dropped claims. Comments and string literals
# are stripped first (scripts/rust_comments.py), so a commented-out entry does
# not satisfy them — but a `#[cfg]`-disabled entry reads identically to a live
# one, and no text check can see that. They are curated because their VALUES
# are stable and drift silently otherwise; they are not proof that the code
# they name is compiled or reachable.
#   vendored crate versions `version` in vendor/<crate>/Cargo.toml
#   frp-rs version          `version` in frp-core/Cargo.toml (prose restatements)
#
# NOT curated: the aggregate test-function total, frp-server/tests count,
# `proptest!` count, and protocol.rs regular-test count (all change whenever a
# test is added, so gating them makes "add a test"
# a cross-PR collision, and the aggregate totals were observed to differ between
# environments on the same tree (215/2069 local vs 216/2071 CI on PR #353; cause
# not established). They stay visible in the Tests section of the report. Also NOT
# curated: client plugin types and fuzz targets, which can only be pinned as
# source text and so cannot establish compilation/enablement. See the longer notes
# next to the counters for why these claims must not be re-added.
#
# "Test function" everywhere here means one `#[test]` / `#[tokio::test]`
# attribute that starts a line after optional indentation, parameterised (e.g.
# `#[tokio::test(flavor = "multi_thread")]`) or not. A comment that merely
# mentions an attribute is not a function and does not count.

def count_compat():
    r = subprocess.run(['bash', 'scripts/compat-test.sh', '--list'],
                       capture_output=True, text=True)
    out = r.stdout.split()
    # A present-but-unrunnable script must not read as "the tree measures 0" —
    # that would be a false claim about the docs. A non-zero exit or an empty
    # token list is the same "could not measure" condition as a missing file
    # (which the preflight already caught); it is never a measured 0.
    if r.returncode != 0 or not out:
        raise PartialTree('scripts/compat-test.sh',
                          '`bash scripts/compat-test.sh --list` produced no scenario list (exit %d)'
                          % r.returncode)
    return sum(1 for x in out if re.match(r'^[a-z0-9_-]+$', x))

# One subprocess: six claims quote this figure, and `--list` is the script's own
# view of which scenarios will run. `--list` covers the non-XTCP scenarios only;
# the 17 XTCP ones are `test_xtcp*()` definitions (they are selected by the
# XTCP_TESTS[] loop, not by a top-level `run_test` line).
try:
    n_compat = count_compat()
except PartialTree as e:
    report_partial([e])

walk_errors = []


def walk_error(e):
    walk_errors.append('%s: %s' % (getattr(e, 'filename', '?'), e.strerror or e))


try:
    n_xtcp = sum(1 for l in read_required('scripts/compat-test.sh').split('\n')
                 if re.match(r'^\s*"test_xtcp[a-z0-9_]*",?\s*$', l))
    n_rows = len(re.findall(r'^\s*run_row ', read_required('scripts/protocol-matrix.sh'), re.M))
except PartialTree as e:
    report_partial([e])
# NOTE: `proptest!` and protocol.rs "regular tests" counts are NOT curated either
# — they are test-function counts that change whenever someone adds a test, the
# same chore as the aggregate totals above. `repo-health.sh` still prints
# `proptest blocks` in the Tests section.
# Scenarios gated on Go frp V2 in compat-test.sh. Two shapes gate a scenario:
# (i) `run_test NAME` inside the `if ensure_go_frp_v2` block, and (ii) a scenario
# function that self-guards with `ensure_go_frp_v2 || return 0` (the two UDP V2
# scenarios are invoked outside that block). The count is the union of names, so
# a scenario that does both is counted once.
try:
    _compat = read_required('scripts/compat-test.sh').split('\n')
except PartialTree as e:
    report_partial([e])
_in_if, _guarded, _cur = set(), set(), None
_seen_if = False
for _l in _compat:
    if re.match(r'\s*if ensure_go_frp_v2\b', _l):
        _seen_if = True
        continue
    if _seen_if and re.match(r'\s*(else|fi)\b', _l):
        _seen_if = False
        continue
    if _seen_if:
        _r = re.match(r'\s*run_test\s+(\S+)', _l)
        if _r:
            _in_if.add(_r.group(1))
    _f = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{', _l)
    if _f:
        _cur = _f.group(1)
    elif _cur and re.match(r'\s*ensure_go_frp_v2\s*\|\|\s*return 0', _l):
        _guarded.add(_cur)
n_v2gated = len(_in_if | _guarded)

def n_group(path):
    m = re.search(r'criterion_group!\(([^)]*)\)', read_required(path))
    return len(re.findall(r'\bbench_[a-z0-9_]+', m.group(1))) if m else 0

# NOTE: the *aggregate* test counts (total test functions, frp-server/tests) are
# deliberately NOT curated here, and must not be re-added as claims:
#   * they change with every test-adding PR, so gating them turns "add a test"
#     into a cross-PR collision on one CLAUDE.md line; and
#   * they are not environment-stable. Observed on PR #353: the SAME committed
#     tree measured 215 / 2069 test functions locally and 216 / 2071 in CI
#     (frp-server/tests +1, total +2). Root cause not established — not
#     investigated further, and deliberately not guessed at.
# A measurement this unstable must be reported, not asserted. `repo-health.sh`
# still prints both in the Tests section (they stay visible/checkable), and
# CLAUDE.md points at the script instead of storing them.

# Client plugin types and fuzz targets are NOT curated. Both can only be checked
# as source text (an expression is present / an `fn fuzz_` exists), which cannot
# establish that the plugin wiring compiles or that the fuzz target is enabled —
# a `#[cfg]`-disabled or broken one still reads the same. Coverage there is
# established by the plugin/compat test suite (`scripts/compat-test.sh`), not by
# a text grep. Attempts to gate them were defeated in review by comment text,
# commented-out lines, binding-name coupling and string/char-literal desync.

# Unsafe counts, computed exactly as the "Unsafe usage" section above does:
# comment-stripped raw occurrence counts, so a doc comment that merely mentions
# an attribute cannot inflate the figure (frp-core/src/mux.rs has such a
# mention). Only frp-core and frp-vnet carry unsafe code.
def unsafe_counts(crate):
    src = os.path.join(crate, 'src')
    if not os.path.isdir(src):
        # A partial tree must not read as "0 unsafe blocks": the counts are
        # *expected* values for the CLAIMS below. The preflight lists these
        # directories too; this is the belt-and-braces path.
        raise PartialTree(src)
    blocks = fns = impls = n_rs = 0
    for root, _d, files in os.walk(src, onerror=walk_error):
        for fn in files:
            if fn.endswith('.rs'):
                n_rs += 1
                text = code_only(read_required(os.path.join(root, fn), errors='ignore'))
                blocks += len(re.findall(r'unsafe\s*\{', text))
                fns += len(re.findall(r'unsafe fn', text))
                impls += len(re.findall(r'unsafe impl', text))
    if n_rs == 0 and not walk_errors:
        # An emptied <crate>/src measures (0,0,0), which the CLAIMS below would
        # report as "the tree measures 0" — a false accusation against the docs.
        # A source directory with no .rs file is not the source those counts come
        # from. (The preflight only proves the directory exists.) A recorded walk
        # error wins: "no .rs files" would be false when the files exist but
        # their directory could not be read, so the block-level
        # `if walk_errors: sys.exit(2)` below reports that instead.
        raise PartialTree(src, reason='no .rs files')
    return (blocks, fns, impls)

try:
    u_core = unsafe_counts('frp-core')
    u_vnet = unsafe_counts('frp-vnet')
except PartialTree as e:
    report_partial([e])

# Vendored crate versions, computed exactly as the "Vendored crates" section
# above does (from each vendor/<crate>/Cargo.toml).
def vendor_version(name):
    path = os.path.join('vendor', name, 'Cargo.toml')
    m = re.search(r'^version\s*=\s*"([^"]+)"', read_required(path), re.M)
    return m.group(1) if m else '?'

# frp-rs's own version (canonical = frp-core/Cargo.toml; the version gate above
# forces the other sources to match it). Live-doc restatements of it are pinned
# here so a bump cannot leave prose behind. References to "Go frp vX.Y.Z" as the
# *compat target* are a different statement and are not pinned.
#
# Every expected value is measured here in one guarded block; the bench-group
# values are precomputed rather than called inside CLAIMS so a missing input is
# reported before any per-claim "claim not found"/"tree measures" line.
try:
    v_rustls = vendor_version('rustls')
    v_yamux = vendor_version('yamux')
    v_russh = vendor_version('russh')
    canon_version = re.search(r'^version\s*=\s*"([^"]+)"',
                              read_required('frp-core/Cargo.toml'), re.M).group(1)
    g_crypto = n_group('frp-core/benches/crypto_bridge.rs')
    g_nathole = n_group('frp-server/benches/nathole.rs')
except PartialTree as e:
    report_partial([e])

if walk_errors:  # a tree walked with errors must not silently undercount
    for e in walk_errors:
        print('walk error: %s' % e)
    sys.exit(2)

# (file, regex whose group 1 is the number the doc claims, expected, source)
# Every live-doc copy of a quantity appears here; see the note above.
CLAIMS = [
    ('README.md',              r'([0-9]+) scenarios plus',                 n_compat, 'compat-test.sh --list'),
    ('README.md',              r'([0-9]+) `compat-test\.sh`',              n_compat, 'compat-test.sh --list'),
    ('CLAUDE.md',              r'([0-9]+) run_test scenarios',             n_compat, 'compat-test.sh --list'),
    ('CLAUDE.md',              r'([0-9]+) passed, 0 failed',               n_compat, 'compat-test.sh --list'),
    ('docs/developing.md',     r'([0-9]+) run_test scenarios',             n_compat, 'compat-test.sh --list'),
    ('docs/developing.md',     r'— ([0-9]+) scenarios \+',                 n_compat, 'compat-test.sh --list'),
    ('docs/architecture.md',   r'compatibility test suite \(([0-9]+) ',    n_compat, 'compat-test.sh --list'),
    ('docs/go-frp-compat-audit.md', r'\*\*([0-9]+) non-XTCP',              n_compat, 'compat-test.sh --list'),
    ('docs/go-frp-compat-audit.md', r'gates: ([0-9]+)/',                   n_compat, 'compat-test.sh --list'),
    ('docs/why-frp-rs.md',     r'runs \*\*([0-9]+)',                       n_compat, 'compat-test.sh --list'),
    ('docs/why-frp-rs.md',     r'对\*\*真实 Go frp 发行版\*\*跑 ([0-9]+) ',  n_compat, 'compat-test.sh --list'),
    ('README.md',              r'([0-9]+)-case XTCP',                      n_xtcp,     "`test_xtcp*()` in compat-test.sh"),
    ('CLAUDE.md',              r'([0-9]+) XTCP pairwise',                  n_xtcp,     "`test_xtcp*()` in compat-test.sh"),
    ('docs/developing.md',     r'([0-9]+) XTCP pairwise',                  n_xtcp,     "`test_xtcp*()` in compat-test.sh"),
    ('docs/developing.md',     r'([0-9]+) tests covering the 2x2',         n_xtcp,     "`test_xtcp*()` in compat-test.sh"),
    ('docs/architecture.md',   r'([0-9]+) XTCP scenarios',                 n_xtcp,     "`test_xtcp*()` in compat-test.sh"),
    ('docs/architecture.md',   r'\(([0-9]+)/[0-9]+ XTCP',                  n_xtcp,     "`test_xtcp*()` in compat-test.sh"),
    ('docs/go-frp-compat-audit.md', r'([0-9]+)-test XTCP',                 n_xtcp,     "`test_xtcp*()` in compat-test.sh"),
    ('docs/why-frp-rs.md',     r'([0-9]+)-case XTCP',                      n_xtcp,     "`test_xtcp*()` in compat-test.sh"),
    ('docs/why-frp-rs.md',     r'([0-9]+) 项 XTCP',                        n_xtcp,     "`test_xtcp*()` in compat-test.sh"),
    ('scripts/README.md',      r'Test Matrix: ([0-9]+) Pairwise',          n_xtcp,     "`test_xtcp*()` in compat-test.sh"),
    ('CLAUDE.md',              r'([0-9]+) transport rows',                 n_rows,     'protocol-matrix.sh `run_row`'),
    ('docs/developing.md',     r'([0-9]+) transport rows',                 n_rows,     'protocol-matrix.sh `run_row`'),
    ('README.md',              r'all ([0-9]+) transport rows',             n_rows,     'protocol-matrix.sh `run_row`'),
    ('README.md',              r'([0-9]+)/[0-9]+ transport rows',          n_rows,     'protocol-matrix.sh `run_row`'),
    ('docs/why-frp-rs.md',     r'all ([0-9]+) transport rows',             n_rows,     'protocol-matrix.sh `run_row`'),
    ('docs/why-frp-rs.md',     r'([0-9]+) 条传输链路',                       n_rows,     'protocol-matrix.sh `run_row`'),
    ('docs/go-frp-compat-audit.md', r'^> ([0-9]+)/[0-9]+\)',               n_rows,     'protocol-matrix.sh `run_row`'),
    ('docs/developing.md',     r'([0-9]+) of which are gated on Go frp V2', n_v2gated, 'V2-gated scenarios in compat-test.sh'),
    ('CLAUDE.md',              r'\(([0-9]+) groups:',                      g_crypto,
                                                                                        'criterion_group! in crypto_bridge.rs'),
    ('docs/developing.md',     r'crypto_bridge\.rs.[^(]*\(([0-9]+) groups', g_crypto,
                                                                                        'criterion_group! in crypto_bridge.rs'),
    ('docs/developing.md',     r'nathole\.rs.[^(]*\(([0-9]+) groups',      g_nathole,
                                                                                        'criterion_group! in nathole.rs'),
    # Unsafe counts — the same numbers the "Unsafe usage" section prints.
    ('CLAUDE.md',              r'frp-core: ([0-9]+) blocks',               u_core[0],  'unsafe-block count, Unsafe usage section'),
    ('CLAUDE.md',              r'\+ ([0-9]+) `unsafe fn`',                 u_core[1],  'unsafe-fn count, Unsafe usage section'),
    ('CLAUDE.md',              r'\+ ([0-9]+) `unsafe impl`',               u_core[2],  'unsafe-impl count, Unsafe usage section'),
    ('CLAUDE.md',              r'frp-vnet: ([0-9]+) blocks',               u_vnet[0],  'unsafe-block count, Unsafe usage section'),
    # Vendored crate versions — the same strings the "Vendored crates" section
    # reads from each vendor/<crate>/Cargo.toml.
    ('README.md',              r'\[`rustls`\]\(vendor/rustls/README-FRP-RS\.md\) \| ([0-9.]+)', v_rustls, 'vendor/rustls/Cargo.toml'),
    ('README.md',              r'\[`yamux`\]\(vendor/yamux/README-FRP-RS\.md\) \| ([0-9.]+)', v_yamux, 'vendor/yamux/Cargo.toml'),
    ('README.md',              r'\[`russh`\]\(vendor/russh/README-FRP-RS\.md\) \| ([0-9.]+)', v_russh, 'vendor/russh/Cargo.toml'),
    ('CLAUDE.md',              r'\*\*Vendored\*\* at `vendor/rustls` ([0-9.]+)', v_rustls, 'vendor/rustls/Cargo.toml'),
    ('CLAUDE.md',              r'pinned by russh ([0-9.]+) \(latest\)',    v_russh,    'vendor/russh/Cargo.toml'),
    ('CLAUDE.md',              r'SSH feature chain \(russh ([0-9.]+)',     v_russh,    'vendor/russh/Cargo.toml'),
    ('docs/architecture.md',   r'vendors rustls \(([0-9.]+) at',           v_rustls,   'vendor/rustls/Cargo.toml'),
    ('docs/developing.md',     r'\(`([0-9.]+)`, the GHSA-2mjx',            v_rustls,   'vendor/rustls/Cargo.toml'),
    # The frp-rs-authored vendored notes restate their version several times;
    # one entry per file checks every frp-rs statement of it (the optional
    # backtick covers "vendors `crate` X.Y.Z"), plus the "Diff from crates.io"
    # continuation line. Each pattern is scoped by the preceding keyword
    # (`Vendored` / `vendors` / `crates.io`), so an unrelated upstream version
    # in the same file (e.g. "hashicorp yamux v0.1.1") cannot satisfy or trip
    # it. Deliberately OUT OF SCOPE, with reasons:
    #   vendor/rustls/README-FRP-RS.md:66  — the 0.23.43 -> 0.23.45 bump history
    #                                        (a historical version, not current)
    #   vendor/rustls/README-FRP-RS.md:93  — crates.io `max_stable_version` /
    #                                        `newest_version`, which move
    #                                        independently of this vendored copy
    #   docs/developing.md:612             — the same crates.io fact
    ('vendor/rustls/README-FRP-RS.md', r'(?:Vendored|vendors|crates\.io)\s+`?rustls`?\s*([0-9]+\.[0-9]+\.[0-9]+)', v_rustls, 'vendor/rustls/Cargo.toml'),
    ('vendor/yamux/README-FRP-RS.md',  r'(?:Vendored|vendors|crates\.io)\s+`?yamux`?\s*([0-9]+\.[0-9]+\.[0-9]+)',  v_yamux,  'vendor/yamux/Cargo.toml'),
    ('vendor/russh/README-FRP-RS.md',  r'(?:Vendored|vendors|crates\.io)\s+`?russh`?\s*([0-9]+\.[0-9]+\.[0-9]+)',  v_russh,  'vendor/russh/Cargo.toml'),
    ('vendor/yamux/README-FRP-RS.md',  r'^([0-9]+\.[0-9]+\.[0-9]+); the full delta', v_yamux, 'vendor/yamux/Cargo.toml'),
    ('vendor/russh/README-FRP-RS.md',  r'^([0-9]+\.[0-9]+\.[0-9]+) \(the normalized', v_russh, 'vendor/russh/Cargo.toml'),
    # frp-rs's own version, as restated in prose (the version gate covers the
    # sources + README). These patterns tolerate losing the surrounding markup
    # (backticks/bold) but still pin the sentence: entries pin exact wording by
    # design, so a real reword reports "claim not found" and the entry must be
    # updated with it. Deliberately NOT pinned: docs/developing.md's crates.io
    # `max_stable_version` 0.23.45 — a crates.io fact that moves independently
    # of the vendored copy, not a statement of the vendored version.
    ('CLAUDE.md',              r'当前\s*`?([0-9]+\.[0-9]+\.[0-9]+)',        canon_version, 'frp-core/Cargo.toml version'),
    ('CLAUDE.md',              r'README at `?([0-9]+\.[0-9]+\.[0-9]+)',     canon_version, 'frp-core/Cargo.toml version'),
    ('docs/go-frp-compat-audit.md', r'as of frp-rs `?([0-9]+\.[0-9]+\.[0-9]+)', canon_version, 'frp-core/Cargo.toml version'),
    ('docs/developing.md',     r'currently \*{0,2}([0-9]+\.[0-9]+\.[0-9]+)', canon_version, 'frp-core/Cargo.toml version'),
]

def preview(line):
    s = line.strip()
    return s if len(s) <= 100 else s[:97] + '...'

fail = []
for i, (path, pat, expected, source) in enumerate(CLAIMS, 1):
    # A doc path that is a FIFO must not hang this gate: read_required refuses a
    # non-regular file atomically and raises PartialTree, which is treated the
    # same as the unreadable/absent case below — the claim is reported not found.
    try:
        lines = read_required(path).split('\n')
    except (PartialTree, UnicodeDecodeError):
        lines = []
    hits = [(j + 1, l) for j, l in enumerate(lines) if re.search(pat, l)]
    if not hits:
        fail.append('  FAIL  #%02d  claim not found in %s  /%s/  '
                    '(the tree now measures %s — claim deleted or reworded?)'
                    % (i, path, pat, expected))
        continue
    where, line = hits[0]
    claimed = re.search(pat, line).group(1)
    for j, l in hits:
        v = re.search(pat, l).group(1)
        if v != str(expected):
            fail.append('  FAIL  #%02d  %s:%d says %s, the tree measures %s (%s)'
                        % (i, path, j, v, expected, source))
    print('  #%02d  %-8s  claimed %-4s  measured %-4s  %s'
          % (i, path, claimed, expected, source))
    print('       witness %s:%d  %s' % (path, where, preview(line)))

if fail:
    print('\n'.join(fail))
    print('  DOC-FIGURES: FAIL — %d doc figure(s) disagree with the tree' % len(fail))
    sys.exit(1)
print('  DOC-FIGURES: ok — %d curated doc figure(s) agree with measured source'
      % len(CLAIMS))
PY
)
  # The decision is the Python process's exit status, never a grep over its
  # stdout: that stdout contains witness lines quoted *from the documents*, so a
  # document could otherwise inject `DOC-FIGURES: ok` and neutralise the gate.
  # Exit 3 is the block's own "could not measure" status (a partial/unreadable
  # tree — its FAIL lines, one per input, are already in the captured output
  # above); exit 2 means the source walk could not complete, which is also not a
  # statement about the docs; any other non-zero status is a real disagreement.
  doc_status=$?
  printf '%s\n' "$doc_claims"
  if [ "$doc_status" -eq 0 ]; then
    printf '  ok    %d curated doc figures agree with the tree (inventory above)\n' \
      "$(printf '%s\n' "$doc_claims" | grep -c 'claimed')"
  elif [ "$doc_status" -eq 3 ]; then
    printf '  FAIL  doc figures not evaluated — the tree is partial (exit 3)\n'
    fail=1
  elif [ "$doc_status" -eq 2 ]; then
    printf '  FAIL  doc figures not evaluated — the walk reported errors (exit 2)\n'
    fail=1
  else
    printf '  FAIL  a live doc quotes a figure the tree no longer matches\n'
    fail=1
  fi

  # (d) Report: the archive inventory size quoted in docs/README.md.
  # Hand-maintained counts go stale silently (it said 81 while the tree had a
  # different number), so measure it here and keep the doc's figure sourced.
  n_arch=$(find docs/archive -type f -name '*.md' ! -name 'README.md' | wc -l | tr -d ' ')
  sz_arch=$(du -sh docs/archive 2>/dev/null | cut -f1)
  printf '  info  archive inventory: %s dated documents (%s)\n' "$n_arch" "$sz_arch"
else
  printf '  FAIL  python3 not found — docs gates (index, paths, doc figures) cannot be evaluated\n'
  fail=1
fi

# ---------------------------------------------------------------- sizes
if [ "${1:-}" = "--sizes" ]; then
  hdr "Release binary sizes (slow — builds)"
  cargo build --release -p frps -p frpc >/dev/null 2>&1
  for b in frps frpc; do
    f="target/release/$b"
    [ -f "$f" ] && printf '  %-6s %s\n' "$b" "$(du -h "$f" | cut -f1)"
  done
else
  hdr "Release binary sizes"
  printf '  skipped (pass --sizes to build and measure)\n'
fi

# Self-check: no captured gate output may contain a failure *line* while the run
# is about to exit 0. Every verdict above comes from a process exit status or
# explicit state, never from grepping printed output — which can contain text
# quoted from documents. This backstops a future gate that prints FAIL without
# setting `fail`. The match is anchored to the exact `  FAIL  ` line prefix the
# script prints: document text only ever appears inside a `witness …` or
# `file:line:` line, so it cannot forge one.
if [ "$fail" -eq 0 ]; then
  for captured in "${unsafe_misses:-}" "${index_misses:-}" "${path_report:-}" "${doc_claims:-}"; do
    if printf '%s\n' "$captured" | grep -q '^  FAIL  '; then
      printf '  FAIL  internal: a gate printed FAIL but the run would exit 0\n'
      fail=1
      break
    fi
  done
fi

hr
if [ "$fail" -eq 0 ]; then
  printf 'RESULT: invariants hold\n'
else
  printf 'RESULT: FAILURES above — fix before release\n'
fi
exit "$fail"
