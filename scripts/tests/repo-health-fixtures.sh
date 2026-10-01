#!/usr/bin/env bash
# repo-health-fixtures.sh — fixture-based checks for scripts/repo-health.sh.
#
# Why this exists: repo-health.sh runs its gates as python programs and maps a
# gate's *own* exit code onto the wrapper's exit code. That mapping is not
# visible from the printed report alone, and two drifts are possible while every
# other check stays green:
#   * a bare `exit 3` (or `fail=3`) at the top level would make the *process*
#     exit 3, which the documented contract (0, or 1 on any failure) forbids;
#   * a claim that "the gate exits 3" about the *process* rather than about the
#     gate would stop matching the wrapper.
#
# This harness builds throwaway trees under `mktemp -d`, runs the script under
# test inside them, and pins both halves: the process rc is 1 (never 3), and the
# gate's *own* row is printed (naming `(exit 3)`). The row must be the specific
# one — "some row carries `(exit 3)`" is vacuous, because a bare tree already
# prints two unrelated `(exit 3)` rows. A throwaway tree is enough because
# repo-health.sh runs its sections top to bottom and never exits early on a
# *failed* gate — it reaches the gate under test regardless of the unrelated
# FAILs a bare tree produces.
#
# Later scenarios go past the exit-code mapping, because a positive check alone
# cannot show that the fixture drives the code it claims to: scenario 4 builds
# the stub inputs that let all four `.rs` walks run and then reverts each walk's
# fall-through in the tree's own copy of the script, one at a time, so the checks
# are shown to red on the right edit; scenario 5 is the clean-tree negative
# control for scenario 1's row; scenario 6 asserts the integration-test-dir
# metric, whose `scripts/tests/` blind spot is why it exists; scenario 7 pins
# site 4's crate-root row with a cross-crate alias (and with the count-inert
# mutation that re-raises it); scenario 8 pins the kernel's symlink-chain refusal
# that makes the in-script `readlink` bound unreachable; scenario 9 shows a failed
# fixture setup stops the run — and pins that **nothing** below it runs at all;
# scenario 10 pins the walk-error path against the false "no .rs files"
# accusation (with both mutations of that guard); scenario 11 pins containment's
# separator with a sibling whose name starts with the crate name.
#
# Self-contained: no network, no dependence on this repo's contents (the tree is
# built from scratch and only the script under test is copied in), and the
# temporary tree is removed on exit.
#
# Usage: bash scripts/tests/repo-health-fixtures.sh
#        (also correct when the harness itself is invoked through a symlink)
set -uo pipefail

# --- self-defence: assert a floor on every exit path --------------------------
# This suite is the only thing that pins `scripts/repo-health.sh`, so a suite
# that silently stops checking must not exit green: `exit "$fail"` alone is happy
# with `RESULT: 0 fixture check(s) hold`. The trap is installed here — before the
# path resolution, the two preflights and the first `ok`/`bad` — so an early
# `exit 0` anywhere below it still has to answer to the floor. `MIN_CHECKS` is
# the measured check count of a green run; with an exact floor, emptying any
# scenario body drops the count below it and reds (TODO.md:8127).
#
# Three limits are stated rather than hidden:
#   * a floor of 0 (or an unset floor, or a zero-padded all-zero floor such as
#     `00`/`000`, which denote 0 but are still all digits) would disable the
#     guard from inside, so each is itself a failure: leading zeros are stripped
#     before the comparison, so no spelling of zero slips past the `0)` arm, and
#     diagnostics print the decimal value — `printf '%d'` reads `032` as octal
#     26, so it is not used (R2-2/R2-3);
#   * the floor is never compared with `[ … -lt … ]` on the values: a floor that
#     is not a number is rejected by the `case` arms below — an empty or
#     non-digit `MIN_CHECKS` (and a non-digit `checks`) is a failure, not a skip
#     — and the below-floor test is an ordered comparison of digit strings:
#     length first (`[ "${#checks}" -lt "${#MIN_CHECKS}" ]`, with `-eq` on the
#     lengths to reach the tie-break), then left-to-right at equal length
#     (`[ "$checks" \< "$MIN_CHECKS" ]`). So `-lt` only ever sees two *lengths* —
#     short decimal numbers — and cannot return status 2 on an all-digit floor,
#     however long: a value above `9223372036854775807` is unparseable as an
#     integer but fine as a string, so it lands as an ordinary below-floor
#     failure rather than a skipped branch (R3-1). Length-then-string order is
#     exactly numeric order for digit strings, which is what makes it fail
#     closed;
#   * `exec true` in place of an ordinary exit still skips the EXIT trap — no
#     in-file mechanism can intercept `exec`, and the sibling suite had the same
#     hole. The closure for that one is outside the file: the CI step's own
#     `grep -qF 'RESULT: %d fixture check(s) hold'` plus its `  ok` line count on
#     the captured output (`.github/workflows/ci.yml`), which see a missing
#     RESULT line and a planted one with no assertions behind it.
# A total is also not a *shape*, so `delete N checks, add N dummy ok lines`
# keeps it; the sibling pins its ordered assertion list for that reason. Here the
# assertion set is loop-driven (scenario 4 walks four sites, scenario 10 two
# shapes), and there is no per-scenario tally to pin: `checks` is one run-wide
# counter, initialised to 0 and bumped once by every `ok()` and every `bad()`
# call, so the floor it feeds (`MIN_CHECKS`) bounds the number of assertions
# *attempted* across the whole run — passed and failed alike, with no
# per-scenario breakdown and no relation to the number of `ok` lines printed.
# Pinning an ordered assertion list would need a second instrumented counter per
# scenario, which this suite does not keep; the count is what can be pinned, and
# that residual gap is recorded in the batch-E report.
MIN_CHECKS=32
checks=0
fail=0
tmp=""

ok()  { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fail=1; printf '  FAIL  %s\n' "$1"; }
hdr() { printf '%s\n' "------------------------------------------------------------"; }

# enforce_substance — the substance half of the floor. `MIN_CHECKS` only bounds
# how many assertions ran, and every label is spelled at the call site, so
# replacing a condition kept the total and the suite green: `if true; then` on
# scenario 6's metric check (RH-M2) and `if false; then` on scenario 7's
# aliased-crate-root check (N1/C3), both measured by the adversarial reviewer.
# Every region marked `substance pin:` is therefore checksummed byte-for-byte,
# the way scenarios 2/10/12/13 are in `scripts/tests/compat-stray-guard.sh`; an
# edit inside one reds until the matching constant below is updated, and the
# failure text prints the value to paste. The pins add no `ok`/`bad` call of
# their own, so they cannot move the count — or the ci.yml literal that pins it
# — by themselves. `self` is resolved further down this file, which is fine: the
# check only runs from the EXIT trap, after it is set.
SCEN6_REGION_SHA='7d31d2b613e1e578c7050a5328cb677f4aac2eba1c6d9a7248f0216d1dd06af7'
SCEN7_REGION_SHA='941be4f7805b74ff79b691e463f91dd011a1b549cd17995f09542ff8d3f40500'
region_sha() {   # $1 = region name, spelled as between the `substance pin:` markers
  local name=$1 tool
  if [ -z "${self:-}" ]; then
    printf 'FAIL  cannot locate %s to checksum the %s region\n' "$0" "$name" >&2
    return 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    tool='sha256sum'
  elif command -v shasum >/dev/null 2>&1; then
    tool='shasum -a 256'
  else
    printf 'FAIL  no sha256 tool on PATH (need sha256sum or shasum); cannot check the %s region\n' "$name" >&2
    return 1
  fi
  # shellcheck disable=SC2086  # $tool is the word-split "shasum -a 256"
  sed -n "/^# --- substance pin: ${name} /,/^# --- end substance pin: ${name} ---/p" "$self" |
    $tool | awk '{print $1}'
}
enforce_substance() {
  local name const got want
  for name in scenario-6 scenario-7; do
    case $name in
      scenario-6) const=SCEN6_REGION_SHA; want=$SCEN6_REGION_SHA ;;
      scenario-7) const=SCEN7_REGION_SHA; want=$SCEN7_REGION_SHA ;;
    esac
    got=$(region_sha "$name") || return 1
    if [ "$got" != "$want" ]; then
      printf 'FAIL  %s region changed: sha256 %s, pinned %s\n' \
        "$name" "${got:-<none>}" "$want" >&2
      printf '      deliberate edit? set %s in %s to the value above\n' \
        "$const" "${self:-this script}" >&2
      return 1
    fi
  done
  return 0
}

cleanup_all() {
  local rc=$? min_raw
  [ -z "$tmp" ] || rm -rf "$tmp"
  if [ "$rc" -eq 0 ]; then
    # Fail closed: `[ NaN -lt 1 ]` is status 2, and `if`/`elif` read status 2 as
    # false, so an unparseable floor used to skip every branch below and exit 0
    # (measured: delete a scenario's assertions, set MIN_CHECKS=NaN, rc 0). The
    # case arms reject a floor that is not a number, and the digits-only arm also
    # rejects a zero-padded zero; the comparison under it is a string order
    # (see below), so an all-digit floor *too large* to be an integer is a
    # below-floor failure, not a status-2 skip.
    case ${MIN_CHECKS:-} in
      ''|0)
        printf 'FAIL  the check floor is disabled (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
          "${MIN_CHECKS:-<unset>}" >&2
        rc=1
        ;;
      *[!0-9]*)
        printf 'FAIL  the check floor is not a number (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
          "$MIN_CHECKS" >&2
        rc=1
        ;;
      *)
        # The digits-only arm above still lets a zero-padded floor through:
        # `00`/`000` denote 0 but never reach the `0)` arm, so the floor was
        # silently off (R2-2, measured `RESULT: 32` rc 0 with the floor written
        # `000`). Strip the leading zeros — a plain string strip, not
        # `$(( … ))`, whose base detection is the thing being avoided — and treat
        # the result as the floor; `min_raw` keeps the author's spelling for the
        # diagnostic. Only zeros leave an empty string, i.e. the disabled case.
        min_raw=$MIN_CHECKS
        while [ "${MIN_CHECKS#0}" != "$MIN_CHECKS" ]; do
          MIN_CHECKS=${MIN_CHECKS#0}
        done
        if [ -z "$MIN_CHECKS" ]; then
          printf 'FAIL  the check floor is disabled (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
            "$min_raw" >&2
          rc=1
        else
          case $checks in
            ''|*[!0-9]*)
              printf 'FAIL  the check counter is not a number (%s); the suite cannot vouch for itself\n' \
                "$checks" >&2
              rc=1
              ;;
            *)
              # Ordered comparison of *digit strings* — length first, then
              # left-to-right at equal length — never a bare `[ … -lt … ]`. An
              # all-digit floor above the signed 64-bit range is unparseable as
              # an integer but fine as a string: `[ "$checks" -lt "$MIN_CHECKS" ]`
              # on `9223372036854775808` returns status 2 (stderr
              # `[: 9223372036854775808: integer expression expected`), `if`
              # reads status 2 as false, the below-floor branch is skipped and a
              # gutted run still exits 0
              # (R3-1; measured rc 0). The digits-only arm above cannot catch it
              # — the value *is* all digits. After the leading-zero strip above,
              # length-then-string order is exactly numeric order for digit
              # strings and cannot return status 2 for any value.
              if [ "${#checks}" -lt "${#MIN_CHECKS}" ] ||
                { [ "${#checks}" -eq "${#MIN_CHECKS}" ] && [ "$checks" \< "$MIN_CHECKS" ]; }; then
                printf 'FAIL  suite exited 0 after only %s check(s); expected at least %s — scenarios did not run\n' \
                  "$checks" "$MIN_CHECKS" >&2
                rc=1
              elif ! enforce_substance; then
                rc=1
              fi
              ;;
          esac
        fi
        ;;
    esac
  fi
  exit "$rc"
}
trap cleanup_all EXIT

self=${BASH_SOURCE[0]:-$0}
case "$self" in
  */*) ;;
  *) if [ -e "$self" ]; then
       self=$PWD/$self
     else
       self=$(command -v -- "$self") || {
         printf 'FAIL  cannot locate the harness: %s\n' "$0"; exit 1; }
     fi ;;
esac
# Follow symlinks to the real file before deriving the repo root. Without this,
# invoking the harness through a symlink (a `ln -s … /tmp/rhfx.sh`, or a wrapper
# in another directory) resolved `../..` against the *link's* directory and looked
# for `//scripts/repo-health.sh`. `readlink -f` is not POSIX and older macOS/BSD
# releases lack it, so loop on plain `readlink`, resolving each target against the
# link's own directory. Bounded for defence in depth, but the bound is
# unreachable in practice: `bash` cannot open this file through a cycle at all —
# the kernel refuses the chain first (measured on this host with a physical path:
# a 32-link chain to this file runs green, a 33-link chain is refused with `Too
# many levels of symbolic links`, rc 126; Linux allows 40 hops, Darwin 32, so the
# kernel always fires before the counter passes 40). An earlier probe under
# `/tmp` counted one hop fewer because `/tmp` is itself a symlink on this host,
# and the prefix's symlinks count toward the same kernel limit; the number in
# `02723f36`'s message is that earlier count. Scenario 8 pins the refusal.
n=0
while [ -L "$self" ]; do
  dir=$(cd -P -- "$(dirname -- "$self")" && pwd) || exit 1
  link=$(readlink -- "$self") || exit 1
  case "$link" in
    /*) self=$link ;;
    *)  self=$dir/$link ;;
  esac
  n=$((n + 1))
  if [ "$n" -gt 40 ]; then
    # Defensive only: unreachable while the kernel's own limit is <= 40 hops
    # (see the comment above and scenario 8). Kept so a platform that does
    # resolve deeper still fails loudly here instead of looping.
    printf 'FAIL  cannot resolve the harness path (symlink cycle?): %s\n' "$0"
    exit 1
  fi
done
# Make `$self` absolute before scenario 8 links to it: it can still be the
# relative path the caller typed (`scripts/tests/repo-health-fixtures.sh`), which
# only resolves from the repo root — a link created under `$tmp` would dangle.
self=$(cd -P -- "$(dirname -- "$self")" && pwd)/$(basename -- "$self")
cd -P -- "$(dirname -- "$self")/../.." || exit 1
RH=$PWD/scripts/repo-health.sh
if [ ! -f "$RH" ]; then
  printf 'FAIL  cannot find the script under test: %s\n' "$RH"
  exit 1
fi
RC_PY=$PWD/scripts/rust_comments.py
if [ ! -f "$RC_PY" ]; then
  printf 'FAIL  cannot find the module the script under test imports: %s\n' "$RC_PY"
  exit 1
fi

tmp=$(mktemp -d) || exit 1

printf '%s\n' 'repo-health.sh fixture checks'

# new_tree <name> — print the path of a throwaway root carrying the script under
# test at scripts/repo-health.sh and an empty docs/archive/.
new_tree() {
  d=$tmp/$1
  mkdir -p "$d/scripts" "$d/docs/archive" "$d/.github/workflows" || return 1
  cp "$RH" "$d/scripts/repo-health.sh" || return 1
  printf '%s\n' "$d"
}

# new_full_tree <name> — new_tree plus the stub measurement inputs that let every
# `.rs` walk actually run. A bare tree cannot show that: the Unsafe usage table
# and the SAFETY scan die on `import rust_comments` (no scripts/ module), and the
# fourth walk (`unsafe_counts` in the doc-figures block) is never reached because
# the preflight reports the missing measurement inputs first and exits. The stubs
# are deliberately minimal — the doc-figure claims below them will not match, so
# the tree is red anyway; that is fine, the checks read per-walk rows.
new_full_tree() {
  d=$(new_tree "$1") || return 1
  mkdir -p "$d/frp-core/src" "$d/frp-vnet/src" "$d/frp-core/benches" \
           "$d/frp-server/benches" "$d/vendor/rustls" "$d/vendor/yamux" \
           "$d/vendor/russh" || return 1
  cp "$RC_PY" "$d/scripts/rust_comments.py" || return 1
  # `--list` must yield a non-empty token list or count_compat() reports a
  # partial tree and exits before unsafe_counts (site 4) runs.
  cat > "$d/scripts/compat-test.sh" <<'STUB' || return 1
#!/usr/bin/env bash
if [ "${1:-}" = "--list" ]; then printf 'test_alpha\ntest_beta\n'; fi
exit 0
STUB
  printf '#!/usr/bin/env bash\nexit 0\n' > "$d/scripts/protocol-matrix.sh"
  printf '[package]\nname = "frp-core"\nversion = "0.71.0"\n' > "$d/frp-core/Cargo.toml"
  for v in rustls yamux russh; do
    printf '[package]\nname = "%s"\nversion = "1.2.3"\n' "$v" > "$d/vendor/$v/Cargo.toml"
  done
  printf 'pub fn placeholder() {}\n' > "$d/frp-core/src/lib.rs"
  printf 'pub fn placeholder() {}\n' > "$d/frp-vnet/src/lib.rs"
  printf 'pub fn placeholder() {}\n' > "$d/frp-core/benches/crypto_bridge.rs"
  printf 'pub fn placeholder() {}\n' > "$d/frp-server/benches/nathole.rs"
  printf '%s\n' "$d"
}

# mut_rwalk <tree> <site> — revert, in the tree's copy of the script, the "a file
# that cannot be stat-ed is still read, so its error is reported" fall-through at
# one of the four `.rs` walk sites. Site 1 is `rs_texts`' `fresh()`; sites 2-4 are
# the three inline walks in file order (Unsafe usage table, SAFETY scan,
# unsafe_counts). The anchor count is asserted, so a refactor that moves the code
# fails the mutation loudly instead of mutating nothing — which would leave the
# teeth-checks vacuously green.
mut_rwalk() {
  python3 - "$1" "$2" <<'PY'
import sys
tree, site = sys.argv[1], int(sys.argv[2])
p = tree + '/scripts/repo-health.sh'
s = open(p).read()
if site == 1:
    old = '        except OSError:\n            return os.path.realpath(path)'
    assert s.count(old) == 1, 'site 1 anchor found %d times' % s.count(old)
    s = s.replace(old, '        except OSError:\n            return None', 1)
else:
    old = 'key = real'
    assert s.count(old) == 3, 'site 2-4 anchor found %d times' % s.count(old)
    i = -1
    for _ in range(site - 1):
        i = s.find(old, i + 1)
    s = s[:i] + 'continue' + s[i + len(old):]
open(p, 'w').write(s)
PY
}

# mut_npresent <tree> — move the site-4 `n_present` increment past the shared
# dedupe `continue`. That refactor is count-inert (blocks/fns/impls are unchanged
# — the deduped file was never going to be counted) and only changes the
# crate-root row, which is exactly what scenario 7 pins. The anchor is asserted
# so a refactor that moves the code fails loudly instead of mutating nothing.
mut_npresent() {
  python3 - "$1" <<'PY'
import sys
p = sys.argv[1] + '/scripts/repo-health.sh'
s = open(p).read()
old = ('                n_present += 1\n'
       '                if key in seen:\n'
       '                    continue\n')
new = ('                if key in seen:\n'
       '                    continue\n'
       '                n_present += 1\n')
assert s.count(old) == 1, 'n_present anchor found %d times' % s.count(old)
open(p, 'w').write(s.replace(old, new, 1))
PY
}

# mut_walkerr <tree> <b|c> — the two `unsafe_counts` walk-error mutants the
# doc-figures block's guard exists for, both invisible to every other fixture
# (each keeps rc 1 and prints no extra FAIL row):
#   b: drop `onerror=walk_error` from the `unsafe_counts` walk. It is the walk
#      that fills `walk_errors`, so the collection stays empty and the
#      `n_present == 0` raise accuses a crate the walk could not read.
#   c: drop `and not walk_errors` from that raise — the same false accusation
#      while the walk error *was* collected.
# `os.walk(src, onerror=walk_error)` occurs three times (the Unsafe usage table,
# the SAFETY scan, `unsafe_counts` in file order); the anchor count is asserted
# and the site is picked by index, so a refactor that moves the walk fails the
# mutation loudly instead of mutating the wrong block.
mut_walkerr() {
  python3 - "$1" "$2" <<'PY'
import sys
tree, shape = sys.argv[1], sys.argv[2]
p = tree + '/scripts/repo-health.sh'
s = open(p).read()
if shape == 'b':
    old = 'os.walk(src, onerror=walk_error)'
    assert s.count(old) == 3, 'walk anchor found %d times' % s.count(old)
    i = -1
    for _ in range(3):
        i = s.find(old, i + 1)
    s = s[:i] + 'os.walk(src)' + s[i + len(old):]
else:
    old = 'if n_present == 0 and not walk_errors:'
    assert s.count(old) == 1, 'walk_errors anchor found %d times' % s.count(old)
    s = s.replace(old, 'if n_present == 0:', 1)
open(p, 'w').write(s)
PY
}

# mut_prefix <tree> — drop the separator from `unsafe_counts`' containment test,
# so a sibling directory whose name merely *starts with* the crate name
# (`frp-core-fake/` next to `frp-core/`) is treated as inside the crate and its
# `.rs` files are counted in the crate's row. The anchor occurs four times
# (`rs_texts.fresh` and the three inline walks); the fourth, in file order, is
# `unsafe_counts`. The count is asserted and the site picked by index, so a
# refactor fails loudly rather than mutating another walk.
mut_prefix() {
  python3 - "$1" <<'PY'
import sys
p = sys.argv[1] + '/scripts/repo-health.sh'
s = open(p).read()
old = 'if not real.startswith(within_real + os.sep):'
assert s.count(old) == 4, 'containment anchor found %d times' % s.count(old)
i = -1
for _ in range(4):
    i = s.find(old, i + 1)
s = s[:i] + 'if not real.startswith(within_real):' + s[i + len(old):]
open(p, 'w').write(s)
PY
}

# tree <name> [full] — set TREE to a fresh throwaway root, or stop the harness
# loudly. The helpers return non-zero when a `mkdir`/`cp` fails, but a bare
# `t=$(new_tree …)` hides that status, and the scenario then ran against an empty
# tree: measured with `chmod 000 scripts/repo-health.sh`, both `newline … no forged
# hit from the split path` checks and `clean archive scan: no archive exit-3 row`
# went vacuous-green while the run was still rc 1 for unrelated reasons.
# Scenario 9 pins this failure, and `setup_die` is the only stop: the helpers
# return non-zero exactly when they printed no root, so a successful call always
# sets a non-empty `TREE`. A second `[ -z "$TREE" ]` guard used to stand here; it
# was reachable only under scenario 9's mutant (`setup_die`'s `exit 1` changed to
# `return 0`), where it fired as an extra `fixture abort:` row that scenario 9
# reads as a row running past the setup FAIL. Pinning it with a scenario was
# rejected: forcing an empty root drives every other scenario, and re-enters this
# harness's own self-copy, against the filesystem root.
tree() {
  if [ -n "${2:-}" ]; then
    TREE=$(new_full_tree "$1") || setup_die "new_full_tree $1"
  else
    TREE=$(new_tree "$1") || setup_die "new_tree $1"
  fi
}

setup_die() {
  bad "fixture setup: $1 failed (mkdir/cp rc) — every check below it would be vacuous"
  exit 1
}

# out_count <needle> — how many lines of the last run_gate output contain it.
out_count() { printf '%s\n' "$out" | grep -cF -- "$1"; }

# run_gate <tree> — run the copied script from inside the tree; sets rc and out.
run_gate() {
  out=$(cd "$1" && bash scripts/repo-health.sh 2>&1)
  rc=$?
}

# assert_exit_mapping <label> <exact FAIL row> — the process rc is 1 (never 3),
# and that specific row is printed. Measured vacuity of the looser check: a bare
# tree already prints `path-reference scan produced no result (exit 3)` and
# `doc figures not evaluated — the tree is partial (exit 3)`, so `rc=1` plus
# "some `(exit 3)` row" held with the archive gate's own `sys.exit(3)` changed
# to `sys.exit(0)` *and* with that row's annotation reworded.
assert_exit_mapping() {
  if [ "$rc" -eq 1 ]; then
    ok "$1: process rc is 1"
  else
    bad "$1: process rc is $rc (expected 1 — a bare exit 3/fail=3 regression?)"
  fi
  if printf '%s\n' "$out" | grep -qF -- "$2"; then
    ok "$1: the expected FAIL row is printed"
  else
    bad "$1: expected FAIL row missing: $2"
  fi
}

# --- scenario 1: a gate exits 3 ---------------------------------------------
# A dangling symlink under docs/archive/ makes the archive-path scan record a
# read error and exit 3; the wrapper must still return 1 and say `(exit 3)`.
hdr
printf '%s\n' 'scenario 1: a gate exits 3 (dangling docs/archive symlink)'
tree exit3
t=$TREE
ln -s nowhere.md "$t/docs/archive/bad.md"
run_gate "$t"
assert_exit_mapping 'exit-3 gate' '  FAIL  archive path scan failed (exit 3)'
if [ "$rc" -eq 3 ]; then
  bad 'the process itself exited 3 (a bare exit 3/fail=3 at top level)'
fi

# --- scenario 2: a newline in a workflow filename ---------------------------
# The scan hands hits to bash as `C <path>:<line>:<text>` lines, so a workflow
# whose own name contains a newline split a hit and had the fragment re-parsed
# as a hit of its own (a fabricated `toolchain:` violation). The path must be
# refused fail-closed: the refusal names it (sanitized), nothing in it is
# scanned, and no forged hit is printed.
hdr
printf '%s\n' 'scenario 2: a workflow filename containing a newline'
tree newline
t=$TREE
wf="$t/.github/workflows/"$'a\nC forged.yml'
printf 'name: probe\non: push\njobs:\n  a:\n    steps:\n      - uses: actions-rust-lang/setup-rust-toolchain@v1\n        with:\n          toolchain: 1.98.0\n' > "$wf"
run_gate "$t"
if printf '%s\n' "$out" | grep -q 'workflow path with a newline in its name was not scanned'; then
  ok 'newline path: the workflow is refused by name'
else
  bad 'newline path: no refusal naming the workflow'
fi
if printf '%s\n' "$out" | grep -q 'toolchain:.*input(s)'; then
  bad 'newline path: a forged toolchain: hit was parsed from the split line'
else
  ok 'newline path: no forged hit from the split path'
fi
if printf '%s\n' "$out" | grep -q 'toolchain input scan not evaluated'; then
  ok 'newline path: the scan reports itself not evaluated (fail-closed)'
else
  bad 'newline path: the scan did not report itself not evaluated'
fi
if [ "$rc" -eq 1 ]; then
  ok 'newline path: process rc is 1'
else
  bad "newline path: process rc is $rc (expected 1)"
fi

# --- scenario 3: a newline in a workflow *directory* ------------------------
# The guard must test the whole path, not the basename: a directory named
# `sub<LF>C forged.yml` around a `probe.yml` carrying a floating-toolchain line
# makes the scan print a `D <path>:<line>:<text>` hit whose first line is the
# directory fragment; the `C ` rest is then re-parsed as a fabricated
# `toolchain:` input (measured: `FAIL 1 toolchain: input(s)`).
hdr
printf '%s\n' 'scenario 3: a workflow directory containing a newline'
tree newline-dir
t=$TREE
dir="$t/.github/workflows/"$'sub\nC forged.yml'
mkdir -p "$dir"
printf 'name: probe\non: push\njobs:\n  a:\n    steps:\n      - run: rustup default stable\n' > "$dir/probe.yml"
run_gate "$t"
if printf '%s\n' "$out" | grep -q 'workflow path with a newline in its name was not scanned'; then
  ok 'newline dir: the workflow is refused by name'
else
  bad 'newline dir: no refusal naming the workflow'
fi
if printf '%s\n' "$out" | grep -q 'toolchain:.*input(s)'; then
  bad 'newline dir: a forged toolchain: hit was parsed from the split line'
else
  ok 'newline dir: no forged hit from the split path'
fi
if printf '%s\n' "$out" | grep -q 'toolchain input scan not evaluated'; then
  ok 'newline dir: the scan reports itself not evaluated (fail-closed)'
else
  bad 'newline dir: the scan did not report itself not evaluated'
fi
if [ "$rc" -eq 1 ]; then
  ok 'newline dir: process rc is 1'
else
  bad "newline dir: process rc is $rc (expected 1)"
fi

# --- scenario 4: an unreadable .rs reaches every walk site ------------------
# Containment must not be checked before readability: a dangling symlink in
# `frp-core/src/` resolves *outside* the crate, and skipping it there hides the
# read error, so a source-count gate would print `ok` over an unreadable input.
# Four separate `.rs` walks exist, and a bare tree pins only the first, so the
# fixture supplies the stub inputs that let all four run and pins each site's own
# evidence: the path is reported by the three read-scope walks (site 1 walks two
# scopes, hence 4 lines) and named by the doc-figures block as a partial tree.
# The four mutants below are what give those two checks teeth — reverting the
# fall-through at any one site drops its line(s), or the partial-tree row.
hdr
printf '%s\n' "scenario 4: an unreadable .rs reaches every walk site"
tree unreadable full
t=$TREE
ln -s nowhere "$t/frp-core/src/zz_broken.rs"
run_gate "$t"
n=$(out_count 'scan error: frp-core/src/zz_broken.rs')
if [ "$n" -eq 4 ]; then
  ok 'unreadable src: reported by all three read-scope walks (4 = src + crate scope)'
else
  bad "unreadable src: expected 4 scan-error lines, got $n"
fi
if printf '%s\n' "$out" | grep -qF 'partial tree: frp-core/src/zz_broken.rs is missing'; then
  ok 'unreadable src: the doc-figures block reports it as a partial tree (site 4)'
else
  bad 'unreadable src: unsafe_counts dropped the broken path (site 4)'
fi
if [ "$rc" -eq 1 ]; then
  ok 'unreadable src: process rc is 1'
else
  bad "unreadable src: process rc is $rc (expected 1)"
fi
for site in 1 2 3 4; do
  tree "unreadable-mut$site" full
  t=$TREE
  ln -s nowhere "$t/frp-core/src/zz_broken.rs"
  # A mutation that does not apply must be a hard failure, not a silently absent
  # edit: the site check below would then pass on the un-mutated tree and report
  # "check has teeth" for the wrong reason. (set -u/-o pipefail, no -e, and the
  # python `assert` is unchecked by the caller, so test the rc here.)
  if ! mut_rwalk "$t" "$site"; then
    bad "unreadable src: site $site mutation failed to apply — anchor missing, the site check would be vacuous"
    continue
  fi
  run_gate "$t"
  if [ "$site" -eq 4 ]; then
    # Site 4 emits no `scan error:` line (it raises out of the whole block), so
    # its revert is pinned by the partial-tree row instead of the count.
    if printf '%s\n' "$out" | grep -qF 'partial tree: frp-core/src/zz_broken.rs is missing'; then
      bad "unreadable src: site $site reverted but the partial-tree row survived"
    else
      ok "unreadable src: site $site revert drops the partial-tree row (check has teeth)"
    fi
  else
    # Exact remainder, not "anything but 4": site 1 walks two scopes, so its
    # revert drops two of the four lines; sites 2/3 drop one each. Measured
    # (baseline 4): site 1 -> 2, sites 2/3 -> 3. A walk that dropped *more* than
    # its own evidence would be a real regression and must not read `ok`.
    case "$site" in 1) want=2 ;; *) want=3 ;; esac
    n=$(out_count 'scan error: frp-core/src/zz_broken.rs')
    if [ "$n" -eq "$want" ]; then
      ok "unreadable src: site $site revert leaves exactly $want of 4 scan-error lines ($n — check has teeth)"
    else
      bad "unreadable src: site $site revert left $n scan-error line(s); measured baseline 4, this site's drop is 4 -> $want"
    fi
  fi
done

# --- scenario 5: the archive (exit 3) row is not printed unconditionally ----
# Negative control for scenario 1: a wrapper that printed the `(exit 3)` row
# without the gate having exited 3 would satisfy scenario 1 while the report no
# longer reflects the gate at all.
hdr
printf '%s\n' 'scenario 5: the archive exit-3 row is absent when the scan succeeds'
tree clean-archive
t=$TREE
run_gate "$t"
if printf '%s\n' "$out" | grep -qF '  FAIL  archive path scan failed'; then
  bad 'clean archive scan: the archive exit-3 row was printed anyway'
else
  ok 'clean archive scan: no archive exit-3 row'
fi

# --- scenario 6: the integration-test-dir metric, with its heuristic ---------
# The metric counts `tests/` directories that carry at least one `.rs` file
# beneath them (a `.rs` anywhere below counts, however deep; a `tests/` dir with
# no `.rs` is dropped). Asserted, not described: a `scripts/tests/` holding a
# non-Rust file must not count, so this pins the F4 fix that stopped the harness'
# own script directory from inflating the number, and both the nested-file rule
# and the "has a .rs" rule at once.
#
# The verdict is a `substance pin` region: the count floor can only see how many
# assertions ran, so replacing this check's condition with `if true; then` kept
# the total (32), every label, and CI green (RH-M2, measured by the adversarial
# reviewer). `enforce_substance` checksums the region instead.
# --- substance pin: scenario-6 (checksummed by enforce_substance) ---
hdr
printf '%s\n' 'scenario 6: the integration-test-dir metric counts only .rs-bearing tests/'
tree testdirs
t=$TREE
mkdir -p "$t/scripts/tests" "$t/frp-core/tests" "$t/frp-vnet/tests/deep"
printf '#!/bin/sh\n:\n' > "$t/scripts/tests/not-rust.sh"
printf 'fn t() {}\n' > "$t/frp-core/tests/it.rs"
printf 'fn u() {}\n' > "$t/frp-vnet/tests/deep/nested.rs"
run_gate "$t"
if printf '%s\n' "$out" | grep -qF 'integration test dirs: 2'; then
  ok 'integration test dirs: 2 (scripts/tests dropped; nested .rs counted)'
else
  bad "integration test dirs: expected 2, got $(printf '%s\n' "$out" | grep -F 'integration test dirs' || echo none)"
fi
# --- end substance pin: scenario-6 ---

# --- scenario 7: site 4 counts an aliased crate root as present --------------
# `unsafe_counts` increments `n_present` *before* the shared-inode dedupe
# `continue`, deliberately: "this root carries a .rs file" must not become false
# because the first crate claimed the inode. A hard link from one crate's `src`
# into another crate's tree is exactly that case — the alias resolves inside its
# own crate (so containment passes), yet its inode was already claimed — and with
# the increment moved after the `continue` the crate would raise the misleading
# `has no .rs files` partial-tree row. An intra-crate alias cannot pin this (the
# count would change too), and a `new_full_tree` without the aliased root always
# has its own placeholder. The mutation is count-inert, so only this row moves.
# --- substance pin: scenario-7 (checksummed by enforce_substance) ---
hdr
printf '%s\n' 'scenario 7: a crate root holding only a cross-crate alias is not "no .rs files"'
tree aliased full
t=$TREE
rm -f "$t/frp-vnet/src/lib.rs"
ln "$t/frp-core/src/lib.rs" "$t/frp-vnet/src/alias.rs" || bad 'aliased root: cannot hard-link the alias'
run_gate "$t"
if printf '%s\n' "$out" | grep -qF 'frp-vnet/src has no .rs files'; then
  bad 'aliased root: the crate-root row fired although the directory holds a .rs alias'
else
  ok 'aliased root: the crate-root row is suppressed (the increment precedes the dedupe continue)'
fi
if mut_npresent "$t"; then
  run_gate "$t"
  if printf '%s\n' "$out" | grep -qF 'frp-vnet/src has no .rs files'; then
    ok 'aliased root: moving the increment past the dedupe re-raises the row (check has teeth)'
  else
    bad 'aliased root: the increment-after-dedupe mutation did not re-raise the row'
  fi
else
  bad 'aliased root: mut_npresent failed to apply — anchor missing, the check would be vacuous'
fi
# --- end substance pin: scenario-7 ---

# --- scenario 8: the readlink bound is defensive; the kernel fires first -----
# The harness resolves its own symlink chain (so a wrapper or `ln -s` invocation
# still finds the repo root) and bounds the loop at 40 hops "so a symlink cycle
# cannot hang the run". That branch cannot be reached: `bash` cannot open the file
# through a cycle, because the kernel refuses the chain first (measured on this
# host with a physical path: a 32-link chain to this file runs green, a 33-link
# chain is refused — the earlier "31/32" came from probing under `/tmp`, itself a
# symlink; Linux allows 40 hops, Darwin 32, so 41 hops below is refused on both).
# The assertable half is that refusal — loud, immediate, and not a hang.
hdr
printf '%s\n' 'scenario 8: a 41-link symlink chain is refused by the kernel, not by the bound'
chain=$tmp/chain
mkdir -p "$chain" || bad 'symlink chain: cannot create its directory'
chain_ok=1
prev=$self
entry=
i=0
while [ "$i" -le 40 ]; do
  if ! ln -s "$prev" "$chain/l$i"; then chain_ok=0; break; fi
  prev=$chain/l$i
  entry=$chain/l$i
  i=$((i + 1))
done
if [ "$chain_ok" -ne 1 ]; then
  bad 'symlink chain: could not build the 41-link chain'
else
  # Enter at the **tail** of the chain: `l0` points straight at this harness, so
  # running it would re-run the whole suite instead of traversing 41 links.
  out=$(bash "$entry" 2>&1); rc=$?
  if [ "$rc" -eq 126 ] && printf '%s\n' "$out" | grep -qF 'Too many levels of symbolic links'; then
    ok 'symlink chain: 41 hops is refused by the kernel (rc 126, ELOOP) — the in-script bound is unreachable'
  else
    bad "symlink chain: expected the kernel refusal (rc 126 + ELOOP), got rc=$rc, first line: $(printf '%s' "$out" | head -1)"
  fi
fi

# --- scenario 9: a failed fixture setup stops the run ------------------------
# `new_tree`/`new_full_tree` used to ignore their `mkdir`/`cp` rc: with the script
# under test unreadable (`chmod 000`) the copy silently did not happen and three
# checks went vacuous-green — both `newline … no forged hit from the split path`
# checks and `clean archive scan: no archive exit-3 row` — while the run was still
# rc 1 for unrelated reasons. `tree` now stops at the failed setup. The fixture is
# a *copy* of this harness (at `<root>/scripts/tests/`), so the repo's own script
# is never chmod-ed and the copy fails its first `cp` for the same reason. The
# *abort* is the point, not the message: with `setup_die`'s `exit 1` mutated to
# `return 0` the outer harness stayed at rc 0 / `RESULT: … hold` while the inner
# run printed six vacuous `ok` rows past the FAIL — including scenarios 7 and 8's
# own rows — and went on to attempt `mkdir -p /scripts/… /docs/archive
# /.github/workflows`. The last check below pins that nothing follows the FAIL.
hdr
printf '%s\n' 'scenario 9: an unreadable script under test fails the run loudly'
t=$tmp/selfcheck
mkdir -p "$t/scripts/tests" "$t/docs/archive" "$t/.github/workflows" || bad 'setup-failure fixture: cannot create its root'
cp "$self" "$t/scripts/tests/harness.sh" || bad 'setup-failure fixture: cannot copy this harness'
cp "$RH" "$t/scripts/repo-health.sh" || bad 'setup-failure fixture: cannot copy the script under test'
cp "$RC_PY" "$t/scripts/rust_comments.py" || bad 'setup-failure fixture: cannot copy rust_comments.py'
chmod 000 "$t/scripts/repo-health.sh"
out=$(cd "$t/scripts/tests" && bash harness.sh 2>&1); rc=$?
if [ "$rc" -eq 1 ]; then
  ok 'unreadable script under test: the copied harness exits 1'
else
  bad "unreadable script under test: expected rc 1, got $rc"
fi
if printf '%s\n' "$out" | grep -qF 'fixture setup: new_tree'; then
  ok 'unreadable script under test: the failure names the setup step'
else
  bad "unreadable script under test: no setup FAIL row — the checks below it would go vacuous-green: $(printf '%s' "$out" | head -3)"
fi
past=$(printf '%s\n' "$out" | awk '
  !seen && /^  FAIL  fixture setup: / { seen = 1; next }
  seen && $0 !~ /^[[:space:]]*$/ { print }
')
if [ -z "$past" ]; then
  ok 'unreadable script under test: nothing runs past the failed setup (the FAIL is the last row)'
else
  bad "unreadable script under test: rows ran past the failed setup: $(printf '%s' "$past" | head -3 | tr '\n' '|')"
fi

# unreadable_dir_tree <name> — a full tree whose `frp-vnet/src` holds an
# unreadable subdirectory and no readable `.rs` of its own (frp-core/src keeps its
# placeholder, so the tree still holds a readable `.rs` elsewhere). Both
# `unsafe_counts` walk-error mutants turn this shape into the false
# `frp-vnet/src has no .rs files` row.
unreadable_dir_tree() {
  tree "$1" full
  rm -f "$TREE/frp-vnet/src/lib.rs"
  mkdir -p "$TREE/frp-vnet/src/hidden" || setup_die "unreadable_dir_tree $1"
  chmod 000 "$TREE/frp-vnet/src/hidden"
}

# --- scenario 10: a walk error is reported, not turned into "no .rs files" ----
# The doc-figures walk is the only thing that fills `walk_errors`, and it is what
# separates "this crate holds no `.rs` under `src/`" from "the walk could not read
# part of it". Two `scripts/repo-health.sh` mutants are invisible to every other
# fixture (each leaves rc 1 and prints no extra FAIL): dropping
# `onerror=walk_error` from the `unsafe_counts` walk, and dropping
# `and not walk_errors` from the raise below it. Both turn a crate that *has* a
# readable `.rs` (or merely an unreadable subdirectory) into the accusation
# `frp-vnet/src has no .rs files — cannot measure the doc figures`.
hdr
printf '%s\n' 'scenario 10: an unreadable directory is a walk error, not "no .rs files"'
unreadable_dir_tree walkerr
t=$TREE
run_gate "$t"
chmod 700 "$t/frp-vnet/src/hidden"
if printf '%s\n' "$out" | grep -qF 'has no .rs files'; then
  bad 'walk error: the crate is accused of holding no .rs files although the walk reported an unreadable directory'
else
  ok 'walk error: no "no .rs files" accusation while the crate walk reported an error'
fi
if printf '%s\n' "$out" | grep -qF 'walk error: '; then
  ok 'walk error: the unreadable directory is named in a walk error row'
else
  bad 'walk error: no "walk error:" row for the unreadable directory'
fi
if printf '%s\n' "$out" | grep -qF 'doc figures not evaluated — the walk reported errors (exit 2)'; then
  ok 'walk error: the doc-figures row reports the walk error (exit 2)'
else
  bad 'walk error: the doc-figures row does not report the walk error'
fi
for shape in b c; do
  unreadable_dir_tree "walkerr-$shape"
  t=$TREE
  if mut_walkerr "$t" "$shape"; then
    run_gate "$t"
    chmod 700 "$t/frp-vnet/src/hidden"
    if printf '%s\n' "$out" | grep -qF 'has no .rs files'; then
      ok "walk error ($shape): the guard mutant re-raises the false accusation (check has teeth)"
    else
      bad "walk error ($shape): the mutant did not re-raise the accusation — the check would be vacuous"
    fi
  else
    bad "walk error ($shape): mut_walkerr failed to apply — anchor missing, the check would be vacuous"
  fi
done

# --- scenario 11: containment needs the path separator ------------------------
# `unsafe_counts` excludes a file whose realpath is outside the crate root, so a
# symlink pointing into a *sibling* directory is not counted for the crate. The
# test is `real.startswith(within_real + os.sep)`: dropping the separator makes a
# sibling named `frp-core-fake/` count as inside `frp-core/` (a pure prefix
# match). The fixture places `frp-core-fake/leak.rs` (one `unsafe` block) next to
# `frp-core/` and symlinks it into `frp-core/src/`, so the mutation is visible in
# `unsafe_counts`' result — measured as the doc-figure row that reports what the
# tree measures for `frp-core`'s unsafe-block claim (the fixture's CLAUDE.md does
# not carry that claim, so the row always reports the measurement: `measures 0`
# intact, `measures 1` mutated).
#
# `unsafe_counts` is the walk the mutation targets; the *Unsafe usage table* is a
# second, separate walk in the script with its own copy of this test, so it stays
# 0 under this mutation and is deliberately not the observable here.
hdr
printf '%s\n' 'scenario 11: a sibling whose name starts with the crate name is not the crate'
tree prefix full
t=$TREE
mkdir -p "$t/frp-core-fake" || bad 'containment: cannot create the sibling directory'
printf '%s\n' '// SAFETY: fixture only.' 'pub fn placeholder() {' '    unsafe {}' '}' > "$t/frp-core-fake/leak.rs"
ln -s "$t/frp-core-fake/leak.rs" "$t/frp-core/src/leak.rs" || bad 'containment: cannot symlink the sibling file into frp-core/src'
measured_unsafe() {
  printf '%s\n' "$out" | awk '
    index($0, "frp-core: ([0-9]+) blocks") > 0 {
      for (i = 1; i <= NF; i++)
        if ($i == "measures") { print $(i + 1); exit }
    }
  '
}
run_gate "$t"
blocks=$(measured_unsafe)
if [ -z "$blocks" ]; then
  bad 'containment: no doc-figure row reports the measured frp-core unsafe-block count (the fixture must drive the doc-figures gate)'
elif [ "$blocks" = "0" ]; then
  ok 'containment: the out-of-crate alias is not counted in the doc-figure measurement for frp-core'
else
  bad "containment: the doc-figure measurement for frp-core is $blocks, expected 0 — a sibling directory leaked into it"
fi
if mut_prefix "$t"; then
  run_gate "$t"
  blocks=$(measured_unsafe)
  if [ "$blocks" = "1" ]; then
    ok 'containment: dropping the separator counts the sibling in the measurement (check has teeth)'
  else
    bad "containment: the within_real-without-separator mutation left the measurement at ${blocks:-absent}, expected 1"
  fi
else
  bad 'containment: mut_prefix failed to apply — anchor missing, the check would be vacuous'
fi

# ---------------------------------------------------------------- summary
hdr
if [ "$fail" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), failures above\n' "$checks"
fi
exit "$fail"
