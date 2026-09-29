#!/usr/bin/env bash
# Probe for the symlinked-`.rs`-file double-count in `scripts/repo-health.sh`.
#
# What it models: a symlinked `.rs` *file* inside a crate whose target is
# another `.rs` in the same crate — both inside `src/` (`ln -s kcp/session.rs
# frp-core/src/zz_symlink_probe.rs`) and *outside* it (`ln -s src/kcp/session.rs
# frp-core/zz_symlink_probe.rs`, `ln -s ../src/kcp/session.rs
# frp-core/tests/zz_symlink_probe.rs`). Before the fix, `os.walk` listed the
# link next to its target, so that one source was read twice: `Code size`
# printed 70 files / 78342 lines for `frp-core`, the unsafe table printed 22
# blocks, and `DOC-FIGURES` failed against the curated `CLAUDE.md` claim of 21.
# After the fix every counted walk dedupes on `os.path.realpath` **per scope**,
# so all three read exactly as the symlink-free tree does — including when the
# alias sits outside `src/` and would otherwise mask the real file from the
# `src` scope entirely.
#
# It also pins the two *root* shapes, which are not the same case:
#   * a symlinked directory *inside* a walked root is already excluded by
#     `followlinks=False` (leg 6: `frp-core/src/zz_symlink_probe_dir` ->
#     `../../frp-server/src` leaves the Code size row unchanged);
#   * a scope root that is *itself* a symlink is refused, because
#     `os.walk(root, ..., followlinks=False)` scandirs its own root and so never
#     applied the flag to it. With `mv frp-core/src ... && ln -s ../frp-server/
#     src frp-core/src` the row used to read `32 / 59146` — frp-server's tree —
#     so leg 7 must see rc != 0 and `0 / 0`, and leg 8 (the `top_only`
#     `frp-server/tests` counter) must see 0, not the 137 that following
#     `frp-client/tests` produced while the crate walk counted none of them.
#
# Every compared value is first asserted non-empty, so a parser that matches
# nothing fails the probe instead of passing it vacuously.
#
# What it does NOT model: symlinked files in the walks this item does not cover
# (`.github/workflows/*.yml` hits, `docs/archive/*.md` path refs) stay
# double-counted; a symlink whose target is in *another crate* is counted in
# both crates; a hard link is not deduped (`realpath` cannot see hard links).
# All three are filed in TODO.md. Nor the no-python3 `find -L` fallback inside
# `repo-health.sh`, which still follows a symlinked scope root — the refusal
# above is not on that path (the run is already red there, and the fallback
# carries its own residual comment).
#
# Every run does one full `repo-health.sh` pass per leg; the symlinks, and the
# two scope roots legs 7-8 move aside, are restored by the EXIT trap even on
# failure. `HEALTH=<path>` overrides the script under test (used to check that
# the probe fails against the pre-fix script).
#
# Usage: bash scripts/probe-symlink-file-count.sh
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

HEALTH="${HEALTH:-scripts/repo-health.sh}"
link_src=frp-core/src/zz_symlink_probe.rs
link_root=frp-core/zz_symlink_probe.rs
link_tests=frp-core/tests/zz_symlink_probe.rs
link_a=frp-core/src/zz_symlink_probe_a.rs
link_b=frp-core/src/zz_symlink_probe_b.rs
dir=frp-core/src/zz_symlink_probe_dir
tmp=$(mktemp -d) || exit 2
fail=0
src_real=''
tests_real=''

cleanup() {
  # Restore any scope root moved aside before removing links, so a failure in
  # legs 7-8 (or a Ctrl-C) cannot leave the worktree short a directory.
  if [ -n "$src_real" ] && [ -d "$src_real" ]; then
    rm -f frp-core/src; mv "$src_real" frp-core/src
  fi
  if [ -n "$tests_real" ] && [ -d "$tests_real" ]; then
    rm -f frp-server/tests; mv "$tests_real" frp-server/tests
  fi
  rm -f "$link_src" "$link_root" "$link_tests" "$link_a" "$link_b" "$dir"
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

for p in "$link_src" "$link_root" "$link_tests" "$link_a" "$link_b" "$dir"; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    echo "probe: refusing to run, $p already exists" >&2
    exit 2
  fi
done
if [ -L frp-core/src ] || [ -L frp-server/tests ]; then
  echo "probe: refusing to run, a scope root is already a symlink" >&2
  exit 2
fi

run() {  # run <outfile> — prints the gate's exit code, output goes to <outfile>
  bash "$HEALTH" >"$1" 2>&1
  echo $?
}

row() {     # row <file> — the `frp-core` Code size row as `files/lines`
  awk '$1 == "frp-core" && NF == 3 { print $2 "/" $3; exit }' "$1"
}

blocks() {  # blocks <file> — the `frp-core` unsafe-table row as `blocks/fns/impls/safety`
  awk '$1 == "frp-core" && NF == 5 { print $2 "/" $3 "/" $4 "/" $5; exit }' "$1"
}

funcs() {   # funcs <file> — the `test functions` counter
  awk '/test functions/ { print $NF; exit }' "$1"
}

srv() {     # srv <file> — the printed `frp-server/tests` counter
  awk '/^  frp-server\/tests +:/ { print $NF; exit }' "$1"
}

# check <label> <outfile> <rc> — green gate and unchanged rows, all non-empty.
check() {
  local lbl="$1" out="$2" rc="$3" r b t
  r=$(row "$out"); b=$(blocks "$out"); t=$(funcs "$out")
  echo "$lbl: rc=$rc  frp-core Code size=${r:-<none>}  unsafe=${b:-<none>}  test functions=${t:-<none>}"
  if [ -z "$r" ] || [ -z "$b" ] || [ -z "$t" ] || [ -z "$base_row" ] || [ -z "$base_blocks" ] || [ -z "$base_funcs" ]; then
    echo "probe: FAIL $lbl — empty parsed value (row='$r' blocks='$b' funcs='$t' base='$base_row'/'$base_blocks'/'$base_funcs')" >&2
    fail=1; return
  fi
  [ "$rc" = 0 ] || { echo "probe: FAIL $lbl gate rc=$rc (see $out)" >&2; fail=1; }
  [ "$r" = "$base_row" ] || { echo "probe: FAIL $lbl double-counted: Code size $r != $base_row" >&2; fail=1; }
  [ "$b" = "$base_blocks" ] || { echo "probe: FAIL $lbl double-counted: unsafe $b != $base_blocks" >&2; fail=1; }
  [ "$t" = "$base_funcs" ] || { echo "probe: FAIL $lbl double-counted: test functions $t != $base_funcs" >&2; fail=1; }
}

# 1. Symlink-free tree: the gate must be green and the baseline rows non-empty.
rc0=$(run "$tmp/0.txt")
base_row=$(row "$tmp/0.txt")
base_blocks=$(blocks "$tmp/0.txt")
base_funcs=$(funcs "$tmp/0.txt")
echo "symlink-free:  rc=$rc0  frp-core Code size=${base_row:-<none>}  unsafe=${base_blocks:-<none>}  test functions=${base_funcs:-<none>}"
[ "$rc0" = 0 ] || { echo "probe: FAIL symlink-free gate rc=$rc0 (see $tmp/0.txt)" >&2; fail=1; }
[ -n "$base_row" ] || { echo "probe: FAIL no frp-core Code size row" >&2; fail=1; }
[ -n "$base_blocks" ] || { echo "probe: FAIL no frp-core unsafe row" >&2; fail=1; }
[ -n "$base_funcs" ] || { echo "probe: FAIL no test functions counter" >&2; fail=1; }

# 2. Symlinked .rs FILE inside `src/`, target in the same crate: counted once.
ln -s kcp/session.rs "$link_src" || exit 2
rc=$(run "$tmp/1.txt"); check "symlinked .rs in src/     " "$tmp/1.txt" "$rc"; rm -f "$link_src"

# 3. Symlinked .rs FILE outside `src/` (crate root): must not mask the target
#    from the `src` scope, and must not add a second copy to the crate scope.
ln -s src/kcp/session.rs "$link_root" || exit 2
rc=$(run "$tmp/2.txt"); check "symlinked .rs in crate root" "$tmp/2.txt" "$rc"; rm -f "$link_root"

# 4. Same, but the alias lives under `tests/` (the other out-of-`src` scope).
ln -s ../src/kcp/session.rs "$link_tests" || exit 2
rc=$(run "$tmp/3.txt"); check "symlinked .rs in tests/    " "$tmp/3.txt" "$rc"; rm -f "$link_tests"

# 5. Two aliases to one target in the same scope: the target counts once.
ln -s kcp/session.rs "$link_a" || exit 2
ln -s kcp/session.rs "$link_b" || exit 2
rc=$(run "$tmp/4.txt"); check "two aliases, one target  " "$tmp/4.txt" "$rc"; rm -f "$link_a" "$link_b"

# 6. Symlinked DIRECTORY *inside* a walked root -> another crate: not followed.
ln -s ../../frp-server/src "$dir" || exit 2
rc=$(run "$tmp/5.txt"); check "symlinked dir            " "$tmp/5.txt" "$rc"; rm -f "$dir"

# 7. Symlinked `<crate>/src` SCOPE ROOT -> another crate: refused, not followed.
#    `followlinks=False` does not cover a walk's own root, so before the guard
#    this absorbed the sibling's whole tree (Code size `32 / 59146`).
src_real="$tmp/frp-core-src"
mv frp-core/src "$src_real" || exit 2
ln -s ../frp-server/src frp-core/src || exit 2
rc=$(run "$tmp/6.txt")
r=$(row "$tmp/6.txt")
echo "symlinked src/ root      : rc=$rc  frp-core Code size=${r:-<none>}"
if [ -z "$r" ]; then
  echo "probe: FAIL symlinked src/ root — no frp-core Code size row" >&2; fail=1
else
  [ "$rc" != 0 ] || { echo "probe: FAIL symlinked src/ root — gate rc=0, expected a failure" >&2; fail=1; }
  [ "$r" = "0/0" ] || { echo "probe: FAIL symlinked src/ root absorbed a sibling crate: Code size $r != 0/0" >&2; fail=1; }
fi
rm -f frp-core/src
mv "$src_real" frp-core/src
src_real=''

# 8. Symlinked `frp-server/tests` SCOPE ROOT (the `top_only` scope): refused too,
#    so the counter agrees with the crate walk, which never descends the link.
tests_real="$tmp/frp-server-tests"
mv frp-server/tests "$tests_real" || exit 2
ln -s ../frp-client/tests frp-server/tests || exit 2
rc=$(run "$tmp/7.txt")
s=$(srv "$tmp/7.txt")
echo "symlinked tests/ root    : rc=$rc  frp-server/tests counter=${s:-<none>}"
if [ -z "$s" ]; then
  echo "probe: FAIL symlinked tests/ root — no frp-server/tests counter" >&2; fail=1
else
  [ "$rc" != 0 ] || { echo "probe: FAIL symlinked tests/ root — gate rc=0, expected a failure" >&2; fail=1; }
  [ "$s" = 0 ] || { echo "probe: FAIL symlinked tests/ root followed the link: counter $s != 0" >&2; fail=1; }
fi
rm -f frp-server/tests
mv "$tests_real" frp-server/tests
tests_real=''

if [ "$fail" = 0 ]; then
  echo "probe: ok — a symlinked .rs file is counted once (inside or outside src/); a symlinked directory is not followed; a symlinked scope root is refused, not followed"
fi
exit "$fail"
