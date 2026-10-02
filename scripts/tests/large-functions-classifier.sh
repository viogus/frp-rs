#!/usr/bin/env bash
# large-functions-classifier.sh — fixture checks for scripts/large-functions.sh.
#
# Why this exists: the script decides how much of a file is production, and the
# refactor backlog is prioritised by that number. Its two hardest cases are
# invisible on a healthy tree — a whole-file test module carries no
# `#[cfg(test)]` inside it, and an out-of-line `#[cfg(test)] mod X;` has no body
# to brace-match. Get either wrong and the script reports the *opposite* of the
# truth (a 2965-line file as 4 production lines was reachable this way), while
# still exiting 0 and printing a plausible table.
#
# The suite is self-contained: it builds a throwaway tree under `mktemp -d`,
# copies the script under test into that tree's `scripts/`, and measures the
# fixture sources. Nothing here depends on the repository's current contents.
#
# Scenarios
#   1  honest classification: the expected production/total/test triple for
#      every fixture file — inline blocks, `tests.rs` / `*_tests.rs` /
#      `*_test.rs` by name, `#[cfg(test)] mod X;` siblings (a `mod.rs`
#      declaration, a `#[path]` target, a non-name-matching sibling, a
#      `pub(crate)` / `pub(super)` declaration and the `X/mod.rs` candidate), a
#      `tests/` directory, and the two negative controls (a plain `mod X;`
#      production sibling and a directory whose name merely starts with
#      `tests`).
#   2  the default table and `--top` are unchanged in shape, and a file the
#      filter excluded is still not listed.
#   3  four mutations of the script, each of which must red exactly one part of
#      scenario 1: drop the name pattern, drop the sibling attribution, restore
#      brace-matching for an out-of-line declaration, and drop `pub(…)` from the
#      declaration pattern. A green suite on a mutant would mean the fixture
#      does not drive the code it claims to.
#
# Usage: bash scripts/tests/large-functions-classifier.sh
set -uo pipefail

# --- self-defence: assert a floor on every exit path --------------------------
# A suite that silently stops checking must not exit green. The trap is
# installed before the path resolution and the first check, so an early `exit 0`
# anywhere below it still has to answer to the floor. `MIN_CHECKS` is the
# measured check count of a green run.
MIN_CHECKS=36
checks=0
fails=0
WORK=""

# shellcheck disable=SC2329  # invoked by the EXIT trap below, not directly
cleanup() {
  local rc=$?
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
  if [ "$rc" -eq 0 ] && [ "$checks" -lt "$MIN_CHECKS" ]; then
    printf 'large-functions-classifier: only %d check(s) ran, floor %d — the suite was cut short\n' \
      "$checks" "$MIN_CHECKS" >&2
    exit 1
  fi
  exit "$rc"
}
trap cleanup EXIT

ok() {
  checks=$((checks + 1))
  printf '  ok    %s\n' "$1"
}

bad() {
  checks=$((checks + 1))
  fails=$((fails + 1))
  printf '  FAIL  %s\n' "$1"
}

# --- locate the script under test, even through a symlink ---------------------
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  case "$SOURCE" in
    /*) ;;
    *) SOURCE="$DIR/$SOURCE" ;;
  esac
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REAL="$REPO_ROOT/scripts/large-functions.sh"

if [ ! -f "$REAL" ]; then
  printf 'FAIL  cannot locate scripts/large-functions.sh from %s\n' "$SCRIPT_DIR" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf 'SKIP  python3 not found — scripts/large-functions.sh cannot measure\n'
  exit 0
fi

WORK="$(mktemp -d)"
TREE="$WORK/tree"
mkdir -p "$TREE/scripts" "$TREE/frp-core/src"

# --- the fixture tree ---------------------------------------------------------
# Expected triples (production / total / test). `total` is `wc -l` plus one: the
# script splits on `\n`, so a file that ends with a newline carries a final
# empty element.
cat > "$TREE/frp-core/src/parent.rs" <<'EOF'
pub fn first() {
    let a = 1;
}

#[cfg(test)]
mod declared_helper;

pub fn after_the_decl() {
    let b = 2;
}

pub fn second() {
    let c = 3;
}

#[cfg(test)]
mod tests {
    #[test]
    fn inline() {}
}

#[cfg(test)]
mod single_test;

mod prod_sibling;

pub fn last() {
    let d = 4;
}

#[cfg(test)]
mod extra_tests;
EOF
mkdir -p "$TREE/frp-core/src/parent" "$TREE/frp-core/src/tests" \
  "$TREE/frp-core/src/testsuite" "$TREE/frp-core/src/pkg" \
  "$TREE/frp-core/src/pathed"

cat > "$TREE/frp-core/src/parent/declared_helper.rs" <<'EOF'
pub fn declared_helper_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/parent/single_test.rs" <<'EOF'
pub fn single_test_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/parent/extra_tests.rs" <<'EOF'
pub fn extra_tests_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/parent/prod_sibling.rs" <<'EOF'
pub fn prod_sibling_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/orphan_tests.rs" <<'EOF'
pub fn orphan_tests_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/orphan_test.rs" <<'EOF'
pub fn orphan_test_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/plain.rs" <<'EOF'
pub fn plain_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/tests/under_dir.rs" <<'EOF'
pub fn under_dir_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/testsuite/prod.rs" <<'EOF'
pub fn testsuite_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/pkg/mod.rs" <<'EOF'
pub fn pkg_mod_prod() {
    let p = 1;
}

#[cfg(test)]
mod helper;
EOF
cat > "$TREE/frp-core/src/pkg/helper.rs" <<'EOF'
pub fn pkg_helper_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/pathed.rs" <<'EOF'
pub fn pathed_prod() {
    let q = 1;
}

#[cfg(test)]
#[path = "pathed/pathed_helper.rs"]
mod pathed_helper;
EOF
cat > "$TREE/frp-core/src/pathed/pathed_helper.rs" <<'EOF'
pub fn pathed_helper_prod() {
    let x = 1;
}
EOF

# Visible qualifiers on the declaration. Rust allows `pub(crate)` / `pub(super)`
# / `pub(in …)` before `mod`, and the whole-file filter must not depend on the
# declaration being bare `pub` (the base script's `MOD_LINE` matched only
# `pub\s+mod`, so `pub(crate) mod X;` was not even seen as a declaration).
mkdir -p "$TREE/frp-core/src/qualified"
cat > "$TREE/frp-core/src/qualified.rs" <<'EOF'
pub fn qualified_prod() {
    let k = 1;
}

#[cfg(test)]
pub(crate) mod bbb;

#[cfg(test)]
pub(super) mod ddd;

pub fn qualified_tail() {
    let m = 2;
}
EOF
cat > "$TREE/frp-core/src/qualified/bbb.rs" <<'EOF'
pub fn bbb_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/qualified/ddd.rs" <<'EOF'
pub fn ddd_prod() {
    let x = 1;
}
EOF

# The fourth module-path candidate: `X/mod.rs` under the parent's stem
# directory (`nested.rs` + `mod deep;` + `nested/deep/mod.rs`).
mkdir -p "$TREE/frp-core/src/nested/deep"
cat > "$TREE/frp-core/src/nested.rs" <<'EOF'
pub fn nested_prod() {
    let n = 1;
}

#[cfg(test)]
mod deep;
EOF
cat > "$TREE/frp-core/src/nested/deep/mod.rs" <<'EOF'
pub fn deep_prod() {
    let x = 1;
}
EOF

# Enough production files that the default top-14 table cannot be filled by
# 0-production rows — otherwise the "default output excludes test modules"
# check below would pass for the wrong reason.
n=1
while [ "$n" -le 20 ]; do
  printf 'pub fn generated_%d() { let x = %d; }\n' "$n" "$n" \
    > "$TREE/frp-core/src/generated_$n.rs"
  n=$((n + 1))
done

# --- helpers ------------------------------------------------------------------
# row <output> <path> -> "production total test", or empty when not listed.
row() {
  printf '%s\n' "$1" | awk -v p="$2" '$NF == p { print $1, $2, $3; exit }'
}

expect_row() { # expect_row <output> <path> <prod> <total> <test> <label>
  local got
  got="$(row "$1" "$2")"
  if [ "$got" = "$3 $4 $5" ]; then
    ok "$6"
  else
    bad "$6: $(basename "$2") is '${got:-<absent>}', expected '$3 $4 $5'"
  fi
}

# mutate <src> <dst> <old> <new> — literal single replacement; rc 2 when the
# anchor is missing, so a mutation that did not apply is never mistaken for a
# green mutant.
mutate() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys
src, dst, old, new = sys.argv[1:5]
text = open(src, encoding='utf8').read()
if old not in text:
    sys.exit(2)
open(dst, 'w', encoding='utf8').write(text.replace(old, new, 1))
PY
}

printf 'large-functions.sh classifier fixtures\n\n'

cp "$REAL" "$TREE/scripts/large-functions.sh"
chmod +x "$TREE/scripts/large-functions.sh"

# ---------------------------------------------------------------- scenario 1
printf 'scenario 1: honest classification\n'
OUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then
  ok "fixture run exits 0"
else
  bad "fixture run exits $rc"
fi

expect_row "$OUT" "frp-core/src/parent.rs" 22 33 11 \
  "out-of-line \`mod X;\` spans only its attribute and declaration"
expect_row "$OUT" "frp-core/src/parent/declared_helper.rs" 0 4 4 \
  "a \`#[cfg(test)] mod X;\` sibling is 0 production even without a test-ish name"
expect_row "$OUT" "frp-core/src/parent/single_test.rs" 0 4 4 \
  "\`*_test.rs\` is 0 production"
expect_row "$OUT" "frp-core/src/parent/extra_tests.rs" 0 4 4 \
  "\`*_tests.rs\` is 0 production"
expect_row "$OUT" "frp-core/src/orphan_tests.rs" 0 4 4 \
  "\`*_tests.rs\` is 0 production even when nothing declares it"
expect_row "$OUT" "frp-core/src/orphan_test.rs" 0 4 4 \
  "\`*_test.rs\` is 0 production even when nothing declares it"
expect_row "$OUT" "frp-core/src/parent/prod_sibling.rs" 4 4 0 \
  "a plain \`mod X;\` sibling stays production"
expect_row "$OUT" "frp-core/src/pkg/mod.rs" 5 7 2 \
  "\`mod.rs\` attributes its declaration line to tests"
expect_row "$OUT" "frp-core/src/pkg/helper.rs" 0 4 4 \
  "a \`mod.rs\` sibling is attributed to tests"
expect_row "$OUT" "frp-core/src/pathed.rs" 5 8 3 \
  "a \`#[path]\` declaration is test lines in its parent"
expect_row "$OUT" "frp-core/src/pathed/pathed_helper.rs" 0 4 4 \
  "a \`#[path]\` sibling is attributed to tests"
expect_row "$OUT" "frp-core/src/qualified.rs" 10 14 4 \
  "\`pub(crate)\` / \`pub(super)\` declarations are found and are test lines only"
expect_row "$OUT" "frp-core/src/qualified/bbb.rs" 0 4 4 \
  "a \`pub(crate) mod X;\` sibling is attributed to tests"
expect_row "$OUT" "frp-core/src/qualified/ddd.rs" 0 4 4 \
  "a \`pub(super) mod X;\` sibling is attributed to tests"
expect_row "$OUT" "frp-core/src/nested.rs" 5 7 2 \
  "an out-of-line declaration before a following production fn spans only itself"
expect_row "$OUT" "frp-core/src/nested/deep/mod.rs" 0 4 4 \
  "a \`X/mod.rs\` sibling is attributed to tests"
expect_row "$OUT" "frp-core/src/tests/under_dir.rs" 0 4 4 \
  "a file under \`tests/\` is 0 production"
expect_row "$OUT" "frp-core/src/testsuite/prod.rs" 4 4 0 \
  "a \`testsuite/\` directory is not a \`tests/\` directory"
expect_row "$OUT" "frp-core/src/plain.rs" 4 4 0 \
  "a plain production file is untouched"

# ---------------------------------------------------------------- scenario 2
printf '\nscenario 2: default output shape\n'
DEF="$(bash "$TREE/scripts/large-functions.sh" 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then
  ok "default run exits 0"
else
  bad "default run exits $rc"
fi

first="$(printf '%s\n' "$DEF" | head -1)"
if [ "$first" = 'Per-file lines (test modules excluded)' ]; then
  ok "per-file header is the documented one"
else
  bad "per-file header changed: $first"
fi

if printf '%s\n' "$DEF" | grep -q 'Largest production functions by CODE lines (top 12)$'; then
  ok "function section header is unchanged"
else
  bad "function section header changed"
fi

# Nothing at 0 production belongs in a table of the biggest production files.
zero_rows="$(printf '%s\n' "$DEF" | awk 'NF == 4 && $1 ~ /^[0-9]+$/ && $1 == 0 { print $4 }' | tr '\n' ' ')"
if [ -z "$zero_rows" ]; then
  ok "default table lists no 0-production row"
else
  bad "default table listed 0-production row(s): $zero_rows"
fi

if row "$DEF" "frp-core/src/orphan_tests.rs" >/dev/null 2>&1 \
   && [ -z "$(row "$DEF" "frp-core/src/orphan_tests.rs")" ]; then
  ok "a filtered test module is absent from the default table"
else
  bad "a filtered test module appeared in the default table"
fi

TOP3="$(bash "$TREE/scripts/large-functions.sh" --top 3 2>&1)"
n3="$(printf '%s\n' "$TOP3" | grep -cE '\(.*:[0-9]+\)$')"
if [ "$n3" -eq 3 ]; then
  ok "\`--top 3\` prints exactly 3 functions"
else
  bad "\`--top 3\` printed $n3 function row(s)"
fi

# ---------------------------------------------------------------- scenario 3
printf '\nscenario 3: mutations of the script must red scenario 1\n'
MUT="$WORK/mutant.sh"

# M1: the name pattern. Only the two undeclared `*_test(s).rs` files depend on
# it; the declared siblings must still be excluded, so the mutation is shown to
# have hit one mechanism and not the other.
if mutate "$REAL" "$MUT" 'TEST_FILE.search(name)' 'False'; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/orphan_tests.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M1 (name pattern removed): the undeclared \`*_tests.rs\` is production again"
  else
    bad "M1 (name pattern removed): expected '4 4 0' for orphan_tests.rs, got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/parent/declared_helper.rs")"
  if [ "$got" = "0 4 4" ]; then
    ok "M1: the declared sibling is still excluded (the mechanisms are independent)"
  else
    bad "M1: declared sibling became '${got:-<absent>}'"
  fi
else
  bad "M1 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M2: the sibling attribution.
if mutate "$REAL" "$MUT" 'test_files.add(cand)' 'pass'; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/parent/declared_helper.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M2 (sibling attribution removed): the non-name-matching sibling is production again"
  else
    bad "M2 (sibling attribution removed): expected '4 4 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/orphan_tests.rs")"
  if [ "$got" = "0 4 4" ]; then
    ok "M2: the name pattern still excludes (the mechanisms are independent)"
  else
    bad "M2: orphan_tests.rs became '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/nested/deep/mod.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M2: the \`X/mod.rs\` candidate is production again (attribution is what excludes it)"
  else
    bad "M2: nested/deep/mod.rs became '${got:-<absent>}'"
  fi
else
  bad "M2 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M3: brace-matching an out-of-line declaration. This is the mutation that made
# `ssh_gateway.rs` read 2726 production / 24 test instead of 2742 / 8.
if mutate "$REAL" "$MUT" 'decl = MOD_DECL.match(lines[j])' 'decl = None'; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/parent.rs")"
  if [ "$got" = "11 33 22" ]; then
    ok "M3 (out-of-line declaration brace-matched): parent.rs swallows its production again"
  else
    bad "M3 (out-of-line declaration brace-matched): expected '11 33 22', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/orphan_tests.rs")"
  if [ "$got" = "0 4 4" ]; then
    ok "M3: the name pattern still excludes (the mechanisms are independent)"
  else
    bad "M3: orphan_tests.rs became '${got:-<absent>}'"
  fi
else
  bad "M3 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M4: the qualifier on the declaration. The base script's declaration pattern
# accepted only a bare `pub`, so `pub(crate) mod X;` / `pub(super) mod X;` were
# not seen as declarations at all — the block ran on to the next braced
# production item and the sibling stayed production.
if mutate "$REAL" "$MUT" \
    '(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;' \
    '(?:pub\s+)?mod\s+([A-Za-z0-9_]+)\s*;'; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/qualified.rs")"
  if [ "$got" = "5 14 9" ]; then
    ok "M4 (bare-\`pub\` declaration pattern): qualified.rs swallows the qualified declarations"
  else
    bad "M4 (bare-\`pub\` declaration pattern): expected '5 14 9', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/qualified/bbb.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M4: a \`pub(crate)\` sibling becomes production again"
  else
    bad "M4: qualified/bbb.rs became '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/qualified/ddd.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M4: a \`pub(super)\` sibling becomes production again"
  else
    bad "M4: qualified/ddd.rs became '${got:-<absent>}'"
  fi
else
  bad "M4 mutation did not apply — anchor missing, the check would be vacuous"
fi

# ---------------------------------------------------------------- summary
printf '\n'
if [ "$fails" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), %d failure(s) above\n' "$checks" "$fails"
fi
exit "$fails"
