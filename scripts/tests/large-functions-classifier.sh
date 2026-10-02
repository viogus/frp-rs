#!/usr/bin/env bash
# large-functions-classifier.sh — fixture checks for scripts/large-functions.sh.
#
# Why this exists: the script decides how much of a file is production, and the
# refactor backlog is prioritised by that number. Its three hardest cases are
# invisible on a healthy tree — a whole-file test module carries no
# `#[cfg(test)]` inside it, an out-of-line `#[cfg(test)] mod X;` has no body to
# brace-match, and a `#[cfg(test)]` attribute's region ends at the item it
# decorates rather than at the next `mod`. Get any of them wrong and the script
# reports the *opposite* of the truth (a 2965-line file as 4 production lines was
# reachable this way), while still exiting 0 and printing a plausible table.
#
# The suite is self-contained: it builds a throwaway tree under `mktemp -d`,
# copies the script under test into that tree's `scripts/`, and measures the
# fixture sources. Nothing here depends on the repository's current contents.
#
# Scenarios
#   1  honest classification: the expected production/total/test triple for
#      every fixture file — inline blocks, `tests.rs` / `test.rs` / `*_tests.rs`
#      / `*_test.rs` by name, `#[cfg(test)] mod X;` siblings (a `mod.rs`
#      declaration, a `#[path]` target, a non-name-matching sibling, a
#      `pub(crate)` / `pub(super)` declaration and the `X/mod.rs` candidate), a
#      `tests/` directory, the attribute-attribution cases (a gate above a `use`
#      / `const` / between two attributes, `#[cfg(all(test, …))]` inline and on a
#      declaration, `#[cfg(all(not(test), …))]`, a `#[path]` written above the
#      gate, and braces inside string literals), the raw-string cases (a
#      multi-line literal and one with embedded quotes inside a gate's region, a
#      production function whose body holds one), the gate-tail cases (a trailing
#      `/* */` or `//` comment, a `]` inside that comment, a second attribute on
#      the gate's line, a one-line `#[cfg(test)] #[path = …] mod X;` declaration,
#      and an ordinary string continued with a backslash at end of line) and the
#      predicate-parse
#      controls (`all(not(any(test, …)))`, `all(not (test), …)`, and the true
#      `all(test, …)` gate beside them), plus the three negative controls
#      (a plain `mod X;` production sibling, a directory whose name merely starts
#      with `tests`, and a production `collide.rs` that another module's
#      `#[cfg(test)] mod collide;` must not claim — Rust resolves that under
#      `attacker/`).
#   2  the default table and `--top` are unchanged in shape, a file the
#      filter excluded is still not listed, and the function table measures the
#      raw-string fixture's function to its true end.
#   3  fifteen mutations of the script, each of which must red exactly one part of
#      scenario 1: drop the name pattern, drop the sibling attribution, drop
#      declaration recognition, drop `pub(…)` from the declaration pattern,
#      offer `dir/X.rs` for a `parent.rs`, drop the `all(…)` arm of the
#      predicate parse, skip the backward attribute walk, scan string literals as
#      code, drop the paren tracking that keeps a `[&str; 2]` type's `;` from
#      ending a `const` early, stop skipping raw strings, treat `not(…)` as
#      implying `test`, require the gate's `]` to end its line, reject a comment
#      tail, consume the attribute run a line at a time again, and drop the
#      ordinary-string continuation. A green suite on a mutant would mean the
#      fixture does not drive the code it claims to.
#
# Usage: bash scripts/tests/large-functions-classifier.sh
set -uo pipefail

# --- self-defence: assert a floor on every exit path --------------------------
# A suite that silently stops checking must not exit green. The trap is
# installed before the path resolution and the first check, so an early `exit 0`
# anywhere below it still has to answer to the floor. `MIN_CHECKS` is the
# measured check count of a green run.
MIN_CHECKS=101
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

# Rust resolves `mod X;` inside `parent.rs` under `parent/` — `parent/X.rs` or
# `parent/X/mod.rs` — and never `dir/X.rs` beside it. `collide.rs` here is a
# production module declared from the crate root; an `attacker.rs` that declares
# a *test* `mod collide;` must not claim it.
mkdir -p "$TREE/frp-core/src/attacker" "$TREE/frp-core/src/bare"
cat > "$TREE/frp-core/src/lib.rs" <<'EOF'
pub mod collide;
EOF
cat > "$TREE/frp-core/src/collide.rs" <<'EOF'
pub fn collide_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/attacker.rs" <<'EOF'
pub fn attacker_prod() {
    let z = 1;
}

#[cfg(test)]
mod collide;
EOF
cat > "$TREE/frp-core/src/attacker/collide.rs" <<'EOF'
pub fn attacker_collide_prod() {
    let x = 1;
}
EOF
cat > "$TREE/frp-core/src/bare/test.rs" <<'EOF'
pub fn bare_test_prod() {
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

# --- attribute attribution ----------------------------------------------------
# A `#[cfg(test)]` region belongs to the item the attribute decorates, not to
# the next `mod` below it. The base script scanned forward for a `mod`, so a gate
# above a `use` charged everything up to the following module to tests — the
# 2965-line `frp-core/src/bridge.rs` read 4 production lines that way. These
# fixtures pin the replacement: statement items end at their `;`, body items are
# brace-matched through the literal-aware scanner, `#[cfg(all(test, …))]` counts
# as a gate while `#[cfg(all(not(test), …))]` does not, and `#[path]` may sit
# above or below the gate.
mkdir -p "$TREE/frp-core/src/attr_all_decl" "$TREE/frp-core/src/attr_back"

cat > "$TREE/frp-core/src/attr_item.rs" <<'EOF'
//! A gate above a `use`: the region ends there, not at the `mod` below it.

#[cfg(test)]
use std::time::Duration;

pub fn prod_between() -> u8 {
    1
}

pub fn prod_after() -> u8 {
    2
}

#[cfg(test)]
mod tests {
    #[test]
    fn inline() {
        let _ = Duration::from_secs(1);
    }
}
EOF

cat > "$TREE/frp-core/src/attr_all_gated.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[cfg(all(test, feature = "x"))]
mod tests {
    #[test]
    fn inline() {}
}
EOF

cat > "$TREE/frp-core/src/attr_all_decl.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[cfg(all(test, feature = "x"))]
mod all_decl_helper;

pub fn prod_after() -> u8 {
    2
}
EOF
cat > "$TREE/frp-core/src/attr_all_decl/all_decl_helper.rs" <<'EOF'
pub fn all_decl_helper_prod() {
    let x = 1;
}
EOF

cat > "$TREE/frp-core/src/attr_not_gated.rs" <<'EOF'
#[cfg(all(not(test), feature = "x"))]
pub fn prod_gated_off_in_tests() -> u8 {
    2
}
EOF

cat > "$TREE/frp-core/src/attr_literal.rs" <<'EOF'
pub fn prod_before() -> &'static str {
    "}"
}

#[cfg(test)]
mod tests {
    #[test]
    fn inline() {
        let s = "{";
        assert_eq!(s.len(), 1);
    }
}

pub fn prod_after() -> &'static str {
    "{"
}
EOF

cat > "$TREE/frp-core/src/attr_back.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[path = "attr_back/back_impl.rs"]
#[cfg(test)]
mod back;

pub fn prod_after() -> u8 {
    2
}
EOF
cat > "$TREE/frp-core/src/attr_back/back_impl.rs" <<'EOF'
pub fn back_impl_prod() {
    let x = 1;
}
EOF

cat > "$TREE/frp-core/src/attr_const.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[cfg(test)]
const FIXTURE_NAMES: [&str; 2] = [
    "a",
    "b",
];

pub fn prod_after() -> u8 {
    2
}
EOF

cat > "$TREE/frp-core/src/attr_gate_then_attr.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    #[test]
    fn inline() {}
}
EOF

cat > "$TREE/frp-core/src/attr_raw_fn.rs" <<'EOF'
//! Fixture: a production function whose body holds a multi-line raw string.
//!
//! The literal's closing brace is not the function's, so a scan that reads it
//! as code ends the body early and the function measures short.

/// Returns the embedded template.
pub fn build_payload(enabled: bool) -> &'static str {
    if enabled {
        let template = r#"
left } right
"#;
        return template.trim();
    }
    "{}"
}
EOF

cat > "$TREE/frp-core/src/attr_raw_multiline.rs" <<'EOF'
//! Fixture: a gated inline module whose body holds a multi-line raw string.
//!
//! A raw string spans lines and ends only at `"` + the opening `#` run, so its
//! braces are not code. Scanned as code the closing brace closes the region
//! early.

#[cfg(test)]
mod tests {
    fn legacy() -> &'static str {
        let payload = r#"
left } right
"#;
        payload
    }

    #[test]
    fn non_empty() {
        assert!(!legacy().is_empty());
    }
}
EOF

cat > "$TREE/frp-core/src/attr_raw_quotes.rs" <<'EOF'
//! Fixture: a gated inline module whose raw string contains quotes.
//!
//! A quote-naive scan leaves raw-string mode at the first inner `"`, so the
//! brace after it is counted and the module closes early.

#[cfg(test)]
mod tests {
    fn legacy() -> &'static str {
        let payload = r#"left " right } tail"#;
        payload
    }

    #[test]
    fn non_empty() {
        assert!(!legacy().is_empty());
    }
}
EOF

cat > "$TREE/frp-core/src/attr_all_gated_like.rs" <<'EOF'
//! Fixture: the true gate spelling, for contrast with the two negations above.

#[cfg(all(test, feature = "x"))]
mod helper {
    #[test]
    fn inline() {}
}
EOF

cat > "$TREE/frp-core/src/attr_not_any_gated.rs" <<'EOF'
//! Fixture: a module that compiles only where `test` is OFF.
//!
//! `all(not(any(test, …)))` is the opposite of a gate — it must stay production.

#[cfg(all(not(any(test, feature = "x"))))]
mod helper {
    pub fn used_in_production() -> u8 {
        7
    }
}
EOF

cat > "$TREE/frp-core/src/attr_not_space_gated.rs" <<'EOF'
//! Fixture: a module that compiles only where `test` is OFF.
//!
//! `not (test)` with a space is still a negation — it must stay production.

#[cfg(all(not (test), feature = "x"))]
mod helper {
    pub fn used_in_production() -> u8 {
        7
    }
}
EOF

# --- the gate's tail, the item on the gate's line, string continuations --------
# A `#[cfg(…)]` is a gate when its predicate implies `test` *and* the rest of the
# line is only whitespace, comments and/or further `#[…]` attributes. Rust
# allows all of these, and an end-of-line anchor that demands the `)]` be last
# loses every one of them: the module is scored production and the gate is not
# seen at all (measured `14 14 0` where the truth is `9 14 5`).
#
#   1  `#[cfg(test)] /* the inline tests */`
#   2  `#[cfg(test)] #[allow(dead_code)]`
#   3  `#[cfg(all(test, feature = "x"))] /* gated */`
#   4  `#[cfg(test)] // see (a)]` — the `]` inside the comment defeats a greedy
#      `(.*)` predicate, so the closing paren must be found by depth counting
#   5  `#[cfg(test)] #[path = "…"] mod helper;` — the attribute run, the `#[path]`
#      and the declaration share one line, which a line-at-a-time walk cannot see
#      (it looks for the declaration on the next line and charges the production
#      code below it to tests)
cat > "$TREE/frp-core/src/fs_cfg_block_comment.rs" <<'EOF'
pub fn alpha() {
    let a = 1;
}

#[cfg(test)] /* the inline tests */
mod tests {
    #[test]
    fn one() {}
}

pub fn omega() {
    let b = 2;
}
EOF

cat > "$TREE/frp-core/src/fs_cfg_comment_bracket.rs" <<'EOF'
pub fn alpha() {
    let a = 1;
}

#[cfg(test)] // see (a)]
mod tests {
    #[test]
    fn one() {}
}

pub fn omega() {
    let b = 2;
}
EOF

cat > "$TREE/frp-core/src/fs_cfg_two_attrs.rs" <<'EOF'
pub fn alpha() {
    let a = 1;
}

#[cfg(test)] #[allow(dead_code)]
mod tests {
    #[test]
    fn one() {}
}

pub fn omega() {
    let b = 2;
}
EOF

cat > "$TREE/frp-core/src/fs_cfg_all_comment.rs" <<'EOF'
pub fn alpha() {
    let a = 1;
}

#[cfg(all(test, feature = "x"))] /* gated */
mod tests {
    #[test]
    fn one() {}
}

pub fn omega() {
    let b = 2;
}
EOF

mkdir -p "$TREE/frp-core/src/fs_cfg_inline_path"
cat > "$TREE/frp-core/src/fs_cfg_inline_path.rs" <<'EOF'
pub fn inline_prod() {
    let q = 1;
}

#[cfg(test)] #[path = "fs_cfg_inline_path/inline_helper.rs"] mod inline_helper;

pub fn inline_tail() {
    let t = 2;
}
EOF
cat > "$TREE/frp-core/src/fs_cfg_inline_path/inline_helper.rs" <<'EOF'
pub fn helper_prod() {
    let x = 1;
}
EOF

# A backslash immediately before the newline continues an ordinary string onto
# the next physical line, so braces there are string content. Without the
# continuation the `}` at the start of the continuation line closes the region:
# the module's tail is charged to production (`9 17 8` where the truth is
# `5 17 12`) and a production function ends at the brace inside the literal
# (`render` measures 3 code lines where the truth is 5).
cat > "$TREE/frp-core/src/fs_string_cont.rs" <<'EOF'
#[cfg(test)]
mod tests {
    #[test]
    fn one() {
        let s = "closing brace follows: \
}";
        assert!(!s.is_empty());
    }

    #[test]
    fn two() {}
}

pub fn after() {
    let b = 2;
}
EOF

cat > "$TREE/frp-core/src/fs_string_fn.rs" <<'EOF'
pub fn render() -> &'static str {
    let s = "a { \
} b";
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn one() {}
}
EOF

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

# fnrow <output> <file:line> -> "code total", or empty when not listed. The
# function table's last field is the site, `(path:line)`.
fnrow() {
  printf '%s\n' "$1" | awk -v p="($2)" '$NF == p { print $1, $2; exit }'
}

expect_fn() { # expect_fn <output> <file:line> <code> <total> <label>
  local got
  got="$(fnrow "$1" "$2")"
  if [ "$got" = "$3 $4" ]; then
    ok "$5"
  else
    bad "$5: $2 is '${got:-<absent>}', expected '$3 $4'"
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
expect_row "$OUT" "frp-core/src/collide.rs" 4 4 0 \
  "a production module beside the parent is not claimed by a test \`mod X;\`"
expect_row "$OUT" "frp-core/src/attacker.rs" 5 7 2 \
  "the test \`mod collide;\` declaration is its own lines only"
expect_row "$OUT" "frp-core/src/attacker/collide.rs" 0 4 4 \
  "the \`parent/X.rs\` candidate is the one that is attributed"
expect_row "$OUT" "frp-core/src/bare/test.rs" 0 4 4 \
  "a file named \`test.rs\` is 0 production"
expect_row "$OUT" "frp-core/src/tests/under_dir.rs" 0 4 4 \
  "a file under \`tests/\` is 0 production"
expect_row "$OUT" "frp-core/src/testsuite/prod.rs" 4 4 0 \
  "a \`testsuite/\` directory is not a \`tests/\` directory"
expect_row "$OUT" "frp-core/src/plain.rs" 4 4 0 \
  "a plain production file is untouched"

# --- attribute attribution ----------------------------------------------------
expect_row "$OUT" "frp-core/src/attr_item.rs" 12 21 9 \
  "a gate above a \`use\` ends there, not at the \`mod tests\` far below"
expect_row "$OUT" "frp-core/src/attr_all_gated.rs" 5 10 5 \
  "\`#[cfg(all(test, …))]\` is a test gate"
expect_row "$OUT" "frp-core/src/attr_all_decl.rs" 9 11 2 \
  "\`#[cfg(all(test, …))] mod X;\` spans only its attribute and declaration"
expect_row "$OUT" "frp-core/src/attr_all_decl/all_decl_helper.rs" 0 4 4 \
  "a \`#[cfg(all(test, …))] mod X;\` sibling is 0 production"
expect_row "$OUT" "frp-core/src/attr_not_gated.rs" 5 5 0 \
  "\`#[cfg(all(not(test), …))]\` is not a test gate"
expect_row "$OUT" "frp-core/src/attr_literal.rs" 9 17 8 \
  "braces inside string literals do not end the region early"
expect_row "$OUT" "frp-core/src/attr_back.rs" 9 12 3 \
  "\`#[path]\` written above the gate is still part of the region"
expect_row "$OUT" "frp-core/src/attr_back/back_impl.rs" 0 4 4 \
  "a \`#[path]\` above the gate still attributes its sibling to tests"
expect_row "$OUT" "frp-core/src/attr_const.rs" 9 14 5 \
  "a gate above a \`const\` ends at its \`;\`, past the \`[&str; 2]\`"
expect_row "$OUT" "frp-core/src/attr_gate_then_attr.rs" 5 11 6 \
  "an attribute between the gate and its item stays in the region"

# --- raw strings and the predicate parse --------------------------------------
expect_row "$OUT" "frp-core/src/attr_raw_fn.rs" 16 16 0 \
  "a production fn whose raw string spans lines is production"
expect_row "$OUT" "frp-core/src/attr_raw_multiline.rs" 7 21 14 \
  "a multi-line raw string does not close its test region early"
expect_row "$OUT" "frp-core/src/attr_raw_quotes.rs" 6 18 12 \
  "quotes inside a raw string do not end it"
expect_row "$OUT" "frp-core/src/attr_all_gated_like.rs" 3 8 5 \
  "the true \`all(test, …)\` gate is still a gate (contrast for the negations)"
expect_row "$OUT" "frp-core/src/attr_not_any_gated.rs" 11 11 0 \
  "\`all(not(any(test, …)))\` is not a gate"
expect_row "$OUT" "frp-core/src/attr_not_space_gated.rs" 11 11 0 \
  "\`all(not (test), …)\` is not a gate"

# --- the gate's tail, the item on the gate's own line, continuations ----------
expect_row "$OUT" "frp-core/src/fs_cfg_block_comment.rs" 9 14 5 \
  "a block comment after the gate leaves it a gate"
expect_row "$OUT" "frp-core/src/fs_cfg_comment_bracket.rs" 9 14 5 \
  "a \`]\` inside a trailing line comment does not break the predicate"
expect_row "$OUT" "frp-core/src/fs_cfg_two_attrs.rs" 9 14 5 \
  "a second attribute on the gate's line leaves it a gate"
expect_row "$OUT" "frp-core/src/fs_cfg_all_comment.rs" 9 14 5 \
  "\`all(test, …)\` with a trailing block comment is still a gate"
expect_row "$OUT" "frp-core/src/fs_cfg_inline_path.rs" 9 10 1 \
  "a one-line \`#[cfg(test)] #[path = …] mod X;\` spans only that line"
expect_row "$OUT" "frp-core/src/fs_cfg_inline_path/inline_helper.rs" 0 4 4 \
  "that one-line \`#[path]\` still attributes its sibling to tests"
expect_row "$OUT" "frp-core/src/fs_string_cont.rs" 5 17 12 \
  "a backslash at end of line continues the string, so its \`}\` is content"

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

# The function table's own view of the raw-string fix: the production fixture's
# body ends at its final brace, not at the `}` inside the literal. The value the
# M10 mutant produces (`7 7`) is asserted there, so this row is the witness.
TOPBIG="$(bash "$TREE/scripts/large-functions.sh" --top 200 2>&1)"
expect_fn "$TOPBIG" "frp-core/src/attr_raw_fn.rs:7" 9 9 \
  "a fn whose raw string spans lines keeps its whole body (\`fn_body_end\`)"
expect_fn "$TOPBIG" "frp-core/src/fs_string_fn.rs:1" 5 5 \
  "a fn whose ordinary string continues past the newline keeps its whole body"

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

# M3: out-of-line declaration recognition. A declaration's region ends at its own
# `;` whether or not the declaration pattern matches, so the observable effect is
# on the sibling: `declared_helper.rs` matches no test-ish name, and this is the
# only mechanism that attributes it. (Before the attribution fix the same
# mutation brace-matched the declaration forward and made `ssh_gateway.rs` read
# 2726 production / 24 test instead of 2742 / 8.) The `parent.rs` row below
# cannot discriminate — it holds with and without the mutation — and is kept
# only as an independence control; the sibling row is the witness.
if mutate "$REAL" "$MUT" 'decl = MOD_DECL.match(lines[j], col)' 'decl = None'; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/parent/declared_helper.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M3 (declaration not recognised): the non-name-matching sibling is production again"
  else
    bad "M3 (declaration not recognised): expected '4 4 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/parent.rs")"
  if [ "$got" = "22 33 11" ]; then
    ok "M3 control (not a witness — the sibling row is): the region still ends at the declaration's \`;\`"
  else
    bad "M3 control: parent.rs became '${got:-<absent>}'"
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
# not seen as declarations at all and their siblings stayed production. The
# region itself still ends at the declaration's `;`, so the `qualified.rs` row
# cannot discriminate and is kept as an independence control: the two sibling
# rows are the witnesses.
if mutate "$REAL" "$MUT" \
    '(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;' \
    '(?:pub\s+)?mod\s+([A-Za-z0-9_]+)\s*;'; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/qualified.rs")"
  if [ "$got" = "10 14 4" ]; then
    ok "M4 control (not a witness — the two sibling rows are): the qualified declarations still end at their \`;\`"
  else
    bad "M4 control: qualified.rs expected '10 14 4', got '${got:-<absent>}'"
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

# M5: the candidate set. Making every parent resolve "beside itself"
# (`dir/X.rs`) is what Rust does *not* do for `parent.rs`, and it lets an
# unrelated production module be claimed by a test declaration.
if mutate "$REAL" "$MUT" 'if stem in (' 'if True or stem in ('; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/collide.rs")"
  if [ "$got" = "0 4 4" ]; then
    ok "M5 (dir/X.rs offered for a parent.rs): the production \`collide.rs\` is claimed as test"
  else
    bad "M5 (dir/X.rs offered for a parent.rs): expected '0 4 4', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attacker/collide.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M5: the mutation drops the real \`parent/X.rs\` candidate too (wrong in both directions)"
  else
    bad "M5: attacker/collide.rs became '${got:-<absent>}'"
  fi
else
  bad "M5 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M6: the `all(…)` arm of the predicate parse. Dropping it leaves both the inline
# module and the declaration's sibling as production, while the bare
# `#[cfg(test)]` regions are untouched — the two arms are independent.
if mutate "$REAL" "$MUT" "    if m.group(1) == 'all':" \
    "    if m.group(1) == 'allX':"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_all_gated.rs")"
  if [ "$got" = "10 10 0" ]; then
    ok "M6 (\`all(test, …)\` gate dropped): the inline module is production again"
  else
    bad "M6 (\`all(test, …)\` gate dropped): expected '10 10 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_all_decl/all_decl_helper.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M6: the \`all(test, …)\` declaration's sibling is production again"
  else
    bad "M6: the \`all(test, …)\` sibling expected '4 4 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_item.rs")"
  if [ "$got" = "12 21 9" ]; then
    ok "M6: the bare \`#[cfg(test)]\` region is unaffected (the arms are independent)"
  else
    bad "M6: attr_item.rs became '${got:-<absent>}'"
  fi
else
  bad "M6 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M7: the attribute run. Without the backward walk a `#[path]` written above the
# gate is invisible, so its sibling is no longer attributed to tests.
if mutate "$REAL" "$MUT" 'while start > 0 and ATTR_LINE.match(lines[start - 1]):' \
    'while start > 0 and False:'; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_back/back_impl.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M7 (attribute run not walked back): a \`#[path]\` above the gate is lost, sibling is production"
  else
    bad "M7 (attribute run not walked back): sibling expected '4 4 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_back.rs")"
  if [ "$got" = "10 12 2" ]; then
    ok "M7: the region shrinks to the gate and its declaration line"
  else
    bad "M7: attr_back.rs became '${got:-<absent>}'"
  fi
else
  bad "M7 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M8: the string skipper. With string literals scanned as code, the `"{"` inside
# the fixture's test region is counted as a brace and the region runs past its
# module to the end of the file.
if mutate "$REAL" "$MUT" "if c == '\"':" "if False and c == '\"':"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_literal.rs")"
  if [ "$got" = "4 17 13" ]; then
    ok "M8 (string literals scanned as code): the region swallows the rest of the file"
  else
    bad "M8 (string literals scanned as code): expected '4 17 13', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_item.rs")"
  if [ "$got" = "12 21 9" ]; then
    ok "M8: a literal-free region is unaffected"
  else
    bad "M8: attr_item.rs became '${got:-<absent>}'"
  fi
else
  bad "M8 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M9: parenthesis tracking before the item's body opens. Without it the `;` in
# the `[&str; 2]` type ends the `const` a line early and the rest of the
# declaration is production.
if mutate "$REAL" "$MUT" "elif c == ';' and paren <= 0:" "elif c == ';':"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_const.rs")"
  if [ "$got" = "12 14 2" ]; then
    ok "M9 (no paren tracking): the \`[&str; 2]\` semicolon ends the region early"
  else
    bad "M9 (no paren tracking): expected '12 14 2', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_literal.rs")"
  if [ "$got" = "9 17 8" ]; then
    ok "M9: a region with no pre-body semicolon is unaffected"
  else
    bad "M9: attr_literal.rs became '${got:-<absent>}'"
  fi
else
  bad "M9 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M10: the raw-string skipper. Without it a literal's braces are read as code, so
# a gated module ends inside the literal — its tail is charged to production and
# its test function is listed — and a function's body ends at the first brace
# inside the string.
if mutate "$REAL" "$MUT" 'm = RAW_OPEN.match(line, j)' 'm = None'; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_raw_multiline.rs")"
  if [ "$got" = "13 21 8" ]; then
    ok "M10 (raw strings unscanned): the gated module ends inside the literal"
  else
    bad "M10 (raw strings unscanned): expected '13 21 8', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_raw_quotes.rs")"
  if [ "$got" = "12 18 6" ]; then
    ok "M10: the quotes inside a raw string end it early"
  else
    bad "M10: attr_raw_quotes.rs expected '12 18 6', got '${got:-<absent>}'"
  fi
  MTOP="$(bash "$TREE/scripts/large-functions.sh" --top 200 2>&1)"
  got="$(fnrow "$MTOP" "frp-core/src/attr_raw_fn.rs:7")"
  if [ "$got" = "7 7" ]; then
    ok "M10: \`fn_body_end\` ends the production fn at the brace inside the literal"
  else
    bad "M10: attr_raw_fn.rs:7 is '${got:-<absent>}', expected '7 7'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_literal.rs")"
  if [ "$got" = "9 17 8" ]; then
    ok "M10: the ordinary-string fixture is unaffected (the mechanisms are independent)"
  else
    bad "M10: attr_literal.rs became '${got:-<absent>}'"
  fi
else
  bad "M10 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M11: the negation rule in the predicate parse. `not(…)` never implies `test`;
# treating it as if it did turns the two negations into gates again, while the
# true `all(test, …)` gate is untouched. The anchor carries the preceding
# `any(…)` arm so the replacement cannot land on a deeper-indented `return
# False` in one of the scanner helpers.
if mutate "$REAL" "$MUT" "        return bool(args) and all(cfg_implies_test(a) for a in args)
    return False" \
    "        return bool(args) and all(cfg_implies_test(a) for a in args)
    return True"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_not_any_gated.rs")"
  if [ "$got" = "5 11 6" ]; then
    ok "M11 (\`not(…)\` treated as a gate): the negated \`all(not(any(test, …)))\` is excluded again"
  else
    bad "M11: attr_not_any_gated.rs expected '5 11 6', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_not_space_gated.rs")"
  if [ "$got" = "5 11 6" ]; then
    ok "M11: the spaced negation \`not (test)\` is excluded again"
  else
    bad "M11: attr_not_space_gated.rs expected '5 11 6', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_all_gated_like.rs")"
  if [ "$got" = "3 8 5" ]; then
    ok "M11: the true \`all(test, …)\` gate is unaffected (the mechanisms are independent)"
  else
    bad "M11: attr_all_gated_like.rs became '${got:-<absent>}'"
  fi
else
  bad "M11 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M12: the gate's tail, restricted to the end of the line — the anchor the
# round-1 matcher carried and the one this round removes. Every same-line tail
# (a comment, a second attribute, a one-line `#[path]` declaration) stops being
# a gate, so all five fixtures are scored production again.
if mutate "$REAL" "$MUT" "                if j >= n or line[j] != ']':" \
    "                if line[j:] != ']':"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  for f in fs_cfg_block_comment fs_cfg_comment_bracket fs_cfg_two_attrs fs_cfg_all_comment; do
    got="$(row "$MOUT" "frp-core/src/$f.rs")"
    if [ "$got" = "14 14 0" ]; then
      ok "M12 (the \`]\` must end the line): $f.rs is production again"
    else
      bad "M12: $f.rs expected '14 14 0', got '${got:-<absent>}'"
    fi
  done
  got="$(row "$MOUT" "frp-core/src/fs_cfg_inline_path.rs")"
  if [ "$got" = "10 10 0" ]; then
    ok "M12: the one-line \`#[path]\` declaration stops being a gate too"
  else
    bad "M12: fs_cfg_inline_path.rs expected '10 10 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/fs_string_cont.rs")"
  if [ "$got" = "5 17 12" ]; then
    ok "M12: the string-continuation fixture is unaffected (the mechanisms are independent)"
  else
    bad "M12: fs_string_cont.rs became '${got:-<absent>}'"
  fi
else
  bad "M12 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M13: the comment tail alone. Rejecting a trailing comment (the round-1
# `(?://.*)?$` arm) drops the comment-carrying gates while the second-attribute
# and one-line-`#[path]` fixtures stay gates — the tail rule has three
# independent arms and this isolates one of them.
if mutate "$REAL" "$MUT" "        elif line.startswith('/*', i) or line.startswith('//', i):
            i = _skip_comment(line, i)" \
    "        elif line.startswith('/*', i) or line.startswith('//', i):
            return False"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  for f in fs_cfg_block_comment fs_cfg_comment_bracket fs_cfg_all_comment; do
    got="$(row "$MOUT" "frp-core/src/$f.rs")"
    if [ "$got" = "14 14 0" ]; then
      ok "M13 (comment tails rejected): $f.rs is production again"
    else
      bad "M13: $f.rs expected '14 14 0', got '${got:-<absent>}'"
    fi
  done
  got="$(row "$MOUT" "frp-core/src/fs_cfg_two_attrs.rs")"
  if [ "$got" = "9 14 5" ]; then
    ok "M13: a second attribute is not a comment — that gate survives"
  else
    bad "M13: fs_cfg_two_attrs.rs became '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/fs_cfg_inline_path.rs")"
  if [ "$got" = "9 10 1" ]; then
    ok "M13: the one-line \`#[path]\` declaration survives too"
  else
    bad "M13: fs_cfg_inline_path.rs became '${got:-<absent>}'"
  fi
else
  bad "M13 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M14: the attribute run, consumed one line at a time again. A one-line
# `#[cfg(test)] #[path = …] mod X;` then looks for its declaration on the next
# line, so `item_end` charges the production code below it to tests and the
# sibling is never attributed — the pre-round-2 behaviour, reproduced.
if mutate "$REAL" "$MUT" "        if k < len(line):" "        if False:"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/fs_cfg_inline_path.rs")"
  if [ "$got" = "5 10 5" ]; then
    ok "M14 (run consumed per line): the region swallows the production fn below the declaration"
  else
    bad "M14: fs_cfg_inline_path.rs expected '5 10 5', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/fs_cfg_inline_path/inline_helper.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M14: the one-line declaration's sibling is production again"
  else
    bad "M14: the inline sibling expected '4 4 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/pathed.rs")"
  if [ "$got" = "5 8 3" ]; then
    ok "M14: a multi-line attribute run is unaffected (the mechanisms are independent)"
  else
    bad "M14: pathed.rs became '${got:-<absent>}'"
  fi
else
  bad "M14 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M15: the ordinary-string continuation. Without it the `\` at end of line ends
# the literal instead of continuing it, so the `}` opening the next line is read
# as code: the gated module ends there and a production fn's body ends at the
# brace inside the literal.
if mutate "$REAL" "$MUT" "                        if j + 1 == len(line):" \
    "                        if False:"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/fs_string_cont.rs")"
  if [ "$got" = "9 17 8" ]; then
    ok "M15 (no string continuation): the region ends at the \`}\` in the literal"
  else
    bad "M15: fs_string_cont.rs expected '9 17 8', got '${got:-<absent>}'"
  fi
  MTOP="$(bash "$TREE/scripts/large-functions.sh" --top 200 2>&1)"
  got="$(fnrow "$MTOP" "frp-core/src/fs_string_fn.rs:1")"
  if [ "$got" = "3 3" ]; then
    ok "M15: \`fn_body_end\` ends the production fn at the brace in the literal"
  else
    bad "M15: fs_string_fn.rs:1 is '${got:-<absent>}', expected '3 3'"
  fi
  got="$(row "$MOUT" "frp-core/src/fs_cfg_block_comment.rs")"
  if [ "$got" = "9 14 5" ]; then
    ok "M15: the comment-tail fixture is unaffected (the mechanisms are independent)"
  else
    bad "M15: fs_cfg_block_comment.rs became '${got:-<absent>}'"
  fi
else
  bad "M15 mutation did not apply — anchor missing, the check would be vacuous"
fi

# ---------------------------------------------------------------- summary
printf '\n'
if [ "$fails" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), %d failure(s) above\n' "$checks" "$fails"
fi
exit "$fails"
