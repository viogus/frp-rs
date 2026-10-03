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
#      gate, and braces inside string literals, a predicate wrapped across
#      lines, a `#[path]` or `#[allow(…)]` sharing the gate's line, a spaced
#      `#[ cfg ( test ) ]` (whose following `#[path]` is a known limitation and
#      stays unattributed), and wrapped predicates declined because their payload
#      crosses a raw string, an ordinary continued string or a block comment), the
#      raw-string cases (a
#      multi-line literal and one with embedded quotes inside a gate's region, a
#      production function whose body holds one), the gate-tail cases (a trailing
#      `/* */` or `//` comment, a `]` inside that comment, a second attribute on
#      the gate's line, a one-line `#[cfg(test)] #[path = …] mod X;` declaration,
#      a block comment opened on the gate's line and closed on a later one, and an
#      ordinary string continued with a backslash at end of line), the text-that-
#      is-not-code cases (a `#[cfg(test)]` inside a block comment, inside a raw
#      string, on a backslash-continued line, and a `#[path]`-shaped raw-string
#      line directly above a real gate), the predicate with an escaped quote, and
#      the predicate-parse
#      controls (`all(not(any(test, …)))`, `all(not (test), …)`, and the true
#      `all(test, …)` gate beside them), plus the three negative controls
#      (a plain `mod X;` production sibling, a directory whose name merely starts
#      with `tests`, and a production `collide.rs` that another module's
#      `#[cfg(test)] mod collide;` must not claim — Rust resolves that under
#      `attacker/`), and a separate latent-hang tree: a gate whose backward walk
#      lands on a line that already carries a complete declaration. That tree is
#      measured under a watchdog (a regression must fail the suite, not hang it)
#      and its rows are asserted against the base script's output.
#   2  the default table and `--top` are unchanged in shape, a file the
#      filter excluded is still not listed, and the function table measures the
#      raw-string fixture's function to its true end.
#   3  twenty-six mutations of the script, each of which must red exactly one part
#      of the fixture suite: drop the name pattern, drop the sibling attribution, drop
#      declaration recognition, drop `pub(…)` from the declaration pattern,
#      offer `dir/X.rs` for a `parent.rs`, drop the `all(…)` arm of the
#      predicate parse, skip the backward attribute walk, scan string literals as
#      code, drop the paren tracking that keeps a `[&str; 2]` type's `;` from
#      ending a `const` early, stop skipping raw strings, treat `not(…)` as
#      implying `test`, require the gate's `]` to end its line, reject a comment
#      tail, consume the attribute run a line at a time again, drop the
#      ordinary-string continuation, skip an attribute tail within its own line
#      only, drop the escape state in the predicate splitter, drop the region
#      pass, and drop the backward walk's region guard, drop the wrapped-predicate
#      and packed-attribute acceptances, remove `CFG_OPEN`'s whitespace
#      tolerance, drop the multi-line raw-string and continued-string declines,
#      never clear the non-first-attribute flag, and drop the backward walk's
#      progress guard (which reds the latent-hang tree's timeout witness rather
#      than a row in scenario 1). A green suite on a mutant
#      would mean the fixture does not drive the code it claims to.
#   4  the check floor: a run without `python3` skips by design and must still
#      exit 0 rather than trip the short-suite guard.
#
# Usage: bash scripts/tests/large-functions-classifier.sh
set -uo pipefail

# --- self-defence: assert a floor on every exit path --------------------------
# A suite that silently stops checking must not exit green. The trap is
# installed before the path resolution and the first check, so an early `exit 0`
# anywhere below it still has to answer to the floor. `MIN_CHECKS` is the
# measured check count of a green run. The one deliberate early exit — the
# `python3`-absent SKIP below — sets `FLOOR_EXEMPT`, because zero checks is the
# right answer there.
MIN_CHECKS=166
checks=0
fails=0
WORK=""
FLOOR_EXEMPT=""

# shellcheck disable=SC2329  # invoked by the EXIT trap below, not directly
cleanup() {
  local rc=$?
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
  if [ "$rc" -eq 0 ] && [ "$checks" -lt "$MIN_CHECKS" ] \
     && [ -z "$FLOOR_EXEMPT" ]; then
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
  FLOOR_EXEMPT=1
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
#
# The run is walked attribute by attribute, so two spellings the round-3 head
# missed are gates too (each reads all-production at base `5682fe6c`, measured):
# a predicate that wraps (`#[cfg(all(` / `test,` / `feature = "x"` / `))]`) and a
# `#[path]` that shares the gate's line. A span that would have to walk through a
# line-spanning comment, string or raw string stays unsupported — pinned by `attr_wrapped_comment.rs`, `attr_wrapped_rawstr.rs` and
# `attr_wrapped_contstr.rs`, which all read production on purpose. The
# non-first attribute need not be a `#[path]`: `#[allow(dead_code)] #[cfg(test)]`
# is the same acceptance, pinned by `attr_allow_first.rs` and its declaration
# variant.
mkdir -p "$TREE/frp-core/src/attr_all_decl" "$TREE/frp-core/src/attr_back" \
  "$TREE/frp-core/src/attr_wrapped_decl" "$TREE/frp-core/src/attr_path_first" \
  "$TREE/frp-core/src/attr_path_first_any" "$TREE/frp-core/src/attr_allow_first_decl"

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

# The predicate wraps. The one-line locator could not see it (base: `17 17 0`),
# and the wrapped attribute has to be consumed across lines by the run walk as
# well, or the region would not even reach the `mod`.
cat > "$TREE/frp-core/src/attr_wrapped_gate.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[cfg(all(
    test,
    feature = "x"
))]
mod tests {
    #[test]
    fn inline() {}
}

pub fn prod_after() -> u8 {
    2
}
EOF

# A predicate that opens a block comment which closes on a later line is
# deliberately not a gate: `attribute_span` declines the span rather than
# re-lexing a multi-line comment beside the line-local scanner, so the module
# stays production. Pins the documented limit.
cat > "$TREE/frp-core/src/attr_wrapped_comment.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[cfg(all(/*
    test,
*/  feature = "x"
))]
mod tests {
    #[test]
    fn inline() {}
}

pub fn prod_after() -> u8 {
    2
}
EOF

# The wrapped predicate on an out-of-line declaration, with its `#[path]` above
# it: the run has to be walked back to the `#[path]` and forward across the
# wrapped attribute, and the sibling is only test lines if both happen.
cat > "$TREE/frp-core/src/attr_wrapped_decl.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[path = "attr_wrapped_decl/wrapped_decl_helper.rs"]
#[cfg(all(
    test,
    feature = "x"
))]
mod wrapped_decl;

pub fn prod_after() -> u8 {
    2
}
EOF
cat > "$TREE/frp-core/src/attr_wrapped_decl/wrapped_decl_helper.rs" <<'EOF'
pub fn wrapped_decl_helper_prod() {
    let x = 1;
}
EOF

# The gate is not the run's first attribute: `#[path]` shares its line. The
# one-line locator anchored on the line's first attribute and missed it
# (base: `11 11 0`, sibling `4 4 0`).
cat > "$TREE/frp-core/src/attr_path_first.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[path = "attr_path_first/path_first_helper.rs"] #[cfg(test)]
mod path_first;

pub fn prod_after() -> u8 {
    2
}
EOF
cat > "$TREE/frp-core/src/attr_path_first/path_first_helper.rs" <<'EOF'
pub fn path_first_helper_prod() {
    let x = 1;
}
EOF

# The same packed line with `any(test)`, so the accepted spelling is the
# attribute position, not the bare `test` predicate.
cat > "$TREE/frp-core/src/attr_path_first_any.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[path = "attr_path_first_any/path_first_any_helper.rs"] #[cfg(any(test))]
mod path_first_any;

pub fn prod_after() -> u8 {
    2
}
EOF
cat > "$TREE/frp-core/src/attr_path_first_any/path_first_any_helper.rs" <<'EOF'
pub fn path_first_any_helper_prod() {
    let x = 1;
}
EOF

# `CFG_OPEN` tolerates whitespace inside the attribute (`#`, `[`, `cfg`, `(`),
# and the spaced spelling is a gate — but nothing pinned that tolerance, so
# M22 removes it.
cat > "$TREE/frp-core/src/attr_spaced_gate.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[ cfg ( test ) ]
mod tests {
    #[test]
    fn inline() {}
}

pub fn prod_after() -> u8 {
    2
}
EOF

# The spaced spelling's known limit: the gate is recognised, but `attribute_run`
# only continues on a literal `#[`, so the `#[path]` and the out-of-line
# `mod t;` that follow a spaced gate are never joined to it and the target stays
# production (`4 4 0`) where the plain spelling attributes it (`0 4 4`). This
# pins a limitation, not desired behaviour.
mkdir -p "$TREE/frp-core/src/attr_spaced_path" "$TREE/frp-core/src/attr_plain_gate_path"
cat > "$TREE/frp-core/src/attr_spaced_path.rs" <<'EOF'
# [ cfg ( test ) ]
#[path = "attr_spaced_path/h.rs"]
mod t;
EOF
cat > "$TREE/frp-core/src/attr_spaced_path/h.rs" <<'EOF'
pub fn h_prod() -> u8 {
    1
}
EOF
cat > "$TREE/frp-core/src/attr_plain_gate_path.rs" <<'EOF'
#[cfg(test)]
#[path = "attr_plain_gate_path/h.rs"]
mod t;
EOF
cat > "$TREE/frp-core/src/attr_plain_gate_path/h.rs" <<'EOF'
pub fn h_prod() -> u8 {
    1
}
EOF

# The non-first attribute does not have to carry a `#[path]`: `#[allow(…)]`
# before the gate on the same line is the same acceptance (base: `14 14 0`,
# head `9 14 5`). The declaration variant also has to walk back to the
# `#[path]` line and attribute that sibling, which only works if the gate line
# itself is the candidate (base: `12 12 0` / sibling `4 4 0`).
cat > "$TREE/frp-core/src/attr_allow_first.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[allow(dead_code)] #[cfg(test)]
mod tests {
    #[test]
    fn inline() {}
}

pub fn prod_after() -> u8 {
    2
}
EOF
cat > "$TREE/frp-core/src/attr_allow_first_decl.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[path = "attr_allow_first_decl/allow_first_decl_helper.rs"]
#[allow(dead_code)] #[cfg(test)]
mod allow_first_decl;

pub fn prod_after() -> u8 {
    2
}
EOF
cat > "$TREE/frp-core/src/attr_allow_first_decl/allow_first_decl_helper.rs" <<'EOF'
pub fn allow_first_decl_helper_prod() {
    let x = 1;
}
EOF

# A wrapped predicate whose payload contains a raw string that runs past the
# line: `attribute_span` declines the span, so the module stays production.
# M23 removes that decline.
cat > "$TREE/frp-core/src/attr_wrapped_rawstr.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[cfg(all(
    test,
    feature = r#"x
"#
))]
mod tests {
    #[test]
    fn inline() {}
}

pub fn prod_after() -> u8 {
    2
}
EOF

# The ordinary-string analogue: the payload's `"` opens a string that ends its
# line with a backslash, which `_string_rest` flags as continued; the span is
# declined. M24 removes that decline.
cat > "$TREE/frp-core/src/attr_wrapped_contstr.rs" <<'EOF'
pub fn prod_before() -> u8 {
    1
}

#[cfg(all(
    test,
    feature = "x \
y"
))]
mod tests {
    #[test]
    fn inline() {}
}

pub fn prod_after() -> u8 {
    2
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

# --- trivia across lines, escapes, and text that is not code -------------------
# Four more ways the region can be misread. Each is measured against the three
# older revisions of the script (base `d922accf…`, `b113b013` `62f10280…`, the
# round-2 head `a44df7f3…`), and in each case the truth is the new head's value:
#
#   1  an attribute's tail may open a block comment that closes on a later line:
#      `#[cfg(test)] /* why` / `   ; } */` / `mod tests { … }` decorates the item
#      on the third line. Trivia therefore has to be skipped across lines;
#      stopping at the first end of line pointed the run at `; } */`, and
#      `item_end` read that `;` as the decorated item, charging the module to
#      production (base `9 15 6`, round-2 head `13 15 2`, truth `9 15 6`).
#   2  a `"` inside the predicate may be escaped: `all(feature = "a\"b", test)`.
#      A comma splitter that treats every quote as a terminator ends the string
#      at the `\"`, so the top-level comma is never seen and the gate is lost
#      entirely (base and round-2 head `14 14 0`, `b113b013` `9 14 5`, truth
#      `9 14 5`).
#   3  `#[cfg(test)]` inside a block comment, a raw string or a backslash-
#      continued string is text, not a gate. The older revisions fabricate a test
#      region out of it: `fs_comment_gate` reads `11 13 2` on all three,
#      `fs_raw_gate` `12 12 0` on base but `6 12 6` / `11 12 1`, `fs_cont_gate`
#      `11 11 0` on base but `6 11 5` / `10 11 1` (truth `13 13 0`, `12 12 0`,
#      `11 11 0`).
#   4  the backward walk over an attribute run must not absorb a `#[…]`-shaped
#      line that is inside such a region: `fs_raw_attr_above.rs` ends a raw
#      string on a line that starts with `#[path = …]` and puts a real gate
#      directly below it (truth `11 16 5`, without the guard `10 16 6`).
cat > "$TREE/frp-core/src/fs_cfg_mlcomment.rs" <<'EOF'
pub fn alpha() {
    let a = 1;
}

#[cfg(test)] /* why
   ; } */
mod tests {
    #[test]
    fn one() {}
}

pub fn omega() {
    let b = 2;
}
EOF

cat > "$TREE/frp-core/src/fs_cfg_escaped_quote.rs" <<'EOF'
pub fn alpha() {
    let a = 1;
}

#[cfg(all(feature = "a\"b", test))]
mod tests {
    #[test]
    fn one() {}
}

pub fn omega() {
    let b = 2;
}
EOF

cat > "$TREE/frp-core/src/fs_comment_gate.rs" <<'EOF'
pub fn alpha() {
    let a = 1;
}

/*
#[cfg(test)]
mod fake;
*/

pub fn omega() {
    let b = 2;
}
EOF

cat > "$TREE/frp-core/src/fs_raw_gate.rs" <<'EOF'
pub fn alpha() {
    let a = 1;
}

pub const GREETING: &str = r#"
#[cfg(test)] mod fake;
"#;

pub fn omega() {
    let b = 2;
}
EOF

cat > "$TREE/frp-core/src/fs_cont_gate.rs" <<'EOF'
pub fn alpha() {
    let a = 1;
}

pub const GREETING: &str = "start \
#[cfg(test)] mod fake;";

pub fn omega() {
    let b = 2;
}
EOF

cat > "$TREE/frp-core/src/fs_raw_attr_above.rs" <<'EOF'
pub fn alpha() {
    let a = 1;
}

pub const BANNER: &str = r#"
#[path = "fs_raw_attr_above/fake.rs"]"#;
#[cfg(test)]
mod tests {
    #[test]
    fn one() {}
}

pub fn omega() {
    let b = 2;
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

# bounded_run <outfile> <tree> — run the subject with a watchdog. `test_blocks`
# can be made to spin forever by a gate whose backward walk lands on a line that
# already carries a complete declaration, and a hung CI job is worse than a
# failed one: kill the run after BOUND_SECS (generous, so a loaded host cannot
# flake) and return 124 so the caller can FAIL on the timeout. The subject is a
# bash wrapper around `python3`, so the watchdog kills the wrapper's children
# too — a killed wrapper would otherwise leave `python3` spinning.
BOUND_SECS=30
bounded_run() { # bounded_run <outfile> <tree>; rc 124 on timeout
  local out="$1" tree="$2" pid wpid rc=0
  bash "$tree/scripts/large-functions.sh" --all >"$out" 2>&1 &
  pid=$!
  (
    sleep "$BOUND_SECS"
    if command -v pkill >/dev/null 2>&1; then
      pkill -9 -P "$pid" 2>/dev/null
    fi
    kill -9 "$pid" 2>/dev/null
  ) >/dev/null 2>&1 &
  wpid=$!
  wait "$pid" || rc=$?
  kill "$wpid" 2>/dev/null || true
  wait "$wpid" 2>/dev/null || true
  if [ "$rc" -gt 128 ]; then
    return 124
  fi
  return "$rc"
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
expect_row "$OUT" "frp-core/src/attr_wrapped_gate.rs" 9 17 8 \
  "a \`#[cfg(all(\` predicate wrapped across lines is a gate"
expect_row "$OUT" "frp-core/src/attr_wrapped_comment.rs" 17 17 0 \
  "a wrapped predicate opening a block comment on its line stays unsupported"
expect_row "$OUT" "frp-core/src/attr_wrapped_decl.rs" 9 15 6 \
  "a wrapped predicate on a \`mod X;\` spans its run and declaration"
expect_row "$OUT" "frp-core/src/attr_wrapped_decl/wrapped_decl_helper.rs" 0 4 4 \
  "a wrapped predicate's \`#[path]\` sibling is attributed to tests"
expect_row "$OUT" "frp-core/src/attr_path_first.rs" 9 11 2 \
  "a \`#[path]\` packed before the gate on its line is still a gate"
expect_row "$OUT" "frp-core/src/attr_path_first/path_first_helper.rs" 0 4 4 \
  "the packed \`#[path]\` still attributes its sibling to tests"
expect_row "$OUT" "frp-core/src/attr_path_first_any.rs" 9 11 2 \
  "the packed spelling gates with \`any(test)\` too"
expect_row "$OUT" "frp-core/src/attr_spaced_gate.rs" 9 14 5 \
  "a spaced \`#[ cfg ( test ) ]\` is a gate"
expect_row "$OUT" "frp-core/src/attr_spaced_path.rs" 1 4 3 \
  "a spaced gate still opens its own region"
expect_row "$OUT" "frp-core/src/attr_spaced_path/h.rs" 4 4 0 \
  "a \`#[path]\` after a spaced gate is a known limitation and stays production"
expect_row "$OUT" "frp-core/src/attr_plain_gate_path/h.rs" 0 4 4 \
  "the plain spelling of the same shape attributes its sibling (the contrast)"
expect_row "$OUT" "frp-core/src/attr_path_first_any/path_first_any_helper.rs" 0 4 4 \
  "the packed \`any(test)\` \`#[path]\` still attributes its sibling to tests"
expect_row "$OUT" "frp-core/src/attr_allow_first.rs" 9 14 5 \
  "a gate preceded by \`#[allow(…)]\` on its line is a gate"
expect_row "$OUT" "frp-core/src/attr_allow_first_decl.rs" 9 12 3 \
  "an \`#[allow(…)]\`-preceded gate still spans its \`#[path]\` and declaration"
expect_row "$OUT" "frp-core/src/attr_allow_first_decl/allow_first_decl_helper.rs" 0 4 4 \
  "the \`#[allow(…)]\`-preceded gate's \`#[path]\` sibling is attributed to tests"
expect_row "$OUT" "frp-core/src/attr_wrapped_rawstr.rs" 18 18 0 \
  "a wrapped predicate crossing a multi-line raw string stays unsupported"
expect_row "$OUT" "frp-core/src/attr_wrapped_contstr.rs" 18 18 0 \
  "a wrapped predicate crossing a backslash-continued string stays unsupported"
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

# --- trivia across lines, escapes, and text that is not code -------------------
expect_row "$OUT" "frp-core/src/fs_cfg_mlcomment.rs" 9 15 6 \
  "a block comment opened on the gate's line and closed later still takes the module"
expect_row "$OUT" "frp-core/src/fs_cfg_escaped_quote.rs" 9 14 5 \
  "an escaped quote in the predicate does not hide the \`test\` argument"
expect_row "$OUT" "frp-core/src/fs_comment_gate.rs" 13 13 0 \
  "a \`#[cfg(test)]\` inside a block comment is not a gate"
expect_row "$OUT" "frp-core/src/fs_raw_gate.rs" 12 12 0 \
  "a \`#[cfg(test)]\` inside a raw string is not a gate"
expect_row "$OUT" "frp-core/src/fs_cont_gate.rs" 11 11 0 \
  "a \`#[cfg(test)]\` on a backslash-continued string line is not a gate"
expect_row "$OUT" "frp-core/src/fs_raw_attr_above.rs" 11 16 5 \
  "a \`#[path]\`-shaped raw-string line does not join the region below it"

# --- the latent-hang tree (the backward walk must always advance) --------------
# `ATTR_LINE` matches a full `#[cfg(test)] #[path = "x.rs"] mod t;` line, not just
# a bare attribute, so the backward walk can start the attribute run on an
# earlier item and `i = j + 1` then leaves the loop state unchanged. Base is
# vulnerable too (v7/v8 hang at `5682fe6c`); the wrapped and packed gates this
# branch added widen the reachable set (v1/v2/v5/v9 hang only on the pre-fix
# head). The tree is separate from `$TREE` on purpose: scenario 3's mutations run
# the subject over `$TREE`, and a mutant that reopens the hang must be caught by
# a bounded run (M26), never by the plain run. Rows for v1/v2/v5/v9 are the base
# script's own output, measured per shape; v7/v8 hang at base, so their rows are
# new. The wrapped gate v3 sits first in its file, where no walk-back happens:
# head and fixed agree on `6 10 4` there and base's `9 10 1` is the round-1
# wrapped-predicate feature, not this guard.
HANG="$WORK/hang"
mkdir -p "$HANG/scripts" "$HANG/frp-core/src" \
  "$HANG/frp-core/src/hang_v1" "$HANG/frp-core/src/hang_v2" \
  "$HANG/frp-core/src/hang_v3" "$HANG/frp-core/src/hang_v7" \
  "$HANG/frp-core/src/hang_v8" "$HANG/frp-core/src/hang_v9"
cp "$REAL" "$HANG/scripts/large-functions.sh"
cat > "$HANG/frp-core/src/hang_v1.rs" <<'EOF'
#[cfg(test)] #[path = "hang_v1/h.rs"] mod t;
#[cfg(all(feature = "x",
    test))]
mod w;

pub fn v1_prod() -> u8 {
    1
}
EOF
cat > "$HANG/frp-core/src/hang_v2.rs" <<'EOF'
#[cfg(test)] #[path = "hang_v2/h.rs"] mod t;
#[path = "hang_v2/h.rs"] #[cfg(test)]
mod w;

pub fn v2_prod() -> u8 {
    1
}
EOF
cat > "$HANG/frp-core/src/hang_v5.rs" <<'EOF'
#[cfg(feature = "y")] mod t;
#[cfg(all(feature = "x",
    test))]
mod w;

pub fn v5_prod() -> u8 {
    1
}
EOF
cat > "$HANG/frp-core/src/hang_v7.rs" <<'EOF'
#[cfg(test)] #[path = "hang_v7/h.rs"] mod t;
#[cfg(test)] #[path = "hang_v7/h.rs"] mod u;
EOF
cat > "$HANG/frp-core/src/hang_v8.rs" <<'EOF'
#[cfg(test)] #[path = "hang_v8/h.rs"] mod t;
#[cfg(test)]
mod u;
EOF
cat > "$HANG/frp-core/src/hang_v9.rs" <<'EOF'
#[cfg(test)] #[path = "hang_v9/h.rs"] mod t;
#[cfg(all(feature = "x",
    test))]
mod w {
    pub fn inner() -> u8 {
        1
    }
}

pub fn v9_prod() -> u8 {
    1
}
EOF
cat > "$HANG/frp-core/src/hang_v3.rs" <<'EOF'
#[cfg(all(feature = "x",
    test))]
mod w;

#[cfg(test)] #[path = "hang_v3/h.rs"] mod t;

pub fn v3_prod() -> u8 {
    1
}
EOF
for v in v1 v2 v3 v7 v8 v9; do
  cat > "$HANG/frp-core/src/hang_$v/h.rs" <<'EOF'
pub fn h_prod() -> u8 {
    1
}
EOF
done
HOUT="$WORK/hang.out"
if bounded_run "$HOUT" "$HANG"; then
  ok "the latent-hang tree terminates (bounded run exits 0)"
else
  bad "the latent-hang tree did not terminate (rc $?, expected 0)"
fi
# `row` takes the subject's output as TEXT, not a path (see its `printf | awk`).
HOUT="$(cat "$WORK/hang.out")"
expect_row "$HOUT" "frp-core/src/hang_v1.rs" 8 9 1 \
  "a wrapped gate under a same-line declaration keeps the base reading"
expect_row "$HOUT" "frp-core/src/hang_v1/h.rs" 0 4 4 \
  "that same-line declaration's sibling stays attributed"
expect_row "$HOUT" "frp-core/src/hang_v2.rs" 7 8 1 \
  "a packed \`#[path]\` gate under a same-line declaration keeps the base reading"
expect_row "$HOUT" "frp-core/src/hang_v2/h.rs" 0 4 4 \
  "that packed shape's sibling stays attributed"
expect_row "$HOUT" "frp-core/src/hang_v5.rs" 9 9 0 \
  "a non-test declaration above a wrapped gate keeps the base reading"
expect_row "$HOUT" "frp-core/src/hang_v7.rs" 2 3 1 \
  "two same-line gate declarations terminate (base hangs)"
expect_row "$HOUT" "frp-core/src/hang_v7/h.rs" 0 4 4 \
  "the first of the two declarations still attributes its sibling"
expect_row "$HOUT" "frp-core/src/hang_v8.rs" 3 4 1 \
  "a same-line declaration then a bare gate terminates (base hangs)"
expect_row "$HOUT" "frp-core/src/hang_v8/h.rs" 0 4 4 \
  "that declaration still attributes its sibling"
expect_row "$HOUT" "frp-core/src/hang_v9.rs" 12 13 1 \
  "a wrapped gate over a braced module under a declaration keeps the base reading"
expect_row "$HOUT" "frp-core/src/hang_v9/h.rs" 0 4 4 \
  "the braced case's sibling stays attributed"
expect_row "$HOUT" "frp-core/src/hang_v3.rs" 6 10 4 \
  "a wrapped gate first in its file is unaffected (head and fixed agree)"
expect_row "$HOUT" "frp-core/src/hang_v3/h.rs" 0 4 4 \
  "the wrapped-first control's sibling is attributed"

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
if mutate "$REAL" "$MUT" \
    'while start > 0 and ATTR_LINE.match(lines[start - 1]) and not flags[start - 1]:' \
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

# M14: the attribute run, advanced a line at a time after each attribute again.
# A one-line `#[cfg(test)] #[path = …] mod X;` then loses the `#[path]` (the run
# looks for the next attribute on the following line), so `item_end` charges the
# production code below the declaration to tests and the sibling is never
# attributed — the pre-round-2 behaviour, reproduced.
if mutate "$REAL" "$MUT" "        i, j = _skip_trivia(lines, i, end + 1)" \
    "        i, j = i + 1, 0"; then
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

# M16: the attribute tail, skipped inside the gate's own line only. A trailing
# block comment that closes on a later line then leaves the run pointing at
# `; } */`, whose semicolon `item_end` reads as the decorated item, so the test
# module below it is charged to production (`13 15 2` — the round-2 head's
# measurement, reproduced).
if mutate "$REAL" "$MUT" "            i, j = i + 1, 0
            while i < n:" "            i, j = i + 1, 0
            while False:"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/fs_cfg_mlcomment.rs")"
  if [ "$got" = "13 15 2" ]; then
    ok "M16 (tail skipped within the line): the module below the comment's \`;\` is production again"
  else
    bad "M16: fs_cfg_mlcomment.rs expected '13 15 2', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/fs_cfg_block_comment.rs")"
  if [ "$got" = "9 14 5" ]; then
    ok "M16: a comment that closes on the gate's own line is unaffected (the mechanisms are independent)"
  else
    bad "M16: fs_cfg_block_comment.rs became '${got:-<absent>}'"
  fi
else
  bad "M16 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M17: the escape state in the predicate splitter. Without it `\"` ends the
# string early, the comma after `"a\"b"` never reads as top-level, and the gate
# is not recognised at all — the module is scored production (`14 14 0`).
if mutate "$REAL" "$MUT" "            if esc:
                esc = False" "            if False:
                esc = False"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/fs_cfg_escaped_quote.rs")"
  if [ "$got" = "14 14 0" ]; then
    ok "M17 (no escape state): the escaped quote hides the \`test\` argument and the gate is lost"
  else
    bad "M17: fs_cfg_escaped_quote.rs expected '14 14 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_all_gated.rs")"
  if [ "$got" = "5 10 5" ]; then
    ok "M17: a predicate without escapes is unaffected (the mechanisms are independent)"
  else
    bad "M17: attr_all_gated.rs became '${got:-<absent>}'"
  fi
else
  bad "M17 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M18: the region pass. Without it the same-line gate spellings inside a block
# comment, a raw string and a backslash-continued string are gates again —
# exactly the values the round-2 head measured (`11 13 2`, `11 12 1`,
# `10 11 1`).
if mutate "$REAL" "$MUT" "        if flags[i] or not is_test_gate_run(lines, i):" \
    "        if not is_test_gate_run(lines, i):"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/fs_comment_gate.rs")"
  if [ "$got" = "11 13 2" ]; then
    ok "M18 (no region pass): a \`#[cfg(test)]\` inside a block comment is a gate again"
  else
    bad "M18: fs_comment_gate.rs expected '11 13 2', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/fs_raw_gate.rs")"
  if [ "$got" = "11 12 1" ]; then
    ok "M18: a \`#[cfg(test)]\` inside a raw string is a gate again"
  else
    bad "M18: fs_raw_gate.rs expected '11 12 1', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/fs_cont_gate.rs")"
  if [ "$got" = "10 11 1" ]; then
    ok "M18: a \`#[cfg(test)]\` on a continued line is a gate again"
  else
    bad "M18: fs_cont_gate.rs expected '10 11 1', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/fs_cfg_two_attrs.rs")"
  if [ "$got" = "9 14 5" ]; then
    ok "M18: a gate in ordinary code is unaffected (the mechanisms are independent)"
  else
    bad "M18: fs_cfg_two_attrs.rs became '${got:-<absent>}'"
  fi
else
  bad "M18 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M19: the backward walk's region guard. The raw string in
# `fs_raw_attr_above.rs` ends on a line that begins with `#[path = …]`, directly
# above a real gate; without the guard that line joins the region and one
# production line is charged to tests (`10 16 6`).
if mutate "$REAL" "$MUT" \
    '        while start > 0 and ATTR_LINE.match(lines[start - 1]) and not flags[start - 1]:' \
    '        while start > 0 and ATTR_LINE.match(lines[start - 1]):'; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/fs_raw_attr_above.rs")"
  if [ "$got" = "10 16 6" ]; then
    ok "M19 (no region guard on the walk-back): the raw-string line joins the region"
  else
    bad "M19: fs_raw_attr_above.rs expected '10 16 6', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/fs_cfg_block_comment.rs")"
  if [ "$got" = "9 14 5" ]; then
    ok "M19: a run whose preceding line is code is unaffected (the mechanisms are independent)"
  else
    bad "M19: fs_cfg_block_comment.rs became '${got:-<absent>}'"
  fi
else
  bad "M19 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M20: the wrapped-predicate acceptance. Dropping it turns a predicate that
# closes on a later line back into production — the tree-wide shape item 1 was
# filed for. The declaration fixture still gates, because its run begins above
# the wrapped attribute (`first` is already False); only the gate-first fixture
# reds, so the two fixtures witness different halves of the rule.
if mutate "$REAL" "$MUT" "                    and (ei > li or not first):" \
    "                    and (not first):"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_wrapped_gate.rs")"
  if [ "$got" = "17 17 0" ]; then
    ok "M20 (no wrapped-predicate acceptance): a wrapped \`#[cfg(all(\` is production again"
  else
    bad "M20: attr_wrapped_gate.rs expected '17 17 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/fs_cfg_inline_path.rs")"
  if [ "$got" = "9 10 1" ]; then
    ok "M20: a same-line gate is unaffected (the mechanisms are independent)"
  else
    bad "M20: fs_cfg_inline_path.rs became '${got:-<absent>}'"
  fi
else
  bad "M20 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M21: the packed-`#[path]` acceptance. Dropping it makes the gate invisible when
# it is not the run's first attribute, so the module and its `#[path]` sibling
# read all-production again; the wrapped fixture is gated by its own first
# attribute (`ei > li`) and stays put, which is the independence control.
if mutate "$REAL" "$MUT" "                    and (ei > li or not first):" \
    "                    and (ei > li):"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_path_first.rs")"
  if [ "$got" = "11 11 0" ]; then
    ok "M21 (no packed-attribute acceptance): \`#[path = …] #[cfg(test)]\` is production again"
  else
    bad "M21: attr_path_first.rs expected '11 11 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_path_first/path_first_helper.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M21: the packed \`#[path]\` sibling is no longer attributed to tests"
  else
    bad "M21: attr_path_first/path_first_helper.rs expected '4 4 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_wrapped_gate.rs")"
  if [ "$got" = "9 17 8" ]; then
    ok "M21: a gate that is the run's first attribute is unaffected"
  else
    bad "M21: attr_wrapped_gate.rs became '${got:-<absent>}'"
  fi
else
  bad "M21 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M22: `CFG_OPEN`'s whitespace tolerance. The spaced spelling gates today only
# because the pattern allows the spaces; narrowing it to the exact `#[cfg(`
# spelling turns `attr_spaced_gate.rs` back into production. `attr_item.rs` is
# the control: a gate that is already exact must not move.
if mutate "$REAL" "$MUT" \
    "CFG_OPEN = re.compile(r'\s*#\s*\[\s*cfg\s*\(')" \
    "CFG_OPEN = re.compile(r'\s*#\[cfg\(')"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_spaced_gate.rs")"
  if [ "$got" = "14 14 0" ]; then
    ok "M22 (no whitespace tolerance): \`#[ cfg ( test ) ]\` no longer gates"
  else
    bad "M22: attr_spaced_gate.rs expected '14 14 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_item.rs")"
  if [ "$got" = "12 21 9" ]; then
    ok "M22: an exactly spelled gate is unaffected (the mechanisms are independent)"
  else
    bad "M22: attr_item.rs became '${got:-<absent>}'"
  fi
else
  bad "M22 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M23: the multi-line raw-string decline in `attribute_span`. Dropping it lets
# the span walk past the line into the rest of the wrapped predicate, so
# `attr_wrapped_rawstr.rs` becomes a gate and its test module stops counting as
# production. `attr_wrapped_contstr.rs` is the control: it is declined by the
# ordinary-string branch, a different check in the same scanner.
if mutate "$REAL" "$MUT" \
    "                    if k < 0:           # the raw string continues past the line
                        return -1, -1" \
    "                    if k < 0:
                        j = n
                        continue"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_wrapped_rawstr.rs")"
  if [ "$got" = "9 18 9" ]; then
    ok "M23 (no multi-line raw-string decline): the wrapped predicate gates again"
  else
    bad "M23: attr_wrapped_rawstr.rs expected '9 18 9', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_wrapped_contstr.rs")"
  if [ "$got" = "18 18 0" ]; then
    ok "M23: a backslash-continued string is still declined (an independent branch)"
  else
    bad "M23: attr_wrapped_contstr.rs became '${got:-<absent>}'"
  fi
else
  bad "M23 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M24: the backslash-continued-string decline. Same mechanism on the
# ordinary-string branch, with the raw-string fixture as the control.
if mutate "$REAL" "$MUT" \
    "                if not done:            # a \`\\\` at end of line continues it
                    return -1, -1" \
    '                if not done:
                    j = n
                    continue'; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_wrapped_contstr.rs")"
  if [ "$got" = "9 18 9" ]; then
    ok "M24 (no continued-string decline): the wrapped predicate gates again"
  else
    bad "M24: attr_wrapped_contstr.rs expected '9 18 9', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_wrapped_rawstr.rs")"
  if [ "$got" = "18 18 0" ]; then
    ok "M24: a multi-line raw string is still declined (an independent branch)"
  else
    bad "M24: attr_wrapped_rawstr.rs became '${got:-<absent>}'"
  fi
else
  bad "M24 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M25: the `first` flag that the non-first acceptance reads. Never clearing it
# reduces the clause to `ei > li`, so a gate that is not the run's first
# attribute is missed — both `#[allow(dead_code)] #[cfg(test)]` fixtures red,
# including the `#[path]` sibling's attribution. The wrapped fixtures are the
# controls: they are accepted on `ei > li`, so the flag is irrelevant to them.
if mutate "$REAL" "$MUT" \
    "        first = False" \
    "        first = True"; then
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_allow_first.rs")"
  if [ "$got" = "14 14 0" ]; then
    ok "M25 (non-first gate never accepted): \`#[allow(…)] #[cfg(test)]\` is production again"
  else
    bad "M25: attr_allow_first.rs expected '14 14 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_allow_first_decl.rs")"
  if [ "$got" = "12 12 0" ]; then
    ok "M25: the \`#[allow(…)]\`-preceded gate no longer spans its declaration"
  else
    bad "M25: attr_allow_first_decl.rs expected '12 12 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_allow_first_decl/allow_first_decl_helper.rs")"
  if [ "$got" = "4 4 0" ]; then
    ok "M25: the \`#[path]\` sibling is no longer attributed to tests"
  else
    bad "M25: attr_allow_first_decl/allow_first_decl_helper.rs expected '4 4 0', got '${got:-<absent>}'"
  fi
  got="$(row "$MOUT" "frp-core/src/attr_wrapped_gate.rs")"
  if [ "$got" = "9 17 8" ]; then
    ok "M25: a wrapped predicate is unaffected (accepted on its closing line)"
  else
    bad "M25: attr_wrapped_gate.rs became '${got:-<absent>}'"
  fi
else
  bad "M25 mutation did not apply — anchor missing, the check would be vacuous"
fi

# M26: the progress guard itself. Reverting it (`if j < i and not flags[start]:`
# → `if False:`) makes
# the backward walk spin again on the latent-hang tree; the witness is the
# watchdog's 124, so the round that reopens the hang FAILS instead of hanging.
# The main tree has no trigger shape, so a control row there must still measure.
if mutate "$REAL" "$MUT" \
    "        if j < i and not flags[start]:" \
    "        if False:"; then
  cp "$MUT" "$HANG/scripts/large-functions.sh"
  m26rc=0
  bounded_run "$WORK/m26.out" "$HANG" || m26rc=$?
  if [ "$m26rc" -eq 124 ]; then
    ok "M26 (no progress guard): the watchdog killed the non-terminating subject"
  else
    bad "M26: the hang tree returned rc $m26rc under the reverted guard, expected the 124 timeout"
  fi
  cp "$MUT" "$TREE/scripts/large-functions.sh"
  MOUT="$(bash "$TREE/scripts/large-functions.sh" --all 2>&1)"
  got="$(row "$MOUT" "frp-core/src/attr_back.rs")"
  if [ "$got" = "9 12 3" ]; then
    ok "M26: the main tree is unaffected — the guard is load-bearing only on the trigger shape"
  else
    bad "M26: attr_back.rs expected '9 12 3', got '${got:-<absent>}'"
  fi
  cp "$REAL" "$HANG/scripts/large-functions.sh"
  cp "$REAL" "$TREE/scripts/large-functions.sh"
else
  bad "M26 mutation did not apply — anchor missing, the check would be vacuous"
fi

# ---------------------------------------------------------------- the floor
printf '\nscenario 4: the check floor and the skip path\n'
# The floor answers a short run with a failure, which is right for a suite that
# stopped checking and wrong for the `python3`-absent SKIP above it: that path
# runs zero checks on purpose and sets `FLOOR_EXEMPT`. Re-run the whole suite
# with a PATH that has no `python3` and assert the skip still exits 0 — a
# regression here would be a red CI job on a machine without python3.
nopy="$(mktemp -d)"
for tool in dirname readlink; do
  ln -s "$(command -v "$tool")" "$nopy/$tool"
done
if skip_out="$(PATH="$nopy" "$BASH" "$0" 2>&1)"; then
  ok "a run without \`python3\` skips cleanly instead of tripping the check floor"
else
  bad "the \`python3\`-absent skip path failed the floor: $skip_out"
fi
rm -rf "$nopy"

# ---------------------------------------------------------------- summary
printf '\n'
if [ "$fails" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), %d failure(s) above\n' "$checks" "$fails"
fi
exit "$fails"
