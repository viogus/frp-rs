// ─── Format detection ────────────────────────────────────────────────
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum ConfigFormat {
    Toml,
    Ini,
    Json,
    Yaml,
}

pub(super) fn detect_format(path: &str) -> ConfigFormat {
    let path_lower = path.to_lowercase();
    if path_lower.ends_with(".ini") {
        ConfigFormat::Ini
    } else if path_lower.ends_with(".json") {
        ConfigFormat::Json
    } else if path_lower.ends_with(".yaml") || path_lower.ends_with(".yml") {
        ConfigFormat::Yaml
    } else {
        ConfigFormat::Toml
    }
}

pub(super) fn parse_to_toml_value(
    content: &str,
    format: ConfigFormat,
) -> Result<toml::Value, Box<dyn std::error::Error>> {
    match format {
        ConfigFormat::Toml => Ok(toml::from_str(content)?),
        ConfigFormat::Ini => ini_to_toml(content),
        ConfigFormat::Json => {
            let json_val: serde_json::Value = serde_json::from_str(content)?;
            Ok(json_to_toml(json_val))
        }
        ConfigFormat::Yaml => yaml_to_toml(content),
    }
}

/// Convert serde_json::Value to toml::Value for normalization pipeline.
fn json_to_toml(v: serde_json::Value) -> toml::Value {
    match v {
        serde_json::Value::Null => toml::Value::String(String::new()),
        serde_json::Value::Bool(b) => toml::Value::Boolean(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                toml::Value::Float(f)
            } else {
                toml::Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => toml::Value::String(s),
        serde_json::Value::Array(arr) => {
            toml::Value::Array(arr.into_iter().map(json_to_toml).collect())
        }
        serde_json::Value::Object(map) => {
            let table: toml::Table = map.into_iter().map(|(k, v)| (k, json_to_toml(v))).collect();
            toml::Value::Table(table)
        }
    }
}

// ─── YAML parser (Go frp's own scalar resolution) ───────────────────────

/// Parse YAML content into a `toml::Value`.
///
/// The parser's own event stream is the source of truth, for three reasons:
///
/// * **Scalar style is only visible there.** A plain `yes` and a quoted `"yes"`
///   are the same `Yaml::String` once loaded, but only the plain one may be read
///   as a YAML 1.1 boolean; a block scalar (`|`, `>`) must never be transformed
///   either.
/// * **The tag is only visible there.** `!!int "017"` is 15 and `!!str 017` is
///   the string `017`, but a loaded tree keeps only the text.
/// * **Anchors, aliases and merge keys are resolved in one traversal**, so the
///   value built here is exactly the value that was written.
///
/// Plain scalars are resolved with the rules of the YAML reader Go frp itself
/// embeds — `gopkg.in/yaml.v2` v2.4.0, measured with `go version -m` on the
/// v0.71.0 release binary — see [`yaml_plain_scalar`]. That is a deliberate
/// behaviour change from the previous `serde_yaml_ng` reader for a small set of
/// plain scalars, which now match Go instead of being silently read the other
/// way:
///
/// * the YAML 1.1 booleans — unquoted `y`/`yes`/`on` and `n`/`no`/`off`, any
///   case, are booleans, so quote them to keep the text (the old reader rejected
///   an unquoted `no` on a boolean field with
///   `invalid type: string "no", expected a boolean`);
/// * a plain leading-zero number is an octal (`017` is 15) where the old reader
///   kept the text, and a tagged `!!float`/`!!int` body is parsed as an integer
///   first (`!!float 017` is 15, not 17);
/// * `_`-prefixed tokens (`_100`) stay strings, matching Go's
///   `resolveTable[in[0]]` gate; a sign selects Go's numeric branch, so `+_100`
///   is still 100;
/// * an uppercase binary prefix resolves (`0B101` is 5 where the old reader kept
///   the text; lowercase `0b101` was already 5).
///
/// Not changes against the old reader, and recorded so they are not re-filed as
/// ones: `0o17` already resolved to 15, and `Null`/`NULL`/`~` already resolved
/// to null.
///
/// Deliberate, *loud* differences from Go frp that remain: duplicate keys in one
/// mapping are an error (the old reader also errored, with the same
/// `duplicate entry with key "…"` text; Go silently keeps the last value), and a
/// second document is an error. Two previously listed "unmeasured" rows now
/// match Go on outcome: a byte-order mark in the middle of a document becomes
/// part of the following key exactly as it does in Go (the old reader errored),
/// and `!!set`/`!!omap`/`!!pairs` accept and reject the same inputs Go does
/// (their resolved shapes differ from Go's `null` values).
///
/// The `serde_json::Value` built here then goes through the same `json_to_toml`
/// conversion as the JSON path, so both formats share one type-inference
/// pipeline.
///
/// Remaining divergences from Go that are **pre-existing at `main`** rather than
/// introduced by this reader, recorded with the measured `main` behaviour so they
/// are not mis-filed as regressions:
///
/// * a map key outside `i64`/`u64` range (`{18446744073709551615: v}`) and a
///   null key (`{~: v}`) are accepted as text; Go errors (`main`: same);
/// * an integral float key renders with its `.0` (`{10.0: v}` -> `"10.0"`, and
///   `{1000.0: v}` -> `"1000.0"`); Go renders `"10"` / `"1000"` (`main`: same);
/// * a `%YAML 1.2` directive is accepted; Go errors (`main`: same);
/// * an empty or comment-only document yields the empty string, which the
///   `ClientConfig` decoder rejects with `invalid type: string "", expected
///   struct ClientConfig`; Go uses defaults (`main`: same);
/// * the top-level dot-key deletion Go's `parseYAMLWithDotFieldsHandling` does
///   is not reproduced, but an unknown key is only ignored, so `.note: hello`
///   loads with defaults rather than erroring (`main`: same);
/// * a quoted `"<<"` is a literal key, as in Go — the old reader errored on it,
///   treating it as a merge key (`main`: differs, toward Go);
/// * `!Custom 7000` resolves to the string `7000`, as in Go — the old reader
///   produced the integer 7000 (`main`: differs, toward Go).
///
/// Unknown differences from Go frp, none of them silent: a merge key is applied
/// in *insertion* order, so an explicitly written key always wins, while Go
/// resolves a merge by position — `{serverPort: 7000, <<: {serverPort: 1234}}`
/// dials **1234** in Go and **7000** here, because an explicit key does not
/// shadow `<<` there; `!!binary` keeps its text instead of being decoded;
/// `!!timestamp`/`!!binary` bodies are not validated, so an invalid one such as
/// `!!timestamp garbage` is kept as a string where Go rejects it; and the
/// strictness of unknown fields is not reproduced.
///
/// Deliberate *refusals* that Go accepts, all loud: a tab used for indentation
/// inside a flow collection (the scanner refuses it), and a multi-line flow
/// collection whose continuation is not indented (`x: [1,` / `2]`), which the
/// scanner reads as `invalid indentation in flow construct` — while the
/// tab-continued form is accepted.
///
/// One more loud refusal is new here and not shared with Go: a document that
/// expands past `400_000` nodes is refused (`document exceeds the node limit`),
/// and so is an alias expansion past the same per-document budget. That is far
/// beyond any real config — roughly 200 000 mapping entries — and it is what
/// stops a node bomb padded with inert bytes (a 1 MiB file whose bomb would
/// expand to ~100 million nodes is refused in tens of milliseconds). It bounds
/// *nodes*, not bytes: a large scalar anchor re-expanded many times stays under
/// the ceiling and can still cost gigabytes. That residual is pre-existing, not
/// a Go divergence, and is registered in `TODO.md` — see `YamlReceiver::new`.
/// Go bounds the node-bomb shape itself with `allowedAliasRatio`.
///
/// # Errors
///
/// `YAML parse error: …` for malformed input, a duplicate mapping key, more than
/// one document, a tab used for indentation, a `...` without a document, an
/// unresolvable alias, an alias expansion or a document past the node budget
/// (`YamlReceiver::new`), or an explicitly
/// tagged scalar (`!!int`) whose body does not match its tag; `YAML merge key
/// (``<<``) error: …` for a merge key whose value is not a mapping or a sequence
/// of mappings.
fn yaml_to_toml(content: &str) -> Result<toml::Value, Box<dyn std::error::Error>> {
    // `yaml-rust2`'s scanner does not strip a byte-order mark (its own TODO);
    // the previous reader did, and config files are UTF-8.
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    // Tabs are checked before parsing because `yaml-rust2` accepts several
    // forms that Go frp (and the previous reader) reject; see the function.
    if let Some((line, column)) = yaml_indentation_tab(content) {
        return Err(format!(
            "YAML parse error: a tab character cannot be used for indentation \
             (line {line} column {column}); indent with spaces"
        )
        .into());
    }
    let mut receiver = YamlReceiver::new(content.len());
    yaml_rust2::parser::Parser::new_from_str(content)
        .load(&mut receiver, true)
        .map_err(|e| format!("YAML parse error: {e}"))?;
    let document = receiver.finish(content)?;
    Ok(json_to_toml(yaml_value_to_json(&document)?))
}

/// The parser-event description of one value, before it becomes a
/// `serde_json::Value`.
///
/// It carries the two things the parser's event stream knows and a plain
/// `Yaml` tree does not: the *written style* of a scalar (plain vs quoted vs
/// block) and its *tag*.
#[derive(Clone, Debug)]
enum YamlNode {
    /// A quoted or block scalar: always a string, never re-typed.
    Str(String),
    /// A plain, untagged scalar, resolved by yaml-rust2's own resolver.
    Resolved(yaml_rust2::yaml::Yaml),
    /// A plain scalar carrying a tag yaml-rust2 does not special-case
    /// (`!!timestamp …`, `!Newtype 1`): the tag carries no configuration
    /// meaning, so it is dropped and the text kept as written.
    Tagged(Box<yaml_rust2::parser::Tag>, String),
    /// An explicitly tagged core scalar whose body does not match its tag
    /// (`!!int notanint`), or an alias naming no anchor. Both must be errors.
    Bad(String),
    /// A sequence, in written order.
    Seq(Vec<YamlNode>),
    /// A mapping, in written order.
    Map(YamlMap),
}

/// One mapping's entries, in written order.
type YamlMap = Vec<(YamlNode, YamlNode)>;

/// Convert the document into the JSON tree the TOML pipeline consumes.
///
/// Mapping keys are converted to their string representation when they are not
/// already strings (JSON and TOML keys are strings; YAML keys may be numbers,
/// booleans, null or collections).
///
/// # Errors
///
/// A merge key whose value is not a mapping (or a sequence of mappings) is
/// reported with the `YAML merge key (``<<``) error:` prefix, matching the
/// previous reader's `Value::apply_merge` failure. An unresolvable alias or a
/// tagged scalar that does not match its tag is reported as a parse error.
fn yaml_value_to_json(v: &YamlNode) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(match v {
        YamlNode::Str(s) => serde_json::Value::String(s.clone()),
        YamlNode::Resolved(scalar) => yaml_scalar_to_json(scalar),
        YamlNode::Tagged(tag, text) => {
            debug!("YAML tagged value in config (tag dropped): {tag:?}");
            serde_json::Value::String(text.clone())
        }
        YamlNode::Bad(reason) => return Err(format!("YAML parse error: {reason}").into()),
        YamlNode::Seq(items) => serde_json::Value::Array(
            items
                .iter()
                .map(yaml_value_to_json)
                .collect::<Result<_, _>>()?,
        ),
        YamlNode::Map(entries) => {
            let mut object = serde_json::Map::new();
            // The keys the mapping itself declares, in written order.
            for (key, value) in entries {
                if is_merge_key(key) {
                    continue;
                }
                let name = yaml_map_key(key)?;
                object.insert(name, yaml_value_to_json(value)?);
            }
            // `<<: *a` / `<<: [*a, *b]` — YAML 1.1 merge (yaml.org/type/merge),
            // which yaml-rust2 does not implement. An explicit key above wins
            // over every merge source, and for a sequence an earlier source wins
            // over a later one; inserting in written order and skipping a name
            // that is already present implements exactly that.
            for (key, value) in entries {
                if !is_merge_key(key) {
                    continue;
                }
                for source in yaml_merge_sources(value)? {
                    for (name, source_value) in source {
                        if object.contains_key(&name) {
                            continue;
                        }
                        object.insert(name, source_value);
                    }
                }
            }
            serde_json::Value::Object(object)
        }
    })
}

/// Whether a mapping key is the YAML 1.1 merge key `<<`.
///
/// Only the **plain** (or explicitly `!!merge`-tagged) form is the merge key:
/// a quoted `"<<"` is an ordinary key named `<<`, because YAML 1.1 gives the
/// merge type to the plain scalar only. That is why this matches
/// [`YamlNode::Resolved`] and not [`YamlNode::Str`].
fn is_merge_key(key: &YamlNode) -> bool {
    matches!(key, YamlNode::Resolved(yaml_rust2::yaml::Yaml::String(s)) if s == "<<")
}

/// The mappings one `<<` value contributes, in the order they were written.
///
/// Each source is resolved (its own merge keys applied) before it is returned,
/// so a merged mapping never leaks a `<<` key of its own.
///
/// # Errors
///
/// A non-mapping value (a scalar, or a sequence element that is not a mapping)
/// is a merge-key error rather than a silently ignored key.
fn yaml_merge_sources(
    value: &YamlNode,
) -> Result<Vec<serde_json::Map<String, serde_json::Value>>, Box<dyn std::error::Error>> {
    let items: Vec<&YamlNode> = match value {
        YamlNode::Seq(items) => items.iter().collect(),
        other => vec![other],
    };
    let mut resolved = Vec::with_capacity(items.len());
    for item in items {
        match yaml_value_to_json(item)? {
            serde_json::Value::Object(object) => resolved.push(object),
            _ => {
                return Err(merge_error(format!(
                    "value must be a mapping or a sequence of mappings, found {}",
                    yaml_node_kind(item)
                )));
            }
        }
    }
    Ok(resolved)
}

fn merge_error(reason: String) -> Box<dyn std::error::Error> {
    format!("YAML merge key (`<<`) error: {reason}").into()
}

/// A short description of a node, for error messages.
fn yaml_node_kind(node: &YamlNode) -> &'static str {
    match node {
        YamlNode::Str(_) | YamlNode::Resolved(_) | YamlNode::Tagged(_, _) => "a scalar",
        YamlNode::Bad(_) => "an unresolvable value",
        YamlNode::Seq(_) => "a sequence",
        YamlNode::Map(_) => "a mapping",
    }
}

/// Convert a resolved YAML scalar to JSON.
///
/// A **finite** real uses the JSON number Go's `json.Marshal` produces: an
/// integral value is emitted as an integer number, because Go renders an
/// integral `float64` without a fraction and so reads `7777.0` into an integer
/// field. A **non-finite** real (`inf`/`-inf`/`nan`, however spelled) has no
/// JSON representation, so it falls back to the canonical scalar text (`.inf`,
/// not `inf`); a typed numeric field then fails loudly instead of silently
/// reading null.
fn yaml_scalar_to_json(scalar: &yaml_rust2::yaml::Yaml) -> serde_json::Value {
    use yaml_rust2::yaml::Yaml;
    match scalar {
        Yaml::Null => serde_json::Value::Null,
        Yaml::Boolean(b) => serde_json::Value::Bool(*b),
        Yaml::Integer(i) => serde_json::Value::Number((*i).into()),
        Yaml::Real(text) => match parse_real(text) {
            Some(value) if value.is_finite() => match integral_json_number(value) {
                Some(number) => serde_json::Value::Number(number),
                None => serde_json::Number::from_f64(value).map_or_else(
                    || serde_json::Value::String(text.clone()),
                    serde_json::Value::Number,
                ),
            },
            _ => serde_json::Value::String(
                non_finite_spelling(text).map_or_else(|| text.clone(), str::to_string),
            ),
        },
        Yaml::String(s) => serde_json::Value::String(s.clone()),
        // `Alias`/`Array`/`Hash`/`BadValue` are handled (or refused) while
        // building the node tree, so reaching them here would be a bug; render
        // them rather than panic.
        other => serde_json::Value::String(format!("{other:?}")),
    }
}

/// Builds the document straight from the parser event stream.
///
/// Shaped after `yaml_rust2::yaml::YamlLoader`, but the written scalar style and
/// tag are kept (so plain `yes` can become a boolean while `"yes"` cannot), a
/// tagged scalar whose body does not match its tag is an error rather than a
/// dropped `BadValue`, duplicate keys are reported with their position, an empty
/// document is null, and more than one document is refused — the previous
/// `serde_yaml_ng` `from_str` refused it too.
/// One container (or a scalar parked at the document root) still being built.
///
/// `size` is the number of nodes the whole subtree holds; it is what an alias
/// that copies this node is charged for.
struct PendingNode {
    node: YamlNode,
    /// The anchor the parser assigned this node (0 for none).
    anchor: usize,
    /// The node count of `node`, including its children.
    size: usize,
}

#[derive(Default)]
struct YamlReceiver {
    docs: Vec<YamlNode>,
    doc_stack: Vec<PendingNode>,
    key_stack: Vec<Option<YamlNode>>,
    /// One set per open mapping: the rendered key names already written there,
    /// so a duplicate is found without rescanning every earlier entry.
    key_sets: Vec<std::collections::HashSet<String>>,
    anchors: std::collections::BTreeMap<usize, (YamlNode, usize)>,
    error: Option<yaml_rust2::scanner::ScanError>,
    /// Nodes built so far, charged against `alias_budget`.
    expanded_nodes: usize,
    /// The most nodes a document of this input length may expand to.
    alias_budget: usize,
}

impl yaml_rust2::parser::MarkedEventReceiver for YamlReceiver {
    fn on_event(&mut self, ev: yaml_rust2::parser::Event, mark: yaml_rust2::scanner::Marker) {
        if self.error.is_some() {
            return;
        }
        if let Err(e) = self.handle(ev, mark) {
            self.error = Some(e);
        }
    }
}

/// The error message for an insertion that pushed the node count past `budget`.
///
/// `is_alias` is passed by the caller, never inferred from the size of the
/// charge: an alias of a *scalar* is charged one node, exactly like a plain
/// scalar, so the charge cannot tell a scalar-alias bomb from a large but honest
/// document. The `Event::Alias` pre-clone check passes `true`; `insert` passes
/// `false` for every node it counts itself, because the alias path's own charge
/// can no longer trip the check there (its pre-check uses the same arithmetic).
fn over_budget_message(is_alias: bool, budget: usize) -> String {
    if is_alias {
        "alias expansion limit exceeded".to_string()
    } else {
        format!("document exceeds the node limit ({budget} nodes)")
    }
}

impl YamlReceiver {
    /// A receiver whose expansion budget is derived from the input size and then
    /// clamped to an absolute ceiling.
    ///
    /// **What the budget bounds is node count, not bytes.** It is what stops a
    /// node bomb — an alias re-expanded until the tree would hold hundreds of
    /// millions of nodes — including the padded form, where a tiny bomb is
    /// diluted with inert bytes to buy a huge proportional allowance. Measured
    /// through the real entry point: a 1 MiB file whose bomb would expand to
    /// ~100 million nodes is refused in 47 ms at 50.8 MB peak RSS instead of
    /// 5.42 s at 12.1 GB.
    ///
    /// It is **not** a memory bound. A node may carry a string as long as the
    /// input and an alias deep-copies the whole string, while the charge is one
    /// node per alias whatever the string's length — so a single large scalar
    /// anchor re-expanded a few thousand times stays far below `400_000` nodes
    /// and still costs gigabytes (measured 2.2–7.9 GB peak RSS on 125 KiB–1 MiB
    /// crafted inputs; the previous reader costs 1.3–4.0 GB and Go's own config
    /// path 8.4 GB on the same file). That residual is pre-existing, is not a
    /// Go-parity divergence, and is registered as debt in `TODO.md` rather than
    /// fixed here.
    ///
    /// The proportional part mirrors `yaml.v2`'s `allowedAliasRatio`
    /// (`max(100_000, input.len() * 100)`), but a ratio on its own buys an
    /// allowance for free: comments, blank lines, `%` directives and a
    /// legitimately large config are inert bytes that inflate it without adding
    /// a single node. The absolute ceiling is what keeps the node count bounded
    /// whatever the padding claims; `400_000` is the order of magnitude of Go's
    /// `alias_ratio_range_low`.
    fn new(input_len: usize) -> Self {
        Self {
            alias_budget: input_len.saturating_mul(100).clamp(100_000, 400_000),
            ..Self::default()
        }
    }

    fn finish(mut self, source: &str) -> Result<YamlNode, Box<dyn std::error::Error>> {
        if let Some(e) = self.error.take() {
            return Err(format!("YAML parse error: {e}").into());
        }
        match self.docs.len() {
            // `yaml-rust2` reports `...` on its own as a stream with no
            // document, exactly like genuinely empty input (`""`, comments).
            // Go frp and the previous reader reject `...`, so the two are
            // told apart here.
            0 if yaml_has_document_end_marker(source) => Err(
                "YAML parse error: did not find expected node content (a `...` marker \
                 ends a document that was never started)"
                    .into(),
            ),
            0 => Ok(YamlNode::Resolved(yaml_rust2::yaml::Yaml::Null)),
            1 => Ok(self.docs.pop().expect("exactly one document")),
            n => Err(format!(
                "YAML parse error: deserializing from YAML containing more than one \
                 document is not supported (found {n})"
            )
            .into()),
        }
    }

    fn handle(
        &mut self,
        ev: yaml_rust2::parser::Event,
        mark: yaml_rust2::scanner::Marker,
    ) -> Result<(), yaml_rust2::scanner::ScanError> {
        use yaml_rust2::parser::Event;
        match ev {
            Event::StreamStart | Event::StreamEnd | Event::Nothing => {}
            Event::DocumentStart => self.anchors.clear(),
            Event::DocumentEnd => {
                // An empty document (`""`, `# comment only`) is null, which is
                // what the previous reader returned.
                let document = match self.doc_stack.len() {
                    0 => YamlNode::Resolved(yaml_rust2::yaml::Yaml::Null),
                    1 => self.doc_stack.pop().expect("one document").node,
                    _ => unreachable!("the document stack holds at most one node"),
                };
                self.docs.push(document);
            }
            Event::SequenceStart(aid, tag) => {
                log_dropped_tag(&tag);
                self.doc_stack.push(PendingNode {
                    node: YamlNode::Seq(Vec::new()),
                    anchor: aid,
                    size: 1,
                });
            }
            Event::SequenceEnd => {
                let node = self.doc_stack.pop().expect("a sequence was started");
                self.insert(node.node, node.anchor, node.size, 1, mark)?;
            }
            Event::MappingStart(aid, tag) => {
                log_dropped_tag(&tag);
                self.doc_stack.push(PendingNode {
                    node: YamlNode::Map(Vec::new()),
                    anchor: aid,
                    size: 1,
                });
                self.key_stack.push(None);
                self.key_sets.push(std::collections::HashSet::new());
            }
            Event::MappingEnd => {
                self.key_stack.pop();
                self.key_sets.pop();
                let node = self.doc_stack.pop().expect("a mapping was started");
                self.insert(node.node, node.anchor, node.size, 1, mark)?;
            }
            Event::Scalar(text, style, aid, tag) => {
                let node = scalar_node(text, style, tag);
                self.insert(node, aid, 1, 1, mark)?;
            }
            Event::Alias(id) => {
                if let Some((node, size)) = self.anchors.get(&id) {
                    // Refuse **before** cloning. The clone is the blow-up, so the
                    // budget has to gate the copy rather than merely count it
                    // afterwards; `insert` re-checks for the non-alias paths.
                    // This is the only caller that reports an alias, whatever
                    // the charged size — a scalar alias charges 1.
                    if self.expanded_nodes.saturating_add(*size) > self.alias_budget {
                        return Err(yaml_rust2::scanner::ScanError::new_string(
                            mark,
                            over_budget_message(true, self.alias_budget),
                        ));
                    }
                    let (node, size) = (node.clone(), *size);
                    self.insert(node, 0, size, size, mark)?;
                } else {
                    // An alias the parser could not resolve is an error, never a
                    // silently dropped node. The message mirrors the previous
                    // reader's `unknown anchor` wording without leaking
                    // yaml-rust2's internal anchor id.
                    self.insert(
                        YamlNode::Bad(
                            "unknown anchor: this alias has no matching anchor in the document"
                                .to_string(),
                        ),
                        0,
                        1,
                        1,
                        mark,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Add a node to the tree being built.
    ///
    /// `size` is the node count of `node`; `contribution` is how many *new* nodes
    /// this insertion adds — 1 for a container whose children were already
    /// counted, `size` for an alias that copies a whole subtree. An alias is
    /// charged for every node it duplicates, so an exponentially expanding
    /// document is refused as soon as the total passes `alias_budget`.
    ///
    /// Every failure here is a plain node past the ceiling, so the message says
    /// so: the alias path pre-checks the same arithmetic before it clones, and
    /// therefore never reaches this check.
    #[allow(clippy::too_many_arguments)] // (node, anchor, size, contribution, mark)
    fn insert(
        &mut self,
        node: YamlNode,
        aid: usize,
        size: usize,
        contribution: usize,
        mark: yaml_rust2::scanner::Marker,
    ) -> Result<(), yaml_rust2::scanner::ScanError> {
        self.expanded_nodes += contribution;
        if self.expanded_nodes > self.alias_budget {
            return Err(yaml_rust2::scanner::ScanError::new_string(
                mark,
                over_budget_message(false, self.alias_budget),
            ));
        }
        // Valid anchor ids start at 1, as in `YamlLoader`.
        if aid > 0 {
            self.anchors.insert(aid, (node.clone(), size));
        }
        if self.doc_stack.is_empty() {
            self.doc_stack.push(PendingNode {
                node,
                anchor: aid,
                size,
            });
            return Ok(());
        }
        let top_is_map = matches!(
            self.doc_stack.last().map(|pending| &pending.node),
            Some(YamlNode::Map(_))
        );
        if top_is_map {
            let slot = self.key_stack.last_mut().expect("a mapping key slot");
            if let Some(key) = slot.take() {
                // Duplicate detection is on the key's rendered string, the same
                // form the JSON/TOML conversion uses, so `a:` twice and `1:` next
                // to `"1":` are both refused rather than one silently winning.
                let name = yaml_key_to_string(&key);
                let fresh = self
                    .key_sets
                    .last_mut()
                    .expect("an open mapping")
                    .insert(name.clone());
                if !fresh {
                    return Err(yaml_rust2::scanner::ScanError::new_string(
                        mark,
                        format!("duplicate entry with key {name:?}"),
                    ));
                }
                match &mut self.doc_stack.last_mut().expect("a container").node {
                    YamlNode::Map(entries) => entries.push((key, node)),
                    _ => unreachable!("only a sequence or a mapping can be a container"),
                }
            } else {
                *slot = Some(node);
            }
        } else {
            match &mut self.doc_stack.last_mut().expect("a container").node {
                YamlNode::Seq(items) => items.push(node),
                _ => unreachable!("only a sequence or a mapping can be a container"),
            }
        }
        self.doc_stack.last_mut().expect("a container").size += size;
        Ok(())
    }
}

/// Resolve one scalar event into a node.
///
/// The **tag** decides first, whatever the written style: `!!str 017` is the
/// string `017` while `!!int "017"` is 15, which is what Go does too. The core
/// tags are resolved here rather than by the loader, because the loader turns a
/// body it cannot resolve into a `BadValue`, silently losing the field, while
/// this makes it an error.
///
/// * A **plain, untagged** scalar is resolved by [`yaml_plain_scalar`] — Go
///   frp's own rules, including the YAML 1.1 booleans.
/// * A **quoted or block**, untagged scalar is always the string that was
///   written; it is never re-typed and never boolean-coerced.
/// * A **tagged** scalar is resolved by its tag. A body that does not match the
///   tag becomes [`YamlNode::Bad`] — a hard error — rather than being dropped.
fn scalar_node(
    text: String,
    style: yaml_rust2::scanner::TScalarStyle,
    tag: Option<yaml_rust2::parser::Tag>,
) -> YamlNode {
    use yaml_rust2::scanner::TScalarStyle;
    use yaml_rust2::yaml::Yaml;
    let Some(tag) = tag else {
        return if style == TScalarStyle::Plain {
            yaml_plain_scalar(&text)
        } else {
            YamlNode::Str(text)
        };
    };
    if tag.handle != "tag:yaml.org,2002:" {
        return YamlNode::Tagged(Box::new(tag), text);
    }
    match tag.suffix.as_str() {
        "str" => YamlNode::Str(text),
        "null" => {
            if yaml_plain_scalar_is_null(&text) {
                YamlNode::Resolved(Yaml::Null)
            } else {
                tag_mismatch(&text, &tag.suffix)
            }
        }
        "bool" => yaml_plain_scalar_bool(&text).map_or_else(
            || tag_mismatch(&text, &tag.suffix),
            |value| YamlNode::Resolved(Yaml::Boolean(value)),
        ),
        "int" => yaml_go_int(&text).map_or_else(
            || tag_mismatch(&text, &tag.suffix),
            |value| YamlNode::Resolved(Yaml::Integer(value)),
        ),
        "float" => yaml_tagged_float(&text).unwrap_or_else(|| tag_mismatch(&text, &tag.suffix)),
        // `!!merge <<` is the merge key written explicitly; it becomes the same
        // node as a plain `<<` so that [`is_merge_key`] recognises it.
        "merge" if text == "<<" => YamlNode::Resolved(Yaml::String("<<".to_string())),
        // The remaining core tags — `!!binary`, `!!timestamp`, `!!omap`, … —
        // keep the scalar text as written, as the previous reader did. (Go
        // decodes `!!binary`; that difference is registered.)
        _ => YamlNode::Str(text),
    }
}

/// The error for a tagged scalar whose body does not resolve as its tag.
///
/// The body is shown with `{:?}` so a control character stays readable, and the
/// tag is named without Rust's `Tag` debug form.
fn tag_mismatch(text: &str, suffix: &str) -> YamlNode {
    YamlNode::Bad(format!(
        "scalar {text:?} does not match its `!!{suffix}` tag"
    ))
}

/// A `!!float`-tagged body: the spelled non-finites keep the canonical text (Go
/// cannot marshal them, and the previous reader produced `.inf`), an integer body
/// is converted the way Go's `!!float` does (`!!float 0x10` is 16), and only then
/// is a YAML-style real accepted.
///
/// The order matters: Go's `resolve` runs `ParseInt(plain, 0, 64)` before its
/// float shape, so `!!float 017` is the legacy-octal `15` and `!!float 010` is
/// `8`, not `17`/`10`.
fn yaml_tagged_float(text: &str) -> Option<YamlNode> {
    if let Some(canonical) = non_finite_spelling(text) {
        return Some(YamlNode::Str(canonical.to_string()));
    }
    // `!!float _100` is an error in Go: the `_` first byte never enters the
    // numeric branch, so the tag cannot be satisfied. Without this gate the
    // underscore stripping below would accept it as 100.
    if !yaml_may_be_numeric(text) {
        return None;
    }
    if let Some(value) = yaml_go_int(text) {
        return Some(YamlNode::Resolved(yaml_rust2::yaml::Yaml::Integer(value)));
    }
    let plain = strip_underscores(text);
    if yaml_style_float(&plain) {
        return Some(YamlNode::Resolved(yaml_rust2::yaml::Yaml::Real(plain)));
    }
    None
}

fn log_dropped_tag(tag: &Option<yaml_rust2::parser::Tag>) {
    if let Some(tag) = tag {
        debug!("YAML tagged value in config (tag dropped): {tag:?}");
    }
}

/// Parse a YAML real scalar the way yaml-rust2 does (the `.inf`/`.nan`
/// spellings, then anything containing a digit that `f64` accepts).
fn parse_real(text: &str) -> Option<f64> {
    match text {
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => Some(f64::INFINITY),
        "-.inf" | "-.Inf" | "-.INF" => Some(f64::NEG_INFINITY),
        ".nan" | ".NaN" | ".NAN" => Some(f64::NAN),
        _ if text.bytes().any(|b| b.is_ascii_digit()) => text.parse::<f64>().ok(),
        _ => None,
    }
}

/// The YAML 1.1 boolean spellings Go frp's YAML library resolves.
///
/// Table-driven on purpose: this is the single place the set may change, and it
/// has a unit test per spelling, because the Go-parity investigation may still
/// refine it. Only **untagged plain** scalars consult it — quoted, block and
/// tagged scalars return before it ([`scalar_node`]).
fn yaml_plain_scalar_bool(text: &str) -> Option<bool> {
    const TRUE: &[&str] = &[
        "y", "Y", "yes", "Yes", "YES", "true", "True", "TRUE", "on", "On", "ON",
    ];
    const FALSE: &[&str] = &[
        "n", "N", "no", "No", "NO", "false", "False", "FALSE", "off", "Off", "OFF",
    ];
    if TRUE.contains(&text) {
        Some(true)
    } else if FALSE.contains(&text) {
        Some(false)
    } else {
        None
    }
}

/// Resolve one plain, untagged scalar exactly as Go frp's YAML reader does.
///
/// Go frp embeds `gopkg.in/yaml.v2` v2.4.0 (measured with `go version -m` on
/// the v0.71.0 release binary), whose `resolve` decides what a plain scalar
/// means. In order:
///
/// 1. the exact, case-sensitive YAML 1.1 boolean table
///    ([`yaml_plain_scalar_bool`]) — `yes` is `true`, `nO` is a string;
/// 2. the null table: ``, `~`, `null`, `Null`, `NULL`;
/// 3. a base-0 integer with the `_` separators removed
///    (`strconv.ParseInt(plain, 0, 64)`): decimal, `0x`/`0X`, `0o`/`0O`,
///    `0b`/`0B`, and the legacy leading-zero **octal** form, so `017` is 15;
/// 4. the spelled non-finites (`.inf`, `-.Inf`, `.NaN`, …), kept as their
///    canonical *text* because Go cannot marshal them to JSON at all and the
///    previous reader produced `.inf`/`-.inf`/`.nan` too;
/// 5. Go's float shape (`^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$`)
///    — where an overflow such as `1e1000` stays the string Go keeps, because
///    Go's `ParseFloat` *fails* on it while Rust's returns infinity;
/// 6. otherwise the string itself.
///
/// This is the one place the scalar rules live, for values and for mapping keys
/// alike (Go resolves keys the same way). Unit tests: `mod
/// yaml_scalar_rule_tests`.
fn yaml_plain_scalar(text: &str) -> YamlNode {
    use yaml_rust2::yaml::Yaml;
    if let Some(value) = yaml_plain_scalar_bool(text) {
        return YamlNode::Resolved(Yaml::Boolean(value));
    }
    if yaml_plain_scalar_is_null(text) {
        return YamlNode::Resolved(Yaml::Null);
    }
    if !yaml_may_be_numeric(text) {
        return YamlNode::Resolved(Yaml::String(text.to_string()));
    }
    if let Some(value) = yaml_go_int(text) {
        return YamlNode::Resolved(Yaml::Integer(value));
    }
    if let Some(canonical) = non_finite_spelling(text) {
        return YamlNode::Str(canonical.to_string());
    }
    let plain = strip_underscores(text);
    if yaml_style_float(&plain) {
        if let Ok(value) = plain.parse::<f64>() {
            if value.is_finite() {
                return YamlNode::Resolved(Yaml::Real(plain));
            }
        }
    }
    YamlNode::Resolved(Yaml::String(text.to_string()))
}

/// Whether Go's resolver would even consider `text` numeric.
///
/// Go looks up `resolveTable[in[0]]` and only enters the int/float/timestamp
/// branch for a sign (`S`), a dot (`.`) or a digit (`D`); every other first byte
/// (`_`, a letter, a space) leaves the scalar a string. This must gate the
/// **whole** numeric path, not just the integer attempt: `_100` would otherwise
/// fail [`yaml_go_int`] and still be retyped as the float `100`.
fn yaml_may_be_numeric(text: &str) -> bool {
    matches!(
        text.as_bytes().first(),
        Some(b'+' | b'-' | b'.' | b'0'..=b'9')
    )
}

/// The null spellings Go's resolver accepts: ``, `~`, `null`, `Null`, `NULL`.
fn yaml_plain_scalar_is_null(text: &str) -> bool {
    matches!(text, "" | "~" | "null" | "Null" | "NULL")
}

/// Go's integer rule: `strconv.ParseInt` with base 0, after removing every `_`.
///
/// `None` when Go would not read the text as an integer — including a
/// leading-zero body that is not valid octal (`008`), which Go resolves as a
/// float instead.
///
/// The first byte is gated **before** the underscores are stripped, because Go's
/// `resolve` decides with `resolveTable[in[0]]` and `'_'` maps to 0: `_100` is a
/// string there, while stripping first would make it the integer 100.
fn yaml_go_int(text: &str) -> Option<i64> {
    if !matches!(text.as_bytes().first(), Some(b'+' | b'-' | b'0'..=b'9')) {
        return None;
    }
    let plain = strip_underscores(text);
    let (negative, digits) = match plain.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, plain.strip_prefix('+').unwrap_or(&plain)),
    };
    let (radix, body) = if let Some(rest) = strip_any(digits, &["0x", "0X"]) {
        (16, rest)
    } else if let Some(rest) = strip_any(digits, &["0o", "0O"]) {
        (8, rest)
    } else if let Some(rest) = strip_any(digits, &["0b", "0B"]) {
        (2, rest)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    let magnitude = u64::from_str_radix(body, radix).ok()?;
    if negative {
        // `-9223372036854775808` is representable even though its magnitude is
        // one past `i64::MAX`.
        (magnitude <= i64::MIN.unsigned_abs()).then(|| (magnitude as i64).wrapping_neg())
    } else {
        (magnitude <= i64::MAX as u64).then_some(magnitude as i64)
    }
}

/// `text` without its `_` separators (Go removes them before parsing a number).
fn strip_underscores(text: &str) -> String {
    text.chars().filter(|c| *c != '_').collect()
}

/// The first prefix in `prefixes` that `text` starts with.
fn strip_any<'a>(text: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    prefixes.iter().find_map(|prefix| text.strip_prefix(prefix))
}

/// Whether `text` has the shape Go's resolver accepts as a float:
/// `^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$`.
fn yaml_style_float(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        index += 1;
    }
    let integer_digits = count_digits(bytes, &mut index);
    let mut fraction_digits = 0;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        fraction_digits = count_digits(bytes, &mut index);
    }
    if integer_digits == 0 && fraction_digits == 0 {
        return false;
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        if count_digits(bytes, &mut index) == 0 {
            return false;
        }
    }
    index == bytes.len()
}

/// Consume the ASCII digits at `*index`, returning how many there were.
fn count_digits(bytes: &[u8], index: &mut usize) -> usize {
    let start = *index;
    while bytes.get(*index).is_some_and(u8::is_ascii_digit) {
        *index += 1;
    }
    *index - start
}

/// The canonical text of a spelled non-finite real (`.inf`, `-.inf`, `.nan`).
///
/// It is kept as text rather than an `f64` because JSON has no non-finite
/// number: Go fails to marshal it, and the previous reader produced exactly
/// these strings (`.inf`, not `inf`), which makes a typed numeric field fail
/// loudly instead of silently reading null. `-.nan`/`+.nan` are not among the
/// spellings either reader resolves, so they stay as written.
fn non_finite_spelling(text: &str) -> Option<&'static str> {
    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if unsigned.eq_ignore_ascii_case(".inf") {
        return Some(if negative { "-.inf" } else { ".inf" });
    }
    if !negative && !text.starts_with('+') && unsigned.eq_ignore_ascii_case(".nan") {
        return Some(".nan");
    }
    None
}

/// A finite real that is an integer becomes an integer JSON number.
///
/// Go resolves `7777.0` to a `float64` and `json.Marshal` renders an integral
/// float without a fraction, so an integer field accepts it (`serverPort:
/// 7777.0` is 7777 there) while the previous reader rejected it. A value outside
/// `i64` stays a float and still fails an integer field, as it does in Go.
fn integral_json_number(value: f64) -> Option<serde_json::Number> {
    /// 2^63, the exclusive upper bound of `i64` as an `f64`.
    const I64_LIMIT: f64 = 9_223_372_036_854_775_808.0;
    if value.fract() != 0.0 || !(-I64_LIMIT..I64_LIMIT).contains(&value) {
        return None;
    }
    Some(serde_json::Number::from(value as i64))
}

/// The position of the first tab used for indentation, if any.
///
/// Go frp (and the previous reader) reject a tab where indentation is required:
/// a line whose leading whitespace contains a tab (`\ta: 1`), a block sequence
/// entry indented with a tab (`- \ta: 1`), and the first content line of a block
/// scalar (`k: |` then `  \tfoo`). `yaml-rust2` accepts several of these, which
/// would silently read `\ta: 1` as the mapping `{a: 1}`, so they are rejected
/// here instead.
///
/// A tab is *not* an indentation error as separation inside a line (`a: \t1`),
/// inside a flow collection (`[\t1]`, or a continued flow line, where there is
/// no indentation), or after a block scalar's indentation has been established
/// (`|`, then `  a`, then `  \tb`) — Go accepts all of those. The check is
/// deliberately conservative: it may miss a case, but it must not reject one Go
/// accepts.
fn yaml_indentation_tab(content: &str) -> Option<(usize, usize)> {
    // The previous line left a flow collection open (it ended with `[`, `{` or
    // a continuation comma), so the next line continues it and carries no
    // indentation of its own.
    let mut in_flow = false;
    // Inside a block scalar: the indentation of its `|`/`>` header, and whether
    // a content line has established that indentation yet.
    let mut block_scalar: Option<(usize, bool)> = None;
    for (index, line) in content.lines().enumerate() {
        let number = index + 1;
        let indentation = line.len() - line.trim_start_matches([' ', '\t']).len();
        let whitespace = &line[..indentation];
        let body = &line[indentation..];
        if let Some((header_indent, established)) = block_scalar {
            if body.is_empty() {
                continue; // A blank line stays inside the block scalar.
            }
            if indentation > header_indent {
                if !established {
                    if let Some(column) = tab_position(whitespace) {
                        return Some((number, column));
                    }
                    block_scalar = Some((header_indent, true));
                }
                continue; // Content is verbatim; a later tab is not indentation.
            }
            block_scalar = None; // The scalar ended; check this line normally.
        }
        if !in_flow {
            if let Some(column) = tab_position(whitespace) {
                return Some((number, column));
            }
            if let Some(rest) = body.strip_prefix('-') {
                let rest = rest.trim_start_matches([' ', '\t']);
                let separation = &body[1..body.len() - rest.len()];
                if let Some(offset) = separation.find('\t') {
                    return Some((number, 2 + offset));
                }
            }
        }
        let content = strip_comment(body).trim_end();
        in_flow = content.ends_with([',', '[', '{']);
        if block_scalar_header(content) {
            block_scalar = Some((indentation, false));
        }
    }
    None
}

/// The 1-based column of the first tab in an indentation run.
fn tab_position(whitespace: &str) -> Option<usize> {
    whitespace.find('\t').map(|offset| offset + 1)
}

/// `body` without a trailing `#` comment (a comment needs leading whitespace).
fn strip_comment(body: &str) -> &str {
    let bytes = body.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'#' && (index == 0 || bytes[index - 1].is_ascii_whitespace()) {
            return &body[..index];
        }
    }
    body
}

/// Whether a line's content opens a block scalar (`|` or `>`, with the optional
/// indentation and chomping modifiers).
///
/// The indicator has to sit in a node position — at the start of the content, or
/// after the `:` of a mapping value or the `-` of a sequence entry — so that a
/// plain scalar which merely ends in `>` (`x: a>`) is not mistaken for a header.
fn block_scalar_header(content: &str) -> bool {
    let bytes = content.as_bytes();
    let mut end = bytes.len();
    let mut modifiers = 0;
    while end > 0 && matches!(bytes[end - 1], b'-' | b'+' | b'0'..=b'9') {
        end -= 1;
        modifiers += 1;
        if modifiers > 2 {
            return false;
        }
    }
    if end == 0 || !matches!(bytes[end - 1], b'|' | b'>') {
        return false;
    }
    let prefix = content[..end - 1].trim_end();
    prefix.is_empty() || prefix.ends_with([':', '-'])
}

/// Whether the source contains a `...` document-end marker.
///
/// `yaml-rust2` cannot tell `...` from empty input in its event stream, but Go
/// frp and the previous reader reject `...` when no document was started, so the
/// text is consulted for that one case.
fn yaml_has_document_end_marker(content: &str) -> bool {
    content.lines().any(|line| {
        line.trim_start()
            .strip_prefix("...")
            .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '\t']))
    })
}

/// The string a mapping key contributes to the JSON/TOML object.
///
/// JSON and TOML keys are strings while YAML keys may be any scalar (or a
/// collection): `1`, `1.5`, `true` and `null` therefore become `"1"`, `"1.5"`,
/// `"true"` and `""`, and a complex key falls back to a debug representation
/// rather than panicking.
fn yaml_key_to_string(key: &YamlNode) -> String {
    match key {
        YamlNode::Str(s) => s.clone(),
        YamlNode::Resolved(scalar) => yaml_scalar_key_text(scalar),
        YamlNode::Tagged(_, text) => text.clone(),
        YamlNode::Bad(reason) => reason.clone(),
        YamlNode::Seq(_) | YamlNode::Map(_) => format!("{key:?}"),
    }
}

/// [`yaml_key_to_string`] for the conversion path, where an unresolvable key is
/// an error rather than a rendered name.
fn yaml_map_key(key: &YamlNode) -> Result<String, Box<dyn std::error::Error>> {
    match key {
        YamlNode::Bad(reason) => Err(format!("YAML parse error: {reason}").into()),
        other => Ok(yaml_key_to_string(other)),
    }
}

/// The text a resolved scalar contributes as a mapping key: strings verbatim,
/// numbers the way `serde_json::Number` renders them (`1e1` → `10.0`, `1.50` →
/// `1.5`, `1E3` → `1000.0`, matching the previous reader), booleans as
/// `true`/`false`, null as the empty string.
fn yaml_scalar_key_text(scalar: &yaml_rust2::yaml::Yaml) -> String {
    use yaml_rust2::yaml::Yaml;
    match scalar {
        Yaml::String(s) => s.clone(),
        Yaml::Integer(i) => i.to_string(),
        Yaml::Real(text) => match parse_real(text).and_then(serde_json::Number::from_f64) {
            Some(number) => number.to_string(),
            // A spelled non-finite (`-.inf`) keeps its canonical text;
            // `serde_json` cannot render a number for it.
            None => non_finite_spelling(text).map_or_else(|| text.clone(), str::to_string),
        },
        Yaml::Boolean(b) => b.to_string(),
        Yaml::Null => String::new(),
        other => format!("{other:?}"),
    }
}

// ─── INI parser (Go Viper-compatible type inference) ─────────────────

/// Parse INI content into a toml::Value.
///
/// Unlike Go's legacy INI loader (`gopkg.in/ini.v1`, which hands every value
/// to the target field as text and lets the *field's* Go type decide), this
/// reader infers a TOML type. The inference is **lossless**: a value only
/// becomes a TOML integer/float/boolean/array when rendering that value back
/// produces exactly the text the file wrote (`ini_value_text`). `007`, `1.50`,
/// `YES` and `a, b` therefore stay strings here — the type decision moves to
/// the target field, made by `super::ini_lenient` for `.ini` configs.
fn ini_to_toml(content: &str) -> Result<toml::Value, Box<dyn std::error::Error>> {
    let mut root = toml::Table::new();
    // Sections are collected **verbatim** first and expanded/inserted afterwards,
    // because whether a dotted header is a v1 nested table or a legacy proxy
    // section that merely *looks* like one cannot be decided from the header
    // alone: the legacy dialect's discriminator is the section's own `type` key,
    // which is only known once the whole section has been read. Deciding from
    // the header (the first cut of this change) turned `[auth.foo]`,
    // `[store.frontend]` and `[log.svc]` — proxy names that happen to start with
    // a v1 section name — into nested tables, so those proxies silently vanished
    // (measured on the real binaries: base and Go v0.71.0 register them,
    // `proxy added: [auth.foo]`; the frozen tree registered `<none>`).
    let mut sections: Vec<(String, toml::Table)> = Vec::new();
    let mut current: Option<usize> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Section header: [section]
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim().to_string();
            // A repeated header keeps its first position and merges into the
            // same table, which is what the old `entry(..).or_insert_with(..)`
            // did at header time.
            let index = match sections.iter().position(|(name, _)| *name == section) {
                Some(index) => index,
                None => {
                    sections.push((section, toml::Table::new()));
                    sections.len() - 1
                }
            };
            current = Some(index);
            continue;
        }

        // Key = value
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value_str = line[eq_pos + 1..].trim();

            if key.is_empty() {
                continue;
            }

            let parsed_value = ini_value_for_key(value_str, &key, current, &sections);

            match current {
                Some(index) => {
                    sections[index].1.insert(key, parsed_value);
                }
                None => {
                    root.insert(key, parsed_value);
                }
            }
        }
    }

    // Go's legacy detector is a whole-file `GetSection("common")`
    // (`DetectLegacyINIFormat`, pkg/config/load.go:65), so the dialect is known
    // before any section is inserted, whatever the order of the headers.
    let legacy_ini = sections.iter().any(|(name, _)| name == "common");
    for (name, table) in sections {
        insert_ini_section(&mut root, &name, table, legacy_ini)?;
    }

    Ok(toml::Value::Table(root))
}

/// The v1 section names whose dotted `.ini` headers become nested tables.
///
/// Both spellings of the sections `normalize_*_config` knows, because the
/// `webServer` → `web_server` (and `httpPlugins` → `http_plugins`,
/// `featureGates` → `feature`) renames happen *after* the INI reader.
///
/// A header that is **not** in this set keeps its whole text as its key, which
/// is what the legacy dialect needs (`plugin.user-manager`, `web01`,
/// `my.proxy`), and so does a header in the set that carries a `type` key — see
/// [`ini_section_path`].
///
/// The v1 **array** roots are deliberately absent. `proxies`, `visitors` and
/// `http_plugins` are `Vec`s in the v1 schema, and an INI header cannot nest
/// into an array: expanding `[visitors.foo]` built
/// `visitors = { foo = { … } }`, a map where the deserializer wants a
/// sequence, so the file was refused with `invalid type: map, expected a
/// sequence` in *both* loader modes where Go v0.71.0 accepts it (measured:
/// `frpc verify` on `[visitors.foo] server_name = s` and on a port-carrying
/// `[proxies.foo]`, and `frps verify` on a portless `[http_plugins.foo]`, are
/// rc 0 on Go under both `--strict-config` values). Go's legacy loader does not
/// expand at all (`gopkg.in/ini.v1` has no dotted-path notion): the section is
/// named literally `visitors.foo` there. It is listed as a *known section* for
/// the client by `collect_legacy_ini_proxy_sections`, which reads it as the
/// legacy proxy section its header names — `visitors`/`proxies` are therefore
/// in that function's array-root list. `http_plugins`/`httpPlugins` are kept
/// here: the server has no collector, so un-nesting the header would only move
/// the failure from a type error to `unknown field "http_plugins.foo"` without
/// reaching Go (recorded as a residual, `TODO.md`).
const INI_NESTED_SECTION_ROOTS: &[&str] = &[
    "common",
    "web_server",
    "webServer",
    "auth",
    "transport",
    "log",
    "http_plugins",
    "httpPlugins",
    "feature",
    "featureGates",
    "ssh_tunnel_gateway",
    "sshTunnelGateway",
    "observability",
    "vnet",
    "store",
];

/// The nesting path of one collected INI section, or `None` to keep its header
/// verbatim as the key.
///
/// A section is held back when:
///
/// * **A `type` key, or a proxy port key, makes the section a legacy proxy.** In
///   the legacy INI dialect every section other than `[common]` is a proxy whose
///   name is a flat, user-chosen identifier, and
///   `collect_legacy_ini_proxy_sections` decides membership by the presence of
///   `type` — or, in the `.ini` dialect, by the section carrying
///   `local_port`/`remote_port` and not declaring `role = "visitor"` — so
///   `[auth.foo]` with `type = tcp` is a proxy *named*
///   `auth.foo`, not the `foo` child of an `auth` table. Go does
///   the same: its legacy loader looks sections up by their raw name
///   (`pkg/config/legacy/server.go`, `section.Name()`), so `[auth.foo]` is one
///   section there too. Expanding it dropped the proxy in both loader modes; the
///   guard keeps it. (The cost, documented in `docs/config.md`: a v1 nested
///   table that itself carries `type` — an `[auth.plugin]`-style table in an
///   `.ini` — does not expand either, which is also what the base tree did. It is
///   then read as any other flat section: on the **client** the legacy collector
///   takes it for a proxy named after the header and proxy validation refuses it
///   (measured: `[auth.plugin] type = "https2http"` → rc 1, `proxy
///   'auth.plugin': invalid proxy_type 'https2http'`), on the **server** it is
///   an unknown strict-mode field.)
///
///   The same holds for a section that carries `local_port` or `remote_port` but
///   no `type`: Go's legacy loader defaults the missing proxy type to `tcp`
///   (measured on the real v0.71.0 binaries: an `.ini` `[myproxy]` with only
///   `local_port`/`remote_port` gives `frpc verify` rc 0, a real frps run logs
///   `new proxy [myproxy] type [tcp] success` and a real frpc run logs
///   `[myproxy] start proxy success`), so `[auth.foo]` with ports is a
///   proxy *named* `auth.foo`, not the `auth.foo` v1 child table. No v1 nested
///   sub-table in either schema carries `local_port`/`remote_port`, so those keys
///   discriminate without affecting the `[auth.oidc]` / `[webServer.tls]`
///   nesting. Without this guard the section stayed nested under `auth`, which
///   `collect_legacy_ini_proxy_sections` skips as a known section, and the proxy
///   was dropped (`frpc verify` rc 0 with `Proxies: 0`).
///
///   The collector reads the same two keys, which is why a `type`-less,
///   port-less `.ini` section is **not** a proxy there (Go's legacy loader would
///   make it a port-0 `tcp` proxy named after the header; measured `frpc verify`
///   on `[myproxy] custom_domains = a.com`: non-strict rc 0 `Proxies: 0`, strict
///   rc 1 `unknown field "myproxy"`).
/// * **A non-v1 first segment, quoting, or an empty path segment** keeps the
///   header verbatim, so `[plugin.user-manager]` stays the flat key its
///   `starts_with("plugin.")` handling reads.
fn ini_section_path(section: &str, table: &toml::Table) -> Option<Vec<String>> {
    if table.contains_key("type") {
        return None;
    }
    if table.contains_key("local_port") || table.contains_key("remote_port") {
        return None;
    }
    if !section.contains('.') || section.contains('"') || section.contains('\'') {
        return None;
    }
    let parts: Vec<String> = section.split('.').map(|p| p.trim().to_string()).collect();
    if parts.iter().any(String::is_empty) {
        return None;
    }
    if !INI_NESTED_SECTION_ROOTS.contains(&parts[0].as_str()) {
        return None;
    }
    Some(parts)
}

/// Insert one collected section into the root value, either under its verbatim
/// header text or under the nesting path [`ini_section_path`] returned.
///
/// A path that runs into a value which is not a table is a conflict, and whether
/// it is **reported** depends on the order the sections appear in:
///
/// * `[webServer] tls = 1` **before** `[webServer.tls]` — the expansion walks into
///   the scalar and errors (`section [webServer.tls] conflicts with the value
///   already set at \`webServer.tls\``, both loader modes, rc 1);
/// * the reverse order — the expansion builds the table first and the later
///   verbatim `[webServer]` section *merges* its keys into it, so `tls = 1`
///   overwrites the table and the nested values are dropped with the file loading
///   rc 0 and `tls_cert() == ""` (measured, both modes).
///
/// Both orders are pinned by
/// `dotted_ini_section_headers_become_nested_tables_in_both_modes`; the asymmetry
/// is a property of "later key wins" in the verbatim path, not of the conflict
/// check.
///
/// A **verbatim** name that collides with an already-present *non-table* value
/// (a root scalar, e.g. `includes = 1` next to an `[includes]` section) keeps
/// the **section** — but only in the legacy dialect, i.e. a `.ini` that has a
/// `[common]` section. Go keeps the two namespaces apart there — a `[name]`
/// section and a DefaultSection key `name = …` are independent in
/// `gopkg.in/ini.v1`, and the legacy reader ignores every DefaultSection key
/// (`LoadAllProxyConfsFromIni` skips `ini.DefaultSection`,
/// `pkg/config/legacy/client.go:255-257`) — so the section's keys (which the
/// collector reads) must survive the collision. On the **v1** path a
/// `[common]`-less `.ini` is decoded into one Go struct, so the same collision
/// is a type error Go reports (`json: cannot unmarshal string into Go value of
/// type v1.rawClientConfig`) and the scalar has to be kept: measured rc 1 in
/// both loader modes on Go v0.71.0, the parent and this tree, where
/// `webServer = 1` precedes `[webServer] tls_cert_file = "x"`.
fn insert_ini_section(
    root: &mut toml::Table,
    section: &str,
    table: toml::Table,
    legacy_ini: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = ini_section_path(section, &table) else {
        let slot = root
            .entry(section.to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        // Only the legacy dialect lets the section win (see the doc comment
        // above): on the v1 path the colliding scalar is what Go decodes, so it
        // survives and fails the v1 type check.
        if legacy_ini && slot.as_table().is_none() {
            *slot = toml::Value::Table(toml::Table::new());
        }
        if let Some(dst) = slot.as_table_mut() {
            for (key, value) in table {
                dst.insert(key, value);
            }
        }
        return Ok(());
    };
    let mut cur = root;
    for (depth, part) in path.iter().enumerate() {
        let slot = cur
            .entry(part.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        cur = slot.as_table_mut().ok_or_else(|| {
            let joined = path[..=depth].join(".");
            format!("section [{joined}] conflicts with the value already set at `{joined}`")
        })?;
    }
    for (key, value) in table {
        cur.insert(key, value);
    }
    Ok(())
}

/// The value a `key = value` line contributes, applying Go's legacy-`start`
/// text model to the one `[common] start` key.
///
/// `gopkg.in/ini.v1` never parses a value into a list: Go fills the legacy
/// `Start []string` (`pkg/config/legacy/client.go:119`) through
/// `Key.Strings(",")`, which splits the **raw value text** (key.go:492), so the
/// field sees the text the file wrote. Everything `infer_ini_value` produces
/// renders back to exactly that text (`ini_value_text`) except a `[a, b]`
/// bracket literal, which is parsed into an `Array`; for this one key that loss
/// decides which sections Go dispatches, so the literal is handed back as text.
/// Measured on Go v0.71.0: `[common] start = ["start"]` next to a `[start]`
/// section registers no proxy (`startProxy` is the single piece `["start"]`),
/// while a bare `start = p1,p2` selects both sections.
fn ini_value_for_key(
    value_str: &str,
    key: &str,
    current: Option<usize>,
    sections: &[(String, toml::Table)],
) -> toml::Value {
    let parsed_value = infer_ini_value(value_str);
    let common_start = key == "start"
        && matches!(parsed_value, toml::Value::Array(_))
        && !round_trips(&parsed_value, value_str)
        && current.is_some_and(|index| {
            sections
                .get(index)
                .is_some_and(|(name, _)| name == "common")
        });
    if common_start {
        return toml::Value::String(value_str.to_string());
    }
    parsed_value
}

/// Deepest legitimate nesting for infer_ini_value (array literal inside a
/// comma element), ~2 levels. The recursion cap keeps a hostile
/// `[`×k + "x" + `]`×k value from overflowing the stack — each frame
/// trims, lowercases, and re-checks, so 30k brackets SIGSEGV/abort
/// (panic="abort") at startup and on frpc reload paths. Past the cap the
/// remaining value degrades to a plain string literal.
const MAX_INI_NESTING: usize = 16;

/// Go's `ini.v1` boolean spellings — `parseBool` (`key.go:194`). The list is
/// case-sensitive there; `yes`/`no`/`1`/`0` are accepted and are *not* inferred
/// as booleans by the lossless reader, so a bool target reads them through
/// `super::ini_lenient` and the legacy-bool pre-pass below.
pub(super) fn parse_ini_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" | "YES" | "yes" | "Yes" | "y" | "ON" | "on"
        | "On" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" | "NO" | "no" | "No" | "n" | "OFF"
        | "off" | "Off" => Some(false),
        _ => None,
    }
}

/// Split a value the way Go's `Key.Strings(",")` does (`key.go:492`): on `,`,
/// trimming each element; `\,` is a literal comma; an empty value is no
/// elements and a trailing empty element is dropped.
///
/// Both the inference below and `super::ini_lenient` use this, so the array
/// form and the text form of a comma list agree — and agree with Go. Measured
/// on Go v0.71.0 (`custom_domains`, `GET /api/proxy/http`): `a\,b` →
/// `["a,b"]`, `x\,y,z` → `["x,y", "z"]`, `a.example.com,` → `["a.example.com"]`.
pub(super) fn split_ini_list(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    let mut items = Vec::new();
    let mut buf = String::new();
    let mut escape = false;
    for c in s.chars() {
        if escape {
            escape = false;
            if c != '\\' && c != ',' {
                buf.push('\\');
            }
            buf.push(c);
        } else if c == '\\' {
            escape = true;
        } else if c == ',' {
            items.push(buf.trim().to_string());
            buf.clear();
        } else {
            buf.push(c);
        }
    }
    if !buf.is_empty() {
        items.push(buf.trim().to_string());
    }
    items
}

/// Render a TOML value as the INI text it came from. The inverse of the
/// lossless inference below: for every value `infer_ini_value_depth` returns
/// that is not a `String`, both this and [`ini_value_json_text`] equal the
/// input text — `super::ini_lenient` relies on that when a string-typed field
/// reads an inferred value.
pub(super) fn ini_value_text(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Array(items) => items
            .iter()
            .map(ini_value_text)
            .collect::<Vec<_>>()
            .join(","),
        // INI never produces these; an empty rendering simply fails the
        // round-trip check below and the text is kept verbatim.
        toml::Value::Datetime(_) | toml::Value::Table(_) => String::new(),
    }
}

/// The text the **JSON projection** renders for a value — what
/// `super::ini_lenient::ini_text` gives a string-typed field, and therefore the
/// rendering that actually has to match the file.
///
/// Rust's `f64` Display and serde_json's `ryu` disagree for extreme
/// magnitudes: `10000000000000000000` is `1e+19` there and `0.0000001` is
/// `1e-7`, while both print as plain decimals here. A value whose two
/// renderings differ is kept as text by the inference, so a string field always
/// receives exactly what the file wrote.
pub(super) fn ini_value_json_text(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(|n| n.to_string())
            .unwrap_or_default(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Array(items) => items
            .iter()
            .map(ini_value_json_text)
            .collect::<Vec<_>>()
            .join(","),
        toml::Value::Datetime(_) | toml::Value::Table(_) => String::new(),
    }
}

/// Whether an inferred value survives both renderers — the losslessness the
/// inference promises.
fn round_trips(v: &toml::Value, raw: &str) -> bool {
    ini_value_text(v) == raw && ini_value_json_text(v) == raw
}

/// Infer INI value type matching Go Viper behavior — losslessly.
///
/// The result must satisfy both `ini_value_text(&result) == input` and
/// `ini_value_json_text(&result) == input`; otherwise the value stays a
/// `String`. See `ini_to_toml`.
fn infer_ini_value(s: &str) -> toml::Value {
    infer_ini_value_depth(s, 0)
}

fn infer_ini_value_depth(s: &str, depth: usize) -> toml::Value {
    let s = s.trim();

    if s.is_empty() {
        return toml::Value::String(String::new());
    }

    // Quoted string → strip quotes. A value that IS a lone quote character
    // (`"` or `'`, length 1) satisfies both starts_with and ends_with — the
    // old `s[1..s.len() - 1]` became `s[1..0]` and panicked ("slice index
    // starts at 1 but ends at 0"), aborting in release builds (panic=abort);
    // reachable from any `.ini` config at startup and on runtime reload
    // (frpc SIGUSR1 / admin API). Go ini.v1 keeps a lone quote as a
    // one-character literal string, so require len >= 2 and let the
    // one-char value fall through to the string branch below.
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        return toml::Value::String(s[1..s.len() - 1].to_string());
    }

    // Boolean — only the canonical spellings, so the text survives the
    // round-trip. `yes`/`no`/`TRUE` stay text and are read as a boolean by
    // `super::ini_lenient` when the target field is a bool (Go's
    // `ini.v1.parseBool` accepts the wider spelling set, `key.go:194`).
    if s == "true" {
        return toml::Value::Boolean(true);
    }
    if s == "false" {
        return toml::Value::Boolean(false);
    }

    // Nested type inference (array literals / comma splits) recurses — cap
    // the depth so hostile nesting degrades to a string literal instead of
    // overflowing the stack (see MAX_INI_NESTING).
    if depth >= MAX_INI_NESTING {
        return toml::Value::String(s.to_string());
    }

    // ["a", "b"] / [] array literal → Array. This is a **frp-rs extension**,
    // not Go syntax: measured on Go v0.71.0, `custom_domains =
    // ["a.example.com","b.example.com"]` reaches frps as
    // `['["a.example.com"', '"b.example.com"]']` (ini.v1 only splits a slice
    // field on `,`; `[]` becomes `["[]"]`). Kept for the slice fields that
    // already accept it; a *string* field reading such a value is rendered by
    // `ini_value_text` as the comma-joined elements, not as the bracket text.
    // Only when the inner content looks like a list: quoted elements or at
    // least one comma. A bare "[::1]" (IPv6 literal) falls through to the
    // string branch instead of becoming the one-element array "["::1"]".
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        if inner.trim().is_empty() {
            return toml::Value::Array(Vec::new());
        }
        let looks_like_list = inner.contains('"') || inner.contains('\'') || inner.contains(',');
        if looks_like_list {
            let parts: Vec<toml::Value> = inner
                .split(',')
                .map(|p| infer_ini_value_depth(p.trim(), depth + 1))
                .collect();
            return toml::Value::Array(parts);
        }
    }

    // Comma-separated → Array (type-infer each element), but only when the
    // split round-trips through *both* renderers: `1,2` becomes an array,
    // `1, 2` keeps its space and `a\,b` keeps its backslash, and both stay
    // text — Go trims each element of a slice field and honours the escape, so
    // the text form and the array form read the same through the target type
    // (see `super::ini_lenient`). The element splitter is Go's own
    // (`Key.Strings(",")`), so `a\,b` is one element here too.
    if s.contains(',') {
        let parts: Vec<toml::Value> = split_ini_list(s)
            .into_iter()
            .map(|p| infer_ini_value_depth(&p, depth + 1))
            .collect();
        let array = toml::Value::Array(parts);
        if round_trips(&array, s) {
            return array;
        }
        return toml::Value::String(s.to_string());
    }

    // Integer / Float — only when the parsed value renders back to exactly
    // this text through **both** renderers: `007`, `+5`, `1.50`, `1e3` stay
    // strings, and are read as a number by `super::ini_lenient` when the target
    // field is numeric. The JSON check matters for extreme magnitudes, where
    // serde_json's `ryu` rendering is exponential and Rust's `f64` Display is
    // not (`1e+19` / `1e-7`): without it a string field would receive
    // `"1e+19"` instead of the `10000000000000000000` the file wrote.
    if let Ok(i) = s.parse::<i64>() {
        let v = toml::Value::Integer(i);
        if round_trips(&v, s) {
            return v;
        }
    }
    if let Ok(f) = s.parse::<f64>() {
        let v = toml::Value::Float(f);
        if round_trips(&v, s) {
            return v;
        }
    }

    // Default: string
    toml::Value::String(s.to_string())
}

#[cfg(test)]
mod yaml_scalar_rule_tests {
    use super::*;
    use yaml_rust2::yaml::Yaml;

    /// One test per boolean spelling, so a changed table names the spelling
    /// that moved. The set is Go's (`gopkg.in/yaml.v2`), which is case
    /// sensitive and has no `nO`-style mixed forms.
    macro_rules! boolean_spelling_tests {
        ($($name:ident: $spelling:literal => $expected:literal,)*) => {
            $(
                #[test]
                #[allow(non_snake_case)] // the spelling is the test name
                fn $name() {
                    assert_eq!(
                        yaml_plain_scalar_bool($spelling),
                        Some($expected),
                        "Go resolves {:?} as a YAML 1.1 boolean",
                        $spelling
                    );
                }
            )*
        };
    }

    boolean_spelling_tests! {
        yaml_boolean_y: "y" => true,
        yaml_boolean_Y: "Y" => true,
        yaml_boolean_yes: "yes" => true,
        yaml_boolean_Yes: "Yes" => true,
        yaml_boolean_YES: "YES" => true,
        yaml_boolean_true: "true" => true,
        yaml_boolean_True: "True" => true,
        yaml_boolean_TRUE: "TRUE" => true,
        yaml_boolean_on: "on" => true,
        yaml_boolean_On: "On" => true,
        yaml_boolean_ON: "ON" => true,
        yaml_boolean_n: "n" => false,
        yaml_boolean_N: "N" => false,
        yaml_boolean_no: "no" => false,
        yaml_boolean_No: "No" => false,
        yaml_boolean_NO: "NO" => false,
        yaml_boolean_false: "false" => false,
        yaml_boolean_False: "False" => false,
        yaml_boolean_FALSE: "FALSE" => false,
        yaml_boolean_off: "off" => false,
        yaml_boolean_Off: "Off" => false,
        yaml_boolean_OFF: "OFF" => false,
    }

    #[test]
    fn mixed_case_and_numeral_words_are_not_booleans() {
        for text in ["nO", "yES", "TRue", "oN", "1", "0", "truey", "yes!", ""] {
            assert_eq!(
                yaml_plain_scalar_bool(text),
                None,
                "{text:?} is not a boolean spelling"
            );
        }
    }

    #[test]
    fn the_null_table_is_go_s() {
        for text in ["", "~", "null", "Null", "NULL"] {
            assert!(yaml_plain_scalar_is_null(text), "{text:?} is null in Go");
        }
        for text in ["nUll", "NULLL", "none", "Nil", "~ "] {
            assert!(
                !yaml_plain_scalar_is_null(text),
                "{text:?} is not null in Go"
            );
        }
    }

    /// Every value here was measured against the Go frp v0.71.0 binary with
    /// `serverPort`, per `/tmp/yaml-go-parity-contract.md`.
    #[test]
    fn go_integer_values_are_reproduced() {
        let table: &[(&str, Option<i64>)] = &[
            ("7000", Some(7000)),
            ("07000", Some(3584)), // legacy leading-zero octal
            ("07777", Some(4095)),
            ("017", Some(15)),
            ("007", Some(7)),
            ("00", Some(0)),
            ("000", Some(0)),
            ("080000", None),
            ("0o17", Some(15)),
            ("0O17", Some(15)),
            ("0x115c", Some(4444)),
            ("0X115C", Some(4444)),
            ("0b1010", Some(10)),
            ("0b101", Some(5)),
            ("0B101", Some(5)),
            ("+7911", Some(7911)),
            ("-017", Some(-15)),
            ("1_000", Some(1000)),
            ("7_9_1_1", Some(7911)),
            ("0", Some(0)),
            ("-0", Some(0)),
            // Not integers for Go: an invalid octal falls through to the float
            // rule, a bare prefix is a string, and an out-of-range body is not
            // an int at all.
            ("008", None),
            ("09999", None),
            ("0x", None),
            ("0b", None),
            ("9999999999999999999", None),
            ("-9223372036854775809", None),
            ("1e2", None),
            ("", None),
            ("abc", None),
        ];
        for (text, expected) in table {
            assert_eq!(yaml_go_int(text), *expected, "{text:?}");
        }
    }

    #[test]
    fn i64_bounds_are_representable() {
        assert_eq!(yaml_go_int("9223372036854775807"), Some(i64::MAX));
        assert_eq!(yaml_go_int("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(yaml_go_int("9223372036854775808"), None);
    }

    /// Go's `yamlStyleFloat` shape, from the harness's measured behaviour:
    /// `1e1000` is *not* a real there (Go's `ParseFloat` fails on overflow).
    #[test]
    fn float_shapes_match_go() {
        for text in [
            "7777.0", "7777.5", "09999", "008", "5.", ".5", "1e2", "1E3", "+1.5", "-1.5e-2",
        ] {
            assert!(yaml_style_float(text), "{text:?} is a Go float shape");
        }
        for text in [
            "1:30",
            "2001-12-14",
            "0x10",
            ".",
            "",
            "e3",
            "1e",
            "1_0",
            ".inf",
            "abc",
            "1.5.5",
        ] {
            assert!(!yaml_style_float(text), "{text:?} is not a Go float shape");
        }
    }

    #[test]
    fn non_finite_spellings_are_canonical() {
        let table: &[(&str, Option<&str>)] = &[
            (".inf", Some(".inf")),
            (".Inf", Some(".inf")),
            (".INF", Some(".inf")),
            ("+.inf", Some(".inf")),
            ("+.INF", Some(".inf")),
            ("-.inf", Some("-.inf")),
            ("-.Inf", Some("-.inf")),
            (".nan", Some(".nan")),
            (".NaN", Some(".nan")),
            (".NAN", Some(".nan")),
            // Neither reader resolves a signed NaN spelling; keep it as written.
            ("-.nan", None),
            ("+.nan", None),
            ("inf", None),
            ("nan", None),
        ];
        for (text, expected) in table {
            assert_eq!(non_finite_spelling(text), *expected, "{text:?}");
        }
    }

    /// Go renders an integral `float64` without a fraction, so those values have
    /// to reach the TOML pipeline as integers (`serverPort: 7777.0` is 7777).
    #[test]
    fn integral_reals_become_integer_json_numbers() {
        let table: &[(f64, Option<&str>)] = &[
            (7777.0, Some("7777")),
            (1000.0, Some("1000")),
            (-15.0, Some("-15")),
            (1.5, None),
            (1e19, None),
            (-9.223372036854776e18, Some("-9223372036854775808")),
        ];
        for (value, expected) in table {
            let rendered = integral_json_number(*value).map(|number| number.to_string());
            assert_eq!(rendered.as_deref(), *expected, "{value}");
        }
        assert!(integral_json_number(f64::INFINITY).is_none());
        assert!(integral_json_number(f64::NAN).is_none());
    }

    fn resolved(text: &str) -> serde_json::Value {
        yaml_value_to_json(&yaml_plain_scalar(text)).expect("a plain scalar resolves")
    }

    fn integer(text: &str) -> i64 {
        match yaml_plain_scalar(text) {
            YamlNode::Resolved(Yaml::Integer(value)) => value,
            other => panic!("{text:?} should resolve to an integer, got {other:?}"),
        }
    }

    /// The end-to-end projection of a plain scalar, with the Go measurement it
    /// reproduces (all per `/tmp/yaml-go-parity-contract.md`).
    #[test]
    fn plain_scalars_resolve_like_go() {
        assert_eq!(integer("017"), 15);
        assert_eq!(integer("007"), 7);
        assert_eq!(integer("07000"), 3584);
        assert_eq!(integer("0b101"), 5);
        assert_eq!(integer("1_000"), 1000);
        assert_eq!(integer("0x115c"), 4444);
        assert_eq!(integer("+7911"), 7911);
        // An invalid octal is a float for Go; the JSON projection of an integral
        // float is an integer, so an integer field still accepts it.
        assert_eq!(resolved("008"), serde_json::json!(8));
        assert_eq!(resolved("080000"), serde_json::json!(80000));
        assert_eq!(resolved("09999"), serde_json::json!(9999));
        assert_eq!(resolved("7777.0"), serde_json::json!(7777));
        assert_eq!(resolved("7777.5"), serde_json::json!(7777.5));
        assert_eq!(resolved("yes"), serde_json::json!(true));
        assert_eq!(resolved("off"), serde_json::json!(false));
        assert_eq!(resolved("NULL"), serde_json::Value::Null);
        assert_eq!(resolved("~"), serde_json::Value::Null);
        assert_eq!(resolved(""), serde_json::Value::Null);
        // Not numbers or booleans: preserve the text.
        assert_eq!(resolved("nO"), serde_json::json!("nO"));
        assert_eq!(resolved("1e1000"), serde_json::json!("1e1000"));
        assert_eq!(resolved("2001-12-14"), serde_json::json!("2001-12-14"));
        assert_eq!(resolved("1:30"), serde_json::json!("1:30"));
        // Non-finites keep their canonical text (Go cannot marshal them).
        assert_eq!(resolved(".inf"), serde_json::json!(".inf"));
        assert_eq!(resolved("-.Inf"), serde_json::json!("-.inf"));
        assert_eq!(resolved(".NaN"), serde_json::json!(".nan"));
        assert_eq!(resolved("-.nan"), serde_json::json!("-.nan"));
        assert_eq!(resolved("hello"), serde_json::json!("hello"));
    }

    /// A tag whose body is shared by two arms.
    fn core_tag(suffix: &str) -> Option<yaml_rust2::parser::Tag> {
        Some(yaml_rust2::parser::Tag {
            handle: "tag:yaml.org,2002:".to_string(),
            suffix: suffix.to_string(),
        })
    }

    /// Go's resolver decides with `resolveTable[in[0]]`, and `'_'` maps to 0, so
    /// an underscore-prefixed body never reaches the int/float branch: `_100`
    /// stays the string `_100` there (`serverPort: _100` is "cannot unmarshal
    /// string into int"), `_1` stays `_1`, and `!!int _100` cannot satisfy its
    /// tag. The gate has to cover the **float fallthrough** too, or `_100` fails
    /// the integer attempt and is still retyped as the integral real 100.
    #[test]
    fn underscore_prefixed_scalars_stay_strings() {
        for text in ["_100", "_1", "__1", "_0x10", "_1.5", "_100_", "_", "__"] {
            assert_eq!(yaml_go_int(text), None, "{text:?} is not an int for Go");
            assert_eq!(
                resolved(text),
                serde_json::json!(text),
                "{text:?} must stay the string it was written as"
            );
        }
        // A sign *does* select Go's numeric branch, and the `_` is then removed:
        // `+_100` is the integer 100 there (measured), unlike the bare `_100`.
        assert_eq!(integer("+_100"), 100);
        assert_eq!(integer("-_100"), -100);

        // Go only strips `_` once the first byte has already selected a numeric
        // branch, so a valid separator is still removed: `1_000` is 1000.
        assert_eq!(integer("1_000"), 1000);
        assert_eq!(integer("7_9_1_1"), 7911);

        // The numeric tags reject the same bodies instead of accepting them.
        for (suffix, text) in [("int", "_100"), ("float", "_100"), ("float", "_1.5")] {
            assert!(
                matches!(
                    scalar_node(
                        text.to_string(),
                        yaml_rust2::scanner::TScalarStyle::Plain,
                        core_tag(suffix)
                    ),
                    YamlNode::Bad(_)
                ),
                "!!{suffix} {text:?} must be an error"
            );
        }
    }

    /// The tab cases were measured against both Go frp and `yaml-rust2`, per the
    /// review's `§4.3`: these are the ones `yaml-rust2` silently accepts.
    #[test]
    fn tab_indentation_is_rejected_where_go_rejects_it() {
        let table: &[(&str, Option<(usize, usize)>)] = &[
            ("\ta: 1\n", Some((1, 1))),
            (" \ta: 1\n", Some((1, 2))),
            ("- \ta: 1\n", Some((1, 3))),
            ("x: |\n  \tfoo\n", Some((2, 3))),
            ("x: >\n  \tfoo\n", Some((2, 3))),
            ("x: |\n\tfoo\n", Some((2, 1))),
            ("# c\n\tx: 1\n", Some((2, 1))),
            ("x: foo\n\tbar\n", Some((2, 1))),
            ("x: 1\n\n\tb: 2\n", Some((3, 1))),
            ("a: 1\n \tb: 2\n", Some((2, 2))),
        ];
        for (source, expected) in table {
            assert_eq!(yaml_indentation_tab(source), *expected, "{source:?}");
        }
    }

    /// These are the shapes the **pre-check** [`yaml_indentation_tab`] allows,
    /// because Go allows them — inside a flow collection, as separation within a
    /// line, and in a block scalar whose indentation is already established.
    ///
    /// This is *not* a claim that the parser accepts them end-to-end.
    /// `yaml-rust2`'s scanner applies its own, stricter rule on top, and refuses
    /// two shapes Go accepts: a tab-indented flow collection
    /// (`metadatas: {\n\tk: v\n}` → `tabs disallowed within this context`) and an
    /// unindented flow continuation (`x: [1,\n2]` → `invalid indentation in
    /// flow construct`). Both
    /// are loud refusals, listed in the migration notes on [`yaml_to_toml`]. The
    /// test pins only the allow-list of this helper, so a change to either the
    /// helper or the scanner shows up as a failure here rather than silently.
    #[test]
    fn tab_pre_check_allows_shapes_the_scanner_independently_refuses() {
        for source in [
            "a: \t1\n",
            "{\ta: 1}\n",
            "x: [\t1, 2]\n",
            "x: [1,\n\t2]\n",
            "x: {\na: 1,\n\tb: 2}\n",
            "x: |\n  a\n  \tb\n",
            "x: |\n  a\n\t\n",
            "x: 1\n",
        ] {
            assert_eq!(yaml_indentation_tab(source), None, "{source:?}");
        }
    }

    #[test]
    fn block_scalar_headers_are_recognised() {
        for content in [
            "x: |", "x: >", "x: |-", "x: >+", "x: |2", "x: |2-", "x: >-2",
        ] {
            assert!(block_scalar_header(content), "{content:?}");
        }
        for content in ["x: a", "x: a>", "x: '|'", "x: |x", ""] {
            assert!(!block_scalar_header(content), "{content:?}");
        }
    }

    #[test]
    fn comments_are_stripped_only_after_whitespace() {
        assert_eq!(strip_comment("x: 1 # c"), "x: 1 ");
        assert_eq!(strip_comment("# c"), "");
        assert_eq!(strip_comment("x: a#b"), "x: a#b");
        assert_eq!(strip_comment("x: 1"), "x: 1");
    }

    #[test]
    fn a_document_end_marker_is_detected() {
        for source in ["...", "...\n", "a: 1\n...\n", "a: 1\n... # end\n"] {
            assert!(yaml_has_document_end_marker(source), "{source:?}");
        }
        for source in ["", "a: 1\n", "...foo\n", "a: \n"] {
            assert!(!yaml_has_document_end_marker(source), "{source:?}");
        }
    }

    /// The proportional rule alone is not a bound on the tree: inert bytes
    /// inflate it, so a padded alias bomb would be allowed millions of nodes.
    /// The absolute ceiling is what bounds the expanded node count, and it must
    /// not let a large input raise the allowance above it.
    #[test]
    fn the_expansion_budget_is_clamped_to_an_absolute_ceiling() {
        assert_eq!(YamlReceiver::new(1_048_576).alias_budget, 400_000);
        assert_eq!(YamlReceiver::new(4_000).alias_budget, 400_000);
        assert_eq!(YamlReceiver::new(892).alias_budget, 100_000);
        assert_eq!(YamlReceiver::new(0).alias_budget, 100_000);
        // Below the ceiling the ratio still applies, so a genuinely large
        // document is not refused for being large while it is still honest.
        assert_eq!(YamlReceiver::new(2_000).alias_budget, 200_000);
    }

    /// An alias bomb and a large honest document must not share an error
    /// message. The cause is what the caller knows, not the size of the charge:
    /// an alias of a scalar is charged exactly one node, like a plain scalar.
    #[test]
    fn over_budget_messages_name_the_right_cause() {
        assert_eq!(
            over_budget_message(true, 400_000),
            "alias expansion limit exceeded"
        );
        assert_eq!(
            over_budget_message(false, 400_000),
            "document exceeds the node limit (400000 nodes)"
        );
    }

    /// A real parse, kept only for the marker it hands back.
    struct FirstMarker(Option<yaml_rust2::scanner::Marker>);

    impl yaml_rust2::parser::MarkedEventReceiver for FirstMarker {
        fn on_event(
            &mut self,
            _event: yaml_rust2::parser::Event,
            mark: yaml_rust2::scanner::Marker,
        ) {
            self.0.get_or_insert(mark);
        }
    }

    /// A scalar alias is charged **one** node per copy, so "the charge is bigger
    /// than one" does not identify an alias: a document that re-expands a
    /// one-character scalar hundreds of thousands of times is a pure alias bomb,
    /// yet it used to be reported as a large but honest document. The receiver is
    /// driven by hand because the real budget floors at `100_000` nodes, which a
    /// one-node alias cannot reach from an input small enough for the suite.
    #[test]
    fn a_scalar_alias_past_the_budget_reports_the_alias_limit() {
        let mut sink = FirstMarker(None);
        yaml_rust2::parser::Parser::new_from_str("x\n")
            .load(&mut sink, false)
            .expect("the probe document parses");
        let mark = sink.0.expect("the probe document emits an event");

        let mut receiver = YamlReceiver {
            alias_budget: 3,
            ..YamlReceiver::default()
        };
        let anchored = |text: &str, aid: usize| {
            yaml_rust2::parser::Event::Scalar(
                text.to_string(),
                yaml_rust2::scanner::TScalarStyle::Plain,
                aid,
                None,
            )
        };
        receiver
            .handle(yaml_rust2::parser::Event::SequenceStart(0, None), mark)
            .expect("a sequence starts");
        receiver
            .handle(anchored("s", 1), mark)
            .expect("the anchored scalar fits");
        for _ in 0..2 {
            receiver
                .handle(yaml_rust2::parser::Event::Alias(1), mark)
                .expect("an alias inside the three-node budget");
        }
        let error = receiver
            .handle(yaml_rust2::parser::Event::Alias(1), mark)
            .expect_err("the third alias passes the three-node budget");
        let message = error.to_string();
        assert!(
            message.starts_with("alias expansion limit exceeded"),
            "{message}"
        );
        assert!(!message.contains("node limit"), "{message}");
    }
}
