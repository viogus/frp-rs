//! Type-directed deserialization of legacy `.ini` configs.
//!
//! Go's legacy INI loader gives every value to the target field as **text**
//! and lets the field's Go type decide how to read it (`gopkg.in/ini.v1`
//! `MapTo`: `Key.String()` for a string field, `Key.Int64()` for an int,
//! `Key.Strings(",")` for a slice — `struct.go:154-266`). frp-rs's INI reader
//! infers a TOML type first (`super::format::ini_to_toml`), so a bare numeric
//! reached a `String` field as an integer and was rejected:
//! `token = 12345678` (Go's own `conf/legacy/frpc_legacy_full.ini`) failed with
//! ``invalid type: integer `12345678`, expected a string`` where Go's
//! `frpc verify -c` exits 0.
//!
//! This module restores Go's model at the deserialization boundary for `.ini`
//! inputs only: a value is read as whatever the target field asks for. The
//! inferred type is still used when the field wants it, and the inference is
//! lossless (`super::format::ini_value_text`), so the text a string field
//! receives is exactly the text the file wrote.
//!
//! Only the `.ini` path uses this (see `load_config_from_file` in
//! `super::normalize`); TOML/JSON/YAML keep the strict serde typing Go's v1
//! decoder has.

use serde::de::{
    self, DeserializeOwned, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor,
};
use serde_json::Value;

/// Deserialize a parsed `.ini` config with the target type deciding how each
/// value is read.
pub(super) fn deserialize_ini<T: DeserializeOwned>(value: &Value) -> Result<T, serde_json::Error> {
    T::deserialize(IniValue(value))
}

/// Render an inferred value as the INI text it stands for. Mirrors
/// `super::format::ini_value_text` (which renders the `toml::Value` before the
/// JSON projection); `ini_value_text_matches_inference` pins the two together.
fn ini_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Array(items) => items.iter().map(ini_text).collect::<Vec<_>>().join(","),
        Value::Null | Value::Object(_) => String::new(),
    }
}

/// Go's `ini.v1` boolean spellings — `parseBool` (`key.go:194`). Go's list is
/// case-sensitive; `yes`/`no`/`ON` are accepted there and are *not* inferred as
/// booleans by the lossless reader, so a `bool` field reads them through here.
fn parse_ini_bool(s: &str) -> Option<bool> {
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
/// elements and a trailing empty element is dropped. A slice-typed field reads
/// a comma list that the lossless reader kept as text (because it re-renders
/// differently, e.g. `a, b`) through here.
fn split_ini_list(s: &str) -> Vec<String> {
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

/// A value being read as whatever the target field asks for.
struct IniValue<'a>(&'a Value);

impl<'de, 'a> Deserializer<'de> for IniValue<'a> {
    type Error = serde_json::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Null => visitor.visit_unit(),
            Value::Bool(b) => visitor.visit_bool(*b),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    visitor.visit_i64(i)
                } else if let Some(u) = n.as_u64() {
                    visitor.visit_u64(u)
                } else if let Some(f) = n.as_f64() {
                    visitor.visit_f64(f)
                } else {
                    Err(de::Error::custom("unsupported JSON number"))
                }
            }
            Value::String(s) => visitor.visit_str(s),
            Value::Array(items) => visitor.visit_seq(IniSeq { iter: items.iter() }),
            Value::Object(map) => visitor.visit_map(IniMap {
                iter: map.iter(),
                value: None,
            }),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_text(visitor)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_text(visitor)
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_text(visitor)
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        // Go reads a bool field with `Key.Bool()` — `parseBool` (`key.go:194`),
        // which accepts `1` and `0`. Those are the canonical
        // rendering of an integer, so they reach this method as numbers, not
        // text.
        match self.0 {
            Value::String(s) => match parse_ini_bool(s) {
                Some(b) => visitor.visit_bool(b),
                None => Err(de::Error::invalid_value(
                    de::Unexpected::Str(s),
                    &"a boolean (`true`/`false`/`yes`/`no`/`on`/`off`/`1`/`0`)",
                )),
            },
            Value::Number(n) => match n.as_i64() {
                Some(1) => visitor.visit_bool(true),
                Some(0) => visitor.visit_bool(false),
                _ => Err(de::Error::invalid_value(
                    de::Unexpected::Other("number"),
                    &"a boolean (`true`/`false`/`yes`/`no`/`on`/`off`/`1`/`0`)",
                )),
            },
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_int(visitor)
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_int(visitor)
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_int(visitor)
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_int(visitor)
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_int(visitor)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_int(visitor)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_int(visitor)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_int(visitor)
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_float(visitor)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_float(visitor)
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::String(s) => visitor.visit_seq(IniTextSeq {
                items: split_ini_list(s).into_iter().map(Value::String).collect(),
                idx: 0,
            }),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        // No config struct is an enum; delegate on an owned clone so an exotic
        // enum field keeps serde_json's externally-tagged handling (its
        // payloads are read strictly).
        self.0.clone().deserialize_enum(name, variants, visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_any(visitor)
    }
}

impl<'a> IniValue<'a> {
    fn deserialize_text<'de, V: Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, serde_json::Error> {
        match self.0 {
            Value::String(s) => visitor.visit_str(s),
            other => visitor.visit_string(ini_text(other)),
        }
    }

    /// An integer target reads a text value by parsing it. Go's `Key.Int64()`
    /// is `strconv.ParseInt(s, 0, 64)` (`key.go:221`) — base 0, so Go reads
    /// `0x10` as 16 where this reads base 10 and refuses it; that difference is
    /// pre-existing (the inference this replaces also read base 10) and is
    /// recorded in `docs/config.md`.
    fn deserialize_int<'de, V: Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, serde_json::Error> {
        if let Value::String(s) = self.0 {
            return match s.parse::<i64>() {
                Ok(i) => visitor.visit_i64(i),
                Err(_) => Err(de::Error::invalid_value(
                    de::Unexpected::Str(s),
                    &"an integer",
                )),
            };
        }
        self.deserialize_any(visitor)
    }

    fn deserialize_float<'de, V: Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, serde_json::Error> {
        if let Value::String(s) = self.0 {
            return match s.parse::<f64>() {
                Ok(f) => visitor.visit_f64(f),
                Err(_) => Err(de::Error::invalid_value(de::Unexpected::Str(s), &"a float")),
            };
        }
        self.deserialize_any(visitor)
    }
}

struct IniSeq<'a> {
    iter: std::slice::Iter<'a, Value>,
}

impl<'de, 'a> SeqAccess<'de> for IniSeq<'a> {
    type Error = serde_json::Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        match self.iter.next() {
            Some(v) => seed.deserialize(IniValue(v)).map(Some),
            None => Ok(None),
        }
    }
}

/// A comma list that stayed text (see `split_ini_list`) read as a sequence.
struct IniTextSeq {
    items: Vec<Value>,
    idx: usize,
}

impl<'de> SeqAccess<'de> for IniTextSeq {
    type Error = serde_json::Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        match self.items.get(self.idx) {
            Some(v) => {
                self.idx += 1;
                seed.deserialize(IniValue(v)).map(Some)
            }
            None => Ok(None),
        }
    }
}

struct IniMap<'a> {
    iter: serde_json::map::Iter<'a>,
    value: Option<&'a Value>,
}

impl<'de, 'a> MapAccess<'de> for IniMap<'a> {
    type Error = serde_json::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        match self.iter.next() {
            Some((k, v)) => {
                self.value = Some(v);
                seed.deserialize(de::value::StrDeserializer::new(k))
                    .map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        let v = self
            .value
            .take()
            .expect("next_value_seed is called only after next_key_seed");
        seed.deserialize(IniValue(v))
    }
}

/// Unused today (no config field is an enum) but keeps the module honest if one
/// is added: a bare string is a unit variant.
#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Probe {
        #[serde(default)]
        num: i64,
        #[serde(default)]
        flag: bool,
        #[serde(default)]
        text: String,
        #[serde(default)]
        list: Vec<String>,
        #[serde(default)]
        numbers: Vec<u16>,
        #[serde(default)]
        ratio: f64,
        #[serde(default)]
        map: std::collections::HashMap<String, String>,
        #[serde(default)]
        nested: Option<Nested>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Nested {
        #[serde(default)]
        inner: String,
    }

    /// The JSON projection of a parsed INI file, as `load_config_from_file`
    /// builds it.
    fn json_from_ini(s: &str) -> Value {
        super::super::normalize::toml_to_json(
            super::super::format::parse_to_toml_value(s, super::super::format::ConfigFormat::Ini)
                .expect("INI parse"),
        )
    }

    #[test]
    fn string_field_reads_integer_float_bool_and_comma_list() {
        let p: Probe = deserialize_ini(&json_from_ini("text = 12345678\nnum = 1\n")).unwrap();
        assert_eq!(p.text, "12345678");

        let p: Probe = deserialize_ini(&json_from_ini("text = 1.50\nnum = 1\n")).unwrap();
        assert_eq!(p.text, "1.50", "a non-canonical float keeps its text");

        let p: Probe = deserialize_ini(&json_from_ini("text = yes\nnum = 1\n")).unwrap();
        assert_eq!(p.text, "yes");

        let p: Probe =
            deserialize_ini(&json_from_ini("text = 2000-3000, 3001, 3003\nnum = 1\n")).unwrap();
        assert_eq!(p.text, "2000-3000, 3001, 3003");

        let p: Probe =
            deserialize_ini(&json_from_ini("text = 2000-3000,3001,3003\nnum = 1\n")).unwrap();
        assert_eq!(p.text, "2000-3000,3001,3003");
    }

    #[test]
    fn numeric_and_bool_fields_read_text() {
        let p: Probe =
            deserialize_ini(&json_from_ini("num = 007\nflag = YES\ntext = x\n")).unwrap();
        assert_eq!(p.num, 7, "a leading zero is still a decimal integer");
        assert!(p.flag);

        let p: Probe =
            deserialize_ini(&json_from_ini("ratio = 1e3\nflag = off\ntext = x\n")).unwrap();
        assert_eq!(p.ratio, 1000.0);
        assert!(!p.flag);

        // Go's `Key.Int64()` is base 0 (`0x10` → 16); this is base 10 and
        // refuses it, as the inference it replaces did.
        let err = deserialize_ini::<Probe>(&json_from_ini("num = 0x10\ntext = x\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid value"), "got: {err}");
    }

    #[test]
    fn fields_keep_serde_defaults_when_absent() {
        let p: Probe = deserialize_ini(&json_from_ini("text = x\n")).unwrap();
        assert_eq!(p.num, 0);
        assert!(!p.flag);
        assert!(p.list.is_empty());
        assert!(p.nested.is_none());
    }

    #[test]
    fn list_and_map_targets_read_text_and_arrays() {
        let p: Probe = deserialize_ini(&json_from_ini("list = a, b\nnumbers = 1, 2\n")).unwrap();
        assert_eq!(p.list, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(p.numbers, vec![1u16, 2]);

        let p: Probe = deserialize_ini(&json_from_ini("list = a,b\nnumbers = 1,2\n")).unwrap();
        assert_eq!(p.list, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(p.numbers, vec![1u16, 2]);

        let p: Probe = deserialize_ini(&json_from_ini("list = []\nnumbers = 1,2\n")).unwrap();
        // frp-rs array-literal extension: `[]` is an empty list.
        assert!(p.list.is_empty());

        let p: Probe = deserialize_ini(&json_from_ini("list =\nnumbers = 1,2\n")).unwrap();
        assert!(p.list.is_empty(), "an empty value is no elements");
    }

    #[test]
    fn nested_tables_and_maps_are_read_by_target_type() {
        let p: Probe = deserialize_ini(&serde_json::json!({
            "num": 1,
            "text": "x",
            "map": {"k": 123},
            "nested": {"inner": 42},
        }))
        .unwrap();
        assert_eq!(p.map.get("k").map(String::as_str), Some("123"));
        assert_eq!(p.nested, Some(Nested { inner: "42".into() }));
    }

    #[test]
    fn ini_value_text_matches_inference() {
        // The invariant `ini_to_toml` promises: for every value the reader
        // turns into a non-string, both renderers reproduce the input text.
        for source in [
            "token = 12345678",
            "port = 7000",
            "ratio = 1.5",
            "flag = true",
            "list = 1,2,3",
            "list = 2000-3000,3001",
            "neg = -1",
        ] {
            let toml_value = super::super::format::parse_to_toml_value(
                source,
                super::super::format::ConfigFormat::Ini,
            )
            .unwrap();
            let (key, raw) = source.split_once('=').unwrap();
            let raw = raw.trim();
            let inferred = toml_value.get(key.trim()).expect("key present");
            if !matches!(inferred, toml::Value::String(_)) {
                assert_eq!(
                    super::super::format::ini_value_text(inferred),
                    raw,
                    "toml renderer for {source}"
                );
                assert_eq!(
                    ini_text(&super::super::normalize::toml_to_json(inferred.clone())),
                    raw,
                    "json renderer for {source}"
                );
            }
        }
    }
}
