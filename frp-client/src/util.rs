//! Small internal helpers shared across frp-client modules.

/// `None` for an empty string/collection, else `Some(clone)`. Centralizes the
/// Go-frp wire convention of omitting empty optional fields. Evaluates its
/// argument exactly once, then works for any type with `is_empty()` + `Clone`
/// (String, Vec<T>, HashMap<K, V>, ...).
macro_rules! opt_if_empty {
    ($e:expr) => {{
        let v = &$e;
        if v.is_empty() { None } else { Some(v.clone()) }
    }};
}
pub(crate) use opt_if_empty;
