// SPDX-License-Identifier: LGPL-2.1-or-later
//! Account settings as the C++ side sees them: the `QVariant` libaccounts-qt makes of a stored
//! `GVariant`, and the Qt 5 conversions the account store applies.

use std::cmp::Ordering;

/// A `QString`; `None` is the null string, distinct from empty on the wire.
pub type QString = Option<String>;

/// A setting's value as a `QVariant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// No value, or one libaccounts-qt does not convert: an invalid `QVariant`.
    Invalid,
    /// A boolean.
    Bool(bool),
    /// A 32-bit signed integer.
    Int(i32),
    /// A 32-bit unsigned integer.
    UInt(u32),
    /// A 64-bit signed integer.
    LongLong(i64),
    /// A 64-bit unsigned integer.
    ULongLong(u64),
    /// A string.
    String(String),
    /// A list of strings.
    StringList(Vec<String>),
    /// `a{sv}`; keys as stored, in the order read.
    Map(Vec<(String, Self)>),
}

impl Value {
    /// `QVariant::toString()`.
    #[must_use]
    pub fn to_qstring(&self) -> QString {
        match self {
            Self::Invalid | Self::Map(_) => None,
            Self::Bool(b) => Some(if *b { "true" } else { "false" }.to_owned()),
            Self::Int(i) => Some(i.to_string()),
            Self::UInt(u) => Some(u.to_string()),
            Self::LongLong(i) => Some(i.to_string()),
            Self::ULongLong(u) => Some(u.to_string()),
            Self::String(s) => Some(s.clone()),
            Self::StringList(list) => match list.as_slice() {
                [only] => Some(only.clone()),
                _ => None,
            },
        }
    }

    /// `QVariant::toInt(&ok)`: `None` when Qt cannot convert. Wider numbers
    /// are cut to 32 bits as Qt does.
    #[must_use]
    pub fn to_int(&self) -> Option<i32> {
        match self {
            Self::Invalid | Self::StringList(_) | Self::Map(_) => None,
            Self::Bool(b) => Some(i32::from(*b)),
            Self::Int(i) => Some(*i),
            Self::UInt(u) => Some(u.cast_signed()),
            Self::LongLong(i) => Some(cut_to_int(*i)),
            Self::ULongLong(u) => Some(cut_to_int(u.cast_signed())),
            Self::String(s) => to_long_long(s).map(cut_to_int),
        }
    }
}

/// The low 32 bits of `v` as a C `int` takes them: how Qt cuts a wider
/// number, and how SQLite's `sqlite3_column_int` cuts an id.
#[must_use]
pub fn cut_to_int(v: i64) -> i32 {
    let [b0, b1, b2, b3, ..] = v.to_le_bytes();
    i32::from_le_bytes([b0, b1, b2, b3])
}

/// `QChar::isSpace()`: the same characters as Unicode's `White_Space`.
#[must_use]
pub fn is_qt_space(c: char) -> bool {
    c.is_whitespace()
}

/// `QString::trimmed()`.
#[must_use]
pub fn trimmed(s: &QString) -> QString {
    s.as_ref().map(|text| text.trim_matches(is_qt_space).to_owned())
}

/// `QString::toLongLong(&ok)` in base 10: surrounding white space, an
/// optional sign, decimal digits.
#[must_use]
pub fn to_long_long(s: &str) -> Option<i64> {
    let text = s.trim_matches(is_qt_space);
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let magnitude: u64 = digits.parse().ok()?;
    if negative {
        if magnitude == 1 << 63 {
            Some(i64::MIN)
        } else {
            i64::try_from(magnitude).ok().and_then(i64::checked_neg)
        }
    } else {
        i64::try_from(magnitude).ok()
    }
}

/// `QString::toInt(&ok)` in base 10: like `to_long_long`, but out of range is
/// a failure, not a cut.
#[must_use]
pub fn to_int(s: &str) -> Option<i32> {
    to_long_long(s).and_then(|v| i32::try_from(v).ok())
}

/// `QString`'s `operator<`: by UTF-16 code units.
#[must_use]
pub fn compare_qstring(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_qstring_follows_qt() {
        assert_eq!(Value::Invalid.to_qstring(), None);
        assert_eq!(Value::Map(Vec::new()).to_qstring(), None);
        assert_eq!(Value::Bool(true).to_qstring().as_deref(), Some("true"));
        assert_eq!(Value::Bool(false).to_qstring().as_deref(), Some("false"));
        assert_eq!(Value::Int(-3).to_qstring().as_deref(), Some("-3"));
        assert_eq!(Value::UInt(3).to_qstring().as_deref(), Some("3"));
        assert_eq!(Value::LongLong(-1 << 40).to_qstring().as_deref(), Some("-1099511627776"));
        assert_eq!(Value::ULongLong(u64::MAX).to_qstring().as_deref(), Some("18446744073709551615"));
        assert_eq!(Value::String(String::new()).to_qstring().as_deref(), Some(""));
        assert_eq!(Value::StringList(vec!["one".into()]).to_qstring().as_deref(), Some("one"));
        assert_eq!(Value::StringList(Vec::new()).to_qstring(), None);
        assert_eq!(Value::StringList(vec!["a".into(), "b".into()]).to_qstring(), None);
    }

    #[test]
    fn to_int_follows_qt() {
        assert_eq!(Value::Invalid.to_int(), None);
        assert_eq!(Value::StringList(vec!["1".into()]).to_int(), None);
        assert_eq!(Value::Map(Vec::new()).to_int(), None);
        assert_eq!(Value::Bool(true).to_int(), Some(1));
        assert_eq!(Value::Bool(false).to_int(), Some(0));
        assert_eq!(Value::Int(2222).to_int(), Some(2222));
        assert_eq!(Value::UInt(u32::MAX).to_int(), Some(-1));
        assert_eq!(Value::LongLong((1 << 32) + 5).to_int(), Some(5));
        assert_eq!(Value::ULongLong((1 << 32) + 6).to_int(), Some(6));
        assert_eq!(Value::String(" 22 ".into()).to_int(), Some(22));
        assert_eq!(Value::String("4294967298".into()).to_int(), Some(2));
        assert_eq!(Value::String("x".into()).to_int(), None);
    }

    #[test]
    fn numbers_from_strings() {
        assert_eq!(to_long_long("7"), Some(7));
        assert_eq!(to_long_long("+7"), Some(7));
        assert_eq!(to_long_long("-7"), Some(-7));
        assert_eq!(to_long_long("\t007\n"), Some(7));
        assert_eq!(to_long_long("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(to_long_long("9223372036854775807"), Some(i64::MAX));
        assert_eq!(to_long_long("9223372036854775808"), None);
        assert_eq!(to_long_long("-9223372036854775809"), None);
        for bad in ["", " ", "-", "+", "1x", "0x10", "1 2", "--1", "++1", "-+1", "١"] {
            assert_eq!(to_long_long(bad), None, "{bad:?}");
        }
        assert_eq!(to_int("2147483647"), Some(i32::MAX));
        assert_eq!(to_int("2147483648"), None);
        assert_eq!(to_int("-2147483648"), Some(i32::MIN));
    }

    #[test]
    fn trimming_and_order() {
        assert_eq!(trimmed(&None), None);
        assert_eq!(trimmed(&Some("\u{a0} a b\u{3000}".into())).as_deref(), Some("a b"));
        assert_eq!(trimmed(&Some("  ".into())).as_deref(), Some(""));
        assert!(is_qt_space('\u{2029}'));
        assert!(!is_qt_space('\u{200b}'));
        // By code unit: a supplementary character sorts before U+FFFF.
        assert_eq!(compare_qstring("\u{1f600}", "\u{ffff}"), Ordering::Less);
        assert_eq!(compare_qstring("a", "b"), Ordering::Less);
        assert_eq!(compare_qstring("b", "b"), Ordering::Equal);
    }
}
