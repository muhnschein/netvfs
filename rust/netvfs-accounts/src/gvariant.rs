// SPDX-License-Identifier: LGPL-2.1-or-later
//! Setting values in `accounts.db`: libaccounts-glib stores each as its
//! `GVariant` type string and `g_variant_print()` text, and reads it back with
//! `g_variant_parse()` (`_ag_value_from_string`, ag-util.c).
//!
//! This parses the text format for the types libaccounts-qt turns into a
//! `QVariant` (`gVariantToQVariant`): `s`, `b`, `i`, `u`, `x`, `t`, `as` and
//! `a{sv}`. Every other type is read as `Value::Invalid`, which is what
//! libaccounts-qt makes of it too; so is text that does not parse, which
//! libaccounts-glib keeps as a key without a value (`got_account_setting`).

use crate::qvariant::Value;

/// The `QVariant` libaccounts-qt makes of a stored setting. `text` is the
/// value column (`None` for SQL NULL).
///
/// The text of a type this module does not parse is not checked: it reads
/// as `Value::Invalid` whether it parses or not, as both do for
/// libaccounts-qt.
#[must_use]
pub fn from_db(type_string: &[u8], text: Option<&[u8]>) -> Value {
    let Some(text) = text else { return Value::Invalid };
    // g_variant_parse() and g_variant_new_string() refuse invalid UTF-8.
    let Ok(text) = std::str::from_utf8(text) else { return Value::Invalid };
    // libaccounts-glib takes an unquoted string as it is (for the XML files).
    if type_string == b"s" && !text.starts_with(['\'', '"']) {
        return Value::String(text.to_owned());
    }
    let Some(expected) = Kind::from_type_string(type_string) else { return Value::Invalid };
    let mut parser = Parser { text: text.as_bytes(), pos: 0 };
    match parser.value(Some(expected)) {
        Ok(value) if parser.at_end() => value,
        _ => Value::Invalid,
    }
}

/// `g_variant_print(value, FALSE)` of a string, as libaccounts-glib stores
/// it. Characters other than printable ASCII are written as `\u` escapes,
/// which `g_variant_parse()` reads back to the same string.
#[must_use]
pub fn print_string(s: &str) -> String {
    let quote = if s.contains('\'') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if u32::from(c) < 0x1_0000 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push_str(&format!("\\U{:08x}", u32::from(c))),
        }
    }
    out.push(quote);
    out
}

/// `g_variant_print(value, FALSE)` of a boolean.
#[must_use]
pub fn print_bool(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

/// The types this parser knows by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    String,
    Bool,
    Int32,
    UInt32,
    Int64,
    UInt64,
    StringArray,
    VarDict,
    /// Parsed, but not a type libaccounts-qt converts.
    Other(Other),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Other {
    Byte,
    Int16,
    UInt16,
    Handle,
    Double,
    ObjectPath,
    Signature,
}

impl Kind {
    fn from_type_string(t: &[u8]) -> Option<Self> {
        Some(match t {
            b"s" => Self::String,
            b"b" => Self::Bool,
            b"i" => Self::Int32,
            b"u" => Self::UInt32,
            b"x" => Self::Int64,
            b"t" => Self::UInt64,
            b"as" => Self::StringArray,
            b"a{sv}" => Self::VarDict,
            b"y" => Self::Other(Other::Byte),
            b"n" => Self::Other(Other::Int16),
            b"q" => Self::Other(Other::UInt16),
            b"h" => Self::Other(Other::Handle),
            b"d" => Self::Other(Other::Double),
            b"o" => Self::Other(Other::ObjectPath),
            b"g" => Self::Other(Other::Signature),
            _ => return None,
        })
    }

    fn from_keyword(word: &str) -> Option<Self> {
        Some(match word {
            "string" => Self::String,
            "boolean" => Self::Bool,
            "int32" => Self::Int32,
            "uint32" => Self::UInt32,
            "int64" => Self::Int64,
            "uint64" => Self::UInt64,
            "byte" => Self::Other(Other::Byte),
            "int16" => Self::Other(Other::Int16),
            "uint16" => Self::Other(Other::UInt16),
            "handle" => Self::Other(Other::Handle),
            "double" => Self::Other(Other::Double),
            "objectpath" => Self::Other(Other::ObjectPath),
            "signature" => Self::Other(Other::Signature),
            _ => return None,
        })
    }
}

/// A parse failure; the value is then unusable as a whole.
#[derive(Debug)]
struct Unparsable;

type Parsed<T> = Result<T, Unparsable>;

/// Nesting deeper than this is refused: no stored setting needs it, and it
/// bounds the recursion.
const MAX_DEPTH: usize = 16;

struct Parser<'a> {
    text: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn skip_space(&mut self) {
        // g_ascii_isspace
        while self
            .text
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r'))
        {
            self.pos += 1;
        }
    }

    fn at_end(&mut self) -> bool {
        self.skip_space();
        self.pos == self.text.len()
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_space();
        self.text.get(self.pos).copied()
    }

    fn expect(&mut self, b: u8) -> Parsed<()> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(Unparsable)
        }
    }

    /// A run of characters that `token_stream_prepare` keeps together.
    fn word(&mut self, also: &[u8]) -> &str {
        self.skip_space();
        let start = self.pos;
        while self.text.get(self.pos).is_some_and(|b| b.is_ascii_alphanumeric() || also.contains(b)) {
            self.pos += 1;
        }
        // ASCII only, so always UTF-8.
        std::str::from_utf8(&self.text[start..self.pos]).unwrap_or_default()
    }

    fn value(&mut self, expected: Option<Kind>) -> Parsed<Value> {
        self.value_at(expected, 0)
    }

    fn value_at(&mut self, expected: Option<Kind>, depth: usize) -> Parsed<Value> {
        if depth > MAX_DEPTH {
            return Err(Unparsable);
        }
        let expected = self.annotation(expected)?;
        match self.peek().ok_or(Unparsable)? {
            b'\'' | b'"' => {
                let s = self.string()?;
                match expected {
                    None | Some(Kind::String) => Ok(Value::String(s)),
                    Some(Kind::Other(Other::ObjectPath | Other::Signature)) => Ok(Value::Invalid),
                    Some(_) => Err(Unparsable),
                }
            }
            b'[' => self.array(expected, depth),
            b'{' => self.dict(expected, depth),
            b'<' => {
                // A variant: libaccounts-qt does not convert one.
                self.pos += 1;
                self.value_at(None, depth + 1)?;
                self.expect(b'>')?;
                match expected {
                    None => Ok(Value::Invalid),
                    Some(_) => Err(Unparsable),
                }
            }
            b'-' | b'+' | b'.' | b'0'..=b'9' => self.number(expected),
            b'a'..=b'z' => {
                let word = self.word(&[]).to_owned();
                match (word.as_str(), expected) {
                    ("true" | "false", None | Some(Kind::Bool)) => Ok(Value::Bool(word == "true")),
                    _ => Err(Unparsable),
                }
            }
            _ => Err(Unparsable),
        }
    }

    /// An optional type annotation (`uint32 5`, `@as []`); the type the
    /// value must then have.
    fn annotation(&mut self, expected: Option<Kind>) -> Parsed<Option<Kind>> {
        let annotated = match self.peek() {
            Some(b'@') => {
                self.pos += 1;
                let start = self.pos;
                while self
                    .text
                    .get(self.pos)
                    .is_some_and(|b| !b.is_ascii_whitespace() && !b",:>]".contains(b))
                {
                    self.pos += 1;
                }
                Some(Kind::from_type_string(&self.text[start..self.pos]).ok_or(Unparsable)?)
            }
            Some(b'a'..=b'z') => {
                let save = self.pos;
                let word = self.word(&[]).to_owned();
                if let Some(kind) = Kind::from_keyword(&word) {
                    Some(kind)
                } else {
                    self.pos = save;
                    None
                }
            }
            _ => None,
        };
        match (annotated, expected) {
            (None, e) => Ok(e),
            (Some(a), None) => Ok(Some(a)),
            (Some(a), Some(e)) if a == e => Ok(Some(e)),
            _ => Err(Unparsable),
        }
    }

    fn string(&mut self) -> Parsed<String> {
        let quote = self.peek().ok_or(Unparsable)?;
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = *self.text.get(self.pos).ok_or(Unparsable)?;
            self.pos += 1;
            if b == quote {
                break;
            }
            if b != b'\\' {
                out.push(b);
                continue;
            }
            let e = *self.text.get(self.pos).ok_or(Unparsable)?;
            self.pos += 1;
            let plain = match e {
                b'u' | b'U' => {
                    let c = self.unicode_escape(if e == b'u' { 4 } else { 8 })?;
                    let mut buf = [0; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    continue;
                }
                b'a' => 0x07,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'v' => 0x0b,
                b'\n' => continue,
                other => other,
            };
            out.push(plain);
        }
        String::from_utf8(out).map_err(|_| Unparsable)
    }

    fn unicode_escape(&mut self, length: usize) -> Parsed<char> {
        let digits = self.text.get(self.pos..self.pos + length).ok_or(Unparsable)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(Unparsable);
        }
        let value = u32::from_str_radix(std::str::from_utf8(digits).map_err(|_| Unparsable)?, 16)
            .map_err(|_| Unparsable)?;
        self.pos += length;
        match char::from_u32(value) {
            Some(c) if value != 0 => Ok(c),
            _ => Err(Unparsable),
        }
    }

    fn number(&mut self, expected: Option<Kind>) -> Parsed<Value> {
        let token = self.word(b"-+.").to_owned();
        let looks_floating = token.contains(['.', 'e', 'E']) && !token.contains(['x', 'X']);
        let kind = match expected {
            Some(kind) => kind,
            None if looks_floating => Kind::Other(Other::Double),
            None => Kind::Int32,
        };
        if kind == Kind::Other(Other::Double) {
            return token.parse::<f64>().map(|_| Value::Invalid).map_err(|_| Unparsable);
        }
        let (negative, digits) = match token.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, token.as_str()),
        };
        let magnitude = strtoull(digits)?;
        let negative = negative && magnitude != 0;
        let fits_signed = |max: u64| magnitude - u64::from(negative) <= max;
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let value = match kind {
            Kind::Int32 if fits_signed(i32::MAX as u64) => {
                Value::Int(if negative { (magnitude as i64).wrapping_neg() as i32 } else { magnitude as i32 })
            }
            Kind::UInt32 if !negative && u32::try_from(magnitude).is_ok() => Value::UInt(magnitude as u32),
            Kind::Int64 if fits_signed(i64::MAX as u64) => {
                Value::LongLong(if negative { (magnitude as i64).wrapping_neg() } else { magnitude as i64 })
            }
            Kind::UInt64 if !negative => Value::ULongLong(magnitude),
            Kind::Other(Other::Byte) if !negative && magnitude <= 0xff => Value::Invalid,
            Kind::Other(Other::UInt16) if !negative && magnitude <= 0xffff => Value::Invalid,
            Kind::Other(Other::Int16) if fits_signed(0x7fff) => Value::Invalid,
            Kind::Other(Other::Handle) if fits_signed(i32::MAX as u64) => Value::Invalid,
            _ => return Err(Unparsable),
        };
        Ok(value)
    }

    fn array(&mut self, expected: Option<Kind>, depth: usize) -> Parsed<Value> {
        // Only arrays of strings convert; an untyped one is `as` when its
        // first item is a string.
        match expected {
            None | Some(Kind::StringArray) => {}
            Some(_) => return Err(Unparsable),
        }
        self.expect(b'[')?;
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            // An empty array needs its type from an annotation.
            return if expected.is_some() { Ok(Value::StringList(items)) } else { Err(Unparsable) };
        }
        loop {
            match self.value_at(Some(Kind::String), depth + 1)? {
                Value::String(s) => items.push(s),
                _ => return Err(Unparsable),
            }
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::StringList(items));
                }
                _ => return Err(Unparsable),
            }
        }
    }

    fn dict(&mut self, expected: Option<Kind>, depth: usize) -> Parsed<Value> {
        match expected {
            None | Some(Kind::VarDict) => {}
            Some(_) => return Err(Unparsable),
        }
        self.expect(b'{')?;
        let mut entries = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return if expected.is_some() { Ok(Value::Map(entries)) } else { Err(Unparsable) };
        }
        loop {
            let Value::String(key) = self.value_at(Some(Kind::String), depth + 1)? else {
                return Err(Unparsable);
            };
            self.expect(b':')?;
            self.expect(b'<')?;
            let value = self.value_at(None, depth + 1)?;
            self.expect(b'>')?;
            entries.push((key, value));
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Map(entries));
                }
                _ => return Err(Unparsable),
            }
        }
    }
}

/// `g_ascii_strtoull(token, &end, 0)` that must use the whole token: an
/// optional sign (a `-` negates modulo 2^64), then hex after `0x`, octal
/// after `0`, else decimal.
fn strtoull(token: &str) -> Parsed<u64> {
    let (negate, rest) = match token.as_bytes().first() {
        Some(b'-') => (true, &token[1..]),
        Some(b'+') => (false, &token[1..]),
        _ => (false, token),
    };
    let (radix, digits) = if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        (16, hex)
    } else if rest.len() > 1 && rest.starts_with('0') {
        (8, &rest[1..])
    } else {
        (10, rest)
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return Err(Unparsable);
    }
    let value = u64::from_str_radix(digits, radix).map_err(|_| Unparsable)?;
    Ok(if negate { value.wrapping_neg() } else { value })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(t: &str, text: &str) -> Value {
        from_db(t.as_bytes(), Some(text.as_bytes()))
    }

    fn s(text: &str) -> Value {
        Value::String(text.to_owned())
    }

    #[test]
    fn strings() {
        assert_eq!(parse("s", "'files.example'"), s("files.example"));
        assert_eq!(parse("s", "\"it's\""), s("it's"));
        assert_eq!(parse("s", r"'a\'b\\c\x'"), s("a'b\\cx"));
        assert_eq!(parse("s", r"'\a\b\f\n\r\t\v'"), s("\u{7}\u{8}\u{c}\n\r\t\u{b}"));
        assert_eq!(parse("s", "'a\\\nb'"), s("ab"));
        assert_eq!(parse("s", r"'é\U0001f600'"), s("é\u{1f600}"));
        // Only a value that starts with a quote is parsed.
        assert_eq!(parse("s", "  'x'  "), s("  'x'  "));
        assert_eq!(parse("s", "string 'x'"), s("string 'x'"));
        assert_eq!(parse("s", "'x'  "), s("x"));
        // Unquoted: taken as it is.
        assert_eq!(parse("s", "plain \\n text"), s("plain \\n text"));
        assert_eq!(parse("s", ""), s(""));
        for bad in ["'x", "'x' 'y'", r"'\u00'", r"'\u0000'", r"'\ud800'", r"'\U00110000'", "'\\"] {
            assert_eq!(parse("s", bad), Value::Invalid, "{bad:?}");
        }
        assert_eq!(from_db(b"s", Some(b"'\xff'")), Value::Invalid);
        assert_eq!(from_db(b"s", Some(b"\xff")), Value::Invalid);
        assert_eq!(from_db(b"s", None), Value::Invalid);
        assert_eq!(from_db(b"", Some(b"'x'")), Value::Invalid);
    }

    #[test]
    fn booleans() {
        assert_eq!(parse("b", "true"), Value::Bool(true));
        assert_eq!(parse("b", "false"), Value::Bool(false));
        assert_eq!(parse("b", "boolean true"), Value::Bool(true));
        for bad in ["1", "True", "'true'", "truex", ""] {
            assert_eq!(parse("b", bad), Value::Invalid, "{bad:?}");
        }
    }

    #[test]
    fn integers() {
        assert_eq!(parse("i", "2222"), Value::Int(2222));
        assert_eq!(parse("i", "-2147483648"), Value::Int(i32::MIN));
        assert_eq!(parse("i", "2147483647"), Value::Int(i32::MAX));
        assert_eq!(parse("i", "0x10"), Value::Int(16));
        assert_eq!(parse("i", "010"), Value::Int(8));
        assert_eq!(parse("i", "+5"), Value::Int(5));
        assert_eq!(parse("i", "-0"), Value::Int(0));
        assert_eq!(parse("i", "int32 7"), Value::Int(7));
        assert_eq!(parse("u", "4294967295"), Value::UInt(u32::MAX));
        assert_eq!(parse("u", "uint32 7"), Value::UInt(7));
        assert_eq!(parse("x", "-9223372036854775808"), Value::LongLong(i64::MIN));
        assert_eq!(parse("x", "int64 3"), Value::LongLong(3));
        assert_eq!(parse("t", "18446744073709551615"), Value::ULongLong(u64::MAX));
        assert_eq!(parse("t", "uint64 3"), Value::ULongLong(3));
        for (t, bad) in [
            ("i", "2147483648"),
            ("i", "-2147483649"),
            ("u", "-1"),
            ("u", "4294967296"),
            ("x", "9223372036854775808"),
            ("t", "-1"),
            ("t", "18446744073709551616"),
            ("i", "08"),
            ("i", "0x"),
            ("i", "1.5"),
            ("i", "uint32 5"),
            ("i", "5 6"),
            ("i", "--5"),
        ] {
            assert_eq!(parse(t, bad), Value::Invalid, "{t} {bad:?}");
        }
    }

    #[test]
    fn string_arrays() {
        assert_eq!(parse("as", "['a', \"b\"]"), Value::StringList(vec!["a".into(), "b".into()]));
        assert_eq!(parse("as", "[]"), Value::StringList(Vec::new()));
        assert_eq!(parse("as", "@as []"), Value::StringList(Vec::new()));
        assert_eq!(parse("as", " [ 'a' ] "), Value::StringList(vec!["a".into()]));
        for bad in ["['a',]", "['a' 'b']", "[1]", "['a'", "'a'", "@ai []"] {
            assert_eq!(parse("as", bad), Value::Invalid, "{bad:?}");
        }
    }

    #[test]
    fn dictionaries() {
        assert_eq!(
            parse("a{sv}", "{'s': <'x'>, 'n': <5>, 'u': <uint32 6>, 'b': <true>, 'l': <['y']>, 'd': <1.5>}"),
            Value::Map(vec![
                ("s".into(), s("x")),
                ("n".into(), Value::Int(5)),
                ("u".into(), Value::UInt(6)),
                ("b".into(), Value::Bool(true)),
                ("l".into(), Value::StringList(vec!["y".into()])),
                ("d".into(), Value::Invalid),
            ])
        );
        assert_eq!(parse("a{sv}", "{}"), Value::Map(Vec::new()));
        assert_eq!(parse("a{sv}", "@a{sv} {}"), Value::Map(Vec::new()));
        assert_eq!(
            parse("a{sv}", "{'m': <{'k': <'v'>}>, 'e': <@as []>, 'v': <<'x'>>, 'o': <objectpath '/a'>}"),
            Value::Map(vec![
                ("m".into(), Value::Map(vec![("k".into(), s("v"))])),
                ("e".into(), Value::StringList(Vec::new())),
                ("v".into(), Value::Invalid),
                ("o".into(), Value::Invalid),
            ])
        );
        for small in ["byte 0xff", "int16 -5", "uint16 5", "handle 1", "double 2"] {
            assert_eq!(
                parse("a{sv}", &format!("{{'k': <{small}>}}")),
                Value::Map(vec![("k".into(), Value::Invalid)])
            );
        }
        for bad in [
            "{'k': 'v'}",
            "{'k' <'v'>}",
            "{5: <1>}",
            "{'k': <[]>}",
            "{'k': <{}>}",
            "{'k': <byte 256>}",
            "{,}",
        ] {
            assert_eq!(parse("a{sv}", bad), Value::Invalid, "{bad:?}");
        }
        let deep = format!("{{'k': {}'x'{}}}", "<".repeat(40), ">".repeat(40));
        assert_eq!(parse("a{sv}", &deep), Value::Invalid);
    }

    #[test]
    fn other_types_are_unsupported() {
        for (t, text) in
            [("d", "1.5"), ("y", "5"), ("o", "'/x'"), ("v", "<'x'>"), ("ai", "[1]"), ("(ss)", "('a', 'b')")]
        {
            assert_eq!(parse(t, text), Value::Invalid, "{t}");
        }
        assert_eq!(parse("(ss)", "garbage"), Value::Invalid);
        assert_eq!(parse("d", "x"), Value::Invalid);
    }

    #[test]
    fn printing_parses_back() {
        for text in ["auth-failed", "it's", "a\"b'c", "back\\slash", "é\u{1f600}\u{7f}\u{1}", "\t\n", ""] {
            let printed = print_string(text);
            assert!(printed.is_ascii());
            assert_eq!(parse("s", &printed), s(text), "{printed}");
        }
        assert_eq!(print_string("auth-failed"), "'auth-failed'");
        assert_eq!(print_string("it's"), "\"it's\"");
        assert_eq!(parse("b", print_bool(true)), Value::Bool(true));
        assert_eq!(parse("b", print_bool(false)), Value::Bool(false));
    }
}
