// SPDX-License-Identifier: LGPL-2.1-or-later
//! Files in `QSettings::IniFormat`, read as Qt 5 reads them and edited in
//! place: `bridge.conf` (XB-6, also written by the account UI) and
//! `handoff.conf` (XB-15).
//!
//! Reading follows `qsettings.cpp` of Qt 5 (`readIniLine`, `readIniSection`,
//! `iniUnescapedKey`, `iniUnescapedStringList`, `stringToVariant`): logical
//! lines (quotes and `\` continue them, `;` starts a comment), sections
//! sorted by name and the last definition of a key winning, `%XX`/`%UXXXX`
//! key escapes, `\` escapes and `,` lists in values, `@`-prefixed types. No
//! codec is set, so bytes are Latin-1 unless the file starts with a UTF-8
//! BOM. `@Variant(…)`, `@DateTime(…)`, `@Rect(…)`, `@Size(…)` and `@Point(…)`
//! values are kept as [`IniValue::Other`], which is not a string.
//!
//! Writing changes only the lines of the key it sets or removes and keeps
//! every other byte (unknown groups, keys, comments), where `QSettings`
//! would rewrite the whole file; new lines are escaped as `QSettings`
//! escapes them, so Qt reads back what it would have written.

use std::collections::BTreeMap;

/// A value as `QSettings::value()` returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IniValue {
    /// A `QString` (UTF-16 code units).
    String(Vec<u16>),
    /// A `QStringList` (a value with an unquoted `,`).
    StringList(Vec<Vec<u16>>),
    /// A `QVariantList`: a list with an `@`-typed item.
    List(Vec<Self>),
    /// `@ByteArray(…)`.
    ByteArray(Vec<u8>),
    /// `@Invalid()`.
    Invalid,
    /// `@Variant(…)`, `@DateTime(…)`, `@Rect(…)`, `@Size(…)`, `@Point(…)`.
    Other,
}

impl IniValue {
    /// `QVariant::toString()`.
    #[must_use]
    pub fn to_qstring(&self) -> Vec<u16> {
        match self {
            Self::String(s) => s.clone(),
            Self::StringList(list) => match list.as_slice() {
                [only] => only.clone(),
                _ => Vec::new(),
            },
            // QString::fromUtf8(constData()): up to the first NUL.
            Self::ByteArray(bytes) => {
                let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).encode_utf16().collect()
            }
            Self::List(_) | Self::Invalid | Self::Other => Vec::new(),
        }
    }

    /// `QVariant::toString()`, as UTF-8 (unpaired surrogates replaced).
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.to_qstring())
    }

    /// `QVariant::toStringList()`.
    #[must_use]
    pub fn to_qstring_list(&self) -> Vec<Vec<u16>> {
        match self {
            Self::String(s) => vec![s.clone()],
            Self::StringList(list) => list.clone(),
            Self::List(items) => items.iter().map(Self::to_qstring).collect(),
            Self::ByteArray(_) | Self::Invalid | Self::Other => Vec::new(),
        }
    }
}

/// One logical line of the file.
#[derive(Clone, Debug)]
struct Line {
    /// First byte (after leading white space).
    start: usize,
    /// One past the last byte.
    end: usize,
    kind: LineKind,
}

#[derive(Clone, Debug)]
enum LineKind {
    /// `[name]`: the prefix of its keys, `""` for the general section.
    Section(Vec<u16>),
    /// `key=value`, with the full key (section prefix included).
    Key { key: Vec<u16>, value: IniValue, section: Vec<u16> },
    /// A line without `=`.
    Other,
}

/// A parsed INI file and its bytes.
#[derive(Clone, Debug, Default)]
pub struct IniFile {
    data: Vec<u8>,
    lines: Vec<Line>,
    values: BTreeMap<Vec<u16>, IniValue>,
}

const BOM: &[u8] = b"\xef\xbb\xbf";

impl IniFile {
    /// Parses `data` as Qt 5's `QSettings` does.
    #[must_use]
    pub fn parse(data: Vec<u8>) -> Self {
        let utf8 = data.starts_with(BOM);
        let mut lines = Vec::new();
        let mut section = Vec::new();
        let mut pos = if utf8 { BOM.len() } else { 0 };
        while let Some((line, next)) = read_ini_line(&data, pos) {
            pos = next;
            let kind = classify(&data, &line, &section, utf8);
            if let LineKind::Section(name) = &kind {
                section.clone_from(name);
            }
            lines.push(Line { start: line.start, end: line.end, kind });
        }
        let values = resolve(&lines);
        Self { data, lines, values }
    }

    /// The file's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// The file's bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// `QSettings::value(key)`: `key` is normalised as `QSettings` does
    /// (no leading, trailing or doubled `/`).
    #[must_use]
    pub fn value(&self, key: &str) -> Option<&IniValue> {
        self.values.get(&normalized_key(key))
    }

    /// `value(key).toString()`, as UTF-8.
    #[must_use]
    pub fn string(&self, key: &str) -> String {
        self.value(key).map(IniValue::to_string_lossy).unwrap_or_default()
    }

    /// `value(key).toStringList()`, as UTF-8.
    #[must_use]
    pub fn string_list(&self, key: &str) -> Vec<String> {
        self.value(key)
            .map(|v| v.to_qstring_list().iter().map(|s| String::from_utf16_lossy(s)).collect())
            .unwrap_or_default()
    }

    /// The stored keys, as `QSettings::allKeys()` lists them (raw, sorted).
    pub fn keys(&self) -> impl Iterator<Item = &[u16]> {
        self.values.keys().map(Vec::as_slice)
    }

    /// `QSettings::setValue("<group>/<name>", value)` for a `QString`:
    /// replaces every line defining the key with one line in the last
    /// `[group]` section, which is appended when there is none. An empty
    /// `group` is the general section.
    pub fn set_string(&mut self, group: &str, name: &str, value: &str) {
        self.remove(group, name);
        let utf8 = self.data.starts_with(BOM);
        let mut line = Vec::new();
        escape_key(name, &mut line);
        line.push(b'=');
        let stored = if value.starts_with('@') { format!("@{value}") } else { value.to_owned() };
        escape_string(&stored, utf8, &mut line);
        line.push(b'\n');
        let end = self.section_end(&section_prefix(group));
        let mut data = std::mem::take(&mut self.data);
        if let Some(at) = end {
            let mut insert = Vec::new();
            // `at` ends a header or key line, so it is past the start.
            if !matches!(data.get(at.saturating_sub(1)), Some(b'\n' | b'\r')) {
                insert.push(b'\n');
            }
            insert.extend_from_slice(&line);
            data.splice(at..at, insert);
        } else {
            append_section(&mut data, group, &line);
        }
        *self = Self::parse(data);
    }

    /// `QSettings::remove("<group>/<name>")` for one key: removes the
    /// physical lines of every definition of it.
    pub fn remove(&mut self, group: &str, name: &str) {
        let mut full = section_prefix(group);
        full.extend(name.encode_utf16());
        let mut data = std::mem::take(&mut self.data);
        for line in self.lines.iter().rev() {
            if matches!(&line.kind, LineKind::Key { key, .. } if *key == full) {
                let start = physical_start(&data, line.start);
                let end = physical_end(&data, line.end);
                data.drain(start..end);
            }
        }
        *self = Self::parse(data);
    }

    /// Where a new key of the section with `prefix` goes: after the
    /// physical end of the section's last header or key line.
    fn section_end(&self, prefix: &[u16]) -> Option<usize> {
        let mut current: &[u16] = &[];
        let mut end = None;
        for line in &self.lines {
            match &line.kind {
                LineKind::Section(name) => current = name,
                LineKind::Key { .. } => {}
                LineKind::Other => continue,
            }
            if current == prefix {
                end = Some(physical_end(&self.data, line.end));
            }
        }
        end
    }
}

/// The key prefix of a section: `"<group>/"`, or `""` for the general one.
fn section_prefix(group: &str) -> Vec<u16> {
    let mut prefix: Vec<u16> = group.encode_utf16().collect();
    if !prefix.is_empty() {
        prefix.push(u16::from(b'/'));
    }
    prefix
}

/// Appends `[group]` (an empty one as `[General]`) with `line`, separated
/// from what precedes by an empty line, as `QSettings` separates sections.
fn append_section(data: &mut Vec<u8>, group: &str, line: &[u8]) {
    if !data.strip_prefix(BOM).unwrap_or(data).is_empty() {
        if !matches!(data.last(), Some(b'\n' | b'\r')) {
            data.push(b'\n');
        }
        data.push(b'\n');
    }
    data.push(b'[');
    if group.is_empty() {
        data.extend_from_slice(b"General");
    } else {
        escape_key(group, data);
    }
    data.extend_from_slice(b"]\n");
    data.extend_from_slice(line);
}

/// The start of the physical line holding `pos`.
fn physical_start(data: &[u8], pos: usize) -> usize {
    let before = data.get(..pos).unwrap_or_default();
    let bom = if data.starts_with(BOM) { BOM.len() } else { 0 };
    before.iter().rposition(|b| matches!(b, b'\n' | b'\r')).map_or(bom, |i| i.saturating_add(1)).max(bom)
}

/// One past the line terminator (`\n`, `\r` or `\r\n`) at or after `pos`.
fn physical_end(data: &[u8], pos: usize) -> usize {
    let rest = data.get(pos..).unwrap_or_default();
    let Some(offset) = rest.iter().position(|b| matches!(b, b'\n' | b'\r')) else {
        return data.len();
    };
    let terminator = pos.saturating_add(offset);
    let after = terminator.saturating_add(1);
    if data.get(terminator) == Some(&b'\r') && data.get(after) == Some(&b'\n') {
        after.saturating_add(1)
    } else {
        after
    }
}

/// `QSettingsPrivate::normalizedKey`: no leading, trailing or doubled `/`.
fn normalized_key(key: &str) -> Vec<u16> {
    let parts: Vec<&str> = key.split('/').filter(|p| !p.is_empty()).collect();
    parts.join("/").encode_utf16().collect()
}

/// Every key's value: sections in name order, each in file order, the last
/// definition winning (`readIniFile` keeps unparsed sections in a map).
fn resolve(lines: &[Line]) -> BTreeMap<Vec<u16>, IniValue> {
    let mut keys: Vec<(&[u16], &[u16], &IniValue)> = lines
        .iter()
        .filter_map(|line| match &line.kind {
            LineKind::Key { key, value, section } => Some((section.as_slice(), key.as_slice(), value)),
            _ => None,
        })
        .collect();
    keys.sort_by(|a, b| a.0.cmp(b.0));
    keys.into_iter().map(|(_, key, value)| (key.to_vec(), value.clone())).collect()
}

// ------------------------------------------------------------------ lines

/// `charTraits` Space: `\t`, `\n`, `\r`, space.
const fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// `charTraits` Special.
const fn is_special(b: u8) -> bool {
    matches!(b, b'=' | b'\n' | b'\r' | b'\\' | b'"' | b';')
}

/// A logical line: `[start, end)` and its first `=` outside quotes.
#[derive(Clone, Copy, Debug)]
struct RawLine {
    start: usize,
    end: usize,
    equals: Option<usize>,
}

/// `readIniLine`: the next logical line from `pos`, and where the next one
/// starts; `None` at the end. Qt's case of a line end at the line's start
/// cannot happen here (nor in Qt): the white space skipped before a line
/// and after a comment includes line ends.
fn read_ini_line(data: &[u8], pos: usize) -> Option<(RawLine, usize)> {
    let skipped = data.get(pos..).unwrap_or_default().iter().take_while(|b| is_space(**b)).count();
    let start = pos.saturating_add(skipped);
    let mut scan = LineScan { data, i: start, line_start: start, in_quotes: false, equals: None };
    while let Some(ch) = scan.next_special() {
        if scan.handle(ch) {
            break;
        }
    }
    let line = RawLine { start: scan.line_start, end: scan.i, equals: scan.equals };
    (line.end > line.start).then_some((line, scan.i))
}

struct LineScan<'a> {
    data: &'a [u8],
    i: usize,
    line_start: usize,
    in_quotes: bool,
    equals: Option<usize>,
}

impl LineScan<'_> {
    /// Moves past the next special character and returns it.
    fn next_special(&mut self) -> Option<u8> {
        let rest = self.data.get(self.i..).unwrap_or_default();
        let Some(offset) = rest.iter().position(|b| is_special(*b)) else {
            self.i = self.data.len();
            return None;
        };
        let at = self.i.saturating_add(offset);
        self.i = at.saturating_add(1);
        self.data.get(at).copied()
    }

    /// Handles the special character just passed; true ends the line.
    fn handle(&mut self, ch: u8) -> bool {
        let first = self.i == self.line_start.saturating_add(1);
        match ch {
            b'=' => {
                if !self.in_quotes && self.equals.is_none() {
                    self.equals = Some(self.i.saturating_sub(1));
                }
                false
            }
            b'\\' => {
                self.skip_escaped();
                false
            }
            b'"' => {
                self.in_quotes = !self.in_quotes;
                false
            }
            b';' if first => {
                self.skip_comment();
                false
            }
            // A line end or a comment after the line's start.
            _ => self.end_line(),
        }
    }

    fn end_line(&mut self) -> bool {
        if self.in_quotes {
            return false;
        }
        self.i = self.i.saturating_sub(1);
        true
    }

    /// After `\`: skips the escaped character, and a `\r\n` or `\n\r` pair.
    fn skip_escaped(&mut self) {
        let Some(&first) = self.data.get(self.i) else { return };
        self.i = self.i.saturating_add(1);
        if let Some(&second) = self.data.get(self.i)
            && matches!((first, second), (b'\n', b'\r') | (b'\r', b'\n'))
        {
            self.i = self.i.saturating_add(1);
        }
    }

    /// A `;` comment at the line's start: skipped with the white space
    /// after it, and the line starts again there.
    fn skip_comment(&mut self) {
        let rest = self.data.get(self.i..).unwrap_or_default();
        let comment = rest.iter().take_while(|b| !matches!(b, b'\n' | b'\r')).count();
        let space = rest.get(comment..).unwrap_or_default().iter().take_while(|b| is_space(**b)).count();
        self.i = self.i.saturating_add(comment).saturating_add(space);
        self.line_start = self.i;
    }
}

/// Section header, key line or anything else.
fn classify(data: &[u8], line: &RawLine, section: &[u16], utf8: bool) -> LineKind {
    let text = data.get(line.start..line.end).unwrap_or_default();
    if text.first() == Some(&b'[') {
        return LineKind::Section(section_name(text));
    }
    let Some(equals) = line.equals else { return LineKind::Other };
    let key_bytes = data.get(line.start..equals).unwrap_or_default();
    let key_len = key_bytes
        .len()
        .saturating_sub(key_bytes.iter().rev().take_while(|b| matches!(b, b' ' | b'\t')).count());
    let mut key = section.to_vec();
    unescape_key(key_bytes.get(..key_len).unwrap_or_default(), &mut key);
    let value = data.get(equals.saturating_add(1)..line.end).unwrap_or_default();
    LineKind::Key { key, value: parse_value(value, utf8), section: section.to_vec() }
}

/// `isspace()` of the C locale.
const fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `QByteArray::trimmed()`.
fn trim_qt(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().take_while(|b| is_c_space(**b)).count();
    let rest = bytes.get(start..).unwrap_or_default();
    let end = rest.len().saturating_sub(rest.iter().rev().take_while(|b| is_c_space(**b)).count());
    rest.get(..end).unwrap_or_default()
}

/// The key prefix of a `[…]` line (`text` starts with `[`).
fn section_name(text: &[u8]) -> Vec<u16> {
    let inner = text.get(1..).unwrap_or_default();
    let inner =
        inner.iter().position(|b| *b == b']').map_or(inner, |close| inner.get(..close).unwrap_or_default());
    let name = trim_qt(inner);
    if name.eq_ignore_ascii_case(b"general") {
        return Vec::new();
    }
    let mut prefix = Vec::new();
    if name.eq_ignore_ascii_case(b"%general") {
        prefix.extend(name.iter().skip(1).map(|b| u16::from(*b)));
    } else {
        unescape_key(name, &mut prefix);
    }
    prefix.push(u16::from(b'/'));
    prefix
}

// ------------------------------------------------------------------ keys

/// `iniUnescapedKey`: `\` is `/`, `%XX` and `%UXXXX` are code units,
/// anything else Latin-1.
pub(crate) fn unescape_key(key: &[u8], out: &mut Vec<u16>) {
    let mut i = 0;
    while let Some(&ch) = key.get(i) {
        let (unit, used) = match ch {
            b'\\' => (u16::from(b'/'), 1),
            b'%' => percent_escape(key.get(i..).unwrap_or_default()),
            other => (u16::from(other), 1),
        };
        out.push(unit);
        i = i.saturating_add(used);
    }
}

/// `%XX` or `%UXXXX` at the start of `text`: the unit and the bytes used; a
/// lone `%` when the digits are missing or bad.
fn percent_escape(text: &[u8]) -> (u16, usize) {
    let lone = (u16::from(b'%'), 1);
    let (digits_at, count): (usize, usize) = if text.get(1) == Some(&b'U') { (2, 4) } else { (1, 2) };
    let end = digits_at.saturating_add(count);
    match text.get(digits_at..end).and_then(qt_hex) {
        Some(unit) => (unit, end),
        None => lone,
    }
}

/// `QByteArray::toInt(&ok, 16)` cut to a `QChar`: optional white space and
/// sign, an optional `0x`, then hex digits only.
fn qt_hex(digits: &[u8]) -> Option<u16> {
    let text = digits.get(digits.iter().take_while(|b| is_c_space(**b)).count()..).unwrap_or_default();
    let (negative, text) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, text),
    };
    let text = text.strip_prefix(b"0x").or_else(|| text.strip_prefix(b"0X")).unwrap_or(text);
    if text.is_empty() || !text.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let value = text.iter().fold(0u16, |v, d| v.wrapping_shl(4).wrapping_add(hex_digit(*d)));
    Some(if negative { value.wrapping_neg() } else { value })
}

/// The value of an ASCII hex digit (0 for anything else).
fn hex_digit(d: u8) -> u16 {
    char::from(d).to_digit(16).and_then(|v| u16::try_from(v).ok()).unwrap_or(0)
}

/// `iniEscapedKey`: `/` as `\`, `[A-Za-z0-9_.-]` as is, `%XX` up to 0xff,
/// `%UXXXX` above (upper-case hex).
fn escape_key(key: &str, out: &mut Vec<u8>) {
    for unit in key.encode_utf16() {
        match u8::try_from(unit) {
            Ok(b'/') => out.push(b'\\'),
            Ok(b) if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.') => out.push(b),
            Ok(b) => out.extend_from_slice(format!("%{b:02X}").as_bytes()),
            Err(_) => out.extend_from_slice(format!("%U{unit:04X}").as_bytes()),
        }
    }
}

// ------------------------------------------------------------------ values

/// `iniEscapedString` without a codec (or with UTF-8 for a file with a
/// BOM): `\` escapes, `\xNN` for control and (without a codec) non-ASCII
/// code units, quotes around a value with `;`, `,` or `=`, or a space at
/// either end.
fn escape_string(value: &str, utf8: bool, out: &mut Vec<u8>) {
    let start = out.len();
    let mut needs_quotes = false;
    let mut escape_next_if_digit = false;
    for c in value.chars() {
        let ascii = u8::try_from(c).ok().filter(u8::is_ascii);
        needs_quotes |= matches!(ascii, Some(b';' | b',' | b'='));
        if escape_next_if_digit && ascii.is_some_and(|b| b.is_ascii_hexdigit()) {
            out.extend_from_slice(format!("\\x{:x}", u32::from(c)).as_bytes());
            continue;
        }
        escape_next_if_digit = match ascii {
            Some(b) => escape_ascii(b, utf8, out),
            None if utf8 => {
                out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
                false
            }
            None => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.extend_from_slice(format!("\\x{unit:x}").as_bytes());
                }
                true
            }
        };
    }
    let written = out.get(start..).unwrap_or_default();
    if needs_quotes || written.first() == Some(&b' ') || written.last() == Some(&b' ') {
        out.insert(start, b'"');
        out.push(b'"');
    }
}

/// One ASCII character of `iniEscapedString`; true when a following hex
/// digit must be escaped too.
fn escape_ascii(b: u8, utf8: bool, out: &mut Vec<u8>) -> bool {
    let named = match b {
        0x07 => Some(b'a'),
        0x08 => Some(b'b'),
        0x0c => Some(b'f'),
        b'\n' => Some(b'n'),
        b'\r' => Some(b'r'),
        b'\t' => Some(b't'),
        0x0b => Some(b'v'),
        b'"' | b'\\' => Some(b),
        _ => None,
    };
    if let Some(code) = named {
        out.extend_from_slice(&[b'\\', code]);
        return false;
    }
    if b == 0 {
        out.extend_from_slice(b"\\0");
        return true;
    }
    if b <= 0x1f || (b == 0x7f && !utf8) {
        out.extend_from_slice(format!("\\x{b:x}").as_bytes());
        return true;
    }
    out.push(b);
    false
}

/// A value's text: `iniUnescapedStringList`, then `stringToVariant` or
/// `stringListToVariantList`.
fn parse_value(text: &[u8], utf8: bool) -> IniValue {
    let mut scan = ValueScan::new(text, utf8);
    scan.run();
    match scan.list {
        Some(mut list) => {
            list.push(scan.result);
            list_value(list)
        }
        None => string_value(scan.result),
    }
}

/// `stringListToVariantList`.
fn list_value(mut list: Vec<Vec<u16>>) -> IniValue {
    let at = u16::from(b'@');
    if list.iter().any(|s| s.first() == Some(&at) && s.get(1) != Some(&at)) {
        return IniValue::List(list.into_iter().map(string_value).collect());
    }
    for s in &mut list {
        if s.first() == Some(&at) {
            s.remove(0);
        }
    }
    IniValue::StringList(list)
}

/// `stringToVariant`.
fn string_value(s: Vec<u16>) -> IniValue {
    let text = String::from_utf16_lossy(&s);
    if !text.starts_with('@') {
        return IniValue::String(s);
    }
    if text.ends_with(')')
        && let Some(value) = typed_value(&s, &text)
    {
        return value;
    }
    if text.starts_with("@@") {
        return IniValue::String(s.get(1..).unwrap_or_default().to_vec());
    }
    IniValue::String(s)
}

/// An `@Type(…)` value, or `None` when it is a plain string after all.
fn typed_value(s: &[u16], text: &str) -> Option<IniValue> {
    let inner = |open: usize| s.get(open..s.len().saturating_sub(1)).unwrap_or_default();
    if text.starts_with("@ByteArray(") {
        // QString::toLatin1(): '?' for what Latin-1 cannot hold.
        let bytes = inner(11).iter().map(|u| u8::try_from(*u).unwrap_or(b'?')).collect();
        return Some(IniValue::ByteArray(bytes));
    }
    if text.starts_with("@String(") {
        return Some(IniValue::String(inner(8).to_vec()));
    }
    if text.starts_with("@Variant(") || text.starts_with("@DateTime(") {
        return Some(IniValue::Other);
    }
    for (prefix, arguments) in [("@Rect(", 4), ("@Size(", 2), ("@Point(", 2)] {
        if text.starts_with(prefix) {
            // splitArgs: one argument per ' ' and per ')'.
            let open = prefix.encode_utf16().count();
            let found = s.iter().skip(open).filter(|u| matches!(u8::try_from(**u), Ok(b' ' | b')'))).count();
            return (found == arguments).then_some(IniValue::Other);
        }
    }
    (text == "@Invalid()").then_some(IniValue::Invalid)
}

/// The state machine of `iniUnescapedStringList`.
struct ValueScan<'a> {
    text: &'a [u8],
    i: usize,
    utf8: bool,
    result: Vec<u16>,
    list: Option<Vec<Vec<u16>>>,
    in_quotes: bool,
    quoted: bool,
    chop_limit: usize,
}

/// Where `iniUnescapedStringList` goes next.
enum Next {
    SkipSpaces,
    Normal,
    Hex(u16),
    Octal(u16),
    End,
}

impl<'a> ValueScan<'a> {
    fn new(text: &'a [u8], utf8: bool) -> Self {
        Self {
            text,
            i: 0,
            utf8,
            result: Vec::new(),
            list: None,
            in_quotes: false,
            quoted: false,
            chop_limit: 0,
        }
    }

    fn run(&mut self) {
        let mut next = Next::SkipSpaces;
        loop {
            next = match next {
                Next::SkipSpaces => {
                    self.skip_spaces();
                    Next::Normal
                }
                Next::Normal => self.normal(),
                Next::Hex(value) => self.number(value, 4),
                Next::Octal(value) => self.number(value, 3),
                Next::End => return,
            };
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.i).copied()
    }

    fn bump(&mut self) {
        self.i = self.i.saturating_add(1);
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.bump();
        }
    }

    /// `StNormal`.
    fn normal(&mut self) -> Next {
        self.chop_limit = self.result.len();
        while let Some(ch) = self.peek() {
            let next = match ch {
                b'\\' => self.escape(),
                b'"' => self.quote(),
                b',' if !self.in_quotes => Some(self.comma()),
                _ => {
                    self.run_of_text();
                    None
                }
            };
            if let Some(next) = next {
                return next;
            }
        }
        if !self.quoted {
            self.chop_trailing_spaces();
        }
        Next::End
    }

    /// After a `\`.
    fn escape(&mut self) -> Option<Next> {
        self.bump();
        let Some(ch) = self.peek() else { return Some(Next::End) };
        self.bump();
        if let Some(unit) = simple_escape(ch) {
            self.result.push(unit);
            return Some(Next::Normal);
        }
        match ch {
            b'x' => match self.peek() {
                None => return Some(Next::End),
                Some(d) if d.is_ascii_hexdigit() => return Some(Next::Hex(0)),
                Some(_) => {}
            },
            b'0'..=b'7' => return Some(Next::Octal(u16::from(ch.wrapping_sub(b'0')))),
            b'\n' | b'\r' => {
                if let Some(second) = self.peek()
                    && matches!(second, b'\n' | b'\r')
                    && second != ch
                {
                    self.bump();
                }
            }
            // Any other escaped character is dropped.
            _ => {}
        }
        self.chop_limit = self.result.len();
        None
    }

    fn quote(&mut self) -> Option<Next> {
        self.bump();
        self.quoted = true;
        self.in_quotes = !self.in_quotes;
        (!self.in_quotes).then_some(Next::SkipSpaces)
    }

    fn comma(&mut self) -> Next {
        if !self.quoted {
            self.chop_trailing_spaces();
        }
        self.list.get_or_insert_with(Vec::new).push(std::mem::take(&mut self.result));
        self.quoted = false;
        self.bump();
        Next::SkipSpaces
    }

    /// Text up to the next `\`, `"` or `,`, through the codec.
    fn run_of_text(&mut self) {
        let rest = self.text.get(self.i..).unwrap_or_default();
        let len = rest
            .iter()
            .skip(1)
            .position(|b| matches!(b, b'\\' | b'"' | b','))
            .map_or(rest.len(), |p| p.saturating_add(1));
        let chunk = rest.get(..len).unwrap_or_default();
        if self.utf8 {
            self.result.extend(String::from_utf8_lossy(chunk).encode_utf16());
        } else {
            self.result.extend(chunk.iter().map(|b| u16::from(*b)));
        }
        self.i = self.i.saturating_add(len);
    }

    /// `StHexEscape` (4 bits per digit) and `StOctEscape` (3 bits).
    fn number(&mut self, mut value: u16, bits: u32) -> Next {
        while let Some(digit) = self.peek().and_then(|d| char::from(d).to_digit(1 << bits)) {
            value = value.wrapping_shl(bits).wrapping_add(u16::try_from(digit).unwrap_or(0));
            self.bump();
        }
        self.result.push(value);
        if self.peek().is_some() { Next::Normal } else { Next::End }
    }

    /// `iniChopTrailingSpaces`.
    fn chop_trailing_spaces(&mut self) {
        let keep = self.result.iter().rposition(|u| !matches!(u8::try_from(*u), Ok(b' ' | b'\t')));
        let keep = keep.map_or(0, |p| p.saturating_add(1)).max(self.chop_limit);
        self.result.truncate(keep);
    }
}

/// The one-character escapes of `iniUnescapedStringList`.
fn simple_escape(ch: u8) -> Option<u16> {
    let unit = match ch {
        b'a' => 0x07,
        b'b' => 0x08,
        b'f' => 0x0c,
        b'n' => 0x0a,
        b'r' => 0x0d,
        b't' => 0x09,
        b'v' => 0x0b,
        b'"' | b'?' | b'\'' | b'\\' => u16::from(ch),
        _ => return None,
    };
    Some(unit)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fmt::Write as _;

    const EDGE: &[u8] = include_bytes!("../tests/data/qsettings/edge.conf");
    const EDGE_DUMP: &str = include_str!("../tests/data/qsettings/edge.dump");
    const BRIDGE_QT: &[u8] = include_bytes!("../tests/data/qsettings/bridge-qt.conf");
    const BRIDGE_QT_DUMP: &str = include_str!("../tests/data/qsettings/bridge-qt.dump");
    const HANDOFF: &[u8] = include_bytes!("../../../src/bridge/data/handoff.conf");
    const HANDOFF_DUMP: &str = include_str!("../tests/data/qsettings/handoff.dump");

    fn utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// As qsettings-golden.cpp escapes: printable ASCII but `\` and `|`.
    fn escaped(units: &[u16]) -> String {
        units
            .iter()
            .map(|u| match u8::try_from(*u) {
                Ok(b) if (0x20..0x7f).contains(&b) && b != b'\\' && b != b'|' => char::from(b).to_string(),
                _ => format!("\\u{u:04x}"),
            })
            .collect()
    }

    fn type_name(value: Option<&IniValue>) -> &'static str {
        match value {
            Some(IniValue::String(_)) => "QString",
            Some(IniValue::StringList(_)) => "QStringList",
            Some(IniValue::List(_)) => "QVariantList",
            Some(IniValue::ByteArray(_)) => "QByteArray",
            Some(IniValue::Other) => "other",
            Some(IniValue::Invalid) | None => "invalid",
        }
    }

    /// The dump of qsettings-golden.cpp, from our reading.
    pub(crate) fn dump(file: &IniFile) -> String {
        let mut out = String::new();
        for key in file.keys() {
            let value = file.value(&String::from_utf16_lossy(key));
            let list = value.map(IniValue::to_qstring_list).unwrap_or_default();
            let string = value.map(IniValue::to_qstring).unwrap_or_default();
            write!(out, "{}|{}|{}|{}", escaped(key), type_name(value), escaped(&string), list.len()).unwrap();
            for item in &list {
                out.push('|');
                out.push_str(&escaped(item));
            }
            out.push('\n');
        }
        out
    }

    /// Qt's dump without its status line, with the types we do not decode
    /// as "other".
    pub(crate) fn qt_dump(text: &str) -> String {
        text.lines()
            .filter(|l| !l.starts_with("status|"))
            .map(|l| {
                let mut fields: Vec<&str> = l.split('|').collect();
                if let Some(t) = fields.get_mut(1)
                    && ["QSize", "QRect", "QPoint", "QDateTime"].contains(t)
                {
                    *t = "other";
                }
                fields.join("|") + "\n"
            })
            .collect()
    }

    #[test]
    fn reads_what_qt_reads() {
        for (data, expected) in [(EDGE, EDGE_DUMP), (BRIDGE_QT, BRIDGE_QT_DUMP), (HANDOFF, HANDOFF_DUMP)] {
            assert_eq!(dump(&IniFile::parse(data.to_vec())), qt_dump(expected));
        }
    }

    #[test]
    fn escaped_line_ends_and_comments() {
        // Qt's dump of the same file (qsettings-golden dump).
        let text = b"k=a\\\r\nb\nl=c\\\n\rd\nm=e\\\nf\n; n=x\n  ;o=y\np=q;r\n";
        let expected = "k|QString|ab|1|ab\nl|QString|cd|1|cd\nm|QString|ef|1|ef\np|QString|q|1|q\n";
        let file = IniFile::parse(text.to_vec());
        assert_eq!(dump(&file), expected);
        assert_eq!(file.clone().into_bytes(), file.as_bytes());
        assert_eq!(file.into_bytes(), text);
    }

    #[test]
    fn lookups_normalise_the_key() {
        let file = IniFile::parse(b"[Consent]\nlautta=granted\nl=a, b\n".to_vec());
        assert_eq!(file.string("Consent/lautta"), "granted");
        assert_eq!(file.string("/Consent//lautta/"), "granted");
        assert_eq!(file.string("Consent/other"), "");
        assert_eq!(file.value("Consent/other"), None);
        assert_eq!(file.string_list("Consent/l"), ["a", "b"]);
        assert_eq!(file.string_list("Consent/lautta"), ["granted"]);
        assert_eq!(file.string_list("nothing").len(), 0);
        assert_eq!(file.as_bytes(), b"[Consent]\nlautta=granted\nl=a, b\n");
    }

    #[test]
    fn utf8_after_a_bom() {
        let file = IniFile::parse(b"\xef\xbb\xbf[Consent]\nlautta=gr\xc3\xa4nted\n".to_vec());
        assert_eq!(file.string("Consent/lautta"), "gr\u{e4}nted");
        let latin = IniFile::parse(b"[Consent]\nlautta=gr\xc3\xa4nted\n".to_vec());
        assert_eq!(latin.string("Consent/lautta"), "gr\u{c3}\u{a4}nted");
    }

    #[test]
    fn conversions_follow_qvariant() {
        let s = |t: &str| IniValue::String(utf16(t));
        assert_eq!(IniValue::StringList(vec![utf16("one")]).to_string_lossy(), "one");
        assert_eq!(IniValue::StringList(vec![utf16("a"), utf16("b")]).to_string_lossy(), "");
        assert_eq!(
            IniValue::List(vec![s("a"), IniValue::Invalid]).to_qstring_list(),
            [utf16("a"), Vec::new()]
        );
        assert_eq!(IniValue::List(vec![s("a")]).to_string_lossy(), "");
        assert_eq!(IniValue::ByteArray(b"ok\0more".to_vec()).to_string_lossy(), "ok");
        assert_eq!(IniValue::ByteArray(b"ok".to_vec()).to_qstring_list().len(), 0);
        for v in [IniValue::Invalid, IniValue::Other] {
            assert_eq!(v.to_string_lossy(), "");
            assert_eq!(v.to_qstring_list().len(), 0);
        }
        assert_eq!(string_value(utf16("@ByteArray(\u{20ac}x)")), IniValue::ByteArray(b"?x".to_vec()));
        assert_eq!(string_value(utf16("@Foo(x)")), s("@Foo(x)"));
        assert_eq!(string_value(utf16("@@Size(1 2)")), s("@Size(1 2)"));
        assert_eq!(string_value(utf16("@Invalid( )")), s("@Invalid( )"));
        assert_eq!(string_value(utf16("@DateTime(x)")), IniValue::Other);
        assert_eq!(string_value(utf16("@Variant(x)")), IniValue::Other);
    }

    /// The lines QSettings wrote into bridge-qt.conf, from our escaping.
    #[test]
    fn escapes_as_qsettings_writes() {
        let line = |key: &str, value: &str| {
            let mut out = Vec::new();
            escape_key(key, &mut out);
            out.push(b'=');
            let stored = if value.starts_with('@') { format!("@{value}") } else { value.to_owned() };
            escape_string(&stored, false, &mut out);
            String::from_utf8(out).unwrap()
        };
        let written = String::from_utf8_lossy(BRIDGE_QT).into_owned();
        for expected in [
            line("odd key", "with, comma; and = signs"),
            line("top", "@at start"),
            line("unicode", "\u{e4}\u{20ac}\u{1}x"),
            line("k\u{4e00}", "v"),
            line("lautta", "granted"),
        ] {
            assert!(written.lines().any(|l| l == expected), "{expected:?} not in\n{written}");
        }
        let mut header = Vec::new();
        escape_key("Weird\u{e4}", &mut header);
        assert_eq!(header, b"Weird%E4");
        let mut key = Vec::new();
        escape_key("a/b_c-d.e%", &mut key);
        assert_eq!(key, b"a\\b_c-d.e%25");
    }

    #[test]
    fn escapes_values() {
        let escape = |value: &str, utf8: bool| {
            let mut out = Vec::new();
            escape_string(value, utf8, &mut out);
            String::from_utf8(out).unwrap()
        };
        assert_eq!(escape("\u{7}\u{8}\u{c}\n\r\t\u{b}\"\\", false), "\\a\\b\\f\\n\\r\\t\\v\\\"\\\\");
        assert_eq!(escape("\0a\0g", false), "\\0\\x61\\0g");
        assert_eq!(escape("\u{1}1\u{7f}f", false), "\\x1\\x31\\x7f\\x66");
        assert_eq!(escape("\u{e4}a\u{1f600}", false), "\\xe4\\x61\\xd83d\\xde00");
        assert_eq!(escape("\u{e4}a\u{7f}", true), "\u{e4}a\u{7f}");
        assert_eq!(escape(" lead", false), "\" lead\"");
        assert_eq!(escape("trail ", false), "\"trail \"");
        assert_eq!(escape("a=b", false), "\"a=b\"");
        assert_eq!(escape("a;b", false), "\"a;b\"");
        assert_eq!(escape("a,b", false), "\"a,b\"");
        assert_eq!(escape("in side", false), "in side");
        assert_eq!(escape("", false), "");
    }

    #[test]
    fn set_replaces_in_place_and_keeps_everything_else() {
        let mut file = IniFile::parse(
            b"; comment\r\n[Ui]\r\nx=1\r\n[Consent]\r\nlautta=denied ; old\r\nphotos=granted\r\n\r\n[Other]\r\ny=2"
                .to_vec(),
        );
        file.set_string("Consent", "lautta", "granted");
        assert_eq!(
            file.as_bytes(),
            b"; comment\r\n[Ui]\r\nx=1\r\n[Consent]\r\nphotos=granted\r\nlautta=granted\n\r\n[Other]\r\ny=2"
        );
        file.set_string("Other", "z", "@3");
        assert!(file.as_bytes().ends_with(b"[Other]\r\ny=2\nz=@@3\n"));
        assert_eq!(file.string("Other/z"), "@3");
        file.remove("Consent", "photos");
        file.remove("Consent", "absent");
        assert_eq!(
            file.as_bytes(),
            b"; comment\r\n[Ui]\r\nx=1\r\n[Consent]\r\nlautta=granted\n\r\n[Other]\r\ny=2\nz=@@3\n"
        );
    }

    #[test]
    fn set_removes_every_definition() {
        // The key in two [Consent] sections and as Consent\lautta in
        // [General]; the new line goes to the last [Consent].
        let mut file = IniFile::parse(
            b"Consent\\lautta=a\n[Consent]\nlautta=b\n[X]\nk=v\n[Consent]\nlau%74ta=c\nq=\"multi\nline\"\n"
                .to_vec(),
        );
        assert_eq!(file.string("Consent/lautta"), "c");
        file.set_string("Consent", "lautta", "granted");
        assert_eq!(file.as_bytes(), b"[Consent]\n[X]\nk=v\n[Consent]\nq=\"multi\nline\"\nlautta=granted\n");
        assert_eq!(file.string("Consent/lautta"), "granted");
        assert_eq!(file.string("Consent/q"), "multi\nline");
    }

    #[test]
    fn set_appends_a_section() {
        let mut empty = IniFile::default();
        empty.set_string("Consent", "lautta", "granted");
        assert_eq!(empty.as_bytes(), include_bytes!("../tests/data/qsettings/fresh.conf"));
        let mut unterminated = IniFile::parse(b"[A]\nk=v".to_vec());
        unterminated.set_string("Consent", "x", "y");
        assert_eq!(unterminated.as_bytes(), b"[A]\nk=v\n\n[Consent]\nx=y\n");
        let mut terminated = IniFile::parse(b"[A]\nk=v\n".to_vec());
        terminated.set_string("Con/sent", "x", "y");
        assert_eq!(terminated.as_bytes(), b"[A]\nk=v\n\n[Con\\sent]\nx=y\n");
        assert_eq!(terminated.string("Con/sent/x"), "y");
        // Into a section whose last line ends the file without a newline.
        let mut last = IniFile::parse(b"[Consent]\na=b".to_vec());
        last.set_string("Consent", "x", "y");
        assert_eq!(last.as_bytes(), b"[Consent]\na=b\nx=y\n");
    }

    #[test]
    fn general_section() {
        let mut top = IniFile::parse(b"a=1\n[S]\nb=2\n".to_vec());
        top.set_string("", "c", "3");
        assert_eq!(top.as_bytes(), b"a=1\nc=3\n[S]\nb=2\n");
        let mut none = IniFile::parse(b"[S]\nb=2\n".to_vec());
        none.set_string("", "c", "3");
        assert_eq!(none.as_bytes(), b"[S]\nb=2\n\n[General]\nc=3\n");
        assert_eq!(none.string("c"), "3");
        let mut bom = IniFile::parse(b"\xef\xbb\xbfa=1\n".to_vec());
        bom.remove("", "a");
        assert_eq!(bom.as_bytes(), b"\xef\xbb\xbf");
        bom.set_string("", "u", "\u{e4}");
        assert_eq!(bom.as_bytes(), "\u{feff}[General]\nu=\u{e4}\n".as_bytes());
        assert_eq!(bom.string("u"), "\u{e4}");
    }

    #[test]
    fn line_ends() {
        assert_eq!(physical_end(b"a\r\nb", 1), 3);
        assert_eq!(physical_end(b"a\n\rb", 1), 2);
        assert_eq!(physical_end(b"a\rb", 1), 2);
        assert_eq!(physical_end(b"ab", 1), 2);
        assert_eq!(physical_start(b"x\ny", 2), 2);
        assert_eq!(physical_start(b"x\ry", 2), 2);
        assert_eq!(physical_start(b"xy", 1), 0);
        // An old Mac file.
        let file = IniFile::parse(b"[S]\ra=1\rb=2\r".to_vec());
        assert_eq!((file.string("S/a").as_str(), file.string("S/b").as_str()), ("1", "2"));
    }

    #[test]
    fn hex_digits() {
        assert_eq!(qt_hex(b"4a"), Some(0x4a));
        assert_eq!(qt_hex(b"\x0b 1"), Some(1));
        assert_eq!(qt_hex(b"-1"), Some(0xffff));
        assert_eq!(qt_hex(b"0X1f"), Some(0x1f));
        for bad in [&b""[..], b"0x", b"1 ", b"g1", b"+"] {
            assert_eq!(qt_hex(bad), None, "{bad:?}");
        }
        assert_eq!(normalized_key("//a///b/"), utf16("a/b"));
    }
}
