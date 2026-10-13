// SPDX-License-Identifier: LGPL-2.1-or-later
//! Logging (SPEC-v2 XB-18, C-16, C-17): the category `netvfs.bridge`, at
//! warning level unless `QT_LOGGING_RULES` says otherwise, every line
//! prefixed with the consumer id: `netvfs.bridge: [lautta] message` on
//! stderr (the journal, under systemd), as Qt's default message handler
//! printed `qCWarning(lcNetVfsBridge) << consumerTag(id) << …`.
//!
//! The rules are read as `QLoggingSettingsParser` and `QLoggingRule` of
//! Qt 5 read `QT_LOGGING_RULES` (design §7: `netvfs.bridge.debug=true`
//! enables debug messages); the rule files Qt also reads
//! (`QT_LOGGING_CONF`, `qtlogging.ini`) are not.
//!
//! C-17 is the callers' part: no secrets at any level; paths, hosts and
//! server text at debug only.

use std::fmt;
use std::io::Write;
use std::sync::OnceLock;

/// The bridge's category.
pub const CATEGORY: &str = "netvfs.bridge";

/// A message level (`QtMsgType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// `qCDebug`.
    Debug,
    /// `qCInfo`.
    Info,
    /// `qCWarning`.
    Warning,
    /// `qCCritical`.
    Critical,
}

impl Level {
    const ALL: [Self; 4] = [Self::Debug, Self::Info, Self::Warning, Self::Critical];

    const fn index(self) -> usize {
        match self {
            Self::Debug => 0,
            Self::Info => 1,
            Self::Warning => 2,
            Self::Critical => 3,
        }
    }
}

/// The bridge's logger: the consumer tag and the enabled levels.
#[derive(Clone, Debug)]
pub struct Logger {
    tag: String,
    enabled: [bool; 4],
}

impl Default for Logger {
    /// No consumer tag, warning and critical enabled.
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl Logger {
    /// The logger of `consumer` (none: no tag), with the `QT_LOGGING_RULES`
    /// value `rules` applied to the default levels.
    #[must_use]
    pub fn new(consumer: Option<&str>, rules: Option<&str>) -> Self {
        // Q_LOGGING_CATEGORY(lcNetVfsBridge, "netvfs.bridge", QtWarningMsg)
        let mut enabled = [false, false, true, true];
        for rule in parse_rules(rules.unwrap_or_default()) {
            for level in Level::ALL {
                if let Some(on) = rule.pass(CATEGORY, level)
                    && let Some(slot) = enabled.get_mut(level.index())
                {
                    *slot = on;
                }
            }
        }
        let tag = consumer.map(|id| format!("[{id}] ")).unwrap_or_default();
        Self { tag, enabled }
    }

    /// Whether messages of `level` are written.
    #[must_use]
    pub fn enabled(&self, level: Level) -> bool {
        self.enabled.get(level.index()).copied().unwrap_or(false)
    }

    /// The line for `message` at `level`, or `None` when the level is off.
    #[must_use]
    pub fn line(&self, level: Level, message: fmt::Arguments<'_>) -> Option<String> {
        self.enabled(level).then(|| format!("{CATEGORY}: {}{message}\n", self.tag))
    }

    /// Writes `message` at `level` to `out` in one write.
    pub fn write_to(&self, out: &mut impl Write, level: Level, message: fmt::Arguments<'_>) {
        if let Some(line) = self.line(level, message) {
            // Nowhere to report a failed log write.
            out.write_all(line.as_bytes()).unwrap_or_default();
        }
    }
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

/// Sets the process's logger, once (main, before anything logs); false if
/// it was set already.
pub fn init(logger: Logger) -> bool {
    LOGGER.set(logger).is_ok()
}

/// The process's logger (the default one before `init`).
#[must_use]
pub fn logger() -> &'static Logger {
    LOGGER.get_or_init(Logger::default)
}

/// Whether the process logs at `level` (to skip building costly text).
#[must_use]
pub fn enabled(level: Level) -> bool {
    logger().enabled(level)
}

/// Logs `message` at `level` on stderr.
pub fn log(level: Level, message: fmt::Arguments<'_>) {
    #[cfg(test)]
    if capture::record(level, message) {
        return;
    }
    logger().write_to(&mut std::io::stderr().lock(), level, message);
}

/// Unit tests read what the code under test logs on their thread, at every
/// level, as `QTest::ignoreMessage` checks the C++ warnings.
#[cfg(test)]
pub(crate) mod capture {
    use super::Level;
    use std::cell::RefCell;
    use std::fmt;

    thread_local! {
        static LINES: RefCell<Option<Vec<(Level, String)>>> = const { RefCell::new(None) };
    }

    /// Records instead of writing while capturing.
    pub(super) fn record(level: Level, message: fmt::Arguments<'_>) -> bool {
        LINES.with_borrow_mut(|lines| lines.as_mut().map(|l| l.push((level, message.to_string()))).is_some())
    }

    /// Starts capturing on this thread, dropping what was captured.
    pub(crate) fn start() {
        LINES.set(Some(Vec::new()));
    }

    /// What was logged since `start`; capturing goes on.
    pub(crate) fn take() -> Vec<(Level, String)> {
        LINES.with_borrow_mut(|lines| lines.as_mut().map(std::mem::take).unwrap_or_default())
    }
}

/// `qCDebug`.
pub fn debug(message: fmt::Arguments<'_>) {
    log(Level::Debug, message);
}

/// `qCInfo`.
pub fn info(message: fmt::Arguments<'_>) {
    log(Level::Info, message);
}

/// `qCWarning`.
pub fn warning(message: fmt::Arguments<'_>) {
    log(Level::Warning, message);
}

/// `qCCritical`.
pub fn critical(message: fmt::Arguments<'_>) {
    log(Level::Critical, message);
}

// ------------------------------------------------------------------ rules

/// Where `*` sits in a rule's category (`QLoggingRule::PatternFlags`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pattern {
    Full,
    /// `prefix*`
    Left,
    /// `*suffix`
    Right,
    /// `*middle*`
    Mid,
}

/// One rule: `<category>[.<level>]=true|false`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Rule {
    category: String,
    pattern: Pattern,
    level: Option<Level>,
    enabled: bool,
}

impl Rule {
    /// `QLoggingRule::parse`; `None` for a `*` inside the category.
    fn parse(pattern: &str, enabled: bool) -> Option<Self> {
        let mut level = None;
        let mut category = pattern;
        for (suffix, l) in [
            (".debug", Level::Debug),
            (".info", Level::Info),
            (".warning", Level::Warning),
            (".critical", Level::Critical),
        ] {
            if let Some(stripped) = pattern.strip_suffix(suffix) {
                level = Some(l);
                category = stripped;
                break;
            }
        }
        let left = category.strip_suffix('*');
        let category_left = left.unwrap_or(category);
        let right = category_left.strip_prefix('*');
        let category = right.unwrap_or(category_left);
        let pattern = match (right.is_some(), left.is_some()) {
            _ if category.contains('*') => return None,
            (true, true) => Pattern::Mid,
            (true, false) => Pattern::Right,
            (false, true) => Pattern::Left,
            (false, false) => Pattern::Full,
        };
        Some(Self { category: category.to_owned(), pattern, level, enabled })
    }

    /// `QLoggingRule::pass`: `Some(enabled)` when the rule applies.
    fn pass(&self, category: &str, level: Level) -> Option<bool> {
        if self.level.is_some_and(|l| l != level) {
            return None;
        }
        let found = category.find(self.category.as_str());
        let applies = match self.pattern {
            Pattern::Full => category == self.category,
            Pattern::Left => found == Some(0),
            // The first occurrence must end the category, as in Qt.
            Pattern::Right => found.is_some() && found == category.len().checked_sub(self.category.len()),
            Pattern::Mid => found.is_some(),
        };
        applies.then_some(self.enabled)
    }
}

/// `QLoggingSettingsParser` over `QT_LOGGING_RULES`: `;` separates lines
/// (implicit `[Rules]` section); malformed rules are skipped.
fn parse_rules(text: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut in_rules = true;
    for line in text.split(['\n', ';']).map(str::trim) {
        if line.len() >= 2 && line.starts_with('[') && line.ends_with(']') {
            let name = line.get(1..line.len().saturating_sub(1)).unwrap_or_default().trim();
            in_rules = name.eq_ignore_ascii_case("rules");
            continue;
        }
        if !in_rules {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        if value.contains('=') {
            continue;
        }
        let enabled = match value.trim() {
            "true" => true,
            "false" => false,
            _ => continue,
        };
        let mut pattern = Vec::new();
        crate::ini::unescape_key(key.trim().as_bytes(), &mut pattern);
        if let Some(rule) = Rule::parse(&String::from_utf16_lossy(&pattern), enabled) {
            rules.push(rule);
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    fn levels(rules: &str) -> [bool; 4] {
        let logger = Logger::new(None, Some(rules));
        Level::ALL.map(|l| logger.enabled(l))
    }

    #[test]
    fn warning_by_default() {
        assert_eq!(levels(""), [false, false, true, true]);
        assert_eq!(Logger::default().enabled, [false, false, true, true]);
    }

    #[test]
    fn rules_as_qt_reads_them() {
        assert_eq!(levels("netvfs.bridge.debug=true"), [true, false, true, true]);
        assert_eq!(levels(" netvfs.bridge.info = true "), [false, true, true, true]);
        assert_eq!(levels("netvfs.bridge=true"), [true, true, true, true]);
        assert_eq!(
            levels("netvfs.bridge.warning=false;netvfs.bridge.critical=false"),
            [false, false, false, false]
        );
        assert_eq!(levels("*.debug=true"), [true, false, true, true]);
        assert_eq!(levels("netvfs.*=true"), [true, true, true, true]);
        assert_eq!(levels("*.bridge.debug=true"), [true, false, true, true]);
        assert_eq!(levels("*vfs.br*.debug=true"), [true, false, true, true]);
        // The later rule wins.
        assert_eq!(levels("netvfs.bridge.debug=true\nnetvfs.*.debug=false"), [false, false, true, true]);
        // Key escapes as in QSettings.
        assert_eq!(levels("netvfs%2Ebridge.debug=true"), [true, false, true, true]);
    }

    #[test]
    fn rules_that_do_not_apply() {
        for rules in [
            "netvfs.bridge.debug=yes",
            "netvfs.bridge.debug=true=x",
            "netvfs.bridgeX.debug=true",
            "netvfs.b*e.debug=true",
            "other.*.debug=true",
            "*.other.debug=true",
            "*.netvfs.debug=true",
            "netvfs.bridge.debug",
            "[Other]\nnetvfs.bridge.debug=true",
            "qt.*.debug=true",
        ] {
            assert_eq!(levels(rules), [false, false, true, true], "{rules:?}");
        }
        assert_eq!(levels("[Other]\n[ rules ]\nnetvfs.bridge.debug=true"), [true, false, true, true]);
        assert_eq!(levels("[]"), [false, false, true, true]);
        // A section needs both brackets.
        assert_eq!(levels("a]\nnetvfs.bridge.debug=true"), [true, false, true, true]);
        assert_eq!(levels("[Other\nnetvfs.bridge.debug=true"), [true, false, true, true]);
        // ';' separates rules like a line end.
        assert_eq!(levels("; netvfs.bridge.debug=true"), [true, false, true, true]);
    }

    #[test]
    fn patterns() {
        let rule = |p: &str| Rule::parse(p, true).unwrap();
        assert_eq!(rule("a.b").pattern, Pattern::Full);
        assert_eq!(rule("a*").pattern, Pattern::Left);
        assert_eq!(rule("*a").pattern, Pattern::Right);
        assert_eq!(rule("*a*").pattern, Pattern::Mid);
        assert_eq!(rule("*").pattern, Pattern::Left);
        assert_eq!(rule("*").category, "");
        assert_eq!(Rule::parse("a*b", true), None);
        assert_eq!(rule("x.critical").level, Some(Level::Critical));
        // Qt matches a right filter at the first occurrence only.
        assert_eq!(rule("*a").pass("a.a", Level::Debug), None);
        assert_eq!(rule("*.a").pass("b.a", Level::Debug), Some(true));
        assert_eq!(rule("*b*").pass("abc", Level::Info), Some(true));
        assert_eq!(rule("*long").pass("g", Level::Info), None);
        assert_eq!(rule("x.debug").pass("x", Level::Info), None);
    }

    #[test]
    fn lines_carry_category_and_tag() {
        let logger = Logger::new(Some("lautta"), Some("netvfs.bridge.debug=true"));
        let mut out = Vec::new();
        logger.write_to(&mut out, Level::Warning, format_args!("Consent {}", "granted"));
        logger.write_to(&mut out, Level::Debug, format_args!("d"));
        logger.write_to(&mut out, Level::Info, format_args!("not shown"));
        assert_eq!(out, b"netvfs.bridge: [lautta] Consent granted\nnetvfs.bridge: [lautta] d\n");
        assert_eq!(Logger::default().line(Level::Critical, format_args!("x")).unwrap(), "netvfs.bridge: x\n");
        assert_eq!(Logger::default().line(Level::Debug, format_args!("x")), None);
    }

    #[test]
    fn process_logger() {
        // init takes once (each test runs in a process of its own under
        // nextest; cargo test may have set the logger already).
        let fresh = LOGGER.get().is_none();
        let first = init(Logger::new(Some("t"), None));
        assert_eq!(first, fresh);
        assert!(!init(Logger::default()));
        if first {
            assert_eq!(logger().tag, "[t] ");
        }
        assert!(enabled(Level::Warning) && !enabled(Level::Debug));
        capture::start();
        warning(format_args!("w {}", 1));
        critical(format_args!("c"));
        info(format_args!("i"));
        debug(format_args!("d"));
        log(Level::Info, format_args!("l"));
        let expected = [
            (Level::Warning, "w 1"),
            (Level::Critical, "c"),
            (Level::Info, "i"),
            (Level::Debug, "d"),
            (Level::Info, "l"),
        ];
        assert_eq!(capture::take(), expected.map(|(l, m)| (l, m.to_owned())));
        assert_eq!(capture::take(), []);
    }
}
