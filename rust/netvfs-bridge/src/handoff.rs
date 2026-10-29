// SPDX-License-Identifier: LGPL-2.1-or-later
//! The settings handoff (SPEC-v2 XB-15): `OpenAccountSettings`,
//! `AddAccount` and `OpenStorageSettings` call the platform's settings D-Bus
//! interface on the session bus, as a table in `handoff.conf` (QSettings INI
//! syntax) says:
//!
//! ```ini
//! [OpenAccountSettings]
//! Service=com.jolla.settings
//! Path=/com/jolla/settings/ui
//! Interface=com.jolla.settings.ui
//! Method=showAccounts
//! Arguments=
//! ```
//!
//! `Arguments` is a list of typed values `s:text`, `i:42`, `u:42` and
//! `b:true`, with the placeholders `{accountId}` and `{provider}`.

use crate::ini::IniFile;
use crate::status::Status;
use netvfs_bridge_proto::ErrorName;
use std::path::PathBuf;
use zbus::zvariant::{StructureBuilder, Value};

/// The table shipped with the package.
pub const DEFAULT_CONFIG: &str = "/usr/share/netvfs/bridge/handoff.conf";

const OPEN_ACCOUNT_SETTINGS: &str = "OpenAccountSettings";
const ADD_ACCOUNT: &str = "AddAccount";
const OPEN_STORAGE_SETTINGS: &str = "OpenStorageSettings";

/// One argument of a handoff call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandoffArg {
    /// `s:`, D-Bus `s`.
    Str(String),
    /// `i:`, D-Bus `i`.
    Int(i32),
    /// `u:`, D-Bus `u`.
    UInt(u32),
    /// `b:`, D-Bus `b`.
    Bool(bool),
}

/// A method call on the session bus, sent without waiting for a reply.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HandoffCall {
    /// The destination.
    pub service: String,
    /// The object path.
    pub path: String,
    /// The interface.
    pub interface: String,
    /// The method.
    pub method: String,
    /// The arguments, in order.
    pub arguments: Vec<HandoffArg>,
}

/// Sends a resolved call.
pub trait Launcher {
    /// Sends `call`.
    ///
    /// # Errors
    /// `Unsupported` when the call cannot be sent.
    fn launch(&self, call: &HandoffCall) -> Result<(), Status>;
}

/// The handoff table and the launcher of its calls.
#[derive(Debug)]
pub struct Handoff<L> {
    config: PathBuf,
    launcher: L,
}

impl<L: Launcher> Handoff<L> {
    /// The table in `config` (normally [`DEFAULT_CONFIG`]); a missing
    /// file makes every handoff `Unsupported`.
    pub fn new(config: impl Into<PathBuf>, launcher: L) -> Self {
        Self { config: config.into(), launcher }
    }

    /// `OpenAccountSettings(accountId, provider)`.
    ///
    /// # Errors
    /// As [`Self::resolve`] and [`Launcher::launch`].
    pub fn open_account_settings(&self, account_id: i32, provider: &str) -> Result<(), Status> {
        self.run(OPEN_ACCOUNT_SETTINGS, account_id, provider)
    }

    /// `AddAccount(provider)`; `{accountId}` is `0`.
    ///
    /// # Errors
    /// As [`Self::resolve`] and [`Launcher::launch`].
    pub fn add_account(&self, provider: &str) -> Result<(), Status> {
        self.run(ADD_ACCOUNT, 0, provider)
    }

    /// `OpenStorageSettings()`; `{accountId}` is `0` and `{provider}` empty.
    ///
    /// # Errors
    /// As [`Self::resolve`] and [`Launcher::launch`].
    pub fn open_storage_settings(&self) -> Result<(), Status> {
        self.run(OPEN_STORAGE_SETTINGS, 0, "")
    }

    /// Whether the table has a valid `OpenStorageSettings` entry: the
    /// feature `storage-settings` of `GetFeatures` (XB-19).
    #[must_use]
    pub fn offers_storage_settings(&self) -> bool {
        self.resolve(OPEN_STORAGE_SETTINGS, 0, "").is_ok()
    }

    fn run(&self, group: &str, account_id: i32, provider: &str) -> Result<(), Status> {
        self.launcher.launch(&self.resolve(group, account_id, provider)?)
    }

    /// The call of `group`.
    ///
    /// # Errors
    /// `Unsupported` when the file or the entry is missing, `InvalidName`
    /// when the entry or one of its arguments is invalid.
    pub fn resolve(&self, group: &str, account_id: i32, provider: &str) -> Result<HandoffCall, Status> {
        let unconfigured = || Status::new(ErrorName::Unsupported, "No settings handoff is configured");
        if !self.config.exists() {
            return Err(unconfigured());
        }
        let file = IniFile::parse(std::fs::read(&self.config).unwrap_or_default());
        let key = |name: &str| format!("{group}/{name}");
        let mut call = HandoffCall {
            service: file.string(&key("Service")),
            path: file.string(&key("Path")),
            interface: file.string(&key("Interface")),
            method: file.string(&key("Method")),
            arguments: Vec::new(),
        };
        if call.service.is_empty() && call.method.is_empty() {
            return Err(unconfigured());
        }
        if !is_valid_entry(&call) {
            return Err(Status::new(
                ErrorName::InvalidName,
                format!("Invalid settings handoff entry {group}"),
            ));
        }
        for spec in file.string_list(&key("Arguments")) {
            let spec = qt_trimmed(&spec);
            if spec.is_empty() {
                continue; // "Arguments=" is an empty list
            }
            let argument = parse_argument(spec, account_id, provider).ok_or_else(|| {
                Status::new(ErrorName::InvalidName, format!("Invalid settings handoff argument in {group}"))
            })?;
            call.arguments.push(argument);
        }
        Ok(call)
    }
}

fn is_valid_entry(call: &HandoffCall) -> bool {
    is_dbus_name(&call.service, '.')
        && is_dbus_name(&call.interface, '.')
        && is_dbus_name(&call.method, '\0')
        && call.path.strip_prefix('/').is_some_and(|rest| is_dbus_name(rest, '/'))
}

/// 1 to 255 characters of ASCII letters and digits, `_` and `separator`
/// (a coarse check: the bus refuses what is still invalid).
fn is_dbus_name(s: &str, separator: char) -> bool {
    (1..=255).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == separator)
}

/// `QChar::isSpace`.
const fn is_qt_space(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | ' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// `QString::trimmed`.
fn qt_trimmed(s: &str) -> &str {
    s.trim_matches(is_qt_space)
}

fn parse_argument(spec: &str, account_id: i32, provider: &str) -> Option<HandoffArg> {
    let mut chars = spec.chars();
    let kind = chars.next()?;
    let value = chars.as_str().strip_prefix(':')?;
    let value = value.replace("{accountId}", &account_id.to_string()).replace("{provider}", provider);
    match kind {
        's' => Some(HandoffArg::Str(value)),
        'i' => qt_trimmed(&value).parse().ok().map(HandoffArg::Int),
        // QString::toUInt refuses any sign but "+", even "-0".
        'u' => Some(qt_trimmed(&value)).filter(|v| !v.starts_with('-'))?.parse().ok().map(HandoffArg::UInt),
        'b' => match value.as_str() {
            "true" => Some(HandoffArg::Bool(true)),
            "false" => Some(HandoffArg::Bool(false)),
            _ => None,
        },
        _ => None,
    }
}

/// Sends the calls on the session bus without waiting for a reply.
#[derive(Debug)]
pub struct SessionBusLauncher {
    bus: Option<zbus::Connection>,
}

impl SessionBusLauncher {
    /// Sends on `bus`; `None` (no session bus) fails every launch.
    #[must_use]
    pub const fn new(bus: Option<zbus::Connection>) -> Self {
        Self { bus }
    }
}

impl Launcher for SessionBusLauncher {
    /// Builds the message now and sends it on the current tokio runtime.
    fn launch(&self, call: &HandoffCall) -> Result<(), Status> {
        let failed = || Status::new(ErrorName::Unsupported, "Settings cannot be opened");
        let bus = self.bus.clone().ok_or_else(failed)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_e| failed())?;
        let message = method_call(call).map_err(|_e| failed())?;
        runtime.spawn(async move {
            if let Err(e) = bus.send(&message).await {
                crate::log::warning(format_args!("Cannot open the settings: {e}"));
            }
        });
        Ok(())
    }
}

fn method_call(call: &HandoffCall) -> zbus::Result<zbus::Message> {
    let builder = zbus::Message::method_call(call.path.as_str(), call.method.as_str())?
        .destination(call.service.as_str())?
        .interface(call.interface.as_str())?
        .with_flags(zbus::message::Flags::NoReplyExpected)?;
    if call.arguments.is_empty() {
        return builder.build(&());
    }
    let body = call
        .arguments
        .iter()
        .fold(StructureBuilder::new(), |body, argument| {
            body.append_field(match argument {
                HandoffArg::Str(s) => Value::from(s.as_str()),
                HandoffArg::Int(i) => Value::from(*i),
                HandoffArg::UInt(u) => Value::from(*u),
                HandoffArg::Bool(b) => Value::from(*b),
            })
        })
        .build()?;
    builder.build(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, TestBus};
    use std::cell::RefCell;
    use std::path::Path;

    #[derive(Debug, Default)]
    struct Recorder(RefCell<Vec<HandoffCall>>);

    impl Launcher for Recorder {
        fn launch(&self, call: &HandoffCall) -> Result<(), Status> {
            self.0.borrow_mut().push(call.clone());
            Ok(())
        }
    }

    fn table(dir: &TempDir, text: &str) -> Handoff<Recorder> {
        Handoff::new(dir.write("handoff.conf", text), Recorder::default())
    }

    fn entry(arguments: &str) -> String {
        format!(
            "[OpenAccountSettings]\nService=s.x\nPath=/p\nInterface=i.x\nMethod=m\nArguments={arguments}\n"
        )
    }

    fn arguments(text: &str) -> Result<Vec<HandoffArg>, ErrorName> {
        let dir = TempDir::new();
        let handoff = table(&dir, &entry(text));
        handoff.resolve(OPEN_ACCOUNT_SETTINGS, 12, "sftp").map(|c| c.arguments).map_err(|s| s.name)
    }

    #[test]
    fn resolve_table() {
        // tst_BridgeUnits::handoff
        let dir = TempDir::new();
        let missing = Handoff::new(dir.join("handoff.conf"), Recorder::default());
        let status = missing.add_account("sftp").unwrap_err();
        assert_eq!(status.to_string(), "Unsupported: No settings handoff is configured");
        let handoff = table(
            &dir,
            "[OpenAccountSettings]\nService=com.example.settings\nPath=/ui\nInterface=com.example.ui\n\
             Method=showAccount\nArguments=i:{accountId},s:{provider}\n\
             [AddAccount]\nService=com.example.settings\nPath=/ui\nInterface=com.example.ui\n\
             Method=bad method\n",
        );
        handoff.open_account_settings(12, "sftp").unwrap();
        let calls = handoff.launcher.0.borrow().clone();
        assert_eq!(
            calls,
            [HandoffCall {
                service: "com.example.settings".into(),
                path: "/ui".into(),
                interface: "com.example.ui".into(),
                method: "showAccount".into(),
                arguments: vec![HandoffArg::Int(12), HandoffArg::Str("sftp".into())],
            }]
        );
        let status = handoff.add_account("sftp").unwrap_err();
        assert_eq!(status.to_string(), "InvalidName: Invalid settings handoff entry AddAccount");
        assert_eq!(handoff.launcher.0.borrow().len(), 1);

        // The shipped table parses.
        let shipped = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src/bridge/data/handoff.conf");
        let shipped = Handoff::new(shipped, Recorder::default());
        for group in [OPEN_ACCOUNT_SETTINGS, ADD_ACCOUNT] {
            let call = shipped.resolve(group, 1, "sftp").unwrap();
            assert_eq!(
                (call.service.as_str(), call.path.as_str(), call.method.as_str(), call.arguments.len()),
                ("com.jolla.settings", "/com/jolla/settings/ui", "showAccounts", 0)
            );
        }
        // jolla-settings' showPage(path) with the Storage page's entry path.
        assert!(shipped.offers_storage_settings());
        shipped.open_storage_settings().unwrap();
        let storage = shipped.launcher.0.borrow().clone();
        assert_eq!(
            storage,
            [HandoffCall {
                service: "com.jolla.settings".into(),
                path: "/com/jolla/settings/ui".into(),
                interface: "com.jolla.settings.ui".into(),
                method: "showPage".into(),
                arguments: vec![HandoffArg::Str("system_settings/system/storage".into())],
            }]
        );
    }

    #[test]
    fn storage_settings_entry() {
        let dir = TempDir::new();
        // A table without the entry offers no storage settings.
        let accounts_only = table(&dir, &entry(""));
        assert!(!accounts_only.offers_storage_settings());
        let status = accounts_only.open_storage_settings().unwrap_err();
        assert_eq!(status.to_string(), "Unsupported: No settings handoff is configured");
        // An invalid entry neither.
        let invalid = table(&dir, "[OpenStorageSettings]\nService=s.x\nPath=p\nInterface=i.x\nMethod=m\n");
        assert!(!invalid.offers_storage_settings());
        assert_eq!(invalid.open_storage_settings().unwrap_err().name, ErrorName::InvalidName);
        assert!(invalid.launcher.0.borrow().is_empty());
        // Placeholders: no account, no provider.
        let storage = table(
            &dir,
            "[OpenStorageSettings]\nService=s.x\nPath=/p\nInterface=i.x\nMethod=m\nArguments=i:{accountId},s:{provider}\n",
        );
        assert!(storage.offers_storage_settings());
        storage.open_storage_settings().unwrap();
        let calls = storage.launcher.0.borrow().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].arguments, [HandoffArg::Int(0), HandoffArg::Str(String::new())]);
    }

    #[test]
    fn unconfigured_entries() {
        let dir = TempDir::new();
        let handoff = table(&dir, "[OpenAccountSettings]\nPath=/p\nInterface=i\n");
        let unsupported = Status::new(ErrorName::Unsupported, "No settings handoff is configured");
        assert_eq!(handoff.open_account_settings(1, "x").unwrap_err(), unsupported);
        assert_eq!(handoff.add_account("x").unwrap_err(), unsupported);
        // A folder in place of the file reads as empty.
        std::fs::create_dir(dir.join("d")).unwrap();
        let folder = Handoff::new(dir.join("d"), Recorder::default());
        assert_eq!(folder.add_account("x").unwrap_err(), unsupported);
        // Either the service or the method is enough to be configured.
        for text in ["[AddAccount]\nService=s.x\n", "[AddAccount]\nMethod=m\n"] {
            let handoff = table(&dir, text);
            assert_eq!(handoff.add_account("x").unwrap_err().name, ErrorName::InvalidName);
        }
        assert!(handoff.launcher.0.borrow().is_empty());
    }

    #[test]
    fn entry_names() {
        let dir = TempDir::new();
        let check = |service: &str, path: &str, interface: &str, method: &str| {
            let text = format!(
                "[AddAccount]\nService={service}\nPath={path}\nInterface={interface}\nMethod={method}\n"
            );
            table(&dir, &text).resolve(ADD_ACCOUNT, 0, "p").map(|_| ()).map_err(|s| s.name)
        };
        let long = "a".repeat(255);
        let too_long = "a".repeat(256);
        assert_eq!(check("org.x_1", "/a/b_2", "org.y", "M_3"), Ok(()));
        assert_eq!(check(&long, &format!("/{long}"), &long, &long), Ok(()));
        // The method's separator is NUL, as in the C++ (QChar()).
        assert_eq!(check("s", "/p", "i", "a\0b"), Ok(()));
        for (service, path, interface, method) in [
            (too_long.as_str(), "/p", "i", "m"),
            ("s", &*format!("/{too_long}"), "i", "m"),
            ("s", "/p", too_long.as_str(), "m"),
            ("s", "/p", "i", too_long.as_str()),
            (":1.2", "/p", "i", "m"),
            ("s-x", "/p", "i", "m"),
            ("s", "p", "i", "m"),
            ("s", "/", "i", "m"),
            ("s", "/a.b", "i", "m"),
            ("s", "/p", "i/x", "m"),
            ("s", "/p", "", "m"),
            ("s", "/p", "i", "a.b"),
            ("s", "/p", "i", "é"),
            ("", "/p", "i", "m"),
            ("s", "/p", "i", ""),
        ] {
            assert_eq!(
                check(service, path, interface, method),
                Err(ErrorName::InvalidName),
                "{service} {path}"
            );
        }
        let status = table(&dir, &entry("x")).resolve(OPEN_ACCOUNT_SETTINGS, 0, "p").unwrap_err();
        assert_eq!(status.message, "Invalid settings handoff argument in OpenAccountSettings");
    }

    #[test]
    fn argument_values() {
        use HandoffArg::{Bool, Int, Str, UInt};
        assert_eq!(arguments(""), Ok(vec![]));
        assert_eq!(arguments(" , ,"), Ok(vec![]));
        assert_eq!(arguments("s:"), Ok(vec![Str(String::new())]));
        assert_eq!(arguments("s:a:b"), Ok(vec![Str("a:b".into())]));
        assert_eq!(arguments("\"s: a , b\""), Ok(vec![Str(" a , b".into())]));
        assert_eq!(arguments("s:{provider}/{accountId}"), Ok(vec![Str("sftp/12".into())]));
        assert_eq!(arguments("i:{accountId}, u:{accountId}"), Ok(vec![Int(12), UInt(12)]));
        assert_eq!(arguments("i:-2147483648,i:+7,i:007"), Ok(vec![Int(i32::MIN), Int(7), Int(7)]));
        assert_eq!(arguments("u:4294967295,u:+1"), Ok(vec![UInt(u32::MAX), UInt(1)]));
        // QString::toInt trims all of Qt's white space (written as INI escapes).
        assert_eq!(arguments("\"i: \\xa0\\t5\""), Ok(vec![Int(5)]));
        assert_eq!(arguments("\"u:\\x3000\\t5 \""), Ok(vec![UInt(5)]));
        assert_eq!(arguments("b:true,b:false"), Ok(vec![Bool(true), Bool(false)]));
        for bad in [
            "x",
            "s",
            ":s",
            "ss:a",
            "x:1",
            "i:",
            "i:2147483648",
            "i:1.0",
            "i:0x10",
            "i:1 2",
            "u:-0",
            "u:-1",
            "u:4294967296",
            "u:",
            "b:True",
            "b:1",
            "\"b: true\"",
            "s:a,x",
        ] {
            assert_eq!(arguments(bad), Err(ErrorName::InvalidName), "{bad}");
        }
    }

    #[test]
    fn qt_white_space() {
        assert_eq!(
            qt_trimmed(
                "\t\n\u{b}\u{c}\r \u{85}\u{a0}x\u{1680}\u{2000}\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}"
            ),
            "x"
        );
        assert_eq!(qt_trimmed("\u{8}\u{1c}x\u{200b}\u{feff}"), "\u{8}\u{1c}x\u{200b}\u{feff}");
        assert!(!is_qt_space('\u{1fff}') && !is_qt_space('\u{200b}') && !is_qt_space('\u{e}'));
    }

    #[test]
    fn no_bus_no_launch() {
        let call = HandoffCall {
            service: "s.x".into(),
            path: "/p".into(),
            interface: "i.x".into(),
            method: "m".into(),
            arguments: vec![],
        };
        let unsupported = Status::new(ErrorName::Unsupported, "Settings cannot be opened");
        assert_eq!(SessionBusLauncher::new(None).launch(&call).unwrap_err(), unsupported);
    }

    #[tokio::test]
    async fn launches_on_the_bus() {
        let Some(bus) = TestBus::start() else { return };
        let settings = bus.connect().await;
        settings.request_name("com.example.settings").await.unwrap();
        let mut stream = zbus::MessageStream::from(&settings);
        let launcher = SessionBusLauncher::new(Some(bus.connect().await));
        let mut call = HandoffCall {
            service: "com.example.settings".into(),
            path: "/ui".into(),
            interface: "com.example.ui".into(),
            method: "showAccount".into(),
            arguments: vec![
                HandoffArg::Str("sftp".into()),
                HandoffArg::Int(-3),
                HandoffArg::UInt(7),
                HandoffArg::Bool(true),
            ],
        };
        launcher.launch(&call).unwrap();
        call.arguments.clear();
        call.method = "plain".into();
        launcher.launch(&call).unwrap();
        // The bus refuses what the table check lets through.
        call.path = "/a//b".into();
        assert_eq!(launcher.launch(&call).unwrap_err().message, "Settings cannot be opened");

        let mut seen = Vec::new();
        while seen.len() < 2 {
            let message = futures_lite::StreamExt::next(&mut stream).await.unwrap().unwrap();
            let header = message.header();
            if header.member().is_some_and(|m| m == "showAccount" || m == "plain") {
                assert_eq!(header.interface().unwrap().as_str(), "com.example.ui");
                assert_eq!(header.path().unwrap().as_str(), "/ui");
                assert!(header.primary().flags().contains(zbus::message::Flags::NoReplyExpected));
                let signature = message.body().signature().to_string_no_parens();
                seen.push((header.member().unwrap().to_string(), signature));
                if seen.len() == 1 {
                    let body: (String, i32, u32, bool) = message.body().deserialize().unwrap();
                    assert_eq!(body, ("sftp".into(), -3, 7, true));
                }
            }
        }
        assert_eq!(seen, [("showAccount".into(), "siub".into()), ("plain".to_owned(), String::new())]);
    }
}
