// SPDX-License-Identifier: LGPL-2.1-or-later
//! The Files slice of src/core/servicepolicy.cpp (SPEC-v2 XA-4, XA-7) and
//! `ConnectionParams` (src/core/types.h).

use crate::qvariant::{trimmed, QString, Value};
use crate::wire::{Error, Outcome};

/// `ConnectionParams`: what a connection to the account needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionParams {
    pub provider: QString,
    pub host: QString,
    pub port: i32,
    pub username: QString,
    /// `netvfs/<provider>/<key>` settings by `<key>`.
    pub options: Vec<(String, Value)>,
    pub connect_timeout_ms: i32,
    pub request_timeout_ms: i32,
}

impl Default for ConnectionParams {
    fn default() -> Self {
        Self {
            provider: None,
            host: None,
            port: 0,
            username: None,
            options: Vec::new(),
            // SPEC C-14
            connect_timeout_ms: 15_000,
            request_timeout_ms: 60_000,
        }
    }
}

impl ConnectionParams {
    fn raw(&self, key: &str) -> Option<&Value> {
        self.options.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// `option(key, fallback)`: the fallback only for a missing key.
    #[must_use]
    pub fn option(&self, key: &str, fallback: &str) -> QString {
        match self.raw(key) {
            Some(v) => v.to_qstring(),
            None => Some(fallback.to_owned()),
        }
    }

    /// `flag(key, fallback)`: "true" or "1"; the fallback for a missing or
    /// invalid value.
    #[must_use]
    pub fn flag(&self, key: &str, fallback: bool) -> bool {
        match self.raw(key) {
            None | Some(Value::Invalid) => fallback,
            Some(v) => matches!(v.to_qstring().as_deref(), Some("true" | "1")),
        }
    }

    fn is_smb(&self) -> bool {
        self.provider.as_deref() == Some(PROVIDER_SMB)
    }
}

pub mod option_keys {
    pub const AUTH_MODE: &str = "auth_mode";
    pub const SECURITY_PROFILE: &str = "security_profile";
    pub const REQUIRE_ENCRYPTION: &str = "require_encryption";
    pub const TLS: &str = "tls";
    pub const TLS_MODE: &str = "tls_mode";
    pub const ALLOW_INSECURE: &str = "allow_insecure";
}

pub mod security_profiles {
    pub const STRICT: &str = "strict";
    pub const SIGNED: &str = "signed";
    pub const LEGACY: &str = "legacy";
    pub const GUEST: &str = "guest";
}

const PROVIDER_SMB: &str = "smb";
const PROVIDER_WEBDAV: &str = "webdav";
const PROVIDER_FTP: &str = "ftp";
const AUTH_INTERACTIVE: &str = "interactive";

/// `securityProfile()`: the SMB profile in effect, `None` for other providers.
#[must_use]
pub fn security_profile(params: &ConnectionParams) -> QString {
    if !params.is_smb() {
        return None;
    }
    let profile = trimmed(&params.option(option_keys::SECURITY_PROFILE, ""));
    if profile.as_deref().is_some_and(|p| !p.is_empty()) {
        return profile;
    }
    // M-3 (v1): require_encryption, default true.
    let strict = params.flag(option_keys::REQUIRE_ENCRYPTION, true);
    Some(if strict { security_profiles::STRICT } else { security_profiles::SIGNED }.to_owned())
}

fn is_known_profile(profile: Option<&str>) -> bool {
    use security_profiles::{GUEST, LEGACY, SIGNED, STRICT};
    matches!(profile, Some(STRICT | SIGNED | LEGACY | GUEST))
}

/// `isInsecureConfiguration()`.
#[must_use]
pub fn is_insecure_configuration(params: &ConnectionParams) -> bool {
    match params.provider.as_deref() {
        Some(PROVIDER_WEBDAV) => params.option(option_keys::TLS, "https").as_deref() == Some("http"),
        Some(PROVIDER_FTP) => params.option(option_keys::TLS_MODE, "explicit").as_deref() == Some("none"),
        Some(PROVIDER_SMB) => matches!(
            security_profile(params).as_deref(),
            Some(security_profiles::LEGACY | security_profiles::GUEST)
        ),
        _ => false,
    }
}

/// `checkServicePolicy(params, Service::Files)`.
#[must_use]
pub fn check_files_policy(params: &ConnectionParams) -> Outcome {
    if params.is_smb() {
        let profile = security_profile(params);
        if !is_known_profile(profile.as_deref()) {
            return Outcome::failure(
                Error::SecurityPolicy,
                format!("Unknown SMB security profile \"{}\"", profile.unwrap_or_default()),
            );
        }
    }
    if is_insecure_configuration(params) && !params.flag(option_keys::ALLOW_INSECURE, false) {
        return Outcome::failure(
            Error::SecurityPolicy,
            "This connection security setting needs the account's consent (allow_insecure)",
        );
    }
    Outcome::success()
}

/// `secretOptional()` (XA-7).
#[must_use]
pub fn secret_optional(params: &ConnectionParams) -> bool {
    params.option(option_keys::AUTH_MODE, "").as_deref() == Some(AUTH_INTERACTIVE)
        || security_profile(params).as_deref() == Some(security_profiles::GUEST)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(provider: &str, options: &[(&str, Value)]) -> ConnectionParams {
        ConnectionParams {
            provider: Some(provider.into()),
            options: options.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect(),
            ..ConnectionParams::default()
        }
    }

    fn s(v: &str) -> Value {
        Value::String(v.into())
    }

    #[test]
    fn options_and_flags() {
        let p = params(
            "x",
            &[("a", s("v")), ("i", Value::Invalid), ("t", Value::Bool(true)), ("one", Value::Int(1))],
        );
        assert_eq!(p.option("a", "f").as_deref(), Some("v"));
        assert_eq!(p.option("missing", "f").as_deref(), Some("f"));
        assert_eq!(p.option("i", "f"), None);
        assert!(p.flag("t", false));
        assert!(p.flag("one", false));
        assert!(!p.flag("a", true));
        assert!(p.flag("i", true));
        assert!(!p.flag("i", false));
        assert!(p.flag("missing", true));
        let d = ConnectionParams::default();
        assert_eq!((d.port, d.connect_timeout_ms, d.request_timeout_ms), (0, 15_000, 60_000));
    }

    #[test]
    fn smb_profiles() {
        assert_eq!(security_profile(&params("sftp", &[])), None);
        assert_eq!(security_profile(&params("smb", &[])).as_deref(), Some("strict"));
        assert_eq!(
            security_profile(&params("smb", &[("require_encryption", Value::Bool(false))])).as_deref(),
            Some("signed")
        );
        assert_eq!(
            security_profile(&params("smb", &[("require_encryption", s("true"))])).as_deref(),
            Some("strict")
        );
        assert_eq!(
            security_profile(&params("smb", &[("security_profile", s(" guest "))])).as_deref(),
            Some("guest")
        );
        assert_eq!(
            security_profile(&params("smb", &[("security_profile", s("  "))])).as_deref(),
            Some("strict")
        );
        assert_eq!(
            security_profile(&params("smb", &[("security_profile", Value::Invalid)])).as_deref(),
            Some("strict")
        );
    }

    #[test]
    fn insecure_configurations() {
        assert!(is_insecure_configuration(&params("webdav", &[("tls", s("http"))])));
        assert!(!is_insecure_configuration(&params("webdav", &[])));
        assert!(!is_insecure_configuration(&params("webdav", &[("tls", s("https"))])));
        assert!(is_insecure_configuration(&params("ftp", &[("tls_mode", s("none"))])));
        assert!(!is_insecure_configuration(&params("ftp", &[])));
        assert!(is_insecure_configuration(&params("smb", &[("security_profile", s("legacy"))])));
        assert!(is_insecure_configuration(&params("smb", &[("security_profile", s("guest"))])));
        assert!(!is_insecure_configuration(&params("smb", &[("security_profile", s("signed"))])));
        assert!(!is_insecure_configuration(&params("sftp", &[("tls", s("http"))])));
    }

    #[test]
    fn files_policy() {
        assert!(check_files_policy(&params("sftp", &[])).ok());
        assert!(check_files_policy(&params("sftp", &[("auth_mode", s("interactive"))])).ok());
        assert!(check_files_policy(&params("smb", &[])).ok());
        let bogus = check_files_policy(&params("smb", &[("security_profile", s("bogus"))]));
        assert_eq!(bogus, Outcome::failure(Error::SecurityPolicy, "Unknown SMB security profile \"bogus\""));
        let http = check_files_policy(&params("webdav", &[("tls", s("http"))]));
        assert_eq!(http.error, Error::SecurityPolicy);
        assert!(check_files_policy(&params("webdav", &[("tls", s("http")), ("allow_insecure", s("1"))])).ok());
        assert!(check_files_policy(&params(
            "smb",
            &[("security_profile", s("guest")), ("allow_insecure", Value::Bool(true))]
        ))
        .ok());
        assert_eq!(
            check_files_policy(&params("smb", &[("security_profile", s("legacy"))])).error,
            Error::SecurityPolicy
        );
    }

    #[test]
    fn optional_secrets() {
        assert!(secret_optional(&params("sftp", &[("auth_mode", s("interactive"))])));
        assert!(secret_optional(&params("smb", &[("security_profile", s("guest"))])));
        assert!(!secret_optional(&params("sftp", &[("auth_mode", s("password"))])));
        assert!(!secret_optional(&params("smb", &[])));
    }
}
