// SPDX-License-Identifier: LGPL-2.1-or-later
//! The Files slice of src/core/servicepolicy.cpp (SPEC-v2 XA-4, XA-7) and
//! `ConnectionParams` (src/core/types.h).

use crate::qvariant::{QString, Value, trimmed};
use crate::wire::{Error, Outcome};

/// `ConnectionParams`: what a connection to the account needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionParams {
    /// The provider's name, such as `smb`.
    pub provider: QString,
    /// The server host (`netvfs/host`).
    pub host: QString,
    /// The server port (`netvfs/port`).
    pub port: i32,
    /// The user name (`netvfs/username`).
    pub username: QString,
    /// `netvfs/<provider>/<key>` settings by `<key>`.
    pub options: Vec<(String, Value)>,
    /// The connect timeout in milliseconds.
    pub connect_timeout_ms: i32,
    /// The request timeout in milliseconds.
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

/// Keys of the provider options, below `netvfs/<provider>/`.
pub mod option_keys {
    /// The authentication mode: `interactive` needs no stored secret.
    pub const AUTH_MODE: &str = "auth_mode";
    /// The SMB security profile, if one is set.
    pub const SECURITY_PROFILE: &str = "security_profile";
    /// The account's consent to an insecure setting.
    pub const ALLOW_INSECURE: &str = "allow_insecure";
}

/// The SMB security profiles (`security_profile`).
pub mod security_profiles {
    /// SMB with encryption required: the default.
    pub const STRICT: &str = "strict";
    /// SMB without required encryption.
    pub const SIGNED: &str = "signed";
    /// Guest SMB without credentials: insecure, needs `allow_insecure`, no secret needed.
    pub const GUEST: &str = "guest";
}

const PROVIDER_SMB: &str = "smb";
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
    Some(security_profiles::STRICT.to_owned())
}

fn is_known_profile(profile: Option<&str>) -> bool {
    use security_profiles::{GUEST, SIGNED, STRICT};
    matches!(profile, Some(STRICT | SIGNED | GUEST))
}

/// `isInsecureConfiguration()`.
#[must_use]
pub fn is_insecure_configuration(params: &ConnectionParams) -> bool {
    security_profile(params).as_deref() == Some(security_profiles::GUEST)
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
        // No other option selects a profile.
        assert_eq!(
            security_profile(&params("smb", &[("require_encryption", Value::Bool(false))])).as_deref(),
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
        assert!(is_insecure_configuration(&params("smb", &[("security_profile", s("guest"))])));
        assert!(!is_insecure_configuration(&params("smb", &[("security_profile", s("signed"))])));
        assert!(!is_insecure_configuration(&params("smb", &[])));
        assert!(!is_insecure_configuration(&params("sftp", &[("security_profile", s("guest"))])));
    }

    #[test]
    fn files_policy() {
        assert!(check_files_policy(&params("sftp", &[])).ok());
        assert!(check_files_policy(&params("sftp", &[("auth_mode", s("interactive"))])).ok());
        assert!(check_files_policy(&params("smb", &[])).ok());
        let bogus = check_files_policy(&params("smb", &[("security_profile", s("bogus"))]));
        assert_eq!(bogus, Outcome::failure(Error::SecurityPolicy, "Unknown SMB security profile \"bogus\""));
        assert!(
            check_files_policy(&params(
                "smb",
                &[("security_profile", s("guest")), ("allow_insecure", s("1"))]
            ))
            .ok()
        );
        assert!(
            check_files_policy(&params(
                "smb",
                &[("security_profile", s("guest")), ("allow_insecure", Value::Bool(true))]
            ))
            .ok()
        );
        assert_eq!(
            check_files_policy(&params("smb", &[("security_profile", s("guest"))])).error,
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
