// SPDX-License-Identifier: LGPL-2.1-or-later
//! The security profiles (SPEC-v2 XM-1 as amended by phase 3 design §5.1):
//! what a connection requires of the server. Nothing is negotiated down
//! from what the profile says (XSEC-2).

use netvfs_vfs::{ErrorName, Status};

/// A security profile, option `security_profile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// Signing, and encryption of every request after SESSION_SETUP.
    #[default]
    Strict,
    /// Signing; encryption where the server marks the session or the
    /// share for it.
    Signed,
    /// NTLMSSP anonymous: no signing, no encryption, no credentials.
    Guest,
}

impl Profile {
    /// Every profile.
    pub const ALL: [Self; 3] = [Self::Strict, Self::Signed, Self::Guest];

    /// The option value of `security_profile` (trimmed; empty is
    /// `strict`).
    ///
    /// # Errors
    /// `SecurityPolicy` for any other value: no profile below these exists.
    pub fn parse(value: Option<&str>) -> Result<Self, Status> {
        let name = value.unwrap_or_default().trim();
        if name.is_empty() {
            return Ok(Self::Strict);
        }
        Self::ALL.into_iter().find(|p| p.name() == name).ok_or_else(|| {
            Status::new(ErrorName::SecurityPolicy, format!("unknown SMB security profile \"{name}\""))
        })
    }

    /// The option value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Signed => "signed",
            Self::Guest => "guest",
        }
    }

    /// Signing is required (and so a user account).
    #[must_use]
    pub const fn signs(self) -> bool {
        !matches!(self, Self::Guest)
    }

    /// Every request after SESSION_SETUP is encrypted.
    #[must_use]
    pub const fn encrypts(self) -> bool {
        matches!(self, Self::Strict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_table() {
        let table: Vec<(&str, bool, bool)> =
            Profile::ALL.iter().map(|p| (p.name(), p.signs(), p.encrypts())).collect();
        assert_eq!(table, [("strict", true, true), ("signed", true, false), ("guest", false, false)]);
        assert_eq!(Profile::default(), Profile::Strict);
    }

    #[test]
    fn parsing() {
        for (value, profile) in [
            (None, Profile::Strict),
            (Some(""), Profile::Strict),
            (Some("  "), Profile::Strict),
            (Some("strict"), Profile::Strict),
            (Some(" signed "), Profile::Signed),
            (Some("guest"), Profile::Guest),
        ] {
            assert_eq!(Profile::parse(value), Ok(profile), "{value:?}");
        }
        for value in ["legacy", "Strict", "none", "signed,guest"] {
            let e = Profile::parse(Some(value)).unwrap_err();
            assert_eq!(e.name, ErrorName::SecurityPolicy);
            assert_eq!(e.message, format!("unknown SMB security profile \"{value}\""));
        }
    }
}
