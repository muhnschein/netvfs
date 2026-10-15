// SPDX-License-Identifier: LGPL-2.1-or-later
//! The backends by provider name (`conn_new`).

use crate::erased::DynBackend;
use netvfs_vfs::Status;

/// A new, unconnected backend of `provider`.
///
/// # Errors
/// `Unsupported` for a provider this build has no backend for.
pub fn create(provider: &[u8]) -> Result<Box<dyn DynBackend>, Status> {
    match provider {
        b"sftp" => Ok(Box::new(netvfs_sftp::backend::Sftp::new())),
        #[cfg(feature = "testing")]
        b"mem" => Ok(Box::new(crate::mem::Mem::new())),
        _ => Err(Status::unsupported(format!(
            "No Rust backend for provider \"{}\"",
            String::from_utf8_lossy(provider)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netvfs_vfs::ErrorName;

    #[test]
    fn unknown_providers_are_unsupported() {
        for provider in [&b"ftp"[..], b"", b"m\xffm", b"SFTP", b"sftp\0"] {
            let e = create(provider).err().unwrap();
            assert_eq!(e.name, ErrorName::Unsupported);
        }
        let e = create(b"webdav").err().unwrap();
        assert_eq!(e.message, "No Rust backend for provider \"webdav\"");
    }

    #[test]
    fn sftp_is_a_provider() {
        create(b"sftp").unwrap();
    }

    #[cfg(feature = "testing")]
    #[test]
    fn mem_is_a_provider_when_testing() {
        create(b"mem").unwrap();
    }
}
