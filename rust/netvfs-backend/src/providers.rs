// SPDX-License-Identifier: LGPL-2.1-or-later
//! The backends by provider name (`conn_new`).

use crate::erased::DynBackend;
use netvfs_vfs::Status;

/// New, unconnected backend of `provider`.
///
/// # Errors
/// `Unsupported` for an unknown provider.
pub fn create(provider: &[u8]) -> Result<Box<dyn DynBackend>, Status> {
    match provider {
        b"sftp" => Ok(Box::new(netvfs_sftp::backend::Sftp::new())),
        b"smb" => Ok(Box::new(netvfs_smb::backend::Smb::new())),
        b"webdav" => Ok(Box::new(netvfs_webdav::backend::Webdav::new())),
        b"ftps" => Ok(Box::new(netvfs_ftps::backend::Ftps::new())),
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
        for provider in [&b"ftp"[..], b"", b"m\xffm", b"SFTP", b"sftp\0", b"WebDAV", b"FTPS"] {
            let e = create(provider).err().unwrap();
            assert_eq!(e.name, ErrorName::Unsupported);
        }
        let e = create(b"ftp").err().unwrap();
        assert_eq!(e.message, "No Rust backend for provider \"ftp\"");
    }

    #[test]
    fn sftp_is_a_provider() {
        create(b"sftp").unwrap();
    }

    #[test]
    fn smb_is_a_provider() {
        create(b"smb").unwrap();
    }

    #[test]
    fn webdav_is_a_provider() {
        create(b"webdav").unwrap();
    }

    #[test]
    fn ftps_is_a_provider() {
        create(b"ftps").unwrap();
    }

    #[cfg(feature = "testing")]
    #[test]
    fn mem_is_a_provider_when_testing() {
        create(b"mem").unwrap();
    }
}
