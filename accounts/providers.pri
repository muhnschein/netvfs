# SPDX-License-Identifier: LGPL-2.1-or-later
# The account providers (SPEC 6.1, SPEC-v2 XA-2) and a generator for the
# provider and service files, shared by files.pro and files-services/.

# Every provider gets <p>.provider, the account UI and a "<p>-files" service
# (XA-1); the providers in NETVFS_BACKUP_PROVIDERS also get "<p>-backup"
# (Buteo plugins exist for them). A webdav-backup service may follow (XA-2).
NETVFS_PROVIDERS = sftp smb webdav ftp
NETVFS_BACKUP_PROVIDERS = sftp smb

NETVFS_NAME_sftp = SFTP
NETVFS_DESCRIPTION_sftp = "Files and backups on an SSH/SFTP server"
NETVFS_NAME_smb = SMB
NETVFS_DESCRIPTION_smb = "Files and backups on an SMB (Windows or Samba) file share"
NETVFS_NAME_webdav = WebDAV
NETVFS_DESCRIPTION_webdav = "Files on a WebDAV server"
NETVFS_NAME_ftp = FTP
NETVFS_DESCRIPTION_ftp = "Files on an FTP or FTPS server"

# Writes `output` from `template`, replacing @PROVIDER@, @NAME@ and @DESCRIPTION@.
defineTest(netvfsGenerate) {
    template = $$1
    output = $$2
    provider = $$3
    name = $$eval(NETVFS_NAME_$${provider})
    description = $$eval(NETVFS_DESCRIPTION_$${provider})
    lines = $$cat($$template, lines)
    out =
    for(line, lines) {
        line = $$replace(line, @PROVIDER@, $$provider)
        line = $$replace(line, @NAME@, $$name)
        line = $$replace(line, @DESCRIPTION@, $$description)
        out += $$line
    }
    write_file($$output, out)|return(false)
    return(true)
}
