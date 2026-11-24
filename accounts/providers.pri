# SPDX-License-Identifier: LGPL-2.1-or-later

NETVFS_PROVIDERS = sftp smb webdav ftps
NETVFS_BACKUP_PROVIDERS = sftp smb webdav ftps

NETVFS_NAME_sftp = SFTP
NETVFS_DESCRIPTION_sftp = "Files and backups on an SSH/SFTP server"
NETVFS_NAME_smb = SMB
NETVFS_DESCRIPTION_smb = "Files and backups on an SMB (Windows or Samba) file share"
NETVFS_NAME_webdav = WebDAV
NETVFS_DESCRIPTION_webdav = "Files and backups on a WebDAV server over HTTPS, such as Nextcloud"
NETVFS_NAME_ftps = FTPS
NETVFS_DESCRIPTION_ftps = "Files and backups on an FTP server over TLS (FTPS)"

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
