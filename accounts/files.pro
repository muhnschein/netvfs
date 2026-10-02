# SPDX-License-Identifier: LGPL-2.1-or-later
# Per provider <p>: /usr/share/accounts/providers/<p>.provider,
# /usr/share/accounts/services/<p>-backup.service (both generated from one
# template, SPEC 6.1) and /usr/share/accounts/ui/<p>{,-settings,-update}.qml.
TEMPLATE = aux

NETVFS_PROVIDERS = sftp smb
NETVFS_NAME_sftp = SFTP
NETVFS_DESCRIPTION_sftp = "Backups to an SSH/SFTP server"
NETVFS_NAME_smb = SMB
NETVFS_DESCRIPTION_smb = "Backups to an SMB (Windows or Samba) file share"

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

for(p, NETVFS_PROVIDERS) {
    netvfsGenerate($$PWD/templates/provider.xml.in, $$OUT_PWD/providers/$${p}.provider, $$p)|error("Cannot write $${p}.provider")
    netvfsGenerate($$PWD/templates/service.xml.in, $$OUT_PWD/services/$${p}-backup.service, $$p)|error("Cannot write $${p}-backup.service")

    eval(provider_$${p}.files = $$OUT_PWD/providers/$${p}.provider)
    eval(provider_$${p}.path = /usr/share/accounts/providers)
    eval(service_$${p}.files = $$OUT_PWD/services/$${p}-backup.service)
    eval(service_$${p}.path = /usr/share/accounts/services)
    eval(ui_$${p}.files = $$PWD/ui/$${p}.qml $$PWD/ui/$${p}-settings.qml $$PWD/ui/$${p}-update.qml)
    eval(ui_$${p}.path = /usr/share/accounts/ui)
    INSTALLS += provider_$${p} service_$${p} ui_$${p}
    OTHER_FILES += ui/$${p}.qml ui/$${p}-settings.qml ui/$${p}-update.qml
}

OTHER_FILES += templates/provider.xml.in templates/service.xml.in
# Re-run qmake (and so regenerate the files) when a template changes.
QMAKE_INTERNAL_INCLUDED_FILES += $$PWD/templates/provider.xml.in $$PWD/templates/service.xml.in
