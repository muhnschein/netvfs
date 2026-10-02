# SPDX-License-Identifier: LGPL-2.1-or-later
# Per provider <p>: /usr/share/accounts/providers/<p>.provider and
# /usr/share/accounts/ui/<p>{,-settings,-update}.qml; for backup providers
# also /usr/share/accounts/services/<p>-backup.service (both generated from
# templates, SPEC 6.1). The "<p>-files" services are in files-services/.
TEMPLATE = aux
include(providers.pri)

for(p, NETVFS_PROVIDERS) {
    netvfsGenerate($$PWD/templates/provider.xml.in, $$OUT_PWD/providers/$${p}.provider, $$p)|error("Cannot write $${p}.provider")

    eval(provider_$${p}.files = $$OUT_PWD/providers/$${p}.provider)
    eval(provider_$${p}.path = /usr/share/accounts/providers)
    eval(ui_$${p}.files = $$PWD/ui/$${p}.qml $$PWD/ui/$${p}-settings.qml $$PWD/ui/$${p}-update.qml)
    eval(ui_$${p}.path = /usr/share/accounts/ui)
    INSTALLS += provider_$${p} ui_$${p}
    OTHER_FILES += ui/$${p}.qml ui/$${p}-settings.qml ui/$${p}-update.qml
}

for(p, NETVFS_BACKUP_PROVIDERS) {
    netvfsGenerate($$PWD/templates/service.xml.in, $$OUT_PWD/services/$${p}-backup.service, $$p)|error("Cannot write $${p}-backup.service")

    eval(service_$${p}.files = $$OUT_PWD/services/$${p}-backup.service)
    eval(service_$${p}.path = /usr/share/accounts/services)
    INSTALLS += service_$${p}
}

OTHER_FILES += providers.pri templates/provider.xml.in templates/service.xml.in
# Re-run qmake (and so regenerate the files) when a template changes.
QMAKE_INTERNAL_INCLUDED_FILES += $$PWD/templates/provider.xml.in $$PWD/templates/service.xml.in
