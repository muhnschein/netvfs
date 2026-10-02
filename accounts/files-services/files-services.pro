# SPDX-License-Identifier: LGPL-2.1-or-later
# SPEC-v2 XA-1, XP-1 (package netvfs-files-services): a "<p>-files" service
# of type "netvfs-files" for every provider, and the service type itself.
# The type differs from "storage", so the Backup page does not list these.
# Generated into <build>/accounts/files-services/services/.
TEMPLATE = aux
include(../providers.pri)

for(p, NETVFS_PROVIDERS) {
    netvfsGenerate($$PWD/files-service.xml.in, $$OUT_PWD/services/$${p}-files.service, $$p)|error("Cannot write $${p}-files.service")
    NETVFS_FILES_SERVICES += $$OUT_PWD/services/$${p}-files.service
}

files_services.files = $$NETVFS_FILES_SERVICES
files_services.path = /usr/share/accounts/services
files_service_type.files = $$PWD/netvfs-files.service-type
files_service_type.path = /usr/share/accounts/service_types
INSTALLS += files_services files_service_type

OTHER_FILES += files-service.xml.in netvfs-files.service-type
QMAKE_INTERNAL_INCLUDED_FILES += $$PWD/files-service.xml.in
