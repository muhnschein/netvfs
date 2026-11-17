# SPDX-License-Identifier: LGPL-2.1-or-later
# Provider descriptors read by the account dialogs (org.netvfs.accounts, ProviderDescriptors),
# shipped with netvfs-ui.
TEMPLATE = aux

descriptors.files = $$files($$PWD/*.json)
descriptors.path = /usr/share/netvfs/providers
INSTALLS += descriptors

OTHER_FILES += $$files($$PWD/*.json)
