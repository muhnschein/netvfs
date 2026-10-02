# SPDX-License-Identifier: LGPL-2.1-or-later
# Engineering English for the account UI: lupdate collects the qsTrId()/
# qtTrId() ids and //% texts from the QML module, its C++ plugin and the
# account UI files; lrelease -idbased writes netvfs_eng_en.qm, which the
# org.netvfs.accounts plugin loads (installed with the core package, SPEC 4.1).
# Translations for other languages go to netvfs-<locale>.qm next to it.
TEMPLATE = aux

NETVFS_TS_FILE = $$OUT_PWD/netvfs.ts
NETVFS_EE_QM = $$OUT_PWD/netvfs_eng_en.qm

netvfs_ts.commands = $$shell_quote($$[QT_INSTALL_BINS]/lupdate) -silent \
    $$shell_quote($$PWD/../src/qml) $$shell_quote($$PWD/../accounts/ui) -ts $$shell_quote($$NETVFS_TS_FILE)
netvfs_ts.target = $$NETVFS_TS_FILE
netvfs_ts.depends = $$files($$PWD/../src/qml/*.qml) $$files($$PWD/../src/qml/*.cpp) $$files($$PWD/../accounts/ui/*.qml)

netvfs_qm.commands = $$shell_quote($$[QT_INSTALL_BINS]/lrelease) -silent -idbased \
    $$shell_quote($$NETVFS_TS_FILE) -qm $$shell_quote($$NETVFS_EE_QM)
netvfs_qm.target = $$NETVFS_EE_QM
netvfs_qm.depends = $$NETVFS_TS_FILE

QMAKE_EXTRA_TARGETS += netvfs_ts netvfs_qm
PRE_TARGETDEPS += $$NETVFS_EE_QM

netvfs_qm_install.files = $$NETVFS_EE_QM
netvfs_qm_install.path = /usr/share/translations
netvfs_qm_install.CONFIG += no_check_exist
INSTALLS += netvfs_qm_install

QMAKE_CLEAN += $$NETVFS_TS_FILE $$NETVFS_EE_QM
