// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_QMLTESTUTIL_H
#define NETVFS_TEST_QMLTESTUTIL_H

#include <QtCore/QCoreApplication>
#include <QtCore/QTranslator>

#include <memory>

namespace NetVfs::Test {
inline bool installEngineeringEnglish(QObject *parent)
{
    auto translator = std::make_unique<QTranslator>(parent);
    if (!translator->load(QStringLiteral("netvfs_eng_en"), QStringLiteral(NETVFS_TEST_BUILD_DIR "/translations")))
        return false;
    const bool installed = QCoreApplication::installTranslator(translator.get());
    translator.release();
    return installed;
}

}

#endif
