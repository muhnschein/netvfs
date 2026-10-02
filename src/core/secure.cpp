// SPDX-License-Identifier: LGPL-2.1-or-later
#include "secure.h"

#include <cstring>

namespace NetVfs {

namespace {
void wipeBytes(char *data, size_t count)
{
    // Stores through a volatile pointer cannot be elided by the compiler.
    volatile char *p = data;
    while (count--)
        *p++ = 0;
}
} // namespace

void secureWipe(QByteArray &data)
{
    if (!data.isEmpty())
        wipeBytes(data.data(), static_cast<size_t>(data.size()));
    data.clear();
}

// QString::fill() lives in QtCore, so the stores cannot be elided here.
void secureWipe(QString &data)
{
    if (!data.isEmpty())
        data.fill(QChar());
    data.clear();
}

} // namespace NetVfs
