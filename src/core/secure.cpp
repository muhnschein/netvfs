// SPDX-License-Identifier: LGPL-2.1-or-later
#include "secure.h"

#include <cstring>

namespace NetVfs {

namespace {
void wipeBytes(void *data, size_t size)
{
    // volatile pointer keeps the compiler from eliding the stores.
    volatile unsigned char *p = static_cast<volatile unsigned char *>(data);
    while (size--)
        *p++ = 0;
}
} // namespace

void secureWipe(QByteArray &data)
{
    if (!data.isEmpty())
        wipeBytes(data.data(), static_cast<size_t>(data.size()));
    data.clear();
}

void secureWipe(QString &data)
{
    if (!data.isEmpty())
        wipeBytes(data.data(), static_cast<size_t>(data.size()) * sizeof(QChar));
    data.clear();
}

} // namespace NetVfs
