// SPDX-License-Identifier: LGPL-2.1-or-later
// fuzz-sources: src/core/names.cpp
#include "names.h"

#include <cstddef>
#include <cstdint>

using namespace NetVfs;

namespace {

void require(bool condition)
{
    if (!condition)
        __builtin_trap();
}

void checkBytes(const QByteArray &bytes)
{
    const QString name = Names::decode(bytes);
    require(Names::encode(name) == bytes);
    require(Names::isEncodable(name));
    require(Names::hasEscapes(name) == (Names::display(name) != name));
    require(Names::display(name).size() == name.size());
    require(Names::decode(Names::encode(name)) == name);
}

void checkUtf16(const uint8_t *data, size_t size)
{
    QString text;
    for (size_t i = 0; i + 1 < size; i += 2)
        text.append(QChar(ushort(data[i] | (data[i + 1] << 8))));
    const QByteArray encoded = Names::encode(text);
    require(Names::encode(Names::decode(encoded)) == encoded);
    (void)Names::isEncodable(text);
    (void)Names::hasEscapes(text);
    (void)Names::display(text);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    checkBytes(QByteArray(reinterpret_cast<const char *>(data), int(size)));
    checkUtf16(data, size);
    return 0;
}
