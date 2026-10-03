// SPDX-License-Identifier: LGPL-2.1-or-later
// SPEC-v2 XT-3: the Names codec (XC-4). For every byte string the codec is
// lossless: encode(decode(x)) == x. Arbitrary UTF-16 input must never crash.
//
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
    require(Names::encode(name) == bytes);                 // lossless round trip
    require(Names::isEncodable(name));                     // decode() only produces encodable names
    require(Names::hasEscapes(name) == (Names::display(name) != name));
    require(Names::display(name).size() == name.size());
    // Idempotent on the string side once it came from bytes.
    require(Names::decode(Names::encode(name)) == name);
}

void checkUtf16(const uint8_t *data, size_t size)
{
    QString text;
    for (size_t i = 0; i + 1 < size; i += 2)
        text.append(QChar(ushort(data[i] | (data[i + 1] << 8))));
    const QByteArray encoded = Names::encode(text);
    // Whatever encode() produced is a byte string like any other.
    require(Names::encode(Names::decode(encoded)) == encoded);
    (void)Names::isEncodable(text);
    (void)Names::hasEscapes(text);
    (void)Names::display(text);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    checkBytes(QByteArray(reinterpret_cast<const char *>(data), int(size)));
    checkUtf16(data, size);
    return 0;
}
