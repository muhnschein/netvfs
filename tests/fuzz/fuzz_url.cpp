// SPDX-License-Identifier: LGPL-2.1-or-later
// SPEC-v2 XT-3: the Url parser (XH-6). parse() must never crash, a password
// must never be accepted, and whatever parse() accepts must survive
// parse -> format -> parse unchanged.
//
// fuzz-sources: src/core/url.cpp src/core/names.cpp src/core/paths.cpp
#include "names.h"
#include "paths.h"
#include "url.h"

#include <cstddef>
#include <cstdint>

using namespace NetVfs;

namespace {

void require(bool condition)
{
    if (!condition)
        __builtin_trap();
}

void checkStable(const ConnectionParams &first, const QString &firstPath)
{
    const QString formatted = Url::format(first, firstPath);
    require(!formatted.isEmpty());
    ConnectionParams second;
    QString secondPath;
    require(Url::parse(formatted, &second, &secondPath).ok());
    require(second.provider == first.provider);
    require(second.host == first.host);
    require(second.port == first.port);
    require(second.username == first.username);
    require(second.options == first.options);
    require(secondPath == firstPath);
    require(Url::format(second, secondPath) == formatted);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Names::decode keeps every byte, including ill-formed UTF-8.
    const QString url = Names::decode(QByteArray(reinterpret_cast<const char *>(data), int(size)));
    ConnectionParams params;
    QString path;
    const Result r = Url::parse(url, &params, &path);
    if (!r.ok()) {
        require(params.provider.isEmpty() && params.host.isEmpty() && path.isEmpty());   // untouched on failure
        return 0;
    }
    QString normalized;
    require(Paths::normalize(path, &normalized).ok() && normalized == path);
    require(params.port >= 0 && params.port <= 65535);
    (void)Url::toAce(params.host);
    checkStable(params, path);
    return 0;
}
