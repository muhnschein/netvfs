// SPDX-License-Identifier: LGPL-2.1-or-later
// libFuzzer harness for the WebDAV multistatus parser (SPEC-v2 XT-3, XSEC-3).
// The input is fed in pieces, as the curl write callback would deliver it
// (the first byte picks the piece size), with small caps so that the depth
// and size limits are reached as well; every resource is then turned into an
// Entry and its href classified, as list() does.
//
// Self-contained: the needed sources are compiled in. Build flags:
//   clang++ -std=c++17 -fsanitize=fuzzer,address,undefined -fPIC
//           -I src/core -I src/backends/webdav $(pkg-config --cflags --libs Qt5Core)
//           tests/fuzz/fuzz_webdav_multistatus.cpp
// Corpus: tests/fuzz/corpus/webdav_multistatus/
#include "../../src/backends/webdav/davstatus.cpp"
#include "../../src/backends/webdav/davurl.cpp"
#include "../../src/backends/webdav/davxml.cpp"
#include "../../src/core/names.cpp"
#include "../../src/core/paths.cpp"

#include <cstddef>
#include <cstdint>

namespace {
constexpr qint64 FuzzMaxBytes = 1 << 16;
constexpr int FuzzMaxDepth = 16;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    using namespace NetVfs;
    using namespace NetVfs::WebDav;
    if (size == 0)
        return 0;
    const qint64 piece = qMax<qint64>(1, data[0]);
    const char *body = reinterpret_cast<const char *>(data + 1);
    const qint64 length = qint64(size) - 1;
    const HrefResolver resolver("https://h.example/dav/dir/");
    MultistatusParser parser([&resolver](const DavResource &resource) {
        QByteArray name;
        if (resolver.classify(resource.href, &name) == HrefResolver::Kind::Child)
            toEntry(resource, Names::decode(name), true);
        SpaceInfo space;
        toSpaceInfo(resource, &space);
        parseChecksums(resource.checksums);
        return true;
    }, FuzzMaxBytes, FuzzMaxDepth);
    for (qint64 offset = 0; offset < length; offset += piece) {
        if (!parser.feed(body + offset, qMin(piece, length - offset)))
            return 0;
    }
    parser.finish();
    return 0;
}
