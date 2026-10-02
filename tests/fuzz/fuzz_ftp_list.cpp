// SPDX-License-Identifier: LGPL-2.1-or-later
// libFuzzer harness for the FTP parsers (SPEC-v2 XT-3, F-3): the LIST
// (Unix and DOS) and MLSD listing parser fed in pieces as the transfer
// would deliver them, and the control-connection reply parsers (reply
// reassembly, FEAT, PWD, SIZE, MDTM, MLST) over the same bytes.
//
// The first byte picks the mode: bit 0 set parses MLSD, else LIST; bits 1..7
// are the piece size. Properties: every listed entry has a usable name (not
// empty, no '/', no NUL, not "." or "..") that round-trips through the Names
// codec (XC-4); no parser crashes or reads out of bounds.
//
// fuzz-sources: src/backends/ftp/ftpparse.cpp src/core/names.cpp
// fuzz-includes: src/backends/ftp
// Corpus: tests/fuzz/corpus/ftp_list/
#include "ftpparse.h"
#include "names.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace {

bool usableName(const QString &name)
{
    const QByteArray bytes = NetVfs::Names::encode(name);
    return !bytes.isEmpty() && !bytes.contains('/') && !bytes.contains('\0') && bytes != "." && bytes != ".."
        && NetVfs::Names::decode(bytes) == name;
}

void replies(const char *data, size_t size)
{
    using namespace NetVfs::Ftp;
    ReplyReader reader;
    reader.feed(data, size);
    for (const Reply &reply : reader.replies()) {
        parseFeatures(reply);
        QByteArray path;
        parsePathReply(reply, &path);
        parseSizeReply(reply);
        parseMdtmReply(reply);
        NetVfs::Entry entry;
        parseMlstReply(reply, &entry);
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    using namespace NetVfs::Ftp;
    if (size == 0)
        return 0;
    const bool mlsd = (data[0] & 1) != 0;
    const size_t piece = std::max<size_t>(1, data[0] >> 1);
    const char *body = reinterpret_cast<const char *>(data + 1);
    const size_t length = size - 1;

    ListingParser parser(mlsd, QDateTime(QDate(2026, 10, 2), QTime(12, 0), Qt::UTC));
    QVector<NetVfs::Entry> entries;
    for (size_t offset = 0; offset < length; offset += piece)
        parser.feed(body + offset, std::min(piece, length - offset), &entries);
    parser.finish(&entries);
    for (const NetVfs::Entry &entry : entries) {
        if (!usableName(entry.name) || entry.size < -1 || entry.mode > 07777)
            __builtin_trap();
    }
    if (parser.invalidLines() < 0)
        __builtin_trap();
    replies(body, length);
    return 0;
}
