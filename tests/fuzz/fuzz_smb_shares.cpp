// SPDX-License-Identifier: LGPL-2.1-or-later
// SPEC-v2 XM-7, XT-3: the SMB share enumeration helper's output parser and
// its request codec. parseShareOutput() reads what another process wrote
// after talking to the server and must never crash or hang; what it accepts
// obeys every limit, holds only valid disk-share names without duplicates,
// and survives the helper's own writers unchanged. decodeShareRequest()
// accepts only what encodeShareRequest() produces.
//
// fuzz-sources: src/backends/smb/smbshares.cpp src/core/error.cpp
// fuzz-includes: src/backends/smb
#include "smbshares.h"

#include <QtCore/QStringList>

#include <cstddef>
#include <cstdint>

using namespace NetVfs;
using namespace NetVfs::Smb;

namespace {

void require(bool condition)
{
    if (!condition)
        __builtin_trap();
}

void checkShares(const QVector<ShareInfo> &shares)
{
    require(shares.size() <= MaxShares);
    QStringList seen;
    for (const ShareInfo &share : shares) {
        require(validShareName(share.name));
        require(!seen.contains(share.name, Qt::CaseInsensitive));
        require(share.remark.size() <= MaxRemarkLength);
        seen.append(share.name);
    }
}

void checkOutput(const QByteArray &output)
{
    QVector<ShareInfo> shares;
    const Result r = parseShareOutput(output, &shares);
    if (!r.ok()) {
        require(shares.isEmpty());
        require(r.error() != Error::None && r.error() != Error::Canceled && r.error() != Error::Internal);
        return;
    }
    checkShares(shares);
    // What was accepted round-trips through the helper's writers.
    QByteArray again;
    for (const ShareInfo &share : shares)
        again += shareLine(share) + '\n';
    again += endLine(shares.size()) + '\n';
    QVector<ShareInfo> reparsed;
    require(parseShareOutput(again, &reparsed).ok());
    require(reparsed.size() == shares.size());
    for (int i = 0; i < shares.size(); ++i) {
        require(reparsed.at(i).name == shares.at(i).name);
        require(reparsed.at(i).type == shares.at(i).type);
        require(reparsed.at(i).remark == shares.at(i).remark);
    }
}

void checkRequest(const QByteArray &data)
{
    ShareRequest request;
    if (!decodeShareRequest(data, &request))
        return;
    require(!request.server.isEmpty());
    require(request.requestTimeoutMs >= 0);
    require(encodeShareRequest(request) == data);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const QByteArray bytes(reinterpret_cast<const char *>(data), static_cast<int>(size));
    checkOutput(bytes);
    checkRequest(bytes);
    return 0;
}
