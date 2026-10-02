// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs-smb-shares (SPEC-v2 XM-7): lists the shares of one SMB server for
// the SMB backend's server mode. It runs as its own short-lived process so
// that the share enumeration (DCE/RPC NetrShareEnum, the largest parser of
// server data in libsmb2) stays out of libnetvfs-smb.so (G-SMB item 4,
// XSEC-3).
//
// Input: one request on stdin (smbshares.h; never argv or the environment).
// Output: JSON lines on stdout (smbshares.h). Exit status 0 with an end line,
// 1 with an error line, 2 for a request it cannot read.
#include "smb2api.h"
#include "smbshares.h"
#include "smbutil.h"

#include "secure.h"

#include <smb2/libsmb2-raw.h>
#include <smb2/libsmb2-share-enum.h>

#include <cerrno>

#include <unistd.h>

using namespace NetVfs;
using namespace NetVfs::Smb;

namespace {

const int ExitError = 1;
const int ExitBadRequest = 2;

bool writeLine(const QByteArray &line)
{
    QByteArray data = line + '\n';
    int done = 0;
    while (done < data.size()) {
        const ssize_t n = ::write(STDOUT_FILENO, data.constData() + done, static_cast<size_t>(data.size() - done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += static_cast<int>(n);
    }
    return true;
}

// At most MaxShareRequestBytes + 1, so that an oversized request is noticed.
QByteArray readRequest()
{
    // One buffer, never reallocated, so that wiping it wipes every copy.
    QByteArray data(MaxShareRequestBytes + 1, '\0');
    int size = 0;
    while (size < data.size()) {
        const ssize_t n = ::read(STDIN_FILENO, data.data() + size, static_cast<size_t>(data.size() - size));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        size += static_cast<int>(n);
    }
    QByteArray request = data.left(size);
    secureWipe(data);
    return request;
}

class Context
{
public:
    Context() : m_ctx(smb2_init_context()) {}
    ~Context()
    {
        if (!m_ctx)
            return;
        if (m_connected)
            smb2_disconnect_share(m_ctx);
        smb2_destroy_context(m_ctx);
    }
    Context(const Context &) = delete;
    Context &operator=(const Context &) = delete;

    smb2_context *get() const { return m_ctx; }
    void setConnected() { m_connected = true; }

private:
    smb2_context *m_ctx;
    bool m_connected = false;
};

Result signIn(const Context &context, const ShareRequest &request, Profile profile)
{
    smb2_context *ctx = context.get();
    // The same settings as the backend's own sessions (XM-1, M-1..M-7).
    applyProfile(ctx, profile, QString::fromUtf8(request.user), QString::fromUtf8(request.domain), request.secret,
                 request.requestTimeoutMs);
    const int rc = smb2_connect_share(ctx, request.server.constData(), "IPC$", nullptr);
    smb2_set_password(ctx, nullptr);       // SEC-5
    const Result r = rc < 0 ? errorForStatus(static_cast<quint32>(smb2_get_nterror(ctx)), -rc, Stage::SessionSetup,
                                             QStringLiteral("Sign-in failed"))
                            : Result::success();
    // The backend's own checks: guest mapping (XM-1), dialect (M-1).
    return checkSession(ctx, profile, r);
}

Result listShares(const Context &context, int *count)
{
    smb2_context *ctx = context.get();
    srvsvc_NetrShareEnum_rep *rep = smb2_share_enum_sync(ctx, SHARE_INFO_1);
    if (!rep)
        return errorForStatus(static_cast<quint32>(smb2_get_nterror(ctx)), EIO, Stage::Established,
                              QStringLiteral("Cannot list the shares"));
    const srvsvc_SHARE_INFO_1_CONTAINER &container = rep->ses.ShareEnum.Level1;
    Result r;
    for (uint32_t i = 0; r.ok() && i < container.EntriesRead && container.share_info_1; ++i) {
        const srvsvc_SHARE_INFO_1 &info = container.share_info_1[i];
        ShareInfo share;
        share.name = info.netname ? decodeName(info.netname) : QString();
        share.type = info.type;
        share.remark = info.remark ? decodeName(info.remark).left(MaxRemarkLength) : QString();
        // A name the backend could not use is left out, not passed on.
        if (!validShareName(share.name))
            continue;
        if (!writeLine(shareLine(share)))
            r = Result(Error::Internal, QStringLiteral("cannot write the share list"));
        ++*count;
    }
    smb2_free_data(ctx, rep);
    return r;
}

} // namespace

int main()
{
    // M-5: the account's password only; and nothing else of the parent's.
    neutraliseUserFile();
    QByteArray input = readRequest();
    ShareRequest request;
    const bool valid = decodeShareRequest(input, &request);
    secureWipe(input);              // XSEC-6
    Profile profile = Profile::Strict;
    QVariantMap options;
    options.insert(QStringLiteral("security_profile"), QString::fromUtf8(request.profile));
    if (!valid || !profileFromOptions(options, &profile).ok()) {
        secureWipe(request.secret);
        writeLine(errorLine(Result(Error::ProtocolError, QStringLiteral("the request is malformed"))));
        return ExitBadRequest;
    }

    Context context;
    Result r = context.get() ? signIn(context, request, profile)
                             : Result(Error::Internal, QStringLiteral("Cannot create an SMB context"));
    secureWipe(request.secret);
    int count = 0;
    if (r.ok()) {
        context.setConnected();
        r = listShares(context, &count);
    }
    if (!r.ok()) {
        writeLine(errorLine(r));
        return ExitError;
    }
    return writeLine(endLine(count)) ? 0 : ExitError;
}
