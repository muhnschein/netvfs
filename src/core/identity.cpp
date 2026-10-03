// SPDX-License-Identifier: LGPL-2.1-or-later
#include "identity.h"

namespace NetVfs {

Result checkServerIdentity(const ServerIdentity &seen, const QString &pin)
{
    if (seen.isEmpty()) {
        if (pin.isEmpty())
            return Result::success();
        return Result(Error::ServerIdentityChanged, QStringLiteral("The server presented no identity"));
    }
    const bool tls = seen.kind == ServerIdentity::Kind::TlsCertificate;
    if (pin.isEmpty() && tls && seen.systemTrusted)
        return Result::success();
    if (pin.isEmpty()) {
        if (tls) {
            return Result(Error::ServerIdentityUnknown,
                          QStringLiteral("Untrusted server certificate %1").arg(seen.fingerprint));
        }
        return Result(Error::ServerIdentityUnknown,
                      QStringLiteral("Unknown server key %1 %2").arg(seen.algorithm, seen.fingerprint));
    }
    if (ServerIdentity::fromPin(pin) == seen)
        return Result::success();
    if (tls) {
        return Result(Error::ServerIdentityChanged,
                      QStringLiteral("The server certificate key changed; it is now %1").arg(seen.fingerprint));
    }
    return Result(Error::ServerIdentityChanged,
                  QStringLiteral("The server key changed; it is now %1 %2").arg(seen.algorithm, seen.fingerprint));
}

Result establish(Backend *backend, const ConnectionParams &params, const Credentials &credentials,
                 ServerIdentity *seen, AuthPrompter *prompter)
{
    ServerIdentity identity;
    Result r = backend->connect(params, &identity);
    if (seen)
        *seen = identity;
    if (!r.ok())
        return r;
    r = checkServerIdentity(identity, params.option(QStringLiteral("host_key")));
    if (!r.ok()) {
        backend->disconnect();
        return r;
    }
    r = backend->authenticate(credentials, prompter);
    if (!r.ok())
        backend->disconnect();
    return r;
}

} // namespace NetVfs
