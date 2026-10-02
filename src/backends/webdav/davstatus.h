// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DAVSTATUS_H
#define NETVFS_DAVSTATUS_H

#include "error.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>

// Error mapping of the WebDAV backend (SPEC-v2 W-13).
namespace NetVfs::WebDav {

enum class Method { Options, Propfind, Proppatch, Mkcol, Get, Put, Patch, Delete, Move, Copy };

QByteArray methodName(Method method);

// A final HTTP status as a Result. `reason` is the reason phrase (for
// detail()), `retryAfterMs` the parsed Retry-After header or -1.
Result httpResult(int status, Method method, const QByteArray &reason = QByteArray(),
                  qint64 retryAfterMs = -1);

// A libcurl CURLcode as a Result. `message` is curl's error buffer.
Result curlResult(int code, const QString &message = QString());

// RFC 9110 HTTP-date (IMF-fixdate, RFC 850, asctime); invalid on failure.
QDateTime parseHttpDate(const QByteArray &value);

// RFC 9110 10.2.3 Retry-After (delay-seconds or HTTP-date) in milliseconds
// from `now`; -1 when absent or unparsable.
qint64 parseRetryAfter(const QByteArray &value, const QDateTime &now);

// First byte position of a Content-Range header ("bytes 100-199/1000" ->
// 100); -1 when unparsable or unsatisfied ("bytes */1000").
qint64 contentRangeStart(const QByteArray &value);

} // namespace NetVfs::WebDav

#endif
