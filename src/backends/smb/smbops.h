// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBOPS_H
#define NETVFS_SMBOPS_H

#include "backend.h"
#include "smbsession.h"

// The SMB operations on one session, below SmbBackend's path handling
// (share mode and server mode, XM-2). Paths are relative to the session's
// share and already translated (translatePath, splitServerPath).
namespace NetVfs::Smb::Ops {

Result statPath(Session &session, const QByteArray &path, Entry *out);
Result unlinkPath(Session &session, const QByteArray &path, const QString &context);
Result listPath(Session &session, const QByteArray &path, ListSink *sink, const ListOptions &options);
Result makeDirectory(Session &session, const QByteArray &path, bool exclusive);
Result removeFile(Session &session, const QByteArray &path);
Result removeDirectory(Session &session, const QByteArray &path);
Result renamePath(Session &session, const QByteArray &from, const QByteArray &to);
// XC-10, XM-5: ReplaceIfExists in the request; a folder is never replaced.
Result renameReplacing(Session &session, const QByteArray &from, const QByteArray &to);
Result spaceInfo(Session &session, const QByteArray &path, SpaceInfo *out);
Result echo(Session &session);

// XC-14: the dispositions; Resume checks the remote size first.
Result openForWrite(Session &session, const QByteArray &path, const WriteOptions &options, smb2fh **fh);
// A file (not a folder) and its size at open time.
Result openForRead(Session &session, const QByteArray &path, smb2fh **fh, qint64 *size);
// Streams `source` into `writer` in chunks of `chunk` bytes (M-11).
Result writeAll(const Session &session, QIODevice *source, WriteHandle *writer, Progress *progress, qint64 base);
// Streams [offset, end) of `reader` into `sink`, with read-ahead (XM-6).
Result copyToSink(const Session &session, ReadHandle *reader, qint64 offset, qint64 end, QIODevice *sink,
                  Progress *progress);

} // namespace NetVfs::Smb::Ops

#endif
