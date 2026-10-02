// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_FTPHANDLES_H
#define NETVFS_FTPHANDLES_H

#include "ftpbackend.h"

namespace NetVfs::Ftp {

// XC-13 over RETR (F-5): a read keeps the RETR of the previous read going
// (paused between calls), so sequential reads cost one data connection.
// Any other offset starts a new RETR with REST. Memory: at most maxBytes
// plus one libcurl chunk (C-10).
class FtpReadHandle : public ReadHandle, public StreamOwner, private TransferSink
{
public:
    FtpReadHandle(FtpBackend *backend, const QByteArray &remote, qint64 size);
    FtpReadHandle(const FtpReadHandle &) = delete;
    FtpReadHandle &operator=(const FtpReadHandle &) = delete;
    ~FtpReadHandle() override;

    qint64 size() const override { return m_size; }
    Result read(qint64 offset, qint64 maxBytes, QByteArray *out) override;
    void readAhead(qint64 offset, qint64 bytes) override;
    Result close() override;

    void streamStopped() override;
    void invalidate() override;

private:
    size_t received(const char *data, size_t size) override;
    Result startAt(qint64 offset);
    Result fill(qint64 wanted);
    void endStream();

    FtpBackend *m_backend;
    QByteArray m_remote;
    qint64 m_size;
    QByteArray m_buffer;          // file bytes from m_bufferStart on
    qint64 m_bufferStart = 0;
    qint64 m_wanted = 0;
    bool m_streaming = false;
    bool m_eof = false;           // the stream ended at m_bufferStart + m_buffer.size()
    bool m_valid = true;
    bool m_closed = false;
};

// XC-13 over STOR/APPE (F-5): write() hands the caller's bytes to the
// running upload and returns once libcurl took all of them (the upload is
// paused in between); commit() ends the upload and waits for the server's
// confirmation, then applies the modification time (MFMT).
class FtpWriteHandle : public WriteHandle, public StreamOwner, private TransferSink
{
public:
    FtpWriteHandle(FtpBackend *backend, const QByteArray &remote, const WriteOptions &options);
    FtpWriteHandle(const FtpWriteHandle &) = delete;
    FtpWriteHandle &operator=(const FtpWriteHandle &) = delete;
    ~FtpWriteHandle() override;

    Result write(const char *data, qint64 length) override;
    qint64 position() const override { return m_position; }
    Result commit() override;
    void abort() override;

    void streamStopped() override;
    void invalidate() override;

private:
    size_t send(char *buffer, size_t size) override;
    Result ensureStarted();
    Result drive(bool toEnd);

    FtpBackend *m_backend;
    QByteArray m_remote;
    WriteOptions m_options;
    qint64 m_position = 0;
    const char *m_data = nullptr;
    qint64 m_length = 0;
    qint64 m_sent = 0;
    bool m_eof = false;
    bool m_streaming = false;
    bool m_started = false;
    bool m_done = false;
    bool m_valid = true;
    Result m_failure;
};

} // namespace NetVfs::Ftp

#endif
