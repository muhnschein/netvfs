// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_ARGS_H
#define NETVFS_BRIDGE_ARGS_H

#include "error.h"
#include "types.h"
#include "unixfd.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QVariant>
#include <QtCore/QVector>

// SPEC-v2 XSEC-7: argument validation of the bridge protocol (XB-10), as pure
// functions over decoded arguments (wire.h decodeArguments) so that they can
// be fuzzed without D-Bus (tests/fuzz/fuzz_bridge_args.cpp). Every path goes
// through Names::decode and Paths::normalize, every number is range-checked,
// every string is length- and charset-checked, unknown option keys are
// refused. File descriptors are checked separately (fdcheck.h) because that
// needs the descriptor itself.
namespace NetVfs {
namespace Bridge {

enum class Lane { Interactive, Bulk, Stream };
QString laneName(Lane lane);

enum class Method {
    Hello, GetConsent, RequestConsent,
    ListLocations, Capabilities, Disconnect,
    ConnectAdHoc, ForgetAdHoc,
    Discover,
    List,
    Stat, ReadLink, SpaceInfo, Checksum,
    MakeDir, RemoveFile, RemoveDir, Rename, SetAttributes, MakeSymlink, MakeHardlink, ServerCopy,
    OpenRead, Read, ReadAhead, Close,
    Upload, Download, CopyAcross, RemoveTree, Walk, Cancel,
    Answer,
    OpenAccountSettings, AddAccount
};

struct MethodInfo {
    Method method;
    const char *name;
    const char *in;          // input signature
    const char *out;         // output signature
    Lane lane;               // default lane
    bool needsConsent;       // XB-6: PermissionDenied until granted
};

// The org.netvfs.Bridge1 methods; the contract test compares this table with
// the introspection XML.
const QVector<MethodInfo> &methods();
const MethodInfo *findMethod(const QString &name);

// XB-17 and XSEC-7 limits.
namespace Limits {
constexpr int MaxListBatch = 512;
constexpr int DefaultListBatch = 256;
constexpr qint64 MaxListBatchBytes = 1 << 20;
constexpr quint32 MaxReadBytes = 1 << 20;
constexpr qint64 MaxReadAheadBytes = 16 << 20;
constexpr qint64 MaxOffset = Q_INT64_C(1) << 62;
constexpr int MaxPathBytes = 4096;
constexpr int MaxSecretBytes = 64 * 1024;
constexpr int MaxUrlLength = 4096;
constexpr int MaxShortString = 256;
constexpr int MaxIdLength = 64;
constexpr int MaxWalkDepth = 4096;
constexpr int MaxAnswers = 16;
constexpr qint64 MinTimeMs = Q_INT64_C(-62135596800000);   // 0001-01-01
constexpr qint64 MaxTimeMs = Q_INT64_C(253402300799999);   // 9999-12-31
} // namespace Limits

struct TransferOptions {
    qint64 offset = 0;                 // first byte, in the local file and remotely
    qint64 size = -1;                  // Upload: bytes to send (-1: to EOF); Download: length
    WriteOptions::Disposition disposition = WriteOptions::CreateNew;   // XC-13 default
    qint32 createMode = -1;
    qint64 mtimeMs = -1;               // -1: none (only with "mtimeMs" absent)
    bool hasMtime = false;
};

struct TreeOptions {
    bool recursive = false;
    bool replace = false;
    int maxDepth = -1;
    bool followSymlinks = false;
    bool postOrder = false;
};

struct AdHocOptions {
    QString user;
    QString securityProfile;           // smb: "strict", "signed", "legacy", "guest"
};

struct QuestionAnswer {
    bool accept = false;
    QVector<QByteArray> answers;       // keyboard-interactive; wiped by the user of the Call
};

// One validated call. Which fields are set depends on the method.
struct Call {
    Method method = Method::Hello;
    QString loc;                       // location id
    QString loc2;                      // CopyAcross destination
    QString path;                      // normalised (Paths::normalize)
    QString path2;                     // second path (Rename to, links, copies)
    QString linkTarget;                // MakeSymlink: verbatim target (Names::decode)
    QString text;                      // client, url, algo, provider, question id
    Lane lane = Lane::Interactive;
    quint32 number = 0;                // protocol, batch, handle, id, max
    qint64 offset = 0;
    qint64 length = 0;
    bool flag = false;                 // follow, exclusive, replace, on
    QByteArray secret;                 // ConnectAdHoc only; wiped by the user (XB-16)
    UnixFd fd;                         // Upload, Download (checked later, fdcheck.h)
    AttributeChanges attributes;
    TransferOptions transfer;
    TreeOptions tree;
    AdHocOptions adHoc;
    QuestionAnswer answer;
};

// Validates a call. `args` comes from decodeArguments(); secrets are moved
// out of it (the variant is cleared) so that only Call::secret holds them.
// Errors: InvalidName for paths, ProtocolError for everything else (the
// adaptor maps it to org.freedesktop.DBus.Error.InvalidArgs), Unsupported for
// an unknown method.
Result validateCall(const QString &member, const QString &signature, QVariantList *args, Call *out);

// XB-16, XSEC-6: overwrites and drops the secret and the keyboard-interactive
// answers of a call (SEC-5).
void wipeSecrets(Call *call);

// Building blocks, exposed for tests.
Result validatePath(const QVariant &bytes, QString *out);
Result validateLocationId(const QVariant &value, QString *out);
Result validateLane(const QVariant &value, Lane fallback, Lane *out);
bool isValidLocationId(const QString &id);
bool isValidToken(const QString &value, int maxLength);   // [a-z0-9-]{1,max}

} // namespace Bridge
} // namespace NetVfs

#endif
