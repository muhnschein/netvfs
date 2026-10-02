// SPDX-License-Identifier: LGPL-2.1-or-later
// SPEC-v2 XD-1: the DNS message codec behind mDNS discovery. decode() parses
// datagrams from the local network and must never crash, hang or read out of
// bounds. What it accepts must survive encode -> decode unchanged, the encoder
// must be deterministic, and the name helpers must agree with each other.
//
// fuzz-sources: src/core/dnsmessage.cpp
// fuzz-qt: Core Network
#include "dnsmessage.h"

#include <cstddef>
#include <cstdint>

using namespace NetVfs;

namespace {

void require(bool condition)
{
    if (!condition)
        __builtin_trap();
}

bool sameRecord(const Dns::Record &a, const Dns::Record &b)
{
    return Dns::canonicalName(a.name) == Dns::canonicalName(b.name) && a.type == b.type && a.cls == b.cls
        && a.cacheFlush == b.cacheFlush && a.ttl == b.ttl
        && Dns::canonicalName(a.target) == Dns::canonicalName(b.target) && a.priority == b.priority
        && a.weight == b.weight && a.port == b.port && a.txt == b.txt && a.address == b.address
        && a.rdata == b.rdata;
}

bool sameRecords(const QVector<Dns::Record> &a, const QVector<Dns::Record> &b)
{
    if (a.size() != b.size())
        return false;
    for (int i = 0; i < a.size(); ++i) {
        if (!sameRecord(a[i], b[i]))
            return false;
    }
    return true;
}

bool sameMessage(const Dns::Message &a, const Dns::Message &b)
{
    if (a.id != b.id || a.flags != b.flags || a.questions.size() != b.questions.size())
        return false;
    for (int i = 0; i < a.questions.size(); ++i) {
        const Dns::Question &x = a.questions[i];
        const Dns::Question &y = b.questions[i];
        if (Dns::canonicalName(x.name) != Dns::canonicalName(y.name) || x.type != y.type || x.cls != y.cls
            || x.unicastResponse != y.unicastResponse)
            return false;
    }
    return sameRecords(a.answers, b.answers) && sameRecords(a.authority, b.authority)
        && sameRecords(a.additional, b.additional);
}

void checkRoundTrip(const Dns::Message &message)
{
    const QByteArray wire = Dns::encode(message);
    if (wire.isEmpty())
        return;     // input that was compressed more cleverly than the encoder may not fit; nothing to compare
    Dns::Message again;
    require(Dns::decode(wire, &again));
    require(sameMessage(message, again));
    require(Dns::encode(again) == wire);
    const QByteArray plain = Dns::encode(message, false);
    if (!plain.isEmpty()) {
        Dns::Message fromPlain;
        require(Dns::decode(plain, &fromPlain));
        require(sameMessage(message, fromPlain));
    }
}

void checkNames(const QByteArray &name)
{
    bool ok = false;
    const QList<QByteArray> labels = Dns::splitName(name, &ok);
    if (!ok)
        return;
    bool again = false;
    require(Dns::splitName(Dns::joinName(labels), &again) == labels);
    require(again);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const QByteArray input(reinterpret_cast<const char *>(data), static_cast<int>(size));
    Dns::Message message;
    QString why;
    if (Dns::decode(input, &message, &why)) {
        checkRoundTrip(message);
        for (const Dns::Question &q : message.questions)
            checkNames(q.name);
        for (const Dns::Record &r : message.answers) {
            checkNames(r.name);
            Dns::txtValue(r.txt, "path");
            Dns::txtHasKey(r.txt, "u");
        }
    } else {
        require(message.questions.isEmpty() && message.answers.isEmpty() && message.authority.isEmpty()
                && message.additional.isEmpty());
    }
    checkNames(input);
    return 0;
}
