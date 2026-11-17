// SPDX-License-Identifier: LGPL-2.1-or-later
#include "rskeytools.h"
#include "rsloader.h"
#include "rsmarshal.h"

namespace NetVfs::Rs {

namespace {

// Private part is wiped twice: by free in Rust and by SshKeyMaterial here.
template <typename Call>
Result keyCall(SshKeyMaterial *out, const Call &call)
{
    Result r;
    const nvr_table *t = table(&r);
    if (!t)
        return r;
    nvr_key *raw = nullptr;
    r = resultOf(t, call(t, &raw));
    const Block<nvr_key> key(raw, Free(t));
    if (out)
        *out = key ? keyOf(*key) : SshKeyMaterial();
    return r;
}

}
Result RsKeyTools::generate(SshKeyMaterial *out)
{
    return keyCall(out, [](const nvr_table *t, nvr_key **key) { return t->key_generate(key); });
}

Result RsKeyTools::importKey(const QByteArray &fileContents, const QByteArray &passphrase, SshKeyMaterial *out)
{
    return keyCall(out, [&fileContents, &passphrase](const nvr_table *t, nvr_key **key) {
        return t->key_import(view(fileContents), view(passphrase), key);
    });
}

Result RsKeyTools::describe(const QByteArray &privateKey, SshKeyMaterial *out)
{
    return keyCall(out, [&privateKey](const nvr_table *t, nvr_key **key) {
        return t->key_describe(view(privateKey), key);
    });
}

}