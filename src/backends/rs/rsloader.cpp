// SPDX-License-Identifier: LGPL-2.1-or-later
#include "rsloader.h"

#include <QtCore/QByteArray>

#include <dlfcn.h>
#include <mutex>

namespace NetVfs::Rs {

namespace {

struct Library {
    std::mutex mutex;
    const nvr_table *table = nullptr;
};

Library &library()
{
    static Library loaded;
    return loaded;
}

} // namespace

const nvr_table *table(Result *result)
{
    Library &lib = library();
    const std::scoped_lock lock(lib.mutex);
    if (!lib.table) {
        QByteArray path = qgetenv("NETVFS_RS_LIB");
        if (path.isEmpty())
            path = QByteArrayLiteral(NETVFS_RS_LIB_PATH);
        void *handle = dlopen(path.constData(), RTLD_NOW | RTLD_LOCAL);
        const auto get = handle ? reinterpret_cast<nvr_get_fn>(dlsym(handle, NVR_ENTRY)) : nullptr;
        if (!get) {
            *result = Result(Error::Internal, QStringLiteral("netvfs Rust backends not installed"),
                             QString::fromLocal8Bit(dlerror()));
            if (handle)
                dlclose(handle);
            return nullptr;
        }
        lib.table = get();
    }
    *result = Result::success();
    return lib.table;
}

} // namespace NetVfs::Rs
