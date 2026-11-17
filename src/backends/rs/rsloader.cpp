// SPDX-License-Identifier: LGPL-2.1-or-later
#include "rsloader.h"

#include <QtCore/QByteArray>

#include <cstring>
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

}
const nvr_table *table(Result *result)
{
    Library &lib = library();
    const std::scoped_lock lock(lib.mutex);
    if (!lib.table) {
        QByteArray path = qgetenv("NETVFS_RS_LIB");
        if (path.isEmpty())
            path = QByteArrayLiteral(NETVFS_RS_LIB_PATH);
        void *handle = dlopen(path.constData(), RTLD_NOW | RTLD_LOCAL);
        void *symbol = handle ? dlsym(handle, NVR_ENTRY) : nullptr;
        // POSIX gives data and function pointers one representation; C++17 has no cast between them
        // but a byte copy.
        nvr_get_fn get = nullptr;
        static_assert(sizeof get == sizeof symbol);
        std::memcpy(&get, &symbol, sizeof get);
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

}