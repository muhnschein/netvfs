// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CURLHANDLES_H
#define NETVFS_CURLHANDLES_H

#include <curl/curl.h>

#include <utility>

// Owners for libcurl's handles. libcurl declares all of them as void, so the
// owner type is what gives each kind its own type; the traits name the
// handle through libcurl's own typedef (CURL, CURLM, CURLSH) and say how it
// is made and released.
namespace NetVfs::Curl {

struct EasyTraits {
    using Pointer = CURL *;
    static Pointer init() { return curl_easy_init(); }
    static void cleanup(Pointer pointer) { curl_easy_cleanup(pointer); }
};

struct MultiTraits {
    using Pointer = CURLM *;
    static Pointer init() { return curl_multi_init(); }
    static void cleanup(Pointer pointer) { curl_multi_cleanup(pointer); }
};

struct ShareTraits {
    using Pointer = CURLSH *;
    static Pointer init() { return curl_share_init(); }
    static void cleanup(Pointer pointer) { curl_share_cleanup(pointer); }
};

// Owns what `Traits::init` returned and releases it with `Traits::cleanup`.
// Movable, not copyable; empty by default.
template<typename Traits>
class Handle
{
public:
    using Pointer = typename Traits::Pointer;

    Handle() = default;
    explicit Handle(Pointer pointer) : m_pointer(pointer) {}
    ~Handle() { release(); }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    Handle(Handle &&other) noexcept : m_pointer(std::exchange(other.m_pointer, nullptr)) {}
    Handle &operator=(Handle &&other) noexcept
    {
        if (this != &other) {
            release();
            m_pointer = std::exchange(other.m_pointer, nullptr);
        }
        return *this;
    }

    static Handle create() { return Handle(Traits::init()); }

    explicit operator bool() const { return m_pointer != nullptr; }
    Pointer get() const { return m_pointer; }
    void reset() { release(); }

private:
    void release()
    {
        if (m_pointer)
            Traits::cleanup(m_pointer);
        m_pointer = nullptr;
    }

    Pointer m_pointer = nullptr;
};

using EasyHandle = Handle<EasyTraits>;
using MultiHandle = Handle<MultiTraits>;
using ShareHandle = Handle<ShareTraits>;

// XSEC-2: every easy handle starts with TLS 1.2 as its floor, whatever
// libcurl's default is; the ceiling stays libcurl's default. Backends that
// pin the version more tightly set their own after this.
inline EasyHandle newEasyHandle()
{
    EasyHandle easy(curl_easy_init());
    if (easy)
        curl_easy_setopt(easy.get(), CURLOPT_SSLVERSION,
                         static_cast<long>(CURL_SSLVERSION_TLSv1_2));
    return easy;
}

inline MultiHandle newMultiHandle()
{
    return MultiHandle::create();
}

inline ShareHandle newShareHandle()
{
    return ShareHandle::create();
}

// Empty owners, for members that are filled later.
inline EasyHandle noEasyHandle()
{
    return EasyHandle();
}

inline MultiHandle noMultiHandle()
{
    return MultiHandle();
}

inline ShareHandle noShareHandle()
{
    return ShareHandle();
}

} // namespace NetVfs::Curl

#endif
