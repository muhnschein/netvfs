// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CURLHANDLES_H
#define NETVFS_CURLHANDLES_H

#include <curl/curl.h>

#include <utility>

// Owners for libcurl's handles. libcurl declares all of them as void, so the
// owner type is what gives each kind its own type.
namespace NetVfs::Curl {

// Owns what `Init` returned and releases it with `Cleanup`. Movable, not
// copyable; empty by default.
template<auto Init, auto Cleanup>
class Handle
{
public:
    using Pointer = decltype(Init());

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

    static Handle create() { return Handle(Init()); }

    explicit operator bool() const { return m_pointer != nullptr; }
    Pointer get() const { return m_pointer; }
    void reset() { release(); }

private:
    void release()
    {
        if (m_pointer)
            Cleanup(m_pointer);
        m_pointer = nullptr;
    }

    Pointer m_pointer = nullptr;
};

using EasyHandle = Handle<&curl_easy_init, &curl_easy_cleanup>;
using MultiHandle = Handle<&curl_multi_init, &curl_multi_cleanup>;
using ShareHandle = Handle<&curl_share_init, &curl_share_cleanup>;

// XSEC-2: every easy handle starts with TLS 1.2 as its floor, whatever
// libcurl's default is. Backends that pin the version more tightly set their
// own after this.
inline EasyHandle newEasyHandle()
{
    EasyHandle easy(curl_easy_init());
    if (easy)
        curl_easy_setopt(easy.get(), CURLOPT_SSLVERSION,
                         long(CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT));
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
