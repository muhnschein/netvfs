// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CURLHANDLES_H
#define NETVFS_CURLHANDLES_H

#include <curl/curl.h>

#include <memory>

// Owners for libcurl's handles. libcurl declares all of them as void, so the
// deleter is what gives each kind its own type.
namespace NetVfs::Curl {

using EasyHandle = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>;
using MultiHandle = std::unique_ptr<CURLM, decltype(&curl_multi_cleanup)>;
using ShareHandle = std::unique_ptr<CURLSH, decltype(&curl_share_cleanup)>;

inline EasyHandle newEasyHandle()
{
    return EasyHandle(curl_easy_init(), &curl_easy_cleanup);
}

inline MultiHandle newMultiHandle()
{
    return MultiHandle(curl_multi_init(), &curl_multi_cleanup);
}

inline ShareHandle newShareHandle()
{
    return ShareHandle(curl_share_init(), &curl_share_cleanup);
}

// Sets options of an easy handle one after the other and keeps the first
// failure: later options are not applied once one was refused.
class OptionChain
{
public:
    explicit OptionChain(const EasyHandle &easy) : m_easy(easy) {}

    template<typename Value>
    OptionChain &set(CURLoption option, Value value)
    {
        if (m_code == CURLE_OK)
            m_code = curl_easy_setopt(m_easy.get(), option, value);
        return *this;
    }
    CURLcode code() const { return m_code; }

private:
    const EasyHandle &m_easy;
    CURLcode m_code = CURLE_OK;
};

// An empty owner, for members that are filled later.
inline EasyHandle noEasyHandle()
{
    return EasyHandle(nullptr, &curl_easy_cleanup);
}

inline MultiHandle noMultiHandle()
{
    return MultiHandle(nullptr, &curl_multi_cleanup);
}

inline ShareHandle noShareHandle()
{
    return ShareHandle(nullptr, &curl_share_cleanup);
}

} // namespace NetVfs::Curl

#endif
