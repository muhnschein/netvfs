// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DAVTRANSFER_H
#define NETVFS_DAVTRANSFER_H

#include "curlhandles.h"

#include <curl/curl.h>

#include <array>

namespace NetVfs::WebDav {
class Client;
struct Request;
struct Response;
}

// The state of one transfer while its easy handle is attached to the multi
// handle (davcallbacks.h): the callbacks of libcurl reach it as their user
// data. Defined in davclient.cpp: the members that do the work.
struct NetVfsDavTransfer {
    NetVfs::WebDav::Client *client = nullptr;
    const NetVfs::Curl::EasyHandle *easy = nullptr;   // the handle in use: the client's, or `owned`
    NetVfs::Curl::EasyHandle owned;                   // set when the transfer owns its handle
    const NetVfs::WebDav::Request *request = nullptr;
    NetVfs::WebDav::Response *response = nullptr;
    curl_slist *headers = nullptr;
    std::array<char, CURL_ERROR_SIZE> error {};
    bool attached = false;
    bool done = false;
    CURLcode code = CURLE_OK;
    bool sinkStopped = false;
    bool sourceFailed = false;
    bool paused = false;

    NetVfsDavTransfer() = default;
    ~NetVfsDavTransfer() { curl_slist_free_all(headers); }
    NetVfsDavTransfer(const NetVfsDavTransfer &) = delete;
    NetVfsDavTransfer &operator=(const NetVfsDavTransfer &) = delete;

    size_t receiveHeader(const char *data, size_t length) const;
    size_t receiveBody(const char *data, size_t length);
    size_t supplyBody(char *buffer, size_t capacity);
    int rewindBody() const;
    bool cancelRequested() const;
};

#endif
