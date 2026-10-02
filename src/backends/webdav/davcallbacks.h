/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_DAVCALLBACKS_H
#define NETVFS_DAVCALLBACKS_H

/*
 * libcurl callbacks of the WebDAV client. Their signatures (untyped user
 * data, mutable buffers) are dictated by libcurl, so they live in C
 * (davcallbacks.c) and hand typed arguments to the handlers that davclient.cpp
 * implements; the client only sees this typed interface.
 */
#include <curl/curl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The state of one transfer; defined by the C++ client. It is the user data
 * of every callback below. */
struct NetVfsDavTransfer;

/* Handlers, implemented in davclient.cpp. Return values follow libcurl's
 * callback conventions. */
size_t netvfs_dav_on_header(struct NetVfsDavTransfer *transfer, const char *line, size_t length);
size_t netvfs_dav_on_body(struct NetVfsDavTransfer *transfer, const char *data, size_t length);
size_t netvfs_dav_on_read(struct NetVfsDavTransfer *transfer, char *buffer, size_t capacity);
int netvfs_dav_on_seek(struct NetVfsDavTransfer *transfer, curl_off_t offset, int origin);
int netvfs_dav_on_progress(const struct NetVfsDavTransfer *transfer);

/* For CURLOPT_HEADERFUNCTION, _WRITEFUNCTION, _READFUNCTION, _SEEKFUNCTION and
 * _XFERINFOFUNCTION; the matching *DATA option is the transfer. */
extern const curl_write_callback netvfs_dav_header_callback;
extern const curl_write_callback netvfs_dav_write_callback;
extern const curl_read_callback netvfs_dav_read_callback;
extern const curl_seek_callback netvfs_dav_seek_callback;
extern const curl_xferinfo_callback netvfs_dav_progress_callback;

#ifdef __cplusplus
}
#endif

#endif
