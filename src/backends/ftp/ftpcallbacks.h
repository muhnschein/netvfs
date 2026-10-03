/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_FTPCALLBACKS_H
#define NETVFS_FTPCALLBACKS_H

/*
 * libcurl callbacks of the FTP backend. Their signatures (untyped user data,
 * mutable buffers) are dictated by libcurl, so they live in C
 * (ftpcallbacks.c) and hand typed arguments to the handlers that
 * ftpconnection.cpp implements; the connection only sees this typed
 * interface.
 */
#include <curl/curl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The user data of the callbacks of a Connection, and of the identity probe;
 * both are defined by the C++ side. */
struct NetVfsFtpHooks;
struct NetVfsFtpProbeState;

size_t netvfs_ftp_on_write(const struct NetVfsFtpHooks *hooks, const char *data, size_t length);
size_t netvfs_ftp_on_read(const struct NetVfsFtpHooks *hooks, char *buffer, size_t capacity);
size_t netvfs_ftp_on_header(const struct NetVfsFtpHooks *hooks, const char *data, size_t length);
void netvfs_ftp_on_debug(const struct NetVfsFtpHooks *hooks, curl_infotype type, const char *data, size_t length);
int netvfs_ftp_on_progress(const struct NetVfsFtpHooks *hooks, curl_off_t download_total, curl_off_t downloaded,
                           curl_off_t upload_total, curl_off_t uploaded);

size_t netvfs_ftp_probe_header(struct NetVfsFtpProbeState *state, const char *data, size_t length);
int netvfs_ftp_probe_progress(const struct NetVfsFtpProbeState *state);

/* For the Connection: CURLOPT_WRITEFUNCTION, _READFUNCTION, _HEADERFUNCTION,
 * _DEBUGFUNCTION and _XFERINFOFUNCTION with a struct NetVfsFtpHooks as the matching *DATA. */
extern const curl_write_callback netvfs_ftp_write_callback;
extern const curl_read_callback netvfs_ftp_read_callback;
extern const curl_write_callback netvfs_ftp_header_callback;
extern const curl_xferinfo_callback netvfs_ftp_progress_callback;
extern const curl_debug_callback netvfs_ftp_debug_callback;

/* For the probe, with a struct NetVfsFtpProbeState as *DATA. */
extern const curl_write_callback netvfs_ftp_probe_header_callback;
extern const curl_xferinfo_callback netvfs_ftp_probe_progress_callback;

#ifdef __cplusplus
}
#endif

#endif
