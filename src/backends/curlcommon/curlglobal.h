/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_CURLGLOBAL_H
#define NETVFS_CURLGLOBAL_H

#ifdef __cplusplus
extern "C" {
#endif

/* curl_global_init with wiping memory callbacks; nonzero on success. Every
 * libcurl based backend plugin (WebDAV, FTP) calls this once (std::call_once)
 * before its first libcurl call. libcurl honours the memory callbacks of the
 * first initialisation in the process only, so all plugins must use this one
 * function: whichever plugin loads first, freed blocks are wiped (SEC-5). */
int netvfs_curl_global_init(void);

#ifdef __cplusplus
}
#endif

#endif
