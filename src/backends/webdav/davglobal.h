/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_DAVGLOBAL_H
#define NETVFS_DAVGLOBAL_H

#ifdef __cplusplus
extern "C" {
#endif

/* curl_global_init with wiping memory callbacks; nonzero on success. Call
 * once per process (std::call_once in Client). */
int netvfs_webdav_curl_init(void);

#ifdef __cplusplus
}
#endif

#endif
