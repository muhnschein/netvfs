/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_SMBCALLBACKS_H
#define NETVFS_SMBCALLBACKS_H

/*
 * Completion callbacks for libsmb2's asynchronous requests. Their signature
 * (smb2_command_cb, with untyped pointers) is dictated by libsmb2, so they
 * live in C (smbcallbacks.c); the backend only sees this typed state.
 */
#include "smb2api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The outcome of one request. It is the callback data of the request. */
struct NetVfsSmbCompletion {
    int done;
    int orphaned;               /* abandoned by the backend: close what it opened */
    int status;                 /* libsmb2's status: >= 0 success, -errno failure */
    uint32_t ntStatus;          /* smb2_get_nterror() at completion */
    struct smb2fh *fh;          /* result of an open */
    struct smb2dir *dir;        /* result of an opendir */
};

/* For requests without a result object (stat, write, close, ...). */
extern const smb2_command_cb netvfs_smb_complete_plain;
/* For smb2_open_async(): stores the file handle. */
extern const smb2_command_cb netvfs_smb_complete_open;
/* For smb2_opendir_async(): stores the directory handle. */
extern const smb2_command_cb netvfs_smb_complete_opendir;

#ifdef __cplusplus
}
#endif

#endif
