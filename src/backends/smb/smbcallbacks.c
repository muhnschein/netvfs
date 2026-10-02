/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "smbcallbacks.h"

#include <stdlib.h>

static void finish(struct smb2_context *smb2, struct NetVfsSmbCompletion *completion, int status);

/* Completion of a close sent for an abandoned open: nothing waits for it. */
static void release_completion(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
    struct NetVfsSmbCompletion *completion = (struct NetVfsSmbCompletion *)private_data;

    (void)command_data;
    finish(smb2, completion, status);
    free(completion);
}

static void close_orphaned_file(struct smb2_context *smb2, struct smb2fh *fh)
{
    struct NetVfsSmbCompletion *closing = calloc(1, sizeof(*closing));

    if (closing && smb2_close_async(smb2, fh, release_completion, closing) < 0)
        free(closing);
}

static void finish(struct smb2_context *smb2, struct NetVfsSmbCompletion *completion, int status)
{
    /* A handle opened by a request that was abandoned is closed again. */
    if (completion->orphaned && completion->fh)
        close_orphaned_file(smb2, completion->fh);
    if (completion->orphaned && completion->dir)
        smb2_closedir(smb2, completion->dir);
    completion->done = 1;
    completion->status = status;
    /* SPEC-smb 5: the NT status is the only input to classification. */
    completion->ntStatus = (uint32_t)smb2_get_nterror(smb2);
}

static void complete_plain(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
    (void)command_data;
    finish(smb2, (struct NetVfsSmbCompletion *)private_data, status);
}

static void complete_open(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
    struct NetVfsSmbCompletion *completion = (struct NetVfsSmbCompletion *)private_data;

    if (status >= 0)
        completion->fh = (struct smb2fh *)command_data;
    finish(smb2, completion, status);
}

static void complete_opendir(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
    struct NetVfsSmbCompletion *completion = (struct NetVfsSmbCompletion *)private_data;

    if (status >= 0)
        completion->dir = (struct smb2dir *)command_data;
    finish(smb2, completion, status);
}

const smb2_command_cb netvfs_smb_complete_plain = complete_plain;
const smb2_command_cb netvfs_smb_complete_open = complete_open;
const smb2_command_cb netvfs_smb_complete_opendir = complete_opendir;
