/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "smbcallbacks.h"

#include <smb2/libsmb2-raw.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

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
    /* Replies hand over -nterror_to_errno(status) as `status` and leave the
     * raw NT status in smb2_get_nterror() (SPEC-smb 5). The library's request
     * timeout (M-7, lib/pdu.c) instead passes the raw NT status as `status`.
     * A raw NT status has a high bit set, an errno does not, so the two cases
     * are told apart by size and the timeout is normalised into the shape the
     * classifier expects (SMB2_STATUS_IO_TIMEOUT -> ETIMEDOUT). */
    if (status <= -0x01000000) {
        completion->ntStatus = (uint32_t)status;
        completion->status = -nterror_to_errno((uint32_t)status);
        return;
    }
    completion->status = status;
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

/* SPEC-v2 XC-11: CREATE (write attributes) + SET_INFO (FileBasicInformation)
 * + CLOSE as one compound. The raw callbacks get NT status codes. */
struct set_basic_data {
    struct NetVfsSmbCompletion *completion;
    uint32_t status;            /* first failing NT status of the compound */
    int pending;                /* callbacks still to come: CREATE, SET_INFO, CLOSE */
};

static void set_basic_step(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
    struct set_basic_data *data = (struct set_basic_data *)private_data;
    struct NetVfsSmbCompletion *completion = data->completion;
    uint32_t nt;

    (void)command_data;
    if (data->status == SMB2_STATUS_SUCCESS)
        data->status = (uint32_t)status;
    if (--data->pending > 0)
        return;
    nt = data->status;
    free(data);
    finish(smb2, completion, nt == SMB2_STATUS_SUCCESS ? 0 : -nterror_to_errno(nt));
    completion->ntStatus = nt;
}

int netvfs_smb_set_basic_info_async(struct smb2_context *smb2, const char *path,
                                    const struct smb2_file_basic_info *info,
                                    struct NetVfsSmbCompletion *completion)
{
    struct set_basic_data *data = calloc(1, sizeof(*data));
    struct smb2_create_request create;
    struct smb2_set_info_request set;
    struct smb2_close_request closing;
    struct smb2_file_basic_info basic = *info;
    struct smb2_pdu *pdu;
    struct smb2_pdu *next;

    if (!data)
        return -ENOMEM;
    data->completion = completion;
    data->pending = 3;

    memset(&create, 0, sizeof(create));
    create.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
    create.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
    create.desired_access = SMB2_FILE_WRITE_ATTRIBUTES;
    create.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
    create.create_disposition = SMB2_FILE_OPEN;
    create.name = path;
    pdu = smb2_cmd_create_async(smb2, &create, set_basic_step, data);
    if (!pdu) {
        free(data);
        return -ENOMEM;
    }

    memset(&set, 0, sizeof(set));
    set.info_type = SMB2_0_INFO_FILE;
    set.file_info_class = SMB2_FILE_BASIC_INFORMATION;
    memcpy(set.file_id, compound_file_id, SMB2_FD_SIZE);
    set.input_data = &basic;
    next = smb2_cmd_set_info_async(smb2, &set, set_basic_step, data);
    if (!next) {
        smb2_free_pdu(smb2, pdu);
        free(data);
        return -ENOMEM;
    }
    smb2_add_compound_pdu(smb2, pdu, next);

    memset(&closing, 0, sizeof(closing));
    memcpy(closing.file_id, compound_file_id, SMB2_FD_SIZE);
    next = smb2_cmd_close_async(smb2, &closing, set_basic_step, data);
    if (!next) {
        smb2_free_pdu(smb2, pdu);
        free(data);
        return -ENOMEM;
    }
    smb2_add_compound_pdu(smb2, pdu, next);
    smb2_queue_pdu(smb2, pdu);
    return 0;
}
