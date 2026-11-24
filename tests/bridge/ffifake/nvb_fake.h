/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NVB_FAKE_H
#define NVB_FAKE_H

#include "netvfs_bridge_ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NVB_FAKE_ENTRY "nvb_fake_get"

typedef struct nvb_fake {
    void (*reset)(void);
    void (*add_file)(nvb_bytes path, nvb_bytes data);
    void (*add_dir)(nvb_bytes path, int32_t mode);
    void (*add_symlink)(nvb_bytes path, nvb_bytes target);
    int32_t (*exists)(nvb_bytes path);
    nvb_blob *(*file_data)(nvb_bytes path);
    int32_t (*node_mode)(nvb_bytes path);
    void (*set_identity_pin)(nvb_bytes pin);
    void (*set_otp)(nvb_bytes otp);
    void (*set_credentials)(nvb_bytes user, nvb_bytes secret);
    void (*set_chunk_delay_ms)(int32_t ms);
    void (*fail_op)(nvb_bytes op, nvb_bytes error_name);
    int32_t (*log_count)(nvb_bytes prefix);
    int32_t (*live_backends)(void);
    void (*free)(void *p);
} nvb_fake;

typedef const nvb_fake *(*nvb_fake_get_fn)(void);

#if defined(__GNUC__)
__attribute__((visibility("default")))
#endif
const nvb_fake *nvb_fake_get(void);

#ifdef __cplusplus
}
#endif

#endif
