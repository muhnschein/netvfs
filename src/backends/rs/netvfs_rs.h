/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_RS_H
#define NETVFS_RS_H

#include "../../bridge/ffi/netvfs_bridge_ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NVR_ENTRY "nvr_get"

typedef struct nvr_conn nvr_conn;
typedef struct nvr_read nvr_read;
typedef struct nvr_write nvr_write;

typedef struct nvr_credentials {
    nvb_bytes user;
    nvb_bytes secret;
    nvb_bytes domain;
} nvr_credentials;

typedef struct nvr_prompter {
    void *ctx;
    int (*prompt)(void *ctx, nvb_bytes name, nvb_bytes instruction,
                  const nvb_prompt *prompts, size_t n, nvb_reply *reply);
} nvr_prompter;

typedef struct nvr_write_opts {
    uint32_t disposition;
    int32_t create_mode;
    int64_t resume_offset;
    int64_t expected_size;
    uint8_t has_mtime;
    int64_t mtime_ms;
} nvr_write_opts;

typedef struct nvr_key {
    nvb_bytes private_key;
    nvb_bytes algorithm;
    nvb_bytes public_line;
    nvb_bytes fingerprint;
} nvr_key;

typedef struct nvr_table {
    void (*free)(void *p);
    void (*reply_set)(nvb_reply *r, const nvb_bytes *answers, size_t n);

    nvb_error *(*conn_new)(nvb_bytes provider, nvr_conn **out);
    void (*conn_free)(nvr_conn *c);
    void (*cancel)(nvr_conn *c);
    void (*reset_cancel)(nvr_conn *c);
    nvb_error *(*connect)(nvr_conn *c, const nvb_params *p, nvb_identity **seen);
    nvb_error *(*authenticate)(nvr_conn *c, const nvr_credentials *cr, const nvr_prompter *pr);
    nvb_error *(*capabilities)(nvr_conn *c, nvb_capabilities **out);
    void (*disconnect)(nvr_conn *c);
    nvb_error *(*keep_alive)(nvr_conn *c);

    nvb_error *(*stat)(nvr_conn *c, nvb_bytes path, int32_t follow, nvb_entry **out);
    nvb_error *(*list)(nvr_conn *c, nvb_bytes dir, uint32_t batch, int32_t resolve_symlinks,
                       nvb_list_sink_fn sink, void *ctx);
    nvb_error *(*make_dir)(nvr_conn *c, nvb_bytes path, int32_t exclusive);
    nvb_error *(*remove_file)(nvr_conn *c, nvb_bytes path);
    nvb_error *(*remove_dir)(nvr_conn *c, nvb_bytes path);
    nvb_error *(*rename)(nvr_conn *c, nvb_bytes from, nvb_bytes to, int32_t replace);
    nvb_error *(*set_attributes)(nvr_conn *c, nvb_bytes path, const nvb_attributes *a);
    nvb_error *(*read_link)(nvr_conn *c, nvb_bytes path, nvb_blob **target);
    nvb_error *(*make_symlink)(nvr_conn *c, nvb_bytes target, nvb_bytes link);
    nvb_error *(*make_hardlink)(nvr_conn *c, nvb_bytes existing, nvb_bytes link);
    nvb_error *(*copy)(nvr_conn *c, nvb_bytes from, nvb_bytes to, int32_t recursive, int32_t replace);
    nvb_error *(*checksum)(nvr_conn *c, nvb_bytes path, nvb_bytes algorithm, nvb_blob **digest);
    nvb_error *(*space_info)(nvr_conn *c, nvb_bytes dir, nvb_space *out);

    nvb_error *(*open_read)(nvr_conn *c, nvb_bytes path, nvr_read **out, int64_t *size);
    nvb_error *(*read)(nvr_read *h, int64_t offset, uint8_t *buf, size_t cap, size_t *len);
    void (*read_ahead)(nvr_read *h, int64_t offset, int64_t bytes);
    nvb_error *(*read_close)(nvr_read *h);
    nvb_error *(*open_write)(nvr_conn *c, nvb_bytes path, const nvr_write_opts *o, nvr_write **out);
    nvb_error *(*write)(nvr_write *h, const uint8_t *data, size_t len);
    int64_t (*position)(const nvr_write *h);
    nvb_error *(*commit)(nvr_write *h);
    void (*abort)(nvr_write *h);

    nvb_error *(*upload)(nvr_conn *c, nvb_bytes path, const nvb_upload_opts *o,
                         const nvb_io *io, const nvb_progress *pr);
    nvb_error *(*download)(nvr_conn *c, nvb_bytes path, int64_t offset, int64_t length,
                           const nvb_io *io, const nvb_progress *pr);

    nvb_error *(*key_generate)(nvr_key **out);
    nvb_error *(*key_import)(nvb_bytes file, nvb_bytes passphrase, nvr_key **out);
    nvb_error *(*key_describe)(nvb_bytes private_key, nvr_key **out);

    nvb_error *(*search)(nvr_conn *c, nvb_bytes root, nvb_bytes text, uint32_t limit,
                         nvb_list_sink_fn sink, void *ctx);
} nvr_table;

typedef const nvr_table *(*nvr_get_fn)(void);

const nvr_table *nvr_get(void);

#ifdef __cplusplus
}
#endif

#endif
