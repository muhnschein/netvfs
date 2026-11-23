/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_BRIDGE_FFI_H
#define NETVFS_BRIDGE_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NVB_FFI_ENTRY "nvb_ffi_get"

typedef struct nvb_bytes {
    const uint8_t *ptr;
    size_t len;
} nvb_bytes;

typedef struct nvb_conn nvb_conn;
typedef struct nvb_handle nvb_handle;
typedef struct nvb_discovery nvb_discovery;
typedef struct nvb_reply nvb_reply;

typedef struct nvb_error {
    nvb_bytes name;
    nvb_bytes message;
    nvb_bytes detail;
    int64_t retry_after_ms;
} nvb_error;

typedef struct nvb_blob {
    nvb_bytes data;
} nvb_blob;

enum {
    NVB_VALUE_STRING = 1,
    NVB_VALUE_BOOL = 2,
    NVB_VALUE_INT = 3,
    NVB_VALUE_BYTES = 4,
    NVB_VALUE_STRING_LIST = 5
};

typedef struct nvb_value {
    uint32_t kind;
    int64_t number;
    nvb_bytes bytes;
    const nvb_bytes *items;
    size_t n_items;
} nvb_value;

typedef struct nvb_kv {
    nvb_bytes key;
    nvb_value value;
} nvb_kv;

typedef struct nvb_params {
    nvb_bytes provider;
    nvb_bytes host;
    int32_t port;
    nvb_bytes username;
    const nvb_kv *options;
    size_t n_options;
    int32_t connect_timeout_ms;
    int32_t request_timeout_ms;
} nvb_params;

typedef struct nvb_url {
    nvb_params params;
    nvb_bytes path;
} nvb_url;

typedef struct nvb_entry {
    nvb_bytes name;
    uint8_t type;
    uint8_t target_type;
    uint16_t flags;
    int32_t mode;
    int64_t size;
    int64_t mtime_ms;
    int64_t ctime_ms;
    int64_t atime_ms;
    int64_t uid;
    int64_t gid;
    nvb_bytes owner;
    nvb_bytes group;
    nvb_bytes etag;
    nvb_bytes content_type;
} nvb_entry;

typedef struct nvb_capabilities {
    const nvb_bytes *flags;
    size_t n_flags;
    const nvb_bytes *checksum_algorithms;
    size_t n_checksum_algorithms;
    int64_t max_name_bytes;
} nvb_capabilities;

typedef struct nvb_space {
    int64_t free_bytes;
    int64_t total_bytes;
    int64_t used_bytes;
} nvb_space;

typedef struct nvb_attributes {
    int32_t mode;
    uint8_t has_mtime;
    uint8_t has_atime;
    int64_t mtime_ms;
    int64_t atime_ms;
} nvb_attributes;

enum { NVB_IDENTITY_NONE = 0, NVB_IDENTITY_SSH = 1, NVB_IDENTITY_TLS = 2 };

typedef struct nvb_identity {
    uint32_t kind;
    nvb_bytes algorithm;
    nvb_bytes public_key;
    nvb_bytes fingerprint;
    nvb_bytes pin;
} nvb_identity;

enum {
    NVB_SECRET_NONE = 0,
    NVB_SECRET_BYTES = 1,
    NVB_SECRET_SIGNON = 2
};

typedef struct nvb_secret {
    uint32_t source;
    nvb_bytes user;
    nvb_bytes secret;
    uint32_t credentials_id;
    uint8_t secret_optional;
} nvb_secret;

enum {
    NVB_ID_USE_CHECK = 0,
    NVB_ID_ACCEPT_UNKNOWN = 1,
    NVB_ID_CANCEL = 2
};

typedef struct nvb_prompt {
    nvb_bytes text;
    uint8_t echo;
} nvb_prompt;

typedef struct nvb_establish_hooks {
    void *ctx;
    uint32_t (*identity)(void *ctx, const nvb_identity *seen, const nvb_error *check);
    int (*prompt)(void *ctx, nvb_bytes name, nvb_bytes instruction,
                  const nvb_prompt *prompts, size_t n_prompts, nvb_reply *reply);
} nvb_establish_hooks;

enum {
    NVB_PHASE_CONNECT = 1,
    NVB_PHASE_IDENTITY = 2,
    NVB_PHASE_CREDENTIALS = 3,
    NVB_PHASE_AUTHENTICATE = 4,
    NVB_PHASE_DONE = 5
};

typedef int (*nvb_list_sink_fn)(void *ctx, const nvb_entry *entries, size_t n);

typedef struct nvb_walk_opts {
    int32_t max_depth;
    uint8_t follow_symlinks;
    uint8_t post_order;
    uint8_t stop_on_list_error;
} nvb_walk_opts;

typedef int (*nvb_walk_visit_fn)(void *ctx, nvb_bytes path, const nvb_entry *entry);

typedef struct nvb_progress {
    void *ctx;
    void (*update)(void *ctx, int64_t done, int64_t total);
    int (*canceled)(void *ctx);
} nvb_progress;

typedef struct nvb_io {
    void *ctx;
    uint8_t sequential;
    int64_t size;
    int64_t (*read)(void *ctx, int64_t pos, uint8_t *buf, size_t cap);
    int64_t (*write)(void *ctx, int64_t pos, const uint8_t *buf, size_t len);
} nvb_io;

enum {
    NVB_DISPOSITION_CREATE_NEW = 0,
    NVB_DISPOSITION_TRUNCATE = 1,
    NVB_DISPOSITION_RESUME = 2
};

typedef struct nvb_upload_opts {
    uint32_t disposition;
    int32_t create_mode;
    int64_t resume_offset;
    int64_t expected_size;
    uint8_t has_mtime;
    int64_t mtime_ms;
} nvb_upload_opts;

typedef struct nvb_nearby {
    nvb_bytes name;
    nvb_bytes provider;
    nvb_bytes host;
    uint16_t port;
} nvb_nearby;

typedef struct nvb_discovery_hooks {
    void *ctx;
    void (*changed)(void *ctx, const nvb_nearby *items, size_t n);
} nvb_discovery_hooks;

typedef struct nvb_ffi {
    int32_t (*init)(nvb_bytes app_name);
    int32_t (*run)(void);
    void (*quit)(int32_t exit_code);
    int32_t (*post)(void (*fn)(void *ctx), void *ctx);
    void (*shutdown)(void);
    void (*free)(void *p);

    int32_t (*provider_available)(nvb_bytes provider);
    nvb_error *(*url_parse)(nvb_bytes url, nvb_url **out);
    nvb_error *(*url_format)(const nvb_params *params, nvb_bytes path, nvb_blob **out);

    nvb_error *(*conn_new)(nvb_bytes provider, nvb_conn **out);
    void (*conn_free)(nvb_conn *conn);
    void (*conn_cancel)(nvb_conn *conn);
    void (*conn_reset_cancel)(nvb_conn *conn);
    nvb_error *(*conn_establish)(nvb_conn *conn, const nvb_params *params, nvb_bytes pin,
                                 const nvb_secret *secret, const nvb_establish_hooks *hooks,
                                 uint32_t *phase);
    void (*reply_set)(nvb_reply *reply, const nvb_bytes *answers, size_t n_answers);
    nvb_error *(*conn_capabilities)(nvb_conn *conn, nvb_capabilities **out);

    nvb_error *(*conn_stat)(nvb_conn *conn, nvb_bytes path, int32_t follow, nvb_entry **out);
    nvb_error *(*conn_list)(nvb_conn *conn, nvb_bytes dir, uint32_t batch_size,
                            nvb_list_sink_fn sink, void *ctx);
    nvb_error *(*conn_read_link)(nvb_conn *conn, nvb_bytes path, nvb_blob **target);
    nvb_error *(*conn_space_info)(nvb_conn *conn, nvb_bytes path, nvb_space *out);
    nvb_error *(*conn_checksum)(nvb_conn *conn, nvb_bytes path, nvb_bytes algorithm,
                                nvb_blob **digest);
    nvb_error *(*conn_make_dir)(nvb_conn *conn, nvb_bytes path, int32_t exclusive);
    nvb_error *(*conn_remove_file)(nvb_conn *conn, nvb_bytes path);
    nvb_error *(*conn_remove_dir)(nvb_conn *conn, nvb_bytes path);
    nvb_error *(*conn_rename)(nvb_conn *conn, nvb_bytes from, nvb_bytes to, int32_t replace);
    nvb_error *(*conn_set_attributes)(nvb_conn *conn, nvb_bytes path,
                                      const nvb_attributes *changes);
    nvb_error *(*conn_make_symlink)(nvb_conn *conn, nvb_bytes target, nvb_bytes link_path);
    nvb_error *(*conn_make_hardlink)(nvb_conn *conn, nvb_bytes existing, nvb_bytes new_path);
    nvb_error *(*conn_copy)(nvb_conn *conn, nvb_bytes from, nvb_bytes to,
                            int32_t recursive, int32_t replace);

    nvb_error *(*conn_open_read)(nvb_conn *conn, nvb_bytes path, nvb_handle **out,
                                 int64_t *size);
    nvb_error *(*handle_read)(nvb_handle *h, int64_t offset, uint8_t *buf, size_t cap,
                              size_t *len);
    void (*handle_read_ahead)(nvb_handle *h, int64_t offset, int64_t bytes);
    nvb_error *(*handle_close)(nvb_handle *h);

    nvb_error *(*conn_upload)(nvb_conn *conn, nvb_bytes path, const nvb_upload_opts *opts,
                              const nvb_io *io, const nvb_progress *progress);
    nvb_error *(*conn_download)(nvb_conn *conn, nvb_bytes path, int64_t offset,
                                int64_t length, const nvb_io *io,
                                const nvb_progress *progress);
    nvb_error *(*remove_tree)(nvb_conn *conn, nvb_bytes path, const nvb_progress *progress,
                              int64_t *files, int64_t *dirs);
    nvb_error *(*walk)(nvb_conn *conn, nvb_bytes root, const nvb_walk_opts *opts,
                       nvb_walk_visit_fn visit, void *ctx);
    nvb_error *(*copy_across)(nvb_conn *source, nvb_bytes source_path,
                              nvb_conn *destination, nvb_bytes destination_path,
                              int32_t recursive, int32_t replace,
                              const nvb_progress *progress);

    nvb_discovery *(*discovery_new)(const nvb_discovery_hooks *hooks);
    int32_t (*discovery_set_running)(nvb_discovery *d, int32_t on);
    void (*discovery_free)(nvb_discovery *d);
} nvb_ffi;

typedef const nvb_ffi *(*nvb_ffi_get_fn)(void);

#if defined(__GNUC__)
__attribute__((visibility("default")))
#endif
const nvb_ffi *nvb_ffi_get(void);

#ifdef __cplusplus
}
#endif

#endif
