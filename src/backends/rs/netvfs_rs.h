/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_RS_H
#define NETVFS_RS_H

/* C ABI between the C++ backend plugins (shim, src/backends/rs) and the Rust backends in
   libnetvfs-rs.so (rust/netvfs-backend).
   Load: dlopen(path, RTLD_NOW | RTLD_LOCAL), dlsym(NVR_ENTRY) as nvr_get_fn, call it for the table.
   Shim and library ship from one commit. Data types are those of netvfs_bridge_ffi.h, direction
   reversed: Rust allocates what it returns.
   Ownership:
   - Inputs are borrowed for the call only (Rust copies); callback pointers only for that callback.
   - Objects returned through an out-pointer (nvb_error, nvb_entry, nvb_blob, nvb_identity,
     nvb_capabilities, nvr_key) are one malloc'd block each. Release with t->free(p): wipes first,
     NULL is a no-op.
   - nvr_conn is freed by conn_free, nvr_read by read_close, nvr_write by commit or abort. conn_free
     also frees the connection's open handles; C++ deletes handles before their backend.
   - Secrets (nvr_credentials.secret, answers to reply_set) are copied into wiped-on-drop buffers;
     the caller wipes its own.
   - Functions returning nvb_error * return NULL on success.
   Threads:
   - conn_* and handle functions: one call at a time per connection, from any thread. Overlap, or a
     call from inside one of its callbacks, returns Internal. cancel: any thread, also during a
     call; must not overlap or follow conn_free.
   - free, reply_set, key_*: any thread.
   - Every call blocks its thread. Callbacks (list sink, prompter, nvb_io, nvb_progress) run on the
     calling thread before the call returns; inside one only cancel, reply_set (prompter only) and
     free are allowed.
   - cancel makes the running and every later call of that connection and its handles return
     Canceled within 2 s until reset_cancel.
   - No Rust panic or C++ exception crosses the boundary: a panic reports Internal; callbacks catch
     everything. */
#include "../../bridge/ffi/netvfs_bridge_ffi.h" /* nvb_* data types */

#ifdef __cplusplus
extern "C" {
#endif

#define NVR_ENTRY "nvr_get"

typedef struct nvr_conn nvr_conn;        /* one Rust backend connection */
typedef struct nvr_read nvr_read;        /* one ReadHandle */
typedef struct nvr_write nvr_write;      /* one WriteHandle */

typedef struct nvr_credentials {
    nvb_bytes user;
    nvb_bytes secret;          /* password, or "netvfs-key-v1:" + base64 key */
    nvb_bytes domain;          /* SMB only, may be empty */
} nvr_credentials;

/* AuthPrompter hook: fills `reply` with reply_set() and returns 1, or returns 0 to decline. */
typedef struct nvr_prompter {
    void *ctx;
    int (*prompt)(void *ctx, nvb_bytes name, nvb_bytes instruction,
                  const nvb_prompt *prompts, size_t n, nvb_reply *reply);
} nvr_prompter;

typedef struct nvr_write_opts {      /* WriteOptions */
    uint32_t disposition;            /* one of the NVB_DISPOSITION_ values */
    int32_t create_mode;             /* -1 backend default */
    int64_t resume_offset;
    int64_t expected_size;           /* -1 unknown */
    uint8_t has_mtime;
    int64_t mtime_ms;
} nvr_write_opts;

typedef struct nvr_key {             /* SshKeyMaterial, one block; private part wiped by free */
    nvb_bytes private_key;           /* OpenSSH format, unencrypted */
    nvb_bytes algorithm;
    nvb_bytes public_line;
    nvb_bytes fingerprint;
} nvr_key;

/* upload/download: nvb_io reads/writes the QIODevice in order; `pos` is bytes moved so far. `size`
   is the source's size from its position (upload; 0 when sequential), 0 for download. */
typedef struct nvr_table {
    void (*free)(void *p);                                   /* also wipes nvr_key */
    void (*reply_set)(nvb_reply *r, const nvb_bytes *answers, size_t n);

    nvb_error *(*conn_new)(nvb_bytes provider, nvr_conn **out);   /* "sftp", "smb", "mem" (testing) */
    void (*conn_free)(nvr_conn *c);                                /* disconnects, frees handles */
    void (*cancel)(nvr_conn *c);
    void (*reset_cancel)(nvr_conn *c);
    nvb_error *(*connect)(nvr_conn *c, const nvb_params *p, nvb_identity **seen);  /* NULL seen: none */
    nvb_error *(*authenticate)(nvr_conn *c, const nvr_credentials *cr, const nvr_prompter *pr);
    nvb_error *(*capabilities)(nvr_conn *c, nvb_capabilities **out);
    void (*disconnect)(nvr_conn *c);
    nvb_error *(*keep_alive)(nvr_conn *c);

    /* Paths: Names::encode bytes of normalised paths. */
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
    nvb_error *(*read_close)(nvr_read *h);                         /* always frees */
    nvb_error *(*open_write)(nvr_conn *c, nvb_bytes path, const nvr_write_opts *o, nvr_write **out);
    nvb_error *(*write)(nvr_write *h, const uint8_t *data, size_t len);
    int64_t (*position)(const nvr_write *h);
    nvb_error *(*commit)(nvr_write *h);                            /* always frees */
    void (*abort)(nvr_write *h);                                   /* always frees */

    nvb_error *(*upload)(nvr_conn *c, nvb_bytes path, const nvb_upload_opts *o,
                         const nvb_io *io, const nvb_progress *pr);
    nvb_error *(*download)(nvr_conn *c, nvb_bytes path, int64_t offset, int64_t length,
                           const nvb_io *io, const nvb_progress *pr);

    nvb_error *(*key_generate)(nvr_key **out);                      /* Ed25519 */
    nvb_error *(*key_import)(nvb_bytes file, nvb_bytes passphrase, nvr_key **out);
    nvb_error *(*key_describe)(nvb_bytes private_key, nvr_key **out);
} nvr_table;

typedef const nvr_table *(*nvr_get_fn)(void);

const nvr_table *nvr_get(void);

#ifdef __cplusplus
}
#endif

#endif /* NETVFS_RS_H */
