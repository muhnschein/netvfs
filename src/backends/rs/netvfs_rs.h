/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_RS_H
#define NETVFS_RS_H

/*
 * C ABI between the C++ backend plugins (the shim, src/backends/rs) and the
 * Rust backends in libnetvfs-rs.so (rust/netvfs-backend). Design:
 * phase3-design.md §1, §2.
 *
 * Loading:
 *   void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
 *   nvr_get_fn get = (nvr_get_fn)dlsym(lib, NVR_ENTRY);
 *   const nvr_table *t = get();
 * Shim and library ship in one package from one commit: no version
 * handshake. The data types are those of netvfs_bridge_ffi.h (its table is
 * not used here), with the same ownership rules O1-O5, the direction
 * reversed: Rust allocates what it returns.
 *
 * Ownership:
 *  R1 Everything passed in is borrowed for the call only; Rust copies.
 *  R2 Pointers handed to a callback are borrowed for that callback only.
 *  R3 Objects returned through an out-pointer (nvb_error, nvb_entry,
 *     nvb_blob, nvb_identity, nvb_capabilities, nvr_key) are ONE malloc'd
 *     block each, including all the bytes they point to. Release with
 *     t->free(p), which wipes the block first; t->free(NULL) is a no-op.
 *  R4 nvr_conn is released by conn_free, nvr_read by read_close, nvr_write
 *     by commit or abort (each always frees). conn_free also frees the
 *     handles of the connection that are still open; C++ deletes its handles
 *     before their backend, so none are left in practice.
 *  R5 Secrets (nvr_credentials.secret, answers given to reply_set) are
 *     copied into wiped-on-drop buffers. The caller wipes its own.
 * Errors: a function returning nvb_error * returns NULL on success.
 *
 * Threads:
 *  S1 conn_* functions and the functions of a connection's handles: one call
 *     at a time per connection, from any thread (C-8: a Backend is used by
 *     one thread at a time, not always the one that made it). A call that
 *     overlaps another of the same connection, or is made from inside one
 *     of its callbacks, returns Internal. The exception is cancel: any
 *     thread, also while a call runs. It must never overlap or follow
 *     conn_free; the caller serialises the two.
 *  S2 free, reply_set and the key_* functions: any thread.
 *  S3 Each call blocks its thread until it is done (NetVfs::Backend is
 *     blocking, C-8). Rust runs its own runtime threads (nvr-io-*) for
 *     protocol work, but every callback passed to a call (list sink,
 *     prompter, nvb_io, nvb_progress) runs on the calling thread before the
 *     call returns. Inside a callback the caller may only use cancel (any
 *     connection), reply_set (prompter only) and free.
 *  S4 cancel makes the running call and every later one of that connection
 *     (and its handles) return Canceled, within 2 s (C-9), until
 *     reset_cancel.
 *  S5 Neither Rust panics nor C++ exceptions cross the boundary: Rust
 *     catches a panic and reports Internal; callbacks catch everything.
 */

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

/* AuthPrompter (XC-15) as a hook; same contract as nvb_establish_hooks.prompt:
   fills `reply` with reply_set() and returns 1, or returns 0 to decline. */
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

/* upload and download: the shim's nvb_io reads and writes its QIODevice in
   order; Rust calls read and write in order as well, with `pos` the number
   of bytes moved so far. `size` is the source's size from its position
   (upload; 0 when sequential) and 0 for download. */

typedef struct nvr_table {
    void (*free)(void *p);                                   /* also wipes nvr_key */
    void (*reply_set)(nvb_reply *r, const nvb_bytes *answers, size_t n);

    /* Lifecycle (one call at a time per connection; cancel any thread). */
    nvb_error *(*conn_new)(nvb_bytes provider, nvr_conn **out);   /* "sftp", "smb", "mem" (testing) */
    void (*conn_free)(nvr_conn *c);                                /* disconnects, frees handles */
    void (*cancel)(nvr_conn *c);
    void (*reset_cancel)(nvr_conn *c);
    nvb_error *(*connect)(nvr_conn *c, const nvb_params *p, nvb_identity **seen);  /* NULL seen: none */
    nvb_error *(*authenticate)(nvr_conn *c, const nvr_credentials *cr, const nvr_prompter *pr);
    nvb_error *(*capabilities)(nvr_conn *c, nvb_capabilities **out);
    void (*disconnect)(nvr_conn *c);
    nvb_error *(*keep_alive)(nvr_conn *c);

    /* Metadata and namespace. Paths: Names::encode bytes of normalised paths. */
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

    /* Handles (XC-13). */
    nvb_error *(*open_read)(nvr_conn *c, nvb_bytes path, nvr_read **out, int64_t *size);
    nvb_error *(*read)(nvr_read *h, int64_t offset, uint8_t *buf, size_t cap, size_t *len);
    void (*read_ahead)(nvr_read *h, int64_t offset, int64_t bytes);
    nvb_error *(*read_close)(nvr_read *h);                         /* always frees */
    nvb_error *(*open_write)(nvr_conn *c, nvb_bytes path, const nvr_write_opts *o, nvr_write **out);
    nvb_error *(*write)(nvr_write *h, const uint8_t *data, size_t len);
    int64_t (*position)(const nvr_write *h);
    nvb_error *(*commit)(nvr_write *h);                            /* always frees */
    void (*abort)(nvr_write *h);                                   /* always frees */

    /* Streaming (XC-14): the shim wraps QIODevice/Progress into nvb_io/nvb_progress. */
    nvb_error *(*upload)(nvr_conn *c, nvb_bytes path, const nvb_upload_opts *o,
                         const nvb_io *io, const nvb_progress *pr);
    nvb_error *(*download)(nvr_conn *c, nvb_bytes path, int64_t offset, int64_t length,
                           const nvb_io *io, const nvb_progress *pr);

    /* Extensions. */
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
