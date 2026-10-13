/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_BRIDGE_FFI_H
#define NETVFS_BRIDGE_FFI_H

/*
 * C ABI between the Rust netvfs-bridge and the C++ backends
 * (libnetvfs-bridge-ffi.so). SPEC-v2 §8a; design: phase2-design.md.
 *
 * Loading:
 *   void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
 *   nvb_ffi_get_fn get = (nvb_ffi_get_fn)dlsym(lib, NVB_FFI_ENTRY);
 *   const nvb_ffi_v1 *t = get(NVB_FFI_VERSION);   NULL: version not offered
 * t->struct_size may exceed sizeof(nvb_ffi_v1): fields are only ever appended.
 *
 * Ownership:
 *  O1 nvb_bytes and structs passed in are borrowed for the call only; C++ copies.
 *  O2 Pointers handed to a callback are borrowed for that callback only.
 *  O3 Objects returned through an out-pointer (nvb_error, nvb_entry, nvb_blob,
 *     nvb_capabilities, nvb_url) are ONE malloc'd block each, including all the
 *     bytes they point to. Release with t->free(p); t->free(NULL) is a no-op.
 *  O4 nvb_conn, nvb_handle, nvb_discovery are released only by their own
 *     conn_free / handle_close / discovery_free.
 *  O5 Secrets (nvb_secret.secret, answers given to reply_set) are copied into
 *     NetVfs::Credentials / QVector<QByteArray>. C++ wipes its copies after use
 *     (SEC-5, XSEC-6). The caller wipes its own.
 * Errors: a function returning nvb_error * returns NULL on success.
 *
 * Threads:
 *  T1 init, run and shutdown: the process's main thread. init comes first, before
 *     any other call, so that Qt's main thread is this thread.
 *  T2 quit, post, free, provider_available, url_parse, url_format: any thread.
 *  T3 discovery_*: the Qt thread only (inside a post() callback). Its hook runs
 *     there.
 *  T4 conn_* and handle_*: only the owner thread, which is the thread that called
 *     conn_new. The exception is conn_cancel: any thread, also while an owner-thread
 *     call is running. It must never overlap or follow conn_free; the caller
 *     serialises the two.
 *  T5 copy_across: both conns are owned by the calling thread.
 *  T6 Callbacks passed to a conn_* or handle_* call run synchronously on the
 *     calling thread before that call returns. Inside them the caller may only
 *     use conn_cancel (any conn), reply_set (prompt hook only) and free.
 *  T7 Neither C++ exceptions nor Rust panics cross the boundary. C++ catches
 *     everything and reports Internal.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NVB_FFI_VERSION 1u
#define NVB_FFI_ENTRY "nvb_ffi_get"

/* ------------------------------------------------------------- basics */

typedef struct nvb_bytes {
    const uint8_t *ptr;      /* may be NULL when len == 0 */
    size_t len;
} nvb_bytes;

typedef struct nvb_conn nvb_conn;             /* one NetVfs::Backend */
typedef struct nvb_handle nvb_handle;         /* one NetVfs::ReadHandle */
typedef struct nvb_discovery nvb_discovery;   /* one NetVfs::Discovery */
typedef struct nvb_reply nvb_reply;           /* answer slot of a prompt */

/* A failure: NetVfs::Result with error != None (XC-21, XC-24). */
typedef struct nvb_error {
    nvb_bytes name;            /* XC-21 errorName(), e.g. "NotFound"; never empty */
    nvb_bytes message;         /* UTF-8, may be empty */
    nvb_bytes detail;          /* UTF-8, may be empty */
    int64_t retry_after_ms;    /* -1: none */
} nvb_error;

/* A byte string C++ produced (link target, digest, formatted URL). */
typedef struct nvb_blob {
    nvb_bytes data;
} nvb_blob;

/* A typed value of ConnectionParams::options or ServerIdentity::details. */
enum {
    NVB_VALUE_STRING = 1,      /* bytes: UTF-8           -> QString            */
    NVB_VALUE_BOOL = 2,        /* number: 0 or 1         -> bool               */
    NVB_VALUE_INT = 3,         /* number                 -> qlonglong          */
    NVB_VALUE_BYTES = 4,       /* bytes                  -> QByteArray         */
    NVB_VALUE_STRING_LIST = 5  /* items: UTF-8 each      -> QStringList        */
};

typedef struct nvb_value {
    uint32_t kind;             /* an NVB_VALUE_* value */
    int64_t number;
    nvb_bytes bytes;
    const nvb_bytes *items;
    size_t n_items;
} nvb_value;

typedef struct nvb_kv {
    nvb_bytes key;             /* UTF-8 */
    nvb_value value;
} nvb_kv;

/* NetVfs::ConnectionParams. Strings UTF-8. */
typedef struct nvb_params {
    nvb_bytes provider;
    nvb_bytes host;
    int32_t port;              /* 0: protocol default */
    nvb_bytes username;
    const nvb_kv *options;     /* keys unique */
    size_t n_options;
    int32_t connect_timeout_ms;
    int32_t request_timeout_ms;
} nvb_params;

/* Url::parse result. */
typedef struct nvb_url {
    nvb_params params;
    nvb_bytes path;            /* Names::encode of the normalised location path */
} nvb_url;

/* ------------------------------------------------------------ entries */

/* NetVfs::Entry (XC-2) in wire form (XB-9). */
typedef struct nvb_entry {
    nvb_bytes name;            /* Names::encode(name) */
    uint8_t type;              /* NetVfs::EntryType */
    uint8_t target_type;
    uint16_t flags;            /* NetVfs::EntryFlags */
    int32_t mode;              /* -1 unknown */
    int64_t size;              /* -1 unknown */
    int64_t mtime_ms;          /* -1 unknown (invalid QDateTime) */
    int64_t ctime_ms;
    int64_t atime_ms;
    int64_t uid;
    int64_t gid;
    nvb_bytes owner;           /* UTF-8 (QString::toUtf8); may hold NUL */
    nvb_bytes group;
    nvb_bytes etag;
    nvb_bytes content_type;
} nvb_entry;

typedef struct nvb_capabilities {
    const nvb_bytes *flags;    /* Capabilities::names(), sorted */
    size_t n_flags;
    const nvb_bytes *checksum_algorithms;
    size_t n_checksum_algorithms;
    int64_t max_name_bytes;    /* -1 unknown */
} nvb_capabilities;

typedef struct nvb_space {
    int64_t free_bytes;
    int64_t total_bytes;
    int64_t used_bytes;        /* each -1 unknown */
} nvb_space;

typedef struct nvb_attributes {
    int32_t mode;              /* -1 unchanged */
    uint8_t has_mtime;
    uint8_t has_atime;
    int64_t mtime_ms;
    int64_t atime_ms;
} nvb_attributes;

/* ------------------------------------------------------------ establish */

enum { NVB_IDENTITY_NONE = 0, NVB_IDENTITY_SSH = 1, NVB_IDENTITY_TLS = 2 };

/* The ServerIdentity seen during connect (XC-16). */
typedef struct nvb_identity {
    uint32_t kind;             /* an NVB_IDENTITY_* value */
    nvb_bytes algorithm;
    nvb_bytes public_key;
    nvb_bytes fingerprint;     /* filled by C++ when the backend left it empty
                                  ("SHA256:" + unpadded base64), as connector.cpp did */
    nvb_bytes pin;             /* ServerIdentity::toPin(); empty without identity */
    uint8_t system_trusted;
    int32_t problems;          /* ServerIdentity bits */
    const nvb_kv *details;     /* wire-able values only; dates as ISO-8601 UTC */
    size_t n_details;
} nvb_identity;

/* Where the credentials come from. */
enum {
    NVB_SECRET_NONE = 0,       /* Credentials(user, "") */
    NVB_SECRET_BYTES = 1,      /* ad hoc: Credentials(user, secret) (XB-16) */
    NVB_SECRET_SIGNON = 2      /* account: SignonSecretSource(credentials_id),
                                  run on the Qt thread, 60 s timeout, cancelable;
                                  an empty fetched user name becomes `user` (A-6, XA-7) */
};

typedef struct nvb_secret {
    uint32_t source;           /* an NVB_SECRET_* value */
    nvb_bytes user;
    nvb_bytes secret;          /* NVB_SECRET_BYTES only */
    uint32_t credentials_id;   /* NVB_SECRET_SIGNON only */
    uint8_t secret_optional;   /* NVB_SECRET_SIGNON only (XA-7) */
} nvb_secret;

/* Verdict of the identity hook. */
enum {
    NVB_ID_USE_CHECK = 0,      /* the checkServerIdentity() result stands */
    NVB_ID_ACCEPT_UNKNOWN = 1, /* proceed; honoured only when the check said
                                  ServerIdentityUnknown, never for Changed */
    NVB_ID_CANCEL = 2          /* fail with Canceled */
};

typedef struct nvb_prompt {
    nvb_bytes text;            /* UTF-8 */
    uint8_t echo;
} nvb_prompt;

typedef struct nvb_establish_hooks {
    void *ctx;
    /* After connect. `check` is checkServerIdentity(seen, pin), or NULL when it
       passed. NULL hook: NVB_ID_USE_CHECK. */
    uint32_t (*identity)(void *ctx, const nvb_identity *seen, const nvb_error *check);
    /* Keyboard-interactive (XC-15). Fills `reply` with reply_set() and returns 1, or
       returns 0 to decline. It may block (the user answers) and should give up when
       the caller's own cancel flag is set. NULL hook: no prompter (nullptr). */
    int (*prompt)(void *ctx, nvb_bytes name, nvb_bytes instruction,
                  const nvb_prompt *prompts, size_t n_prompts, nvb_reply *reply);
} nvb_establish_hooks;

/* How far conn_establish got. */
enum {
    NVB_PHASE_CONNECT = 1,     /* Backend::connect */
    NVB_PHASE_IDENTITY = 2,    /* identity verdict (attention-relevant) */
    NVB_PHASE_CREDENTIALS = 3, /* secret lookup (no attention) */
    NVB_PHASE_AUTHENTICATE = 4,/* Backend::authenticate (attention-relevant) */
    NVB_PHASE_DONE = 5
};

/* ------------------------------------------------------------ streaming */

/* One backend batch of a listing (XC-6). Return 1 to go on, 0 to stop (Canceled). */
typedef int (*nvb_list_sink_fn)(void *ctx, const nvb_entry *entries, size_t n);

typedef struct nvb_walk_opts {
    int32_t max_depth;         /* -1 unlimited, 0: root's children only */
    uint8_t follow_symlinks;   /* Ops::SymlinkPolicy::Follow */
    uint8_t post_order;        /* Ops::WalkOptions::postOrder; leave() is not reported */
    uint8_t stop_on_list_error;/* 0: unreadable sub-folders are skipped (bridge default) */
} nvb_walk_opts;

/* One visited entry; `path` = Names::encode(full path). Return 1 to go on, 0 to stop. */
typedef int (*nvb_walk_visit_fn)(void *ctx, nvb_bytes path, const nvb_entry *entry);

typedef struct nvb_progress {
    void *ctx;
    void (*update)(void *ctx, int64_t done, int64_t total);   /* total -1: unknown */
    int (*canceled)(void *ctx);                               /* 1: stop (Canceled) */
} nvb_progress;

/* The local side of Upload/Download: C++ wraps it into a QIODevice (Unbuffered).
   Rust does the pread/pwrite (regular file) or read/write (FIFO) on the checked fd. */
typedef struct nvb_io {
    void *ctx;
    uint8_t sequential;        /* FIFO */
    int64_t size;              /* QIODevice::size(): bytes in range; 0 for FIFOs */
    /* Device position `pos` (ignored when sequential). Returns bytes read, 0 at
       end, -1 on error or cancel. */
    int64_t (*read)(void *ctx, int64_t pos, uint8_t *buf, size_t cap);
    /* Returns bytes written (may be short), -1 on error or cancel. */
    int64_t (*write)(void *ctx, int64_t pos, const uint8_t *buf, size_t len);
} nvb_io;

enum {
    NVB_DISPOSITION_CREATE_NEW = 0,
    NVB_DISPOSITION_TRUNCATE = 1,
    NVB_DISPOSITION_RESUME = 2
};

typedef struct nvb_upload_opts {
    uint32_t disposition;      /* NVB_DISPOSITION_* (WriteOptions) */
    int32_t create_mode;       /* -1 backend default (XC-23) */
    int64_t resume_offset;
    int64_t expected_size;     /* -1 unknown */
    uint8_t has_mtime;
    int64_t mtime_ms;
} nvb_upload_opts;

/* ------------------------------------------------------------ discovery */

typedef struct nvb_nearby {
    nvb_bytes name;            /* DiscoveredService::instanceName, UTF-8 */
    nvb_bytes provider;
    nvb_bytes host;
    uint16_t port;
    nvb_bytes path;            /* Names::encode(path) */
} nvb_nearby;

typedef struct nvb_discovery_hooks {
    void *ctx;
    /* Qt thread; the full current Discovery::services() after found/updated/lost. */
    void (*changed)(void *ctx, const nvb_nearby *items, size_t n);
} nvb_discovery_hooks;

/* ------------------------------------------------------------ the table */

typedef struct nvb_ffi_v1 {
    uint32_t version;          /* NVB_FFI_VERSION */
    uint32_t struct_size;      /* sizeof(nvb_ffi_v1) in the library */

    /* Process and Qt event loop (T1, T2). */
    int32_t (*init)(nvb_bytes app_name);        /* QCoreApplication; 0 ok, -1 twice */
    int32_t (*run)(void);                       /* exec(); returns quit()'s code */
    void (*quit)(int32_t exit_code);            /* queued exit(); any thread */
    int32_t (*post)(void (*fn)(void *ctx), void *ctx);  /* 1 queued, 0 not (no app,
                                                    or quitting): fn never runs */
    void (*shutdown)(void);                     /* after run(): deletes the app */
    void (*free)(void *p);

    /* Helpers (T2). */
    int32_t (*provider_available)(nvb_bytes provider);  /* BackendLoader::isAvailable */
    nvb_error *(*url_parse)(nvb_bytes url, nvb_url **out);          /* Url::parse */
    nvb_error *(*url_format)(const nvb_params *params, nvb_bytes path, nvb_blob **out);

    /* Connection lifecycle (T4). */
    nvb_error *(*conn_new)(nvb_bytes provider, nvb_conn **out);  /* BackendLoader::create */
    void (*conn_free)(nvb_conn *conn);          /* closes open handles, disconnect(),
                                                   deletes; conn must be idle */
    void (*conn_cancel)(nvb_conn *conn);        /* Backend::cancel (C-9); any thread;
                                                   also ends a signond wait */
    void (*conn_reset_cancel)(nvb_conn *conn);  /* Backend::resetCancel */
    /* connect; checkServerIdentity(seen, pin) + hooks->identity; secret; authenticate.
       Disconnects on any failure after connect. *phase: how far it got. */
    nvb_error *(*conn_establish)(nvb_conn *conn, const nvb_params *params, nvb_bytes pin,
                                 const nvb_secret *secret, const nvb_establish_hooks *hooks,
                                 uint32_t *phase);
    void (*reply_set)(nvb_reply *reply, const nvb_bytes *answers, size_t n_answers);
    nvb_error *(*conn_capabilities)(nvb_conn *conn, nvb_capabilities **out);

    /* Metadata and namespace (T4). Paths: Rust-normalised protocol bytes. */
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
                            int32_t recursive, int32_t replace);         /* ServerCopy */

    /* Read handles (XC-13), owned by their conn's thread (T4). */
    nvb_error *(*conn_open_read)(nvb_conn *conn, nvb_bytes path, nvb_handle **out,
                                 int64_t *size);
    /* Reads at most `cap` bytes at `offset` into `buf` (Rust's buffer); *len < cap
       only at EOF. */
    nvb_error *(*handle_read)(nvb_handle *h, int64_t offset, uint8_t *buf, size_t cap,
                              size_t *len);
    void (*handle_read_ahead)(nvb_handle *h, int64_t offset, int64_t bytes);
    nvb_error *(*handle_close)(nvb_handle *h);  /* ReadHandle::close + delete; always frees */

    /* Transfers and tree operations (T4, T5, T6). */
    nvb_error *(*conn_upload)(nvb_conn *conn, nvb_bytes path, const nvb_upload_opts *opts,
                              const nvb_io *io, const nvb_progress *progress);
    nvb_error *(*conn_download)(nvb_conn *conn, nvb_bytes path, int64_t offset,
                                int64_t length, const nvb_io *io,
                                const nvb_progress *progress);
    nvb_error *(*remove_tree)(nvb_conn *conn, nvb_bytes path, const nvb_progress *progress,
                              int64_t *files, int64_t *dirs);            /* Ops::removeTree */
    nvb_error *(*walk)(nvb_conn *conn, nvb_bytes root, const nvb_walk_opts *opts,
                       nvb_walk_visit_fn visit, void *ctx);              /* Ops::walk */
    nvb_error *(*copy_across)(nvb_conn *source, nvb_bytes source_path,
                              nvb_conn *destination, nvb_bytes destination_path,
                              int32_t recursive, int32_t replace,
                              const nvb_progress *progress);             /* Ops::copyAcross */

    /* Discovery (XD-5), Qt thread only (T3). */
    nvb_discovery *(*discovery_new)(const nvb_discovery_hooks *hooks);
    int32_t (*discovery_set_running)(nvb_discovery *d, int32_t on);  /* idempotent; 1 if
                                                                         a socket is open */
    void (*discovery_free)(nvb_discovery *d);   /* no hook call after it returns */
} nvb_ffi_v1;

typedef const nvb_ffi_v1 *(*nvb_ffi_get_fn)(uint32_t version);

#if defined(__GNUC__)
__attribute__((visibility("default")))
#endif
const nvb_ffi_v1 *nvb_ffi_get(uint32_t version);

#ifdef __cplusplus
}
#endif

#endif /* NETVFS_BRIDGE_FFI_H */
