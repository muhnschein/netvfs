/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NVB_FAKE_H
#define NVB_FAKE_H

/*
 * Test-only control table of the fake backend (provider "fake",
 * tests/fakeplugin), exported by libnetvfs-bridge-ffi-fake.so; never
 * installed. Design: phase2-design.md §4.1. It links libnetvfstest.so and so
 * drives the same FakeServer singleton as the plugin that conn_new loads
 * through NETVFS_BACKEND_PATH.
 *
 * Loading: as libnetvfs-bridge-ffi.so (netvfs_bridge_ffi.h), entry
 * NVB_FAKE_ENTRY. Paths are protocol bytes (Names::decode); a leading '/'
 * does not matter. Any thread; every call takes the server's lock.
 * Ownership: as O1 and O3 of netvfs_bridge_ffi.h.
 */

#include "netvfs_bridge_ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NVB_FAKE_VERSION 1u
#define NVB_FAKE_ENTRY "nvb_fake_get"

typedef struct nvb_fake_v1 {
    uint32_t version;          /* NVB_FAKE_VERSION */
    uint32_t struct_size;      /* sizeof(nvb_fake_v1) in the library */

    void (*reset)(void);       /* FakeServer::reset(): empty, user "user", secret "secret" */
    void (*add_file)(nvb_bytes path, nvb_bytes data);        /* with missing parents */
    void (*add_dir)(nvb_bytes path, int32_t mode);           /* mode -1: 0755 */
    void (*add_symlink)(nvb_bytes path, nvb_bytes target);   /* target verbatim */
    int32_t (*exists)(nvb_bytes path);
    nvb_blob *(*file_data)(nvb_bytes path);  /* NULL when there is no such file */
    int32_t (*node_mode)(nvb_bytes path);    /* -1 when there is no such node */
    void (*set_identity_pin)(nvb_bytes pin); /* ServerIdentity::fromPin; "" none */
    void (*set_otp)(nvb_bytes otp);          /* non-empty: keyboard-interactive code */
    void (*set_credentials)(nvb_bytes user, nvb_bytes secret);
    void (*set_chunk_delay_ms)(int32_t ms);  /* per 64 KiB chunk and listing batch */
    /* The next call of `op` ("connect", "list", "upload", ...) fails once
       with the XC-21 error `error_name`. */
    void (*fail_op)(nvb_bytes op, nvb_bytes error_name);
    /* Log lines starting with `prefix`: "connect", "authenticate",
       "answers:<n>", "disconnect", "<op>:<path>" ... */
    int32_t (*log_count)(nvb_bytes prefix);
    int32_t (*live_backends)(void);          /* FakeBackend instances alive */
    void (*free)(void *p);
} nvb_fake_v1;

typedef const nvb_fake_v1 *(*nvb_fake_get_fn)(uint32_t version);

#if defined(__GNUC__)
__attribute__((visibility("default")))
#endif
const nvb_fake_v1 *nvb_fake_get(uint32_t version);

#ifdef __cplusplus
}
#endif

#endif /* NVB_FAKE_H */
