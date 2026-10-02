/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_TLSCALLBACKS_H
#define NETVFS_TLSCALLBACKS_H

/*
 * OpenSSL and libcurl hooks of the TLS identity code (XC-16, W-3, F-1). The
 * signatures are dictated by OpenSSL and libcurl (untyped user data, mutable
 * parameters), so the hooks live in C (tlscallbacks.c); C++ only sees the
 * typed state below.
 */
#include <curl/curl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#ifdef __cplusplus
extern "C" {
#endif

/* What the capture hook takes from a handshake. Both members are owned by
 * the structure; netvfs_tls_capture_release() frees them. */
struct NetVfsTlsCapture {
    X509 *leaf;                 /* the server certificate */
    STACK_OF(X509) *untrusted;  /* the other certificates the server presented */
};

void netvfs_tls_capture_release(struct NetVfsTlsCapture *capture);

/* CURLOPT_SSL_CTX_FUNCTION for the identity probe (C-7), with a
 * struct NetVfsTlsCapture as CURLOPT_SSL_CTX_DATA. libcurl's own verification
 * stays as configured; the hook replaces OpenSSL's chain building with a
 * function that records the chain and always rejects it, so the handshake
 * never completes and nothing is sent on the connection. */
extern const curl_ssl_ctx_callback netvfs_tls_capture_ssl_context;

/* Verifies the chain prepared in `ctx` (X509_STORE_CTX_init) and records the
 * distinct error codes of every certificate (X509_V_ERR_*) instead of
 * stopping at the first. Returns how many of `capacity` entries of `codes`
 * were filled; `*verified` is 1 when the chain verified. */
int netvfs_tls_verify_collecting(X509_STORE_CTX *ctx, int *codes, int capacity, int *verified);

#ifdef __cplusplus
}
#endif

#endif
