/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "tlscallbacks.h"

#include <openssl/ssl.h>

void netvfs_tls_capture_release(struct NetVfsTlsCapture *capture)
{
    X509_free(capture->leaf);
    capture->leaf = NULL;
    sk_X509_pop_free(capture->untrusted, X509_free);
    capture->untrusted = NULL;
}

/* Replaces OpenSSL's chain verification: keeps the chain for the caller and
 * refuses it. */
static int capture_and_reject(X509_STORE_CTX *store, void *user_data)
{
    struct NetVfsTlsCapture *capture = (struct NetVfsTlsCapture *)user_data;
    X509 *leaf = X509_STORE_CTX_get0_cert(store);
    STACK_OF(X509) *untrusted = X509_STORE_CTX_get0_untrusted(store);

    netvfs_tls_capture_release(capture);
    if (leaf && X509_up_ref(leaf) == 1)
        capture->leaf = leaf;
    if (untrusted)
        capture->untrusted = X509_chain_up_ref(untrusted);
    X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;   /* never complete this handshake (C-7) */
}

static CURLcode capture_ssl_context(CURL *curl, void *ssl_ctx, void *user_data)
{
    SSL_CTX *ctx = (SSL_CTX *)ssl_ctx;

    (void)curl;
    /* VERIFY_PEER makes OpenSSL abort the handshake when the verify function
     * fails; with VERIFY_NONE its result would be ignored. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cert_verify_callback(ctx, capture_and_reject, user_data);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    return CURLE_OK;
}

const curl_ssl_ctx_callback netvfs_tls_capture_ssl_context = capture_ssl_context;

struct ErrorCollector {
    int *codes;
    int capacity;
    int count;
};

static int collect_error(int ok, X509_STORE_CTX *ctx)
{
    struct ErrorCollector *collector = (struct ErrorCollector *)X509_STORE_CTX_get_ex_data(ctx, 0);
    int code;
    int i;

    if (ok || !collector)
        return 1;
    code = X509_STORE_CTX_get_error(ctx);
    for (i = 0; i < collector->count; ++i) {
        if (collector->codes[i] == code)
            return 1;
    }
    if (collector->count < collector->capacity)
        collector->codes[collector->count++] = code;
    return 1;   /* go on: every error of the chain is wanted */
}

int netvfs_tls_verify_collecting(X509_STORE_CTX *ctx, int *codes, int capacity, int *verified)
{
    struct ErrorCollector collector;

    collector.codes = codes;
    collector.capacity = capacity;
    collector.count = 0;
    X509_STORE_CTX_set_ex_data(ctx, 0, &collector);
    X509_STORE_CTX_set_verify_cb(ctx, collect_error);
    *verified = X509_verify_cert(ctx) == 1;
    X509_STORE_CTX_set_ex_data(ctx, 0, NULL);
    return collector.count;
}
