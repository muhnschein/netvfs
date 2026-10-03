/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Process-wide libcurl initialisation for the libcurl based backends
 * (SPEC-v2 W-1, F-1).
 * libcurl keeps its own copies of user names, passwords, bearer tokens and
 * request headers and frees them without overwriting. Its memory callbacks
 * are therefore routed through allocators that wipe every block before it
 * is released (SEC-5, XSEC-6). curl_global_init_mem() only takes effect for
 * the first initialisation in the process. */
#include "curlglobal.h"

#include <curl/curl.h>
#include <malloc.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

static void wipingFree(void *block)
{
    if (block) {
        OPENSSL_cleanse(block, malloc_usable_size(block));
        free(block);
    }
}

static void *wipingRealloc(void *block, size_t size)
{
    void *moved;
    size_t keep;
    if (!block)
        return malloc(size);
    if (size == 0) {
        wipingFree(block);
        return NULL;
    }
    moved = malloc(size);
    if (!moved)
        return NULL;
    keep = malloc_usable_size(block);
    memcpy(moved, block, keep < size ? keep : size);
    wipingFree(block);
    return moved;
}

static char *wipingStrdup(const char *text)
{
    const size_t length = strlen(text) + 1;
    char *copy = malloc(length);
    if (copy)
        memcpy(copy, text, length);
    return copy;
}

int netvfs_curl_global_init(void)
{
    return curl_global_init_mem(CURL_GLOBAL_DEFAULT, malloc, wipingFree, wipingRealloc, wipingStrdup, calloc)
        == CURLE_OK;
}
