/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "davcallbacks.h"

static size_t on_header(char *data, size_t size, size_t count, void *user_data)
{
    return netvfs_dav_on_header((struct NetVfsDavTransfer *)user_data, data, size * count);
}

static size_t on_write(char *data, size_t size, size_t count, void *user_data)
{
    return netvfs_dav_on_body((struct NetVfsDavTransfer *)user_data, data, size * count);
}

static size_t on_read(char *buffer, size_t size, size_t count, void *user_data)
{
    return netvfs_dav_on_read((struct NetVfsDavTransfer *)user_data, buffer, size * count);
}

static int on_seek(void *user_data, curl_off_t offset, int origin)
{
    return netvfs_dav_on_seek((struct NetVfsDavTransfer *)user_data, offset, origin);
}

static int on_progress(void *user_data, curl_off_t dl_total, curl_off_t dl_now, curl_off_t ul_total,
                       curl_off_t ul_now)
{
    (void)dl_total;
    (void)dl_now;
    (void)ul_total;
    (void)ul_now;
    return netvfs_dav_on_progress((const struct NetVfsDavTransfer *)user_data);
}

const curl_write_callback netvfs_dav_header_callback = on_header;
const curl_write_callback netvfs_dav_write_callback = on_write;
const curl_read_callback netvfs_dav_read_callback = on_read;
const curl_seek_callback netvfs_dav_seek_callback = on_seek;
const curl_xferinfo_callback netvfs_dav_progress_callback = on_progress;
