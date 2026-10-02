/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "ftpcallbacks.h"

static size_t on_write(char *data, size_t size, size_t count, void *user_data)
{
    return netvfs_ftp_on_write((struct NetVfsFtpHooks *)user_data, data, size * count);
}

static size_t on_read(char *buffer, size_t size, size_t count, void *user_data)
{
    return netvfs_ftp_on_read((struct NetVfsFtpHooks *)user_data, buffer, size * count);
}

static size_t on_header(char *data, size_t size, size_t count, void *user_data)
{
    return netvfs_ftp_on_header((struct NetVfsFtpHooks *)user_data, data, size * count);
}

static int on_progress(void *user_data, curl_off_t download_total, curl_off_t downloaded, curl_off_t upload_total,
                       curl_off_t uploaded)
{
    return netvfs_ftp_on_progress((struct NetVfsFtpHooks *)user_data, download_total, downloaded, upload_total,
                                  uploaded);
}

static size_t on_probe_header(char *data, size_t size, size_t count, void *user_data)
{
    return netvfs_ftp_probe_header((struct NetVfsFtpProbeState *)user_data, data, size * count);
}

static int on_probe_progress(void *user_data, curl_off_t download_total, curl_off_t downloaded,
                             curl_off_t upload_total, curl_off_t uploaded)
{
    (void)download_total;
    (void)downloaded;
    (void)upload_total;
    (void)uploaded;
    return netvfs_ftp_probe_progress((const struct NetVfsFtpProbeState *)user_data);
}

const curl_write_callback netvfs_ftp_write_callback = on_write;
const curl_read_callback netvfs_ftp_read_callback = on_read;
const curl_write_callback netvfs_ftp_header_callback = on_header;
const curl_xferinfo_callback netvfs_ftp_progress_callback = on_progress;
const curl_write_callback netvfs_ftp_probe_header_callback = on_probe_header;
const curl_xferinfo_callback netvfs_ftp_probe_progress_callback = on_probe_progress;
