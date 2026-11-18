# SPDX-License-Identifier: LGPL-2.1-or-later
# proftpd with mod_tls for the FTPS interop suite. Certificate, password and passive ports come at run time.
FROM mirror.gcr.io/library/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends proftpd-core proftpd-mod-crypto openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /srv/ftp && chown proftpd:nogroup /srv/ftp
COPY proftpd.conf /etc/proftpd/netvfs.conf
COPY start.sh /usr/local/bin/netvfs-start
RUN chmod 0755 /usr/local/bin/netvfs-start
EXPOSE 2121
CMD ["/usr/local/bin/netvfs-start"]
