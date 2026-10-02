# SPDX-License-Identifier: LGPL-2.1-or-later
# Apache httpd + mod_dav for the WebDAV interop suite (SPEC-v2 XT-2).
# Certificates and the password are copied in / passed at run time.
FROM mirror.gcr.io/library/httpd:2.4
COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY start.sh /usr/local/bin/netvfs-start
RUN chmod 0755 /usr/local/bin/netvfs-start \
    && mkdir -p /srv/dav /srv/digest /srv/small /usr/local/apache2/var /etc/netvfs \
    && chown -R daemon:daemon /srv/dav /srv/digest /srv/small /usr/local/apache2/var
EXPOSE 80 443 8443
CMD ["/usr/local/bin/netvfs-start"]
