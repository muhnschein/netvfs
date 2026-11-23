# SPDX-License-Identifier: LGPL-2.1-or-later
FROM mirror.gcr.io/library/httpd:2.4
COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY start.sh /usr/local/bin/netvfs-start
RUN chmod 0755 /usr/local/bin/netvfs-start \
    && mkdir -p /srv/dav /srv/small /usr/local/apache2/var \
    && chown -R daemon:daemon /srv/dav /srv/small /usr/local/apache2/var
EXPOSE 443 8443 9443
CMD ["/usr/local/bin/netvfs-start"]
