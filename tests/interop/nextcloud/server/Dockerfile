# SPDX-License-Identifier: LGPL-2.1-or-later
FROM mirror.gcr.io/library/nextcloud:31.0.14-apache
RUN a2enmod ssl >/dev/null \
    && a2ensite default-ssl >/dev/null \
    && sed -i -e 's#/etc/ssl/certs/ssl-cert-snakeoil.pem#/etc/netvfs/self.crt#' \
        -e 's#/etc/ssl/private/ssl-cert-snakeoil.key#/etc/netvfs/self.key#' \
        /etc/apache2/sites-available/default-ssl.conf
EXPOSE 443
