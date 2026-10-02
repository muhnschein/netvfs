# SPDX-License-Identifier: LGPL-2.1-or-later
# Samba server image for the SMB interop suite (SPEC-smb section 7).
# BASE selects the Samba release: ubuntu:24.04 ships 4.19.5 (M-T1..M-T9),
# debian:testing a current release (M-T10).
ARG BASE=mirror.gcr.io/library/ubuntu:24.04
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends samba smbclient tcpdump python3 \
 && rm -rf /var/lib/apt/lists/* \
 && cp /etc/samba/smb.conf /etc/samba/smb.conf.dist
COPY conf/ /opt/netvfs/conf/
COPY start.sh flipproxy.py /opt/netvfs/
ENTRYPOINT ["/bin/sh", "/opt/netvfs/start.sh"]
