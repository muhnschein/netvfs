#!/bin/sh
# Installs the built RPMs into the SDK target (resolving Requires from the
# release repositories) and checks that every shared object resolves.
set -eu
: "${SDK_IMAGE:?}" "${TARGET:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
sudo chown -R 100000:100000 "$root"
trap 'sudo chown -R "$(id -u):$(id -g)" "$root"' EXIT
docker run --rm -v "$root:/home/mersdk/src" -w /home/mersdk/src "$SDK_IMAGE" bash -euc "
    rpms=\$(ls RPMS/*.rpm | grep -v -e debuginfo -e debugsource)
    for r in \$rpms; do echo \"== \$r\"; rpm -qp --requires \"\$r\" | sed 's/^/  requires: /'; done
    sb2 -t '$TARGET' -m sdk-install -R zypper --non-interactive in --allow-unsigned-rpm \$rpms
    status=0
    for so in \$(sb2 -t '$TARGET' rpm -ql \$(for r in \$rpms; do rpm -qp --qf '%{NAME} ' \"\$r\"; done) | grep '\\.so'); do
        [ -f \"/srv/mer/targets/$TARGET\$so\" ] || continue
        if sb2 -t '$TARGET' ldd \"\$so\" | grep 'not found'; then
            echo \"unresolved libraries in \$so\"; status=1
        fi
        if readelf -d \"/srv/mer/targets/$TARGET\$so\" | grep -E 'RPATH|RUNPATH'; then
            echo \"\$so carries a library search path from the build\"; status=1
        fi
    done
    exit \$status
"
