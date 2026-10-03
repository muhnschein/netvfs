#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPEC-v2 XP-2: an update from a release before the package split keeps the
# backups. In a fresh SDK target per scenario: installs the old release's
# RPMs, serves the new RPMs from a local repository, updates and checks that
# every file the old netvfs-account-* packages installed (backup plugins and
# profiles, backup service, provider, account UI, backend) is still there
# and belongs to a package of the new release, and that the netvfs-backup-*
# packages were installed.
#
# Usage: tools/ci/check-upgrade.sh OLD_RPMS_DIR NEW_RPMS_DIR [SCENARIO...]
#   Both folders are inside the source tree. Scenarios:
#     up        zypper up from the new repository (the whole system update)
#     packages  zypper in of the installed netvfs packages by name (how
#               PackageKit and the store apps update single packages)
#   Default: both.
# Env: SDK_IMAGE (container image), TARGET (sb2 target name).
set -eu
: "${SDK_IMAGE:?}" "${TARGET:?}"

if [ "${1:-}" != --in-sdk ]; then
    old_dir=${1:?usage: $0 OLD_RPMS_DIR NEW_RPMS_DIR [SCENARIO...]}
    new_dir=${2:?usage: $0 OLD_RPMS_DIR NEW_RPMS_DIR [SCENARIO...]}
    shift 2
    scenarios=${*:-up packages}
    root=$(cd "$(dirname "$0")/../.." && pwd)
    old_rel=$(cd "$old_dir" && pwd | sed "s|^$root/||")
    new_rel=$(cd "$new_dir" && pwd | sed "s|^$root/||")
    # The SDK runs as mersdk (uid 100000).
    sudo chown -R 100000:100000 "$root"
    trap 'sudo chown -R "$(id -u):$(id -g)" "$root"' EXIT
    status=0
    for scenario in $scenarios; do
        echo "=== update scenario: $scenario"
        docker run --rm -e TARGET -e SDK_IMAGE -v "$root:/home/mersdk/src" -w /home/mersdk/src "$SDK_IMAGE" \
            sh tools/ci/check-upgrade.sh --in-sdk "$old_rel" "$new_rel" "$scenario" || status=1
    done
    exit $status
fi

# In the SDK container, in the source tree.
old_dir=$2
new_dir=$3
scenario=$4
target_root=/srv/mer/targets/$TARGET
status=0

fail() {
    message=$1
    echo "FAIL: $message"
    status=1
}

# Exit code 106 (a repository could not be refreshed) is informational: a
# dependency it would have provided fails the transaction with its own error.
zypper_target() {
    code=0
    sb2 -t "$TARGET" -m sdk-install -R zypper --non-interactive "$@" || code=$?
    [ "$code" -eq 0 ] || [ "$code" -eq 106 ]
}

packages() {
    folder=$1
    ls "$folder"/*.rpm | grep -v -e debuginfo -e debugsource
}

old_rpms=$(packages "$old_dir")
old_version=$(rpm -qp --qf '%{VERSION}' "$(packages "$old_dir" | grep '/netvfs-core-[0-9]')")
new_version=$(rpm -qp --qf '%{VERSION}' "$(packages "$new_dir" | grep '/netvfs-core-[0-9]')")
echo "old: $(for r in $old_rpms; do basename "$r"; done | tr '\n' ' ')"

# shellcheck disable=SC2086 # one word per file
zypper_target in --allow-unsigned-rpm $old_rpms
installed_old=$(sb2 -t "$TARGET" rpm -qa --qf '%{NAME}\n' 'netvfs*' | sort)
accounts_old=$(echo "$installed_old" | grep '^netvfs-account-')
# shellcheck disable=SC2086 # one word per package
keep=$(sb2 -t "$TARGET" rpm -ql $accounts_old)

repo=$PWD/build-upgrade-repo-$$
rm -rf "$repo"
mkdir -p "$repo"
# shellcheck disable=SC2046 # one word per file
cp $(packages "$new_dir") "$repo/"
createrepo_c -q "$repo"
zypper_target ar -G "file://$repo" netvfs-new
zypper_target ref netvfs-new

case $scenario in
    up) update="up -r netvfs-new" ;;
    packages) update="in $installed_old" ;;
    *)
        echo "unknown scenario $scenario"
        exit 2 ;;
esac
# Exit code 107: an RPM scriptlet failed. Netvfs 0.1.0 ran
# "%postun -p /sbin/ldconfig", which fails when rpm passes it the instance
# count; that scriptlet ships in the installed old package and cannot be
# fixed by the update. Any other failed scriptlet fails the check.
log=$repo.log
code=0
# shellcheck disable=SC2086 # one word per argument
sb2 -t "$TARGET" -m sdk-install -R zypper --non-interactive $update >"$log" 2>&1 || code=$?
cat "$log"
case $code in
    0|106) ;;
    107)
        others=$(grep 'scriptlet failed' "$log" | grep -v "^warning: %postun(netvfs-core-$old_version-[^)]*) scriptlet failed" || true)
        [ -z "$others" ] || fail "scriptlets failed: $others" ;;
    *)
        echo "FAIL: zypper exited with $code"
        exit 1 ;;
esac

echo "installed after the update:"
sb2 -t "$TARGET" rpm -qa 'netvfs*' | sort | sed 's/^/  /'
for account in $accounts_old; do
    backup=$(echo "$account" | sed 's/^netvfs-account-/netvfs-backup-/')
    for package in "$account" "$backup"; do
        version=$(sb2 -t "$TARGET" rpm -q --qf '%{VERSION}' "$package" 2>/dev/null || true)
        [ "$version" = "$new_version" ] || fail "$package $new_version is not installed (found: $version)"
    done
done
for file in $keep; do
    if [ ! -e "$target_root$file" ]; then
        fail "$file is gone"
        continue
    fi
    owner=$(sb2 -t "$TARGET" rpm -qf --qf '%{NAME} %{VERSION}\n' "$file" 2>/dev/null | head -n 1 || true)
    case $owner in
        "netvfs-"*" $new_version") ;;
        *) fail "$file belongs to '$owner', not to a netvfs $new_version package" ;;
    esac
done
echo "checked $(echo "$keep" | wc -w) files of: $accounts_old"
rm -rf "$repo" "$log"
exit $status
