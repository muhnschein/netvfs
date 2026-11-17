#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Prove apt-install.sh drops the right apt lists, keeps the rest. Deleting the Ubuntu archive (sources.list or a .sources file under sources.list.d) is the catastrophic failure: cases cover both.
set -u

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
script="$root/tools/ci/apt-install.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [[ ! -x "$script" ]]; then
    echo "selftest: FAIL $script is missing or not executable" >&2
    exit 1
fi

status=0
cases=0

stage() {
    rm -rf "$work/sources"
    mkdir -p "$work/sources"

    # GitHub image's extras beside Ubuntu's, one-line format.
    cat >"$work/sources/google-chrome.list" <<'EOF'
deb [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable main
EOF
    cat >"$work/sources/microsoft-prod.list" <<'EOF'
deb [arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main
EOF
    # Ubuntu archive, deb822 (current image). Dropping it is the mistake that matters.
    cat >"$work/sources/ubuntu.sources" <<'EOF'
Types: deb
URIs: http://azure.archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-backports
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
    # One-line format (older image).
    cat >"$work/sources/archive.list" <<'EOF'
deb http://archive.ubuntu.com/ubuntu jammy main
EOF
    # Not a source list: apt ignores anything without the two extensions.
    cat >"$work/sources/google-chrome.list.save" <<'EOF'
deb [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable main
EOF
    return 0
}

# survives <file> <yes|no> <why>
survives() {
    local name=$1 want=$2 why=$3
    cases=$((cases + 1))
    local there=no
    if [[ -f "$work/sources/$name" ]]; then
        there=yes
    fi
    if [[ "$there" = "$want" ]]; then
        echo "selftest: ok   $why"
    else
        echo "selftest: FAIL $why -- $name present=$there, wanted $want" >&2
        status=1
    fi
    return 0
}

stage
out=$(APT_SOURCES_DIR="$work/sources" "$script" --prune-only 2>&1)
rc=$?

cases=$((cases + 1))
if [[ "$rc" -eq 0 ]]; then
    echo "selftest: ok   pruning succeeds"
else
    echo "selftest: FAIL pruning should exit 0, got $rc" >&2
    echo "$out" >&2
    status=1
fi

survives google-chrome.list no "a third-party list is dropped"
survives microsoft-prod.list no "every third-party list is dropped, not just the first"
survives ubuntu.sources yes "the archive in deb822 form is kept"
survives archive.list yes "the archive in one-line form is kept"
survives google-chrome.list.save yes "a file apt would not read is left alone"

# Log names each file acted on.
cases=$((cases + 1))
if grep -q "dropping google-chrome.list" <<<"$out" &&
    grep -q "keeping ubuntu.sources" <<<"$out"; then
    echo "selftest: ok   the log names what was dropped and what was kept"
else
    echo "selftest: FAIL the log should name each list it acted on" >&2
    echo "$out" >&2
    status=1
fi

# Empty and missing dir both fine. "accepted", not "not an error": Sonar S7677 reads any message with "error" as an error.
rm -rf "$work/sources"
mkdir -p "$work/sources"
cases=$((cases + 1))
if APT_SOURCES_DIR="$work/sources" "$script" --prune-only >/dev/null 2>&1; then
    echo "selftest: ok   an empty sources.list.d is accepted"
else
    echo "selftest: FAIL an empty sources.list.d was rejected" >&2
    status=1
fi

cases=$((cases + 1))
if APT_SOURCES_DIR="$work/nowhere" "$script" --prune-only >/dev/null 2>&1; then
    echo "selftest: ok   a missing sources.list.d is accepted"
else
    echo "selftest: FAIL a missing sources.list.d was rejected" >&2
    status=1
fi

# No packages, no --prune-only: workflow lost its list. Refuse, not silent no-op.
stage
cases=$((cases + 1))
if APT_SOURCES_DIR="$work/sources" "$script" >/dev/null 2>&1; then
    echo "selftest: FAIL naming no packages should not exit 0" >&2
    status=1
else
    echo "selftest: ok   naming no packages is refused"
fi

# Mirror down: stand-in apt fails `update` while $APT_DOWN holds "once" or "always"; `install` alike with "install-once", "install-always". "update-slow", "download-slow" hang that call once. "installed": nothing left to fetch. `--print-uris` names two debs, big one first. Logs every call.
cat >"$work/apt-get" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$APT_LOG"
mode=$(cat "$APT_DOWN" 2>/dev/null || true)
case " $* " in
*" --print-uris "*)
    if [[ "$mode" != installed ]]; then
        echo "'mirror+file:/etc/apt/apt-mirrors.txt/pool/universe/b/big/big%2b1.deb' big+1.deb 3000000 MD5Sum:0"
        echo "'mirror+file:/etc/apt/apt-mirrors.txt/pool/main/s/small/small.deb' small.deb 9000 MD5Sum:0"
    fi
    ;;
*" update "*)
    if [[ "$mode" = update-slow ]]; then
        rm -f "$APT_DOWN"
        exec sleep 60
    fi
    if [[ "$mode" = once ]]; then
        rm -f "$APT_DOWN"
        exit 100
    fi
    if [[ "$mode" = always ]]; then
        exit 100
    fi
    ;;
*" install "*)
    if [[ "$mode" = download-slow ]] && [[ " $* " = *" --download-only "* ]]; then
        rm -f "$APT_DOWN"
        exec sleep 60
    fi
    if [[ "$mode" = install-once ]]; then
        rm -f "$APT_DOWN"
        exit 100
    fi
    if [[ "$mode" = install-always ]]; then
        exit 100
    fi
    ;;
esac
exit 0
EOF
chmod +x "$work/apt-get"

# Stand-in curl: answers per $APT_SPEEDS for URL's host ("<host> <status> <bytes> <seconds>"); unlisted host = no connection. Logs every call.
cat >"$work/curl" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$APT_PROBES"
url=${*: -1}
while read -r host answer; do
    if [[ "$url" = *"://$host/"* ]]; then
        printf '%s' "$answer"
        exit 0
    fi
done <"$APT_SPEEDS"
printf '000 0 0'
exit 7
EOF
chmod +x "$work/curl"

# Mirror speeds for next run_install. Default: azure fastest.
default_speeds() {
    printf '%s\n' 'azure.archive.ubuntu.com 206 2097152 0.2' \
        'archive.ubuntu.com 206 2097152 1.0' \
        'mirrors.edge.kernel.org 206 2097152 0.5' >"$work/speeds"
    return 0
}

# Image's mirror list (ubuntu.sources names it `mirror+file:`): azure first.
image_mirrors() {
    printf '%s\tpriority:%s\n' http://azure.archive.ubuntu.com/ubuntu/ 1 \
        https://archive.ubuntu.com/ubuntu/ 2 \
        http://security.ubuntu.com/ubuntu/ 3
    return 0
}

# run_install <down mode>: script with stand-in apt and curl, staged lists. Speeds from $work/speeds, reset after.
run_install() {
    local mode=$1
    stage
    printf 'deb http://de.archive.ubuntu.com/ubuntu jammy main\n' >"$work/sources.list"
    image_mirrors >"$work/apt-mirrors.txt"
    rm -f "$work/probes" "$work/down"
    if [[ -n "$mode" ]]; then
        echo "$mode" >"$work/down"
    fi
    run_again
    return $?
}

# run_again: as run_install, on lists as last run left them.
run_again() {
    [[ -f "$work/speeds" ]] || default_speeds
    rm -f "$work/apt.log"
    touch "$work/probes"
    APT_SOURCES_DIR="$work/sources" APT_SOURCES_LIST="$work/sources.list" \
        APT_MIRROR_LIST="$work/apt-mirrors.txt" APT_GET="$work/apt-get" \
        APT_LOG="$work/apt.log" APT_DOWN="$work/down" APT_FIRST_TRY_SECONDS=1 \
        APT_CURL="$work/curl" APT_SPEEDS="$work/speeds" \
        APT_PROBES="$work/probes" \
        "$script" qtbase5-dev >"$work/out" 2>&1
    local rc=$?
    rm -f "$work/speeds"
    return "$rc"
}

# Mirror list's URLs in order, one line.
mirror_order() {
    cut -f1 "$work/apt-mirrors.txt" | tr '\n' ' '
    return 0
}

# set_speeds <line>...: speeds for next run_install.
set_speeds() {
    printf '%s\n' "$@" >"$work/speeds"
    return 0
}

# check <why> <command...>: one case, passes when command does.
check() {
    local why=$1
    shift
    cases=$((cases + 1))
    if "$@"; then
        echo "selftest: ok   $why"
    else
        echo "selftest: FAIL $why" >&2
        cat "$work/out" >&2
        status=1
    fi
    return 0
}

run_install ""
check "a working mirror installs at once" test "$(grep -c '' "$work/apt.log")" -eq 4
check "the capped first try only downloads, so a kill never leaves dpkg half done" \
    test "$(grep -c -- '--download-only' "$work/apt.log")" -eq 1
check "apt retries each file and gives up on a stalled one" \
    grep -q 'Acquire::Retries=3 -o Acquire::http::Timeout=30' "$work/apt.log"
check "a working mirror is left as it is" \
    grep -q 'azure.archive.ubuntu.com' "$work/sources/ubuntu.sources"
check "a working mirror stays first in the image's mirror list" \
    grep -q '^http://azure.archive.ubuntu.com/' "$work/apt-mirrors.txt"

run_install once
check "a failed mirror is tried once more" test "$(grep -c '' "$work/apt.log")" -eq 3
check "the retry goes to archive.ubuntu.com (deb822)" \
    grep -q 'URIs: http://archive.ubuntu.com/ubuntu/' "$work/sources/ubuntu.sources"
check "the retry goes to archive.ubuntu.com (sources.list)" \
    grep -q 'deb http://archive.ubuntu.com/ubuntu jammy' "$work/sources.list"
check "the retry goes to archive.ubuntu.com (image's mirror list)" \
    test "$(mirror_order)" = "https://archive.ubuntu.com/ubuntu/ http://security.ubuntu.com/ubuntu/ http://azure.archive.ubuntu.com/ubuntu/ "
check "a failed index is not followed by timing mirrors" test ! -s "$work/probes"
check "the mirror list keeps security.ubuntu.com" \
    grep -q '^http://security.ubuntu.com/' "$work/apt-mirrors.txt"
check "the log says the mirror was switched" \
    grep -q 'now uses archive.ubuntu.com' "$work/out"

run_install install-once
check "a failed download is tried once more" test "$(grep -c '' "$work/apt.log")" -eq 5
check "the download retry goes to archive.ubuntu.com" \
    grep -q 'URIs: http://archive.ubuntu.com/ubuntu/' "$work/sources/ubuntu.sources"

# slow <mode> <why>: trickling call cut at cap, rest from archive, well before stand-in's 60 s.
slow() {
    local mode=$1 why=$2 began=$SECONDS
    run_install "$mode"
    local rc=$?
    check "$why" test "$rc" -eq 0 -a $((SECONDS - began)) -lt 30
    check "$why, from archive.ubuntu.com" \
        grep -q 'URIs: http://archive.ubuntu.com/ubuntu/' "$work/sources/ubuntu.sources"
    return 0
}
slow update-slow "a trickling index is cut short and fetched again"
slow download-slow "a trickling download is cut short and fetched again"

# Mirror pick. Slow runner: azure trickles, others fast. Security fastest, still never first: own pocket's debs only.
set_speeds 'azure.archive.ubuntu.com 206 131072 5.0' \
    'archive.ubuntu.com 206 2097152 0.4' \
    'mirrors.edge.kernel.org 206 2097152 0.8' \
    'security.ubuntu.com 206 2097152 0.1'
run_install ""
check "the fastest mirror goes first, security.ubuntu.com stays last" \
    test "$(mirror_order)" = "https://archive.ubuntu.com/ubuntu/ https://mirrors.edge.kernel.org/ubuntu/ http://azure.archive.ubuntu.com/ubuntu/ http://security.ubuntu.com/ubuntu/ "
check "the mirror list keeps the image's form" \
    grep -q $'^https://archive.ubuntu.com/ubuntu/\tpriority:1$' "$work/apt-mirrors.txt"
check "mirrors are timed on the biggest deb the install needs" \
    test "$(grep -c 'pool/universe/b/big/big%2b1.deb$' "$work/probes")" -eq 3
check "each mirror is timed on 2 MiB, at most 5 s" \
    test "$(grep -c -- '-r 0-2097151 --max-time 5 ' "$work/probes")" -eq 3
check "the log gives each mirror's speed" \
    grep -q 'azure.archive.ubuntu.com/ubuntu/ 25 kB/s' "$work/out"
check "the log names the mirror picked" \
    grep -q 'debs from https://archive.ubuntu.com/ubuntu/ first' "$work/out"

# Second run in same job: list already has kernel.org. Timed once, listed once.
rm -f "$work/probes"
set_speeds 'azure.archive.ubuntu.com 206 2097152 0.2' \
    'archive.ubuntu.com 206 2097152 1.0' \
    'mirrors.edge.kernel.org 206 2097152 0.5'
run_again
check "a mirror already listed is timed once" \
    test "$(grep -c 'kernel.org' "$work/probes")" -eq 1
check "a mirror already listed is listed once" \
    test "$(mirror_order)" = "http://azure.archive.ubuntu.com/ubuntu/ https://mirrors.edge.kernel.org/ubuntu/ https://archive.ubuntu.com/ubuntu/ http://security.ubuntu.com/ubuntu/ "

# Error page comes fast: by bytes per second alone, azure would win.
set_speeds 'azure.archive.ubuntu.com 404 283 0.0001' \
    'archive.ubuntu.com 206 2097152 1.0' \
    'mirrors.edge.kernel.org 206 1048576 5.0'
run_install ""
check "a mirror answering with an error is never first" \
    test "$(mirror_order)" = "https://archive.ubuntu.com/ubuntu/ https://mirrors.edge.kernel.org/ubuntu/ http://azure.archive.ubuntu.com/ubuntu/ http://security.ubuntu.com/ubuntu/ "

set_speeds 'nowhere.example 206 1 1'
run_install ""
check "no mirror answering leaves the mirror list as it was" \
    test "$(cat "$work/apt-mirrors.txt")" = "$(image_mirrors)"
check "no mirror answering still installs" test "$(grep -c '' "$work/apt.log")" -eq 4

run_install installed
check "nothing to fetch: no mirror timed" test ! -s "$work/probes"
check "nothing to fetch: mirror list as it was" \
    test "$(cat "$work/apt-mirrors.txt")" = "$(image_mirrors)"

# Picked mirror trickles after all: fallback puts next fastest first.
set_speeds 'azure.archive.ubuntu.com 206 131072 5.0' \
    'archive.ubuntu.com 206 2097152 0.4' \
    'mirrors.edge.kernel.org 206 2097152 0.8'
run_install download-slow
check "a picked mirror that trickles after all hands over to the next fastest" \
    test "$(mirror_order)" = "https://mirrors.edge.kernel.org/ubuntu/ http://azure.archive.ubuntu.com/ubuntu/ http://security.ubuntu.com/ubuntu/ https://archive.ubuntu.com/ubuntu/ "

# fails <mode> <why>: archive no better, job must fail.
fails() {
    local mode=$1 why=$2
    cases=$((cases + 1))
    if run_install "$mode"; then
        echo "selftest: FAIL $why should not exit 0" >&2
        status=1
    else
        echo "selftest: ok   $why"
    fi
    return 0
}
fails always "index from the archive failing too fails the job"
fails install-always "download from the archive failing too fails the job"

echo "selftest: $cases case(s)"
if [[ "$status" -ne 0 ]]; then
    echo "selftest: FAILED" >&2
fi
exit "$status"
