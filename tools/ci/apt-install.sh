#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Install Ubuntu packages on CI runner, without others' apt repo breaking the
# build.
#
# `apt-get update` exits 100 if ANY repo fails. Runner image ships extra repos
# this project never uses: one bad index kills every job.
#
# So third-party lists dropped before update. Ubuntu's kept wherever image puts
# them (sources.list, or .list/.sources under sources.list.d). List dropped only
# if no ubuntu.com host in it, so the archive we install from is never deleted.
#
# Mirror pick: azure.archive.ubuntu.com trickles debs on some runners while
# neighbours in same run install in 16 s (seen: 26 kB/s, 98 MB, 1 h). Indexes
# no guide: same mirror served them at 9 MB/s. So after index, each mirror
# timed on 2 MiB of biggest deb install needs, fastest first in mirror list.
#
# Mirror slow or down anyway: apt retries each file, gives up on a stalled one;
# still failing = next mirror, once (older image's lists: Ubuntu's own
# archive.ubuntu.com). Trickling mirror never stalls (seen: 120 kB/s, 124 MB,
# 9.5 min of 20): first try's index and download each capped at
# APT_FIRST_TRY_SECONDS (240), then next. Download only under cap: killed
# apt-get mid-dpkg leaves system half-installed. Debs fetched stay, reused.
#
# Usage:  tools/ci/apt-install.sh <package>...
#         tools/ci/apt-install.sh --prune-only     (drop lists, install nothing)
#
# APT_SOURCES_DIR, APT_SOURCES_LIST, APT_MIRROR_LIST override pruned dir,
# sources.list and apt-mirrors.txt;
# APT_GET, APT_CURL stand in for `sudo apt-get`, `curl`:
# tools/ci/apt-install-selftest.sh tests its own dir, a failing or slow apt, mirrors
# of chosen speed.
set -euo pipefail

sources_dir=$(printenv APT_SOURCES_DIR || true)
if [[ -z "$sources_dir" ]]; then
    sources_dir=/etc/apt/sources.list.d
fi
sources_list=$(printenv APT_SOURCES_LIST || true)
if [[ -z "$sources_list" ]]; then
    sources_list=/etc/apt/sources.list
fi
# Current image: ubuntu.sources says `mirror+file:` this list; hosts live here
# (azure first). apt moves on only when a request errors; trickle never does.
mirror_list=$(printenv APT_MIRROR_LIST || true)
if [[ -z "$mirror_list" ]]; then
    mirror_list=/etc/apt/apt-mirrors.txt
fi
apt_stub=$(printenv APT_GET || true)
first_try=$(printenv APT_FIRST_TRY_SECONDS || true)
if [[ -z "$first_try" ]]; then
    first_try=240
fi
curl_cmd=$(printenv APT_CURL || true)
if [[ -z "$curl_cmd" ]]; then
    curl_cmd=curl
fi
# Probed beside mirror list's own. Official Ubuntu mirror, run by kernel.org;
# not in Azure, so not behind same slowdown.
extra_mirrors=(https://mirrors.edge.kernel.org/ubuntu/)
probe_seconds=5

prune_only=0
if [[ "$#" -ge 1 ]] && [[ "$1" = "--prune-only" ]]; then
    prune_only=1
    shift
fi

# rm as owner if writable, else sudo. Selftest dir must not prompt for password.
drop() {
    local list=$1
    if [[ -w "$(dirname -- "$list")" ]]; then
        rm -f "$list"
    else
        sudo rm -f "$list"
    fi
}

if [[ -d "$sources_dir" ]]; then
    for list in "$sources_dir"/*; do
        [[ -f "$list" ]] || continue
        case "$list" in
            *.list|*.sources) ;;
            *) continue ;;
        esac
        if grep -qE '://[^[:space:]]*\.ubuntu\.com' "$list"; then
            echo "apt-install: keeping $(basename -- "$list")"
            continue
        fi
        echo "apt-install: dropping $(basename -- "$list")"
        drop "$list"
    done
fi

if [[ "$prune_only" -eq 1 ]]; then
    exit 0
fi

if [[ "$#" -eq 0 ]]; then
    echo "apt-install: no packages named" >&2
    exit 1
fi

# Per file: 3 retries, 30 s without data = stalled. `--within <s>`: killed
# after s seconds (timeout under sudo: must reach root apt-get).
apt_get() {
    local options=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30
        -o Acquire::https::Timeout=30)
    local cap=() flag=${1-} seconds=${2-}
    if [[ "$flag" = --within ]]; then
        cap=(timeout "$seconds")
        shift 2
    fi
    if [[ -n "$apt_stub" ]]; then
        "${cap[@]}" "$apt_stub" "${options[@]}" "$@"
    else
        sudo "${cap[@]}" apt-get "${options[@]}" "$@"
    fi
    return $?
}

# Country or cloud mirror (azure.archive.ubuntu.com) to archive.ubuntu.com, in
# every list left. security.ubuntu.com, ports.ubuntu.com: not mirrors, kept.
# Mirror list: next_mirror_first.
use_main_archive() {
    local list mirror='://[a-z0-9.-]+\.archive\.ubuntu\.com'
    local rewrite="s#$mirror#://archive.ubuntu.com#g"
    for list in "$sources_list" "$sources_dir"/*.list "$sources_dir"/*.sources; do
        [[ -f "$list" ]] || continue
        grep -qE "$mirror" "$list" || continue
        echo "apt-install: $(basename -- "$list") now uses archive.ubuntu.com"
        if [[ -w "$list" ]]; then
            sed -i -E "$rewrite" "$list"
        else
            sudo sed -i -E "$rewrite" "$list"
        fi
    done
}

# write_mirrors <url>...: mirror list, in that order. Same form as image's.
write_mirrors() {
    local url priority=0 text=''
    for url in "$@"; do
        priority=$((priority + 1))
        text+=$(printf '%s\tpriority:%d' "$url" "$priority")$'\n'
    done
    if [[ -w "$mirror_list" ]]; then
        printf '%s' "$text" >"$mirror_list"
    else
        printf '%s' "$text" | sudo tee "$mirror_list" >/dev/null
    fi
    return 0
}

# Mirror list's URLs, in order: archives in `mirrors`, security.ubuntu.com
# (only its own pocket's debs, never picked first) in `security`.
mirrors=()
security=()
read_mirrors() {
    local url rest
    mirrors=()
    security=()
    while read -r url rest; do
        case "$url" in
            '' | '#'*) continue ;;
            *://security.ubuntu.com/*) security+=("$url") ;;
            *) mirrors+=("$url") ;;
        esac
    done <"$mirror_list"
    return 0
}

# Bytes per second <url> gives over its first 2 MiB, at most probe_seconds
# long; 0 if error status or nothing came. Cut short = rate so far.
probe() {
    local url=$1 out code size seconds
    out=$("$curl_cmd" -sS -o /dev/null -r 0-2097151 --max-time "$probe_seconds" \
        -w '%{http_code} %{size_download} %{time_total}' "$url" 2>/dev/null) || true
    read -r code size seconds <<<"$out"
    case "$code" in
        200 | 206) ;;
        *)
            echo 0
            return 0
            ;;
    esac
    awk -v size="$size" -v seconds="$seconds" \
        'BEGIN { if (seconds > 0) printf "%d\n", size / seconds; else print 0 }'
    return 0
}

# After index: biggest deb install needs, timed from each mirror; fastest
# first. Nothing to fetch, no mirror list, or nothing answered = list as was.
fastest_mirror_first() {
    [[ -f "$mirror_list" ]] || return 0
    local pool
    pool=$(apt_get install -y -qq --print-uris "$@" | sort -k3,3n | tail -n 1 |
        sed -nE "s#^'[^']*/(pool/[^']*)'.*#\1#p") || true
    if [[ -z "$pool" ]]; then
        echo "apt-install: no deb to time mirrors on; mirror list as it was"
        return 0
    fi
    read_mirrors
    local url known
    for url in "${extra_mirrors[@]}"; do
        for known in "${mirrors[@]}"; do
            [[ "$known" = "$url" ]] && continue 2
        done
        mirrors+=("$url")
    done
    local rate ranked=''
    for url in "${mirrors[@]}"; do
        rate=$(probe "$url$pool")
        echo "apt-install: $url $((rate / 1024)) kB/s"
        ranked+="$rate $url"$'\n'
    done
    # Stable: ties keep list's order.
    ranked=$(printf '%s' "$ranked" | sort -s -k1,1nr)
    if [[ "${ranked%% *}" -eq 0 ]]; then
        echo "apt-install: no mirror answered; mirror list as it was"
        return 0
    fi
    mapfile -t mirrors < <(printf '%s\n' "$ranked" | cut -d' ' -f2)
    write_mirrors "${mirrors[@]}" "${security[@]}"
    echo "apt-install: debs from ${mirrors[0]} first"
    return 0
}

# Fallback: first mirror let us down. Next goes first, it goes last.
next_mirror_first() {
    [[ -f "$mirror_list" ]] || return 0
    read_mirrors
    [[ "${#mirrors[@]}" -ge 2 ]] || return 0
    write_mirrors "${mirrors[@]:1}" "${security[@]}" "${mirrors[0]}"
    echo "apt-install: debs from ${mirrors[1]} first, ${mirrors[0]} last"
    return 0
}

if apt_get --within "$first_try" update &&
    fastest_mirror_first "$@" &&
    apt_get --within "$first_try" install -y --download-only "$@"; then
    apt_get install -y "$@"
    exit 0
fi
echo "apt-install: mirror failed or slower than ${first_try} s; once more from the next" >&2
next_mirror_first
use_main_archive
apt_get update
apt_get install -y "$@"
