#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Regenerates the QSettings golden files of netvfs-bridge's `ini` and
# `consent` tests with Qt 5 itself (qsettings-golden.cpp). Needs g++ and the
# Qt5Core development files; run from anywhere:
#
#   rust/netvfs-bridge/tests/data/qsettings/generate.sh
#
# Inputs (checked in, hand-written): edge.conf, bridge-rust-edited.conf (what
# ConsentStore writes; the `consent` tests check that it still does).
# Outputs: *.dump (what QSettings reads), bridge-qt.conf and fresh.conf
# (written by QSettings). Then it checks the lock file against QLockFile.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
g++ -std=c++17 -fPIC -O1 -o "$work/qsg" "$here/qsettings-golden.cpp" $(pkg-config --cflags --libs Qt5Core)
qsg="$work/qsg"

# A bridge.conf as the account UI leaves it: consents among other groups.
rm -f "$here/bridge-qt.conf"
"$qsg" write "$here/bridge-qt.conf" \
    Consent/lautta s granted \
    Consent/photos s denied \
    Ui/lastPage s consent \
    'Ui/odd key' s 'with, comma; and = signs' \
    top s '@at start' \
    list l 'a|b, c| d' \
    unicode s 'ä€\u0001x' \
    'Weirdä/k一' s v \
    bytes b 01ff00 \
    num i 42 \
    size z 1,2 \
    'Consent%/x' s y
"$qsg" dump "$here/bridge-qt.conf" > "$here/bridge-qt.dump"

# The same edits by QSettings: what ConsentStore's edits must read as.
cp "$here/bridge-qt.conf" "$work/edited.conf"
"$qsg" write "$work/edited.conf" \
    Consent/lautta s denied \
    Consent/photos r - \
    Consent/new-one s granted
"$qsg" dump "$work/edited.conf" > "$here/bridge-qt-edited.dump"

# A first consent in a new file: ConsentStore writes the same bytes.
rm -f "$here/fresh.conf"
"$qsg" write "$here/fresh.conf" Consent/lautta s granted

# Every key of a file full of syntax corner cases.
"$qsg" dump "$here/edge.conf" > "$here/edge.dump"

# The shipped handoff table.
"$qsg" dump "$here/../../../../../src/bridge/data/handoff.conf" > "$here/handoff.dump"
# ConsentStore's own result reads the same in Qt.
"$qsg" dump "$here/bridge-rust-edited.conf" > "$work/rust-edited.dump"
cmp "$here/bridge-qt-edited.dump" "$work/rust-edited.dump"

# Our lock file against QLockFile, both ways.
NETVFS_QSETTINGS_GOLDEN="$qsg" cargo test --manifest-path "$here/../../../Cargo.toml" --lib -- \
    lockfile::tests::qlockfile_interop
echo "golden files written to $here"
