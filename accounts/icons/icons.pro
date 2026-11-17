# SPDX-License-Identifier: LGPL-2.1-or-later
# graphic-service-<p>.png for every theme scale, converted from the SVGs at package build time by
# the sailfish-svg2png qmake feature (as the platform's account packages do). No-op on hosts
# without the feature.
TEMPLATE = aux
THEMENAME = sailfish-default
CONFIG += sailfish-svg2png

OTHER_FILES += $$PWD/svgs/*
