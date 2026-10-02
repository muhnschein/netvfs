# SPDX-License-Identifier: LGPL-2.1-or-later
# Built and run only inside the Sailfish OS SDK target by run-in-sdk.sh.
TEMPLATE = app
TARGET = qmlcheck
QT = core gui qml
CONFIG -= app_bundle
SOURCES = qmlcheck.cpp
