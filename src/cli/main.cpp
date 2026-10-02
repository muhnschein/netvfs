// SPDX-License-Identifier: LGPL-2.1-or-later
#include "cli.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QTextStream>

#include <cstdio>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    QTextStream err(stderr);
    return NetVfs::Cli::run(app.arguments().mid(1), out, err);
}
