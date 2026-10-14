// SPDX-License-Identifier: LGPL-2.1-or-later
// Writes and dumps QSettings INI files and QLockFile lock files, for the
// golden files of netvfs-bridge's `ini` and `consent` modules (generate.sh).
// Not built by the project; only generate.sh compiles it, against Qt 5.
//
//   qsettings-golden dump FILE                 every key QSettings reads, one per line
//   qsettings-golden write FILE {KEY TYPE VALUE}...
//        TYPE s: QString, l: QStringList ('|'-separated), b: QByteArray (hex),
//             i: int, z: QSize ("w,h"), r: remove the key (VALUE ignored)
//        Strings take \uXXXX escapes (UTF-16 units).
//   qsettings-golden lock FILE                 holds QLockFile FILE until stdin closes
//   qsettings-golden trylock FILE              0 if QLockFile FILE could be taken at once
//
// Dump lines: KEY|TYPE|toString()|n|item1|...|itemN (toStringList(), n items),
// strings escaped: printable ASCII as is except '\' and '|', the rest \uXXXX.
#include <QtCore/QCoreApplication>
#include <QtCore/QLockFile>
#include <QtCore/QSettings>
#include <QtCore/QSize>
#include <QtCore/QStringList>
#include <QtCore/QTextStream>

#include <cstdio>

namespace {

QString escaped(const QString &s)
{
    QString out;
    for (const QChar c : s) {
        const ushort u = c.unicode();
        if (u >= 0x20 && u < 0x7f && u != '\\' && u != '|')
            out += c;
        else
            out += QStringLiteral("\\u%1").arg(u, 4, 16, QLatin1Char('0'));
    }
    return out;
}

QString unescaped(const QString &s)
{
    QString out;
    for (int i = 0; i < s.size(); ++i) {
        if (s.at(i) == QLatin1Char('\\') && i + 5 < s.size() && s.at(i + 1) == QLatin1Char('u')) {
            out += QChar(s.mid(i + 2, 4).toUShort(nullptr, 16));
            i += 5;
        } else {
            out += s.at(i);
        }
    }
    return out;
}

int dump(const QString &file)
{
    QSettings settings(file, QSettings::IniFormat);
    QTextStream out(stdout);
    for (const QString &key : settings.allKeys()) {
        const QVariant v = settings.value(key);
        const QStringList list = v.toStringList();
        QStringList items;
        for (const QString &item : list)
            items << escaped(item);
        out << escaped(key) << '|' << (v.isValid() ? v.typeName() : "invalid") << '|' << escaped(v.toString())
            << '|' << list.size();
        for (const QString &item : items)
            out << '|' << item;
        out << '\n';
    }
    out << "status|" << settings.status() << '\n';
    return 0;
}

int write(const QString &file, const QStringList &args)
{
    QSettings settings(file, QSettings::IniFormat);
    for (int i = 0; i + 2 < args.size(); i += 3) {
        const QString key = unescaped(args.at(i));
        const QString type = args.at(i + 1);
        const QString value = unescaped(args.at(i + 2));
        if (type == QLatin1String("s"))
            settings.setValue(key, value);
        else if (type == QLatin1String("l"))
            settings.setValue(key, value.split(QLatin1Char('|')));
        else if (type == QLatin1String("b"))
            settings.setValue(key, QByteArray::fromHex(value.toLatin1()));
        else if (type == QLatin1String("i"))
            settings.setValue(key, value.toInt());
        else if (type == QLatin1String("z"))
            settings.setValue(key, QSize(value.section(QLatin1Char(','), 0, 0).toInt(),
                                         value.section(QLatin1Char(','), 1, 1).toInt()));
        else if (type == QLatin1String("r"))
            settings.remove(key);
        else
            return 2;
    }
    settings.sync();
    return settings.status() == QSettings::NoError ? 0 : 1;
}

int lock(const QString &file, bool once)
{
    QLockFile lockFile(file);
    if (once)
        return lockFile.tryLock(0) ? 0 : 1;
    if (!lockFile.lock())
        return 1;
    std::printf("locked\n");
    std::fflush(stdout);
    while (std::getchar() != EOF) {
    }
    return 0;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QStringList args = QCoreApplication::arguments();
    if (args.size() >= 3 && args.at(1) == QLatin1String("dump"))
        return dump(args.at(2));
    if (args.size() >= 3 && args.at(1) == QLatin1String("write"))
        return write(args.at(2), args.mid(3));
    if (args.size() == 3 && args.at(1) == QLatin1String("lock"))
        return lock(args.at(2), false);
    if (args.size() == 3 && args.at(1) == QLatin1String("trylock"))
        return lock(args.at(2), true);
    std::fprintf(stderr, "usage: qsettings-golden dump|write|lock|trylock FILE ...\n");
    return 2;
}
