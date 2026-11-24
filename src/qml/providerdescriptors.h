// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_PROVIDERDESCRIPTORS_H
#define NETVFS_QML_PROVIDERDESCRIPTORS_H

#include "error.h"

#include <QtCore/QHash>
#include <QtCore/QJsonObject>
#include <QtCore/QObject>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>

namespace NetVfsUi {

class InputRules;

class ProviderDescriptors : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(ProviderDescriptors)

public:
    explicit ProviderDescriptors(QObject *parent = nullptr);
    ~ProviderDescriptors() override;

    static QString directory();
    static QStringList knownTextIds();
    static NetVfs::Result validate(const QJsonObject &descriptor, const QString &provider);
    static NetVfs::Result load(const QString &provider, QVariantMap *descriptor);

    Q_INVOKABLE QVariantMap descriptor(const QString &provider);
    Q_INVOKABLE QStringList providers() const;
    Q_INVOKABLE QString text(const QString &id) const;

    Q_INVOKABLE QVariantMap initialValues(const QString &provider);
    Q_INVOKABLE bool isVisible(const QVariantMap &field, const QVariantMap &values, const QStringList &services) const;
    Q_INVOKABLE QString problem(const QString &provider, const QVariantMap &field, const QVariantMap &values,
                                const QStringList &services) const;
    Q_INVOKABLE bool isValid(const QString &provider, const QVariantMap &values, const QStringList &services);
    Q_INVOKABLE bool offersService(const QString &provider, const QString &service);
    Q_INVOKABLE QVariantMap authMode(const QString &provider, const QVariantMap &values);
    Q_INVOKABLE QString secretKind(const QString &provider, const QVariantMap &values);
    Q_INVOKABLE QVariantMap makeParams(const QString &provider, const QVariantMap &values,
                                       const QVariantMap &extraOptions);
    Q_INVOKABLE QString serviceValue(const QString &provider, const QVariantMap &values, const QString &key) const;
    Q_INVOKABLE QVariantList details(const QString &provider, const QVariantMap &params);

private:
    QString ruleProblem(const QString &provider, const QString &rule, const QVariant &value) const;

    QHash<QString, QVariantMap> m_cache;
    InputRules *m_rules;
};

}
#endif
