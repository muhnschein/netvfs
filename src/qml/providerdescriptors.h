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

// Provider descriptors, /usr/share/netvfs/providers/<p>.json (NETVFS_PROVIDERS_DIR overrides,
// tests). Account dialogs render from them; every rule for what is shown, accepted or stored lives
// here, unit tested.
// Keys (all required unless marked optional):
//   provider: equals the file's base name
//   services: non-empty list of "backup" or "files"
//   defaultPort: 0..65535 (0: protocol default)
//   authModes: non-empty list of { id: password|publickey|interactive, source (optional, publickey
//     only): generate|import, label: text id, secret: password|key|none }
//   noSecretWhen (optional): condition under which no secret is asked (smb guest)
//   fields: list of { key: [a-z_]+, unique; type: text|switch|choice|note; label: text id;
//     description, placeholder (optional): text ids; default (optional): string or bool (switch);
//     choices (choice only): non-empty list of { value, label }; validation (optional):
//     host|port|userName|share|folder|consent; optional (optional bool): empty text acceptable;
//     input (optional): url|digits|text; service (optional): backup|files, a setting of that
//     service, shown only with it; visibleWhen (optional): condition }
//   condition: { <field key or "auth_mode">: [accepted string values] }, all entries must match.
// "host", "port", "username" are the connection itself; fields with a service are service settings
// (backups_path, files_root); notes carry no value; all others are provider options
// ("netvfs/<p>/<key>"). Text ids must be in knownTextIds().
class ProviderDescriptors : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(ProviderDescriptors)

public:
    explicit ProviderDescriptors(QObject *parent = nullptr);
    ~ProviderDescriptors() override;

    static QString directory();
    // Text ids descriptors may use (descriptortexts.cpp).
    static QStringList knownTextIds();
    // Error message names the first problem.
    static NetVfs::Result validate(const QJsonObject &descriptor, const QString &provider);
    static NetVfs::Result load(const QString &provider, QVariantMap *descriptor);

    // Empty map when the descriptor is missing or invalid (logged).
    Q_INVOKABLE QVariantMap descriptor(const QString &provider);
    Q_INVOKABLE QStringList providers() const;
    Q_INVOKABLE QString text(const QString &id) const;

    // Values: { <field key>: string or bool, auth_mode, key_source }. Services: those the account
    // is set up for.
    Q_INVOKABLE QVariantMap initialValues(const QString &provider);
    Q_INVOKABLE bool isVisible(const QVariantMap &field, const QVariantMap &values, const QStringList &services) const;
    // Translated problem of one field, "" when acceptable or not shown.
    Q_INVOKABLE QString problem(const QString &provider, const QVariantMap &field, const QVariantMap &values,
                                const QStringList &services) const;
    Q_INVOKABLE bool isValid(const QString &provider, const QVariantMap &values, const QStringList &services);
    Q_INVOKABLE bool offersService(const QString &provider, const QString &service);
    // Selected auth mode entry (by auth_mode and key_source); first by default.
    Q_INVOKABLE QVariantMap authMode(const QString &provider, const QVariantMap &values);
    // "password", "key" or "none" (interactive, smb guest).
    Q_INVOKABLE QString secretKind(const QString &provider, const QVariantMap &values);
    // Connection parameters (Helpers::makeParams shape): host, port, user name, visible option
    // fields, auth_mode when the provider has more than one, plus `extraOptions` (accepted pin's
    // options). Hidden fields are not stored (a guest has no user).
    Q_INVOKABLE QVariantMap makeParams(const QString &provider, const QVariantMap &values,
                                       const QVariantMap &extraOptions);
    Q_INVOKABLE QString serviceValue(const QString &provider, const QVariantMap &values, const QString &key) const;
    // [{ label, value }] for the visible, non-service fields with a value.
    Q_INVOKABLE QVariantList details(const QString &provider, const QVariantMap &params);

private:
    QString ruleProblem(const QString &provider, const QString &rule, const QVariant &value) const;

    QHash<QString, QVariantMap> m_cache;
    InputRules *m_rules;
};

}
#endif
