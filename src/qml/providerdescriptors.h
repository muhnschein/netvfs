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

// SPEC-v2 XA-5: provider descriptors, /usr/share/netvfs/providers/<p>.json
// (directory overridable with NETVFS_PROVIDERS_DIR, for tests). The account
// dialogs render from them instead of per-provider QML branches; every rule
// that decides what is shown, accepted or stored lives here so it is unit
// tested.
//
// Format (all keys required unless marked optional):
//   provider     string, equals the file's base name
//   services     non-empty list of "backup" | "files" the provider offers
//   defaultPort  integer 0..65535, prefilled port (0: none, the protocol default)
//   authModes    non-empty list of
//                  { id: "password"|"publickey"|"interactive"|"token",
//                    source (optional, publickey only): "generate"|"import",
//                    label: text id, secret: "password"|"token"|"key"|"none" }
//   noSecretWhen (optional) condition under which no secret is asked (smb guest)
//   fields       list of
//                  { key: [a-z_]+, unique,
//                    type: "text" | "switch" | "choice" | "note",
//                    label: text id,
//                    description, placeholder (optional): text ids,
//                    default (optional): string (text, choice) or bool (switch),
//                    choices (choice only): non-empty list of { value, label },
//                    validation (optional): host | port | userName | share | folder
//                                           | path | consent,
//                    optional (optional bool): an empty text is acceptable,
//                    input (optional): "url" | "digits" | "text",
//                    service (optional): "backup" | "files" -- a setting of
//                                        that service, shown only with it,
//                    visibleWhen (optional): condition }
//   condition    { <field key or "auth_mode">: [accepted string values] },
//                all entries must match; switch values compare as "true"/"false".
//
// Keys "host", "port" and "username" are the connection itself; fields with
// a service are service settings (backups_path, files_root); notes carry no
// value; all other fields are provider options ("netvfs/<p>/<key>").
// Text ids must be among knownTextIds(), so every label has a translation.
class ProviderDescriptors : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(ProviderDescriptors)

public:
    explicit ProviderDescriptors(QObject *parent = nullptr);
    ~ProviderDescriptors() override;

    static QString directory();
    // The text ids descriptors may use (descriptortexts.cpp).
    static QStringList knownTextIds();
    // Checks a parsed descriptor against the format above; the error message
    // names the first problem.
    static NetVfs::Result validate(const QJsonObject &descriptor, const QString &provider);
    // Reads and validates <directory>/<provider>.json.
    static NetVfs::Result load(const QString &provider, QVariantMap *descriptor);

    // Empty map when the descriptor is missing or invalid (logged).
    Q_INVOKABLE QVariantMap descriptor(const QString &provider);
    // Providers with a valid descriptor, sorted.
    Q_INVOKABLE QStringList providers() const;
    // The translation of a descriptor text id.
    Q_INVOKABLE QString text(const QString &id) const;

    // Values: { <field key>: string or bool, auth_mode, key_source }.
    // Services: the services the account is set up for ("backup", "files").
    Q_INVOKABLE QVariantMap initialValues(const QString &provider);
    Q_INVOKABLE bool isVisible(const QVariantMap &field, const QVariantMap &values, const QStringList &services) const;
    // Translated problem of one field, "" when acceptable or not shown.
    Q_INVOKABLE QString problem(const QString &provider, const QVariantMap &field, const QVariantMap &values,
                                const QStringList &services) const;
    // No visible field has a problem.
    Q_INVOKABLE bool isValid(const QString &provider, const QVariantMap &values, const QStringList &services);
    Q_INVOKABLE bool offersService(const QString &provider, const QString &service);
    // The selected auth mode entry (by auth_mode and key_source); the first one by default.
    Q_INVOKABLE QVariantMap authMode(const QString &provider, const QVariantMap &values);
    // "password", "token", "key" or "none" (XA-7: interactive, smb guest).
    Q_INVOKABLE QString secretKind(const QString &provider, const QVariantMap &values);
    // Connection parameters (Helpers::makeParams shape) from the values:
    // host, port, user name and the visible option fields, auth_mode when the
    // provider has more than one mode, plus `extraOptions` (the accepted
    // pin's options). Hidden fields are not stored (a guest has no user).
    Q_INVOKABLE QVariantMap makeParams(const QString &provider, const QVariantMap &values,
                                       const QVariantMap &extraOptions);
    // Cleaned value of a service setting (backups_path, files_root).
    Q_INVOKABLE QString serviceValue(const QString &provider, const QVariantMap &values, const QString &key) const;
    // Read-only view of stored parameters for the settings page:
    // [{ label, value }] for the visible, non-service fields with a value.
    Q_INVOKABLE QVariantList details(const QString &provider, const QVariantMap &params);

private:
    QString ruleProblem(const QString &provider, const QString &rule, const QVariant &value) const;

    QHash<QString, QVariantMap> m_cache;
    InputRules *m_rules;
};

} // namespace NetVfsUi

#endif
