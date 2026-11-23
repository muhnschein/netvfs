// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CLI_PROMPT_H
#define NETVFS_CLI_PROMPT_H

#include "types.h"

#include <QtCore/QFile>
#include <QtCore/QTextStream>

namespace NetVfs::Cli {
class EchoControl
{
public:
    virtual ~EchoControl() = default;
    virtual bool setEcho(bool on) = 0;
};

class Terminal : public EchoControl
{
public:
    Terminal() = default;
    Terminal(const Terminal &) = delete;
    Terminal &operator=(const Terminal &) = delete;

    bool open();
    QIODevice *device() { return &m_file; }
    bool setEcho(bool on) override;

private:
    QFile m_file;
};

class TerminalPrompter : public AuthPrompter
{
public:
    TerminalPrompter(QIODevice *input, QTextStream *prompts, EchoControl *echo);

    bool answer(const QString &name, const QString &instruction, const QVector<AuthPrompt> &prompts,
                QVector<QByteArray> *answers) override;

private:
    bool readAnswer(const AuthPrompt &prompt, QByteArray *answer) const;

    QIODevice *m_input;
    QTextStream *m_prompts;
    EchoControl *m_echo;
};

}
#endif
