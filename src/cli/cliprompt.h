// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CLI_PROMPT_H
#define NETVFS_CLI_PROMPT_H

#include "types.h"

#include <QtCore/QFile>
#include <QtCore/QTextStream>

// Keyboard-interactive authentication on the terminal (netvfs-cli --prompt).
namespace NetVfs::Cli {

// Switches the terminal echo; the real one uses termios on the controlling terminal, tests
// substitute a recorder.
class EchoControl
{
public:
    virtual ~EchoControl() = default;
    virtual bool setEcho(bool on) = 0;
};

// Controlling terminal (/dev/tty), opened for reading answers. Echo restored on every path out of a
// prompt.
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

// Asks every server prompt on `prompts` (the terminal, never stdout), reads one line per prompt
// from `input`. No-echo prompts read with echo off. Server text sanitised before display. End of
// input declines (AuthFailed).
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
