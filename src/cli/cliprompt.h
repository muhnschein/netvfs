// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CLI_PROMPT_H
#define NETVFS_CLI_PROMPT_H

#include "types.h"

#include <QtCore/QFile>
#include <QtCore/QTextStream>

// SPEC-v2 XC-15 / XC-CLI: keyboard-interactive authentication on the terminal
// (netvfs-cli --prompt).
namespace NetVfs::Cli {

// Switches the terminal echo; the real one uses termios on the controlling
// terminal, tests substitute a recorder.
class EchoControl
{
public:
    virtual ~EchoControl() = default;
    virtual bool setEcho(bool on) = 0;
};

// The controlling terminal (/dev/tty), opened for reading answers. Echo is
// restored on every path out of a prompt.
class Terminal : public EchoControl
{
public:
    Terminal() = default;
    Terminal(const Terminal &) = delete;
    Terminal &operator=(const Terminal &) = delete;

    // False when the process has no controlling terminal.
    bool open();
    QIODevice *device() { return &m_file; }
    bool setEcho(bool on) override;

private:
    QFile m_file;
};

// Asks every prompt of the server on `prompts` (the terminal, never stdout)
// and reads one line per prompt from `input`. Prompts the server marks as
// no-echo are read with the echo off. Server text is sanitised before it is
// shown (terminal escape sequences). End of input declines (AuthFailed).
class TerminalPrompter : public AuthPrompter
{
public:
    // `echo` may be null (input is not a terminal).
    TerminalPrompter(QIODevice *input, QTextStream *prompts, EchoControl *echo);

    bool answer(const QString &name, const QString &instruction, const QVector<AuthPrompt> &prompts,
                QVector<QByteArray> *answers) override;

private:
    bool readAnswer(const AuthPrompt &prompt, QByteArray *answer);

    QIODevice *m_input;
    QTextStream *m_prompts;
    EchoControl *m_echo;
};

} // namespace NetVfs::Cli

#endif
