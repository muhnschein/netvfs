// SPDX-License-Identifier: LGPL-2.1-or-later
#include "cliprompt.h"

#include "cliformat.h"
#include "secure.h"

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

namespace NetVfs::Cli {

bool Terminal::open()
{
    const int fd = ::open("/dev/tty", O_RDWR);
    if (fd < 0)
        return false;
    if (!m_file.open(fd, QIODevice::ReadOnly, QFile::AutoCloseHandle)) {
        ::close(fd);
        return false;
    }
    return true;
}

bool Terminal::setEcho(bool on)
{
    termios settings;
    const int fd = m_file.handle();
    if (fd < 0 || ::tcgetattr(fd, &settings) != 0)
        return false;
    if (on)
        settings.c_lflag |= ECHO;
    else
        settings.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    return ::tcsetattr(fd, TCSAFLUSH, &settings) == 0;
}

TerminalPrompter::TerminalPrompter(QIODevice *input, QTextStream *prompts, EchoControl *echo)
    : m_input(input)
    , m_prompts(prompts)
    , m_echo(echo)
{
}

bool TerminalPrompter::readAnswer(const AuthPrompt &prompt, QByteArray *answer) const
{
    *m_prompts << sanitizeForTerminal(prompt.text);
    m_prompts->flush();
    // A secret is never read with the echo on: if it cannot be switched off,
    // the prompt is declined.
    const bool hide = !prompt.echo && m_echo;
    if (hide && !m_echo->setEcho(false))
        return false;
    QByteArray line = m_input->readLine();
    if (hide) {
        m_echo->setEcho(true);
        *m_prompts << '\n';
        m_prompts->flush();
    }
    const bool complete = !line.isEmpty();
    while (line.endsWith('\n') || line.endsWith('\r'))
        line.chop(1);
    *answer = line;
    secureWipe(line);
    return complete;
}

bool TerminalPrompter::answer(const QString &name, const QString &instruction, const QVector<AuthPrompt> &prompts,
                              QVector<QByteArray> *answers)
{
    if (!name.isEmpty())
        *m_prompts << sanitizeForTerminal(name) << '\n';
    if (!instruction.isEmpty())
        *m_prompts << sanitizeForTerminal(instruction) << '\n';
    answers->clear();
    for (const AuthPrompt &prompt : prompts) {
        QByteArray reply;
        if (!readAnswer(prompt, &reply)) {
            for (QByteArray &given : *answers)
                secureWipe(given);
            answers->clear();
            return false;
        }
        answers->append(reply);
    }
    return true;
}

} // namespace NetVfs::Cli
