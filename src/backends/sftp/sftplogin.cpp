// SPDX-License-Identifier: LGPL-2.1-or-later
// Sign-in (SPEC-sftp S-10 to S-14, SPEC-v2 XS-11).
//
// Without a prompter the v1 rules apply unchanged: exactly the configured
// method, keyboard-interactive only as S-11 describes (the stored password
// answers one non-echo prompt), SSH_AUTH_PARTIAL is AuthFailed (S-13).
//
// With a prompter (XS-11, amends S-11, S-13 and S-14):
//  - keyboard-interactive is tried after the configured method failed, and
//    is the method of auth_mode=interactive; every round the stored
//    password does not answer by S-11 goes to the prompter, for as many
//    rounds as the server sends (up to MaxKeyboardInteractiveRounds);
//  - partial success continues with keyboard-interactive, or with a
//    password asked through the prompter, so publickey + OTP and
//    password + OTP chains work;
//  - answers are wiped after use (SEC-5, XSEC-6), and cancel() ends a wait
//    in the prompter (XC-22, AuthPrompter::cancel()).
#include "secure.h"
#include "sftpinternal.h"
#include "sshkeys.h"
#include "sshutil.h"

namespace NetVfs::Sftp {

namespace {

constexpr const char *AuthModeOption = "auth_mode";
constexpr int MaxKeyboardInteractiveRounds = 8;
constexpr int MaxAuthSteps = 4;   // methods in one sign-in, partial successes included

bool offers(int methods, int method)
{
    return (static_cast<unsigned>(methods) & static_cast<unsigned>(method)) != 0;
}

// The SSH result of one method, or a failure that ends the sign-in.
struct Step {
    int rc = SSH_AUTH_ERROR;
    Result failure;
    bool stopped() const { return !failure.ok(); }
    static Step of(int rc) { return Step { rc, Result() }; }
    static Step fail(const Result &r) { return Step { SSH_AUTH_ERROR, r }; }
};

} // namespace

class SftpBackend::Login
{
public:
    Login(SftpBackend &backend, const QByteArray &secret, AuthPrompter *prompter)
        : m_b(backend), m_secret(secret), m_prompter(prompter),
          m_mode(backend.m_params.option(QLatin1String(AuthModeOption), QLatin1String(AuthModePassword)))
    {
    }

    Result run();

private:
    Step first(int methods);
    Step afterPartial();
    Step password(int methods);
    Step publicKey(int methods);
    Step keyboardInteractive();
    Step promptedPassword();
    Step round();
    Result promptFailure(PromptOutcome outcome) const;
    PromptOutcome ask(const QString &name, const QString &instruction, const QVector<AuthPrompt> &prompts,
                      const std::function<bool(int, const QByteArray &)> &setAnswer);
    bool passwordMode() const { return m_mode == QLatin1String(AuthModePassword); }

    SftpBackend &m_b;
    const QByteArray &m_secret;
    AuthPrompter *m_prompter;
    const QString m_mode;
    bool m_secretUsed = false;          // S-11: the stored password answered a round
    bool m_triedInteractive = false;
};

Result SftpBackend::authenticate(const Credentials &credentials, AuthPrompter *prompter)
{
    if (!m_session || m_sftp)
        return Result(Error::Internal, QStringLiteral("authenticate() needs a fresh connection"));
    if (m_identityMismatch)
        return Result(Error::ServerIdentityChanged,
                      QStringLiteral("The server key does not match the saved key; not signing in"));
    if (m_canceled)
        return canceled();

    const QString mode = m_params.option(QLatin1String(AuthModeOption), QLatin1String(AuthModePassword));
    Result r = checkSecretForMode(mode, credentials.secret);
    if (!r.ok())
        return r;
    if (const QByteArray user = credentials.userName.toUtf8(); !user.isEmpty())
        ssh_options_set(m_session, SSH_OPTIONS_USER, user.constData());

    // S-10: learn the offered methods first.
    const int rc = ssh_userauth_none(m_session, nullptr);
    if (rc == SSH_AUTH_ERROR)
        return Requests(*this).sessionFailure();
    if (rc != SSH_AUTH_SUCCESS)
        r = Login(*this, credentials.secret, prompter).run();
    if (r.ok())
        r = Connection(*this).openSftp();
    if (r.ok() && !Requests(*this).setTimeout(m_params.requestTimeoutMs))
        r = Result(Error::Internal, QStringLiteral("Cannot set the timeout"));
    if (r.ok() && m_canceled)
        r = canceled();
    return r;
}

Result SftpBackend::Login::run()
{
    Step step = first(ssh_userauth_list(m_b.m_session, nullptr));
    for (int steps = 1; !step.stopped(); ++steps) {
        if (step.rc == SSH_AUTH_SUCCESS)
            return Result::success();
        const bool another = steps < MaxAuthSteps && m_prompter;
        if (step.rc == SSH_AUTH_PARTIAL && another) {
            step = afterPartial();   // XS-11
        } else if (step.rc == SSH_AUTH_PARTIAL) {
            return authPartial();    // S-13
        } else if (step.rc == SSH_AUTH_DENIED && another && !m_triedInteractive
                   && offers(ssh_userauth_list(m_b.m_session, nullptr), SSH_AUTH_METHOD_INTERACTIVE)) {
            step = keyboardInteractive();   // XS-11: after the configured method failed
        } else if (step.rc == SSH_AUTH_DENIED) {
            return authDenied(ssh_userauth_list(m_b.m_session, nullptr));   // S-14
        } else {
            return Requests(m_b).established(Requests(m_b).sessionFailure());
        }
    }
    return step.failure;
}

Step SftpBackend::Login::first(int methods)
{
    if (m_mode == QLatin1String(AuthModePublicKey))
        return publicKey(methods);
    if (passwordMode())
        return password(methods);
    // auth_mode=interactive: a stored password where the server takes one,
    // else keyboard-interactive, which needs a prompter (XC-15).
    if (!m_secret.isEmpty() && offers(methods, SSH_AUTH_METHOD_PASSWORD))
        return Step::of(ssh_userauth_password(m_b.m_session, nullptr, m_secret.constData()));
    if (!m_prompter)
        return Step::fail(interactiveNotSupported());
    if (!offers(methods, SSH_AUTH_METHOD_INTERACTIVE))
        return Step::fail(authDenied(methods));
    return keyboardInteractive();
}

Step SftpBackend::Login::afterPartial()
{
    const int methods = ssh_userauth_list(m_b.m_session, nullptr);
    if (offers(methods, SSH_AUTH_METHOD_INTERACTIVE))
        return keyboardInteractive();
    if (offers(methods, SSH_AUTH_METHOD_PASSWORD))
        return promptedPassword();
    return Step::fail(authPartial());
}

Step SftpBackend::Login::password(int methods)
{
    // S-11. QByteArray data is NUL terminated.
    if (offers(methods, SSH_AUTH_METHOD_PASSWORD))
        return Step::of(ssh_userauth_password(m_b.m_session, nullptr, m_secret.constData()));
    if (offers(methods, SSH_AUTH_METHOD_INTERACTIVE))
        return keyboardInteractive();
    return Step::of(SSH_AUTH_DENIED);
}

Step SftpBackend::Login::publicKey(int methods)
{
    // S-12: the key comes from memory only; never from ~/.ssh or an agent (S-3).
    if (!offers(methods, SSH_AUTH_METHOD_PUBLICKEY))
        return Step::of(SSH_AUTH_DENIED);
    QByteArray privateKey;
    decodeKeySecret(m_secret, &privateKey);
    KeyPtr key;
    const Result r = importPrivateKey(privateKey, QByteArray(), &key);
    secureWipe(privateKey);
    if (!r.ok())
        return Step::fail(Result(Error::AuthFailed, QStringLiteral("The stored SSH key cannot be used")));
    return Step::of(ssh_userauth_publickey(m_b.m_session, nullptr, key.get()));
}

Step SftpBackend::Login::keyboardInteractive()
{
    // S-11: rounds without prompts (OpenSSH sends one after PAM succeeds)
    // are acknowledged; XS-11: the others go to the prompter.
    m_triedInteractive = true;
    int rc = ssh_userauth_kbdint(m_b.m_session, nullptr, nullptr);
    for (int rounds = 0; rc == SSH_AUTH_INFO && rounds < MaxKeyboardInteractiveRounds; ++rounds) {
        if (const Step step = round(); step.stopped())
            return step;
        rc = ssh_userauth_kbdint(m_b.m_session, nullptr, nullptr);
    }
    if (rc == SSH_AUTH_INFO)
        return Step::fail(interactiveNotSupported());
    return Step::of(rc);
}

Step SftpBackend::Login::round()
{
    ssh_session session = m_b.m_session;
    const int count = ssh_userauth_kbdint_getnprompts(session);
    QVector<AuthPrompt> prompts;
    for (int i = 0; i < count; ++i) {
        char echo = 0;
        const char *prompt = ssh_userauth_kbdint_getprompt(session, static_cast<unsigned>(i), &echo);
        AuthPrompt entry;
        entry.text = text(prompt);
        entry.echo = echo != 0;
        prompts.append(entry);
    }
    const bool secretUsable = passwordMode() && !m_secretUsed;
    const bool first = count > 0;
    switch (keyboardInteractiveAction(count, first && prompts.first().echo, first && isPasswordPrompt(prompts.first().text),
                                      secretUsable, m_prompter != nullptr)) {
    case RoundAction::Acknowledge:
        return Step();
    case RoundAction::AnswerWithSecret:
        m_secretUsed = true;
        if (ssh_userauth_kbdint_setanswer(session, 0, m_secret.constData()) < 0)
            return Step::fail(Requests(m_b).sessionFailure());
        return Step();
    case RoundAction::AskPrompter:
        break;
    case RoundAction::Refuse:
        return Step::fail(interactiveNotSupported());
    }
    const PromptOutcome outcome = ask(text(ssh_userauth_kbdint_getname(session)),
                                      text(ssh_userauth_kbdint_getinstruction(session)), prompts,
                                      [session](int index, const QByteArray &answer) {
                                          return ssh_userauth_kbdint_setanswer(session, static_cast<unsigned>(index),
                                                                               answer.constData()) >= 0;
                                      });
    if (outcome != PromptOutcome::Answered)
        return Step::fail(promptFailure(outcome));
    return Step();
}

Step SftpBackend::Login::promptedPassword()
{
    AuthPrompt prompt;
    prompt.text = QStringLiteral("Password: ");
    QByteArray password;
    const PromptOutcome outcome = ask(QString(), QString(), { prompt }, [&password](int, const QByteArray &answer) {
        password = answer;
        password.detach();
        return true;
    });
    Step step = outcome == PromptOutcome::Answered
        ? Step::of(ssh_userauth_password(m_b.m_session, nullptr, password.constData()))
        : Step::fail(promptFailure(outcome));
    secureWipe(password);
    return step;
}

PromptOutcome SftpBackend::Login::ask(const QString &name, const QString &instruction,
                                      const QVector<AuthPrompt> &prompts,
                                      const std::function<bool(int, const QByteArray &)> &setAnswer)
{
    // XC-22: cancel() reaches the prompter while it waits.
    Connection(m_b).setPrompter(m_prompter);
    QVector<QByteArray> answers;
    const PromptOutcome outcome = m_b.m_canceled
        ? PromptOutcome::Declined
        : promptRound(m_prompter, name, instruction, prompts, &answers, setAnswer);
    Connection(m_b).setPrompter(nullptr);
    return outcome;
}

Result SftpBackend::Login::promptFailure(PromptOutcome outcome) const
{
    if (m_b.m_canceled)
        return canceled();
    if (outcome == PromptOutcome::Rejected)
        return Requests(m_b).established(Requests(m_b).sessionFailure());
    return interactiveDeclined();
}

} // namespace NetVfs::Sftp
