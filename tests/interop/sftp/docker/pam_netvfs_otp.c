/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * One-time password stub for the SFTP interop suite (SPEC-v2 XT-2, XS-11).
 * Asks "Verification code: " (no echo) through the PAM conversation, which
 * OpenSSH turns into a keyboard-interactive round, and accepts one fixed
 * code. Never install this anywhere but a test container.
 *
 * Arguments:
 *   code=VALUE    the code that is accepted (required)
 *   wrong=ignore  a wrong answer is PAM_IGNORE instead of PAM_AUTH_ERR, so
 *                 that a following module decides (used where the password
 *                 method runs the same stack, see start-sshd.sh)
 *   first=echo    ask "Token label: " with echo first (answer ignored), so
 *                 the client sees a round with an echoed prompt
 */
#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <stdlib.h>
#include <string.h>

static int ask(pam_handle_t *pamh, int style, const char *text, char **answer)
{
    const struct pam_conv *conv = NULL;
    struct pam_message message;
    const struct pam_message *messages[1];
    struct pam_response *response = NULL;
    int rc = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (rc != PAM_SUCCESS || conv == NULL || conv->conv == NULL)
        return PAM_CONV_ERR;
    message.msg_style = style;
    message.msg = text;
    messages[0] = &message;
    rc = conv->conv(1, messages, &response, conv->appdata_ptr);
    if (rc != PAM_SUCCESS || response == NULL || response[0].resp == NULL) {
        free(response);
        return PAM_CONV_ERR;
    }
    *answer = response[0].resp;
    free(response);
    return PAM_SUCCESS;
}

static void discard(char *answer)
{
    if (answer != NULL) {
        memset(answer, 0, strlen(answer));
        free(answer);
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *code = NULL;
    int ignoreWrong = 0;
    int echoFirst = 0;
    char *answer = NULL;
    int rc;
    int i;
    (void)flags;
    for (i = 0; i < argc; ++i) {
        if (strncmp(argv[i], "code=", 5) == 0)
            code = argv[i] + 5;
        else if (strcmp(argv[i], "wrong=ignore") == 0)
            ignoreWrong = 1;
        else if (strcmp(argv[i], "first=echo") == 0)
            echoFirst = 1;
    }
    if (code == NULL || *code == '\0')
        return PAM_AUTH_ERR;
    if (echoFirst) {
        rc = ask(pamh, PAM_PROMPT_ECHO_ON, "Token label: ", &answer);
        discard(answer);
        answer = NULL;
        if (rc != PAM_SUCCESS)
            return PAM_AUTH_ERR;
    }
    rc = ask(pamh, PAM_PROMPT_ECHO_OFF, "Verification code: ", &answer);
    if (rc != PAM_SUCCESS)
        return ignoreWrong ? PAM_IGNORE : PAM_AUTH_ERR;
    rc = strcmp(answer, code) == 0 ? PAM_SUCCESS : (ignoreWrong ? PAM_IGNORE : PAM_AUTH_ERR);
    discard(answer);
    return rc;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
