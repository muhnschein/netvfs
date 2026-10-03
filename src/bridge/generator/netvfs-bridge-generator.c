/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * netvfs-bridge-generator: systemd user generator (SPEC-v2 XB-3, XB-4).
 *
 *   /usr/lib/systemd/user-generators/netvfs-bridge-generator NORMAL [EARLY LATE]
 *
 * For every consumer registered in /usr/share/netvfs/consumers/<id>.conf
 * (NETVFS_CONSUMERS_DIR overrides the folder, for tests) it writes into NORMAL:
 *
 *   netvfs-bridge@<id>.socket             ListenStream=%h/<DataDir>/netvfs/bridge.sock,
 *                                         SocketMode=0600, DirectoryMode=0700, Accept=no
 *   netvfs-bridge@<id>.service            ExecStart=/usr/libexec/netvfs/netvfs-bridge <id>
 *   netvfs-bridge@<id>.path               PathChanged=%h/<DataDir>: the consumer's folder
 *                                         appeared or disappeared (data cleared, app
 *                                         reinstalled), or changed
 *   netvfs-bridge-rendezvous@<id>.service started by the .path unit: restarts the socket
 *                                         unit when the socket file is missing or the
 *                                         unit is not active, and does nothing otherwise
 *   sockets.target.wants/, paths.target.wants/ links that enable the socket and path units
 *
 * Generators run early and must never fail the boot of the user manager: an
 * invalid consumer file is skipped with a message on stderr, and the exit
 * status is 0 unless the output folder itself is unusable.
 *
 * Validation (the same rules as NetVfs::ConsumerInfo in libnetvfs):
 *   Id          [a-z0-9-]{1,64}, equal to the file name without ".conf"
 *   DisplayName non-empty, no control characters
 *   Executable  absolute; characters [A-Za-z0-9._/+-]; no empty, "." or ".." component
 *   DataDir     relative to $HOME; same characters; no empty, "." or ".." component
 */
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONSUMERS_DIR "/usr/share/netvfs/consumers"
#define BRIDGE_BINARY "/usr/libexec/netvfs/netvfs-bridge"
#define MAX_ID 64
#define MAX_VALUE 1024
#define MAX_LINE 2048
#define MAX_PATH_LENGTH 4096
#define MAX_FILE_BYTES 16384
#define MAX_CONSUMERS 256

struct consumer {
    char id[MAX_ID + 1];
    char display_name[MAX_VALUE + 1];
    char executable[MAX_VALUE + 1];
    char data_dir[MAX_VALUE + 1];
};

static int is_id_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
}

static int is_path_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '.'
        || c == '_' || c == '-' || c == '+';
}

int netvfs_valid_id(const char *id)
{
    size_t n = strlen(id);
    if (n == 0 || n > MAX_ID)
        return 0;
    for (size_t i = 0; i < n; ++i) {
        if (!is_id_char(id[i]))
            return 0;
    }
    return 1;
}

/* No empty, "." or ".." component in a '/'-separated path (without a leading '/'). */
static int clean_components(const char *path)
{
    const char *p = path;
    for (;;) {
        const char *slash = strchr(p, '/');
        size_t n = slash ? (size_t)(slash - p) : strlen(p);
        if (n == 0 || (n == 1 && p[0] == '.') || (n == 2 && p[0] == '.' && p[1] == '.'))
            return 0;
        if (!slash)
            return 1;
        p = slash + 1;
    }
}

static int only_path_chars(const char *path)
{
    for (const char *p = path; *p; ++p) {
        if (!is_path_char(*p))
            return 0;
    }
    return 1;
}

int netvfs_valid_data_dir(const char *dir)
{
    size_t n = strlen(dir);
    return n > 0 && n <= MAX_VALUE && dir[0] != '/' && only_path_chars(dir) && clean_components(dir);
}

int netvfs_valid_executable(const char *path)
{
    size_t n = strlen(path);
    return n > 1 && n <= MAX_VALUE && path[0] == '/' && only_path_chars(path) && clean_components(path + 1);
}

static int valid_display_name(const char *name)
{
    if (name[0] == '\0')
        return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    }
    return 1;
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        ++s;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = '\0';
    return s;
}

static int copy_value(char *dst, size_t size, const char *value)
{
    size_t n = strlen(value);
    if (n >= size)
        return 0;
    memcpy(dst, value, n + 1);
    return 1;
}

static int assign(struct consumer *c, const char *key, const char *value)
{
    if (strcmp(key, "Id") == 0)
        return copy_value(c->id, sizeof(c->id), value);
    if (strcmp(key, "DisplayName") == 0)
        return copy_value(c->display_name, sizeof(c->display_name), value);
    if (strcmp(key, "Executable") == 0)
        return copy_value(c->executable, sizeof(c->executable), value);
    if (strcmp(key, "DataDir") == 0)
        return copy_value(c->data_dir, sizeof(c->data_dir), value);
    return 1; /* unknown keys are ignored */
}

/* Reads the [Consumer] group of `path`. Returns 0 on success, else a message. */
static const char *parse_consumer(const char *path, struct consumer *c)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return "cannot be read";
    *c = (struct consumer){ 0 };
    char line[MAX_LINE];
    int in_group = 0;
    long total = 0;
    const char *error = NULL;
    while (!error && fgets(line, sizeof(line), f)) {
        total += (long)strlen(line);
        if (total > MAX_FILE_BYTES) {
            error = "is too large";
            break;
        }
        char *s = trim(line);
        if (*s == '\0' || *s == '#' || *s == ';')
            continue;
        if (*s == '[') {
            in_group = strcmp(s, "[Consumer]") == 0;
            continue;
        }
        char *eq = strchr(s, '=');
        if (!in_group || !eq || eq == s)
            continue;
        *eq = '\0';
        if (!assign(c, trim(s), trim(eq + 1)))
            error = "has a value that is too long";
    }
    fclose(f);
    return error;
}

static const char *validate(const struct consumer *c, const char *stem)
{
    if (strcmp(c->id, stem) != 0)
        return "Id must match [a-z0-9-]+ and the file name";
    if (!valid_display_name(c->display_name))
        return "DisplayName is empty or has control characters";
    if (!netvfs_valid_executable(c->executable))
        return "Executable must be an absolute path";
    if (!netvfs_valid_data_dir(c->data_dir))
        return "DataDir must be relative to the home folder, without \"..\"";
    return NULL;
}

static int write_file(const char *dir, const char *name, const char *content)
{
    char path[MAX_PATH_LENGTH];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path))
        return -1;
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    int ok = fputs(content, f) >= 0;
    ok = (fclose(f) == 0) && ok;
    return ok ? 0 : -1;
}

static int link_unit(const char *dir, const char *target, const char *unit)
{
    char wants[MAX_PATH_LENGTH];
    char link[MAX_PATH_LENGTH];
    char destination[MAX_PATH_LENGTH];
    if (snprintf(wants, sizeof(wants), "%s/%s.wants", dir, target) >= (int)sizeof(wants)
            || snprintf(link, sizeof(link), "%s/%s", wants, unit) >= (int)sizeof(link)
            || snprintf(destination, sizeof(destination), "../%s", unit) >= (int)sizeof(destination))
        return -1;
    if (mkdir(wants, 0700) != 0 && errno != EEXIST)
        return -1;
    (void)unlink(link);
    return symlink(destination, link);
}

/* Description= expands specifiers: a literal '%' is written as "%%". */
static void escape_specifiers(const char *in, char *out, size_t size)
{
    size_t n = 0;
    const char *p = in;
    while (*p && n + 2 < size) {
        if (*p == '%')
            out[n++] = '%';
        out[n++] = *p++;
    }
    out[n] = '\0';
}

static int emit(const char *dir, const struct consumer *c, const char *source)
{
    char name[MAX_PATH_LENGTH];
    char text[4 * MAX_PATH_LENGTH];
    char display[2 * MAX_VALUE + 1];
    const char *id = c->id;
    int rc = 0;

    escape_specifiers(c->display_name, display, sizeof(display));

    snprintf(text, sizeof(text),
             "# Generated by netvfs-bridge-generator from %s (SPEC-v2 XB-3, XB-4)\n"
             "[Unit]\n"
             "Description=netvfs bridge rendezvous for %s\n"
             "ConditionPathIsDirectory=%%h/%s\n"
             "\n"
             "[Socket]\n"
             "ListenStream=%%h/%s/netvfs/bridge.sock\n"
             "SocketMode=0600\n"
             "DirectoryMode=0700\n"
             "Accept=no\n"
             "RemoveOnStop=yes\n",
             source, display, c->data_dir, c->data_dir);
    snprintf(name, sizeof(name), "netvfs-bridge@%s.socket", id);
    rc |= write_file(dir, name, text);
    rc |= link_unit(dir, "sockets.target", name);

    snprintf(text, sizeof(text),
             "# Generated by netvfs-bridge-generator from %s (SPEC-v2 XB-2)\n"
             "[Unit]\n"
             "Description=netvfs bridge for %s\n"
             "Requires=netvfs-bridge@%s.socket\n"
             "After=netvfs-bridge@%s.socket\n"
             "PartOf=netvfs-bridge@%s.socket\n"
             "\n"
             "[Service]\n"
             "Type=simple\n"
             "ExecStart=" BRIDGE_BINARY " %s\n"
             "NoNewPrivileges=yes\n",
             source, display, id, id, id, id);
    snprintf(name, sizeof(name), "netvfs-bridge@%s.service", id);
    rc |= write_file(dir, name, text);

    snprintf(text, sizeof(text),
             "# Generated by netvfs-bridge-generator from %s (SPEC-v2 XB-4)\n"
             "[Unit]\n"
             "Description=netvfs bridge folder watch for %s\n"
             "\n"
             "[Path]\n"
             "PathChanged=%%h/%s\n"
             "Unit=netvfs-bridge-rendezvous@%s.service\n",
             source, display, c->data_dir, id);
    snprintf(name, sizeof(name), "netvfs-bridge@%s.path", id);
    rc |= write_file(dir, name, text);
    rc |= link_unit(dir, "paths.target", name);

    /* $$ is a literal $ for systemd; the script gets the socket path as $0
     * and the socket unit as $1. */
    snprintf(text, sizeof(text),
             "# Generated by netvfs-bridge-generator from %s (SPEC-v2 XB-4)\n"
             "[Unit]\n"
             "Description=netvfs bridge rendezvous check for %s\n"
             "\n"
             "[Service]\n"
             "Type=oneshot\n"
             "ExecStart=/bin/sh -c 'test -S \"$$0\" && systemctl --user -q is-active \"$$1\" "
             "|| exec systemctl --user restart \"$$1\"' %%h/%s/netvfs/bridge.sock netvfs-bridge@%s.socket\n",
             source, display, c->data_dir, id);
    snprintf(name, sizeof(name), "netvfs-bridge-rendezvous@%s.service", id);
    rc |= write_file(dir, name, text);
    return rc;
}

/* "<stem>.conf": copies the stem. */
static int has_conf_suffix(const char *name, char *stem, size_t size)
{
    size_t n = strlen(name);
    if (n <= 5 || strcmp(name + n - 5, ".conf") != 0 || n - 5 >= size)
        return 0;
    memcpy(stem, name, n - 5);
    stem[n - 5] = '\0';
    return 1;
}

static int compare_ids(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* No control characters, no ".." component. */
static int clean_folder(const char *path)
{
    for (const unsigned char *p = (const unsigned char *)path; *p; ++p) {
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    }
    for (const char *p = strstr(path, ".."); p; p = strstr(p + 1, "..")) {
        const int starts = p == path || p[-1] == '/';
        const int ends = p[2] == '\0' || p[2] == '/';
        if (starts && ends)
            return 0;
    }
    return 1;
}

/* The folder with the consumer files: NETVFS_CONSUMERS_DIR (for tests) when it is an absolute path of
 * a plausible length without control characters or ".." components. */
static const char *consumers_dir(void)
{
    const char *overridden = getenv("NETVFS_CONSUMERS_DIR");
    if (overridden && overridden[0] == '/' && strlen(overridden) <= MAX_PATH_LENGTH / 2 && clean_folder(overridden))
        return overridden;
    return CONSUMERS_DIR;
}

/* A file name for a message: only [A-Za-z0-9._-] are copied, anything else as \xNN, so a name
 * can neither forge a log line nor carry control characters. */
static void escaped(const char *in, char *out, size_t size)
{
    static const char hex[] = "0123456789abcdef";
    size_t n = 0;
    const unsigned char *p = (const unsigned char *)in;
    while (*p && n + 4 < size) {
        if (is_id_char((char)*p) || (*p >= 'A' && *p <= 'Z') || *p == '.' || *p == '_') {
            out[n++] = (char)*p;
        } else {
            out[n++] = '\\';
            out[n++] = 'x';
            out[n++] = hex[*p >> 4];
            out[n++] = hex[*p & 15];
        }
        ++p;
    }
    out[n] = '\0';
}

/* The consumer file of a validated id below the canonical `base`: the canonical path of
 * "<base>/<id>.conf", which must still be inside `base` (no symbolic link leads out). */
static int resolve_inside(const char *base, const char *id, char *resolved)
{
    char path[MAX_PATH_LENGTH];
    if (!netvfs_valid_id(id) || snprintf(path, sizeof(path), "%s/%s.conf", base, id) >= (int)sizeof(path))
        return 0;
    if (!realpath(path, resolved))
        return 0;
    size_t n = strlen(base);
    return strncmp(resolved, base, n) == 0 && resolved[n] == '/';
}

static void report(const char *name, const char *problem)
{
    char shown[MAX_PATH_LENGTH];
    escaped(name, shown, sizeof(shown));
    fprintf(stderr, "netvfs-bridge-generator: skipping %s: %s\n", shown, problem);
}

/* Reads the ids of the "<id>.conf" files of `dir`; other names are reported and skipped. */
static size_t collect_ids(DIR *dir, char ids[][MAX_ID + 2], size_t capacity)
{
    size_t count = 0;
    const struct dirent *entry;
    while (count < capacity && (entry = readdir(dir)) != NULL) {
        char stem[MAX_ID + 2];
        if (entry->d_name[0] == '.' || !has_conf_suffix(entry->d_name, stem, sizeof(stem)))
            continue;
        if (netvfs_valid_id(stem))
            memcpy(ids[count++], stem, sizeof(stem));
        else
            report(entry->d_name, "Id must match [a-z0-9-]+ and the file name");
    }
    return count;
}

/* One consumer: read, validate, emit. Returns 0 unless the output folder is unusable. */
static int generate_one(const char *out, const char *base, const char *dir_name, const char *id)
{
    char resolved[MAX_PATH_LENGTH];
    char name[MAX_ID + 8];
    char source[MAX_PATH_LENGTH];
    struct consumer c;
    snprintf(name, sizeof(name), "%.*s.conf", MAX_ID + 1, id);
    const char *problem = NULL;
    if (!resolve_inside(base, id, resolved))
        problem = "is not a file of the consumers folder";
    else
        problem = parse_consumer(resolved, &c);
    if (!problem)
        problem = validate(&c, id);
    if (problem) {
        report(name, problem);
        return 0;
    }
    if (snprintf(source, sizeof(source), "%s/%s", dir_name, name) >= (int)sizeof(source))
        return 0;
    return emit(out, &c, source) != 0;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argv[1][0] == '\0') {
        fprintf(stderr, "netvfs-bridge-generator: usage: %s NORMAL-DIR [EARLY-DIR LATE-DIR]\n", argv[0]);
        return 1;
    }
    const char *out = argv[1];
    const char *dir_name = consumers_dir();
    char base[MAX_PATH_LENGTH];
    if (!realpath(dir_name, base))
        return 0; /* nothing registered */
    DIR *dir = opendir(base);
    if (!dir)
        return 0;

    char ids[MAX_CONSUMERS][MAX_ID + 2];
    const size_t count = collect_ids(dir, ids, MAX_CONSUMERS);
    closedir(dir);
    qsort(ids, count, sizeof(ids[0]), compare_ids);

    int status = 0;
    for (size_t i = 0; i < count; ++i) {
        if (generate_one(out, base, dir_name, ids[i]))
            status = 1;
    }
    return status;
}
