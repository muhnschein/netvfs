// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sandbox.h"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

// The kernel numbers of syscalls newer than the target's headers. Syscalls
// added since Linux 5.1 have one number on every architecture.
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef SYS_openat2
#define SYS_openat2 437
#endif
#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

#if defined(__SANITIZE_ADDRESS__)
#define NETVFS_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define NETVFS_ASAN 1
#endif
#endif

namespace NetVfs::Bridge {

namespace {

// <linux/landlock.h> as of ABI 7; the target's headers predate it.
namespace Landlock {
struct RulesetAttr {
    std::uint64_t handledAccessFs;
    std::uint64_t handledAccessNet;   // ABI 4
    std::uint64_t scoped;             // ABI 6
};
struct PathBeneathAttr {
    std::uint64_t allowedAccess;
    std::int32_t parentFd;
} __attribute__((packed));

constexpr std::uint32_t CreateRulesetVersion = 1U << 0;
constexpr int RulePathBeneath = 1;

constexpr std::uint64_t Execute = 1ULL << 0;
constexpr std::uint64_t WriteFile = 1ULL << 1;
constexpr std::uint64_t ReadFile = 1ULL << 2;
constexpr std::uint64_t ReadDir = 1ULL << 3;
constexpr std::uint64_t RemoveDir = 1ULL << 4;
constexpr std::uint64_t RemoveFile = 1ULL << 5;
constexpr std::uint64_t MakeChar = 1ULL << 6;
constexpr std::uint64_t MakeDir = 1ULL << 7;
constexpr std::uint64_t MakeReg = 1ULL << 8;
constexpr std::uint64_t MakeSock = 1ULL << 9;
constexpr std::uint64_t MakeFifo = 1ULL << 10;
constexpr std::uint64_t MakeBlock = 1ULL << 11;
constexpr std::uint64_t MakeSym = 1ULL << 12;
constexpr std::uint64_t Refer = 1ULL << 13;      // ABI 2
constexpr std::uint64_t Truncate = 1ULL << 14;   // ABI 3
constexpr std::uint64_t IoctlDev = 1ULL << 15;   // ABI 5

constexpr std::uint64_t NetBindTcp = 1ULL << 0;      // ABI 4
constexpr std::uint64_t NetConnectTcp = 1ULL << 1;   // ABI 4

constexpr std::uint64_t ScopeAbstractUnixSocket = 1ULL << 0;   // ABI 6
constexpr std::uint64_t ScopeSignal = 1ULL << 1;               // ABI 6

constexpr std::uint64_t Abi1Fs = Execute | WriteFile | ReadFile | ReadDir | RemoveDir | RemoveFile | MakeChar
    | MakeDir | MakeReg | MakeSock | MakeFifo | MakeBlock | MakeSym;
// What a rule on a file (not a folder) may allow.
constexpr std::uint64_t FileRights = Execute | WriteFile | ReadFile | Truncate | IoctlDev;

constexpr std::uint64_t ReadOnly = ReadFile | ReadDir;
// The database folder: SQLite creates, truncates and removes its -wal and
// -shm files there; libaccounts creates its folder when missing.
constexpr std::uint64_t ReadWrite = ReadFile | ReadDir | WriteFile | Truncate | MakeReg | RemoveFile | MakeDir;
} // namespace Landlock

const char RuntimeRoot[] = "/run/user";

void warn(const char *what)
{
    std::fprintf(stderr, "netvfs-accounts: %s: %s\n", what, std::strerror(errno));
}

QByteArray environmentOr(const char *name, const QByteArray &fallback)
{
    const QByteArray value = qgetenv(name);
    return value.startsWith('/') ? value : fallback;
}

void closeFrom(int lowest)
{
    if (::syscall(SYS_close_range, static_cast<unsigned>(lowest), ~0U, 0U) == 0)
        return;
    // Before Linux 5.9: whatever /proc lists, else every possible number.
    std::vector<int> open;
    if (DIR *dir = ::opendir("/proc/self/fd")) {
        while (const struct dirent *entry = ::readdir(dir)) {
            const int fd = std::atoi(entry->d_name);
            if (fd >= lowest && fd != ::dirfd(dir))
                open.push_back(fd);
        }
        ::closedir(dir);
    } else {
        const long max = std::min(::sysconf(_SC_OPEN_MAX), 65536L);
        for (int fd = lowest; fd < max; ++fd)
            open.push_back(fd);
    }
    for (const int fd : open)
        ::close(fd);
}

// One Landlock rule below `path`, for what of `access` the ruleset handles.
// A missing path needs no rule.
void allowBeneath(int ruleset, std::uint64_t handled, const QByteArray &path, std::uint64_t access)
{
    const int fd = ::open(path.constData(), O_PATH | O_CLOEXEC);
    if (fd < 0)
        return;
    struct stat st {};
    if (::fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode))
        access &= Landlock::FileRights;
    Landlock::PathBeneathAttr rule { access & handled, fd };
    if (rule.allowedAccess != 0
            && ::syscall(SYS_landlock_add_rule, ruleset, Landlock::RulePathBeneath, &rule, 0U) != 0)
        std::fprintf(stderr, "netvfs-accounts: Landlock rule for %s: %s\n", path.constData(), std::strerror(errno));
    ::close(fd);
}

// seccomp-bpf, assembled.
class Filter
{
public:
    static constexpr std::uint32_t Allow = SECCOMP_RET_ALLOW;
    static constexpr std::uint32_t Deny = SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA);
    static constexpr std::uint32_t NoSys = SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA);

    void loadNumber() { stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)); }
    void loadArch() { stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)); }
    // The low 32 bits of an argument (all targets are little-endian).
    void loadArgument(int i)
    {
        stmt(BPF_LD | BPF_W | BPF_ABS, static_cast<std::uint32_t>(offsetof(struct seccomp_data, args) + 8 * i));
    }
    void ret(std::uint32_t action) { stmt(BPF_RET | BPF_K, action); }

    // With the number loaded: `action` for syscall `nr`.
    void on(long nr, std::uint32_t action)
    {
        jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(nr), 0, 1);
        ret(action);
    }
    // With the number loaded: EPERM for `nr` when argument `i` has any of
    // `bits`; the number is loaded again afterwards.
    void denyArgumentBits(long nr, int i, std::uint32_t bits)
    {
        jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(nr), 0, 4);
        loadArgument(i);
        jump(BPF_JMP | BPF_JSET | BPF_K, bits, 0, 1);
        ret(Deny);
        loadNumber();
    }
    // With the number loaded: EPERM for `nr` when it creates a file (flags in
    // argument `flags`) whose mode (argument `mode`) has any of `bits`. Without
    // O_CREAT or O_TMPFILE the mode is unused and may be garbage: sanitizers
    // call openat without one.
    void denyCreatedModeBits(long nr, int flags, int mode, std::uint32_t bits)
    {
        jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(nr), 0, 6);
        loadArgument(flags);
        jump(BPF_JMP | BPF_JSET | BPF_K, O_CREAT | (O_TMPFILE & ~O_DIRECTORY), 0, 3);
        loadArgument(mode);
        jump(BPF_JMP | BPF_JSET | BPF_K, bits, 0, 1);
        ret(Deny);
        loadNumber();
    }
    // With the number loaded: EPERM for `nr` unless argument `i` is `value`.
    void denyArgumentOtherThan(long nr, int i, std::uint32_t value)
    {
        jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(nr), 0, 4);
        loadArgument(i);
        jump(BPF_JMP | BPF_JEQ | BPF_K, value, 1, 0);
        ret(Deny);
        loadNumber();
    }
    void jump(std::uint16_t code, std::uint32_t k, std::uint8_t jt, std::uint8_t jf)
    {
        m_program.push_back(sock_filter { code, jt, jf, k });
    }

    bool install()
    {
        const sock_fprog program { static_cast<unsigned short>(m_program.size()), m_program.data() };
        return ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0, 0) == 0;
    }

private:
    void stmt(std::uint16_t code, std::uint32_t k) { m_program.push_back(sock_filter { code, 0, 0, k }); }

    std::vector<sock_filter> m_program;
};

#if defined(__x86_64__)
constexpr std::uint32_t NativeArch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
constexpr std::uint32_t NativeArch = AUDIT_ARCH_AARCH64;
#elif defined(__arm__) && !defined(__ARMEB__)
constexpr std::uint32_t NativeArch = AUDIT_ARCH_ARM;
#else
#define NETVFS_NO_SECCOMP 1
#endif

// Syscalls the helper never needs and that would widen what code run inside
// it could do with the group.
const long DeniedSyscalls[] = {
    SYS_execve, SYS_execveat,
#ifndef NETVFS_ASAN
    SYS_ptrace,
#endif
    SYS_process_vm_readv, SYS_process_vm_writev,
    SYS_unshare, SYS_setns, SYS_mount, SYS_umount2, SYS_pivot_root, SYS_chroot,
#ifdef SYS_open_tree
    SYS_open_tree, SYS_move_mount, SYS_fsopen, SYS_fsconfig, SYS_fsmount, SYS_fspick,
#endif
#ifdef SYS_mount_setattr
    SYS_mount_setattr,
#endif
    SYS_init_module, SYS_finit_module, SYS_delete_module, SYS_kexec_load,
#ifdef SYS_kexec_file_load
    SYS_kexec_file_load,
#endif
    SYS_bpf, SYS_userfaultfd, SYS_perf_event_open,
#ifdef SYS_io_uring_setup
    SYS_io_uring_setup, SYS_io_uring_enter, SYS_io_uring_register,
#endif
    SYS_keyctl, SYS_add_key, SYS_request_key,
    SYS_name_to_handle_at, SYS_open_by_handle_at,
    SYS_fanotify_init, SYS_swapon, SYS_swapoff, SYS_reboot, SYS_acct, SYS_quotactl, SYS_syslog,
#ifdef SYS_socketcall
    SYS_socketcall,
#endif
#ifdef SYS_uselib
    SYS_uselib,
#endif
#ifdef SYS_iopl
    SYS_iopl, SYS_ioperm,
#endif
#ifdef SYS_modify_ldt
    SYS_modify_ldt,
#endif
};

constexpr std::uint32_t NewNamespaces = CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC
    | CLONE_NEWUTS | CLONE_NEWCGROUP;
constexpr std::uint32_t SetIdBits = S_ISUID | S_ISGID;

} // namespace

bool sanitizeDescriptors()
{
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; ++fd) {
        if (::fcntl(fd, F_GETFD) != -1 || errno != EBADF)
            continue;
        // The lowest free number, which is `fd`.
        const int opened = ::open("/dev/null", fd == STDIN_FILENO ? O_RDONLY : O_WRONLY);
        if (opened != fd) {
            if (opened >= 0)
                ::close(opened);
            return false;
        }
    }
    closeFrom(STDERR_FILENO + 1);
    return true;
}

void resetProcessState()
{
    ::umask(077);
    // A caller's handlers do not survive exec, but ignored signals and the
    // mask do.
    for (int sig = 1; sig < NSIG; ++sig) {
        if (sig != SIGKILL && sig != SIGSTOP)
            ::signal(sig, SIG_DFL);   // EINVAL for glibc's own signals
    }
    sigset_t none;
    sigemptyset(&none);
    ::sigprocmask(SIG_SETMASK, &none, nullptr);
    if (struct rlimit size {}; ::getrlimit(RLIMIT_FSIZE, &size) == 0 && size.rlim_cur != size.rlim_max) {
        size.rlim_cur = size.rlim_max;
        ::setrlimit(RLIMIT_FSIZE, &size);
    }
}

QList<QByteArray> accountsDirectories()
{
    if (const QByteArray accounts = qgetenv("ACCOUNTS"); accounts.startsWith('/'))
        return { accounts };
    const QByteArray home = qgetenv("HOME");
    return { environmentOr("XDG_DATA_HOME", home + "/.local/share") + "/system/privileged/Accounts",
             environmentOr("XDG_CONFIG_HOME", home + "/.config") + "/libaccounts-glib" };
}

FilesystemRestriction restrictFilesystem(const QList<QByteArray> &writable, bool allowAbstractSockets)
{
    FilesystemRestriction result;
    const long abi = ::syscall(SYS_landlock_create_ruleset, nullptr, 0, Landlock::CreateRulesetVersion);
    if (abi <= 0)
        return result;   // ENOSYS: not built; EOPNOTSUPP: not enabled at boot
    result.abi = int(abi);
    const int used = std::min(result.abi, LandlockNewestAbi);

    Landlock::RulesetAttr attr { Landlock::Abi1Fs, 0, 0 };
    if (used >= 2)
        attr.handledAccessFs |= Landlock::Refer;
    if (used >= 3)
        attr.handledAccessFs |= Landlock::Truncate;
    if (used >= 4)
        attr.handledAccessNet = Landlock::NetBindTcp | Landlock::NetConnectTcp;
    if (used >= 5)
        attr.handledAccessFs |= Landlock::IoctlDev;
    if (used >= 6)
        attr.scoped = Landlock::ScopeSignal | (allowAbstractSockets ? 0 : Landlock::ScopeAbstractUnixSocket);
    // ABI 7 logs denials to the audit log by default, which is what we want.

    // An older kernel takes the larger struct as long as its unknown fields
    // are zero.
    const int ruleset = int(::syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0U));
    if (ruleset < 0) {
        warn("Landlock ruleset");
        return result;
    }
    const std::uint64_t handled = attr.handledAccessFs;
    for (const char *system : { "/usr", "/etc", "/lib", "/lib64", "/proc", "/dev/urandom", "/dev/random" })
        allowBeneath(ruleset, handled, system, Landlock::ReadOnly);
    allowBeneath(ruleset, handled, "/dev/null", Landlock::ReadFile | Landlock::WriteFile);
    // The uid's own runtime folder, never XDG_RUNTIME_DIR: the caller sets that.
    allowBeneath(ruleset, handled, QByteArray(RuntimeRoot) + '/' + QByteArray::number(::getuid()), Landlock::ReadOnly);
    // Providers and services: the user's own, and those a test names.
    const QByteArray dataHome = environmentOr("XDG_DATA_HOME", qgetenv("HOME") + "/.local/share");
    allowBeneath(ruleset, handled, dataHome + "/accounts", Landlock::ReadOnly);
    for (const char *variable : { "AG_PROVIDERS", "AG_SERVICES", "AG_SERVICE_TYPES", "AG_APPLICATIONS" }) {
        if (const QByteArray dir = qgetenv(variable); dir.startsWith('/'))
            allowBeneath(ruleset, handled, dir, Landlock::ReadOnly);
    }
    for (const QByteArray &dir : writable)
        allowBeneath(ruleset, handled, dir, Landlock::ReadWrite);
#ifdef NETVFS_SANITIZER_DIR
    allowBeneath(ruleset, handled, NETVFS_SANITIZER_DIR, Landlock::ReadOnly);
#endif
#ifdef NETVFS_COVERAGE_DIR
    // gcov's counters, written at exit next to the objects.
    allowBeneath(ruleset, handled, NETVFS_COVERAGE_DIR, Landlock::ReadWrite);
#endif

    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        warn("no_new_privs");
    else if (::syscall(SYS_landlock_restrict_self, ruleset, 0U) != 0)
        warn("Landlock");
    else
        result.enforced = true;
    ::close(ruleset);
    return result;
}

bool restrictSyscalls()
{
#ifdef NETVFS_NO_SECCOMP
    return false;
#else
    Filter filter;
    filter.loadArch();
    filter.jump(BPF_JMP | BPF_JEQ | BPF_K, NativeArch, 1, 0);
    filter.ret(Filter::Deny);   // another ABI's numbers would mean other syscalls
    filter.loadNumber();
#if defined(__x86_64__)
    filter.jump(BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1);   // x32
    filter.ret(Filter::Deny);
#endif
    for (const long nr : DeniedSyscalls)
        filter.on(nr, Filter::Deny);
    // Arguments behind a pointer are out of the filter's sight.
    filter.on(SYS_clone3, Filter::NoSys);
    filter.on(SYS_openat2, Filter::NoSys);
    filter.denyArgumentBits(SYS_clone, 0, NewNamespaces);
    filter.denyArgumentOtherThan(SYS_socket, 0, AF_UNIX);
    filter.denyArgumentOtherThan(SYS_socketpair, 0, AF_UNIX);
    filter.denyArgumentBits(SYS_fchmod, 1, SetIdBits);
    filter.denyArgumentBits(SYS_fchmodat, 2, SetIdBits);
    filter.denyArgumentBits(SYS_fchmodat2, 2, SetIdBits);
    filter.denyCreatedModeBits(SYS_openat, 2, 3, SetIdBits);
    filter.denyArgumentBits(SYS_mkdirat, 2, SetIdBits);
    filter.denyArgumentBits(SYS_mknodat, 2, SetIdBits);
#ifdef SYS_chmod
    filter.denyArgumentBits(SYS_chmod, 1, SetIdBits);
#endif
#ifdef SYS_open
    filter.denyCreatedModeBits(SYS_open, 1, 2, SetIdBits);
#endif
#ifdef SYS_creat
    filter.denyArgumentBits(SYS_creat, 1, SetIdBits);
#endif
#ifdef SYS_mkdir
    filter.denyArgumentBits(SYS_mkdir, 1, SetIdBits);
#endif
#ifdef SYS_mknod
    filter.denyArgumentBits(SYS_mknod, 1, SetIdBits);
#endif
    filter.ret(Filter::Allow);

    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        warn("no_new_privs");
        return false;
    }
    if (!filter.install()) {
        if (errno != EINVAL)   // EINVAL: a kernel without seccomp filters
            warn("seccomp");
        return false;
    }
    return true;
#endif
}

bool dropSetIdGroup()
{
    const gid_t real = ::getgid();
    if (::setresgid(real, real, real) != 0)
        return false;
    gid_t r = 0;
    gid_t e = 0;
    gid_t s = 0;
    return ::getresgid(&r, &e, &s) == 0 && r == real && e == real && s == real;
}

} // namespace NetVfs::Bridge
