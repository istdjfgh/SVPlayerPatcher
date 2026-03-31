/*
 * seccomp_bypass.c v2 - Smart exit/kill blocking via seccomp-bpf
 *
 * Loaded BEFORE libsupercell_brawlstars.so (Promon SHIELD).
 * Installs a kernel-level seccomp filter that:
 *   - Blocks exit() and exit_group() unconditionally
 *   - Blocks kill/tgkill ONLY for deadly signals (SIGKILL/SIGABRT/SIGTERM)
 *   - Allows kill/tgkill with other signals (SIGUSR1 etc) for GC/threads
 *
 * v1 blocked ALL kill/tgkill which broke Android GC (uses tgkill+SIGUSR1)
 * causing permanent black screen. v2 fixes this.
 */

#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <android/log.h>

#define TAG "SC_BYPASS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/*
 * Syscall numbers for BOTH architectures.
 * Under Houdini on x86_64, seccomp sees x86_64 numbers after translation.
 * We include ARM64 numbers too just in case.
 */

/* x86_64 syscall numbers */
#define NR_X64_EXIT        60
#define NR_X64_KILL        62
#define NR_X64_TGKILL      234
#define NR_X64_EXIT_GROUP  231

/* ARM64 (aarch64) syscall numbers */
#define NR_A64_EXIT        93
#define NR_A64_EXIT_GROUP  94
#define NR_A64_KILL        129
#define NR_A64_TGKILL      131

/*
 * BPF filter layout (21 instructions):
 *
 * [0]     Load syscall number
 * [1-4]   exit/exit_group -> BLOCK unconditionally
 * [5-6]   kill -> CHECK_KILL_SIG
 * [7-8]   tgkill -> CHECK_TGKILL_SIG
 * [9]     Default: ALLOW
 * [10-14] CHECK_KILL: load args[1] (sig), block SIGKILL/SIGABRT/SIGTERM
 * [15-19] CHECK_TGKILL: load args[2] (sig), block SIGKILL/SIGABRT/SIGTERM
 * [20]    BLOCK: return ERRNO(EPERM)
 */
static struct sock_filter seccomp_filter[] = {
    /* [0] Load syscall number */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* exit/exit_group - BLOCK unconditionally */
    /* [1]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X64_EXIT,       18, 0),
    /* [2]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_A64_EXIT,       17, 0),
    /* [3]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X64_EXIT_GROUP, 16, 0),
    /* [4]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_A64_EXIT_GROUP, 15, 0),

    /* kill(pid, sig) - check signal before blocking */
    /* [5]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X64_KILL,  4, 0),
    /* [6]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_A64_KILL,  3, 0),

    /* tgkill(tgid, tid, sig) - check signal before blocking */
    /* [7]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X64_TGKILL, 7, 0),
    /* [8]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_A64_TGKILL, 6, 0),

    /* [9]  Default: ALLOW everything else */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* CHECK_KILL_SIG: load args[1] = signal for kill(pid, sig) */
    /* [10] */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
    /* [11] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, 8, 0),
    /* [12] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 7, 0),
    /* [13] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGTERM, 6, 0),
    /* [14] */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),  /* other signals OK */

    /* CHECK_TGKILL_SIG: load args[2] = signal for tgkill(tgid, tid, sig) */
    /* [15] */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
    /* [16] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, 3, 0),
    /* [17] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 2, 0),
    /* [18] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGTERM, 1, 0),
    /* [19] */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),  /* other signals OK */

    /* [20] BLOCK: return error instead of terminating */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
};

__attribute__((constructor))
static void install_seccomp(void) {
    LOGI("=== seccomp_bypass v2 loading ===");
    LOGI("Smart filter: exit/exit_group=BLOCK, kill/tgkill=BLOCK only SIGKILL/SIGABRT/SIGTERM");

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        LOGE("PR_SET_NO_NEW_PRIVS failed: %d (%s)", errno, strerror(errno));
    }

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(seccomp_filter) / sizeof(seccomp_filter[0])),
        .filter = seccomp_filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        LOGE("PR_SET_SECCOMP failed: %d (%s)", errno, strerror(errno));
        LOGE("seccomp-bpf NOT available on this kernel!");
        return;
    }

    LOGI("seccomp-bpf v2 INSTALLED successfully");
    LOGI("  exit(%d/%d) exit_group(%d/%d) = ALWAYS BLOCKED",
         NR_X64_EXIT, NR_A64_EXIT, NR_X64_EXIT_GROUP, NR_A64_EXIT_GROUP);
    LOGI("  kill(%d/%d) tgkill(%d/%d) = BLOCKED only for sig 9,6,15",
         NR_X64_KILL, NR_A64_KILL, NR_X64_TGKILL, NR_A64_TGKILL);
}
