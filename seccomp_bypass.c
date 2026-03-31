/*
 * seccomp_bypass.c - Block exit/kill syscalls via seccomp-bpf
 * 
 * Loaded BEFORE libsupercell_brawlstars.so (Promon SHIELD).
 * Installs a kernel-level seccomp filter that prevents any code
 * (including direct SVC #0 syscalls) from terminating the process.
 * 
 * This works on Houdini because seccomp operates at kernel level,
 * after Houdini translates ARM64 SVC to x86_64 syscalls.
 */

#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <android/log.h>

#define TAG "SC_BYPASS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

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

static struct sock_filter seccomp_filter[] = {
    /* [0] Load syscall number */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (offsetof(struct seccomp_data, nr))),

    /* x86_64 syscalls */
    /* [1]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X64_EXIT_GROUP, 8, 0),
    /* [2]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X64_EXIT,       7, 0),
    /* [3]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X64_KILL,       6, 0),
    /* [4]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X64_TGKILL,     5, 0),

    /* ARM64 syscalls */
    /* [5]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_A64_EXIT_GROUP, 4, 0),
    /* [6]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_A64_EXIT,       3, 0),
    /* [7]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_A64_KILL,       2, 0),
    /* [8]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_A64_TGKILL,     1, 0),

    /* [9]  Default: ALLOW */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* [10] Matched: BLOCK with EPERM */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
};

__attribute__((constructor))
static void install_seccomp(void) {
    LOGI("=== seccomp_bypass v1 loading ===");

    /* PR_SET_NO_NEW_PRIVS is required before installing seccomp filter */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        LOGE("PR_SET_NO_NEW_PRIVS failed: %d (%s)", errno, strerror(errno));
    }

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(seccomp_filter) / sizeof(seccomp_filter[0])),
        .filter = seccomp_filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        LOGE("PR_SET_SECCOMP failed: %d (%s)", errno, strerror(errno));
        LOGE("seccomp-bpf not available on this kernel!");
        return;
    }

    LOGI("seccomp-bpf filter INSTALLED! exit/kill/tgkill blocked.");
    LOGI("Blocked syscalls: exit(%d/%d) exit_group(%d/%d) kill(%d/%d) tgkill(%d/%d)",
         NR_X64_EXIT, NR_A64_EXIT,
         NR_X64_EXIT_GROUP, NR_A64_EXIT_GROUP,
         NR_X64_KILL, NR_A64_KILL,
         NR_X64_TGKILL, NR_A64_TGKILL);
}
