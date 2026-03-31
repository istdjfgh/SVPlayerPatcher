/*
 * Zygisk module: Seccomp bypass for Brawl Stars
 * 
 * Injects seccomp-bpf filter into com.supercell.brawlstars BEFORE
 * Promon SHIELD loads. This runs in the Zygote fork (native x86_64),
 * so no APK modification needed = shield's signature check passes.
 *
 * The filter blocks exit/exit_group and deadly signals via kill/tgkill,
 * preventing the shield from terminating the process when it detects
 * root/emulator/other checks.
 */

#include "zygisk.hpp"

#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <android/log.h>

/* seccomp headers */
#include <linux/seccomp.h>
#include <linux/filter.h>

#define TAG "SC_BYPASS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* Package to target */
static const char *TARGET_PACKAGE = "com.supercell.brawlstars";

/*
 * Syscall numbers - architecture dependent
 */
#ifdef __x86_64__
  #define NR_EXIT        60
  #define NR_KILL        62
  #define NR_TGKILL      234
  #define NR_EXIT_GROUP  231
  #define NR_FORK        57
  #define NR_VFORK       58
  #define NR_CLONE       56
#elif defined(__aarch64__)
  #define NR_EXIT        93
  #define NR_KILL        129
  #define NR_TGKILL      131
  #define NR_EXIT_GROUP  94
  #define NR_FORK        1079   /* doesn't exist on ARM64 */
  #define NR_VFORK       1078   /* doesn't exist on ARM64 */
  #define NR_CLONE       220
#else
  #error "Unsupported architecture"
#endif

#ifndef CLONE_VM
#define CLONE_VM 0x00000100
#endif

static void install_seccomp() {
    struct sock_filter filter[] = {
        /* [0] Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        /* exit/exit_group: BLOCK */
        /* [1]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_EXIT,       18, 0),
        /* [2]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_EXIT_GROUP, 17, 0),

        /* fork/vfork: BLOCK */
        /* [3]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_FORK,       16, 0),
        /* [4]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_VFORK,      15, 0),

        /* clone: check if fork (no CLONE_VM) or thread (CLONE_VM) */
        /* [5]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_CLONE, 0, 3),
        /* [6]  Load clone flags (args[0]) */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        /* [7]  CLONE_VM set? yes=thread(allow), no=fork(block) */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_VM, 0, 12), /* no CLONE_VM → BLOCK */
        /* [8]  Reload nr (clobbered) then fall through to kill check */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        /* kill: check signal */
        /* [9]  */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_KILL,  2, 0),
        /* tgkill: check signal */
        /* [10] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_TGKILL, 5, 0),

        /* [11] Default: ALLOW */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* CHECK_KILL: load args[1] = signal for kill(pid, sig) */
        /* [12] */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        /* [13] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, 6, 0),
        /* [14] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 5, 0),
        /* [15] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGTERM, 4, 0),
        /* [16] */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* CHECK_TGKILL: load args[2] = signal for tgkill(tgid, tid, sig) */
        /* [17] */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
        /* [18] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, 1, 0),
        /* [19] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 0, 1),

        /* [20] BLOCK: return errno=0 (looks like success to caller) */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (0 & SECCOMP_RET_DATA)),
        /* [21] ALLOW (fallthrough for non-deadly tgkill signals) */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        LOGE("PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        LOGE("PR_SET_SECCOMP failed: %s", strerror(errno));
        return;
    }

    LOGI("seccomp filter INSTALLED (Zygisk)");
}

class BrawlBypass : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api_ = api;
        this->env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *process = env_->GetStringUTFChars(args->nice_name, nullptr);
        
        if (process && strstr(process, TARGET_PACKAGE) != nullptr) {
            LOGI("Target: %s - installing seccomp", process);
            install_seccomp();
            is_target_ = true;
        } else {
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }

        if (process) {
            env_->ReleaseStringUTFChars(args->nice_name, process);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (is_target_) {
            LOGI("Post-specialize: seccomp active for Brawl Stars");
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    bool is_target_ = false;
};

REGISTER_ZYGISK_MODULE(BrawlBypass)
