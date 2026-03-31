/*
 * Zygisk module: Seccomp bypass for Brawl Stars
 *
 * Injects seccomp-bpf filter into com.supercell.brawlstars BEFORE
 * Promon SHIELD loads. No APK modification = signature check passes.
 */

#include <sys/types.h>
#include "zygisk.hpp"

#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <android/log.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#define TAG "SC_BYPASS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static const char *TARGET_PKG = "com.supercell.brawlstars";

/*
 * Architecture-specific syscall numbers.
 * x86_64 for LDPlayer, ARM64 for real devices.
 */
#ifdef __x86_64__
  #define NR_EXIT        60
  #define NR_KILL        62
  #define NR_TGKILL      234
  #define NR_EXIT_GROUP  231
#elif defined(__aarch64__)
  #define NR_EXIT        93
  #define NR_KILL        129
  #define NR_TGKILL      131
  #define NR_EXIT_GROUP  94
#else
  #error "Unsupported architecture"
#endif

static void install_seccomp() {
    /*
     * BPF filter (15 instructions):
     * [0]     Load syscall number
     * [1-2]   exit/exit_group -> BLOCK[14]
     * [3]     kill -> CHECK_KILL[7]
     * [4]     tgkill -> CHECK_TGKILL[10]
     * [5]     Default: ALLOW
     * [6]     Dead zone (padding)
     * [7-9]   CHECK_KILL: load args[1], check SIGKILL/SIGABRT
     * [10-12] CHECK_TGKILL: load args[2], check SIGKILL/SIGABRT
     * [13]    ALLOW (non-deadly signal)
     * [14]    BLOCK (return EPERM)
     *
     * Jump verification:
     *   [1]  jt=12: 1+1+12=14 BLOCK
     *   [2]  jt=11: 2+1+11=14 BLOCK
     *   [3]  jt=3:  3+1+3=7   CHECK_KILL
     *   [4]  jt=5:  4+1+5=10  CHECK_TGKILL
     *   [8]  jt=5:  8+1+5=14  BLOCK
     *   [9]  jt=4:  9+1+4=14  BLOCK
     *   [11] jt=2:  11+1+2=14 BLOCK
     *   [12] jt=1:  12+1+1=14 BLOCK
     */
    struct sock_filter f[] = {
        /* [0]  Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* [1]  exit? -> BLOCK[14] */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_EXIT,       12, 0),
        /* [2]  exit_group? -> BLOCK[14] */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_EXIT_GROUP, 11, 0),
        /* [3]  kill? -> CHECK_KILL[7] */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_KILL,  3, 0),
        /* [4]  tgkill? -> CHECK_TGKILL[10] */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_TGKILL, 5, 0),
        /* [5]  ALLOW (default) */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* -- dead zone, will never reach [6] -- */
        /* [6]  */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* CHECK_KILL: load args[1] (signal) */
        /* [7]  */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        /* [8]  SIGKILL(9) -> BLOCK[14] */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, 5, 0),
        /* [9]  SIGABRT(6) -> BLOCK[14] */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 4, 0),
        /* CHECK_TGKILL: load args[2] (signal) */
        /* [10] */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
        /* [11] SIGKILL -> BLOCK[14] */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, 2, 0),
        /* [12] SIGABRT -> BLOCK[14] */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 1, 0),
        /* [13] ALLOW (non-deadly signal) */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* [14] BLOCK */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (0 & SECCOMP_RET_DATA)),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(f) / sizeof(f[0])),
        .filter = f,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        LOGE("PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        LOGE("PR_SET_SECCOMP failed: %s", strerror(errno));
        return;
    }

    LOGI("seccomp-bpf v3 INSTALLED (Zygisk, 15 instructions)");
}

class BrawlBypass : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api_ = api;
        this->env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *name = env_->GetStringUTFChars(args->nice_name, nullptr);

        if (name && strstr(name, TARGET_PKG)) {
            LOGI("Target: %s — installing seccomp before shield", name);
            install_seccomp();
            target_ = true;
        } else {
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }

        if (name) env_->ReleaseStringUTFChars(args->nice_name, name);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (target_) LOGI("Post-specialize: seccomp active for Brawl Stars");
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    bool target_ = false;
};

REGISTER_ZYGISK_MODULE(BrawlBypass)
