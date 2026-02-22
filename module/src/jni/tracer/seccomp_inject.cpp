#include "seccomp_inject.h"
#include "arch.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "../log.h"

#define TAG "[seccomp_inject] "

#ifndef __NR_seccomp
#define __NR_seccomp 277
#endif

// ---------------------------------------------------------------------------
// ptrace memory helpers
// ---------------------------------------------------------------------------

static bool ptrace_read(pid_t pid, uintptr_t addr, void *buf, size_t len) {
    auto *dst = reinterpret_cast<uint8_t *>(buf);
    for (size_t off = 0; off < len; off += sizeof(uint64_t)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + off), nullptr);
        if (errno != 0) return false;

        size_t chunk = sizeof(uint64_t);
        if (off + chunk > len) chunk = len - off;
        memcpy(dst + off, &word, chunk);
    }
    return true;
}

static bool ptrace_write(pid_t pid, uintptr_t addr, const void *buf, size_t len) {
    const auto *src = reinterpret_cast<const uint8_t *>(buf);
    for (size_t off = 0; off < len; off += sizeof(uint64_t)) {
        uint64_t word = 0;
        size_t chunk = sizeof(uint64_t);
        if (off + chunk > len) chunk = len - off;

        if (chunk < sizeof(uint64_t)) {
            errno = 0;
            long orig = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + off), nullptr);
            if (errno != 0) return false;
            word = static_cast<uint64_t>(orig);
        }

        memcpy(&word, src + off, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + off), (void *)word) < 0)
            return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// ARM64 remote syscall helper
// We patch current PC with:
//   svc #0
//   brk #0
// Then set x8/x0..x5 and continue. BRK traps back to tracer.
// ---------------------------------------------------------------------------

static bool run_remote_syscall(pid_t pid,
                               tracer_regs &regs,
                               uint64_t trampoline_pc,
                               uint64_t nr,
                               uint64_t x0,
                               uint64_t x1,
                               uint64_t x2,
                               uint64_t x3,
                               uint64_t x4,
                               uint64_t x5,
                               int64_t &ret_out) {
    tracer_set_syscall_nr(regs, nr);
    tracer_set_arg(regs, 0, x0);
    tracer_set_arg(regs, 1, x1);
    tracer_set_arg(regs, 2, x2);
    tracer_set_arg(regs, 3, x3);
    tracer_set_arg(regs, 4, x4);
    tracer_set_arg(regs, 5, x5);
    tracer_set_pc(regs, trampoline_pc);

    if (!tracer_setregs(pid, regs)) {
        LOGE(TAG "SETREGSET failed before syscall %llu: %s",
             (unsigned long long)nr, strerror(errno));
        return false;
    }

    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
        LOGE(TAG "PTRACE_CONT failed before syscall %llu: %s",
             (unsigned long long)nr, strerror(errno));
        return false;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        LOGE(TAG "waitpid failed after syscall %llu: %s",
             (unsigned long long)nr, strerror(errno));
        return false;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        if (WIFSTOPPED(status)) {
            LOGE(TAG "unexpected stop signal %d after syscall %llu (status=0x%x)",
                 WSTOPSIG(status), (unsigned long long)nr, status);
        } else {
            LOGE(TAG "target not stopped after syscall %llu (status=0x%x)",
                 (unsigned long long)nr, status);
        }
        return false;
    }

    if (!tracer_getregs(pid, regs)) {
        LOGE(TAG "GETREGSET failed after syscall %llu: %s",
             (unsigned long long)nr, strerror(errno));
        return false;
    }

    ret_out = static_cast<int64_t>(tracer_get_retval(regs));
    return true;
}

// ---------------------------------------------------------------------------
// inject_seccomp_filter main entry
// ---------------------------------------------------------------------------

// ARM64 sock_fprog layout (same as kernel).
struct arm64_sock_fprog {
    uint16_t len;
    uint16_t _pad[3];
    uint64_t filter;
};
static_assert(sizeof(arm64_sock_fprog) == 16, "unexpected sock_fprog size");

static int inject_seccomp_filter_once(pid_t pid,
                                      const seccomp_bpf_program &prog,
                                      uint64_t seccomp_flags,
                                      int64_t *seccomp_ret_out) {
    const int64_t kRetUnavailable = std::numeric_limits<int64_t>::min();
    int64_t seccomp_ret = kRetUnavailable;

    LOGI(TAG "injecting seccomp filter (%zu instructions, flags=0x%llx) into pid %d",
         prog.size(), (unsigned long long)seccomp_flags, pid);

    tracer_regs orig_regs;
    if (!tracer_getregs(pid, orig_regs)) {
        LOGE(TAG "GETREGSET failed: %s", strerror(errno));
        return -1;
    }

    size_t filter_bytes = prog.size() * sizeof(struct sock_filter);
    size_t fprog_bytes = sizeof(arm64_sock_fprog);
    size_t total = filter_bytes + fprog_bytes;
    total = (total + 15) & ~(size_t)15;

    uint64_t orig_sp = tracer_get_sp(orig_regs);
    uint64_t new_sp = (orig_sp - total) & ~(uint64_t)15;
    uint64_t filter_addr = new_sp;
    uint64_t fprog_addr = filter_addr + filter_bytes;
    uint64_t tramp_pc = tracer_get_pc(orig_regs);

    LOGI(TAG "stack: orig_sp=0x%llx new_sp=0x%llx total=%zu",
         (unsigned long long)orig_sp, (unsigned long long)new_sp, total);
    LOGI(TAG "layout: filter@0x%llx fprog@0x%llx trampoline_pc=0x%llx",
         (unsigned long long)filter_addr,
         (unsigned long long)fprog_addr,
         (unsigned long long)tramp_pc);

    std::vector<uint8_t> stack_backup(total);
    if (!ptrace_read(pid, new_sp, stack_backup.data(), total)) {
        LOGE(TAG "failed to backup stack: %s", strerror(errno));
        return -1;
    }

    uint8_t code_backup[8] = {};
    if (!ptrace_read(pid, tramp_pc, code_backup, sizeof(code_backup))) {
        LOGE(TAG "failed to backup code at PC=0x%llx: %s",
             (unsigned long long)tramp_pc, strerror(errno));
        return -1;
    }

    bool code_patched = false;
    bool ok = false;

    do {
        if (!ptrace_write(pid, filter_addr, prog.data(), filter_bytes)) {
            LOGE(TAG "failed to write BPF filter: %s", strerror(errno));
            break;
        }

        arm64_sock_fprog fprog{};
        fprog.len = static_cast<uint16_t>(prog.size());
        fprog.filter = filter_addr;
        if (!ptrace_write(pid, fprog_addr, &fprog, fprog_bytes)) {
            LOGE(TAG "failed to write sock_fprog: %s", strerror(errno));
            break;
        }

        const uint32_t tramp_code[2] = {
            0xD4000001,  // svc #0
            0xD4200000   // brk #0
        };
        if (!ptrace_write(pid, tramp_pc, tramp_code, sizeof(tramp_code))) {
            LOGE(TAG "failed to patch syscall trampoline: %s", strerror(errno));
            break;
        }
        code_patched = true;

        tracer_regs exec_regs = orig_regs;
        tracer_set_sp(exec_regs, new_sp);

        int64_t prctl_ret = kRetUnavailable;
        if (!run_remote_syscall(pid, exec_regs, tramp_pc,
                                __NR_prctl,
                                PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0,
                                prctl_ret)) {
            break;
        }

        if (prctl_ret < 0) {
            LOGE(TAG "prctl(PR_SET_NO_NEW_PRIVS) returned %lld (errno=%lld)",
                 (long long)prctl_ret, (long long)(-prctl_ret));
            break;
        }

        if (!run_remote_syscall(pid, exec_regs, tramp_pc,
                                __NR_seccomp,
                                SECCOMP_SET_MODE_FILTER,
                                seccomp_flags,
                                fprog_addr,
                                0, 0, 0,
                                seccomp_ret)) {
            break;
        }

        ok = true;
    } while (false);

    if (code_patched && !ptrace_write(pid, tramp_pc, code_backup, sizeof(code_backup))) {
        LOGW(TAG "failed to restore code at PC (non-fatal)");
    }

    if (!ptrace_write(pid, new_sp, stack_backup.data(), total)) {
        LOGW(TAG "failed to restore stack (non-fatal)");
    }

    if (!tracer_setregs(pid, orig_regs)) {
        LOGE(TAG "failed to restore registers: %s", strerror(errno));
        return -1;
    }

    if (seccomp_ret_out) {
        *seccomp_ret_out = seccomp_ret;
    }

    LOGI(TAG "injection complete, target resumed at original PC=0x%llx",
         (unsigned long long)tramp_pc);
    return ok ? 0 : -1;
}

int inject_seccomp_filter(pid_t pid, const seccomp_bpf_program &prog) {
    const int64_t kRetUnavailable = std::numeric_limits<int64_t>::min();

    int64_t seccomp_ret = kRetUnavailable;
    if (inject_seccomp_filter_once(pid, prog, SECCOMP_FILTER_FLAG_TSYNC, &seccomp_ret) < 0) {
        return -1;
    }

    if (seccomp_ret == 0) {
        LOGI(TAG "seccomp filter installed successfully (TSYNC)");
        return 0;
    }

    if (seccomp_ret > 0) {
        LOGW(TAG "seccomp(TSYNC) sync failed at tid=%lld; retrying without TSYNC",
             (long long)seccomp_ret);

        seccomp_ret = kRetUnavailable;
        if (inject_seccomp_filter_once(pid, prog, 0, &seccomp_ret) < 0) {
            return -1;
        }

        if (seccomp_ret == 0) {
            LOGW(TAG "seccomp filter installed without TSYNC (thread-local fallback)");
            return 0;
        }
    }

    if (seccomp_ret < 0 && seccomp_ret != kRetUnavailable) {
        LOGE(TAG "seccomp() returned %lld (errno=%lld)",
             (long long)seccomp_ret, (long long)(-seccomp_ret));
    } else if (seccomp_ret > 0) {
        LOGE(TAG "seccomp() failed with tsync offender tid=%lld", (long long)seccomp_ret);
    } else {
        LOGE(TAG "seccomp() return value unavailable");
    }

    return -1;
}
