#include "tracer_main.h"
#include "arch.h"
#include "seccomp_filter.h"
#include "seccomp_inject.h"
#include "syscall_handler.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <set>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../log.h"

#define TAG "[tracer] "

// Track pids waiting for syscall-exit stop (after PTRACE_SYSCALL)
static std::set<pid_t> g_awaiting_exit;
static constexpr long kPtraceOptions =
        PTRACE_O_TRACESECCOMP |
        PTRACE_O_TRACECLONE |
        PTRACE_O_TRACEFORK |
        PTRACE_O_TRACESYSGOOD;

// ---------------------------------------------------------------------------
// Tracer process main logic (runs as root in a forked child)
// ---------------------------------------------------------------------------

static void tracer_process(pid_t target_pid, const std::string &log_path, bool verbose_logs) {
    LOGI(TAG "tracer started, target pid=%d, log=%s",
         target_pid, log_path.c_str());

    // 1. PTRACE_SEIZE — non-stop attach, no SIGSTOP sent to target
    long ret = ptrace(PTRACE_SEIZE, target_pid, nullptr,
                      (void*)(uintptr_t)kPtraceOptions);
    if (ret < 0) {
        LOGE(TAG "PTRACE_SEIZE failed: %s", strerror(errno));
        _exit(1);
    }
    LOGI(TAG "PTRACE_SEIZE succeeded");

    // 2. Interrupt target to inject seccomp filter
    if (ptrace(PTRACE_INTERRUPT, target_pid, nullptr, nullptr) < 0) {
        LOGE(TAG "PTRACE_INTERRUPT failed: %s", strerror(errno));
        _exit(1);
    }

    int status = 0;
    waitpid(target_pid, &status, 0);

    if (!WIFSTOPPED(status)) {
        LOGE(TAG "target not stopped after INTERRUPT: status=0x%x", status);
        _exit(1);
    }

    // 3. Build and inject seccomp filter
    auto bpf = build_default_io_filter();
    LOGI(TAG "BPF filter: %zu instructions", bpf.size());

    if (inject_seccomp_filter(target_pid, bpf) < 0) {
        LOGE(TAG "seccomp injection failed, detaching");
        ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr);
        _exit(1);
    }

    // 4. Initialize syscall handler (opens log file)
    syscall_handler_init(target_pid, log_path, verbose_logs);

    // 5. Resume target
    if (ptrace(PTRACE_CONT, target_pid, nullptr, nullptr) < 0) {
        LOGE(TAG "PTRACE_CONT after inject failed: %s", strerror(errno));
        _exit(1);
    }

    LOGI(TAG "entering monitoring loop");

    // 6. Main monitoring loop
    for (;;) {
        pid_t stopped_pid = waitpid(-1, &status, __WALL);
        if (stopped_pid < 0) {
            if (errno == ECHILD) {
                LOGI(TAG "no more children, exiting");
                break;
            }
            if (errno == EINTR) continue;
            LOGE(TAG "waitpid error: %s", strerror(errno));
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (stopped_pid == target_pid) {
                LOGI(TAG "target exited, tracer done");
                break;
            }
            // A child thread/process exited
            continue;
        }

        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        int event = (status >> 16) & 0xFF;

        // seccomp-stop: this is what we care about
        if (event == PTRACE_EVENT_SECCOMP) {
            seccomp_action act = handle_seccomp_stop(stopped_pid);
            if (act == SECCOMP_ACT_WAIT_EXIT) {
                // Need syscall-exit: use PTRACE_SYSCALL so we get
                // a stop after the syscall completes (sig = SIGTRAP|0x80)
                g_awaiting_exit.insert(stopped_pid);
                ptrace(PTRACE_SYSCALL, stopped_pid, nullptr, nullptr);
            } else {
                ptrace(PTRACE_CONT, stopped_pid, nullptr, nullptr);
            }
            continue;
        }

        // New child from clone/fork — auto-traced via PTRACE_O_TRACECLONE
        if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK) {
            unsigned long new_pid = 0;
            ptrace(PTRACE_GETEVENTMSG, stopped_pid, nullptr, &new_pid);
            LOGI(TAG "new child %lu from pid %d", new_pid, stopped_pid);
            ptrace(PTRACE_CONT, stopped_pid, nullptr, nullptr);
            continue;
        }

        // If we are waiting for syscall-exit on this tid, accept both
        // SIGTRAP|0x80 (normal TRACESYSGOOD case) and plain SIGTRAP.
        // Some kernels/devices report the exit-stop as plain SIGTRAP after
        // a SECCOMP stop + PTRACE_SYSCALL sequence.
        if (g_awaiting_exit.count(stopped_pid) &&
            (sig == (SIGTRAP | 0x80) || (sig == SIGTRAP && event == 0))) {
            handle_syscall_exit(stopped_pid);
            g_awaiting_exit.erase(stopped_pid);
            ptrace(PTRACE_CONT, stopped_pid, nullptr, nullptr);
            continue;
        }

        // group-stop or signal-delivery-stop — forward the signal
        int inject_sig = 0;
        if (sig != SIGTRAP && sig != (SIGTRAP | 0x80)) {
            inject_sig = sig;
        }
        ptrace(PTRACE_CONT, stopped_pid, nullptr, (void*)(uintptr_t)inject_sig);
    }

    syscall_handler_fini();
    LOGI(TAG "tracer exiting");
    _exit(0);
}

// ---------------------------------------------------------------------------
// Public API: fork a tracer child process
// ---------------------------------------------------------------------------

pid_t launch_tracer(pid_t target_pid, const std::string &log_path, bool verbose_logs) {
    pid_t child = fork();
    if (child < 0) {
        LOGE(TAG "fork failed: %s", strerror(errno));
        return -1;
    }
    if (child == 0) {
        // In tracer child — detach from parent's session
        setsid();
        tracer_process(target_pid, log_path, verbose_logs);
        _exit(0);  // unreachable
    }
    LOGI(TAG "launched tracer pid=%d for target pid=%d", child, target_pid);
    return child;
}
