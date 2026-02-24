#include "tracer_main.h"
#include "arch.h"
#include "seccomp_filter.h"
#include "seccomp_inject.h"
#include "syscall_handler.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <set>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../log.h"

#define TAG "[tracer] "

// Track pids waiting for syscall-exit stop (after PTRACE_SYSCALL)
static std::set<pid_t> g_awaiting_exit;
// Track threads that already have the seccomp filter injected
static std::set<pid_t> g_filter_injected;
// Whether TSYNC succeeded (if true, all threads inherit the filter automatically)
static bool g_tsync_ok = false;
// Cached BPF program for injecting into new threads
static seccomp_bpf_program g_bpf;
static constexpr long kPtraceOptions =
        PTRACE_O_TRACESECCOMP |
        PTRACE_O_TRACECLONE |
        PTRACE_O_TRACEFORK |
        PTRACE_O_TRACESYSGOOD;

// ---------------------------------------------------------------------------
// PTRACE_SEIZE existing threads so seccomp TRACE events are delivered to tracer.
//
// stage="pre-inject": seize before seccomp install to avoid a window where
// sibling threads get SECCOMP_RET_TRACE but are not traced yet (kernel then
// returns -ENOSYS with no PTRACE_EVENT_SECCOMP stop/log).
//
// stage="post-inject": catch threads created during the injection sequence.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// "Stop the world": seize AND freeze every sibling thread.
//
// Unlike the old seize_existing_threads() which only PTRACE_SEIZE'd threads
// (leaving them running), this function also PTRACE_INTERRUPT + waitpid each
// thread so it is fully stopped.  We loop until /proc/<pid>/task stabilises,
// guaranteeing no thread is missed — a stopped thread cannot clone().
//
// Returns the set of tids that were frozen (caller must PTRACE_CONT them).
// ---------------------------------------------------------------------------
static std::set<pid_t> freeze_all_threads(pid_t target_pid) {
    std::set<pid_t> frozen;
    char task_dir[64];
    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", target_pid);

    for (int pass = 0; pass < 8; pass++) {
        int new_count = 0;
        DIR *dir = opendir(task_dir);
        if (!dir) {
            LOGW(TAG "freeze_all_threads: cannot open %s: %s", task_dir, strerror(errno));
            break;
        }

        struct dirent *ent;
        while ((ent = readdir(dir)) != nullptr) {
            if (ent->d_name[0] == '.') continue;
            pid_t tid = (pid_t)atoi(ent->d_name);
            if (tid <= 0 || tid == target_pid) continue;
            if (frozen.count(tid)) continue;  // already frozen

            // Seize
            long r = ptrace(PTRACE_SEIZE, tid, nullptr,
                            (void *)(uintptr_t)kPtraceOptions);
            if (r < 0) {
                LOGW(TAG "freeze_all_threads: SEIZE tid %d failed: %s", tid, strerror(errno));
                continue;
            }

            // Interrupt to stop it
            if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0) {
                LOGW(TAG "freeze_all_threads: INTERRUPT tid %d failed: %s", tid, strerror(errno));
                continue;
            }

            // Wait for the stop
            int st = 0;
            pid_t wp = waitpid(tid, &st, __WALL);
            if (wp == tid && WIFSTOPPED(st)) {
                frozen.insert(tid);
                g_filter_injected.insert(tid);
                new_count++;
            } else {
                LOGW(TAG "freeze_all_threads: waitpid tid %d returned wp=%d status=0x%x",
                     tid, wp, st);
            }
        }
        closedir(dir);

        LOGI(TAG "freeze_all_threads: pass %d, froze %d new threads (total %zu)",
             pass, new_count, frozen.size());

        if (new_count == 0) break;  // stable — no new threads found
    }

    return frozen;
}

// Resume all previously frozen threads.
static void resume_frozen_threads(const std::set<pid_t> &frozen) {
    for (pid_t tid : frozen) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    }
    LOGI(TAG "resumed %zu frozen threads", frozen.size());
}

// ---------------------------------------------------------------------------
// Tracer process main logic (runs as root in a forked child)
// ---------------------------------------------------------------------------

static void tracer_process(pid_t target_pid, const std::string &log_path, bool verbose_logs,
                           bool block_self_kill,
                           const std::vector<so_hook_config> &so_hooks) {
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

    // 2b. "Stop the world": seize + freeze ALL sibling threads.
    // Every thread is stopped before the filter is installed, so no thread
    // can escape with SECCOMP_RET_TRACE but without a ptrace tracer.
    std::set<pid_t> frozen = freeze_all_threads(target_pid);

    // 3. Build and inject seccomp filter
    g_bpf = build_default_io_filter(block_self_kill);
    LOGI(TAG "BPF filter: %zu instructions", g_bpf.size());

    if (inject_seccomp_filter(target_pid, g_bpf, &g_tsync_ok) < 0) {
        LOGE(TAG "seccomp injection failed, detaching");
        ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr);
        _exit(1);
    }
    g_filter_injected.insert(target_pid);
    LOGI(TAG "seccomp filter injected, tsync_ok=%d", g_tsync_ok ? 1 : 0);

    // 4. Initialize syscall handler (opens log file)
    syscall_handler_init(target_pid, log_path, verbose_logs, block_self_kill, so_hooks);

    // 5. Resume all frozen siblings, then the leader
    resume_frozen_threads(frozen);

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
            if (WIFEXITED(status)) {
                LOGE(TAG "pid %d exited with code %d", stopped_pid, WEXITSTATUS(status));
            } else {
                LOGE(TAG "pid %d killed by signal %d (%s)", stopped_pid,
                     WTERMSIG(status), strsignal(WTERMSIG(status)));
            }
            if (stopped_pid == target_pid) {
                LOGE(TAG "target process died, tracer done");
                break;
            }
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

            // When TSYNC failed, new threads don't inherit our filter.
            // Inject it before letting them run.
            if (!g_tsync_ok && new_pid > 0 &&
                g_filter_injected.find((pid_t)new_pid) == g_filter_injected.end()) {
                // The new thread gets an initial SIGSTOP; wait for it.
                int child_status = 0;
                pid_t wp = waitpid((pid_t)new_pid, &child_status, __WALL);
                if (wp == (pid_t)new_pid && WIFSTOPPED(child_status)) {
                    if (inject_seccomp_filter_thread((pid_t)new_pid, g_bpf) == 0) {
                        g_filter_injected.insert((pid_t)new_pid);
                        LOGI(TAG "injected seccomp filter into new tid %lu", new_pid);
                    } else {
                        LOGW(TAG "failed to inject filter into new tid %lu", new_pid);
                    }
                    ptrace(PTRACE_CONT, (pid_t)new_pid, nullptr, nullptr);
                } else {
                    LOGW(TAG "waitpid for new tid %lu returned wp=%d status=0x%x",
                         new_pid, wp, child_status);
                }
            }

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

pid_t launch_tracer(pid_t target_pid, const std::string &log_path, bool verbose_logs,
                    bool block_self_kill,
                    const std::vector<so_hook_config> &so_hooks) {
    pid_t child = fork();
    if (child < 0) {
        LOGE(TAG "fork failed: %s", strerror(errno));
        return -1;
    }
    if (child == 0) {
        // In tracer child — detach from parent's session
        setsid();
        tracer_process(target_pid, log_path, verbose_logs, block_self_kill, so_hooks);
        _exit(0);  // unreachable
    }
    LOGI(TAG "launched tracer pid=%d for target pid=%d", child, target_pid);
    return child;
}
