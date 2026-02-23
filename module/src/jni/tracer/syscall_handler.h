#ifndef ZYGISKFRIDA_TRACER_SYSCALL_HANDLER_H
#define ZYGISKFRIDA_TRACER_SYSCALL_HANDLER_H

#include <sys/types.h>
#include <string>

// Return codes from handle_seccomp_stop
enum seccomp_action {
    SECCOMP_ACT_CONTINUE = 0,   // Normal: just PTRACE_CONT
    SECCOMP_ACT_WAIT_EXIT = 1,  // Need syscall-exit stop: use PTRACE_SYSCALL,
                                // then call handle_syscall_exit()
};

// Initialize the syscall handler, open log file.
void syscall_handler_init(pid_t target_pid, const std::string &log_path, bool verbose_logs);

// Handle a PTRACE_EVENT_SECCOMP stop (syscall-entry).
// Returns SECCOMP_ACT_WAIT_EXIT if the caller must use PTRACE_SYSCALL
// and call handle_syscall_exit() on the next stop.
seccomp_action handle_seccomp_stop(pid_t pid);

// Handle syscall-exit stop for read() on a tracked fd.
// Called after PTRACE_SYSCALL delivers the exit stop.
void handle_syscall_exit(pid_t pid);

// Flush and close the log file.
void syscall_handler_fini();

#endif // ZYGISKFRIDA_TRACER_SYSCALL_HANDLER_H
