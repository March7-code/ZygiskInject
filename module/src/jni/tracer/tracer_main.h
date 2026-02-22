#ifndef ZYGISKFRIDA_TRACER_MAIN_H
#define ZYGISKFRIDA_TRACER_MAIN_H

#include <sys/types.h>
#include <string>

// Launch the tracer process for a target app.
// Called from the companion daemon (root context).
// Forks a child that will PTRACE_SEIZE the target pid,
// inject seccomp filter, and enter the monitoring loop.
//
// target_pid:  pid of the app process (known after postAppSpecialize)
// log_path:    file to write syscall trace log
//
// Returns the tracer child pid (>0) on success, -1 on failure.
pid_t launch_tracer(pid_t target_pid, const std::string &log_path);

#endif // ZYGISKFRIDA_TRACER_MAIN_H
