#ifndef ZYGISKFRIDA_TRACER_MAIN_H
#define ZYGISKFRIDA_TRACER_MAIN_H

#include <sys/types.h>
#include <string>
#include <vector>
#include "../config.h"

// Launch the tracer process for a target app.
// Called from the companion daemon (root context).
// Forks a child that will PTRACE_SEIZE the target pid,
// inject seccomp filter, and enter the monitoring loop.
//
// target_pid:  pid of the app process (known after postAppSpecialize)
// log_path:    file to write syscall trace log
// verbose_logs: enable detailed per-read debug logs
// block_self_kill: when true, block exit_group/kill/tgkill; when false, allow but still log
// so_hooks:    SO load-time hook configs (patch functions via ptrace before .init_array)
//
// Returns the tracer child pid (>0) on success, -1 on failure.
pid_t launch_tracer(pid_t target_pid, const std::string &log_path, bool verbose_logs = false,
                    bool block_self_kill = false,
                    const std::vector<so_hook_config> &so_hooks = {});

#endif // ZYGISKFRIDA_TRACER_MAIN_H
