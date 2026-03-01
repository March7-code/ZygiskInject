#ifndef ZYGISKFRIDA_TRACER_SYSCALL_RULES_H
#define ZYGISKFRIDA_TRACER_SYSCALL_RULES_H

#include <cstdint>
#include <vector>

// Centralized syscall rules for tracer:
// - syscall number -> name mapping
// - kill-related syscall classification
// - default seccomp interception list

const char *tracer_syscall_name(uint64_t nr);

bool tracer_is_process_kill_syscall(uint64_t nr);

// For kill-family syscalls, extract the signal argument from raw syscall args.
// arg1 = syscall arg1 (x1), arg2 = syscall arg2 (x2).
bool tracer_extract_kill_signal_arg(uint64_t nr,
                                    uint64_t arg1,
                                    uint64_t arg2,
                                    uint64_t *out_sig);

std::vector<uint32_t> build_default_tracer_syscall_nrs(bool block_self_kill);

#endif  // ZYGISKFRIDA_TRACER_SYSCALL_RULES_H
