#ifndef ZYGISKFRIDA_TRACER_SECCOMP_INJECT_H
#define ZYGISKFRIDA_TRACER_SECCOMP_INJECT_H

#include <cstdint>
#include <sys/types.h>
#include "seccomp_filter.h"

// Inject a seccomp BPF filter into a ptraced target process.
//
// The target must already be stopped (PTRACE_SEIZE + PTRACE_INTERRUPT).
// This function:
//   1. Saves all registers
//   2. Writes BPF bytecode + sock_fprog + prctl shellcode onto the
//      target's stack
//   3. Executes the shellcode (prctl(PR_SET_NO_NEW_PRIVS) + prctl(PR_SET_SECCOMP))
//   4. Restores all registers and stack contents
//
// Returns 0 on success, -1 on failure.
int inject_seccomp_filter(pid_t pid, const seccomp_bpf_program &prog);

#endif // ZYGISKFRIDA_TRACER_SECCOMP_INJECT_H
