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
// If tsync_ok is non-null, *tsync_ok is set to true when TSYNC succeeded
// (all threads already have the filter), false when only the main thread
// was injected and callers must handle new/existing threads themselves.
int inject_seccomp_filter(pid_t pid, const seccomp_bpf_program &prog,
                          bool *tsync_ok = nullptr);

// Inject the seccomp filter into a single already-stopped thread (no TSYNC).
// Use this for threads discovered via PTRACE_EVENT_CLONE or enumerated from
// /proc/<pid>/task/ after the initial TSYNC failed.
// Returns 0 on success, -1 on failure.
int inject_seccomp_filter_thread(pid_t tid, const seccomp_bpf_program &prog);

#endif // ZYGISKFRIDA_TRACER_SECCOMP_INJECT_H
