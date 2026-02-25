#ifndef ZYGISKFRIDA_TRACER_SECCOMP_INJECT_H
#define ZYGISKFRIDA_TRACER_SECCOMP_INJECT_H

#include <cstdint>
#include <sys/types.h>
#include "seccomp_filter.h"
#include "arch.h"

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

// Execute a single syscall in the stopped target process via ptrace trampoline.
//
// The target must already be stopped (e.g. at a seccomp-stop or PTRACE_INTERRUPT).
// Saves/restores all registers and the 8 bytes at the current PC used as
// the trampoline (svc #0 / brk #0).
//
// Returns true on success; ret_out receives the syscall return value.
bool ptrace_remote_syscall(pid_t pid,
                           uint64_t nr,
                           uint64_t a0, uint64_t a1, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5,
                           int64_t &ret_out);

#endif // ZYGISKFRIDA_TRACER_SECCOMP_INJECT_H
