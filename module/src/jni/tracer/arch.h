#ifndef ZYGISKFRIDA_TRACER_ARCH_H
#define ZYGISKFRIDA_TRACER_ARCH_H

// ARM64-only tracer architecture abstraction.
// Provides register access helpers for ptrace on aarch64.

#include <cstdint>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#include <linux/ptrace.h>

// ARM64 uses struct user_pt_regs (via NT_PRSTATUS iovec)
// regs[0..30] = x0..x30, sp, pc, pstate
// syscall nr  = regs[8]
// args         = regs[0..5]  (x0..x5)
// return value = regs[0]     (x0)

struct tracer_regs {
    uint64_t regs[31];  // x0 - x30
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

// Read all GP registers via PTRACE_GETREGSET (NT_PRSTATUS)
inline bool tracer_getregs(pid_t pid, tracer_regs &r) {
    struct iovec iov = { &r, sizeof(r) };
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == 0;
}

// Write all GP registers
inline bool tracer_setregs(pid_t pid, const tracer_regs &r) {
    struct iovec iov = { (void*)&r, sizeof(r) };
    return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) == 0;
}

// Syscall number: x8
inline uint64_t tracer_get_syscall_nr(const tracer_regs &r) { return r.regs[8]; }
inline void tracer_set_syscall_nr(tracer_regs &r, uint64_t nr) { r.regs[8] = nr; }

// Syscall arguments: x0..x5
inline uint64_t tracer_get_arg(const tracer_regs &r, int n) { return r.regs[n]; }
inline void tracer_set_arg(tracer_regs &r, int n, uint64_t val) { r.regs[n] = val; }

// Return value: x0
inline uint64_t tracer_get_retval(const tracer_regs &r) { return r.regs[0]; }
inline void tracer_set_retval(tracer_regs &r, uint64_t val) { r.regs[0] = val; }

// PC / SP
inline uint64_t tracer_get_pc(const tracer_regs &r) { return r.pc; }
inline void tracer_set_pc(tracer_regs &r, uint64_t val) { r.pc = val; }
inline uint64_t tracer_get_sp(const tracer_regs &r) { return r.sp; }
inline void tracer_set_sp(tracer_regs &r, uint64_t val) { r.sp = val; }

#endif // ZYGISKFRIDA_TRACER_ARCH_H
