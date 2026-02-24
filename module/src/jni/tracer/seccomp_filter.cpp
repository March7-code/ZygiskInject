#include "seccomp_filter.h"

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <cstddef>

// seccomp_data layout:
//   offset 0: int nr          (syscall number)
//   offset 4: __u32 arch
//   offset 8: __u64 instruction_pointer
//   offset 16: __u64 args[6]

#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 (EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif

seccomp_bpf_program build_seccomp_filter(const std::vector<uint32_t> &syscall_nrs) {
    seccomp_bpf_program prog;
    auto &f = prog.filter;

    // ---- Step 1: validate architecture = AARCH64 ----
    // BPF_LD: load arch field
    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                          offsetof(struct seccomp_data, arch)));
    // If arch != AARCH64, kill (safety).
    // If equal, skip the kill-return and continue.
    f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                          AUDIT_ARCH_AARCH64, 1, 0));
    f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // ---- Step 2: load syscall number ----
    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                          offsetof(struct seccomp_data, nr)));

    // ---- Step 3: compare against each target syscall ----
    // For each syscall: if match, jump to TRACE return; else fall through.
    // After all comparisons, fall through to ALLOW.
    //
    // Layout:
    //   [cmp_0] [cmp_1] ... [cmp_N-1] [RET_ALLOW] [RET_TRACE]
    //
    // Each cmp_i: BPF_JEQ -> if true, jump forward to RET_TRACE
    //             if false, fall through to cmp_i+1

    size_t n = syscall_nrs.size();
    for (size_t i = 0; i < n; i++) {
        // Distance to RET_TRACE from this instruction:
        //   remaining comparisons: (n - 1 - i)
        //   + 1 for RET_ALLOW
        uint8_t jt = (uint8_t)(n - 1 - i + 1);  // jump-true offset
        f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                              syscall_nrs[i], jt, 0));
    }

    // ---- Step 4: default action = ALLOW ----
    f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // ---- Step 5: trace action for matched syscalls ----
    // SECCOMP_RET_TRACE with data=0 (tracer sees PTRACE_EVENT_SECCOMP)
    f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE));

    return prog;
}

seccomp_bpf_program build_default_io_filter() {
    std::vector<uint32_t> nrs;

    // ARM64 does NOT have __NR_open or __NR_access (removed in aarch64 ABI).
    // Only the *at variants exist.
    nrs.push_back(__NR_openat);
    nrs.push_back(__NR_faccessat);
#ifdef __NR_newfstatat
    nrs.push_back(__NR_newfstatat);   // fstatat64 on arm64, also covers lstat
#endif
    nrs.push_back(__NR_readlinkat);
    nrs.push_back(__NR_statx);        // newer kernels prefer statx

    // Needed for anti-cheat that uses opendir() to enumerate /proc/self/task
    // or /proc/self/fd — opendir internally calls getdents64.
    nrs.push_back(__NR_getdents64);

    // Needed for TracerPid hiding: intercept read() so we can tamper with
    // the buffer content after the kernel writes /proc/self/status data.
    // Also used for ELF checksum bypass: tamper read() on library fds.
    nrs.push_back(__NR_read);
#ifdef __NR_pread64
    // Some libc paths read procfs via pread64().
    nrs.push_back(__NR_pread64);
#endif
    // Track fd lifecycle so reused fd numbers do not keep stale tamper state.
    nrs.push_back(__NR_close);
#ifdef __NR_mmap
    // SO load-time hook fallback: linker maps target ELF via mmap.
    nrs.push_back(__NR_mmap);
#endif
#ifdef __NR_mprotect
    // SO load-time hook fallback: constructors typically run after final RX mprotect.
    nrs.push_back(__NR_mprotect);
#endif

    // Process-killing syscalls: intercept to log caller PC and optionally block.
    nrs.push_back(__NR_exit_group);
    nrs.push_back(__NR_kill);
    nrs.push_back(__NR_tgkill);

    return build_seccomp_filter(nrs);
}
