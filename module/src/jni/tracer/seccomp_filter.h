#ifndef ZYGISKFRIDA_TRACER_SECCOMP_FILTER_H
#define ZYGISKFRIDA_TRACER_SECCOMP_FILTER_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <linux/filter.h>
#include <linux/seccomp.h>

// Build a BPF program that returns SECCOMP_RET_TRACE for the given
// syscall numbers and SECCOMP_RET_ALLOW for everything else.
// The caller owns the returned sock_filter memory.
struct seccomp_bpf_program {
    std::vector<struct sock_filter> filter;

    const struct sock_filter* data() const { return filter.data(); }
    size_t size() const { return filter.size(); }
};

// Build filter for a set of syscall numbers to intercept.
seccomp_bpf_program build_seccomp_filter(const std::vector<uint32_t> &syscall_nrs);

// Convenience: build filter for the default anti-cheat IO syscalls.
seccomp_bpf_program build_default_io_filter();

#endif // ZYGISKFRIDA_TRACER_SECCOMP_FILTER_H
