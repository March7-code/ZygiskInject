#include "syscall_rules.h"

#include <sys/syscall.h>

const char *tracer_syscall_name(uint64_t nr) {
    switch (nr) {
#ifdef __NR_openat
        case __NR_openat: return "openat";
#endif
#ifdef __NR_faccessat
        case __NR_faccessat: return "faccessat";
#endif
#ifdef __NR_newfstatat
        case __NR_newfstatat: return "newfstatat";
#endif
#ifdef __NR_readlinkat
        case __NR_readlinkat: return "readlinkat";
#endif
#ifdef __NR_statx
        case __NR_statx: return "statx";
#endif
#ifdef __NR_getdents64
        case __NR_getdents64: return "getdents64";
#endif
#ifdef __NR_read
        case __NR_read: return "read";
#endif
#ifdef __NR_pread64
        case __NR_pread64: return "pread64";
#endif
#ifdef __NR_close
        case __NR_close: return "close";
#endif
#ifdef __NR_mmap
        case __NR_mmap: return "mmap";
#endif
#ifdef __NR_mprotect
        case __NR_mprotect: return "mprotect";
#endif
#ifdef __NR_exit
        case __NR_exit: return "exit";
#endif
#ifdef __NR_exit_group
        case __NR_exit_group: return "exit_group";
#endif
#ifdef __NR_kill
        case __NR_kill: return "kill";
#endif
#ifdef __NR_tkill
        case __NR_tkill: return "tkill";
#endif
#ifdef __NR_tgkill
        case __NR_tgkill: return "tgkill";
#endif
#ifdef __NR_rt_sigqueueinfo
        case __NR_rt_sigqueueinfo: return "rt_sigqueueinfo";
#endif
#ifdef __NR_rt_tgsigqueueinfo
        case __NR_rt_tgsigqueueinfo: return "rt_tgsigqueueinfo";
#endif
#ifdef __NR_pidfd_send_signal
        case __NR_pidfd_send_signal: return "pidfd_send_signal";
#endif
        default: return "unknown";
    }
}

bool tracer_is_process_kill_syscall(uint64_t nr) {
#ifdef __NR_exit_group
    if (nr == __NR_exit_group) return true;
#endif
#ifdef __NR_kill
    if (nr == __NR_kill) return true;
#endif
#ifdef __NR_tgkill
    if (nr == __NR_tgkill) return true;
#endif
#ifdef __NR_exit
    if (nr == __NR_exit) return true;
#endif
#ifdef __NR_tkill
    if (nr == __NR_tkill) return true;
#endif
#ifdef __NR_rt_sigqueueinfo
    if (nr == __NR_rt_sigqueueinfo) return true;
#endif
#ifdef __NR_rt_tgsigqueueinfo
    if (nr == __NR_rt_tgsigqueueinfo) return true;
#endif
#ifdef __NR_pidfd_send_signal
    if (nr == __NR_pidfd_send_signal) return true;
#endif
    return false;
}

bool tracer_extract_kill_signal_arg(uint64_t nr,
                                    uint64_t arg1,
                                    uint64_t arg2,
                                    uint64_t *out_sig) {
    if (!out_sig) return false;

    if (false) {
#ifdef __NR_kill
    } else if (nr == __NR_kill) {
#endif
#ifdef __NR_tkill
    } else if (nr == __NR_tkill) {
#endif
#ifdef __NR_rt_sigqueueinfo
    } else if (nr == __NR_rt_sigqueueinfo) {
#endif
#ifdef __NR_pidfd_send_signal
    } else if (nr == __NR_pidfd_send_signal) {
#endif
        *out_sig = arg1;
        return true;
    }

    if (false) {
#ifdef __NR_tgkill
    } else if (nr == __NR_tgkill) {
#endif
#ifdef __NR_rt_tgsigqueueinfo
    } else if (nr == __NR_rt_tgsigqueueinfo) {
#endif
        *out_sig = arg2;
        return true;
    }

    return false;
}

std::vector<uint32_t> build_default_tracer_syscall_nrs(bool block_self_kill) {
    std::vector<uint32_t> nrs;

#ifdef __NR_openat
    nrs.push_back(__NR_openat);
#endif
#ifdef __NR_faccessat
    nrs.push_back(__NR_faccessat);
#endif
#ifdef __NR_newfstatat
    nrs.push_back(__NR_newfstatat);
#endif
#ifdef __NR_readlinkat
    nrs.push_back(__NR_readlinkat);
#endif
#ifdef __NR_statx
    nrs.push_back(__NR_statx);
#endif
#ifdef __NR_getdents64
    nrs.push_back(__NR_getdents64);
#endif
#ifdef __NR_read
    nrs.push_back(__NR_read);
#endif
#ifdef __NR_pread64
    nrs.push_back(__NR_pread64);
#endif
#ifdef __NR_close
    nrs.push_back(__NR_close);
#endif
#ifdef __NR_mmap
    nrs.push_back(__NR_mmap);
#endif
#ifdef __NR_mprotect
    nrs.push_back(__NR_mprotect);
#endif

    if (block_self_kill) {
#ifdef __NR_exit
        nrs.push_back(__NR_exit);
#endif
#ifdef __NR_exit_group
        nrs.push_back(__NR_exit_group);
#endif
#ifdef __NR_kill
        nrs.push_back(__NR_kill);
#endif
#ifdef __NR_tkill
        nrs.push_back(__NR_tkill);
#endif
#ifdef __NR_tgkill
        nrs.push_back(__NR_tgkill);
#endif
#ifdef __NR_rt_sigqueueinfo
        nrs.push_back(__NR_rt_sigqueueinfo);
#endif
#ifdef __NR_rt_tgsigqueueinfo
        nrs.push_back(__NR_rt_tgsigqueueinfo);
#endif
#ifdef __NR_pidfd_send_signal
        nrs.push_back(__NR_pidfd_send_signal);
#endif
    }

    return nrs;
}
