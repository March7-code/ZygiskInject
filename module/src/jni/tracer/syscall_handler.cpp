#include "syscall_handler.h"
#include "arch.h"

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../log.h"

#define TAG "[syscall_handler] "

static FILE *g_log_fp = nullptr;
static pid_t g_target_pid = 0;

// =========================================================================
// TracerPid hiding: fd tracking
// =========================================================================
// Track fds that were opened on /proc/self/status or /proc/<pid>/status.
// When read() is called on these fds, we need to tamper with the buffer.

static std::set<uint64_t> g_status_fds;  // fds pointing to proc status

// Check if a path is /proc/self/status or /proc/<target_pid>/status
static bool is_proc_status_path(const std::string &path) {
    if (path == "/proc/self/status") return true;
    char buf[64];
    snprintf(buf, sizeof(buf), "/proc/%d/status", g_target_pid);
    if (path == buf) return true;
    return false;
}

// Set of pids currently waiting for syscall-exit (read on status fd)
static std::set<pid_t> g_waiting_read_exit;

// =========================================================================
// Level-1 fast filter: path prefix check
// =========================================================================
static const char *g_interesting_prefixes[] = {
    "/proc/",
    "/data/local/tmp",
    "/data/adb/",
    "/sys/",
    nullptr
};

static bool peek_prefix(pid_t pid, uint64_t addr, char out[8]) {
    if (addr == 0) return false;
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, nullptr);
    if (errno != 0) return false;
    memcpy(out, &word, 8);
    return true;
}

static bool is_interesting_prefix(const char prefix[8]) {
    for (int i = 0; g_interesting_prefixes[i]; i++) {
        const char *p = g_interesting_prefixes[i];
        size_t len = strlen(p);
        if (len > 8) len = 8;
        if (memcmp(prefix, p, len) == 0) return true;
    }
    return false;
}

// =========================================================================
// Level-2: maps cache
// =========================================================================
struct maps_entry {
    uint64_t start;
    uint64_t end;
    char name[256];
};

static std::vector<maps_entry> g_maps_cache;
static uint64_t g_maps_cache_time = 0;

static uint64_t now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void refresh_maps_cache(pid_t pid) {
    uint64_t now = now_ms();
    if (!g_maps_cache.empty() && (now - g_maps_cache_time) < 1000) return;
    g_maps_cache.clear();
    g_maps_cache_time = now;

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        maps_entry e{};
        char perms[8];
        unsigned long offset, dev_major, dev_minor, inode;
        int n = sscanf(line, "%" PRIx64 "-%" PRIx64 " %4s %lx %lx:%lx %lu %255s",
                       &e.start, &e.end, perms, &offset,
                       &dev_major, &dev_minor, &inode, e.name);
        if (n >= 2) g_maps_cache.push_back(e);
    }
    fclose(fp);
}

static std::string resolve_caller_cached(pid_t pid, uint64_t pc) {
    refresh_maps_cache(pid);
    for (auto &e : g_maps_cache) {
        if (pc >= e.start && pc < e.end) {
            const char *basename = strrchr(e.name, '/');
            basename = basename ? basename + 1 : e.name;
            char buf[320];
            snprintf(buf, sizeof(buf), "%s+0x%" PRIx64, basename, pc - e.start);
            return buf;
        }
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%" PRIx64, pc);
    return buf;
}

// =========================================================================
// Level-3: fd cache for getdents64
// =========================================================================
static std::map<uint64_t, std::string> g_fd_cache;

static const std::string& resolve_fd_cached(pid_t pid, uint64_t fd_val) {
    auto it = g_fd_cache.find(fd_val);
    if (it != g_fd_cache.end()) return it->second;

    char link_path[64];
    char target[256] = {0};
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%llu",
             pid, (unsigned long long)fd_val);
    ssize_t len = readlink(link_path, target, sizeof(target) - 1);
    if (len > 0) target[len] = '\0';

    g_fd_cache[fd_val] = target;
    return g_fd_cache[fd_val];
}

static uint64_t g_fd_cache_time = 0;
static void maybe_flush_fd_cache() {
    uint64_t now = now_ms();
    if ((now - g_fd_cache_time) > 5000) {
        g_fd_cache.clear();
        g_fd_cache_time = now;
    }
}

// =========================================================================
// Read full string from tracee
// =========================================================================
static std::string read_tracee_string(pid_t pid, uint64_t addr, size_t max_len = 256) {
    std::string result;
    if (addr == 0) return "(null)";
    for (size_t off = 0; off < max_len; off += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           (void*)(addr + off), nullptr);
        if (errno != 0) { result += "<?>"; break; }
        const char *bytes = reinterpret_cast<const char*>(&word);
        for (size_t i = 0; i < sizeof(long); i++) {
            if (bytes[i] == '\0') return result;
            result += bytes[i];
        }
    }
    return result;
}

// =========================================================================
// Write bytes into tracee memory via PTRACE_POKEDATA
// =========================================================================
static bool write_tracee_mem(pid_t pid, uint64_t addr,
                             const void *data, size_t len) {
    const uint8_t *src = (const uint8_t*)data;
    size_t off = 0;
    while (off < len) {
        long word;
        if (off + sizeof(long) <= len) {
            memcpy(&word, src + off, sizeof(long));
        } else {
            // Partial word: read-modify-write
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid,
                          (void*)(addr + off), nullptr);
            if (errno != 0) return false;
            memcpy(&word, src + off, len - off);
        }
        if (ptrace(PTRACE_POKEDATA, pid,
                   (void*)(addr + off), (void*)word) < 0)
            return false;
        off += sizeof(long);
    }
    return true;
}

// =========================================================================
// Read bytes from tracee memory via PTRACE_PEEKDATA
// =========================================================================
static bool read_tracee_mem(pid_t pid, uint64_t addr,
                            void *out, size_t len) {
    uint8_t *dst = (uint8_t*)out;
    size_t off = 0;
    while (off < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           (void*)(addr + off), nullptr);
        if (errno != 0) return false;
        size_t chunk = (off + sizeof(long) <= len) ? sizeof(long) : (len - off);
        memcpy(dst + off, &word, chunk);
        off += sizeof(long);
    }
    return true;
}

// =========================================================================
// TracerPid tampering: scan buffer and replace TracerPid value with 0
// =========================================================================
// /proc/self/status format: "TracerPid:\t<number>\n"
// We replace the number with "0" and pad the rest with spaces until newline.
static bool tamper_tracer_pid(pid_t pid, uint64_t buf_addr, size_t buf_len) {
    if (buf_len == 0 || buf_len > 8192) return false;

    std::vector<char> buf(buf_len);
    if (!read_tracee_mem(pid, buf_addr, buf.data(), buf_len))
        return false;

    // Search for "TracerPid:\t"
    const char *needle = "TracerPid:\t";
    size_t needle_len = strlen(needle);
    char *pos = nullptr;
    for (size_t i = 0; i + needle_len <= buf_len; i++) {
        if (memcmp(buf.data() + i, needle, needle_len) == 0) {
            pos = buf.data() + i;
            break;
        }
    }
    if (!pos) return false;  // TracerPid line not in this read chunk

    // Found it. Replace the number after "TracerPid:\t" with "0"
    // and pad with spaces until the newline.
    char *num_start = pos + needle_len;
    char *buf_end = buf.data() + buf_len;

    // Find the newline
    char *nl = num_start;
    while (nl < buf_end && *nl != '\n') nl++;

    // Write "0" then spaces until newline
    if (num_start < buf_end) {
        *num_start = '0';
        for (char *p = num_start + 1; p < nl; p++)
            *p = ' ';
    }

    // Write the modified region back
    size_t mod_offset = (size_t)(num_start - buf.data());
    size_t mod_len = (size_t)(nl - num_start);
    if (mod_len > 0) {
        uint64_t write_addr = buf_addr + mod_offset;
        if (!write_tracee_mem(pid, write_addr, num_start, mod_len)) {
            LOGE(TAG "POKEDATA failed for TracerPid tamper: %s",
                 strerror(errno));
            return false;
        }
    }

    LOGI(TAG "TracerPid tampered for pid %d", pid);
    return true;
}

// =========================================================================
// Syscall name lookup
// =========================================================================
static const char* syscall_name(uint64_t nr) {
    switch (nr) {
        case __NR_openat:     return "openat";
        case __NR_faccessat:  return "faccessat";
#ifdef __NR_newfstatat
        case __NR_newfstatat: return "newfstatat";
#endif
        case __NR_readlinkat: return "readlinkat";
#ifdef __NR_statx
        case __NR_statx:      return "statx";
#endif
        case __NR_getdents64: return "getdents64";
        case __NR_read:       return "read";
        default:              return "unknown";
    }
}

// =========================================================================
// Statistics
// =========================================================================
static uint64_t g_stat_total = 0;
static uint64_t g_stat_filtered = 0;
static uint64_t g_stat_logged = 0;
static uint64_t g_stat_tampered = 0;
static uint64_t g_stat_last_report = 0;

static void maybe_report_stats() {
    uint64_t now = now_ms();
    if ((now - g_stat_last_report) < 10000) return;
    g_stat_last_report = now;

    if (g_log_fp && g_stat_total > 0) {
        fprintf(g_log_fp,
                "--- stats: total=%llu filtered=%llu logged=%llu tampered=%llu (%.1f%% filtered) ---\n",
                (unsigned long long)g_stat_total,
                (unsigned long long)g_stat_filtered,
                (unsigned long long)g_stat_logged,
                (unsigned long long)g_stat_tampered,
                g_stat_total > 0 ? (100.0 * g_stat_filtered / g_stat_total) : 0.0);
        fflush(g_log_fp);
    }
    LOGI(TAG "stats: total=%llu filtered=%llu logged=%llu tampered=%llu",
         (unsigned long long)g_stat_total,
         (unsigned long long)g_stat_filtered,
         (unsigned long long)g_stat_logged,
         (unsigned long long)g_stat_tampered);
}

// =========================================================================
// Log a single syscall event
// =========================================================================
static void log_syscall(pid_t pid, const char *name,
                        const char *path, const char *caller) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (g_log_fp) {
        fprintf(g_log_fp, "[%ld.%03ld] pid=%d %s(\"%s\") from %s\n",
                ts.tv_sec, ts.tv_nsec / 1000000,
                pid, name, path, caller);
        static int flush_counter = 0;
        if (++flush_counter >= 16) {
            fflush(g_log_fp);
            flush_counter = 0;
        }
    }
}

// =========================================================================
// Public API
// =========================================================================

void syscall_handler_init(pid_t target_pid, const std::string &log_path) {
    g_target_pid = target_pid;
    g_stat_total = g_stat_filtered = g_stat_logged = g_stat_tampered = 0;
    g_stat_last_report = now_ms();
    g_fd_cache_time = now_ms();
    g_status_fds.clear();
    g_waiting_read_exit.clear();

    if (!log_path.empty()) {
        // Ensure parent directory exists (tracer runs as root)
        std::string dir = log_path.substr(0, log_path.rfind('/'));
        if (!dir.empty()) {
            mkdir(dir.c_str(), 0755);
        }
        g_log_fp = fopen(log_path.c_str(), "a");
        if (!g_log_fp) {
            LOGE(TAG "failed to open log %s: %s",
                 log_path.c_str(), strerror(errno));
        } else {
            fprintf(g_log_fp, "=== tracer started, target pid=%d ===\n",
                    target_pid);
            fflush(g_log_fp);
        }
    }
}

seccomp_action handle_seccomp_stop(pid_t pid) {
    g_stat_total++;

    tracer_regs regs;
    if (!tracer_getregs(pid, regs)) {
        LOGE(TAG "GETREGSET failed for pid %d: %s", pid, strerror(errno));
        return SECCOMP_ACT_CONTINUE;
    }

    uint64_t nr = tracer_get_syscall_nr(regs);

    // --- Handle read() on tracked status fds ---
    if (nr == __NR_read) {
        uint64_t fd_val = tracer_get_arg(regs, 0);
        if (g_status_fds.count(fd_val)) {
            // This is a read on /proc/self/status — we need syscall-exit
            // to tamper with the buffer after the kernel fills it.
            g_waiting_read_exit.insert(pid);
            return SECCOMP_ACT_WAIT_EXIT;
        }
        // read() on non-status fd: skip entirely
        g_stat_filtered++;
        maybe_report_stats();
        return SECCOMP_ACT_CONTINUE;
    }

    // --- For openat: check if it opens /proc/self/status ---
    if (nr == __NR_openat) {
        uint64_t path_addr = tracer_get_arg(regs, 1);
        char prefix[8] = {0};
        if (peek_prefix(pid, path_addr, prefix)) {
            if (is_interesting_prefix(prefix)) {
                std::string path = read_tracee_string(pid, path_addr);
                if (is_proc_status_path(path)) {
                    // We need the fd returned by openat to track it.
                    // Mark this pid for syscall-exit handling.
                    g_waiting_read_exit.insert(pid);
                    // Log it
                    uint64_t pc = tracer_get_pc(regs);
                    std::string caller = resolve_caller_cached(pid, pc);
                    log_syscall(pid, "openat", path.c_str(), caller.c_str());
                    g_stat_logged++;
                    return SECCOMP_ACT_WAIT_EXIT;
                }
                // Interesting path but not status — log normally
                uint64_t pc = tracer_get_pc(regs);
                std::string caller = resolve_caller_cached(pid, pc);
                log_syscall(pid, "openat", path.c_str(), caller.c_str());
                g_stat_logged++;
                maybe_report_stats();
                return SECCOMP_ACT_CONTINUE;
            }
        }
        g_stat_filtered++;
        maybe_report_stats();
        return SECCOMP_ACT_CONTINUE;
    }

    // --- Level-1 filter for other *at syscalls ---
    if (nr != __NR_getdents64) {
        uint64_t path_addr = tracer_get_arg(regs, 1);
        char prefix[8] = {0};
        if (peek_prefix(pid, path_addr, prefix)) {
            if (!is_interesting_prefix(prefix)) {
                g_stat_filtered++;
                maybe_report_stats();
                return SECCOMP_ACT_CONTINUE;
            }
        }
    } else {
        maybe_flush_fd_cache();
        uint64_t fd_val = tracer_get_arg(regs, 0);
        const std::string &fd_path = resolve_fd_cached(pid, fd_val);
        if (fd_path.find("/proc/") == std::string::npos) {
            g_stat_filtered++;
            maybe_report_stats();
            return SECCOMP_ACT_CONTINUE;
        }
    }

    // --- Level-2: full path + caller ---
    uint64_t pc = tracer_get_pc(regs);
    std::string caller = resolve_caller_cached(pid, pc);

    if (nr == __NR_getdents64) {
        uint64_t fd_val = tracer_get_arg(regs, 0);
        const std::string &fd_path = resolve_fd_cached(pid, fd_val);
        log_syscall(pid, "getdents64", fd_path.c_str(), caller.c_str());
    } else {
        uint64_t path_addr = tracer_get_arg(regs, 1);
        std::string path = read_tracee_string(pid, path_addr);
        log_syscall(pid, syscall_name(nr), path.c_str(), caller.c_str());
    }

    g_stat_logged++;
    maybe_report_stats();
    return SECCOMP_ACT_CONTINUE;
}

void handle_syscall_exit(pid_t pid) {
    tracer_regs regs;
    if (!tracer_getregs(pid, regs)) {
        LOGE(TAG "GETREGSET failed on exit for pid %d", pid);
        g_waiting_read_exit.erase(pid);
        return;
    }

    uint64_t nr = tracer_get_syscall_nr(regs);
    int64_t ret = (int64_t)tracer_get_retval(regs);

    if (nr == __NR_openat) {
        // openat returned — ret is the new fd (or negative on error)
        if (ret >= 0) {
            g_status_fds.insert((uint64_t)ret);
            LOGI(TAG "tracking status fd=%lld for pid %d",
                 (long long)ret, pid);
        }
    } else if (nr == __NR_read) {
        // read returned — ret is bytes read (or negative on error)
        if (ret > 0) {
            uint64_t buf_addr = tracer_get_arg(regs, 1);
            if (tamper_tracer_pid(pid, buf_addr, (size_t)ret)) {
                g_stat_tampered++;
                if (g_log_fp) {
                    fprintf(g_log_fp,
                            "[tamper] pid=%d read() on status fd, "
                            "replaced TracerPid, %lld bytes\n",
                            pid, (long long)ret);
                    fflush(g_log_fp);
                }
            }
        }
    }

    g_waiting_read_exit.erase(pid);
}

void syscall_handler_fini() {
    if (g_log_fp) {
        fprintf(g_log_fp,
                "=== tracer finished: total=%llu filtered=%llu "
                "logged=%llu tampered=%llu ===\n",
                (unsigned long long)g_stat_total,
                (unsigned long long)g_stat_filtered,
                (unsigned long long)g_stat_logged,
                (unsigned long long)g_stat_tampered);
        fclose(g_log_fp);
        g_log_fp = nullptr;
    }
}
