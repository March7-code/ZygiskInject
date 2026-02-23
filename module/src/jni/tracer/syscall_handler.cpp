#include "syscall_handler.h"
#include "arch.h"

#include <algorithm>
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

// Forward declarations
static void refresh_maps_cache(pid_t pid);
static bool read_tracee_mem(pid_t pid, uint64_t addr, void *out, size_t len);
static bool write_tracee_mem(pid_t pid, uint64_t addr, const void *data, size_t len);

// Keep ptrace memory accesses robust on ARM64 with top-byte tags.
static inline uint64_t untag_user_addr(uint64_t addr) {
    return addr & 0x00FFFFFFFFFFFFFFULL;
}

// =========================================================================
// TracerPid hiding: fd tracking
// =========================================================================
// Track fds that were opened on /proc/self/status or /proc/<pid>/status.
// When read() is called on these fds, we need to tamper with the buffer.

struct tracked_fd_key {
    pid_t tgid;
    uint64_t fd;

    bool operator<(const tracked_fd_key &other) const {
        if (tgid != other.tgid) return tgid < other.tgid;
        return fd < other.fd;
    }
};

static std::map<pid_t, pid_t> g_tid_to_tgid_cache;

static pid_t resolve_tracee_tgid(pid_t tid) {
    auto it = g_tid_to_tgid_cache.find(tid);
    if (it != g_tid_to_tgid_cache.end()) return it->second;

    char status_path[64];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", tid);
    FILE *fp = fopen(status_path, "r");
    if (!fp) {
        g_tid_to_tgid_cache[tid] = tid;
        return tid;
    }

    char line[256];
    pid_t tgid = tid;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Tgid:", 5) == 0) {
            // "Tgid:\t12345"
            int parsed = 0;
            if (sscanf(line + 5, "%d", &parsed) == 1 && parsed > 0) {
                tgid = (pid_t)parsed;
            }
            break;
        }
    }
    fclose(fp);

    g_tid_to_tgid_cache[tid] = tgid;
    return tgid;
}

static inline tracked_fd_key make_fd_key(pid_t tid, uint64_t fd) {
    return tracked_fd_key{resolve_tracee_tgid(tid), fd};
}

static std::set<tracked_fd_key> g_status_fds;  // (tgid, fd) for proc status

static bool is_proc_task_status_path(const std::string &path,
                                     const std::string &prefix) {
    // Match "<prefix><tid>/status", where <tid> is decimal.
    if (path.rfind(prefix, 0) != 0) return false;

    size_t tid_start = prefix.size();
    size_t slash_pos = path.find('/', tid_start);
    if (slash_pos == std::string::npos) return false;
    if (slash_pos + 7 != path.size()) return false;
    if (path.compare(slash_pos, 7, "/status") != 0) return false;

    if (slash_pos == tid_start) return false;
    for (size_t i = tid_start; i < slash_pos; ++i) {
        char c = path[i];
        if (c < '0' || c > '9') return false;
    }
    return true;
}

static bool parse_proc_numeric_leaf(const std::string &path,
                                    const char *leaf,
                                    pid_t *out_pid) {
    const std::string prefix = "/proc/";
    if (path.rfind(prefix, 0) != 0) return false;

    size_t num_start = prefix.size();
    size_t slash_pos = path.find('/', num_start);
    if (slash_pos == std::string::npos) return false;
    if (slash_pos + 1 >= path.size()) return false;

    const std::string suffix = std::string("/") + leaf;
    if (path.compare(slash_pos, suffix.size(), suffix) != 0) return false;
    if (slash_pos + suffix.size() != path.size()) return false;

    if (slash_pos == num_start) return false;
    int value = 0;
    for (size_t i = num_start; i < slash_pos; ++i) {
        char c = path[i];
        if (c < '0' || c > '9') return false;
        value = value * 10 + (c - '0');
    }
    if (value <= 0) return false;
    if (out_pid) *out_pid = (pid_t)value;
    return true;
}

// Check if a path is one of:
// - /proc/self/status
// - /proc/<target_pid>/status
// - /proc/self/task/<tid>/status
// - /proc/<target_pid>/task/<tid>/status
static bool is_proc_status_path(const std::string &path) {
    if (path == "/proc/self/status") return true;
    if (path == "/proc/thread-self/status") return true;

    char buf[64];
    snprintf(buf, sizeof(buf), "/proc/%d/status", g_target_pid);
    if (path == buf) return true;

    pid_t proc_pid = 0;
    if (parse_proc_numeric_leaf(path, "status", &proc_pid)) {
        if (proc_pid == g_target_pid) return true;
        if (resolve_tracee_tgid(proc_pid) == g_target_pid) return true;
    }

    if (is_proc_task_status_path(path, "/proc/self/task/")) return true;

    snprintf(buf, sizeof(buf), "/proc/%d/task/", g_target_pid);
    if (is_proc_task_status_path(path, buf)) return true;

    return false;
}

// Set of pids currently waiting for syscall-exit (read on status fd)
static std::set<pid_t> g_waiting_read_exit;

struct pending_exit_state {
    uint64_t nr = 0;
    uint64_t args[6] = {0, 0, 0, 0, 0, 0};
};
static std::map<pid_t, pending_exit_state> g_pending_exit;

static inline void remember_pending_exit(pid_t tid, const tracer_regs &regs) {
    pending_exit_state st{};
    st.nr = tracer_get_syscall_nr(regs);
    for (int i = 0; i < 6; ++i) {
        st.args[i] = tracer_get_arg(regs, i);
    }
    g_pending_exit[tid] = st;
}

// =========================================================================
// ELF checksum bypass: /proc/self/maps tampering
// =========================================================================
// The detection code (detect_frida_memdiskcompare) reads /proc/self/maps
// to find executable segments of protected libraries, then compares the
// in-memory checksum against a pre-computed disk checksum.  Frida modifies
// the .text section in memory, causing a mismatch.
//
// Strategy: intercept read() on /proc/self/maps fds and change the
// permission field from "r-xp" to "r--p" for protected library lines.
// This makes scan_executable_segments() skip the checksum comparison
// because buf[2] != 'x'.

// fds pointing to /proc/self/maps (tracked like status fds)
static std::set<tracked_fd_key> g_maps_fds;
static uint64_t g_maps_stage_start_ms = 0;

// Library names to protect (basenames). Populated at init.
static std::vector<std::string> g_protected_libs;
struct maps_fd_state {
    bool tamper_enabled = false;
    size_t stream_pos = 0;
    std::string sanitized_maps;
};
static std::map<tracked_fd_key, maps_fd_state> g_maps_fd_states;

// Check if a path is /proc/self/maps or /proc/<pid>/maps
static bool is_proc_maps_path(const std::string &path) {
    if (path == "/proc/self/maps") return true;
    if (path == "/proc/thread-self/maps") return true;
    char buf[64];
    snprintf(buf, sizeof(buf), "/proc/%d/maps", g_target_pid);
    if (path == buf) return true;

    pid_t proc_pid = 0;
    if (parse_proc_numeric_leaf(path, "maps", &proc_pid)) {
        if (proc_pid == g_target_pid) return true;
        if (resolve_tracee_tgid(proc_pid) == g_target_pid) return true;
    }
    return false;
}

static void sanitize_maps_line(std::string &line) {
    bool is_protected = false;
    for (const auto &lib : g_protected_libs) {
        if (line.find(lib) != std::string::npos) {
            is_protected = true;
            break;
        }
    }
    if (!is_protected) return;

    // maps line: "<start>-<end> <perms> ..."
    size_t perms_pos = line.find(' ');
    if (perms_pos == std::string::npos) return;
    while (perms_pos < line.size() && line[perms_pos] == ' ')
        perms_pos++;

    if (perms_pos + 2 < line.size() && line[perms_pos + 2] == 'x') {
        line[perms_pos + 2] = '-';
    }
}

static bool build_sanitized_maps_snapshot(pid_t pid, std::string &out) {
    out.clear();

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return false;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        std::string s(line);
        sanitize_maps_line(s);
        out += s;
    }
    fclose(fp);
    return !out.empty();
}

// Tamper a read() buffer from /proc/self/maps: for lines containing a
// protected library name with executable permission, change 'x' to '-'
// in the permission field so the detection skips checksum comparison.
//
// Maps line format: "start-end perms offset dev inode pathname\n"
// Example: "7a8c000000-7a8c100000 r-xp 00000000 fe:06 123 /apex/.../libc.so\n"
// We change "r-xp" to "r--p" for lines matching protected libs.
static bool tamper_maps_read_chunk(pid_t pid, uint64_t buf_addr, size_t bytes_read) {
    if (bytes_read == 0) return false;

    std::vector<char> buf(bytes_read);
    if (!read_tracee_mem(pid, buf_addr, buf.data(), bytes_read))
        return false;

    bool tampered = false;
    size_t i = 0;
    while (i < bytes_read) {
        // Find end of current line
        size_t line_start = i;
        while (i < bytes_read && buf[i] != '\n') i++;
        size_t line_end = i;
        if (i < bytes_read) i++;  // skip '\n'

        size_t line_len = line_end - line_start;
        if (line_len < 20) continue;  // too short to be a valid maps line

        // Check if this line contains any protected library name
        bool is_protected = false;
        for (auto &lib : g_protected_libs) {
            // Search for the library name in this line
            for (size_t j = line_start; j + lib.size() <= line_end; j++) {
                if (memcmp(buf.data() + j, lib.data(), lib.size()) == 0) {
                    is_protected = true;
                    break;
                }
            }
            if (is_protected) break;
        }
        if (!is_protected) continue;

        // Find the permissions field (after the first space)
        // Format: "addr-addr perms ..."
        size_t space_pos = line_start;
        while (space_pos < line_end && buf[space_pos] != ' ') space_pos++;
        if (space_pos >= line_end) continue;
        space_pos++;  // skip space

        // perms is 4 chars: rwxp/rwxs
        if (space_pos + 3 >= line_end) continue;

        // Check if this is an executable mapping (perms[2] == 'x')
        if (buf[space_pos + 2] == 'x') {
            buf[space_pos + 2] = '-';  // r-xp -> r--p
            tampered = true;
            LOGI(TAG "maps_bypass: hid executable perm for protected lib");
        }
    }

    if (tampered) {
        if (!write_tracee_mem(pid, buf_addr, buf.data(), bytes_read)) {
            LOGE(TAG "maps_bypass: POKEDATA failed");
            return false;
        }
    }
    return tampered;
}

// Stream-aware maps tamper:
// Many anti-Frida samples read /proc/self/maps byte-by-byte via read(fd, &c, 1).
// Chunk-only tampering misses that pattern, so we keep a per-fd sanitized
// snapshot and rewrite returned bytes by stream position.
static bool tamper_maps_read_stream(pid_t pid,
                                    uint64_t fd_val,
                                    uint64_t buf_addr,
                                    size_t bytes_read) {
    if (bytes_read == 0) return false;

    tracked_fd_key key = make_fd_key(pid, fd_val);
    auto it = g_maps_fd_states.find(key);
    if (it == g_maps_fd_states.end()) {
        return tamper_maps_read_chunk(pid, buf_addr, bytes_read);
    }

    maps_fd_state &state = it->second;
    if (!state.tamper_enabled) {
        if (g_log_fp) {
            fprintf(g_log_fp,
                    "[maps_bypass] stream skip (disabled): tid=%d tgid=%d fd=%llu bytes=%zu pos=%zu\n",
                    pid, key.tgid, (unsigned long long)fd_val, bytes_read, state.stream_pos);
            fflush(g_log_fp);
        }
        state.stream_pos += bytes_read;
        return false;
    }

    if (state.sanitized_maps.empty()) {
        if (!build_sanitized_maps_snapshot(g_target_pid, state.sanitized_maps)) {
            // Fallback to chunk mode if snapshot cannot be built.
            state.stream_pos += bytes_read;
            return tamper_maps_read_chunk(pid, buf_addr, bytes_read);
        }
    }

    std::vector<char> original(bytes_read);
    if (!read_tracee_mem(pid, buf_addr, original.data(), bytes_read))
        return false;

    std::vector<char> patched = original;
    if (state.stream_pos < state.sanitized_maps.size()) {
        size_t copy_len = std::min(bytes_read,
                                   state.sanitized_maps.size() - state.stream_pos);
        memcpy(patched.data(),
               state.sanitized_maps.data() + state.stream_pos,
               copy_len);
    }
    state.stream_pos += bytes_read;

    if (memcmp(original.data(), patched.data(), bytes_read) == 0)
        return false;

    if (!write_tracee_mem(pid, buf_addr, patched.data(), bytes_read)) {
        LOGE(TAG "maps_bypass: stream POKEDATA failed");
        return false;
    }
    return true;
}

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
    addr = untag_user_addr(addr);
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
static std::map<tracked_fd_key, std::string> g_fd_cache;

static const std::string& resolve_fd_cached(pid_t pid, uint64_t fd_val) {
    tracked_fd_key key = make_fd_key(pid, fd_val);
    auto it = g_fd_cache.find(key);
    if (it != g_fd_cache.end()) return it->second;

    char link_path[64];
    char target[256] = {0};
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%llu",
             pid, (unsigned long long)fd_val);
    ssize_t len = readlink(link_path, target, sizeof(target) - 1);
    if (len > 0) target[len] = '\0';

    g_fd_cache[key] = target;
    return g_fd_cache[key];
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
    addr = untag_user_addr(addr);
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
    addr = untag_user_addr(addr);
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
    addr = untag_user_addr(addr);
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
#ifdef __NR_pread64
        case __NR_pread64:    return "pread64";
#endif
        case __NR_close:      return "close";
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
    g_maps_stage_start_ms = now_ms();
    g_stat_total = g_stat_filtered = g_stat_logged = g_stat_tampered = 0;
    g_stat_last_report = now_ms();
    g_fd_cache_time = now_ms();
    g_tid_to_tgid_cache.clear();
    g_status_fds.clear();
    g_maps_fds.clear();
    g_maps_fd_states.clear();
    g_waiting_read_exit.clear();
    g_pending_exit.clear();

    // Default protected libraries for ELF checksum bypass.
    // These are the libraries that DetectFrida checks via memdisk compare.
    // TODO: make this configurable via config.json in the future.
    g_protected_libs.clear();
    g_protected_libs.push_back("libc.so");
    g_protected_libs.push_back("libnative-lib.so");

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

    // close() cleanup for tracked fds (maps/status).
    // We only clean tracked fds on close-exit when ret == 0.
    if (nr == __NR_close) {
        uint64_t fd_val = tracer_get_arg(regs, 0);
        tracked_fd_key key = make_fd_key(pid, fd_val);
        if (g_maps_fds.count(key) || g_status_fds.count(key)) {
            g_waiting_read_exit.insert(pid);
            remember_pending_exit(pid, regs);
            return SECCOMP_ACT_WAIT_EXIT;
        }
        // close() on non-tracked fd: keep fast path.
        g_fd_cache.erase(key);
        g_stat_filtered++;
        maybe_report_stats();
        return SECCOMP_ACT_CONTINUE;
    }

    // --- For openat: check if it opens maps/status files we may tamper ---
    if (nr == __NR_openat) {
        uint64_t path_addr = tracer_get_arg(regs, 1);
        char prefix[8] = {0};
        bool have_prefix = peek_prefix(pid, path_addr, prefix);

        bool maybe_interesting = have_prefix && is_interesting_prefix(prefix);

        if (maybe_interesting) {
            std::string path = read_tracee_string(pid, path_addr);

            // Check /proc/self/maps for checksum bypass
            if (is_proc_maps_path(path) && !g_protected_libs.empty()) {
                g_waiting_read_exit.insert(pid);
                remember_pending_exit(pid, regs);
                uint64_t pc = tracer_get_pc(regs);
                std::string caller = resolve_caller_cached(pid, pc);
                log_syscall(pid, "openat", path.c_str(), caller.c_str());
                g_stat_logged++;
                if (g_log_fp) {
                    fprintf(g_log_fp,
                            "[maps_bypass] detected openat on %s\n",
                            path.c_str());
                    fflush(g_log_fp);
                }
                return SECCOMP_ACT_WAIT_EXIT;
            }

            // Check /proc/self/status for TracerPid hiding
            if (is_proc_status_path(path)) {
                g_waiting_read_exit.insert(pid);
                remember_pending_exit(pid, regs);
                uint64_t pc = tracer_get_pc(regs);
                std::string caller = resolve_caller_cached(pid, pc);
                log_syscall(pid, "openat", path.c_str(), caller.c_str());
                g_stat_logged++;
                return SECCOMP_ACT_WAIT_EXIT;
            }

            // Interesting path but not maps/status — log normally
            uint64_t pc = tracer_get_pc(regs);
            std::string caller = resolve_caller_cached(pid, pc);
            log_syscall(pid, syscall_name(nr), path.c_str(), caller.c_str());
            g_stat_logged++;
            maybe_report_stats();
            return SECCOMP_ACT_CONTINUE;
        }
        g_stat_filtered++;
        maybe_report_stats();
        return SECCOMP_ACT_CONTINUE;
    }
    if (nr == __NR_read
#ifdef __NR_pread64
        || nr == __NR_pread64
#endif
    ) {
        uint64_t fd_val = tracer_get_arg(regs, 0);
        tracked_fd_key key = make_fd_key(pid, fd_val);
        if (!g_maps_fds.count(key) && !g_status_fds.count(key)) {
            // Recovery path: if openat-exit tracking missed this fd, detect maps/status
            // directly from /proc/<tid>/fd/<fd> and add it lazily.
            const std::string &fd_path = resolve_fd_cached(pid, fd_val);
            if (is_proc_maps_path(fd_path) && !g_protected_libs.empty()) {
                g_maps_fds.insert(key);
                auto it = g_maps_fd_states.find(key);
                if (it == g_maps_fd_states.end()) {
                    maps_fd_state state{};
                    uint64_t age_ms = now_ms() - g_maps_stage_start_ms;
                    state.tamper_enabled = (key.tgid != g_target_pid) || (age_ms > 1500);
                    if (state.tamper_enabled) {
                        build_sanitized_maps_snapshot(g_target_pid, state.sanitized_maps);
                    }
                    g_maps_fd_states[key] = std::move(state);
                }
                if (g_log_fp) {
                    fprintf(g_log_fp,
                            "[maps_bypass] late-track maps fd: tid=%d tgid=%d fd=%llu path=%s\n",
                            pid, key.tgid, (unsigned long long)fd_val, fd_path.c_str());
                }
            } else if (is_proc_status_path(fd_path)) {
                g_status_fds.insert(key);
                if (g_log_fp) {
                    fprintf(g_log_fp,
                            "[tamper] late-track status fd: tid=%d tgid=%d fd=%llu path=%s\n",
                            pid, key.tgid, (unsigned long long)fd_val, fd_path.c_str());
                }
            }
        }

        // Check maps fds first (checksum bypass)
        if (g_maps_fds.count(key)) {
            if (g_log_fp) {
                fprintf(g_log_fp,
                        "[maps_bypass] read wait: tid=%d tgid=%d fd=%llu\n",
                        pid, key.tgid, (unsigned long long)fd_val);
                fflush(g_log_fp);
            }
            g_waiting_read_exit.insert(pid);
            remember_pending_exit(pid, regs);
            return SECCOMP_ACT_WAIT_EXIT;
        }
        // Then check status fds (TracerPid bypass)
        if (g_status_fds.count(key)) {
            g_waiting_read_exit.insert(pid);
            remember_pending_exit(pid, regs);
            return SECCOMP_ACT_WAIT_EXIT;
        }
        // read() on non-tracked fd: skip entirely
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
    pending_exit_state pending{};
    bool have_pending = false;
    auto pending_it = g_pending_exit.find(pid);
    if (pending_it != g_pending_exit.end()) {
        pending = pending_it->second;
        g_pending_exit.erase(pending_it);
        have_pending = true;
    }

    tracer_regs regs;
    if (!tracer_getregs(pid, regs)) {
        LOGE(TAG "GETREGSET failed on exit for pid %d", pid);
        g_waiting_read_exit.erase(pid);
        return;
    }

    uint64_t nr = have_pending ? pending.nr : tracer_get_syscall_nr(regs);
    int64_t ret = (int64_t)tracer_get_retval(regs);

    if (nr == __NR_close) {
        uint64_t fd_val = have_pending ? pending.args[0] : tracer_get_arg(regs, 0);
        tracked_fd_key key = make_fd_key(pid, fd_val);
        if (ret == 0) {
            g_maps_fds.erase(key);
            g_maps_fd_states.erase(key);
            g_status_fds.erase(key);
        }
        g_fd_cache.erase(key);
    } else if (nr == __NR_openat) {
        if (ret >= 0) {
            // Resolve what path was opened via /proc/<pid>/fd/<fd>
            char link_path[64], target[256] = {0};
            snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%lld",
                     pid, (long long)ret);
            ssize_t len = readlink(link_path, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                std::string path_str(target);
                if (is_proc_maps_path(path_str)) {
                    uint64_t fd_val = (uint64_t)ret;
                    tracked_fd_key key = make_fd_key(pid, fd_val);
                    g_maps_fds.insert(key);
                    g_fd_cache.erase(key);

                    maps_fd_state state{};
                    // Avoid breaking constructor-time bootstrap that parses
                    // executable mappings before checksums are captured.
                    uint64_t age_ms = now_ms() - g_maps_stage_start_ms;
                    state.tamper_enabled = (key.tgid != g_target_pid) || (age_ms > 1500);
                    if (state.tamper_enabled) {
                        if (!build_sanitized_maps_snapshot(g_target_pid, state.sanitized_maps)) {
                            LOGW(TAG "maps_bypass: failed to prebuild sanitized snapshot for pid %d",
                                 g_target_pid);
                        }
                    }
                    g_maps_fd_states[key] = std::move(state);

                    LOGI(TAG "maps_bypass: tracking maps fd=%lld for pid %d",
                         (long long)ret, pid);
                    if (g_log_fp) {
                        fprintf(g_log_fp,
                                "[maps_bypass] tracking maps fd=%lld -> %s (enabled=%d)\n",
                                (long long)ret, target,
                                g_maps_fd_states[key].tamper_enabled ? 1 : 0);
                        fflush(g_log_fp);
                    }
                } else if (is_proc_status_path(path_str)) {
                    tracked_fd_key key = make_fd_key(pid, (uint64_t)ret);
                    g_status_fds.insert(key);
                    LOGI(TAG "tracking status fd=%lld for pid %d",
                         (long long)ret, pid);
                }
            } else {
                // Fallback: couldn't readlink, try status fd tracking
                tracked_fd_key key = make_fd_key(pid, (uint64_t)ret);
                g_status_fds.insert(key);
                LOGI(TAG "tracking status fd=%lld for pid %d (fallback)",
                     (long long)ret, pid);
            }
        }
    } else if (nr == __NR_read
#ifdef __NR_pread64
               || nr == __NR_pread64
#endif
    ) {
        if (g_log_fp) {
            uint64_t fd_val = have_pending ? pending.args[0] : tracer_get_arg(regs, 0);
            tracked_fd_key key = make_fd_key(pid, fd_val);
            int maps_enabled = -1;
            auto st_it = g_maps_fd_states.find(key);
            if (st_it != g_maps_fd_states.end()) {
                maps_enabled = st_it->second.tamper_enabled ? 1 : 0;
            }
            fprintf(g_log_fp,
                    "[maps_bypass] read-exit: tid=%d tgid=%d fd=%llu ret=%lld tracked_maps=%d tracked_status=%d pending=%d maps_enabled=%d\n",
                    pid, key.tgid, (unsigned long long)fd_val, (long long)ret,
                    g_maps_fds.count(key) ? 1 : 0,
                    g_status_fds.count(key) ? 1 : 0,
                    have_pending ? 1 : 0,
                    maps_enabled);
            fflush(g_log_fp);
        }
        if (ret > 0) {
            uint64_t fd_val = have_pending ? pending.args[0] : tracer_get_arg(regs, 0);
            uint64_t buf_addr = have_pending ? pending.args[1] : tracer_get_arg(regs, 1);
            tracked_fd_key key = make_fd_key(pid, fd_val);

            // Check maps fd first (checksum bypass via maps tampering)
            if (g_maps_fds.count(key)) {
                bool tampered = tamper_maps_read_stream(pid, fd_val, buf_addr, (size_t)ret);
                if (tampered) {
                    g_stat_tampered++;
                    if (g_log_fp) {
                        fprintf(g_log_fp,
                                "[maps_bypass] tampered read() on maps fd=%llu, "
                                "%lld bytes\n",
                                (unsigned long long)fd_val, (long long)ret);
                        fflush(g_log_fp);
                    }
                } else if (g_log_fp) {
                    fprintf(g_log_fp,
                            "[maps_bypass] read seen but unchanged: tid=%d tgid=%d fd=%llu bytes=%lld\n",
                            pid, key.tgid, (unsigned long long)fd_val, (long long)ret);
                    fflush(g_log_fp);
                }
            } else if (g_status_fds.count(key)) {
                // TracerPid tampering
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
    }

    g_waiting_read_exit.erase(pid);
}

void syscall_handler_fini() {
    if (g_log_fp) {
        fprintf(g_log_fp,
                "=== tracer finished: total=%llu filtered=%llu "
                "logged=%llu tampered=%llu maps_fds_tracked=%zu ===\n",
                (unsigned long long)g_stat_total,
                (unsigned long long)g_stat_filtered,
                (unsigned long long)g_stat_logged,
                (unsigned long long)g_stat_tampered,
                g_maps_fds.size());
        fclose(g_log_fp);
        g_log_fp = nullptr;
    }
    g_maps_fds.clear();
    g_maps_fd_states.clear();
    g_status_fds.clear();
    g_tid_to_tgid_cache.clear();
    g_pending_exit.clear();
    g_protected_libs.clear();
}
